package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

type LifecycleOperation string
type LifecyclePhase string

const (
	LifecycleMove              LifecycleOperation = "move"
	LifecyclePurge             LifecycleOperation = "purge"
	LifecycleRollback          LifecycleOperation = "rollback"
	LifecycleCleanup           LifecycleOperation = "cleanup_retained"
	LifecycleVerify            LifecycleOperation = "verify"
	LifecycleRepair            LifecycleOperation = "repair"
	LifecycleCleanupConversion LifecycleOperation = "cleanup_conversion"
	LifecycleRestore           LifecycleOperation = "restore"

	LifecycleQueued    LifecyclePhase = "queued"
	LifecycleRunning   LifecyclePhase = "running"
	LifecycleCompleted LifecyclePhase = "completed"
	LifecycleFailed    LifecyclePhase = "failed"
)

var lifecycleIDPattern = regexp.MustCompile(`^op_[0-9a-f]{32}$`)

var ErrLifecycleConflict = errors.New("another account lifecycle operation is already running")

// LifecycleJob is the durable operator record for account movement and purge.
type LifecycleJob struct {
	SchemaVersion    int                `json:"schema_version"`
	ID               string             `json:"id"`
	Operation        LifecycleOperation `json:"operation"`
	Phase            LifecyclePhase     `json:"phase"`
	Login            string             `json:"login"`
	AccountID        string             `json:"account_id"`
	SourceRootID     string             `json:"source_root_id,omitempty"`
	TargetRootID     string             `json:"target_root_id,omitempty"`
	ReportID         string             `json:"report_id,omitempty"`
	ParentJobID      string             `json:"parent_job_id,omitempty"`
	RetainedSource   string             `json:"retained_source,omitempty"`
	RetainedPurgedAt *time.Time         `json:"retained_purged_at,omitzero"`
	SourceGeneration string             `json:"source_generation,omitempty"`
	TargetGeneration string             `json:"target_generation,omitempty"`
	TargetEngine     store.Backend      `json:"target_engine,omitempty"`
	Integrity        *IntegrityProgress `json:"integrity,omitempty"`
	Error            string             `json:"error,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
	CompletedAt      time.Time          `json:"completed_at,omitzero"`
}

// StartIntegrityCheck runs an account verification or repair as a durable
// lifecycle job. Repair fences only this account; ordinary verification keeps
// it online under the shared generation lease.
func (m *Manager) StartIntegrityCheck(login string, repair bool) (LifecycleJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return LifecycleJob{}, store.ErrNotFound
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return LifecycleJob{}, err
	}
	if !m.beginOperation() {
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, ErrTemporarilyUnavailable
	}
	operation := LifecycleVerify
	if repair {
		operation = LifecycleRepair
	}
	job, err := m.newLifecycleJob(entry, operation, "")
	if err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	go func(job LifecycleJob) {
		defer m.operations.Done()
		defer runtime.lifecycle.Store(false)
		job.Phase, job.UpdatedAt = LifecycleRunning, time.Now().UTC()
		_ = m.writeLifecycleJob(job)
		lastSaved := time.Time{}
		progress := func(value IntegrityProgress) error {
			job.Integrity = &value
			now := time.Now().UTC()
			complete := value.ItemsScanned == value.ItemsTotal && value.FoldersScanned == value.FoldersTotal
			if !complete && !lastSaved.IsZero() && now.Sub(lastSaved) < 500*time.Millisecond && value.ItemsScanned%100 != 0 {
				return nil
			}
			job.UpdatedAt, lastSaved = now, now
			return m.writeLifecycleJob(job)
		}
		report, checkErr := m.runIntegrityCheck(context.Background(), entry, repair, runtime, progress)
		m.finishLifecycleJob(&job, report.ID, checkErr, &runtime.lifecycle)
	}(job)
	return job, nil
}

func (m *Manager) StartMove(login, targetRootID string) (LifecycleJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return LifecycleJob{}, store.ErrNotFound
	}
	m.mu.RLock()
	_, configured := m.roots[targetRootID]
	m.mu.RUnlock()
	if !configured {
		return LifecycleJob{}, fmt.Errorf("account root %q is not configured", targetRootID)
	}
	if entry.RootID == targetRootID {
		return LifecycleJob{}, errors.New("account already uses target root")
	}
	before, err := m.retainedSources(entry.Manifest.ID, entry.RootID)
	if err != nil {
		return LifecycleJob{}, err
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return LifecycleJob{}, err
	}
	if !m.beginOperation() {
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, ErrTemporarilyUnavailable
	}
	job, err := m.newLifecycleJob(entry, LifecycleMove, targetRootID)
	if err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	go func(job LifecycleJob) {
		defer m.operations.Done()
		defer runtime.lifecycle.Store(false)
		job.Phase, job.UpdatedAt = LifecycleRunning, time.Now().UTC()
		_ = m.writeLifecycleJob(job)
		_, report, moveErr := m.move(context.Background(), login, targetRootID, true)
		if moveErr == nil {
			job.RetainedSource, moveErr = m.newRetainedSource(entry.Manifest.ID, entry.RootID, before)
		}
		m.finishLifecycleJob(&job, report.ID, moveErr, &runtime.lifecycle)
	}(job)
	return job, nil
}

// StartRollback moves the current logical account image back to the source
// root named by a completed move job. It preserves current data and creates a
// new retained target snapshot; it does not resurrect a stale byte-for-byte
// copy over changes made since the original move.
func (m *Manager) StartRollback(login, moveJobID, confirmation string) (LifecycleJob, error) {
	original, err := m.lifecycleJob(moveJobID)
	if err != nil {
		return LifecycleJob{}, err
	}
	if original.Login != normalizeLogin(login) || original.Operation != LifecycleMove || original.Phase != LifecycleCompleted || confirmation != "rollback:"+original.ID {
		return LifecycleJob{}, errors.New("move rollback confirmation or job state does not match")
	}
	entry, found := m.ByLogin(login)
	if !found {
		return LifecycleJob{}, store.ErrNotFound
	}
	if entry.RootID != original.TargetRootID {
		return LifecycleJob{}, errors.New("account is no longer at the move target")
	}
	if err := m.validateRetainedSource(original, entry); err != nil {
		return LifecycleJob{}, err
	}
	before, err := m.retainedSources(entry.Manifest.ID, entry.RootID)
	if err != nil {
		return LifecycleJob{}, err
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return LifecycleJob{}, err
	}
	if !m.beginOperation() {
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, ErrTemporarilyUnavailable
	}
	job, err := m.newLifecycleJob(entry, LifecycleRollback, original.SourceRootID)
	if err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	job.ParentJobID = original.ID
	if err := m.writeLifecycleJob(job); err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	go func(job LifecycleJob) {
		defer m.operations.Done()
		defer runtime.lifecycle.Store(false)
		job.Phase, job.UpdatedAt = LifecycleRunning, time.Now().UTC()
		_ = m.writeLifecycleJob(job)
		_, report, moveErr := m.move(context.Background(), login, original.SourceRootID, true)
		if moveErr == nil {
			job.RetainedSource, moveErr = m.newRetainedSource(entry.Manifest.ID, entry.RootID, before)
		}
		m.finishLifecycleJob(&job, report.ID, moveErr, &runtime.lifecycle)
	}(job)
	return job, nil
}

// StartRetainedCleanup removes the closed source snapshot from a completed
// move after exact confirmation. Active account paths are never accepted.
func (m *Manager) StartRetainedCleanup(login, moveJobID, confirmation string) (LifecycleJob, error) {
	original, err := m.lifecycleJob(moveJobID)
	if err != nil {
		return LifecycleJob{}, err
	}
	if original.Login != normalizeLogin(login) || original.Phase != LifecycleCompleted || original.RetainedSource == "" || confirmation != "cleanup:"+original.ID {
		return LifecycleJob{}, errors.New("retained cleanup confirmation or job state does not match")
	}
	entry, found := m.ByLogin(login)
	if !found {
		return LifecycleJob{}, store.ErrNotFound
	}
	if err := m.validateRetainedSource(original, entry); err != nil {
		return LifecycleJob{}, err
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return LifecycleJob{}, err
	}
	if !m.beginOperation() {
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, ErrTemporarilyUnavailable
	}
	job, err := m.newLifecycleJob(entry, LifecycleCleanup, "")
	if err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	job.ParentJobID = original.ID
	if err := m.writeLifecycleJob(job); err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	go func(job LifecycleJob) {
		defer m.operations.Done()
		defer runtime.lifecycle.Store(false)
		job.Phase, job.UpdatedAt = LifecycleRunning, time.Now().UTC()
		_ = m.writeLifecycleJob(job)
		cleanupErr := os.RemoveAll(original.RetainedSource)
		if cleanupErr == nil {
			cleanupErr = syncDirectory(filepath.Dir(original.RetainedSource))
		}
		if cleanupErr == nil {
			purgedAt := time.Now().UTC()
			original.RetainedPurgedAt = &purgedAt
			original.RetainedSource = ""
			cleanupErr = m.writeLifecycleJob(original)
		}
		m.finishLifecycleJob(&job, "", cleanupErr, &runtime.lifecycle)
	}(job)
	return job, nil
}

// StartConversionRetainedCleanup records conversion-generation deletion as a
// durable lifecycle job instead of performing an invisible filesystem action.
func (m *Manager) StartConversionRetainedCleanup(login, conversionJobID, confirmation string) (LifecycleJob, error) {
	if confirmation != "cleanup:"+conversionJobID {
		return LifecycleJob{}, errors.New("conversion cleanup confirmation does not match")
	}
	return m.startConversionRetainedCleanup(login, conversionJobID)
}

func (m *Manager) startConversionRetainedCleanup(login, conversionJobID string) (LifecycleJob, error) {
	entry, conversion, err := m.conversionCleanupCandidate(login, conversionJobID)
	if err != nil {
		return LifecycleJob{}, err
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return LifecycleJob{}, err
	}
	if !m.beginOperation() {
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, ErrTemporarilyUnavailable
	}
	job, err := m.newLifecycleJob(entry, LifecycleCleanupConversion, "")
	if err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	job.ParentJobID = conversion.ID
	if err := m.writeLifecycleJob(job); err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	go func(job LifecycleJob) {
		defer m.operations.Done()
		defer runtime.lifecycle.Store(false)
		job.Phase, job.UpdatedAt = LifecycleRunning, time.Now().UTC()
		_ = m.writeLifecycleJob(job)
		_, cleanupErr := m.cleanupConversionSource(entry, conversion)
		m.finishLifecycleJob(&job, "", cleanupErr, &runtime.lifecycle)
	}(job)
	return job, nil
}

// ReapRetained starts bounded, durable cleanup work for verified rollback
// copies older than the managed retention policy. It never deletes inline.
func (m *Manager) ReapRetained(now time.Time) ([]LifecycleJob, error) {
	days := m.retainedCleanupDays.Load()
	if days < 1 {
		return []LifecycleJob{}, nil
	}
	cutoff := now.UTC().Add(-time.Duration(days) * 24 * time.Hour)
	started := make([]LifecycleJob, 0)
	var resultErr error
	jobs, err := m.LifecycleJobs("")
	if err != nil {
		return nil, err
	}
	for _, parent := range jobs {
		if (parent.Operation != LifecycleMove && parent.Operation != LifecycleRollback && parent.Operation != LifecycleRestore) || parent.Phase != LifecycleCompleted || parent.RetainedSource == "" || !lifecycleBefore(parent, cutoff) {
			continue
		}
		job, startErr := m.StartRetainedCleanup(parent.Login, parent.ID, "cleanup:"+parent.ID)
		if startErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cleanup retained move %s: %w", parent.ID, startErr))
			continue
		}
		started = append(started, job)
	}
	for _, entry := range m.Entries() {
		conversions, jobsErr := m.Jobs(entry.Manifest.Login)
		if jobsErr != nil {
			resultErr = errors.Join(resultErr, jobsErr)
			continue
		}
		for _, conversion := range conversions {
			if conversion.Phase != ConversionCompleted || conversion.SourcePurgedAt != nil || conversion.CompletedAt.IsZero() || !conversion.CompletedAt.Before(cutoff) {
				continue
			}
			job, startErr := m.startConversionRetainedCleanup(entry.Manifest.Login, conversion.ID)
			if startErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("cleanup retained conversion %s: %w", conversion.ID, startErr))
				continue
			}
			started = append(started, job)
		}
	}
	return started, resultErr
}

func lifecycleBefore(job LifecycleJob, cutoff time.Time) bool {
	completed := job.CompletedAt
	if completed.IsZero() {
		completed = job.UpdatedAt
	}
	return completed.Before(cutoff)
}

func (m *Manager) StartPurge(login, confirmation string) (LifecycleJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return LifecycleJob{}, store.ErrNotFound
	}
	if confirmation != "purge:"+entry.Manifest.ID {
		return LifecycleJob{}, errors.New("account purge confirmation does not match")
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return LifecycleJob{}, err
	}
	if !m.beginOperation() {
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, ErrTemporarilyUnavailable
	}
	job, err := m.newLifecycleJob(entry, LifecyclePurge, "")
	if err != nil {
		m.operations.Done()
		runtime.lifecycle.Store(false)
		return LifecycleJob{}, err
	}
	go func(job LifecycleJob) {
		defer m.operations.Done()
		defer runtime.lifecycle.Store(false)
		job.Phase, job.UpdatedAt = LifecycleRunning, time.Now().UTC()
		_ = m.writeLifecycleJob(job)
		m.finishLifecycleJob(&job, "", m.purge(login, confirmation, true), &runtime.lifecycle)
	}(job)
	return job, nil
}

func (m *Manager) beginOperation() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing.Load() {
		return false
	}
	m.operations.Add(1)
	return true
}

func (m *Manager) newLifecycleJob(entry Entry, operation LifecycleOperation, targetRootID string) (LifecycleJob, error) {
	id, err := randomID("op")
	if err != nil {
		return LifecycleJob{}, err
	}
	now := time.Now().UTC()
	job := LifecycleJob{SchemaVersion: 1, ID: id, Operation: operation, Phase: LifecycleQueued, Login: entry.Manifest.Login, AccountID: entry.Manifest.ID, SourceRootID: entry.RootID, TargetRootID: targetRootID, CreatedAt: now, UpdatedAt: now}
	return job, m.writeLifecycleJob(job)
}

// finishLifecycleJob releases the account's lifecycle reservation before
// recording the terminal phase, so a caller that sees the job finish can
// start the next operation at once.
func (m *Manager) finishLifecycleJob(job *LifecycleJob, reportID string, cause error, reservation *atomic.Bool) {
	reservation.Store(false)
	job.ReportID = reportID
	job.UpdatedAt, job.CompletedAt = time.Now().UTC(), time.Now().UTC()
	if cause != nil {
		job.Phase, job.Error = LifecycleFailed, cause.Error()
	} else {
		job.Phase = LifecycleCompleted
	}
	_ = m.writeLifecycleJob(*job)
}

func (m *Manager) LifecycleJobs(login string) ([]LifecycleJob, error) {
	directory := m.lifecycleDirectory()
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []LifecycleJob{}, nil
	}
	if err != nil {
		return nil, err
	}
	jobs := make([]LifecycleJob, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		job, err := readLifecycleJob(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		if login == "" || job.Login == normalizeLogin(login) {
			jobs = append(jobs, job)
		}
	}
	slices.SortFunc(jobs, func(a, b LifecycleJob) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return jobs, nil
}

func (m *Manager) lifecycleJob(id string) (LifecycleJob, error) {
	if !lifecycleIDPattern.MatchString(id) {
		return LifecycleJob{}, errors.New("invalid lifecycle job ID")
	}
	return readLifecycleJob(filepath.Join(m.lifecycleDirectory(), id+".json"))
}

func (m *Manager) retainedSources(accountID, rootID string) (map[string]struct{}, error) {
	if !accountIDPattern.MatchString(accountID) {
		return nil, errors.New("invalid account identity")
	}
	m.mu.RLock()
	root, found := m.roots[rootID]
	m.mu.RUnlock()
	if !found {
		return nil, fmt.Errorf("account root %q is not configured", rootID)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	prefix := ".moved-" + accountID + "-mov_"
	result := make(map[string]struct{})
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if safe, err := safeDirectoryExists(path); err != nil {
			return nil, err
		} else if safe {
			result[path] = struct{}{}
		}
	}
	return result, nil
}

func (m *Manager) newRetainedSource(accountID, rootID string, before map[string]struct{}) (string, error) {
	after, err := m.retainedSources(accountID, rootID)
	if err != nil {
		return "", err
	}
	var added string
	for path := range after {
		if _, existed := before[path]; existed {
			continue
		}
		if added != "" {
			return "", errors.New("move created multiple retained source directories")
		}
		added = path
	}
	if added == "" {
		return "", errors.New("move did not create a retained source directory")
	}
	return added, nil
}

func (m *Manager) validateRetainedSource(job LifecycleJob, active Entry) error {
	if !accountIDPattern.MatchString(job.AccountID) || job.RetainedSource == "" {
		return errors.New("lifecycle job has no retained source")
	}
	if job.Operation == LifecycleRestore {
		if !generationPattern.MatchString(job.SourceGeneration) {
			return errors.New("restore lifecycle job has an invalid source generation")
		}
		retained := filepath.Clean(job.RetainedSource)
		expected := filepath.Join(active.Path, "generations", job.SourceGeneration)
		if retained != expected || active.Manifest.ActiveGeneration == job.SourceGeneration {
			return errors.New("refusing to remove an active or unexpected restore generation")
		}
		exists, err := safeDirectoryExists(retained)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("retained restore generation no longer exists")
		}
		return nil
	}
	m.mu.RLock()
	root, found := m.roots[job.SourceRootID]
	m.mu.RUnlock()
	if !found {
		return fmt.Errorf("retained source root %q is not configured", job.SourceRootID)
	}
	retained := filepath.Clean(job.RetainedSource)
	wantPrefix := ".moved-" + job.AccountID + "-mov_"
	if filepath.Dir(retained) != filepath.Clean(root) || !strings.HasPrefix(filepath.Base(retained), wantPrefix) {
		return errors.New("retained source path is outside its configured root")
	}
	if filepath.Clean(active.Path) == retained {
		return errors.New("refusing to remove the active account path")
	}
	exists, err := validMovedAccount(retained, job.AccountID)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("retained source no longer exists")
	}
	return nil
}

func (m *Manager) lifecycleDirectory() string { return filepath.Join(m.Root(), ".lifecycle-jobs") }

func (m *Manager) writeLifecycleJob(job LifecycleJob) error {
	if job.SchemaVersion != 1 || !lifecycleIDPattern.MatchString(job.ID) || !accountIDPattern.MatchString(job.AccountID) {
		return errors.New("invalid lifecycle job")
	}
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	directory := m.lifecycleDirectory()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, job.ID+".json")
	temporary, err := os.CreateTemp(directory, ".lifecycle-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := errors.Join(temporary.Sync(), temporary.Close()); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func readLifecycleJob(path string) (LifecycleJob, error) {
	file, err := os.Open(path)
	if err != nil {
		return LifecycleJob{}, err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestSize+1))
	decoder.DisallowUnknownFields()
	var job LifecycleJob
	if err := decoder.Decode(&job); err != nil {
		return LifecycleJob{}, err
	}
	if job.SchemaVersion != 1 || filepath.Base(path) != job.ID+".json" || !lifecycleIDPattern.MatchString(job.ID) || !accountIDPattern.MatchString(job.AccountID) {
		return LifecycleJob{}, errors.New("invalid lifecycle job identity")
	}
	return job, nil
}

func (m *Manager) reconcileLifecycleJobs() error {
	jobs, err := m.LifecycleJobs("")
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job.Phase != LifecycleQueued && job.Phase != LifecycleRunning {
			continue
		}
		entry, found := m.ByLogin(job.Login)
		completed := ((job.Operation == LifecycleMove || job.Operation == LifecycleRollback) && found && entry.RootID == job.TargetRootID) || (job.Operation == LifecyclePurge && !found)
		if job.Operation == LifecycleRestore {
			completed = found && entry.Manifest.ActiveGeneration == job.TargetGeneration && entry.Manifest.Engine == job.TargetEngine
			if completed {
				if job.RetainedSource == "" && generationPattern.MatchString(job.SourceGeneration) && job.SourceGeneration != job.TargetGeneration {
					job.RetainedSource = filepath.Join(entry.Path, "generations", job.SourceGeneration)
				}
			} else if found && generationPattern.MatchString(job.TargetGeneration) && job.TargetGeneration != entry.Manifest.ActiveGeneration {
				target := filepath.Join(entry.Path, "generations", job.TargetGeneration)
				if removeErr := os.RemoveAll(target); removeErr != nil {
					return fmt.Errorf("remove interrupted restore generation: %w", removeErr)
				}
				if syncErr := syncDirectory(filepath.Dir(target)); syncErr != nil {
					return fmt.Errorf("sync interrupted restore cleanup: %w", syncErr)
				}
			}
		}
		if job.Operation == LifecycleCleanup {
			parent, parentErr := m.lifecycleJob(job.ParentJobID)
			if parentErr != nil {
				return parentErr
			}
			retainedExists := false
			if parent.RetainedSource != "" {
				retainedExists, err = safeDirectoryExists(parent.RetainedSource)
				if err != nil {
					return err
				}
			}
			completed = parent.RetainedSource == "" || !retainedExists
			if completed && parent.RetainedSource != "" {
				purgedAt := time.Now().UTC()
				parent.RetainedPurgedAt = &purgedAt
				parent.RetainedSource = ""
				if err := m.writeLifecycleJob(parent); err != nil {
					return err
				}
			}
		}
		if job.Operation == LifecycleCleanupConversion {
			if !found {
				completed = false
			} else {
				conversion, conversionErr := ReadConversionJob(entry.Path, job.ParentJobID)
				if conversionErr != nil {
					return conversionErr
				}
				retainedPath := filepath.Join(entry.Path, "generations", conversion.SourceGeneration)
				retainedExists, existsErr := safeDirectoryExists(retainedPath)
				if existsErr != nil {
					return existsErr
				}
				completed = conversion.SourcePurgedAt != nil || !retainedExists
				if completed && conversion.SourcePurgedAt == nil {
					purgedAt := time.Now().UTC()
					conversion.SourcePurgedAt = &purgedAt
					conversion.UpdatedAt = purgedAt
					if err := writeConversionJob(entry.Path, conversion); err != nil {
						return err
					}
				}
			}
		}
		job.UpdatedAt, job.CompletedAt = time.Now().UTC(), time.Now().UTC()
		if completed {
			job.Phase = LifecycleCompleted
		} else {
			job.Phase, job.Error = LifecycleFailed, "operation interrupted before completion; prior active state was preserved; retry explicitly"
		}
		if err := m.writeLifecycleJob(job); err != nil {
			return err
		}
	}
	return nil
}
