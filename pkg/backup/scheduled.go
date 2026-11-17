package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"

	"github.com/lkarlslund/veksel/pkg/backup/archivecrypt"
	"github.com/lkarlslund/veksel/pkg/backup/schedule"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Scheduled backups write installation archives into a destination directory
// on a wall-clock schedule. Each archive is produced by WriteInstallation,
// optionally encrypted to age recipients, written atomically, verified by the
// VerifyArchive restore drill, and recorded in a durable ledger. Retention
// only ever deletes archives that the ledger names, so files an operator puts
// in the directory are never touched.
const (
	scheduledPrefix     = "veksel-scheduled-"
	scheduledStamp      = "20060102T150405Z"
	scheduledTarSuffix  = ".tar"
	scheduledStateKey   = "state"
	scheduledActor      = "system:backup-scheduler"
	scheduledRunTimeout = 24 * time.Hour
	scheduledPollPeriod = 30 * time.Second
	// minimumFreeBytes is required on the destination before any run and is
	// the whole estimate until a previous archive size is known.
	minimumFreeBytes = 64 << 20

	TriggerSchedule = "schedule"
	TriggerManual   = "manual"

	ResultRunning   = "running"
	ResultSucceeded = "succeeded"
	ResultFailed    = "failed"
)

var (
	scheduledName    = regexp.MustCompile(`^veksel-scheduled-\d{8}T\d{6}Z\.tar(\.age)?$`)
	scheduledPartial = regexp.MustCompile(`^\.veksel-scheduled-\d{8}T\d{6}Z\.tar(\.age)?\.partial-`)
)

// ErrBackupRunning is returned when a backup is requested while another
// online backup, scheduled or manual, is in progress.
var ErrBackupRunning = errors.New("another backup is already running")

// SchedulePolicy is the live configuration of scheduled backups.
type SchedulePolicy struct {
	Schedule   schedule.Schedule
	Directory  string
	DataDir    string
	Recipients []age.Recipient
	KeepDaily  int
	KeepWeekly int
}

// SchedulePolicyFromConfig derives the policy from managed configuration.
func SchedulePolicyFromConfig(cfg *config.Config) (SchedulePolicy, error) {
	parsed, err := schedule.Parse(cfg.BackupSchedule)
	if err != nil {
		return SchedulePolicy{}, err
	}
	recipients, err := archivecrypt.ParseRecipients(cfg.BackupAgeRecipients)
	if err != nil {
		return SchedulePolicy{}, err
	}
	dataDir, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return SchedulePolicy{}, err
	}
	return SchedulePolicy{
		Schedule: parsed, Directory: cfg.BackupDirectoryPath(), DataDir: dataDir, Recipients: recipients,
		KeepDaily: cfg.BackupRetentionDaily, KeepWeekly: cfg.BackupRetentionWeekly,
	}, nil
}

// Downloadable reports whether archives in the destination may be served by
// the administration API: only when the directory lies inside the data
// directory, so the API never becomes a reader of arbitrary mounts.
func (p SchedulePolicy) Downloadable() bool {
	relative, err := filepath.Rel(p.DataDir, p.Directory)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// ScheduledArchive is one ledger entry: an archive the scheduler wrote and
// verified.
type ScheduledArchive struct {
	Name      string    `json:"name"`
	Directory string    `json:"directory"`
	CreatedAt time.Time `json:"created_at"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Encrypted bool      `json:"encrypted"`
	Accounts  int       `json:"accounts"`
}

// ScheduleState is the durable scheduler record. It survives restarts so a
// missed slot is caught up exactly once and retention knows which files it
// owns.
type ScheduleState struct {
	Schedule       string             `json:"schedule"`
	Baseline       time.Time          `json:"baseline,omitzero"`
	LastAttemptAt  time.Time          `json:"last_attempt_at,omitzero"`
	LastFinishedAt time.Time          `json:"last_finished_at,omitzero"`
	LastSuccessAt  time.Time          `json:"last_success_at,omitzero"`
	LastResult     string             `json:"last_result,omitempty"`
	LastTrigger    string             `json:"last_trigger,omitempty"`
	LastError      string             `json:"last_error,omitempty"`
	LastArchive    string             `json:"last_archive,omitempty"`
	LastSize       int64              `json:"last_size,omitempty"`
	LastDurationMS int64              `json:"last_duration_ms,omitempty"`
	NextRunAt      time.Time          `json:"next_run_at,omitzero"`
	Archives       []ScheduledArchive `json:"archives"`
}

// Auditor records administrative evidence; *audit.Logger satisfies it.
type Auditor interface {
	Log(actor, action, target string, details map[string]string)
}

// SchedulerOptions wires a Scheduler to the running installation.
type SchedulerOptions struct {
	Store *model.TypedStore
	// Source describes the live installation for each run.
	Source func() InstallationSource
	Audit  Auditor
	// Capacity checks free space before a run; nil skips the check.
	Capacity health.CapacityProber
	// Now and Location default to time.Now and time.Local.
	Now      func() time.Time
	Location *time.Location
}

// Scheduler runs scheduled backups and serializes every online installation
// backup, so a scheduled run and an administrator's download never overlap.
type Scheduler struct {
	options SchedulerOptions
	gate    sync.Mutex
	running atomic.Bool
	wake    chan struct{}

	mu     sync.Mutex
	policy SchedulePolicy
	state  ScheduleState
	// background is the context of Start, used by Trigger.
	background context.Context
}

// NewScheduler loads the durable state. A run that was in progress when the
// process stopped is recorded as failed so it raises an alert.
func NewScheduler(ctx context.Context, options SchedulerOptions) (*Scheduler, error) {
	if options.Store == nil || options.Source == nil {
		return nil, errors.New("backup scheduler requires a store and a source")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Location == nil {
		options.Location = time.Local
	}
	if err := options.Store.EnsureNamespace(ctx, model.NSBackupSchedule); err != nil {
		return nil, err
	}
	s := &Scheduler{options: options, wake: make(chan struct{}, 1), background: context.Background()}
	if err := options.Store.Get(ctx, model.NSBackupSchedule, scheduledStateKey, &s.state); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("load backup schedule state: %w", err)
	}
	if s.state.LastResult == ResultRunning {
		s.state.LastResult, s.state.LastError = ResultFailed, "backup was interrupted by a shutdown or crash"
		s.state.LastFinishedAt = s.now()
		if err := s.saveLocked(ctx); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Scheduler) now() time.Time { return s.options.Now().In(s.options.Location) }

func (s *Scheduler) saveLocked(ctx context.Context) error {
	if s.state.Archives == nil {
		s.state.Archives = []ScheduledArchive{}
	}
	s.state.NextRunAt = s.policy.Schedule.NextRun(s.state.LastAttemptAt, s.state.Baseline, s.now())
	return s.options.Store.Set(ctx, model.NSBackupSchedule, scheduledStateKey, s.state)
}

// SetPolicy applies a new policy. A changed schedule takes effect from now:
// slots before the change are not caught up.
func (s *Scheduler) SetPolicy(ctx context.Context, policy SchedulePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = policy
	if canonical := policy.Schedule.String(); s.state.Schedule != canonical {
		s.state.Schedule, s.state.Baseline = canonical, s.now()
	}
	if err := s.saveLocked(ctx); err != nil {
		return fmt.Errorf("save backup schedule state: %w", err)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Start runs due backups until ctx ends. The returned function stops it.
func (s *Scheduler) Start(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.background = ctx
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(scheduledPollPeriod)
		defer ticker.Stop()
		for {
			s.runIfDue(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-s.wake:
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (s *Scheduler) runIfDue(ctx context.Context) {
	s.mu.Lock()
	due := s.policy.Schedule.Due(s.state.LastAttemptAt, s.state.Baseline, s.now())
	s.mu.Unlock()
	if !due {
		return
	}
	if _, err := s.Run(ctx, TriggerSchedule, scheduledActor); err != nil && !errors.Is(err, ErrBackupRunning) {
		log.Error("backup: scheduled backup failed", "error", err)
	}
}

// Exclusive runs fn while holding the online backup gate, or returns
// ErrBackupRunning when another backup holds it. A nil Scheduler runs fn
// directly, for installations without scheduling.
func (s *Scheduler) Exclusive(fn func() error) error {
	if s == nil {
		return fn()
	}
	if !s.gate.TryLock() {
		return ErrBackupRunning
	}
	defer s.gate.Unlock()
	s.running.Store(true)
	defer s.running.Store(false)
	return fn()
}

// Trigger starts a run in the background and returns at once, or returns
// ErrBackupRunning.
func (s *Scheduler) Trigger(actor string) error {
	if !s.gate.TryLock() {
		return ErrBackupRunning
	}
	s.mu.Lock()
	ctx := s.background
	s.mu.Unlock()
	go func() {
		defer s.gate.Unlock()
		if _, err := s.runLocked(ctx, TriggerManual, actor); err != nil {
			log.Error("backup: requested backup failed", "error", err)
		}
	}()
	return nil
}

// Run performs one run now and waits for it.
func (s *Scheduler) Run(ctx context.Context, trigger, actor string) (ScheduledArchive, error) {
	if !s.gate.TryLock() {
		return ScheduledArchive{}, ErrBackupRunning
	}
	defer s.gate.Unlock()
	return s.runLocked(ctx, trigger, actor)
}

func (s *Scheduler) runLocked(ctx context.Context, trigger, actor string) (ScheduledArchive, error) {
	s.running.Store(true)
	defer s.running.Store(false)
	ctx, cancel := context.WithTimeout(ctx, scheduledRunTimeout)
	defer cancel()
	s.mu.Lock()
	policy, lastSize, started := s.policy, s.state.LastSize, s.now()
	s.state.LastAttemptAt, s.state.LastTrigger, s.state.LastResult, s.state.LastError = started, trigger, ResultRunning, ""
	saveErr := s.saveLocked(ctx)
	s.mu.Unlock()
	if saveErr != nil {
		return ScheduledArchive{}, fmt.Errorf("record backup start: %w", saveErr)
	}
	log.Info("backup: scheduled backup starting", "trigger", trigger, "directory", policy.Directory, "encrypted", len(policy.Recipients) > 0)
	archive, err := s.write(ctx, policy, lastSize, started)
	finished := s.now()
	details := map[string]string{"trigger": trigger, "directory": policy.Directory, "encrypted": fmt.Sprint(len(policy.Recipients) > 0)}
	s.mu.Lock()
	s.state.LastFinishedAt, s.state.LastDurationMS = finished, finished.Sub(started).Milliseconds()
	if err != nil {
		s.state.LastResult, s.state.LastError = ResultFailed, err.Error()
	} else {
		s.state.LastResult, s.state.LastSuccessAt = ResultSucceeded, finished
		s.state.LastArchive, s.state.LastSize = archive.Name, archive.Size
		s.state.Archives = append(s.state.Archives, archive)
		details["archive"], details["size"], details["sha256"], details["accounts"] = archive.Name, fmt.Sprint(archive.Size), archive.SHA256, fmt.Sprint(archive.Accounts)
		s.applyRetentionLocked(policy)
	}
	saveErr = s.saveLocked(context.WithoutCancel(ctx))
	s.mu.Unlock()
	if err != nil {
		details["result"], details["error"] = ResultFailed, err.Error()
		s.audit(actor, "backup.scheduled", details)
		log.Error("backup: scheduled backup failed", "trigger", trigger, "error", err)
		return ScheduledArchive{}, err
	}
	details["result"], details["verified"] = ResultSucceeded, "true"
	s.audit(actor, "backup.scheduled", details)
	log.Info("backup: scheduled backup verified", "archive", archive.Name, "bytes", archive.Size, "duration", finished.Sub(started))
	if saveErr != nil {
		return archive, fmt.Errorf("record backup result: %w", saveErr)
	}
	return archive, nil
}

func (s *Scheduler) audit(actor, action string, details map[string]string) {
	if s.options.Audit != nil {
		s.options.Audit.Log(actor, action, "scheduled", details)
	}
}

// write produces, verifies, and atomically publishes one archive.
func (s *Scheduler) write(ctx context.Context, policy SchedulePolicy, lastSize int64, started time.Time) (ScheduledArchive, error) {
	if policy.Directory == "" {
		return ScheduledArchive{}, errors.New("no backup directory is configured")
	}
	if err := os.MkdirAll(policy.Directory, 0o700); err != nil {
		return ScheduledArchive{}, fmt.Errorf("create backup directory: %w", err)
	}
	removeStalePartials(policy.Directory)
	source := s.options.Source()
	if err := s.checkFreeSpace(policy.Directory, source.TempDir, lastSize); err != nil {
		return ScheduledArchive{}, err
	}
	encrypted := len(policy.Recipients) > 0
	name := scheduledPrefix + started.UTC().Format(scheduledStamp) + scheduledTarSuffix
	if encrypted {
		name += archivecrypt.Extension
	}
	var accounts int
	written, err := WriteFileAtomic(filepath.Join(policy.Directory, name), func(w io.Writer) error {
		var err error
		accounts, err = writeVerified(ctx, source, w, policy.Recipients)
		return err
	})
	if err != nil {
		return ScheduledArchive{}, err
	}
	return ScheduledArchive{
		Name: name, Directory: policy.Directory, CreatedAt: started.UTC(), Size: written.Size, SHA256: written.SHA256,
		Encrypted: encrypted, Accounts: accounts,
	}, nil
}

// writeVerified writes an installation archive to w, encrypted when
// recipients are given, while the VerifyArchive restore drill consumes the
// same plaintext stream. Verifying the stream lets the server check archives
// it can encrypt but not decrypt; WriteFileAtomic then confirms the stored
// bytes match what was written.
func writeVerified(ctx context.Context, source InstallationSource, w io.Writer, recipients []age.Recipient) (int, error) {
	plaintext, finish := w, func() error { return nil }
	if len(recipients) > 0 {
		encryptor, err := archivecrypt.Encrypt(w, recipients)
		if err != nil {
			return 0, err
		}
		plaintext, finish = encryptor, encryptor.Close
	}
	reader, writer := io.Pipe()
	type outcome struct {
		verification *ArchiveVerification
		err          error
	}
	verified := make(chan outcome, 1)
	go func() {
		verification, err := VerifyArchive(ctx, reader, source.TempDir)
		if err == nil {
			_, err = io.Copy(io.Discard, reader)
		}
		if err != nil {
			// Unblock the writer with an error it can tell apart from its own.
			reader.CloseWithError(&verificationFailure{err: err})
		} else {
			_ = reader.Close()
		}
		verified <- outcome{verification, err}
	}()
	writeErr := WriteInstallation(ctx, source, io.MultiWriter(plaintext, writer))
	writer.CloseWithError(writeErr)
	result := <-verified
	var failure *verificationFailure
	switch {
	case errors.As(writeErr, &failure):
		return 0, fmt.Errorf("verify archive: %w", failure.err)
	case writeErr != nil:
		return 0, writeErr
	case result.err != nil:
		return 0, fmt.Errorf("verify archive: %w", result.err)
	case result.verification.Installation == nil:
		return 0, errors.New("verify archive: not an installation archive")
	}
	if err := finish(); err != nil {
		return 0, fmt.Errorf("encrypt archive: %w", err)
	}
	return len(result.verification.Installation.Accounts), nil
}

// verificationFailure marks the error the verifier closed the pipe with.
type verificationFailure struct{ err error }

func (f *verificationFailure) Error() string { return f.err.Error() }
func (f *verificationFailure) Unwrap() error { return f.err }

// WrittenFile describes a file published by WriteFileAtomic.
type WrittenFile struct {
	Size   int64
	SHA256 string
}

// WriteFileAtomic writes path through a temporary file in the same
// directory: produce writes the contents, the file is fsynced and renamed
// into place, the directory is fsynced, and the stored file is read back to
// confirm its digest. On any failure nothing remains at path.
func WriteFileAtomic(path string, produce func(io.Writer) error) (WrittenFile, error) {
	dir, base := filepath.Split(path)
	if _, err := os.Lstat(path); err == nil {
		return WrittenFile{}, fmt.Errorf("%s already exists", path)
	}
	partial, err := os.CreateTemp(dir, "."+base+".partial-")
	if err != nil {
		return WrittenFile{}, fmt.Errorf("create temporary file: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = partial.Close()
			_ = os.Remove(partial.Name())
		}
	}()
	digest := sha256.New()
	buffered := bufio.NewWriterSize(io.MultiWriter(partial, digest), 1<<20)
	counter := &countingWriter{w: buffered}
	if err := produce(counter); err != nil {
		return WrittenFile{}, err
	}
	if err := errors.Join(buffered.Flush(), partial.Sync(), partial.Close()); err != nil {
		return WrittenFile{}, fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(partial.Name(), path); err != nil {
		return WrittenFile{}, fmt.Errorf("publish %s: %w", path, err)
	}
	published = true
	written := WrittenFile{Size: counter.n, SHA256: fmt.Sprintf("%x", digest.Sum(nil))}
	if err := syncDirectory(dir); err != nil {
		_ = os.Remove(path)
		return WrittenFile{}, err
	}
	if stored, err := digestFile(path); err != nil || stored != written {
		_ = os.Remove(path)
		if err == nil {
			err = errors.New("stored file does not match the written bytes")
		}
		return WrittenFile{}, fmt.Errorf("read back %s: %w", path, err)
	}
	return written, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func syncDirectory(dir string) error {
	if dir == "" {
		dir = "."
	}
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	// Some filesystems (and platforms) cannot fsync a directory; the rename
	// is still atomic there, so only an open failure is fatal.
	_ = handle.Sync()
	return handle.Close()
}

func digestFile(path string) (WrittenFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return WrittenFile{}, err
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return WrittenFile{}, err
	}
	return WrittenFile{Size: size, SHA256: fmt.Sprintf("%x", digest.Sum(nil))}, nil
}

// removeStalePartials deletes temporary files an interrupted run left behind.
func removeStalePartials(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && scheduledPartial.MatchString(entry.Name()) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err == nil {
				log.Info("backup: removed interrupted partial archive", "file", entry.Name())
			}
		}
	}
}

// checkFreeSpace refuses a run that would likely exhaust the destination or
// the spool and verification scratch space. The estimate is the previous
// archive plus a quarter; verification stages up to twice that.
func (s *Scheduler) checkFreeSpace(destination, scratch string, lastSize int64) error {
	if s.options.Capacity == nil {
		return nil
	}
	estimate := lastSize + lastSize/4
	checks := []struct {
		path, label string
		need        int64
	}{{destination, "backup directory", max(estimate, minimumFreeBytes)}}
	if scratch != "" {
		checks = append(checks, struct {
			path, label string
			need        int64
		}{scratch, "backup scratch directory", max(2*estimate, minimumFreeBytes)})
	}
	for _, check := range checks {
		capacity, err := s.options.Capacity.Capacity(check.path)
		if err != nil {
			return fmt.Errorf("check free space in %s: %w", check.label, err)
		}
		if capacity.AvailableBytes < uint64(check.need) {
			return fmt.Errorf("%s %s has %d bytes free; about %d are needed", check.label, check.path, capacity.AvailableBytes, check.need)
		}
	}
	return nil
}

// applyRetentionLocked deletes ledger archives in the current directory
// beyond the policy, keeping the newest archive of each of the KeepDaily most
// recent days and the KeepWeekly most recent ISO weeks, and always the newest
// archive. Archives in a former directory are left alone.
func (s *Scheduler) applyRetentionLocked(policy SchedulePolicy) {
	keep, remove := retention(s.state.Archives, policy, s.options.Location)
	for _, archive := range remove {
		details := map[string]string{"archive": archive.Name, "directory": archive.Directory, "result": ResultSucceeded}
		if err := removeOwnedArchive(archive); err != nil {
			details["result"], details["error"] = ResultFailed, err.Error()
			log.Warn("backup: retention left an archive in place", "archive", archive.Name, "error", err)
		} else {
			log.Info("backup: retention removed archive", "archive", archive.Name)
		}
		s.audit(scheduledActor, "backup.retention.delete", details)
	}
	s.state.Archives = keep
}

func retention(archives []ScheduledArchive, policy SchedulePolicy, location *time.Location) (keep, remove []ScheduledArchive) {
	current := make([]ScheduledArchive, 0, len(archives))
	for _, archive := range archives {
		if archive.Directory == policy.Directory {
			current = append(current, archive)
		} else {
			keep = append(keep, archive)
		}
	}
	slices.SortFunc(current, func(a, b ScheduledArchive) int { return b.CreatedAt.Compare(a.CreatedAt) })
	days, weeks := map[string]bool{}, map[string]bool{}
	for i, archive := range current {
		local := archive.CreatedAt.In(location)
		day := local.Format(time.DateOnly)
		year, number := local.ISOWeek()
		week := fmt.Sprintf("%d-%02d", year, number)
		retained := i == 0
		if !days[day] && len(days) < policy.KeepDaily {
			days[day], retained = true, true
		}
		if !weeks[week] && len(weeks) < policy.KeepWeekly {
			weeks[week], retained = true, true
		}
		if retained {
			keep = append(keep, archive)
		} else {
			remove = append(remove, archive)
		}
	}
	slices.SortFunc(keep, func(a, b ScheduledArchive) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return keep, remove
}

// removeOwnedArchive deletes a ledger archive only while it still looks like
// the file the scheduler wrote: a scheduler name, a regular file (not a
// link), and the recorded size. A missing file is already gone.
func removeOwnedArchive(archive ScheduledArchive) error {
	if !scheduledName.MatchString(archive.Name) {
		return fmt.Errorf("%q is not a scheduled archive name", archive.Name)
	}
	path := filepath.Join(archive.Directory, archive.Name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != archive.Size {
		return errors.New("file no longer matches the archive the scheduler wrote")
	}
	return os.Remove(path)
}

// ScheduleStatus is the administration view of scheduled backups.
type ScheduleStatus struct {
	Schedule     string                 `json:"schedule"`
	Enabled      bool                   `json:"enabled"`
	Directory    string                 `json:"directory"`
	Encrypted    bool                   `json:"encrypted"`
	Recipients   int                    `json:"recipients"`
	KeepDaily    int                    `json:"keep_daily"`
	KeepWeekly   int                    `json:"keep_weekly"`
	Downloadable bool                   `json:"downloadable"`
	Running      bool                   `json:"running"`
	State        ScheduleState          `json:"state"`
	Archives     []ScheduledArchiveView `json:"archives"`
}

// ScheduledArchiveView is a ledger entry with its current presence on disk.
type ScheduledArchiveView struct {
	ScheduledArchive
	Present bool `json:"present"`
}

// Status reports the policy, durable state, and retained archives, newest
// first.
func (s *Scheduler) Status() ScheduleStatus {
	s.mu.Lock()
	policy, state := s.policy, s.state
	state.Archives = slices.Clone(state.Archives)
	s.mu.Unlock()
	status := ScheduleStatus{
		Schedule: policy.Schedule.String(), Enabled: policy.Schedule.Enabled, Directory: policy.Directory,
		Encrypted: len(policy.Recipients) > 0, Recipients: len(policy.Recipients), KeepDaily: policy.KeepDaily, KeepWeekly: policy.KeepWeekly,
		Downloadable: policy.Downloadable(), Running: s.running.Load(), State: state, Archives: []ScheduledArchiveView{},
	}
	status.State.NextRunAt = policy.Schedule.NextRun(state.LastAttemptAt, state.Baseline, s.now())
	for i := len(state.Archives) - 1; i >= 0; i-- {
		archive := state.Archives[i]
		info, err := os.Lstat(filepath.Join(archive.Directory, archive.Name))
		status.Archives = append(status.Archives, ScheduledArchiveView{ScheduledArchive: archive, Present: err == nil && info.Size() == archive.Size})
	}
	return status
}

// OpenArchive opens a retained archive for download. Only ledger archives in
// the current directory, and only when that directory is inside the data
// directory, can be opened.
func (s *Scheduler) OpenArchive(name string) (*os.File, ScheduledArchive, error) {
	s.mu.Lock()
	policy := s.policy
	index := slices.IndexFunc(s.state.Archives, func(archive ScheduledArchive) bool {
		return archive.Name == name && archive.Directory == policy.Directory
	})
	var archive ScheduledArchive
	if index >= 0 {
		archive = s.state.Archives[index]
	}
	s.mu.Unlock()
	if index < 0 || !scheduledName.MatchString(name) {
		return nil, ScheduledArchive{}, os.ErrNotExist
	}
	if !policy.Downloadable() {
		return nil, ScheduledArchive{}, os.ErrPermission
	}
	file, err := os.Open(filepath.Join(archive.Directory, archive.Name))
	if err != nil {
		return nil, ScheduledArchive{}, err
	}
	return file, archive, nil
}

// Observation projects scheduled-backup health: a failed last run is
// critical and an overdue successful run is a warning. Both become durable
// operational alerts through the health evaluator.
func (s *Scheduler) Observation(now time.Time) health.Observation {
	s.mu.Lock()
	policy, state := s.policy, s.state
	s.mu.Unlock()
	failed := state.LastResult == ResultFailed
	observation := health.Observation{ID: "scheduled-backup", Label: "Scheduled backups", Kind: "storage", Desired: policy.Schedule.Enabled || failed, State: health.StateHealthy}
	if !observation.Desired {
		observation.State = health.StateDisabled
		return observation
	}
	observation.Details = map[string]string{"schedule": policy.Schedule.String(), "directory": policy.Directory, "archives": fmt.Sprint(len(state.Archives)), "encrypted": fmt.Sprint(len(policy.Recipients) > 0)}
	if !state.LastSuccessAt.IsZero() {
		observation.Details["last_success"] = state.LastSuccessAt.UTC().Format(time.RFC3339)
		observation.Details["last_size"] = fmt.Sprint(state.LastSize)
	}
	reference := state.LastSuccessAt
	if state.Baseline.After(reference) {
		reference = state.Baseline
	}
	switch {
	case failed:
		observation.State, observation.Severity = health.StateUnavailable, health.SeverityCritical
		observation.Reason = "last backup failed: " + state.LastError
	case policy.Schedule.Enabled && state.LastResult != ResultRunning && now.Sub(reference) > policy.Schedule.Period()+6*time.Hour:
		observation.State, observation.Severity = health.StateDegraded, health.SeverityWarning
		observation.Reason = "no successful scheduled backup since " + reference.UTC().Format(time.RFC3339)
	}
	return observation
}
