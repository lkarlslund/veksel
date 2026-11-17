package account

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

var (
	// ErrTemporarilyUnavailable tells protocol adapters to return a retryable error.
	ErrTemporarilyUnavailable = errors.New("account is temporarily unavailable")
	ErrConversionConflict     = errors.New("account conversion conflicts with current state")
	ErrConversionCanceled     = errors.New("account conversion canceled")
	errConversionInterrupted  = errors.New("simulated conversion process interruption")
)

type conversionHooks struct {
	interrupt func(string, ConversionJob) error
}

func (h *conversionHooks) hit(boundary string, job ConversionJob) error {
	if h == nil || h.interrupt == nil {
		return nil
	}
	return h.interrupt(boundary, job)
}

// ConversionPhase is a durable conversion job phase.
type ConversionPhase string

const (
	ConversionPreparing  ConversionPhase = "preparing"
	ConversionCopying    ConversionPhase = "copying"
	ConversionVerifying  ConversionPhase = "verifying"
	ConversionActivating ConversionPhase = "activating"
	ConversionCompleted  ConversionPhase = "completed"
	ConversionCanceled   ConversionPhase = "canceled"
	ConversionFailed     ConversionPhase = "failed"
)

// ConversionJob records enough information to resume a process-interrupted copy.
type ConversionJob struct {
	SchemaVersion    int             `json:"schema_version"`
	ID               string          `json:"id"`
	AccountID        string          `json:"account_id"`
	SourceEngine     store.Backend   `json:"source_engine"`
	SourceGeneration string          `json:"source_generation"`
	TargetEngine     store.Backend   `json:"target_engine"`
	TargetGeneration string          `json:"target_generation"`
	SourceEncrypted  bool            `json:"source_encrypted,omitempty"`
	TargetEncrypted  bool            `json:"target_encrypted,omitempty"`
	RotateKey        bool            `json:"rotate_key,omitempty"`
	ParentJobID      string          `json:"parent_job_id,omitempty"`
	OriginalState    State           `json:"original_state"`
	Phase            ConversionPhase `json:"phase"`
	CancelRequested  bool            `json:"cancel_requested,omitempty"`
	SourcePurgedAt   *time.Time      `json:"source_purged_at,omitzero"`
	Stats            TransferStats   `json:"stats"`
	Error            string          `json:"error,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	CompletedAt      time.Time       `json:"completed_at,omitzero"`
}

// ConversionTarget describes the generation a conversion builds. Encryption
// changes and data-encryption key rotation reuse the engine conversion path:
// the logical image is copied into a new generation, verified, and activated.
type ConversionTarget struct {
	Engine    store.Backend `json:"engine"`
	Encrypted bool          `json:"encrypted"`
	// RotateKey rebuilds an encrypted account under a fresh data-encryption
	// key on the same engine.
	RotateKey bool `json:"rotate_key,omitempty"`
}

// Convert creates and runs a synchronous engine conversion of a plaintext
// account. Other accounts remain available; the caller must route access
// through OpenActive. Encrypted accounts convert through a Manager.
func Convert(ctx context.Context, accountPath string, targetEngine store.Backend) (ConversionJob, error) {
	return convert(ctx, accountPath, ConversionTarget{Engine: targetEngine}, nil)
}

func convert(ctx context.Context, accountPath string, target ConversionTarget, keys KeyWrapper) (ConversionJob, error) {
	job, err := prepareConversion(accountPath, target, keys, nil)
	if err != nil {
		return job, err
	}
	return resumeConversion(ctx, accountPath, job.ID, keys, nil)
}

// PrepareConversion durably creates and fences a plaintext engine conversion
// job without doing the potentially long copy. Job runners use this to
// acknowledge an API call immediately; ResumeConversion performs the
// idempotent copy and activation.
func PrepareConversion(accountPath string, targetEngine store.Backend) (ConversionJob, error) {
	return prepareConversion(accountPath, ConversionTarget{Engine: targetEngine}, nil, nil)
}

func prepareConversion(accountPath string, target ConversionTarget, keys KeyWrapper, hooks *conversionHooks) (ConversionJob, error) {
	if !SupportedEngine(target.Engine) {
		return ConversionJob{}, fmt.Errorf("unsupported target engine %q", target.Engine)
	}
	manifestPath := filepath.Join(accountPath, ManifestFilename)
	manifest, err := ReadManifest(manifestPath)
	if err != nil {
		return ConversionJob{}, err
	}
	if manifest.State != StateReady && manifest.State != StateDisabled {
		return ConversionJob{}, fmt.Errorf("%w: account state is %s", ErrConversionConflict, manifest.State)
	}
	if target.RotateKey && (!manifest.Encrypted || !target.Encrypted) {
		return ConversionJob{}, fmt.Errorf("%w: key rotation requires an encrypted account", ErrConversionConflict)
	}
	if manifest.Engine == target.Engine && manifest.Encrypted == target.Encrypted && !target.RotateKey {
		return ConversionJob{}, fmt.Errorf("%w: account already uses %s", ErrConversionConflict, describeStorage(target.Engine, target.Encrypted))
	}
	if (manifest.Encrypted || target.Encrypted) && keys == nil {
		return ConversionJob{}, ErrEncryptionKeysUnavailable
	}
	jobID, err := randomID("cnv")
	if err != nil {
		return ConversionJob{}, err
	}
	targetGeneration, err := NewGenerationID()
	if err != nil {
		return ConversionJob{}, err
	}
	now := time.Now().UTC()
	job := ConversionJob{
		SchemaVersion:    1,
		ID:               jobID,
		AccountID:        manifest.ID,
		SourceEngine:     manifest.Engine,
		SourceGeneration: manifest.ActiveGeneration,
		TargetEngine:     target.Engine,
		TargetGeneration: targetGeneration,
		SourceEncrypted:  manifest.Encrypted,
		TargetEncrypted:  target.Encrypted,
		RotateKey:        target.RotateKey,
		OriginalState:    manifest.State,
		Phase:            ConversionPreparing,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := writeConversionJob(accountPath, job); err != nil {
		return job, err
	}
	if err := hooks.hit("prepared", job); err != nil {
		return job, err
	}
	created, err := createGeneration(accountPath, targetGeneration, target.Engine, keys, target.Encrypted)
	if err != nil {
		return failBeforeFence(accountPath, job, err)
	}
	if err := created.Close(); err != nil {
		return failBeforeFence(accountPath, job, err)
	}
	if err := hooks.hit("target_created", job); err != nil {
		return job, err
	}
	manifest.State = StateConverting
	manifest.ConversionID = job.ID
	manifest.UpdatedAt = time.Now().UTC()
	if err := WriteManifest(manifestPath, manifest); err != nil {
		return failBeforeFence(accountPath, job, err)
	}
	if err := hooks.hit("fenced", job); err != nil {
		return job, err
	}
	return job, nil
}

// ResumeConversion resumes a job left in converting state by process interruption.
func ResumeConversion(ctx context.Context, accountPath, jobID string) (ConversionJob, error) {
	return resumeConversion(ctx, accountPath, jobID, nil, nil)
}

func resumeConversion(ctx context.Context, accountPath, jobID string, keys KeyWrapper, hooks *conversionHooks) (ConversionJob, error) {
	manifest, err := ReadManifest(filepath.Join(accountPath, ManifestFilename))
	if err != nil {
		return ConversionJob{}, err
	}
	job, err := ReadConversionJob(accountPath, jobID)
	if err != nil {
		return ConversionJob{}, err
	}
	if manifest.ID != job.AccountID {
		return job, fmt.Errorf("%w: manifest does not reference job %s", ErrConversionConflict, job.ID)
	}
	if job.CancelRequested && manifest.State == StateConverting && manifest.ConversionID == job.ID {
		return rollbackConversion(accountPath, manifest, job, ErrConversionCanceled)
	}
	if conversionIsActivated(manifest, job) {
		return completeActivatedConversion(accountPath, job)
	}
	if manifest.State != StateConverting || manifest.ConversionID != job.ID || job.Phase == ConversionCompleted {
		return job, fmt.Errorf("%w: manifest does not reference job %s", ErrConversionConflict, job.ID)
	}
	return runConversion(ctx, accountPath, manifest, job, keys, hooks)
}

func conversionIsActivated(manifest Manifest, job ConversionJob) bool {
	return (job.Phase == ConversionActivating || job.Phase == ConversionCompleted) &&
		manifest.ID == job.AccountID && manifest.Engine == job.TargetEngine && manifest.Encrypted == job.TargetEncrypted &&
		manifest.ActiveGeneration == job.TargetGeneration && manifest.State == job.OriginalState &&
		manifest.ConversionID == ""
}

func completeActivatedConversion(accountPath string, job ConversionJob) (ConversionJob, error) {
	if job.Phase == ConversionCompleted {
		return job, nil
	}
	job.Phase = ConversionCompleted
	job.Error = ""
	job.CompletedAt = time.Now().UTC()
	job.UpdatedAt = job.CompletedAt
	if err := writeConversionJob(accountPath, job); err != nil {
		return job, fmt.Errorf("reconcile activated conversion: %w", err)
	}
	return job, nil
}

// reconcileActivatedConversions closes the final crash window where manifest
// activation reached durable storage but the job's completed phase did not.
func reconcileActivatedConversions(entry Entry) error {
	if entry.Manifest.State == StateConverting {
		return nil
	}
	directory := filepath.Join(entry.Path, "conversions")
	files, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, file := range files {
		id := strings.TrimSuffix(file.Name(), ".json")
		if file.IsDir() || id == file.Name() || !validConversionID(id) {
			continue
		}
		job, err := ReadConversionJob(entry.Path, id)
		if err != nil {
			return err
		}
		if conversionIsActivated(entry.Manifest, job) {
			if _, err := completeActivatedConversion(entry.Path, job); err != nil {
				return err
			}
		}
	}
	return nil
}

// recoverPreparingConversion closes the pre-fence crash windows. A durable
// preparing job is authoritative when the source manifest is still unchanged;
// startup creates or validates its staging generation and publishes the fence
// before the manager starts the ordinary resumable runner.
func recoverPreparingConversion(entry Entry, keys KeyWrapper) (bool, error) {
	if entry.Manifest.State != StateReady && entry.Manifest.State != StateDisabled {
		return false, nil
	}
	directory := filepath.Join(entry.Path, "conversions")
	files, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	jobs := make([]ConversionJob, 0)
	for _, file := range files {
		id := strings.TrimSuffix(file.Name(), ".json")
		if file.IsDir() || id == file.Name() || !validConversionID(id) {
			continue
		}
		job, readErr := ReadConversionJob(entry.Path, id)
		if readErr != nil {
			return false, readErr
		}
		if job.Phase == ConversionPreparing && job.AccountID == entry.Manifest.ID && job.SourceEngine == entry.Manifest.Engine && job.SourceGeneration == entry.Manifest.ActiveGeneration {
			jobs = append(jobs, job)
		}
	}
	if len(jobs) == 0 {
		return false, nil
	}
	slices.SortFunc(jobs, func(a, b ConversionJob) int { return a.CreatedAt.Compare(b.CreatedAt) })
	selected := jobs[0]
	if !SupportedEngine(selected.TargetEngine) || !generationPattern.MatchString(selected.TargetGeneration) {
		return false, errors.New("preparing conversion has invalid target generation")
	}
	for _, superseded := range jobs[1:] {
		superseded.Phase = ConversionFailed
		superseded.Error = "superseded by earlier preparing conversion " + selected.ID
		superseded.UpdatedAt = time.Now().UTC()
		if err := writeConversionJob(entry.Path, superseded); err != nil {
			return false, err
		}
	}
	targetPath := filepath.Join(entry.Path, "generations", selected.TargetGeneration)
	exists, err := safeDirectoryExists(targetPath)
	if err != nil {
		return false, err
	}
	if !exists {
		target, createErr := createGeneration(entry.Path, selected.TargetGeneration, selected.TargetEngine, keys, selected.TargetEncrypted)
		if createErr != nil {
			return false, createErr
		}
		if err := target.Close(); err != nil {
			return false, err
		}
	} else {
		target, openErr := openGenerationWith(entry.Path, selected.TargetGeneration, selected.TargetEngine, keys)
		if openErr != nil {
			return false, openErr
		}
		if err := target.Close(); err != nil {
			return false, err
		}
	}
	manifest := entry.Manifest
	manifest.State = StateConverting
	manifest.ConversionID = selected.ID
	manifest.UpdatedAt = time.Now().UTC()
	if err := WriteManifest(filepath.Join(entry.Path, ManifestFilename), manifest); err != nil {
		return false, err
	}
	return true, nil
}

func runConversion(ctx context.Context, accountPath string, manifest Manifest, job ConversionJob, keys KeyWrapper, hooks *conversionHooks) (ConversionJob, error) {
	manifestPath := filepath.Join(accountPath, ManifestFilename)
	job.Phase = ConversionCopying
	job.Error = ""
	job.UpdatedAt = time.Now().UTC()
	if err := writeConversionJob(accountPath, job); err != nil {
		return job, err
	}
	if err := hooks.hit("copying", job); err != nil {
		return job, err
	}
	source, err := openGenerationWith(accountPath, job.SourceGeneration, job.SourceEngine, keys)
	if err != nil {
		return rollbackConversion(accountPath, manifest, job, err)
	}
	target, err := openGenerationWith(accountPath, job.TargetGeneration, job.TargetEngine, keys)
	if err != nil {
		_ = source.Close()
		return rollbackConversion(accountPath, manifest, job, err)
	}
	if source.Encrypted != job.SourceEncrypted || target.Encrypted != job.TargetEncrypted {
		_ = errors.Join(target.Close(), source.Close())
		return rollbackConversion(accountPath, manifest, job, errors.New("generation encryption does not match the conversion job"))
	}
	lastSaved, lastStats := time.Now(), TransferStats{}
	stats, err := TransferWithProgress(ctx, source, target, func(progress TransferStats) error {
		if progress.NamespacesCompleted == lastStats.NamespacesCompleted && progress.Items-lastStats.Items < 100 && progress.PayloadBytes-lastStats.PayloadBytes < 16<<20 && time.Since(lastSaved) < 500*time.Millisecond {
			return nil
		}
		job.Stats = progress
		job.UpdatedAt = time.Now().UTC()
		if err := writeConversionJob(accountPath, job); err != nil {
			return err
		}
		lastSaved, lastStats = time.Now(), progress
		return conversionCancellation(ctx, accountPath, &job)
	})
	if err != nil {
		_ = target.Close()
		_ = source.Close()
		return rollbackConversion(accountPath, manifest, job, err)
	}
	if err := hooks.hit("copied", job); err != nil {
		_ = target.Close()
		_ = source.Close()
		return job, err
	}
	job.Stats = stats
	job.Phase = ConversionVerifying
	job.UpdatedAt = time.Now().UTC()
	if err := writeConversionJob(accountPath, job); err != nil {
		_ = target.Close()
		_ = source.Close()
		return rollbackConversion(accountPath, manifest, job, err)
	}
	if err := hooks.hit("verifying", job); err != nil {
		_ = target.Close()
		_ = source.Close()
		return job, err
	}
	sourceStats, sourceErr := VerifyTransfer(ctx, source)
	targetStats, targetErr := VerifyTransfer(ctx, target)
	closeErr := errors.Join(target.Close(), source.Close())
	if err := errors.Join(sourceErr, targetErr, closeErr); err != nil {
		return rollbackConversion(accountPath, manifest, job, err)
	}
	if sourceStats.Digest != targetStats.Digest || sourceStats.Items != targetStats.Items || sourceStats.MetadataKeys != targetStats.MetadataKeys {
		return rollbackConversion(accountPath, manifest, job, errors.New("logical source and target verification differ"))
	}
	// Reopen the target to prove the durable representation, not process caches.
	reopened, err := openGenerationWith(accountPath, job.TargetGeneration, job.TargetEngine, keys)
	if err != nil {
		return rollbackConversion(accountPath, manifest, job, err)
	}
	reopenedStats, verifyErr := VerifyTransfer(ctx, reopened)
	closeErr = reopened.Close()
	if err := errors.Join(verifyErr, closeErr); err != nil {
		return rollbackConversion(accountPath, manifest, job, err)
	}
	if reopenedStats.Digest != sourceStats.Digest {
		return rollbackConversion(accountPath, manifest, job, errors.New("reopened target verification differs from source"))
	}
	if err := hooks.hit("verified", job); err != nil {
		return job, err
	}
	if err := conversionCancellation(ctx, accountPath, &job); err != nil {
		return rollbackConversion(accountPath, manifest, job, err)
	}

	job.Phase = ConversionActivating
	job.UpdatedAt = time.Now().UTC()
	if err := writeConversionJob(accountPath, job); err != nil {
		return rollbackConversion(accountPath, manifest, job, err)
	}
	if err := conversionCancellation(ctx, accountPath, &job); err != nil {
		return rollbackConversion(accountPath, manifest, job, err)
	}
	manifest.Engine = job.TargetEngine
	manifest.Encrypted = job.TargetEncrypted
	manifest.ActiveGeneration = job.TargetGeneration
	manifest.State = job.OriginalState
	manifest.ConversionID = ""
	manifest.UpdatedAt = time.Now().UTC()
	if err := WriteManifest(manifestPath, manifest); err != nil {
		return rollbackConversion(accountPath, manifest, job, err)
	}
	job.Phase = ConversionCompleted
	job.CompletedAt = time.Now().UTC()
	job.UpdatedAt = job.CompletedAt
	if err := writeConversionJob(accountPath, job); err != nil {
		// Activation is authoritative; a stale job status must not roll it back.
		return job, fmt.Errorf("account activated but conversion status update failed: %w", err)
	}
	return job, nil
}

func conversionCancellation(ctx context.Context, accountPath string, job *ConversionJob) error {
	if err := ctx.Err(); err != nil {
		job.CancelRequested = true
		return ErrConversionCanceled
	}
	stored, err := ReadConversionJob(accountPath, job.ID)
	if err != nil {
		return err
	}
	if stored.CancelRequested {
		job.CancelRequested = true
		return ErrConversionCanceled
	}
	return nil
}

func failBeforeFence(accountPath string, job ConversionJob, cause error) (ConversionJob, error) {
	job.Phase = ConversionFailed
	if errors.Is(cause, ErrConversionCanceled) || errors.Is(cause, context.Canceled) {
		job.Phase = ConversionCanceled
		job.CancelRequested = true
		cause = ErrConversionCanceled
	}
	job.Error = cause.Error()
	job.UpdatedAt = time.Now().UTC()
	writeErr := writeConversionJob(accountPath, job)
	return job, errors.Join(cause, writeErr)
}

func rollbackConversion(accountPath string, converting Manifest, job ConversionJob, cause error) (ConversionJob, error) {
	manifest := converting
	manifest.Engine = job.SourceEngine
	manifest.Encrypted = job.SourceEncrypted
	manifest.ActiveGeneration = job.SourceGeneration
	manifest.State = job.OriginalState
	manifest.ConversionID = ""
	manifest.UpdatedAt = time.Now().UTC()
	manifestErr := WriteManifest(filepath.Join(accountPath, ManifestFilename), manifest)
	job.Phase = ConversionFailed
	if errors.Is(cause, ErrConversionCanceled) || errors.Is(cause, context.Canceled) {
		job.Phase = ConversionCanceled
		job.CancelRequested = true
		cause = ErrConversionCanceled
	}
	job.Error = cause.Error()
	job.UpdatedAt = time.Now().UTC()
	jobErr := writeConversionJob(accountPath, job)
	return job, errors.Join(cause, manifestErr, jobErr)
}

// OpenActive opens a plaintext account only when its lifecycle state allows
// service. Encrypted accounts open through a Manager.
func OpenActive(entry Entry) (*Generation, error) {
	return openActive(entry, nil)
}

func openActive(entry Entry, keys KeyWrapper) (*Generation, error) {
	if entry.Manifest.State == StateConverting || entry.Manifest.State == StateUnavailable {
		return nil, fmt.Errorf("%w: account state is %s", ErrTemporarilyUnavailable, entry.Manifest.State)
	}
	if entry.Manifest.State == StateDisabled {
		return nil, errors.New("account is disabled")
	}
	return openManifestGeneration(entry, keys)
}

// openManifestGeneration opens the active generation and requires its
// encryption to match the manifest, so a deleted key file is reported
// instead of ciphertext being read as plaintext.
func openManifestGeneration(entry Entry, keys KeyWrapper) (*Generation, error) {
	generation, err := openGenerationWith(entry.Path, entry.Manifest.ActiveGeneration, entry.Manifest.Engine, keys)
	if err != nil {
		return nil, err
	}
	if generation.Encrypted != entry.Manifest.Encrypted {
		return nil, errors.Join(fmt.Errorf("account %s manifest encryption (%t) does not match its generation", entry.Manifest.Login, entry.Manifest.Encrypted), generation.Close())
	}
	return generation, nil
}

func describeStorage(engine store.Backend, encrypted bool) string {
	if encrypted {
		return "encrypted " + string(engine)
	}
	return string(engine)
}

// ReadConversionJob reads one strict durable job record.
func ReadConversionJob(accountPath, jobID string) (ConversionJob, error) {
	if !validConversionID(jobID) {
		return ConversionJob{}, fmt.Errorf("invalid conversion job ID %q", jobID)
	}
	file, err := os.Open(conversionJobPath(accountPath, jobID))
	if err != nil {
		return ConversionJob{}, fmt.Errorf("open conversion job: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestSize+1))
	decoder.DisallowUnknownFields()
	var job ConversionJob
	if err := decoder.Decode(&job); err != nil {
		return ConversionJob{}, fmt.Errorf("decode conversion job: %w", err)
	}
	if !validConversionID(job.ID) || job.ID != jobID || !accountIDPattern.MatchString(job.AccountID) {
		return ConversionJob{}, errors.New("invalid conversion job identity")
	}
	return job, nil
}

func writeConversionJob(accountPath string, job ConversionJob) error {
	if !validConversionID(job.ID) {
		return fmt.Errorf("invalid conversion job ID %q", job.ID)
	}
	if existing, err := ReadConversionJob(accountPath, job.ID); err == nil && existing.CancelRequested {
		job.CancelRequested = true
	}
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return fmt.Errorf("encode conversion job: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(accountPath, "conversions"), 0o700); err != nil {
		return fmt.Errorf("create conversion directory: %w", err)
	}
	if err := writeFileAtomic(conversionJobPath(accountPath, job.ID), append(data, '\n')); err != nil {
		return fmt.Errorf("write conversion job: %w", err)
	}
	return nil
}

func conversionJobPath(accountPath, jobID string) string {
	return filepath.Join(accountPath, "conversions", jobID+".json")
}

func validConversionID(id string) bool {
	if !strings.HasPrefix(id, "cnv_") || len(id) != len("cnv_")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, "cnv_"))
	return err == nil
}
