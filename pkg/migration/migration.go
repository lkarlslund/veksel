// Package migration provides resumable imports into Veksel' generic typed
// folders. Protocol clients implement Source; the runner never depends on a
// remote protocol or local storage backend.
package migration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/keyring"
	veksellog "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const jobNamespace = "migration_jobs"
const credentialNamespace = "sync_job_credentials"
const runNamespace = "sync_job_runs"
const migrationSourceHeader = "X-Veksel-Migration-Source"
const migrationItemHeader = "X-Veksel-Migration-Item"
const migrationFingerprintHeader = "X-Veksel-Migration-Fingerprint"
const sourcePageMaxAttempts = 5
const sourcePageRetryBackoff = 500 * time.Millisecond
const maxRetainedItemFailures = 100

var errCompletedWithErrors = errors.New("sync completed with isolated errors")

// Keep destination-store write locks short enough for interactive API and
// protocol traffic to make progress during large synchronization pages.
const transferCommitChunkSize = 50
const transferCommitChunkBytes = 16 << 20

type State string

// RunOutcome describes one attempt independently from the reusable profile's
// scheduling and lifecycle state.
type RunOutcome string

type Schedule string

type SourceDeletionPolicy string

type ConflictPolicy string

type FolderMappingAction string

const (
	ScheduleManual      Schedule = "manual"
	ScheduleHourly      Schedule = "hourly"
	ScheduleEvery6Hours Schedule = "every_6_hours"
	ScheduleDaily       Schedule = "daily"
	ScheduleWeekly      Schedule = "weekly"
)

const (
	SourceDeletionRetain SourceDeletionPolicy = "retain"
	SourceDeletionTrash  SourceDeletionPolicy = "trash"
)

const (
	ConflictSourceWins      ConflictPolicy = "source_wins"
	ConflictDestinationWins ConflictPolicy = "destination_wins"
	ConflictKeepBoth        ConflictPolicy = "keep_both"
)

const (
	FolderMappingCreate   FolderMappingAction = "create"
	FolderMappingReuse    FolderMappingAction = "reuse"
	FolderMappingConflict FolderMappingAction = "conflict"
)

func (s Schedule) Interval() time.Duration {
	switch s {
	case ScheduleHourly:
		return time.Hour
	case ScheduleEvery6Hours:
		return 6 * time.Hour
	case ScheduleDaily:
		return 24 * time.Hour
	case ScheduleWeekly:
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

func (s Schedule) Valid() bool { return s == ScheduleManual || s.Interval() > 0 }

func (p SourceDeletionPolicy) Valid() bool {
	return p == SourceDeletionRetain || p == SourceDeletionTrash
}

func (p ConflictPolicy) Valid() bool {
	return p == ConflictSourceWins || p == ConflictDestinationWins || p == ConflictKeepBoth
}

const (
	StateDraft               State = "draft"
	StateRunning             State = "running"
	StateInterrupted         State = "interrupted"
	StatePaused              State = "paused"
	StateCredentialsRequired State = "credentials-required"
	StateCompleted           State = "completed"
	StateCompletedWithErrors State = "completed-with-errors"
	StateFailed              State = "failed"
	StateCancelled           State = "cancelled"
)

const (
	RunOutcomeInProgress          RunOutcome = "in_progress"
	RunOutcomeCompleted           RunOutcome = "completed"
	RunOutcomeCompletedWithErrors RunOutcome = "completed_with_errors"
	RunOutcomeFatalFailure        RunOutcome = "fatal_failure"
	RunOutcomePaused              RunOutcome = "paused"
	RunOutcomeCancelled           RunOutcome = "cancelled"
	RunOutcomeInterrupted         RunOutcome = "interrupted"
)

type Folder struct {
	ID            string           `json:"id"`
	ParentID      string           `json:"parent_id,omitempty"`
	Name          string           `json:"name"`
	Type          model.FolderType `json:"type"`
	Special       string           `json:"special,omitempty"`
	Estimate      int64            `json:"estimate"`
	EstimateKnown bool             `json:"estimate_known"`
}

// FolderMapping is one non-mutating source-to-destination planning decision.
// DestinationID is empty when the folder will be created by the run.
type FolderMapping struct {
	SourceFolderID      string              `json:"source_folder_id"`
	SourceParentID      string              `json:"source_parent_id,omitempty"`
	SourceName          string              `json:"source_name"`
	SourceType          model.FolderType    `json:"source_type"`
	DestinationFolderID string              `json:"destination_folder_id,omitempty"`
	DestinationParentID string              `json:"destination_parent_id,omitempty"`
	DestinationName     string              `json:"destination_name,omitempty"`
	DestinationPath     string              `json:"destination_path,omitempty"`
	Action              FolderMappingAction `json:"action"`
	Reason              string              `json:"reason"`
	Transfer            bool                `json:"transfer"`
	Error               string              `json:"error,omitempty"`
}

// Preflight is a dry-run folder plan. It is safe to render before a job is
// created because it performs authorization-aware reads and no mutations.
type Preflight struct {
	Ready              bool            `json:"ready"`
	Mappings           []FolderMapping `json:"mappings"`
	DestinationFolders []model.Folder  `json:"destination_folders"`
	Creates            int             `json:"creates"`
	Reuses             int             `json:"reuses"`
	Conflicts          int             `json:"conflicts"`
}

type Item struct {
	ID           string            `json:"id"`
	Version      string            `json:"version,omitempty"`
	Name         string            `json:"name,omitempty"`
	Data         []byte            `json:"data,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Flags        []string          `json:"flags,omitempty"`
	InternalDate time.Time         `json:"internal_date,omitzero"`
}

// ItemFailure is bounded source-side evidence for one item that could not be
// represented safely. A source may advance a page checkpoint with failures
// only when its protocol proves the failed item boundary and no unseen item can
// be skipped. The runner records the failure but never manufactures content.
type ItemFailure struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

type Page struct {
	Items                   []Item        `json:"items"`
	DeletedIDs              []string      `json:"deleted_ids,omitempty"`
	ItemFailures            []ItemFailure `json:"item_failures,omitempty"`
	Checkpoint              string        `json:"checkpoint,omitempty"`
	Done                    bool          `json:"done"`
	InitialCoverageComplete bool          `json:"initial_coverage_complete,omitempty"`
	SourceExplicitlyEmpty   bool          `json:"source_explicitly_empty,omitempty"`
}

// Source is implemented by IMAP, EWS, and EAS migration clients.
type Source interface {
	ID() string
	Folders(context.Context) ([]Folder, error)
	Items(context.Context, Folder, string) (Page, error)
	Close() error
}

// InventorySource optionally provides a richer folder inventory than the
// transfer path needs, such as protocol-native item estimates.
type InventorySource interface {
	Inventory(context.Context) ([]Folder, error)
}

// ConcurrentFolderSource declares that Items calls for different folders are
// independent. Calls for one folder remain ordered so its checkpoint advances
// serially.
type ConcurrentFolderSource interface {
	FolderConcurrency() int
}

// SourcePressureError marks a source failure caused by transient remote
// pressure, such as throttling, an exhausted retryable HTTP failure, or a
// transport timeout. Protocol clients should return this wrapper only when
// reducing concurrent source requests can help. Deterministic folder and
// protocol errors must remain ordinary errors so one unsupported collection
// cannot serialize unrelated folder transfers.
type SourcePressureError struct {
	Err error
}

func (e *SourcePressureError) Error() string { return e.Err.Error() }
func (e *SourcePressureError) Unwrap() error { return e.Err }

// MarkSourcePressure annotates a retryable source error for the adaptive
// concurrency controller without losing the underlying error identity.
func MarkSourcePressure(err error) error {
	if err == nil {
		return nil
	}
	var pressure *SourcePressureError
	if errors.As(err, &pressure) {
		return err
	}
	return &SourcePressureError{Err: err}
}

func isSourcePressure(err error) bool {
	var pressure *SourcePressureError
	return errors.As(err, &pressure)
}

func Inventory(ctx context.Context, source Source) ([]Folder, error) {
	if inventory, ok := source.(InventorySource); ok {
		return inventory.Inventory(ctx)
	}
	return source.Folders(ctx)
}

// SourceOptions contains ephemeral connection material. It is accepted by
// factories and is never part of a persisted Job.
type SourceOptions struct {
	Endpoint string `json:"endpoint"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLSMode  string `json:"tls_mode,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// ConnectionProfile is the non-secret portion of a source connection. It is
// persisted with a sync job so the job can be run again without retaining the
// source password.
type ConnectionProfile struct {
	Endpoint     string `json:"endpoint"`
	Username     string `json:"username"`
	TLSMode      string `json:"tls_mode,omitempty"`
	Insecure     bool   `json:"insecure,omitempty"`
	PageSize     int    `json:"page_size,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	StateVersion int    `json:"state_version,omitempty"`
}

func NewConnectionProfile(options SourceOptions) ConnectionProfile {
	return ConnectionProfile{
		Endpoint: strings.TrimSpace(options.Endpoint),
		Username: strings.TrimSpace(options.Username),
		TLSMode:  strings.TrimSpace(options.TLSMode),
		Insecure: options.Insecure,
		PageSize: options.PageSize,
		ClientID: options.ClientID,
	}
}

func (p ConnectionProfile) SourceOptions(password string) SourceOptions {
	return SourceOptions{
		Endpoint: p.Endpoint,
		Username: p.Username,
		Password: password,
		TLSMode:  p.TLSMode,
		Insecure: p.Insecure,
		PageSize: p.PageSize,
		ClientID: p.ClientID,
	}
}

type SourceFactory func(context.Context, SourceOptions) (Source, error)

// FolderFailure records a source folder that could not be read during the
// most recent run. Successful folders retain their checkpoints and do not
// need to be transferred again when the profile is retried.
type FolderFailure struct {
	FolderID   string `json:"folder_id"`
	FolderName string `json:"folder_name"`
	Error      string `json:"error"`
}

// FailurePhase identifies the operation that stopped a synchronization run.
// Values are protocol-neutral so every source adapter and UI can use the same
// diagnostic contract.
type FailurePhase string

const (
	FailurePhaseConnect            FailurePhase = "source_connect"
	FailurePhaseInventory          FailurePhase = "source_inventory"
	FailurePhaseDestinationMapping FailurePhase = "destination_mapping"
	FailurePhaseSourceRead         FailurePhase = "source_read"
	FailurePhaseDestinationWrite   FailurePhase = "destination_write"
	FailurePhaseSourceDeletion     FailurePhase = "source_deletion"
	FailurePhaseCheckpoint         FailurePhase = "checkpoint_persist"
	FailurePhaseRun                FailurePhase = "run"
)

// RetryDisposition tells clients what must change before another attempt can
// make progress.
type RetryDisposition string

const (
	RetryRecommended           RetryDisposition = "retry_recommended"
	RetryCredentialsRequired   RetryDisposition = "credentials_required"
	RetryConfigurationRequired RetryDisposition = "configuration_required"
	RetryManualReview          RetryDisposition = "manual_review"
)

// FailureContext supplies structured context for failures that occur before
// the Runner owns a source. Runner failures derive the same fields from typed
// internal errors.
type FailureContext struct {
	Phase      FailurePhase
	FolderID   string
	FolderName string
	ItemID     string
	Checkpoint string
}

// TerminalFailure is bounded, secret-redacted evidence explaining why a run
// stopped and whether repeating it can make progress.
type TerminalFailure struct {
	Message             string           `json:"message"`
	Phase               FailurePhase     `json:"phase"`
	FolderID            string           `json:"folder_id,omitempty"`
	FolderName          string           `json:"folder_name,omitempty"`
	ItemID              string           `json:"item_id,omitempty"`
	Checkpoint          string           `json:"checkpoint,omitempty"`
	OccurredAt          time.Time        `json:"occurred_at"`
	RetryDisposition    RetryDisposition `json:"retry_disposition"`
	RetryRecommended    bool             `json:"retry_recommended"`
	RetryAdvice         string           `json:"retry_advice"`
	CheckpointsRetained bool             `json:"checkpoints_retained"`
}

type FolderReconciliation struct {
	SourceFolderID          string           `json:"source_folder_id"`
	SourceFolderName        string           `json:"source_folder_name"`
	SourceFolderType        model.FolderType `json:"source_folder_type"`
	DestinationFolderID     string           `json:"destination_folder_id"`
	SourceItems             int64            `json:"source_items"`
	SourceItemsKnown        bool             `json:"source_items_known"`
	DestinationItemsBefore  int64            `json:"destination_items_before"`
	DestinationItemsAfter   int64            `json:"destination_items_after"`
	DestinationBytesBefore  int64            `json:"destination_bytes_before"`
	DestinationBytesAfter   int64            `json:"destination_bytes_after"`
	ImportedItems           int64            `json:"imported_items"`
	ImportedBytes           int64            `json:"imported_bytes"`
	SkippedItems            int64            `json:"skipped_items"`
	ExaminedItems           int64            `json:"examined_items"`
	FailedItems             int64            `json:"failed_items"`
	ItemFailures            []ItemFailure    `json:"item_failures,omitempty"`
	RemainingItems          int64            `json:"remaining_items"`
	RemainingItemsKnown     bool             `json:"remaining_items_known"`
	TraversalComplete       bool             `json:"traversal_complete"`
	InitialCoverageComplete bool             `json:"initial_coverage_complete,omitempty"`
	SourceExplicitlyEmpty   bool             `json:"source_explicitly_empty,omitempty"`
	ConflictItems           int64            `json:"conflict_items"`
	PreservedItems          int64            `json:"preserved_items"`
	SourceDeletedItems      int64            `json:"source_deleted_items"`
	TrashedItems            int64            `json:"trashed_items"`
	DriftItems              int64            `json:"drift_items"`
	Checkpoint              string           `json:"checkpoint,omitempty"`
	CheckpointAt            time.Time        `json:"checkpoint_at,omitzero"`
	State                   string           `json:"state"`
	Error                   string           `json:"error,omitempty"`
	StartedAt               time.Time        `json:"started_at"`
	CompletedAt             time.Time        `json:"completed_at"`
}

type Job struct {
	ID                          string                 `json:"id"`
	OwnerID                     string                 `json:"owner_id"`
	DestinationID               string                 `json:"destination_id"`
	SourceType                  string                 `json:"source_type"`
	SourceIdentity              string                 `json:"source_identity"`
	Connection                  ConnectionProfile      `json:"connection"`
	SelectedFolderIDs           []string               `json:"selected_folder_ids,omitempty"`
	Schedule                    Schedule               `json:"schedule,omitempty"`
	SourceDeletionPolicy        SourceDeletionPolicy   `json:"source_deletion_policy,omitempty"`
	ConflictPolicy              ConflictPolicy         `json:"conflict_policy,omitempty"`
	CredentialStored            bool                   `json:"credential_stored"`
	LastRunAt                   time.Time              `json:"last_run_at,omitzero"`
	NextRunAt                   time.Time              `json:"next_run_at,omitzero"`
	State                       State                  `json:"state"`
	FolderMap                   map[string]string      `json:"folder_map,omitempty"`
	FolderTargets               map[string]string      `json:"folder_targets,omitempty"`
	Checkpoints                 map[string]string      `json:"checkpoints,omitempty"`
	IndexedSources              map[string]string      `json:"indexed_sources,omitempty"`
	ImportedItems               int64                  `json:"imported_items"`
	ImportedBytes               int64                  `json:"imported_bytes"`
	SkippedItems                int64                  `json:"skipped_items"`
	ConflictItems               int64                  `json:"conflict_items"`
	PreservedItems              int64                  `json:"preserved_items"`
	RunStartedAt                time.Time              `json:"run_started_at,omitzero"`
	RunFinishedAt               time.Time              `json:"run_finished_at,omitzero"`
	RunOutcome                  RunOutcome             `json:"run_outcome,omitempty"`
	LastSuccessAt               time.Time              `json:"last_success_at,omitzero"`
	RunSourceItems              int64                  `json:"run_source_items"`
	RunSourceItemsKnown         bool                   `json:"run_source_items_known"`
	RunItemsExamined            int64                  `json:"run_items_examined"`
	RunItemsFailed              int64                  `json:"run_items_failed"`
	RunItemsRemaining           int64                  `json:"run_items_remaining"`
	RunItemsRemainingKnown      bool                   `json:"run_items_remaining_known"`
	RunTraversalComplete        bool                   `json:"run_traversal_complete"`
	RunLastCheckpointFolderID   string                 `json:"run_last_checkpoint_folder_id,omitempty"`
	RunLastCheckpointFolderName string                 `json:"run_last_checkpoint_folder_name,omitempty"`
	RunLastCheckpointAt         time.Time              `json:"run_last_checkpoint_at,omitzero"`
	RunFatalError               string                 `json:"run_fatal_error,omitempty"`
	RunTerminalFailure          *TerminalFailure       `json:"run_terminal_failure,omitempty"`
	RunFoldersTotal             int64                  `json:"run_folders_total"`
	RunFoldersDone              int64                  `json:"run_folders_done"`
	RunFoldersFailed            int64                  `json:"run_folders_failed"`
	RunFolderFailures           []FolderFailure        `json:"run_folder_failures,omitempty"`
	RunFolderResults            []FolderReconciliation `json:"run_folder_results,omitempty"`
	RunImportedItems            int64                  `json:"run_imported_items"`
	RunImportedBytes            int64                  `json:"run_imported_bytes"`
	RunSkippedItems             int64                  `json:"run_skipped_items"`
	RunConflictItems            int64                  `json:"run_conflict_items"`
	RunPreservedItems           int64                  `json:"run_preserved_items"`
	SourceDeletedItems          int64                  `json:"source_deleted_items"`
	RunSourceDeletedItems       int64                  `json:"run_source_deleted_items"`
	RunTrashedItems             int64                  `json:"run_trashed_items"`
	RunItemsPerSecond           float64                `json:"run_items_per_second"`
	RunBytesPerSecond           float64                `json:"run_bytes_per_second"`
	SourceConcurrencyHint       int                    `json:"source_concurrency_hint,omitempty"`
	SourceCalls                 int64                  `json:"source_calls"`
	SourceRetryEvents           int64                  `json:"source_retry_events"`
	SourceBackoffMillis         int64                  `json:"source_backoff_millis"`
	RunSourceCalls              int64                  `json:"run_source_calls"`
	RunSourceRetryEvents        int64                  `json:"run_source_retry_events"`
	RunSourceBackoffMs          int64                  `json:"run_source_backoff_millis"`
	RunSourceLatencyMs          int64                  `json:"run_source_latency_millis"`
	RunSourceConcurrency        int                    `json:"run_source_concurrency"`
	RunSourcePeak               int                    `json:"run_source_peak_concurrency"`
	RunSourcePressure           float64                `json:"run_source_pressure"`
	CutoverRequested            bool                   `json:"cutover_requested,omitempty"`
	CutoverState                string                 `json:"cutover_state,omitempty"`
	CutoverAt                   time.Time              `json:"cutover_at,omitzero"`
	LastError                   string                 `json:"last_error,omitempty"`
	CreatedAt                   time.Time              `json:"created_at"`
	UpdatedAt                   time.Time              `json:"updated_at"`
}

// RunRecord is immutable, secret-free fidelity evidence for one completed,
// failed, paused, or interrupted synchronization attempt.
type RunRecord struct {
	ID                       string                 `json:"id"`
	JobID                    string                 `json:"job_id"`
	State                    State                  `json:"state"`
	SourceType               string                 `json:"source_type"`
	SourceIdentity           string                 `json:"source_identity"`
	SourceDeletionPolicy     SourceDeletionPolicy   `json:"source_deletion_policy"`
	ConflictPolicy           ConflictPolicy         `json:"conflict_policy"`
	Cutover                  bool                   `json:"cutover"`
	StartedAt                time.Time              `json:"started_at"`
	FinishedAt               time.Time              `json:"finished_at"`
	Outcome                  RunOutcome             `json:"outcome"`
	SourceItems              int64                  `json:"source_items"`
	SourceItemsKnown         bool                   `json:"source_items_known"`
	ItemsExamined            int64                  `json:"items_examined"`
	ItemsFailed              int64                  `json:"items_failed"`
	ItemsRemaining           int64                  `json:"items_remaining"`
	ItemsRemainingKnown      bool                   `json:"items_remaining_known"`
	TraversalComplete        bool                   `json:"traversal_complete"`
	LastCheckpointFolderID   string                 `json:"last_checkpoint_folder_id,omitempty"`
	LastCheckpointFolderName string                 `json:"last_checkpoint_folder_name,omitempty"`
	LastCheckpointAt         time.Time              `json:"last_checkpoint_at,omitzero"`
	FatalError               string                 `json:"fatal_error,omitempty"`
	TerminalFailure          *TerminalFailure       `json:"terminal_failure,omitempty"`
	FoldersTotal             int64                  `json:"folders_total"`
	FoldersDone              int64                  `json:"folders_done"`
	FoldersFailed            int64                  `json:"folders_failed"`
	ImportedItems            int64                  `json:"imported_items"`
	ImportedBytes            int64                  `json:"imported_bytes"`
	SkippedItems             int64                  `json:"skipped_items"`
	ConflictItems            int64                  `json:"conflict_items"`
	PreservedItems           int64                  `json:"preserved_items"`
	SourceDeletedItems       int64                  `json:"source_deleted_items"`
	TrashedItems             int64                  `json:"trashed_items"`
	ItemsPerSecond           float64                `json:"items_per_second"`
	BytesPerSecond           float64                `json:"bytes_per_second"`
	SourceCalls              int64                  `json:"source_calls"`
	SourceRetryEvents        int64                  `json:"source_retry_events"`
	SourceBackoffMillis      int64                  `json:"source_backoff_millis"`
	SourceLatencyMillis      int64                  `json:"source_latency_millis"`
	SourceConcurrency        int                    `json:"source_concurrency"`
	SourcePeakConcurrency    int                    `json:"source_peak_concurrency"`
	SourcePressure           float64                `json:"source_pressure"`
	FolderFailures           []FolderFailure        `json:"folder_failures,omitempty"`
	FolderResults            []FolderReconciliation `json:"folder_results,omitempty"`
	Error                    string                 `json:"error,omitempty"`
}

type Store struct {
	backend store.Store

	// credentialMu orders credential writes against rotation rewrapping.
	credentialMu sync.RWMutex
	keys         *keyring.Ring
}

func NewStore(ctx context.Context, backend store.Store) (*Store, error) {
	if backend == nil {
		return nil, errors.New("migration store is required")
	}
	exists, err := backend.NamespaceExists(ctx, jobNamespace)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, jobNamespace); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
	}
	exists, err = backend.NamespaceExists(ctx, credentialNamespace)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, credentialNamespace); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
	}
	exists, err = backend.NamespaceExists(ctx, runNamespace)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, runNamespace); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
	}
	keys, err := keyring.For(ctx, backend)
	if err != nil {
		return nil, fmt.Errorf("initialize sync credential encryption: %w", err)
	}
	return &Store{backend: backend, keys: keys}, nil
}

func (s *Store) Create(ctx context.Context, job Job) (Job, error) {
	if strings.TrimSpace(job.OwnerID) == "" || strings.TrimSpace(job.DestinationID) == "" || strings.TrimSpace(job.SourceType) == "" {
		return Job{}, errors.New("owner, destination, and source type are required")
	}
	if job.ID == "" {
		var err error
		job.ID, err = randomID()
		if err != nil {
			return Job{}, err
		}
	}
	if strings.EqualFold(job.SourceType, "eas") {
		if job.Connection.ClientID == "" {
			job.Connection.ClientID = syncClientID(job.ID)
		}
		job.Connection.StateVersion = easStateVersion
	}
	now := time.Now().UTC()
	job.State = StateDraft
	job.CreatedAt = now
	job.UpdatedAt = now
	job.FolderMap = make(map[string]string)
	job.FolderTargets = cloneStringMap(job.FolderTargets)
	job.Checkpoints = make(map[string]string)
	job.IndexedSources = make(map[string]string)
	if job.Schedule == "" {
		job.Schedule = ScheduleManual
	}
	if job.SourceDeletionPolicy == "" {
		job.SourceDeletionPolicy = SourceDeletionRetain
	}
	if !job.SourceDeletionPolicy.Valid() {
		return Job{}, errors.New("invalid source deletion policy")
	}
	if job.ConflictPolicy == "" {
		job.ConflictPolicy = ConflictSourceWins
	}
	if !job.ConflictPolicy.Valid() {
		return Job{}, errors.New("invalid conflict policy")
	}
	data, err := json.Marshal(job)
	if err != nil {
		return Job{}, err
	}
	if err := s.backend.Put(ctx, jobNamespace, job.ID, data); err != nil {
		return Job{}, err
	}
	return job, nil
}

// Version 7 preserves the established EAS device partnership across request-
// semantics upgrades and atomically resets every device-scoped synchronization
// artifact. Version 6 rotated ClientID while retaining source folder ID maps;
// Exchange assigns those IDs within the partnership, so an old ID could then
// point at an unrelated destination folder even though its type still matched.
const easStateVersion = 7

// PrepareRun upgrades EAS jobs to the current checkpoint and mapping format.
// EAS synchronization keys and source-ID keyed mappings cannot safely be mixed
// across request semantics or device partnerships. Preserve an existing device
// identity so selected folder IDs remain meaningful; only legacy jobs without
// one receive the deterministic per-job identity.
func (s *Store) PrepareRun(ctx context.Context, job Job) (Job, error) {
	if !strings.EqualFold(job.SourceType, "eas") || job.Connection.StateVersion >= easStateVersion {
		return job, nil
	}
	if job.Connection.ClientID == "" {
		job.Connection.ClientID = syncClientID(job.ID)
	}
	job.Connection.StateVersion = easStateVersion
	job.Checkpoints = make(map[string]string)
	job.FolderMap = make(map[string]string)
	job.FolderTargets = make(map[string]string)
	job.IndexedSources = make(map[string]string)
	job.ImportedItems = 0
	job.ImportedBytes = 0
	job.SkippedItems = 0
	job.ConflictItems = 0
	job.PreservedItems = 0
	if err := s.Save(ctx, job); err != nil {
		return Job{}, err
	}
	return job, nil
}

func syncClientID(jobID string) string {
	hash := sha256.Sum256([]byte("veksel-sync:" + jobID))
	return strings.ToUpper(hex.EncodeToString(hash[:16]))
}

func (s *Store) Get(ctx context.Context, id string) (Job, error) {
	data, err := s.backend.Get(ctx, jobNamespace, id)
	if err != nil {
		return Job{}, err
	}
	var job Job
	if err := json.Unmarshal(data, &job); err != nil {
		return Job{}, fmt.Errorf("decode migration job: %w", err)
	}
	if job.FolderMap == nil {
		job.FolderMap = make(map[string]string)
	}
	if job.FolderTargets == nil {
		job.FolderTargets = make(map[string]string)
	}
	if job.Checkpoints == nil {
		job.Checkpoints = make(map[string]string)
	}
	if job.IndexedSources == nil {
		job.IndexedSources = make(map[string]string)
	}
	if job.Connection.Endpoint == "" {
		legacy := legacyConnectionProfile(job.SourceType, job.SourceIdentity)
		if legacy.Endpoint != "" {
			legacy.ClientID = job.Connection.ClientID
			job.Connection = legacy
		}
	}
	if job.Schedule == "" {
		job.Schedule = ScheduleManual
	}
	if job.SourceDeletionPolicy == "" {
		job.SourceDeletionPolicy = SourceDeletionRetain
	}
	if job.ConflictPolicy == "" {
		job.ConflictPolicy = ConflictSourceWins
	}
	sanitizeJobDiagnostics(&job)
	if job.RunOutcome == "" && !job.RunStartedAt.IsZero() {
		job.RunOutcome = inferRunOutcome(job.State, len(job.RunFolderFailures), job.RunFoldersTotal, job.RunFoldersDone, job.RunFoldersFailed)
		if job.RunOutcome == RunOutcomeCompleted {
			job.RunTraversalComplete = true
		}
		if job.RunOutcome == RunOutcomeFatalFailure && job.RunFatalError == "" {
			job.RunFatalError = boundedRunError(errors.New(job.LastError))
		}
	}
	if job.RunOutcome == RunOutcomeCompleted && job.LastSuccessAt.IsZero() {
		job.LastSuccessAt = nonZeroTime(job.RunFinishedAt, job.UpdatedAt)
	}
	if job.RunOutcome == RunOutcomeFatalFailure && job.RunTerminalFailure == nil {
		job.RunTerminalFailure = terminalFailure(job, errors.New(job.RunFatalError), nonZeroTime(job.RunFinishedAt, job.UpdatedAt), FailureContext{})
	}
	return job, nil
}

func legacyConnectionProfile(sourceType, identity string) ConnectionProfile {
	sourceType = strings.ToLower(strings.TrimSpace(sourceType))
	prefix := sourceType + "://"
	if !strings.HasPrefix(strings.ToLower(identity), prefix) {
		return ConnectionProfile{}
	}
	remainder := identity[len(prefix):]
	separator := strings.LastIndex(remainder, "@")
	if separator <= 0 || separator == len(remainder)-1 {
		return ConnectionProfile{}
	}
	profile := ConnectionProfile{Username: remainder[:separator], Endpoint: remainder[separator+1:]}
	switch sourceType {
	case "eas", "ews":
		profile.Endpoint = "https://" + profile.Endpoint
		profile.TLSMode = "https"
	case "imap":
		profile.TLSMode = "implicit"
	}
	return profile
}

func (s *Store) Save(ctx context.Context, job Job) error {
	job.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return s.backend.Set(ctx, jobNamespace, job.ID, data)
}

func (s *Store) Delete(ctx context.Context, id string) error {
	s.credentialMu.RLock()
	if err := s.backend.Delete(ctx, credentialNamespace, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.credentialMu.RUnlock()
		return err
	}
	s.credentialMu.RUnlock()
	if err := s.backend.Delete(ctx, jobNamespace, id); err != nil {
		return err
	}
	keys, err := s.backend.List(ctx, runNamespace)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if strings.HasPrefix(key, id+":") {
			if err := s.backend.Delete(ctx, runNamespace, key); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
	}
	return nil
}

func runRecordFromJob(job Job) RunRecord {
	id := fmt.Sprintf("%s:%020d", job.ID, job.RunStartedAt.UnixNano())
	return RunRecord{
		ID: id, JobID: job.ID, State: job.State, SourceType: job.SourceType, SourceIdentity: job.SourceIdentity,
		SourceDeletionPolicy: job.SourceDeletionPolicy, ConflictPolicy: job.ConflictPolicy, Cutover: job.CutoverRequested,
		StartedAt: job.RunStartedAt, FinishedAt: job.RunFinishedAt,
		Outcome: job.RunOutcome, SourceItems: job.RunSourceItems, SourceItemsKnown: job.RunSourceItemsKnown,
		ItemsExamined: job.RunItemsExamined, ItemsFailed: job.RunItemsFailed,
		ItemsRemaining: job.RunItemsRemaining, ItemsRemainingKnown: job.RunItemsRemainingKnown,
		TraversalComplete:      job.RunTraversalComplete,
		LastCheckpointFolderID: job.RunLastCheckpointFolderID, LastCheckpointFolderName: job.RunLastCheckpointFolderName,
		LastCheckpointAt: job.RunLastCheckpointAt, FatalError: job.RunFatalError, TerminalFailure: cloneTerminalFailure(job.RunTerminalFailure),
		FoldersTotal: job.RunFoldersTotal, FoldersDone: job.RunFoldersDone, FoldersFailed: job.RunFoldersFailed,
		ImportedItems: job.RunImportedItems, ImportedBytes: job.RunImportedBytes, SkippedItems: job.RunSkippedItems,
		ConflictItems: job.RunConflictItems, PreservedItems: job.RunPreservedItems,
		SourceDeletedItems: job.RunSourceDeletedItems, TrashedItems: job.RunTrashedItems,
		ItemsPerSecond: job.RunItemsPerSecond, BytesPerSecond: job.RunBytesPerSecond,
		SourceCalls: job.RunSourceCalls, SourceRetryEvents: job.RunSourceRetryEvents,
		SourceBackoffMillis: job.RunSourceBackoffMs, SourceLatencyMillis: job.RunSourceLatencyMs,
		SourceConcurrency: job.RunSourceConcurrency, SourcePeakConcurrency: job.RunSourcePeak,
		SourcePressure: job.RunSourcePressure,
		FolderFailures: append([]FolderFailure(nil), job.RunFolderFailures...),
		FolderResults:  append([]FolderReconciliation(nil), job.RunFolderResults...), Error: job.LastError,
	}
}

func (s *Store) SaveRun(ctx context.Context, job Job) error {
	if job.ID == "" || job.RunStartedAt.IsZero() || job.RunFinishedAt.IsZero() {
		return errors.New("completed sync run identity and timestamps are required")
	}
	record := runRecordFromJob(job)
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.backend.Set(ctx, runNamespace, record.ID, data)
}

// RecordFatalAttempt retains evidence when a run cannot construct or connect
// its source. Those failures happen before Runner.Run owns a Source, but they
// are still real attempts and must not look like an unexplained profile state.
func (s *Store) RecordFatalAttempt(ctx context.Context, jobID string, runErr error, failureContext ...FailureContext) (Job, error) {
	if runErr == nil {
		return Job{}, errors.New("fatal sync error is required")
	}
	job, err := s.Get(ctx, jobID)
	if err != nil {
		return Job{}, err
	}
	now := time.Now().UTC()
	resetRunTelemetry(&job, now)
	job.State = StateFailed
	job.RunOutcome = RunOutcomeFatalFailure
	context := FailureContext{Phase: FailurePhaseConnect}
	if len(failureContext) > 0 {
		context = failureContext[0]
	}
	job.RunTerminalFailure = terminalFailure(job, runErr, now, context)
	job.RunFatalError = job.RunTerminalFailure.Message
	job.LastError = job.RunFatalError
	finishRun(&job, now)
	if job.CutoverRequested {
		job.CutoverState = "failed"
	}
	logRunOutcome(job)
	if err := s.Save(ctx, job); err != nil {
		return Job{}, err
	}
	if err := s.SaveRun(ctx, job); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (s *Store) Runs(ctx context.Context, jobID string, limit int) ([]RunRecord, error) {
	runs, _, _, err := s.RunsPage(ctx, jobID, "", limit)
	return runs, err
}

// Run returns one retained run with its full folder-level evidence.
func (s *Store) Run(ctx context.Context, jobID, runID string) (RunRecord, error) {
	prefix := strings.TrimSpace(jobID) + ":"
	if strings.TrimSpace(jobID) == "" || !strings.HasPrefix(runID, prefix) {
		return RunRecord{}, store.ErrNotFound
	}
	data, err := s.backend.Get(ctx, runNamespace, runID)
	if err != nil {
		return RunRecord{}, err
	}
	return decodeRunRecord(runID, data)
}

// RunsPage returns one newest-first page of immutable run evidence. before is
// the oldest included run ID from the previous page. Run IDs contain a fixed-
// width start timestamp, so their key order is also their chronological order.
// Only records in the requested page are read and decoded.
func (s *Store) RunsPage(ctx context.Context, jobID, before string, limit int) ([]RunRecord, int, string, error) {
	if strings.TrimSpace(jobID) == "" {
		return nil, 0, "", errors.New("sync job ID is required")
	}
	if limit < 1 {
		limit = 20
	}
	limit = min(limit, 100)
	prefix := jobID + ":"
	if before != "" && !strings.HasPrefix(before, prefix) {
		return nil, 0, "", errors.New("sync run cursor does not belong to this job")
	}
	var records []RunRecord
	var total int
	var nextBefore string
	err := store.View(ctx, s.backend, func(viewCtx context.Context) error {
		keys, scanErr := s.backend.Scan(viewCtx, runNamespace, prefix)
		if scanErr != nil {
			return scanErr
		}
		total = len(keys)
		start := total - 1
		if before != "" {
			cursorIndex := sort.SearchStrings(keys, before)
			if cursorIndex >= len(keys) || keys[cursorIndex] != before {
				return errors.New("sync run cursor is no longer available")
			}
			start = cursorIndex - 1
		}
		if start < 0 {
			records = []RunRecord{}
			return nil
		}
		first := max(0, start-limit+1)
		records = make([]RunRecord, 0, start-first+1)
		for index := start; index >= first; index-- {
			key := keys[index]
			data, getErr := s.backend.Get(viewCtx, runNamespace, key)
			if getErr != nil {
				return getErr
			}
			record, decodeErr := decodeRunRecord(key, data)
			if decodeErr != nil {
				return decodeErr
			}
			records = append(records, record)
		}
		if first > 0 {
			nextBefore = keys[first]
		}
		return nil
	})
	if err != nil {
		return nil, 0, "", err
	}
	return records, total, nextBefore, nil
}

func decodeRunRecord(key string, data []byte) (RunRecord, error) {
	var record RunRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return RunRecord{}, fmt.Errorf("decode sync run %q: %w", key, err)
	}
	sanitizeRunRecordDiagnostics(&record)
	if record.Outcome == "" {
		record.Outcome = inferRunOutcome(record.State, len(record.FolderFailures), record.FoldersTotal, record.FoldersDone, record.FoldersFailed)
		if record.Outcome == RunOutcomeCompleted {
			record.TraversalComplete = true
		}
		if record.Outcome == RunOutcomeFatalFailure && record.FatalError == "" {
			record.FatalError = boundedRunError(errors.New(record.Error))
		}
	}
	if record.Outcome == RunOutcomeFatalFailure && record.TerminalFailure == nil {
		legacy := Job{RunFatalError: record.FatalError, RunFinishedAt: record.FinishedAt, RunLastCheckpointFolderID: record.LastCheckpointFolderID, RunLastCheckpointFolderName: record.LastCheckpointFolderName, RunLastCheckpointAt: record.LastCheckpointAt, RunFolderFailures: record.FolderFailures}
		record.TerminalFailure = terminalFailure(legacy, errors.New(record.FatalError), record.FinishedAt, FailureContext{})
	}
	return record, nil
}

func (s *Store) SaveCredential(ctx context.Context, id, password string) error {
	if strings.TrimSpace(password) == "" {
		return errors.New("password is required")
	}
	s.credentialMu.RLock()
	defer s.credentialMu.RUnlock()
	sealed, err := s.sealCredential(id, password)
	if err != nil {
		return err
	}
	return s.backend.Set(ctx, credentialNamespace, id, sealed)
}

func (s *Store) Credential(ctx context.Context, id string) (string, error) {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()
	data, err := s.backend.Get(ctx, credentialNamespace, id)
	if err != nil {
		return "", err
	}
	password, legacy, err := s.openCredential(id, data)
	if err != nil {
		return "", err
	}
	if legacy {
		sealed, err := s.sealCredential(id, password)
		if err != nil {
			return "", err
		}
		if err := s.backend.Set(ctx, credentialNamespace, id, sealed); err != nil {
			return "", fmt.Errorf("upgrade legacy sync credential: %w", err)
		}
	}
	return password, nil
}

func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	s.credentialMu.RLock()
	defer s.credentialMu.RUnlock()
	err := s.backend.Delete(ctx, credentialNamespace, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

func (s *Store) List(ctx context.Context, ownerID string) ([]Job, error) {
	keys, err := s.backend.List(ctx, jobNamespace)
	if err != nil {
		return nil, err
	}
	jobs := make([]Job, 0, len(keys))
	for _, key := range keys {
		job, err := s.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		if ownerID == "" || job.OwnerID == ownerID {
			jobs = append(jobs, job)
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.After(jobs[j].CreatedAt) })
	return jobs, nil
}

// MarkInterrupted moves jobs left running by a stopped process into a state
// that the scheduler resumes immediately. A job without a usable persisted
// credential cannot resume unattended and is made actionable instead.
func (s *Store) MarkInterrupted(ctx context.Context) error {
	jobs, err := s.List(ctx, "")
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job.State == StateRunning {
			job.State = StateInterrupted
			job.RunOutcome = RunOutcomeInterrupted
			job.LastError = "sync interrupted by server restart; resuming automatically"
			if !job.CredentialStored {
				job.State = StateCredentialsRequired
				job.LastError = "sync interrupted by server restart; password is required to resume"
			} else if _, err := s.Credential(ctx, job.ID); err != nil {
				job.State = StateCredentialsRequired
				job.CredentialStored = false
				job.LastError = "stored sync credential is unavailable after restart"
			}
			if !job.RunStartedAt.IsZero() {
				finishRun(&job, time.Now().UTC())
			}
			if err := s.Save(ctx, job); err != nil {
				return err
			}
			if !job.RunStartedAt.IsZero() {
				if err := s.SaveRun(ctx, job); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type Runner struct {
	jobs  *Store
	space service.FolderSpace

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func NewRunner(jobs *Store, space service.FolderSpace) *Runner {
	return &Runner{jobs: jobs, space: space, cancels: make(map[string]context.CancelFunc)}
}

func (r *Runner) Run(ctx context.Context, jobID string, source Source) error {
	if source == nil {
		return errors.New("migration source is required")
	}
	defer func() { _ = source.Close() }()
	job, err := r.jobs.Get(ctx, jobID)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	if _, running := r.cancels[jobID]; running {
		r.mu.Unlock()
		cancel()
		return errors.New("migration job is already running")
	}
	r.cancels[jobID] = cancel
	r.mu.Unlock()
	defer func() {
		cancel()
		r.mu.Lock()
		delete(r.cancels, jobID)
		r.mu.Unlock()
	}()

	resetRunTelemetry(&job, time.Now().UTC())
	job.SourceIdentity = source.ID()
	if job.CutoverRequested {
		job.CutoverState = "running"
	}
	if err := r.jobs.Save(ctx, job); err != nil {
		return err
	}
	syncLog.Info("sync run started", "job", job.ID, "owner", job.OwnerID, "source", job.SourceType, "identity", job.SourceIdentity)
	if err := r.run(runCtx, &job, source); err != nil {
		finishRun(&job, time.Now().UTC())
		if errors.Is(err, errCompletedWithErrors) {
			job.State = StateCompletedWithErrors
			job.RunOutcome = RunOutcomeCompletedWithErrors
			if job.RunFoldersFailed > 0 {
				job.LastError = fmt.Sprintf("%d source folder(s) could not be fully traversed; successful folders and checkpoints were retained", job.RunFoldersFailed)
			} else {
				job.LastError = fmt.Sprintf("all folders were traversed; %d source item(s) were skipped with terminal errors", job.RunItemsFailed)
			}
			if job.CutoverRequested {
				job.CutoverState = "failed"
			}
			return r.persistRun(context.WithoutCancel(ctx), job)
		}
		if ctx.Err() != nil {
			// During graceful shutdown, dependent services may close before an
			// in-flight destination operation observes the parent cancellation.
			// The parent context is authoritative: retain the checkpoint and let
			// the scheduler resume instead of recording that secondary error as
			// a fatal sync failure.
			job.State = StateInterrupted
			job.RunOutcome = RunOutcomeInterrupted
			job.LastError = "sync interrupted by server restart; resuming automatically"
		} else if errors.Is(err, context.Canceled) {
			job.State = StatePaused
			job.RunOutcome = RunOutcomePaused
			job.LastError = "sync paused before the source inventory was fully traversed"
		} else {
			job.State = StateFailed
			job.RunOutcome = RunOutcomeFatalFailure
			job.RunTerminalFailure = terminalFailure(job, err, job.RunFinishedAt, FailureContext{})
			job.RunFatalError = job.RunTerminalFailure.Message
			job.LastError = job.RunFatalError
		}
		if job.CutoverRequested {
			job.CutoverState = "failed"
		}
		persistErr := r.persistRun(context.WithoutCancel(ctx), job)
		return errors.Join(err, persistErr)
	}
	job.State = StateCompleted
	job.RunOutcome = RunOutcomeCompleted
	job.RunTraversalComplete = true
	finishRun(&job, time.Now().UTC())
	job.LastSuccessAt = job.RunFinishedAt
	if job.CutoverRequested {
		job.CutoverState = "completed"
		job.CutoverAt = job.RunFinishedAt
		job.Schedule = ScheduleManual
		job.NextRunAt = time.Time{}
	}
	return r.persistRun(ctx, job)
}

func resetRunTelemetry(job *Job, now time.Time) {
	job.State = StateRunning
	job.LastRunAt = now
	job.RunStartedAt = now
	job.RunFinishedAt = time.Time{}
	job.RunOutcome = RunOutcomeInProgress
	job.RunSourceItems = 0
	job.RunSourceItemsKnown = false
	job.RunItemsExamined = 0
	job.RunItemsFailed = 0
	job.RunItemsRemaining = 0
	job.RunItemsRemainingKnown = false
	job.RunTraversalComplete = false
	job.RunLastCheckpointFolderID = ""
	job.RunLastCheckpointFolderName = ""
	job.RunLastCheckpointAt = time.Time{}
	job.RunFatalError = ""
	job.RunTerminalFailure = nil
	job.RunFoldersTotal = 0
	job.RunFoldersDone = 0
	job.RunFoldersFailed = 0
	job.RunFolderFailures = nil
	job.RunFolderResults = nil
	job.RunImportedItems = 0
	job.RunImportedBytes = 0
	job.RunSkippedItems = 0
	job.RunConflictItems = 0
	job.RunPreservedItems = 0
	job.RunSourceDeletedItems = 0
	job.RunTrashedItems = 0
	job.RunItemsPerSecond = 0
	job.RunBytesPerSecond = 0
	job.RunSourceCalls = 0
	job.RunSourceRetryEvents = 0
	job.RunSourceBackoffMs = 0
	job.RunSourceLatencyMs = 0
	job.RunSourceConcurrency = 0
	job.RunSourcePeak = 0
	job.RunSourcePressure = 0
	job.LastError = ""
}

var syncLog = veksellog.For(veksellog.ModuleSync)

// logRunOutcome records how a synchronization run ended, so failures are
// in the log and not only on the job.
func logRunOutcome(job Job) {
	attrs := []any{"job", job.ID, "owner", job.OwnerID, "source", job.SourceType, "identity", job.SourceIdentity,
		"outcome", job.RunOutcome, "examined", job.RunItemsExamined, "failed", job.RunItemsFailed, "folders_failed", job.RunFoldersFailed,
		"duration", job.RunFinishedAt.Sub(job.RunStartedAt).Round(time.Millisecond)}
	if failure := job.RunTerminalFailure; failure != nil {
		attrs = append(attrs, "phase", failure.Phase, "retry", failure.RetryDisposition, "error", failure.Message)
	} else if job.LastError != "" && job.RunOutcome != RunOutcomeCompleted {
		attrs = append(attrs, "error", job.LastError)
	}
	switch job.RunOutcome {
	case RunOutcomeCompleted:
		syncLog.Info("sync run completed", attrs...)
	case RunOutcomeInterrupted, RunOutcomePaused:
		syncLog.Info("sync run stopped", attrs...)
	default:
		syncLog.Warn("sync run failed", attrs...)
	}
}

func (r *Runner) persistRun(ctx context.Context, job Job) error {
	logRunOutcome(job)
	if err := r.jobs.Save(ctx, job); err != nil {
		return err
	}
	return r.jobs.SaveRun(ctx, job)
}

func (r *Runner) Pause(jobID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cancel, ok := r.cancels[jobID]
	if ok {
		cancel()
	}
	return ok
}

func (r *Runner) run(ctx context.Context, job *Job, source Source) error {
	folders, err := source.Folders(ctx)
	if err != nil {
		return &failureContextError{context: FailureContext{Phase: FailurePhaseInventory}, err: fmt.Errorf("discover source folders: %w", err)}
	}
	sort.SliceStable(folders, func(i, j int) bool { return folderDepth(folders[i], folders) < folderDepth(folders[j], folders) })
	access := service.UserAccess(job.DestinationID, "migration")
	selected := selectedFolderSet(job.SelectedFolderIDs)
	required := requiredFolderSet(folders, selected)
	type transfer struct {
		source      Folder
		destination string
	}
	transfers := make([]transfer, 0, len(folders))
	for _, sourceFolder := range folders {
		if len(selected) > 0 {
			if _, ok := required[sourceFolder.ID]; !ok {
				continue
			}
		}
		destinationID, err := r.ensureFolder(ctx, access, job, sourceFolder)
		if err != nil {
			return &failureContextError{context: FailureContext{Phase: FailurePhaseDestinationMapping, FolderID: sourceFolder.ID, FolderName: sourceFolder.Name}, err: err}
		}
		if len(selected) > 0 {
			if _, ok := selected[sourceFolder.ID]; !ok {
				continue
			}
		}
		transfers = append(transfers, transfer{source: sourceFolder, destination: destinationID})
	}
	// Small personal-data collections must not be starved behind very large
	// mail trees. This also lets their independent checkpoints complete before
	// a heavily loaded source asks the whole client to back off.
	sort.SliceStable(transfers, func(i, j int) bool {
		return migrationFolderPriority(transfers[i].source.Type) < migrationFolderPriority(transfers[j].source.Type)
	})
	job.RunSourceItemsKnown = true
	for _, transfer := range transfers {
		// Protocol checkpoints usually represent an incremental change feed. A
		// folder's advertised total then is not the number this attempt must
		// examine, so do not manufacture a percentage from incomparable values.
		if !transfer.source.EstimateKnown || job.Checkpoints[transfer.source.ID] != "" {
			job.RunSourceItemsKnown = false
			continue
		}
		job.RunSourceItems += max(0, transfer.source.Estimate)
	}
	if !job.RunSourceItemsKnown {
		job.RunSourceItems = 0
	}
	job.RunItemsRemainingKnown = job.RunSourceItemsKnown
	if job.RunItemsRemainingKnown {
		job.RunItemsRemaining = job.RunSourceItems
	}

	concurrency := 1
	if concurrent, ok := source.(ConcurrentFolderSource); ok {
		concurrency = concurrent.FolderConcurrency()
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(transfers) {
		concurrency = len(transfers)
	}
	if concurrency == 0 {
		job.RunFoldersTotal = 0
		job.RunTraversalComplete = true
		return r.jobs.Save(ctx, *job)
	}
	controller := newSourceConcurrencyController(concurrency, job.SourceConcurrencyHint)
	job.RunFoldersTotal = int64(len(transfers))
	job.RunSourceConcurrency = controller.limitValue()
	job.RunSourcePeak = controller.peakValue()
	if err := r.jobs.Save(ctx, *job); err != nil {
		return err
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	tasks := make(chan transfer)
	var jobMu sync.Mutex
	var workers sync.WaitGroup
	var errorOnce sync.Once
	var firstError error
	stopTasks := make(chan struct{})
	var stopTasksOnce sync.Once
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range tasks {
				result, err := r.transferFolder(workerCtx, source, access, job, &jobMu, controller, task.source, task.destination)
				if err != nil {
					var sourceError *sourceFolderReadError
					if workerCtx.Err() == nil {
						recordErr := r.failFolder(workerCtx, job, &jobMu, task.source, result, err)
						// A deterministic collection failure is isolated, so retain its
						// evidence and continue other folders. Persistent global source
						// pressure is not folder-local: abort the run after recording it
						// instead of issuing the same doomed request for every folder.
						if errors.As(err, &sourceError) && !isSourcePressure(err) && recordErr == nil {
							continue
						}
						if recordErr != nil {
							err = recordErr
						}
					}
					wonTerminal := false
					errorOnce.Do(func() {
						firstError = err
						wonTerminal = true
					})
					if wonTerminal && isSourcePressure(err) {
						// Stop feeding the overloaded source, but do not cancel
						// unrelated requests already in flight. They may be expensive
						// initial collections whose durable checkpoint would otherwise
						// be starved by one pressured folder on every retry.
						stopTasksOnce.Do(func() { close(stopTasks) })
					} else if wonTerminal {
						cancel()
					}
					return
				}
				if err := r.completeFolder(workerCtx, job, &jobMu, result); err != nil {
					errorOnce.Do(func() {
						firstError = err
						cancel()
					})
					return
				}
			}
		}()
	}
taskLoop:
	for _, task := range transfers {
		select {
		case tasks <- task:
		case <-stopTasks:
			break taskLoop
		case <-workerCtx.Done():
			break taskLoop
		}
	}
	close(tasks)
	workers.Wait()
	if firstError != nil {
		return firstError
	}
	if len(job.RunFolderFailures) > 0 {
		return fmt.Errorf("%w: %d source folder(s) failed", errCompletedWithErrors, len(job.RunFolderFailures))
	}
	job.RunTraversalComplete = true
	if job.RunItemsFailed > 0 {
		return fmt.Errorf("%w: %d source item(s) failed terminally", errCompletedWithErrors, job.RunItemsFailed)
	}
	return workerCtx.Err()
}

func migrationFolderPriority(folderType model.FolderType) int {
	switch folderType {
	case model.FolderTypeCalendar:
		return 0
	case model.FolderTypeContacts:
		return 1
	case model.FolderTypeNotes:
		return 2
	case model.FolderTypeFiles:
		return 3
	default:
		return 4
	}
}

type sourceFolderReadError struct {
	folder Folder
	err    error
}

func (e *sourceFolderReadError) Error() string {
	return fmt.Sprintf("read source folder %q: %v", e.folder.Name, e.err)
}

func (e *sourceFolderReadError) Unwrap() error { return e.err }

type failureContextError struct {
	context FailureContext
	err     error
}

func (e *failureContextError) Error() string { return e.err.Error() }
func (e *failureContextError) Unwrap() error { return e.err }

func (r *Runner) transferFolder(ctx context.Context, source Source, access service.AccessContext, job *Job, jobMu *sync.Mutex, controller *sourceConcurrencyController, folder Folder, destinationID string) (FolderReconciliation, error) {
	jobMu.Lock()
	initialCheckpoint := job.Checkpoints[folder.ID]
	jobMu.Unlock()
	estimateKnown := folder.EstimateKnown && initialCheckpoint == ""
	result := FolderReconciliation{
		SourceFolderID: folder.ID, SourceFolderName: folder.Name, SourceFolderType: folder.Type,
		DestinationFolderID: destinationID, SourceItems: folder.Estimate, SourceItemsKnown: estimateKnown,
		RemainingItems: max(0, folder.Estimate), RemainingItemsKnown: estimateKnown,
		State: "running", StartedAt: time.Now().UTC(),
	}
	destination, err := r.space.GetFolder(ctx, access, destinationID)
	if err != nil {
		result.State, result.Error, result.CompletedAt = "failed", err.Error(), time.Now().UTC()
		return result, &failureContextError{context: FailureContext{Phase: FailurePhaseDestinationMapping, FolderID: folder.ID, FolderName: folder.Name}, err: err}
	}
	result.DestinationItemsBefore = destination.ItemCount
	result.DestinationBytesBefore = destination.LogicalBytes
	if err := r.ensureExternalIndex(ctx, source.ID(), access, job, jobMu, folder.ID, destinationID); err != nil {
		return r.finishFolderReconciliation(ctx, access, result, "", &failureContextError{context: FailureContext{Phase: FailurePhaseDestinationMapping, FolderID: folder.ID, FolderName: folder.Name}, err: err})
	}
	for {
		jobMu.Lock()
		previousCheckpoint := job.Checkpoints[folder.ID]
		jobMu.Unlock()
		if err := controller.acquire(ctx); err != nil {
			return r.finishFolderReconciliation(ctx, access, result, previousCheckpoint, err)
		}
		page, readStats, err := readAdvancingPageObserved(ctx, source, folder, previousCheckpoint, sourcePageMaxAttempts, sourcePageRetryBackoff)
		controller.release(readStats, err)
		recordSourceRead(job, jobMu, controller, readStats)
		if err != nil {
			return r.finishFolderReconciliation(ctx, access, result, previousCheckpoint, &sourceFolderReadError{folder: folder, err: err})
		}
		committed, err := r.commitPage(ctx, access, source.ID(), job, jobMu, folder.ID, folder.Name, destinationID, page)
		result.ImportedItems += committed.importedItems
		result.ImportedBytes += committed.importedBytes
		result.SkippedItems += committed.skippedItems
		result.ExaminedItems += committed.importedItems + committed.skippedItems + committed.failedItems
		result.FailedItems += committed.failedItems
		result.ItemFailures = append(result.ItemFailures, committed.itemFailures...)
		if page.InitialCoverageComplete {
			result.InitialCoverageComplete = true
			result.SourceExplicitlyEmpty = page.SourceExplicitlyEmpty
			if page.SourceExplicitlyEmpty {
				result.SourceItemsKnown = true
				result.SourceItems = 0
				result.RemainingItemsKnown = true
				result.RemainingItems = 0
			}
		}
		if result.RemainingItemsKnown {
			result.RemainingItems = max(0, result.SourceItems-result.ExaminedItems)
		}
		if !committed.checkpointAt.IsZero() {
			result.Checkpoint = page.Checkpoint
			result.CheckpointAt = committed.checkpointAt
		}
		result.ConflictItems += committed.conflictItems
		result.PreservedItems += committed.preservedItems
		result.SourceDeletedItems += committed.sourceDeletedItems
		result.TrashedItems += committed.trashedItems
		if err != nil {
			return r.finishFolderReconciliation(ctx, access, result, previousCheckpoint, err)
		}
		if page.Done {
			result.TraversalComplete = true
			return r.finishFolderReconciliation(ctx, access, result, page.Checkpoint, nil)
		}
	}
}

func (r *Runner) finishFolderReconciliation(ctx context.Context, access service.AccessContext, result FolderReconciliation, checkpoint string, failure error) (FolderReconciliation, error) {
	destination, err := r.space.GetFolder(ctx, access, result.DestinationFolderID)
	if err != nil && failure == nil {
		failure = err
	}
	if err == nil {
		result.DestinationItemsAfter = destination.ItemCount
		result.DestinationBytesAfter = destination.LogicalBytes
	}
	result.Checkpoint = checkpoint
	result.CompletedAt = time.Now().UTC()
	if failure != nil {
		result.State, result.Error = "failed", boundedRunError(failure)
		return result, failure
	}
	if result.FailedItems > 0 {
		result.State = "completed_with_errors"
		result.Error = fmt.Sprintf("%d source item(s) were skipped with terminal errors; traversal completed", result.FailedItems)
		return result, nil
	}
	if !result.SourceItemsKnown {
		result.State = "unverified"
	} else {
		result.DriftItems = result.DestinationItemsAfter - result.SourceItems
		result.State = "matched"
		if result.DriftItems != 0 {
			result.State = "drift"
		}
	}
	return result, nil
}

func (r *Runner) failFolder(ctx context.Context, job *Job, jobMu *sync.Mutex, folder Folder, result FolderReconciliation, failure error) error {
	jobMu.Lock()
	defer jobMu.Unlock()
	updatedJob := *job
	updatedJob.RunFoldersFailed++
	updatedJob.RunFolderResults = append(append([]FolderReconciliation(nil), job.RunFolderResults...), result)
	updatedJob.RunFolderFailures = append(append([]FolderFailure(nil), job.RunFolderFailures...), FolderFailure{
		FolderID: folder.ID, FolderName: folder.Name, Error: boundedRunError(failure),
	})
	updateRunRates(&updatedJob, time.Now().UTC())
	if err := r.jobs.Save(ctx, updatedJob); err != nil {
		return err
	}
	*job = updatedJob
	return nil
}

type pageCommitResult struct {
	importedItems, importedBytes, skippedItems, failedItems int64
	conflictItems, preservedItems                           int64
	sourceDeletedItems, trashedItems                        int64
	itemFailures                                            []ItemFailure
	checkpointAt                                            time.Time
}

func (r *Runner) commitPage(ctx context.Context, access service.AccessContext, sourceID string, job *Job, jobMu *sync.Mutex, sourceFolderID, sourceFolderName, destinationID string, page Page) (result pageCommitResult, err error) {
	trashLookup := sourceDeletionTrashLookup{}
	itemFailures := boundedItemFailures(page.ItemFailures)
	itemFailureCount := int64(len(page.ItemFailures))
	for start := 0; start < len(page.DeletedIDs); start += transferCommitChunkSize {
		end := min(start+transferCommitChunkSize, len(page.DeletedIDs))
		for _, externalID := range page.DeletedIDs[start:end] {
			found, err := r.applySourceDeletion(ctx, access, sourceID, destinationID, externalID, job.SourceDeletionPolicy, &trashLookup)
			if err != nil {
				return result, &failureContextError{context: FailureContext{Phase: FailurePhaseSourceDeletion, FolderID: sourceFolderID, FolderName: sourceFolderName, ItemID: externalID, Checkpoint: page.Checkpoint}, err: fmt.Errorf("apply source deletion %q: %w", externalID, err)}
			}
			result.sourceDeletedItems++
			if found && job.SourceDeletionPolicy == SourceDeletionTrash {
				result.trashedItems++
			}
		}
	}
	for start := 0; start < len(page.Items) || start == 0; {
		end := transferChunkEnd(page.Items, start)
		finalChunk := end == len(page.Items)
		var chunk pageCommitResult
		items := page.Items[start:end]
		// Account data and the system job catalog can use different backends.
		// Import through the durable FolderSpace without a cross-store batch;
		// conflict-free appends may use its account-local batch capability.
		// External IDs make a retry safe if progress persistence fails afterward.
		if len(items) > 0 && r.createNewItems(ctx, access, sourceID, destinationID, items) {
			for _, item := range items {
				chunk.importedItems++
				chunk.importedBytes += int64(len(item.Data))
			}
			items = nil
		}
		for _, item := range items {
			outcome, err := r.importItem(ctx, access, sourceID, destinationID, item, job.ConflictPolicy)
			if err != nil {
				chunk.failedItems = 1
				_, persistErr := r.persistPageProgress(ctx, job, jobMu, sourceFolderID, sourceFolderName, page, false, chunk)
				result.add(chunk)
				failure := &failureContextError{context: FailureContext{Phase: FailurePhaseDestinationWrite, FolderID: sourceFolderID, FolderName: sourceFolderName, ItemID: item.ID, Checkpoint: page.Checkpoint}, err: fmt.Errorf("import source item %q: %w", item.ID, err)}
				if persistErr != nil {
					failure = &failureContextError{context: FailureContext{Phase: FailurePhaseCheckpoint, FolderID: sourceFolderID, FolderName: sourceFolderName, ItemID: item.ID, Checkpoint: page.Checkpoint}, err: errors.Join(failure, persistErr)}
				}
				return result, failure
			}
			if outcome.imported {
				chunk.importedItems++
				chunk.importedBytes += outcome.bytes
			} else {
				chunk.skippedItems++
			}
			if outcome.conflict {
				chunk.conflictItems++
			}
			if outcome.preserved {
				chunk.preservedItems++
			}
		}
		if finalChunk {
			chunk.sourceDeletedItems = result.sourceDeletedItems
			chunk.trashedItems = result.trashedItems
			chunk.failedItems += itemFailureCount
			chunk.itemFailures = itemFailures
		}
		checkpointAt, err := r.persistPageProgress(ctx, job, jobMu, sourceFolderID, sourceFolderName, page, finalChunk, chunk)
		if err != nil {
			return result, &failureContextError{context: FailureContext{Phase: FailurePhaseCheckpoint, FolderID: sourceFolderID, FolderName: sourceFolderName, Checkpoint: page.Checkpoint}, err: err}
		}
		result.add(chunk)
		if finalChunk {
			result.checkpointAt = checkpointAt
		}
		if finalChunk {
			return result, nil
		}
		start = end
	}
	return result, nil
}

// transferChunkEnd keeps the common small-item path large enough to amortize
// durable command and progress writes without allowing a page of attachment-
// heavy messages to become one unbounded in-memory command. A single large
// item is always allowed through so the loop advances.
func transferChunkEnd(items []Item, start int) int {
	if start >= len(items) {
		return len(items)
	}
	end := min(start+transferCommitChunkSize, len(items))
	bytes := 0
	for index := start; index < end; index++ {
		itemBytes := len(items[index].Data) + len(items[index].Name)
		if index > start && bytes+itemBytes > transferCommitChunkBytes {
			return index
		}
		bytes += itemBytes
	}
	return end
}

// createNewItems uses FolderSpace's atomic multi-item capability only when the
// whole chunk is a conflict-free append. Existing identities, named items,
// duplicate source IDs, lookup failures, and batch failures fall back to the
// ordinary per-item path so conflict policy and item-level failure evidence do
// not change. The durable and account-routed FolderSpace implementations batch
// their command journal, accounting, change records, payload/index writes, and
// system item-location records without exposing a storage backend to migration.
func (r *Runner) createNewItems(ctx context.Context, access service.AccessContext, sourceID, folderID string, items []Item) bool {
	creator, ok := r.space.(service.FolderItemBatchCreator)
	if !ok {
		return false
	}
	seen := make(map[string]struct{}, len(items))
	inputs := make([]service.ItemInput, 0, len(items))
	for _, item := range items {
		if item.ID == "" || item.Name != "" {
			return false
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return false
		}
		seen[item.ID] = struct{}{}
		if _, err := r.space.GetItemMetadataByExternalID(ctx, access, folderID, sourceID, item.ID); err == nil || !errors.Is(err, store.ErrNotFound) {
			return false
		}
		inputs = append(inputs, sourceItemInput(sourceID, item))
	}
	created, err := creator.CreateItems(ctx, access, folderID, inputs)
	return err == nil && len(created) == len(inputs)
}

func (r *Runner) persistPageProgress(ctx context.Context, job *Job, jobMu *sync.Mutex, sourceFolderID, sourceFolderName string, page Page, checkpoint bool, progress pageCommitResult) (time.Time, error) {
	jobMu.Lock()
	defer jobMu.Unlock()
	updatedJob := *job
	updatedJob.Checkpoints = cloneStringMap(job.Checkpoints)
	updatedJob.ImportedItems += progress.importedItems
	updatedJob.ImportedBytes += progress.importedBytes
	updatedJob.SkippedItems += progress.skippedItems
	updatedJob.ConflictItems += progress.conflictItems
	updatedJob.PreservedItems += progress.preservedItems
	updatedJob.RunImportedItems += progress.importedItems
	updatedJob.RunImportedBytes += progress.importedBytes
	updatedJob.RunSkippedItems += progress.skippedItems
	updatedJob.RunItemsFailed += progress.failedItems
	updatedJob.RunItemsExamined += progress.importedItems + progress.skippedItems + progress.failedItems
	updatedJob.RunConflictItems += progress.conflictItems
	updatedJob.RunPreservedItems += progress.preservedItems
	if updatedJob.RunItemsRemainingKnown {
		updatedJob.RunItemsRemaining = max(0, updatedJob.RunSourceItems-updatedJob.RunItemsExamined)
	}
	now := time.Now().UTC()
	updateRunRates(&updatedJob, now)
	if checkpoint {
		// Persist deletion telemetry with the checkpoint. If saving fails, a
		// retry may replay idempotent trash operations but cannot count the
		// same source change twice.
		updatedJob.SourceDeletedItems += progress.sourceDeletedItems
		updatedJob.RunSourceDeletedItems += progress.sourceDeletedItems
		updatedJob.RunTrashedItems += progress.trashedItems
		updatedJob.Checkpoints[sourceFolderID] = page.Checkpoint
		updatedJob.RunLastCheckpointFolderID = sourceFolderID
		updatedJob.RunLastCheckpointFolderName = sourceFolderName
		updatedJob.RunLastCheckpointAt = now
	}
	if err := r.jobs.Save(ctx, updatedJob); err != nil {
		return time.Time{}, err
	}
	*job = updatedJob
	if checkpoint {
		return now, nil
	}
	return time.Time{}, nil
}

func (r *pageCommitResult) add(other pageCommitResult) {
	r.importedItems += other.importedItems
	r.importedBytes += other.importedBytes
	r.skippedItems += other.skippedItems
	r.failedItems += other.failedItems
	r.itemFailures = append(r.itemFailures, other.itemFailures...)
	r.conflictItems += other.conflictItems
	r.preservedItems += other.preservedItems
}

func boundedItemFailures(failures []ItemFailure) []ItemFailure {
	result := make([]ItemFailure, 0, min(len(failures), maxRetainedItemFailures))
	for _, failure := range failures {
		if len(result) == maxRetainedItemFailures {
			break
		}
		failure.ID = boundedDiagnostic(redactDiagnostic(failure.ID))
		failure.Error = boundedRunError(errors.New(failure.Error))
		if failure.Error == "" {
			failure.Error = "source item could not be represented safely"
		}
		result = append(result, failure)
	}
	return result
}

type sourceDeletionTrashLookup struct {
	loaded      bool
	externalIDs map[string]struct{}
}

func (r *Runner) applySourceDeletion(ctx context.Context, access service.AccessContext, sourceID, folderID, externalID string, policy SourceDeletionPolicy, trashLookup *sourceDeletionTrashLookup) (bool, error) {
	if policy == SourceDeletionRetain {
		return false, nil
	}
	item, err := r.space.GetItemMetadataByExternalID(ctx, access, folderID, sourceID, externalID)
	if errors.Is(err, store.ErrNotFound) {
		// The folder-scoped external index no longer contains an item after it
		// moves to trash. Build a page-local trash lookup so a replay following
		// a failed checkpoint save still recognizes the action as applied.
		if err := r.loadTrashedExternalIDs(ctx, access, sourceID, folderID, trashLookup); err != nil {
			return false, err
		}
		_, found := trashLookup.externalIDs[externalID]
		return found, nil
	}
	if err != nil {
		return false, err
	}
	recoverable, ok := r.space.(service.RecoverableFolderSpace)
	if !ok {
		return false, errors.New("destination does not support recoverable deletion")
	}
	if item.TrashedAt.IsZero() {
		if _, err := recoverable.TrashItem(ctx, access, item.ID); err != nil {
			return false, err
		}
	}
	// Return whether the corresponding destination item exists, not whether
	// this invocation mutated it. That makes page replay after a job-store
	// failure account for an already-applied trash action exactly once when
	// the checkpoint and counters are eventually committed together.
	return true, nil
}

func (r *Runner) loadTrashedExternalIDs(ctx context.Context, access service.AccessContext, sourceID, folderID string, lookup *sourceDeletionTrashLookup) error {
	if lookup.loaded {
		return nil
	}
	lookup.loaded = true
	lookup.externalIDs = make(map[string]struct{})
	recoverable, ok := r.space.(service.RecoverableFolderSpace)
	if !ok {
		return errors.New("destination does not support recoverable deletion")
	}
	trash, err := recoverable.ListTrash(ctx, access)
	if err != nil {
		return err
	}
	for _, summary := range trash {
		if summary.OriginalFolderID != folderID {
			continue
		}
		item, err := r.space.GetItem(ctx, access, summary.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if externalID := item.ExternalIDs[sourceID]; externalID != "" {
			lookup.externalIDs[externalID] = struct{}{}
		}
	}
	return nil
}

func (r *Runner) completeFolder(ctx context.Context, job *Job, jobMu *sync.Mutex, result FolderReconciliation) error {
	jobMu.Lock()
	defer jobMu.Unlock()
	updatedJob := *job
	updatedJob.RunFoldersDone++
	updatedJob.RunFolderResults = append(append([]FolderReconciliation(nil), job.RunFolderResults...), result)
	updateRunRates(&updatedJob, time.Now().UTC())
	if err := r.jobs.Save(ctx, updatedJob); err != nil {
		return err
	}
	*job = updatedJob
	return nil
}

func updateRunRates(job *Job, now time.Time) {
	if job.RunStartedAt.IsZero() {
		return
	}
	elapsed := now.Sub(job.RunStartedAt).Seconds()
	if elapsed <= 0 {
		return
	}
	job.RunItemsPerSecond = float64(job.RunItemsExamined) / elapsed
	job.RunBytesPerSecond = float64(job.RunImportedBytes) / elapsed
}

func finishRun(job *Job, now time.Time) {
	job.RunFinishedAt = now
	sort.Slice(job.RunFolderResults, func(i, j int) bool {
		if job.RunFolderResults[i].SourceFolderName == job.RunFolderResults[j].SourceFolderName {
			return job.RunFolderResults[i].SourceFolderID < job.RunFolderResults[j].SourceFolderID
		}
		return job.RunFolderResults[i].SourceFolderName < job.RunFolderResults[j].SourceFolderName
	})
	updateRunRates(job, now)
}

func boundedRunError(err error) string {
	if err == nil {
		return ""
	}
	return boundedDiagnostic(redactDiagnostic(err.Error()))
}

var (
	diagnosticCredentialPattern = regexp.MustCompile(`(?i)\b(password|passwd|pwd|access[_-]?token|refresh[_-]?token|session[_-]?token|id[_-]?token|csrf[_-]?token|api[_-]?key|client[_-]?secret|private[_-]?key|credential|secret|authorization|proxy-authorization|cookie|set-cookie)\s*([:=])\s*("[^"]*"|'[^']*'|[^\s,;]+)`)
	diagnosticAuthPattern       = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
	diagnosticURLPattern        = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

func redactDiagnostic(message string) string {
	message = diagnosticAuthPattern.ReplaceAllString(message, `$1 [redacted]`)
	message = diagnosticCredentialPattern.ReplaceAllString(message, `$1$2[redacted]`)
	return diagnosticURLPattern.ReplaceAllStringFunc(message, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		if parsed.User != nil {
			if _, present := parsed.User.Password(); present {
				parsed.User = url.UserPassword(parsed.User.Username(), "[redacted]")
			}
		}
		if parsed.RawQuery != "" {
			query := parsed.Query()
			for key := range query {
				query.Set(key, "[redacted]")
			}
			parsed.RawQuery = query.Encode()
		}
		parsed.Fragment = ""
		return parsed.String()
	})
}

func boundedDiagnostic(message string) string {
	message = strings.Map(func(character rune) rune {
		if character < ' ' || character == '\u007f' {
			return ' '
		}
		return character
	}, strings.TrimSpace(message))
	message = strings.Join(strings.Fields(message), " ")
	runes := []rune(message)
	if len(runes) > 2048 {
		message = string(runes[:2047]) + "…"
	}
	return message
}

func sanitizeJobDiagnostics(job *Job) {
	job.LastError = boundedRunError(errors.New(job.LastError))
	job.RunFatalError = boundedRunError(errors.New(job.RunFatalError))
	for index := range job.RunFolderFailures {
		job.RunFolderFailures[index].Error = boundedRunError(errors.New(job.RunFolderFailures[index].Error))
	}
	for index := range job.RunFolderResults {
		job.RunFolderResults[index].Error = boundedRunError(errors.New(job.RunFolderResults[index].Error))
		job.RunFolderResults[index].ItemFailures = boundedItemFailures(job.RunFolderResults[index].ItemFailures)
	}
	if job.RunTerminalFailure != nil {
		job.RunTerminalFailure.Message = boundedRunError(errors.New(job.RunTerminalFailure.Message))
		job.RunTerminalFailure.RetryAdvice = boundedDiagnostic(job.RunTerminalFailure.RetryAdvice)
	}
}

func sanitizeRunRecordDiagnostics(record *RunRecord) {
	record.Error = boundedRunError(errors.New(record.Error))
	record.FatalError = boundedRunError(errors.New(record.FatalError))
	for index := range record.FolderFailures {
		record.FolderFailures[index].Error = boundedRunError(errors.New(record.FolderFailures[index].Error))
	}
	for index := range record.FolderResults {
		record.FolderResults[index].Error = boundedRunError(errors.New(record.FolderResults[index].Error))
		record.FolderResults[index].ItemFailures = boundedItemFailures(record.FolderResults[index].ItemFailures)
	}
	if record.TerminalFailure != nil {
		record.TerminalFailure.Message = boundedRunError(errors.New(record.TerminalFailure.Message))
		record.TerminalFailure.RetryAdvice = boundedDiagnostic(record.TerminalFailure.RetryAdvice)
	}
}

func terminalFailure(job Job, runErr error, occurredAt time.Time, supplied FailureContext) *TerminalFailure {
	context := supplied
	var contextual *failureContextError
	if errors.As(runErr, &contextual) {
		context = mergeFailureContext(context, contextual.context)
	}
	var sourceRead *sourceFolderReadError
	if errors.As(runErr, &sourceRead) {
		context = mergeFailureContext(context, FailureContext{Phase: FailurePhaseSourceRead, FolderID: sourceRead.folder.ID, FolderName: sourceRead.folder.Name})
	}
	if context.Phase == "" {
		message := boundedRunError(runErr)
		for _, failure := range job.RunFolderFailures {
			if failure.Error == message || (failure.Error != "" && strings.Contains(message, failure.Error)) {
				context = FailureContext{Phase: FailurePhaseSourceRead, FolderID: failure.FolderID, FolderName: failure.FolderName}
				break
			}
		}
	}
	if context.Phase == "" {
		context.Phase = FailurePhaseRun
	}
	if context.Checkpoint == "" && context.FolderID != "" {
		context.Checkpoint = job.Checkpoints[context.FolderID]
	}
	if context.FolderID == "" {
		context.FolderID = job.RunLastCheckpointFolderID
		context.FolderName = job.RunLastCheckpointFolderName
		if context.Checkpoint == "" && context.FolderID != "" {
			context.Checkpoint = job.Checkpoints[context.FolderID]
		}
	}
	message := boundedRunError(runErr)
	disposition, recommended, advice := classifyRetry(runErr, context.Phase, message)
	return &TerminalFailure{
		Message: message, Phase: context.Phase, FolderID: context.FolderID, FolderName: context.FolderName,
		ItemID: context.ItemID, Checkpoint: context.Checkpoint, OccurredAt: nonZeroTime(occurredAt, time.Now().UTC()),
		RetryDisposition: disposition, RetryRecommended: recommended, RetryAdvice: advice,
		CheckpointsRetained: len(job.Checkpoints) > 0,
	}
}

func mergeFailureContext(primary, fallback FailureContext) FailureContext {
	if primary.Phase == "" {
		primary.Phase = fallback.Phase
	}
	if primary.FolderID == "" {
		primary.FolderID = fallback.FolderID
	}
	if primary.FolderName == "" {
		primary.FolderName = fallback.FolderName
	}
	if primary.ItemID == "" {
		primary.ItemID = fallback.ItemID
	}
	if primary.Checkpoint == "" {
		primary.Checkpoint = fallback.Checkpoint
	}
	return primary
}

func classifyRetry(runErr error, phase FailurePhase, message string) (RetryDisposition, bool, string) {
	lower := strings.ToLower(message)
	if service.IsTemporarilyUnavailable(runErr) {
		return RetryRecommended, true, "The destination account was temporarily unavailable. Existing checkpoints are retained; retry when the account is ready."
	}
	for _, marker := range []string{"unauthorized", "authentication", "invalid credentials", "logon failure", "password required", "status 401"} {
		if strings.Contains(lower, marker) {
			return RetryCredentialsRequired, false, "Update the stored source credentials, then run the sync again."
		}
	}
	for _, marker := range []string{"unsupported", "unavailable in this build", "invalid endpoint", "invalid configuration"} {
		if strings.Contains(lower, marker) {
			return RetryConfigurationRequired, false, "Review the source type and connection settings before retrying."
		}
	}
	if isSourcePressure(runErr) || strings.Contains(lower, "retry later") || strings.Contains(lower, "throttl") {
		return RetryRecommended, true, "The source asked Veksel to back off. Existing checkpoints are retained; retry later."
	}
	if phase == FailurePhaseConnect || phase == FailurePhaseInventory {
		return RetryRecommended, true, "Check source availability and retry; completed checkpoints are retained."
	}
	return RetryManualReview, false, "Review the failed phase and retained run details before retrying."
}

func cloneTerminalFailure(failure *TerminalFailure) *TerminalFailure {
	if failure == nil {
		return nil
	}
	cloned := *failure
	return &cloned
}

func nonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Now().UTC()
}

func inferRunOutcome(state State, folderFailures int, foldersTotal, foldersDone, foldersFailed int64) RunOutcome {
	switch state {
	case StateRunning:
		return RunOutcomeInProgress
	case StateCompleted:
		return RunOutcomeCompleted
	case StateCompletedWithErrors:
		return RunOutcomeCompletedWithErrors
	case StatePaused:
		return RunOutcomePaused
	case StateInterrupted, StateCredentialsRequired:
		return RunOutcomeInterrupted
	case StateCancelled:
		return RunOutcomeCancelled
	case StateFailed:
		if folderFailures > 0 && foldersTotal > 0 && foldersDone+foldersFailed == foldersTotal {
			return RunOutcomeCompletedWithErrors
		}
		return RunOutcomeFatalFailure
	default:
		return ""
	}
}

type sourceReadStats struct {
	calls, attempts, retries, pressureEvents int64
	backoff, latency                         time.Duration
}

type sourceConcurrencyController struct {
	mu          sync.Mutex
	maximum     int
	limit       int
	active      int
	peak        int
	successes   int
	stateChange chan struct{}
}

func newSourceConcurrencyController(maximum, hint int) *sourceConcurrencyController {
	maximum = max(1, maximum)
	// Never let a stale low-water mark serialize a new run. Starting at two
	// still avoids an initial burst, then healthy reads rapidly recover the
	// protocol client's declared maximum.
	initial := max(hint, min(2, maximum))
	initial = min(maximum, max(1, initial))
	return &sourceConcurrencyController{maximum: maximum, limit: initial, stateChange: make(chan struct{})}
}

func (c *sourceConcurrencyController) acquire(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.active < c.limit {
			c.active++
			c.peak = max(c.peak, c.active)
			c.mu.Unlock()
			return nil
		}
		changed := c.stateChange
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (c *sourceConcurrencyController) release(stats sourceReadStats, failure error) {
	c.mu.Lock()
	c.active = max(0, c.active-1)
	if stats.retries > 0 || stats.pressureEvents > 0 || isSourcePressure(failure) {
		c.limit = max(1, c.limit/2)
		c.successes = 0
	} else if failure == nil {
		c.successes++
		if c.limit < c.maximum && c.successes >= max(4, c.limit*2) {
			c.limit++
			c.successes = 0
		}
	}
	close(c.stateChange)
	c.stateChange = make(chan struct{})
	c.mu.Unlock()
}

func (c *sourceConcurrencyController) snapshot() (limit, peak int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limit, c.peak
}

func (c *sourceConcurrencyController) limitValue() int {
	limit, _ := c.snapshot()
	return limit
}

func (c *sourceConcurrencyController) peakValue() int {
	_, peak := c.snapshot()
	return peak
}

func recordSourceRead(job *Job, jobMu *sync.Mutex, controller *sourceConcurrencyController, stats sourceReadStats) {
	limit, peak := controller.snapshot()
	jobMu.Lock()
	defer jobMu.Unlock()
	job.SourceCalls += stats.calls
	retryEvents := stats.retries + stats.pressureEvents
	job.SourceRetryEvents += retryEvents
	job.SourceBackoffMillis += stats.backoff.Milliseconds()
	job.RunSourceCalls += stats.calls
	job.RunSourceRetryEvents += retryEvents
	job.RunSourceBackoffMs += stats.backoff.Milliseconds()
	job.RunSourceLatencyMs += stats.latency.Milliseconds()
	job.RunSourceConcurrency = limit
	job.RunSourcePeak = max(job.RunSourcePeak, peak)
	job.SourceConcurrencyHint = limit
	denominator := job.RunSourceCalls + job.RunSourceRetryEvents
	if denominator > 0 {
		job.RunSourcePressure = float64(job.RunSourceRetryEvents) / float64(denominator)
	}
}

func readAdvancingPage(ctx context.Context, source Source, folder Folder, checkpoint string, maxAttempts int, retryBackoff time.Duration) (Page, error) {
	page, _, err := readAdvancingPageObserved(ctx, source, folder, checkpoint, maxAttempts, retryBackoff)
	return page, err
}

func readAdvancingPageObserved(ctx context.Context, source Source, folder Folder, checkpoint string, maxAttempts int, retryBackoff time.Duration) (page Page, stats sourceReadStats, err error) {
	started := time.Now()
	stats.calls = 1
	defer func() { stats.latency = time.Since(started) }()
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		stats.attempts++
		page, err := source.Items(ctx, folder, checkpoint)
		if err != nil {
			if isSourcePressure(err) {
				stats.pressureEvents++
			}
			return Page{}, stats, err
		}
		if page.Done || page.Checkpoint != checkpoint {
			return page, stats, nil
		}
		if attempt == maxAttempts {
			if len(page.Items) == 0 {
				return Page{}, stats, fmt.Errorf("migration source returned an empty non-advancing page after %d attempts", maxAttempts)
			}
			return Page{}, stats, fmt.Errorf("migration source returned a non-advancing page with %d items after %d attempts", len(page.Items), maxAttempts)
		}
		stats.retries++
		if retryBackoff <= 0 {
			continue
		}
		delay := retryBackoff * time.Duration(attempt)
		stats.backoff += delay
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Page{}, stats, ctx.Err()
		case <-timer.C:
		}
	}
	return Page{}, stats, errors.New("migration source page retry loop ended unexpectedly")
}

func cloneStringMap(input map[string]string) map[string]string {
	clone := make(map[string]string, len(input))
	for key, value := range input {
		clone[key] = value
	}
	return clone
}

func (r *Runner) ensureExternalIndex(ctx context.Context, sourceID string, access service.AccessContext, job *Job, jobMu *sync.Mutex, sourceFolderID, destinationID string) error {
	jobMu.Lock()
	indexed := job.IndexedSources[sourceFolderID] == sourceID
	jobMu.Unlock()
	if indexed {
		return nil
	}
	items, err := r.space.ListItems(ctx, access, destinationID, service.ItemQuery{})
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Headers[migrationSourceHeader] != sourceID || item.ExternalIDs[sourceID] != "" {
			continue
		}
		storedIdentity := item.Headers[migrationItemHeader]
		separator := strings.LastIndex(storedIdentity, "@")
		if separator <= 0 {
			continue
		}
		if _, err := r.space.BindItemExternalID(ctx, access, item.ID, sourceID, storedIdentity[:separator]); err != nil {
			return fmt.Errorf("index legacy source item %q: %w", item.ID, err)
		}
	}
	jobMu.Lock()
	job.IndexedSources[sourceFolderID] = sourceID
	err = r.jobs.Save(ctx, *job)
	jobMu.Unlock()
	return err
}

func selectedFolderSet(ids []string) map[string]struct{} {
	selected := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			selected[id] = struct{}{}
		}
	}
	return selected
}

func requiredFolderSet(folders []Folder, selected map[string]struct{}) map[string]struct{} {
	if len(selected) == 0 {
		return nil
	}
	parents := make(map[string]string, len(folders))
	for _, folder := range folders {
		parents[folder.ID] = folder.ParentID
	}
	required := make(map[string]struct{}, len(selected))
	for id := range selected {
		seen := make(map[string]struct{})
		for current := id; current != ""; current = parents[current] {
			if _, cycle := seen[current]; cycle {
				break
			}
			seen[current] = struct{}{}
			required[current] = struct{}{}
		}
	}
	return required
}

// PreflightFolders returns the exact folder reuse/create decisions a run would
// make for the current destination state. targets maps source folder IDs to
// explicit existing destination folder IDs.
func (r *Runner) PreflightFolders(ctx context.Context, destinationID string, folders []Folder, selectedIDs []string, targets map[string]string) (Preflight, error) {
	access := service.UserAccess(destinationID, "sync-preflight")
	destinationFolders, err := r.space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return Preflight{}, err
	}
	byID := make(map[string]model.Folder, len(destinationFolders))
	byPath := make(map[string]model.Folder, len(destinationFolders))
	bySpecial := make(map[string]model.Folder)
	for _, folder := range destinationFolders {
		byID[folder.ID] = folder
		byPath[folder.Path] = folder
		if special := normalizeSpecialUse(folder.SpecialUse); special != "" {
			bySpecial[string(folder.Type)+":"+special] = folder
		}
	}

	ordered := append([]Folder(nil), folders...)
	sort.SliceStable(ordered, func(i, j int) bool { return folderDepth(ordered[i], ordered) < folderDepth(ordered[j], ordered) })
	selected := selectedFolderSet(selectedIDs)
	required := requiredFolderSet(ordered, selected)
	planned := make(map[string]FolderMapping, len(ordered))
	reservedPaths := make(map[string]model.FolderType)
	claimedAutomaticTargets := make(map[string]struct{})
	result := Preflight{Ready: true, Mappings: make([]FolderMapping, 0, len(ordered)), DestinationFolders: destinationFolders}
	for _, source := range ordered {
		if len(selected) > 0 {
			if _, ok := required[source.ID]; !ok {
				continue
			}
		}
		_, transfer := selected[source.ID]
		if len(selected) == 0 {
			transfer = true
		}
		mapping := FolderMapping{
			SourceFolderID: source.ID, SourceParentID: source.ParentID, SourceName: source.Name,
			SourceType: source.Type, Transfer: transfer,
		}
		if targetID := strings.TrimSpace(targets[source.ID]); targetID != "" {
			target, ok := byID[targetID]
			if !ok || target.Type != source.Type {
				mapping.Action, mapping.Reason, mapping.Error = FolderMappingConflict, "explicit-target", "destination folder does not exist or has a different item type"
				result.Conflicts++
				result.Ready = false
				planned[source.ID] = mapping
				result.Mappings = append(result.Mappings, mapping)
				continue
			}
			mapping.Action, mapping.Reason = FolderMappingReuse, "explicit-target"
			setMappingDestination(&mapping, target)
			result.Reuses++
			planned[source.ID] = mapping
			result.Mappings = append(result.Mappings, mapping)
			continue
		}
		if source.Special != "" {
			if target, ok := bySpecial[string(source.Type)+":"+normalizeSpecialUse(source.Special)]; ok {
				mapping.Action, mapping.Reason = FolderMappingReuse, "special-use"
				setMappingDestination(&mapping, target)
				result.Reuses++
				planned[source.ID] = mapping
				result.Mappings = append(result.Mappings, mapping)
				continue
			}
		}

		parentPath := ""
		if parent, ok := planned[source.ParentID]; ok && parent.SourceType == source.Type {
			if parent.Action == FolderMappingConflict {
				mapping.Action, mapping.Reason, mapping.Error = FolderMappingConflict, "parent-conflict", "source parent has no valid destination mapping"
				result.Conflicts++
				result.Ready = false
				planned[source.ID] = mapping
				result.Mappings = append(result.Mappings, mapping)
				continue
			}
			mapping.DestinationParentID = parent.DestinationFolderID
			parentPath = parent.DestinationPath
		}
		for attempt := 0; attempt < 100; attempt++ {
			name := destinationFolderName(source.Name, source.Type, attempt)
			path := name
			if parentPath != "" {
				path = parentPath + "/" + name
			}
			if existing, ok := byPath[path]; ok {
				if existing.Type != source.Type {
					continue
				}
				if _, claimed := claimedAutomaticTargets[existing.ID]; claimed {
					continue
				}
				mapping.Action, mapping.Reason = FolderMappingReuse, "existing-path"
				setMappingDestination(&mapping, existing)
				claimedAutomaticTargets[existing.ID] = struct{}{}
				result.Reuses++
				break
			}
			if _, reserved := reservedPaths[path]; reserved {
				// Two distinct source folders cannot target one newly-created
				// path; choose the next deterministic candidate.
				continue
			}
			mapping.Action, mapping.Reason = FolderMappingCreate, "new-folder"
			mapping.DestinationName, mapping.DestinationPath = name, path
			reservedPaths[path] = source.Type
			result.Creates++
			break
		}
		if mapping.Action == "" {
			mapping.Action, mapping.Reason, mapping.Error = FolderMappingConflict, "name-exhausted", "no non-conflicting destination path is available"
			result.Conflicts++
			result.Ready = false
		}
		planned[source.ID] = mapping
		result.Mappings = append(result.Mappings, mapping)
	}
	return result, nil
}

func setMappingDestination(mapping *FolderMapping, folder model.Folder) {
	mapping.DestinationFolderID = folder.ID
	mapping.DestinationParentID = folder.ParentID
	mapping.DestinationName = folder.Name
	mapping.DestinationPath = folder.Path
}

func (r *Runner) ensureFolder(ctx context.Context, access service.AccessContext, job *Job, source Folder) (string, error) {
	if targetID := strings.TrimSpace(job.FolderTargets[source.ID]); targetID != "" {
		folder, err := r.space.GetFolder(ctx, access, targetID)
		if err != nil {
			return "", fmt.Errorf("resolve explicit destination for %q: %w", source.Name, err)
		}
		if folder.Type != source.Type {
			return "", fmt.Errorf("explicit destination for %q has type %q, want %q", source.Name, folder.Type, source.Type)
		}
		job.FolderMap[source.ID] = folder.ID
		return folder.ID, r.jobs.Save(ctx, *job)
	}
	if id := job.FolderMap[source.ID]; id != "" {
		if folder, err := r.space.GetFolder(ctx, access, id); err == nil && folder.Type == source.Type {
			return id, nil
		}
		delete(job.FolderMap, source.ID)
	}
	if source.Special != "" {
		folders, err := r.space.ListFolders(ctx, access, service.FolderQuery{Type: source.Type})
		if err != nil {
			return "", err
		}
		for _, folder := range folders {
			if normalizeSpecialUse(folder.SpecialUse) == normalizeSpecialUse(source.Special) {
				job.FolderMap[source.ID] = folder.ID
				return folder.ID, nil
			}
		}
	}
	parentID, parentPath := job.FolderMap[source.ParentID], ""
	if parentID != "" {
		parent, err := r.space.GetFolder(ctx, access, parentID)
		if err != nil {
			return "", fmt.Errorf("resolve destination parent for %q: %w", source.Name, err)
		}
		// Veksel folders contain one item kind and only nest below folders of
		// that kind. Some sources expose virtual or mixed-type hierarchy
		// containers; flatten those boundaries rather than failing the import.
		if parent.Type != source.Type {
			parentID = ""
		} else {
			parentPath = parent.Path
		}
	}
	for attempt := 0; attempt < 100; attempt++ {
		name := destinationFolderName(source.Name, source.Type, attempt)
		path := name
		if parentPath != "" {
			path = parentPath + "/" + name
		}
		if existing, lookupErr := r.space.GetFolderByPath(ctx, access, path); lookupErr == nil {
			if existing.Type == source.Type {
				if destinationAlreadyMapped(job.FolderMap, source.ID, existing.ID) {
					continue
				}
				job.FolderMap[source.ID] = existing.ID
				return existing.ID, r.jobs.Save(ctx, *job)
			}
			continue
		} else if !errors.Is(lookupErr, store.ErrNotFound) {
			return "", fmt.Errorf("inspect destination folder %q: %w", path, lookupErr)
		}
		created, createErr := r.space.CreateFolder(ctx, access, name, source.Type, parentID)
		if errors.Is(createErr, store.ErrExists) {
			continue
		}
		if createErr != nil {
			return "", fmt.Errorf("create destination folder %q: %w", source.Name, createErr)
		}
		job.FolderMap[source.ID] = created.ID
		return created.ID, r.jobs.Save(ctx, *job)
	}
	return "", fmt.Errorf("create destination folder %q: no non-conflicting name available", source.Name)
}

func destinationAlreadyMapped(folderMap map[string]string, sourceID, destinationID string) bool {
	for mappedSourceID, mappedDestinationID := range folderMap {
		if mappedSourceID != sourceID && mappedDestinationID == destinationID {
			return true
		}
	}
	return false
}

func destinationFolderName(sourceName string, folderType model.FolderType, attempt int) string {
	name := sanitizeFolderName(sourceName)
	if attempt == 1 {
		return name + " (" + string(folderType) + ")"
	}
	if attempt > 1 {
		return name + fmt.Sprintf(" (%s %d)", folderType, attempt)
	}
	return name
}

func normalizeSpecialUse(value string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "\\"))
}

type itemImportOutcome struct {
	imported  bool
	bytes     int64
	conflict  bool
	preserved bool
}

func (r *Runner) importItem(ctx context.Context, access service.AccessContext, sourceID, folderID string, item Item, policy ConflictPolicy) (itemImportOutcome, error) {
	identity := item.ID + "@"
	var prior *model.Item
	existing, err := r.space.GetItemMetadataByExternalID(ctx, access, folderID, sourceID, item.ID)
	if err == nil {
		prior = &existing
	} else if !errors.Is(err, store.ErrNotFound) {
		return itemImportOutcome{}, err
	}
	if prior != nil && prior.Headers[migrationItemHeader] == identity+item.Version {
		return itemImportOutcome{}, nil
	}
	conflict := false
	if prior != nil {
		full, err := r.space.GetItem(ctx, access, prior.ID)
		if err != nil {
			return itemImportOutcome{}, err
		}
		prior = &full
		storedFingerprint := prior.Headers[migrationFingerprintHeader]
		conflict = storedFingerprint == "" || storedFingerprint != itemFingerprint(prior.Data, prior.Flags)
		// Protocol versions and synchronization keys identify remote change-feed
		// positions, not necessarily content changes. After a source reset, EAS in
		// particular can replay every item under new SyncKeys. If both the locally
		// tracked content and the replayed source content match the last imported
		// fingerprint, this is unchanged work: avoid rewriting the payload and
		// inflating transfer telemetry merely to replace an opaque version marker.
		if !conflict && storedFingerprint == itemFingerprint(item.Data, item.Flags) {
			return itemImportOutcome{}, nil
		}
	} else if item.Name != "" {
		named, err := r.space.GetItemByName(ctx, access, folderID, item.Name)
		if err == nil {
			prior, conflict = &named, true
		} else if !errors.Is(err, store.ErrNotFound) {
			return itemImportOutcome{}, err
		}
	}
	if conflict && policy == ConflictDestinationWins {
		return itemImportOutcome{conflict: true}, nil
	}
	preserved := false
	if conflict && policy == ConflictKeepBoth && prior != nil && prior.ExternalIDs[sourceID] == item.ID {
		if err := r.preserveDestinationItem(ctx, access, sourceID, item.ID, *prior); err != nil {
			return itemImportOutcome{}, err
		}
		preserved = true
	}
	input := sourceItemInput(sourceID, item)
	headers := input.Headers
	if prior != nil {
		if conflict && policy == ConflictKeepBoth && prior.ExternalIDs[sourceID] != item.ID {
			prior = nil
			item.Name = conflictItemName(item.Name, sourceID, item.ID, "source")
			input.Name = item.Name
		} else {
			updated, err := r.space.UpdateItem(ctx, access, prior.ID, item.Data, headers)
			if err != nil {
				return itemImportOutcome{}, err
			}
			if _, err := r.space.SetFlags(ctx, access, updated.ID, item.Flags); err != nil {
				return itemImportOutcome{}, err
			}
			if prior.ExternalIDs[sourceID] != item.ID {
				if _, err := r.space.BindItemExternalID(ctx, access, updated.ID, sourceID, item.ID); err != nil {
					return itemImportOutcome{}, err
				}
			}
			return itemImportOutcome{imported: true, bytes: int64(len(item.Data)), conflict: conflict, preserved: preserved}, nil
		}
	}
	created, err := r.space.CreateItem(ctx, access, folderID, input)
	if err != nil {
		return itemImportOutcome{}, err
	}
	return itemImportOutcome{imported: true, bytes: created.Size, conflict: conflict, preserved: conflict && policy == ConflictKeepBoth}, nil
}

func sourceItemInput(sourceID string, item Item) service.ItemInput {
	headers := cloneHeaders(item.Headers)
	headers[migrationSourceHeader] = sourceID
	headers[migrationItemHeader] = item.ID + "@" + item.Version
	headers[migrationFingerprintHeader] = itemFingerprint(item.Data, item.Flags)
	return service.ItemInput{
		Name: item.Name, Data: item.Data, Headers: headers,
		ExternalIDs: map[string]string{sourceID: item.ID}, Flags: item.Flags, InternalDate: item.InternalDate,
	}
}

func (r *Runner) preserveDestinationItem(ctx context.Context, access service.AccessContext, sourceID, externalID string, item model.Item) error {
	headers := cloneHeaders(item.Headers)
	delete(headers, migrationSourceHeader)
	delete(headers, migrationItemHeader)
	delete(headers, migrationFingerprintHeader)
	_, err := r.space.CreateItem(ctx, access, item.FolderID, service.ItemInput{
		Name: conflictItemName(item.Name, sourceID, externalID, "local"), Data: item.Data,
		Headers: headers, Flags: item.Flags, InternalDate: item.InternalDate,
	})
	return err
}

func itemFingerprint(data []byte, flags []string) string {
	orderedFlags := append([]string(nil), flags...)
	sort.Strings(orderedFlags)
	hash := sha256.New()
	_, _ = hash.Write(data)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(strings.Join(orderedFlags, "\x00")))
	return hex.EncodeToString(hash.Sum(nil))
}

func conflictItemName(name, sourceID, externalID, kind string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Conflicting item"
	}
	hash := sha256.Sum256([]byte(sourceID + "\x00" + externalID + "\x00" + kind))
	suffix := " (" + kind + " " + hex.EncodeToString(hash[:4]) + ")"
	if dot := strings.LastIndex(name, "."); dot > 0 {
		return name[:dot] + suffix + name[dot:]
	}
	return name + suffix
}

func cloneHeaders(headers map[string]string) map[string]string {
	clone := make(map[string]string, len(headers)+2)
	for key, value := range headers {
		clone[key] = value
	}
	return clone
}

func folderDepth(folder Folder, folders []Folder) int {
	parents := make(map[string]string, len(folders))
	for _, candidate := range folders {
		parents[candidate.ID] = candidate.ParentID
	}
	depth := 0
	seen := map[string]struct{}{folder.ID: {}}
	for parent := folder.ParentID; parent != ""; parent = parents[parent] {
		if _, duplicate := seen[parent]; duplicate {
			return len(folders)
		}
		seen[parent] = struct{}{}
		depth++
	}
	return depth
}

func sanitizeFolderName(name string) string {
	name = strings.TrimSpace(strings.Trim(name, "/"))
	name = strings.ReplaceAll(name, "/", "_")
	if name == "" {
		return "Imported"
	}
	return name
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
