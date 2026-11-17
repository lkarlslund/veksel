package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	retentionCursorKey          = "retention_cursor"
	DefaultRetentionInterval    = 6 * time.Hour
	DefaultRetentionRunActions  = 5000
	DefaultRetentionActionDelay = 5 * time.Millisecond
)

// AuditSink records administrative evidence; *audit.Logger implements it.
type AuditSink interface {
	Log(actor, action, target string, details map[string]string)
}

// CounterSink records monotonic counters; *metrics.Metrics implements it.
type CounterSink interface {
	IncrementCounterBy(name string, amount float64, labels map[string]string)
}

// RetentionRunReport summarizes one bounded pass of the retention job.
type RetentionRunReport struct {
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	AccountsScanned int       `json:"accounts_scanned"`
	Deleted         int       `json:"deleted"`
	Archived        int       `json:"archived"`
	HeldPurged      int       `json:"held_purged"`
	HeldSkipped     int       `json:"held_skipped"`
	Errors          int       `json:"errors"`
	LastError       string    `json:"last_error,omitempty"`
	// Complete is false when the action budget ran out before every account
	// was visited; the next run resumes after the persisted cursor.
	Complete bool   `json:"complete"`
	Cursor   string `json:"cursor,omitempty"`
}

// RetentionStatus is the administrator-facing job state.
type RetentionStatus struct {
	Enabled       bool                `json:"enabled"`
	Interval      string              `json:"interval"`
	Running       bool                `json:"running"`
	Cursor        string              `json:"cursor,omitempty"`
	LastRun       *RetentionRunReport `json:"last_run,omitempty"`
	TotalRuns     int64               `json:"total_runs"`
	TotalDeleted  int64               `json:"total_deleted"`
	TotalArchived int64               `json:"total_archived"`
	TotalErrors   int64               `json:"total_errors"`
}

// RetentionJob applies retention policies through FolderSpace, one account at
// a time in login order. The cursor naming the last completed account is
// persisted after every account, so a restart resumes where it stopped; a
// partially processed account is simply rescanned, which is idempotent
// because processed items no longer match. Each run performs at most
// MaxActions item actions, paced by ActionDelay.
type RetentionJob struct {
	space      FolderSpace
	compliance *Compliance
	ts         *model.TypedStore
	audit      AuditSink
	counters   CounterSink

	// Folders optionally lists an account's own folders more cheaply than
	// space; production passes the account router.
	Folders     OwnFolderLister
	MaxActions  int
	ActionDelay time.Duration
	Now         func() time.Time
	Sleep       func(context.Context, time.Duration) error

	mu       sync.Mutex
	running  bool
	enabled  bool
	interval time.Duration
	wake     chan struct{}
	status   RetentionStatus
}

// NewRetentionJob creates a disabled job; SetPolicy enables it.
func NewRetentionJob(space FolderSpace, compliance *Compliance, ts *model.TypedStore, audit AuditSink, counters CounterSink) *RetentionJob {
	return &RetentionJob{
		space: space, compliance: compliance, ts: ts, audit: audit, counters: counters,
		MaxActions: DefaultRetentionRunActions, ActionDelay: DefaultRetentionActionDelay,
		Now: time.Now, Sleep: sleepContext, interval: DefaultRetentionInterval, wake: make(chan struct{}, 1),
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SetPolicy applies retention_enabled and retention_job_interval live.
func (j *RetentionJob) SetPolicy(enabled bool, interval time.Duration) {
	if interval < time.Minute {
		interval = time.Minute
	}
	j.mu.Lock()
	j.enabled, j.interval = enabled, interval
	j.mu.Unlock()
	select {
	case j.wake <- struct{}{}:
	default:
	}
}

// Status returns the job's configuration and counters.
func (j *RetentionJob) Status(ctx context.Context) RetentionStatus {
	j.mu.Lock()
	status := j.status
	status.Enabled, status.Interval, status.Running = j.enabled, j.interval.String(), j.running
	if status.LastRun != nil {
		last := *status.LastRun
		status.LastRun = &last
	}
	j.mu.Unlock()
	status.Cursor, _ = j.loadCursor(ctx)
	return status
}

// Run executes RunOnce every interval while enabled until ctx ends.
func (j *RetentionJob) Run(ctx context.Context) {
	// A policy applied before the loop started is already in effect.
	select {
	case <-j.wake:
	default:
	}
	for {
		j.mu.Lock()
		enabled, interval := j.enabled, j.interval
		j.mu.Unlock()
		if enabled {
			if _, err := j.RunOnce(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, errRetentionBusy) {
				j.recordError(err)
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-j.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

var errRetentionBusy = errors.New("retention run already in progress")

func (j *RetentionJob) recordError(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.status.TotalErrors++
	if j.status.LastRun != nil {
		j.status.LastRun.LastError = err.Error()
	}
}

func (j *RetentionJob) loadCursor(ctx context.Context) (string, error) {
	var cursor string
	err := j.ts.Get(ctx, nsComplianceState, retentionCursorKey, &cursor)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return cursor, err
}

func (j *RetentionJob) saveCursor(ctx context.Context, cursor string) error {
	return j.ts.Set(ctx, nsComplianceState, retentionCursorKey, cursor)
}

// RunOnce performs one bounded pass and records an audit summary.
func (j *RetentionJob) RunOnce(ctx context.Context) (RetentionRunReport, error) {
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return RetentionRunReport{}, errRetentionBusy
	}
	j.running = true
	j.mu.Unlock()
	defer func() {
		j.mu.Lock()
		j.running = false
		j.mu.Unlock()
	}()

	report := RetentionRunReport{StartedAt: j.Now().UTC()}
	err := j.run(ctx, &report)
	report.FinishedAt = j.Now().UTC()
	if err != nil {
		report.Errors++
		report.LastError = err.Error()
	}
	j.mu.Lock()
	j.status.LastRun = &report
	j.status.TotalRuns++
	j.status.TotalDeleted += int64(report.Deleted + report.HeldPurged)
	j.status.TotalArchived += int64(report.Archived)
	j.status.TotalErrors += int64(report.Errors)
	j.mu.Unlock()
	if j.counters != nil {
		j.counters.IncrementCounterBy("veksel_retention_items_deleted_total", float64(report.Deleted+report.HeldPurged), nil)
		j.counters.IncrementCounterBy("veksel_retention_items_archived_total", float64(report.Archived), nil)
		j.counters.IncrementCounterBy("veksel_retention_items_held_total", float64(report.HeldSkipped), nil)
		j.counters.IncrementCounterBy("veksel_retention_errors_total", float64(report.Errors), nil)
		j.counters.IncrementCounterBy("veksel_retention_runs_total", 1, nil)
	}
	if j.audit != nil {
		details := map[string]string{
			"accounts": strconv.Itoa(report.AccountsScanned), "deleted": strconv.Itoa(report.Deleted),
			"archived": strconv.Itoa(report.Archived), "held_purged": strconv.Itoa(report.HeldPurged),
			"held_skipped": strconv.Itoa(report.HeldSkipped), "errors": strconv.Itoa(report.Errors),
			"complete": strconv.FormatBool(report.Complete),
		}
		if report.LastError != "" {
			details["last_error"] = report.LastError
		}
		j.audit.Log("system", "retention.run", "retention", details)
	}
	return report, err
}

func (j *RetentionJob) run(ctx context.Context, report *RetentionRunReport) error {
	if j.space == nil || j.compliance == nil || j.ts == nil {
		return errors.New("retention job is not configured")
	}
	cursor, err := j.loadCursor(ctx)
	if err != nil {
		return err
	}
	users, err := j.ts.UserStore().List(ctx)
	if err != nil {
		return err
	}
	accounts := make([]string, 0, len(users))
	for _, user := range users {
		accounts = append(accounts, strings.ToLower(user.ID))
	}
	sort.Strings(accounts)
	budget := j.MaxActions
	if budget < 1 {
		budget = DefaultRetentionRunActions
	}
	for _, accountID := range accounts {
		if cursor != "" && accountID <= cursor {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		exhausted, err := j.processAccount(ctx, accountID, &budget, report)
		if err != nil {
			report.Errors++
			report.LastError = fmt.Sprintf("%s: %v", accountID, err)
		}
		if exhausted {
			report.Cursor = cursor
			return nil
		}
		report.AccountsScanned++
		cursor = accountID
		if err := j.saveCursor(ctx, cursor); err != nil {
			return err
		}
	}
	report.Complete, report.Cursor = true, ""
	return j.saveCursor(ctx, "")
}

// processAccount applies the effective policy to each of accountID's mail
// folders and, once no hold remains, destroys items preserved by a released
// hold. It reports whether the action budget ran out.
func (j *RetentionJob) processAccount(ctx context.Context, accountID string, budget *int, report *RetentionRunReport) (bool, error) {
	held := j.compliance.AccountHeld(ctx, accountID)
	domain := j.compliance.PrimaryDomain(ctx, accountID)
	access := UserAccess(accountID, ProtocolRetention)
	folders, err := j.accountFolders(ctx, accountID)
	if err != nil {
		return false, err
	}
	var archive model.Folder
	for _, folder := range folders {
		if folder.Type == model.FolderTypeMail && folder.SpecialUse == model.SpecialUseArchive {
			archive = folder
		}
	}
	now := j.Now().UTC()
	var firstErr error
	for _, folder := range folders {
		policy, ok := j.compliance.EffectivePolicy(accountID, domain, folder)
		if !ok || policy.Action == RetentionActionArchive && (archive.ID == "" || archive.ID == folder.ID) {
			continue
		}
		cutoff := now.AddDate(0, 0, -policy.Days)
		items, err := j.space.ListItems(ctx, access, folder.ID, ItemQuery{Before: cutoff, MetadataOnly: true})
		if err != nil {
			firstErr = errors.Join(firstErr, err)
			continue
		}
		for _, item := range items {
			if policy.Action == RetentionActionDelete && held {
				report.HeldSkipped++
				continue
			}
			if *budget <= 0 {
				return true, firstErr
			}
			if policy.Action == RetentionActionDelete {
				err = j.space.DeleteItem(ctx, access, item.ID)
			} else {
				_, err = j.space.MoveItem(ctx, access, item.ID, archive.ID, "")
			}
			*budget--
			switch {
			case errors.Is(err, ErrLegalHold):
				report.HeldSkipped++
			case errors.Is(err, store.ErrNotFound):
			case err != nil:
				firstErr = errors.Join(firstErr, err)
			case policy.Action == RetentionActionDelete:
				report.Deleted++
			default:
				report.Archived++
			}
			if err := j.Sleep(ctx, j.ActionDelay); err != nil {
				return true, errors.Join(firstErr, err)
			}
		}
	}
	if held {
		return false, firstErr
	}
	exhausted, err := j.purgeReleased(ctx, accountID, budget, report)
	return exhausted, errors.Join(firstErr, err)
}

// purgeReleased destroys items a user deleted while a now-released hold
// preserved them, completing the deletion the hold deferred.
func (j *RetentionJob) purgeReleased(ctx context.Context, accountID string, budget *int, report *RetentionRunReport) (bool, error) {
	access := ComplianceAccess(accountID)
	folders, err := j.accountFolders(ctx, accountID)
	if err != nil {
		return false, err
	}
	var firstErr error
	for _, folder := range folders {
		if !model.IsHeldDeletedFolder(folder) {
			continue
		}
		items, err := j.space.ListItems(ctx, access, folder.ID, ItemQuery{MetadataOnly: true})
		if err != nil {
			firstErr = errors.Join(firstErr, err)
			continue
		}
		for _, item := range items {
			if *budget <= 0 {
				return true, firstErr
			}
			err := j.space.DeleteItem(ctx, access, item.ID)
			*budget--
			switch {
			case errors.Is(err, ErrLegalHold):
				report.HeldSkipped++
			case errors.Is(err, store.ErrNotFound):
			case err != nil:
				firstErr = errors.Join(firstErr, err)
			default:
				report.HeldPurged++
			}
			if err := j.Sleep(ctx, j.ActionDelay); err != nil {
				return true, errors.Join(firstErr, err)
			}
		}
	}
	return false, firstErr
}

// OwnFolderLister lists only the folders an account owns. The account router
// implements it without visiting every other account.
type OwnFolderLister interface {
	ListOwnFolders(context.Context, AccessContext, FolderQuery) ([]model.Folder, error)
}

// accountFolders enumerates accountID's own folders, including held-deleted
// folders, through compliance access.
func (j *RetentionJob) accountFolders(ctx context.Context, accountID string) ([]model.Folder, error) {
	access := ComplianceAccess(accountID)
	lister, ok := j.space.(OwnFolderLister)
	if j.Folders != nil {
		lister, ok = j.Folders, true
	}
	if ok {
		return lister.ListOwnFolders(ctx, access, FolderQuery{})
	}
	folders, err := j.space.ListFolders(ctx, access, FolderQuery{})
	if err != nil {
		return nil, err
	}
	own := folders[:0]
	for _, folder := range folders {
		if strings.EqualFold(folder.UserID, accountID) {
			own = append(own, folder)
		}
	}
	return own, nil
}
