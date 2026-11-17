// Package accountverify schedules read-only account integrity checks through
// account.Manager and projects their durable operational state.
package accountverify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	StateDue       = "due"
	StateDeferred  = "deferred"
	StateQueued    = "queued"
	StateRunning   = "running"
	StateHealthy   = "healthy"
	StateUnhealthy = "unhealthy"
	StateFailed    = "failed"
)

// Policy is the complete managed scheduling policy.
type Policy struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"-"`
	Workers  int           `json:"workers"`
}

func (p Policy) Validate() error {
	if p.Interval < time.Hour || p.Interval > 365*24*time.Hour || p.Workers < 1 || p.Workers > 16 {
		return errors.New("account verification requires a 1-8760 hour interval and 1-16 workers")
	}
	return nil
}

// Status is the payload-free durable scheduler state for one account.
type Status struct {
	SchemaVersion   int       `json:"schema_version"`
	AccountID       string    `json:"account_id"`
	Login           string    `json:"login"`
	State           string    `json:"state"`
	LastResult      string    `json:"last_result,omitempty"`
	JobID           string    `json:"job_id,omitempty"`
	ReportID        string    `json:"report_id,omitempty"`
	IssueCount      int       `json:"issue_count"`
	LastStartedAt   time.Time `json:"last_started_at,omitzero"`
	LastCompletedAt time.Time `json:"last_completed_at,omitzero"`
	DueAt           time.Time `json:"due_at"`
	NextAttemptAt   time.Time `json:"next_attempt_at,omitzero"`
	Error           string    `json:"error,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Runner is the narrow account lifecycle boundary consumed by Scheduler.
type Runner interface {
	Entries() []account.Entry
	StartIntegrityCheck(login string, repair bool) (account.LifecycleJob, error)
	LifecycleJobs(login string) ([]account.LifecycleJob, error)
	IntegrityReport(login, reportID string) (account.IntegrityReport, error)
}

// Scheduler coordinates recurring verification without touching account
// storage directly. RunOnce is serialized and safe to call from API/health
// refreshes as well as the background loop.
type Scheduler struct {
	typed    *model.TypedStore
	runner   Runner
	policyMu sync.RWMutex
	policy   Policy
	runMu    sync.Mutex
	inflight map[string]string
}

func New(ctx context.Context, typed *model.TypedStore, runner Runner, policy Policy) (*Scheduler, error) {
	if typed == nil || runner == nil {
		return nil, errors.New("account verification requires storage and an account manager")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if err := typed.EnsureNamespace(ctx, model.NSAccountVerifications); err != nil {
		return nil, fmt.Errorf("initialize account verification state: %w", err)
	}
	return &Scheduler{typed: typed, runner: runner, policy: policy, inflight: make(map[string]string)}, nil
}

func (s *Scheduler) SetPolicy(policy Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	s.policyMu.Lock()
	s.policy = policy
	s.policyMu.Unlock()
	return nil
}

func (s *Scheduler) Policy() Policy {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.policy
}

// Start runs an immediate pass and then reconciles progress every five
// seconds. The returned stop function waits for the goroutine to exit.
func (s *Scheduler) Start(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.RunOnce(ctx, time.Now().UTC())
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				_ = s.RunOnce(ctx, now.UTC())
			}
		}
	}()
	return func() { cancel(); <-done }
}

// RunOnce reconciles owned jobs and starts the oldest due accounts up to the
// configured global worker limit. Automatic checks always pass repair=false.
func (s *Scheduler) RunOnce(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	policy := s.Policy()
	entries := s.runner.Entries()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Manifest.Login < entries[j].Manifest.Login })
	statuses := make([]Status, 0, len(entries))
	active := 0
	var joined error
	for _, entry := range entries {
		status, err := s.load(ctx, entry, now, policy)
		if err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		if jobID := s.inflight[status.Login]; jobID != "" && status.JobID == "" {
			status.JobID, status.State = jobID, StateRunning
		}
		if status.State == StateQueued || status.State == StateRunning {
			status, err = s.reconcile(ctx, status, now, policy)
			if err != nil {
				joined = errors.Join(joined, err)
				continue
			}
		}
		if status.State == StateQueued || status.State == StateRunning {
			active++
		}
		statuses = append(statuses, status)
	}
	if !policy.Enabled {
		return joined
	}
	sort.SliceStable(statuses, func(i, j int) bool {
		left, right := statuses[i].DueAt, statuses[j].DueAt
		if left.Equal(right) {
			return statuses[i].Login < statuses[j].Login
		}
		return left.Before(right)
	})
	for _, status := range statuses {
		if active >= policy.Workers {
			break
		}
		retryDue := status.LastResult == StateFailed && !status.NextAttemptAt.IsZero() && !now.Before(status.NextAttemptAt)
		ordinaryDue := !now.Before(status.DueAt) && (status.NextAttemptAt.IsZero() || !now.Before(status.NextAttemptAt))
		if status.State == StateQueued || status.State == StateRunning || (!ordinaryDue && !retryDue) {
			continue
		}
		job, err := s.runner.StartIntegrityCheck(status.Login, false)
		if err != nil {
			status.State, status.UpdatedAt = StateDeferred, now
			status.NextAttemptAt = now.Add(retryDelay(policy.Interval))
			if !errors.Is(err, account.ErrLifecycleConflict) && !errors.Is(err, account.ErrTemporarilyUnavailable) {
				status.State, status.LastResult, status.Error = StateFailed, StateFailed, boundedError(err)
			}
			if saveErr := s.save(ctx, status); saveErr != nil {
				joined = errors.Join(joined, saveErr)
			}
			continue
		}
		// Keep the previous report and error visible while a retry is active. They
		// describe the last completed result and are replaced only when this job
		// reaches a terminal state.
		status.State, status.JobID = StateQueued, job.ID
		status.LastStartedAt, status.NextAttemptAt, status.UpdatedAt = now, time.Time{}, now
		s.inflight[status.Login] = job.ID
		if err := s.save(ctx, status); err != nil {
			joined = errors.Join(joined, err)
		}
		active++
	}
	return joined
}

func (s *Scheduler) load(ctx context.Context, entry account.Entry, now time.Time, policy Policy) (Status, error) {
	var status Status
	err := s.typed.Get(ctx, model.NSAccountVerifications, entry.Manifest.ID, &status)
	if errors.Is(err, store.ErrNotFound) {
		return Status{SchemaVersion: 1, AccountID: entry.Manifest.ID, Login: entry.Manifest.Login, State: StateDue, DueAt: now, UpdatedAt: now}, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("read account verification %s: %w", entry.Manifest.Login, err)
	}
	if status.SchemaVersion != 1 || status.AccountID != entry.Manifest.ID || status.Login != entry.Manifest.Login {
		return Status{}, fmt.Errorf("invalid account verification state for %s", entry.Manifest.Login)
	}
	if !status.LastCompletedAt.IsZero() && status.State != StateQueued && status.State != StateRunning {
		status.DueAt = status.LastCompletedAt.Add(policy.Interval)
	}
	return status, nil
}

func (s *Scheduler) reconcile(ctx context.Context, status Status, now time.Time, policy Policy) (Status, error) {
	jobs, err := s.runner.LifecycleJobs(status.Login)
	if err != nil {
		return status, fmt.Errorf("list verification lifecycle for %s: %w", status.Login, err)
	}
	var found *account.LifecycleJob
	for index := range jobs {
		if jobs[index].ID == status.JobID && jobs[index].Operation == account.LifecycleVerify {
			found = &jobs[index]
			break
		}
	}
	if found == nil {
		status.State, status.LastResult, status.Error = StateFailed, StateFailed, "scheduled verification job is missing"
		status.LastCompletedAt, status.NextAttemptAt, status.UpdatedAt = now, now.Add(retryDelay(policy.Interval)), now
		delete(s.inflight, status.Login)
		return status, s.save(ctx, status)
	}
	switch found.Phase {
	case account.LifecycleQueued:
		status.State = StateQueued
	case account.LifecycleRunning:
		status.State = StateRunning
	case account.LifecycleCompleted:
		report, reportErr := s.runner.IntegrityReport(status.Login, found.ReportID)
		if reportErr != nil {
			status.State, status.LastResult, status.Error = StateFailed, StateFailed, boundedError(reportErr)
			status.NextAttemptAt = now.Add(retryDelay(policy.Interval))
		} else {
			status.ReportID, status.IssueCount, status.Error = report.ID, len(report.Issues), ""
			if report.Healthy {
				status.State, status.LastResult = StateHealthy, StateHealthy
			} else {
				status.State, status.LastResult = StateUnhealthy, StateUnhealthy
			}
			status.NextAttemptAt = time.Time{}
		}
		status.LastCompletedAt = found.CompletedAt
		if status.LastCompletedAt.IsZero() {
			status.LastCompletedAt = now
		}
		status.DueAt = status.LastCompletedAt.Add(policy.Interval)
		delete(s.inflight, status.Login)
	case account.LifecycleFailed:
		status.State, status.LastResult, status.Error = StateFailed, StateFailed, strings.TrimSpace(found.Error)
		if status.Error == "" {
			status.Error = "scheduled verification failed"
		}
		status.LastCompletedAt = found.CompletedAt
		if status.LastCompletedAt.IsZero() {
			status.LastCompletedAt = now
		}
		status.DueAt, status.NextAttemptAt = status.LastCompletedAt.Add(policy.Interval), now.Add(retryDelay(policy.Interval))
		delete(s.inflight, status.Login)
	default:
		return status, fmt.Errorf("invalid verification lifecycle phase %q", found.Phase)
	}
	status.UpdatedAt = now
	return status, s.save(ctx, status)
}

func retryDelay(interval time.Duration) time.Duration {
	delay := interval / 4
	if delay < 5*time.Minute {
		return 5 * time.Minute
	}
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func (s *Scheduler) save(ctx context.Context, status Status) error {
	status.SchemaVersion = 1
	return s.typed.Set(ctx, model.NSAccountVerifications, status.AccountID, status)
}

// Statuses returns one detached status for every currently discovered account.
func (s *Scheduler) Statuses(ctx context.Context, now time.Time) ([]Status, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	policy := s.Policy()
	entries := s.runner.Entries()
	result := make([]Status, 0, len(entries))
	for _, entry := range entries {
		status, err := s.load(ctx, entry, now, policy)
		if err != nil {
			return nil, err
		}
		result = append(result, status)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Login < result[j].Login })
	return result, nil
}

// Observation aggregates per-account evidence without exposing account data.
func (s *Scheduler) Observation(ctx context.Context, now time.Time) health.Observation {
	policy := s.Policy()
	observation := health.Observation{ID: "account-integrity", Label: "Scheduled account verification", Kind: "storage", Desired: policy.Enabled, Required: false, State: health.StateHealthy}
	if !policy.Enabled {
		observation.State = health.StateDisabled
		return observation
	}
	statuses, err := s.Statuses(ctx, now)
	if err != nil {
		observation.State, observation.Severity, observation.Reason = health.StateUnavailable, health.SeverityCritical, "verification state is unavailable"
		return observation
	}
	counts, results := map[string]int{}, map[string]int{}
	issues, overdue := 0, 0
	grace := retryDelay(policy.Interval)
	for _, status := range statuses {
		counts[status.State]++
		results[status.LastResult]++
		issues += status.IssueCount
		if !status.DueAt.IsZero() && now.After(status.DueAt.Add(grace)) && status.State != StateQueued && status.State != StateRunning {
			overdue++
		}
	}
	observation.Details = map[string]string{
		"accounts": fmt.Sprint(len(statuses)), "healthy": fmt.Sprint(results[StateHealthy]), "unhealthy": fmt.Sprint(results[StateUnhealthy]),
		"failed": fmt.Sprint(results[StateFailed]), "running": fmt.Sprint(counts[StateRunning] + counts[StateQueued]), "overdue": fmt.Sprint(overdue), "issues": fmt.Sprint(issues),
		"interval_hours": fmt.Sprintf("%.0f", policy.Interval.Hours()), "workers": fmt.Sprint(policy.Workers),
	}
	if results[StateFailed] > 0 {
		observation.State, observation.Severity = health.StateUnavailable, health.SeverityCritical
		observation.Reason = fmt.Sprintf("%d account verification(s) failed", results[StateFailed])
	} else if results[StateUnhealthy] > 0 || issues > 0 {
		observation.State, observation.Severity = health.StateDegraded, health.SeverityWarning
		observation.Reason = fmt.Sprintf("%d account(s) have integrity findings", results[StateUnhealthy])
	} else if overdue > 0 {
		observation.State, observation.Severity = health.StateDegraded, health.SeverityWarning
		observation.Reason = fmt.Sprintf("%d account verification(s) are overdue", overdue)
	}
	return observation
}
