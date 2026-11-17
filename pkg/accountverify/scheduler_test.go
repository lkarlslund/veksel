package accountverify

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type fakeRunner struct {
	mu       sync.Mutex
	entries  []account.Entry
	jobs     map[string][]account.LifecycleJob
	reports  map[string]account.IntegrityReport
	startErr map[string]error
	starts   []string
	repairs  []bool
}

func newFakeRunner(logins ...string) *fakeRunner {
	runner := &fakeRunner{jobs: make(map[string][]account.LifecycleJob), reports: make(map[string]account.IntegrityReport), startErr: make(map[string]error)}
	for index, login := range logins {
		runner.entries = append(runner.entries, account.Entry{Manifest: account.Manifest{ID: fmt.Sprintf("acc_%032x", index+1), Login: login}})
	}
	return runner
}

func (r *fakeRunner) Entries() []account.Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]account.Entry(nil), r.entries...)
}

func (r *fakeRunner) StartIntegrityCheck(login string, repair bool) (account.LifecycleJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.startErr[login]; err != nil {
		return account.LifecycleJob{}, err
	}
	now := time.Now().UTC()
	job := account.LifecycleJob{ID: fmt.Sprintf("op_%032x", len(r.starts)+1), Login: login, Operation: account.LifecycleVerify, Phase: account.LifecycleQueued, CreatedAt: now, UpdatedAt: now}
	r.jobs[login] = append([]account.LifecycleJob{job}, r.jobs[login]...)
	r.starts, r.repairs = append(r.starts, login), append(r.repairs, repair)
	return job, nil
}

func (r *fakeRunner) LifecycleJobs(login string) ([]account.LifecycleJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]account.LifecycleJob(nil), r.jobs[login]...), nil
}

func (r *fakeRunner) IntegrityReport(_ string, reportID string) (account.IntegrityReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	report, found := r.reports[reportID]
	if !found {
		return account.IntegrityReport{}, store.ErrNotFound
	}
	return report, nil
}

func (r *fakeRunner) finish(login string, phase account.LifecyclePhase, healthy bool, issues int, message string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	job := &r.jobs[login][0]
	job.Phase, job.CompletedAt, job.UpdatedAt = phase, at, at
	if phase == account.LifecycleCompleted {
		job.ReportID = "chk_" + job.ID[3:]
		findings := make([]account.IntegrityIssue, issues)
		r.reports[job.ReportID] = account.IntegrityReport{ID: job.ReportID, Login: login, Healthy: healthy, Issues: findings, CompletedAt: at}
	} else {
		job.Error = message
	}
}

func schedulerFixture(t *testing.T, runner Runner, policy Policy) (*Scheduler, *model.TypedStore) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	scheduler, err := New(t.Context(), typed, runner, policy)
	if err != nil {
		t.Fatal(err)
	}
	return scheduler, typed
}

func TestSchedulerBoundsConcurrencyAndNeverRepairs(t *testing.T) {
	runner := newFakeRunner("alice", "bob", "carol")
	scheduler, _ := schedulerFixture(t, runner, Policy{Enabled: true, Interval: 24 * time.Hour, Workers: 2})
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	if err := scheduler.RunOnce(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 2 || runner.starts[0] != "alice" || runner.starts[1] != "bob" {
		t.Fatalf("initial starts = %v", runner.starts)
	}
	for _, repair := range runner.repairs {
		if repair {
			t.Fatal("automatic scheduler requested repair")
		}
	}
	if err := scheduler.RunOnce(t.Context(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 2 {
		t.Fatalf("running jobs did not enforce worker limit: %v", runner.starts)
	}
	runner.finish("alice", account.LifecycleCompleted, true, 0, "", now.Add(2*time.Second))
	if err := scheduler.RunOnce(t.Context(), now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 3 || runner.starts[2] != "carol" {
		t.Fatalf("freed worker did not start oldest due account: %v", runner.starts)
	}
	statuses, err := scheduler.Statuses(t.Context(), now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if statuses[0].State != StateHealthy || statuses[0].ReportID == "" || !statuses[0].DueAt.Equal(now.Add(2*time.Second).Add(24*time.Hour)) {
		t.Fatalf("completed status = %+v", statuses[0])
	}
}

func TestSchedulerReconcilesRestartAndRetriesFailure(t *testing.T) {
	runner := newFakeRunner("alice")
	policy := Policy{Enabled: true, Interval: 24 * time.Hour, Workers: 1}
	scheduler, typed := schedulerFixture(t, runner, policy)
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	if err := scheduler.RunOnce(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.jobs["alice"][0].Phase = account.LifecycleRunning
	runner.mu.Unlock()
	reopened, err := New(t.Context(), typed, runner, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.RunOnce(t.Context(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 1 {
		t.Fatalf("restart duplicated active job: %v", runner.starts)
	}
	runner.finish("alice", account.LifecycleFailed, false, 0, "read generation: checksum mismatch", now.Add(2*time.Minute))
	if err := reopened.RunOnce(t.Context(), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	statuses, err := reopened.Statuses(t.Context(), now.Add(3*time.Minute))
	if err != nil || len(statuses) != 1 || statuses[0].State != StateFailed || statuses[0].Error == "" {
		t.Fatalf("failed restart reconciliation = %+v, %v", statuses, err)
	}
	if err := reopened.RunOnce(t.Context(), now.Add(63*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 2 {
		t.Fatalf("failed verification was not retried after bounded delay: %v", runner.starts)
	}
	statuses, err = reopened.Statuses(t.Context(), now.Add(63*time.Minute))
	if err != nil || statuses[0].State != StateQueued || statuses[0].LastResult != StateFailed || statuses[0].Error == "" {
		t.Fatalf("retry lost last failure evidence: %+v, %v", statuses, err)
	}
}

func TestSchedulerDefersLifecycleConflictWithoutFalseFailure(t *testing.T) {
	runner := newFakeRunner("alice")
	runner.startErr["alice"] = account.ErrLifecycleConflict
	scheduler, _ := schedulerFixture(t, runner, Policy{Enabled: true, Interval: time.Hour, Workers: 1})
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	if err := scheduler.RunOnce(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	statuses, err := scheduler.Statuses(t.Context(), now)
	if err != nil || len(statuses) != 1 || statuses[0].State != StateDeferred || statuses[0].LastResult == StateFailed || statuses[0].Error != "" {
		t.Fatalf("deferred status = %+v, %v", statuses, err)
	}
	if observation := scheduler.Observation(t.Context(), now); observation.State != health.StateHealthy {
		t.Fatalf("fresh lifecycle deferral health = %+v", observation)
	}
}

func TestSchedulerHealthTracksFindingsFailureRecoveryAndDisabledPolicy(t *testing.T) {
	runner := newFakeRunner("alice", "bob")
	scheduler, _ := schedulerFixture(t, runner, Policy{Enabled: false, Interval: 24 * time.Hour, Workers: 2})
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	if err := scheduler.RunOnce(t.Context(), now); err != nil || len(runner.starts) != 0 {
		t.Fatalf("disabled run = starts %v, error %v", runner.starts, err)
	}
	if observation := scheduler.Observation(t.Context(), now); observation.State != health.StateDisabled || observation.Desired {
		t.Fatalf("disabled observation = %+v", observation)
	}
	if err := scheduler.SetPolicy(Policy{Enabled: true, Interval: 24 * time.Hour, Workers: 2}); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.RunOnce(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	runner.finish("alice", account.LifecycleCompleted, false, 3, "", now.Add(time.Minute))
	runner.finish("bob", account.LifecycleFailed, false, 0, "cannot read manifest", now.Add(time.Minute))
	if err := scheduler.RunOnce(t.Context(), now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	observation := scheduler.Observation(t.Context(), now.Add(2*time.Minute))
	if observation.State != health.StateUnavailable || observation.Details["unhealthy"] != "1" || observation.Details["failed"] != "1" || observation.Details["issues"] != "3" {
		t.Fatalf("unhealthy observation = %+v", observation)
	}
	statuses, _ := scheduler.Statuses(t.Context(), now.Add(2*time.Minute))
	for _, status := range statuses {
		status.State, status.LastResult, status.IssueCount, status.Error = StateHealthy, StateHealthy, 0, ""
		status.LastCompletedAt, status.DueAt = now.Add(3*time.Minute), now.Add(24*time.Hour)
		if err := scheduler.save(t.Context(), status); err != nil {
			t.Fatal(err)
		}
	}
	if observation = scheduler.Observation(t.Context(), now.Add(4*time.Minute)); observation.State != health.StateHealthy {
		t.Fatalf("recovered observation = %+v", observation)
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, policy := range []Policy{{Interval: 0, Workers: 1}, {Interval: time.Hour, Workers: 0}, {Interval: 366 * 24 * time.Hour, Workers: 1}, {Interval: time.Hour, Workers: 17}} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("invalid policy accepted: %+v", policy)
		}
	}
	if err := (Policy{Interval: time.Hour, Workers: 1}).Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), nil, newFakeRunner("alice"), Policy{Interval: time.Hour, Workers: 1}); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := New(context.Background(), &model.TypedStore{}, nil, Policy{Interval: time.Hour, Workers: 1}); err == nil {
		t.Fatal("nil runner accepted")
	}
}

func TestSchedulerHealthMarksOverdueChecks(t *testing.T) {
	runner := newFakeRunner("alice")
	scheduler, _ := schedulerFixture(t, runner, Policy{Enabled: true, Interval: time.Hour, Workers: 1})
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	status := Status{AccountID: runner.entries[0].Manifest.ID, Login: "alice", State: StateHealthy, LastResult: StateHealthy, LastCompletedAt: now.Add(-2 * time.Hour), DueAt: now.Add(-time.Hour), UpdatedAt: now.Add(-2 * time.Hour)}
	if err := scheduler.save(t.Context(), status); err != nil {
		t.Fatal(err)
	}
	observation := scheduler.Observation(t.Context(), now.Add(6*time.Minute))
	if observation.State != health.StateDegraded || observation.Details["overdue"] != "1" {
		t.Fatalf("overdue observation = %+v", observation)
	}
}
