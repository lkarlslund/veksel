package scheduledsend

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type fakeSubmitter struct {
	mu       sync.Mutex
	requests []service.Submission
	keys     []string
	err      error
	started  chan struct{}
	release  chan struct{}
}

func (f *fakeSubmitter) SubmitIdempotent(ctx context.Context, _ model.PrincipalRef, request service.Submission, key string) (service.SubmissionResult, error) {
	if f.started != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
	}
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return service.SubmissionResult{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests, f.keys = append(f.requests, request), append(f.keys, key)
	if f.err != nil {
		return service.SubmissionResult{}, f.err
	}
	return service.SubmissionResult{ID: "submission-1", SentItemID: "sent-1", AcceptedAt: time.Now().UTC()}, nil
}

func fixture(t *testing.T, submitter *fakeSubmitter) (*Service, *model.TypedStore, service.FolderSpace, time.Time) {
	t.Helper()
	backend, err := jsonstore.New(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, ns := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), ns); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := typed.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alice", "bob"} {
		if err := typed.FolderStore().CreateForUser(t.Context(), id); err != nil {
			t.Fatal(err)
		}
		if err := typed.UserStore().AddEmailAddress(t.Context(), id+"@example.test", id, "example.test", true); err != nil {
			t.Fatal(err)
		}
	}
	space := service.NewFolderSpace(typed, authz.New(typed))
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	scheduler, err := New(t.Context(), typed, space, submitter, Config{Workers: 2, MinDelay: time.Second, MaxDelay: 24 * time.Hour, Lease: time.Minute, Retry: time.Minute, Tick: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	scheduler.now = func() time.Time { return now }
	return scheduler, typed, space, now
}

func createDraft(t *testing.T, space service.FolderSpace, owner, subject string) model.Item {
	t.Helper()
	access := service.UserAccess(owner, "test")
	drafts, err := space.GetFolderByPath(t.Context(), access, "Drafts")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: " + owner + "@example.test\r\nTo: recipient@example.net\r\nSubject: " + subject + "\r\nContent-Type: text/plain\r\n\r\nbody")
	item, err := space.CreateItem(t.Context(), access, drafts.ID, service.ItemInput{Data: raw, Headers: map[string]string{"Subject": subject}, Flags: []string{model.FlagDraft}})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func waitState(t *testing.T, scheduler *Service, owner, id string, state State) Job {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, err := scheduler.Get(t.Context(), owner, id)
		if err == nil && job.State == state {
			return job
		}
		time.Sleep(time.Millisecond)
	}
	job, _ := scheduler.Get(t.Context(), owner, id)
	t.Fatalf("job state = %s, want %s", job.State, state)
	return Job{}
}

func TestScheduleSendsLatestDraftOnceAndIsOwnerScoped(t *testing.T) {
	submitter := &fakeSubmitter{}
	scheduler, _, space, now := fixture(t, submitter)
	draft := createDraft(t, space, "alice", "original")
	job, err := scheduler.Schedule(t.Context(), "alice", draft.ID, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.Get(t.Context(), "bob", job.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign get = %v", err)
	}
	if _, err := scheduler.List(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	updated := []byte("From: alice@example.test\r\nTo: recipient@example.net\r\nSubject: edited\r\nImportance: high\r\nX-Priority: 1\r\nX-Veksel-Require-TLS: true\r\nContent-Type: text/plain\r\n\r\nlatest")
	if _, err := space.UpdateItem(t.Context(), service.UserAccess("alice", "test"), draft.ID, updated, map[string]string{"Subject": "edited", "Importance": "high", "X-Priority": "1"}); err != nil {
		t.Fatal(err)
	}
	scheduler.now = func() time.Time { return now.Add(time.Hour) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	completed := waitState(t, scheduler, "alice", job.ID, StateCompleted)
	if completed.Submission.ID == "" || completed.Attempts != 1 || len(submitter.requests) != 1 || submitter.requests[0].Subject != "edited" || submitter.requests[0].Importance != service.MailImportanceHigh || !submitter.requests[0].RequireTLS || submitter.keys[0] != "scheduled:"+job.ID {
		t.Fatalf("completed=%+v requests=%+v keys=%v", completed, submitter.requests, submitter.keys)
	}
	if _, err := space.GetItem(t.Context(), service.UserAccess("alice", "test"), draft.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sent draft remains active: %v", err)
	}
}

func TestCancelAndClaimRaceHasDeterministicState(t *testing.T) {
	submitter := &fakeSubmitter{started: make(chan struct{}, 1), release: make(chan struct{})}
	scheduler, _, space, now := fixture(t, submitter)
	job, err := scheduler.Schedule(t.Context(), "alice", createDraft(t, space, "alice", "race").ID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	scheduler.now = func() time.Time { return now.Add(time.Second) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-submitter.started
	if _, err := scheduler.Cancel(t.Context(), "alice", job.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancel claimed job = %v", err)
	}
	close(submitter.release)
	waitState(t, scheduler, "alice", job.ID, StateCompleted)
}

func TestExpiredLeaseRecoversAndTemporaryFailureRetries(t *testing.T) {
	submitter := &fakeSubmitter{err: queue.ErrFull}
	scheduler, typed, space, now := fixture(t, submitter)
	job, err := scheduler.Schedule(t.Context(), "alice", createDraft(t, space, "alice", "retry").ID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	job.State, job.LeaseUntil = StateRunning, now.Add(-time.Second)
	if err := typed.Set(t.Context(), model.NSScheduledSubmissions, job.ID, job); err != nil {
		t.Fatal(err)
	}
	scheduler.now = func() time.Time { return now.Add(time.Second) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending := waitState(t, scheduler, "alice", job.ID, StatePending)
	if pending.Attempts != 1 || pending.LastError == "" || !pending.NextAttemptAt.Equal(now.Add(time.Minute+time.Second)) {
		t.Fatalf("retry state = %+v", pending)
	}
	submitter.err = nil
	scheduler.now = func() time.Time { return pending.NextAttemptAt }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	completed := waitState(t, scheduler, "alice", job.ID, StateCompleted)
	if completed.Attempts != 2 || len(submitter.requests) != 2 {
		t.Fatalf("retried completion = %+v requests=%d", completed, len(submitter.requests))
	}
}

func TestScheduleValidatesTimeAndDraftOwnership(t *testing.T) {
	scheduler, _, space, now := fixture(t, &fakeSubmitter{})
	draft := createDraft(t, space, "alice", "bounds")
	if _, err := scheduler.Schedule(t.Context(), "alice", draft.ID, now); err == nil {
		t.Fatal("immediate schedule accepted")
	}
	if _, err := scheduler.Schedule(t.Context(), "bob", draft.ID, now.Add(time.Hour)); err == nil {
		t.Fatal("foreign draft accepted")
	}
}

func TestScheduledSubmissionIsNotEarlyAndCancellationKeepsDraft(t *testing.T) {
	submitter := &fakeSubmitter{}
	scheduler, _, space, now := fixture(t, submitter)
	draft := createDraft(t, space, "alice", "not early")
	job, err := scheduler.Schedule(t.Context(), "alice", draft.ID, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	scheduler.now = func() time.Time { return now.Add(time.Hour - time.Nanosecond) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if current, err := scheduler.Get(t.Context(), "alice", job.ID); err != nil || current.State != StatePending || current.Attempts != 0 {
		t.Fatalf("early job = %+v, err = %v", current, err)
	}
	if len(submitter.requests) != 0 {
		t.Fatalf("early submission count = %d", len(submitter.requests))
	}
	cancelled, err := scheduler.Cancel(t.Context(), "alice", job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != StateCancelled || cancelled.CancelledAt.IsZero() {
		t.Fatalf("cancelled job = %+v", cancelled)
	}
	scheduler.now = func() time.Time { return now.Add(2 * time.Hour) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(submitter.requests) != 0 {
		t.Fatalf("cancelled submission count = %d", len(submitter.requests))
	}
	if _, err := space.GetItem(t.Context(), service.UserAccess("alice", "test"), draft.ID); err != nil {
		t.Fatalf("cancel removed draft: %v", err)
	}
}

func TestFatalFailureCanBeEditedAndRetriedByRescheduling(t *testing.T) {
	submitter := &fakeSubmitter{err: errors.New("sending identity permission was revoked")}
	scheduler, _, space, now := fixture(t, submitter)
	draft := createDraft(t, space, "alice", "revoked")
	job, err := scheduler.Schedule(t.Context(), "alice", draft.ID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	scheduler.now = func() time.Time { return now.Add(time.Second) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	failed := waitState(t, scheduler, "alice", job.ID, StateFailed)
	if failed.LastError != "sending identity permission was revoked" || failed.Attempts != 1 {
		t.Fatalf("failed job = %+v", failed)
	}
	if _, err := space.GetItem(t.Context(), service.UserAccess("alice", "test"), draft.ID); err != nil {
		t.Fatalf("failed submission removed draft: %v", err)
	}
	submitter.err = nil
	retryAt := now.Add(2 * time.Second)
	rescheduled, err := scheduler.Reschedule(t.Context(), "alice", job.ID, retryAt)
	if err != nil {
		t.Fatal(err)
	}
	if rescheduled.State != StatePending || rescheduled.LastError != "" || !rescheduled.DueAt.Equal(retryAt) {
		t.Fatalf("rescheduled job = %+v", rescheduled)
	}
	scheduler.now = func() time.Time { return retryAt }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	completed := waitState(t, scheduler, "alice", job.ID, StateCompleted)
	if completed.Attempts != 2 || len(submitter.requests) != 2 {
		t.Fatalf("retried job = %+v, submissions = %d", completed, len(submitter.requests))
	}
}

func TestConcurrentRunsClaimDueJobOnlyOnce(t *testing.T) {
	submitter := &fakeSubmitter{started: make(chan struct{}, 1), release: make(chan struct{})}
	scheduler, _, space, now := fixture(t, submitter)
	job, err := scheduler.Schedule(t.Context(), "alice", createDraft(t, space, "alice", "single claim").ID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	scheduler.now = func() time.Time { return now.Add(time.Second) }
	var calls sync.WaitGroup
	calls.Add(2)
	for range 2 {
		go func() {
			defer calls.Done()
			if err := scheduler.RunOnce(t.Context()); err != nil {
				t.Errorf("run once: %v", err)
			}
		}()
	}
	calls.Wait()
	<-submitter.started
	current, err := scheduler.Get(t.Context(), "alice", job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != StateRunning || current.Attempts != 1 {
		t.Fatalf("claimed job = %+v", current)
	}
	close(submitter.release)
	completed := waitState(t, scheduler, "alice", job.ID, StateCompleted)
	if completed.Attempts != 1 || len(submitter.requests) != 1 {
		t.Fatalf("completed job = %+v, submissions = %d", completed, len(submitter.requests))
	}
}
