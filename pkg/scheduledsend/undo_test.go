package scheduledsend

import (
	"errors"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/service"
)

func TestUndoHoldBypassesMinimumAndCancelKeepsDraftUnsent(t *testing.T) {
	submitter := &fakeSubmitter{}
	scheduler, _, space, now := fixture(t, submitter)
	scheduler.cfg.MinDelay = time.Minute
	draft := createDraft(t, space, "alice", "Oops")
	for _, delay := range []time.Duration{0, 500 * time.Millisecond, MaxUndoDelay + time.Second} {
		if _, err := scheduler.HoldForUndo(t.Context(), "alice", draft.ID, delay); err == nil {
			t.Fatalf("delay %s accepted", delay)
		}
	}
	if _, err := scheduler.HoldForUndo(t.Context(), "bob", draft.ID, 10*time.Second); err == nil {
		t.Fatal("another user's draft was held")
	}
	job, err := scheduler.HoldForUndo(t.Context(), "alice", draft.ID, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !job.Undo || !job.DueAt.Equal(now.Add(10*time.Second)) {
		t.Fatalf("held job = %+v", job)
	}
	scheduler.now = func() time.Time { return now.Add(9 * time.Second) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.Cancel(t.Context(), "alice", job.ID); err != nil {
		t.Fatal(err)
	}
	scheduler.now = func() time.Time { return now.Add(time.Minute) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	scheduler.wg.Wait()
	if len(submitter.requests) != 0 {
		t.Fatalf("cancelled undo hold submitted %d messages", len(submitter.requests))
	}
	if _, err := space.GetItem(t.Context(), service.UserAccess("alice", "test"), draft.ID); err != nil {
		t.Fatalf("draft removed after undo: %v", err)
	}
	// Finished holds are pruned after the retention window.
	scheduler.now = func() time.Time { return now.Add(undoRetention + 2*time.Minute) }
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.Get(t.Context(), "alice", job.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned undo hold lookup err = %v", err)
	}
}

func TestUndoHoldSurvivesRestartAndSendsOnce(t *testing.T) {
	submitter := &fakeSubmitter{}
	scheduler, typed, space, now := fixture(t, submitter)
	draft := createDraft(t, space, "alice", "Survives restart")
	job, err := scheduler.HoldForUndo(t.Context(), "alice", draft.ID, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// The process stops mid-window; a new scheduler over the same store
	// sends the held message once its window has elapsed.
	restarted, err := New(t.Context(), typed, space, submitter, scheduler.cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return now.Add(6 * time.Second) }
	if err := restarted.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	completed := waitState(t, restarted, "alice", job.ID, StateCompleted)
	if completed.Submission.SentItemID == "" || len(submitter.requests) != 1 || submitter.keys[0] != "scheduled:"+job.ID {
		t.Fatalf("completed = %+v requests=%d keys=%v", completed, len(submitter.requests), submitter.keys)
	}
	if _, err := space.GetItem(t.Context(), service.UserAccess("alice", "test"), draft.ID); err == nil {
		t.Fatal("sent draft still present")
	}
	if _, err := restarted.Cancel(t.Context(), "alice", job.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancel after send err = %v", err)
	}
}
