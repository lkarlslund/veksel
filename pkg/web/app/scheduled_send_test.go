package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/scheduledsend"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestScheduledSubmissionResponseOmitsUnsetLifecycleTimes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	encoded, err := json.Marshal(scheduledSubmissionResponse(scheduledsend.Job{
		SchemaVersion: 1,
		ID:            "scheduled-1",
		OwnerID:       "alice",
		DraftID:       "draft-1",
		State:         scheduledsend.StatePending,
		DueAt:         now.Add(time.Hour),
		CreatedAt:     now,
		UpdatedAt:     now,
	}))
	if err != nil {
		t.Fatal(err)
	}
	response := string(encoded)
	for _, field := range []string{"next_attempt_at", "lease_until", "submission", "completed_at", "cancelled_at"} {
		if strings.Contains(response, field) {
			t.Errorf("unset field %q leaked into response: %s", field, response)
		}
	}
}

func TestScheduledSubmissionResponseIncludesTerminalEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	view := scheduledSubmissionResponse(scheduledsend.Job{
		ID:          "scheduled-1",
		State:       scheduledsend.StateCompleted,
		CompletedAt: now,
		Submission: service.SubmissionResult{
			ID:         "submission-1",
			SentItemID: "sent-1",
			AcceptedAt: now,
		},
	})
	if view.CompletedAt == nil || !view.CompletedAt.Equal(now) {
		t.Fatalf("completed_at = %v, want %v", view.CompletedAt, now)
	}
	if view.Submission == nil || view.Submission.ID != "submission-1" || view.Submission.SentItemID != "sent-1" {
		t.Fatalf("submission = %#v", view.Submission)
	}
}
