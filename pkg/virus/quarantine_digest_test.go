package virus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func newDigestTestService(t *testing.T) (*QuarantineDigestService, *QuarantineStore, time.Time) {
	t.Helper()
	quarantine, typed := newQuarantineTestStore(t, QuarantinePolicy{Retention: 30 * 24 * time.Hour})
	actions, err := NewQuarantineActionService(t.Context(), typed, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 10, 30, 0, 0, time.UTC)
	quarantine.now, actions.now = func() time.Time { return now }, func() time.Time { return now }
	service, err := NewQuarantineDigestService(typed, quarantine, actions, func(_ context.Context, userID string) (string, error) {
		return userID + "@example.test", nil
	}, QuarantineDigestConfig{BaseURL: "https://mail.example.test", FromAddress: "Veksel <postmaster@example.test>", MaxEntries: 50, MaxJobsPerRun: 10, MaxAttempts: 3, RetryBase: time.Minute, JobRetention: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	return service, quarantine, now
}

func TestNextQuarantineDigestRun(t *testing.T) {
	now := time.Date(2026, 8, 18, 10, 30, 0, 0, time.UTC) // Tuesday
	if got, want := nextQuarantineDigestRun(now, QuarantineDigestDaily, 9, 0), time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC); got != want {
		t.Fatalf("daily next = %s, want %s", got, want)
	}
	if got, want := nextQuarantineDigestRun(now, QuarantineDigestWeekly, 8, int(time.Monday)), time.Date(2026, 8, 24, 8, 0, 0, 0, time.UTC); got != want {
		t.Fatalf("weekly next = %s, want %s", got, want)
	}
}

func TestQuarantineDigestRetryDelayCapsWithoutOverflow(t *testing.T) {
	if got := quarantineDigestRetryDelay(24*time.Hour, 100); got != 24*time.Hour {
		t.Fatalf("retry delay = %s, want 24h", got)
	}
	if got := quarantineDigestRetryDelay(time.Minute, 3); got != 4*time.Minute {
		t.Fatalf("retry delay = %s, want 4m", got)
	}
}

func TestQuarantineDigestPersistsBeforeSendingAndCompletes(t *testing.T) {
	service, quarantine, now := newDigestTestService(t)
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "held", OwnerID: "alice", Sender: "sender@example.net", Subject: "Held subject", MessageData: []byte("message")}); err != nil {
		t.Fatal(err)
	}
	preference, err := service.SetPreference(t.Context(), QuarantineDigestPreference{UserID: "alice", Schedule: QuarantineDigestDaily, HourUTC: 11, Weekday: int(time.Monday)})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return preference.NextRunAt }
	var sent QuarantineDigestJob
	result, err := service.Run(t.Context(), func(_ context.Context, job QuarantineDigestJob) error {
		jobs, listErr := service.ListJobs(t.Context())
		if listErr != nil || len(jobs) != 1 || jobs[0].Status != quarantineDigestSending || len(jobs[0].FullMessage) == 0 {
			t.Fatalf("job not durable before send: %+v, %v", jobs, listErr)
		}
		sent = job
		return nil
	})
	if err != nil || result.Prepared != 1 || result.Sent != 1 {
		t.Fatalf("run = %+v, %v", result, err)
	}
	message := string(sent.FullMessage)
	if !strings.Contains(message, "Held subject") || !strings.Contains(message, "/quarantine/action?token=") || !strings.Contains(message, "Auto-Submitted: auto-generated") {
		t.Fatalf("digest message = %s", message)
	}
	jobs, _ := service.ListJobs(t.Context())
	if jobs[0].Status != quarantineDigestSent || len(jobs[0].FullMessage) != 0 {
		t.Fatalf("completed job = %+v", jobs[0])
	}
	updated, _ := service.GetPreference(t.Context(), "alice")
	if updated.PendingJobID != "" || updated.LastSentAt != preference.NextRunAt || !updated.NextRunAt.After(now) {
		t.Fatalf("updated preference = %+v", updated)
	}
}

func TestQuarantineDigestEmptyRunAndRetrySurviveRestart(t *testing.T) {
	service, quarantine, _ := newDigestTestService(t)
	preference, err := service.SetPreference(t.Context(), QuarantineDigestPreference{UserID: "alice", Schedule: QuarantineDigestDaily, HourUTC: 11, Weekday: 0})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return preference.NextRunAt }
	result, err := service.Run(t.Context(), func(context.Context, QuarantineDigestJob) error { return nil })
	if err != nil || result.Empty != 1 || result.Prepared != 0 {
		t.Fatalf("empty run = %+v, %v", result, err)
	}
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "held", OwnerID: "alice", Subject: "retry", MessageData: []byte("message")}); err != nil {
		t.Fatal(err)
	}
	preference, _ = service.GetPreference(t.Context(), "alice")
	service.now = func() time.Time { return preference.NextRunAt }
	result, err = service.Run(t.Context(), func(context.Context, QuarantineDigestJob) error { return errors.New("queue unavailable") })
	if err != nil || result.Prepared != 1 || result.Retried != 1 {
		t.Fatalf("retry run = %+v, %v", result, err)
	}
	jobs, _ := service.ListJobs(t.Context())
	if len(jobs) != 1 || jobs[0].Status != quarantineDigestPending || jobs[0].Attempts != 1 || len(jobs[0].FullMessage) == 0 {
		t.Fatalf("retry job = %+v", jobs)
	}
	service.now = func() time.Time { return jobs[0].NextAttemptAt }
	result, err = service.Run(t.Context(), func(context.Context, QuarantineDigestJob) error { return nil })
	if err != nil || result.Sent != 1 {
		t.Fatalf("restart retry = %+v, %v", result, err)
	}
}

func TestQuarantineDigestOptOutCancelsPendingJob(t *testing.T) {
	service, quarantine, _ := newDigestTestService(t)
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "held", OwnerID: "alice", MessageData: []byte("message")}); err != nil {
		t.Fatal(err)
	}
	preference, _ := service.SetPreference(t.Context(), QuarantineDigestPreference{UserID: "alice", Schedule: QuarantineDigestDaily, HourUTC: 11})
	service.now = func() time.Time { return preference.NextRunAt }
	if _, _, err := service.preparePreference(t.Context(), "alice", preference.NextRunAt); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetPreference(t.Context(), QuarantineDigestPreference{UserID: "alice", Schedule: QuarantineDigestOff, HourUTC: 11}); err != nil {
		t.Fatal(err)
	}
	jobs, _ := service.ListJobs(t.Context())
	if len(jobs) != 1 || jobs[0].Status != quarantineDigestCancelled || len(jobs[0].FullMessage) != 0 {
		t.Fatalf("cancelled job = %+v", jobs)
	}
}
