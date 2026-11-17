package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

func vacationIntent() *queue.Message {
	return &queue.Message{ID: "intent-1", Kind: smtp.MailTaskVacation, ParentID: "original-1", CorrelationID: "transaction-1",
		Attributes: map[string]string{"user_id": "alice", "sender": "sender@example.net", "derived_kind": "vacation"}, Recipient: "sender@example.net", Content: []byte("From: alice@example.test\r\n\r\nAway")}
}

func TestVacationIntentProcessorRepairsCrashAfterDerivedEnqueue(t *testing.T) {
	queued := map[string]*queue.Message{}
	enqueues, completes, records, releases := 0, 0, 0, 0
	completeErr := errors.New("rate store unavailable")
	p := VacationIntentProcessor{
		Prepare: func(context.Context, smtp.DerivedMessage) (*smtp.MailMessage, error) {
			return &smtp.MailMessage{ID: "derived-1", Recipient: "sender@example.net", Outbound: true}, nil
		},
		GetQueue:  func(id string) *queue.Message { return queued[id] },
		Completed: func(string) bool { return false },
		Enqueue: func(message *smtp.MailMessage) error {
			enqueues++
			if !message.Held {
				t.Fatal("derived vacation delivery was not held")
			}
			queued[message.ID] = &queue.Message{ID: message.ID, Status: queue.StatusPaused}
			return nil
		},
		Release:  func(string) bool { releases++; return true },
		Reserve:  func(context.Context, string, string, time.Duration) (string, bool, error) { return "token", true, nil },
		Complete: func(context.Context, string, string, string) error { completes++; return completeErr },
		Cancel:   func(context.Context, string, string, string) error { return nil },
		Record:   func(context.Context, string, string) error { records++; return nil },
	}
	if err := p.Process(t.Context(), vacationIntent()); !errors.Is(err, completeErr) {
		t.Fatalf("first process error = %v", err)
	}
	if err := p.Process(t.Context(), vacationIntent()); err != nil {
		t.Fatalf("replay process: %v", err)
	}
	if enqueues != 1 || completes != 1 || records != 1 || releases != 1 {
		t.Fatalf("enqueues=%d completes=%d records=%d releases=%d", enqueues, completes, records, releases)
	}
}

func TestVacationIntentProcessorPreservesTransportSecurity(t *testing.T) {
	intent := vacationIntent()
	intent.Attributes[smtp.AttributeRequireTLS] = "true"
	var prepared *smtp.MailMessage
	p := VacationIntentProcessor{
		Prepare: func(context.Context, smtp.DerivedMessage) (*smtp.MailMessage, error) {
			return &smtp.MailMessage{ID: "derived-secure"}, nil
		},
		GetQueue: func(string) *queue.Message { return nil }, Completed: func(string) bool { return false },
		Enqueue: func(message *smtp.MailMessage) error { prepared = message; return nil }, Release: func(string) bool { return true },
		Reserve:  func(context.Context, string, string, time.Duration) (string, bool, error) { return "token", true, nil },
		Complete: func(context.Context, string, string, string) error { return nil }, Cancel: func(context.Context, string, string, string) error { return nil },
		Record: func(context.Context, string, string) error { return nil },
	}
	if err := p.Process(t.Context(), intent); err != nil {
		t.Fatal(err)
	}
	if prepared == nil || prepared.Attributes[smtp.AttributeRequireTLS] != "true" {
		t.Fatalf("prepared message = %#v", prepared)
	}
}

func TestVacationIntentProcessorRequestsSigningOnlyForAuthorizedReplies(t *testing.T) {
	for _, authorized := range []bool{true, false} {
		intent := vacationIntent()
		if authorized {
			intent.Attributes[smtp.AttributeDKIMSign] = "true"
		}
		var derived smtp.DerivedMessage
		p := VacationIntentProcessor{
			Prepare: func(_ context.Context, message smtp.DerivedMessage) (*smtp.MailMessage, error) {
				derived = message
				return &smtp.MailMessage{ID: "derived-signed", DKIM: message.DKIM}, nil
			},
			GetQueue: func(string) *queue.Message { return nil }, Completed: func(string) bool { return false },
			Enqueue: func(*smtp.MailMessage) error { return nil }, Release: func(string) bool { return true },
			Reserve:  func(context.Context, string, string, time.Duration) (string, bool, error) { return "token", true, nil },
			Complete: func(context.Context, string, string, string) error { return nil }, Cancel: func(context.Context, string, string, string) error { return nil },
			Record: func(context.Context, string, string) error { return nil },
		}
		if err := p.Process(t.Context(), intent); err != nil {
			t.Fatal(err)
		}
		if (derived.DKIM != nil) != authorized {
			t.Fatalf("authorized=%v: DKIM request = %+v", authorized, derived.DKIM)
		}
	}
}

func TestVacationIntentProcessorCancelsFailedEnqueueAndHonorsRateLimit(t *testing.T) {
	cancelled, enqueued := "", 0
	allowed := true
	p := VacationIntentProcessor{
		Prepare: func(context.Context, smtp.DerivedMessage) (*smtp.MailMessage, error) {
			return &smtp.MailMessage{ID: "derived-1"}, nil
		},
		GetQueue:  func(string) *queue.Message { return nil },
		Completed: func(string) bool { return false },
		Enqueue:   func(*smtp.MailMessage) error { enqueued++; return errors.New("queue unavailable") },
		Release:   func(string) bool { return true },
		Reserve: func(context.Context, string, string, time.Duration) (string, bool, error) {
			return "token", allowed, nil
		},
		Complete: func(context.Context, string, string, string) error { return nil },
		Cancel:   func(_ context.Context, _, _, token string) error { cancelled = token; return nil },
		Record:   func(context.Context, string, string) error { return nil },
	}
	if err := p.Process(t.Context(), vacationIntent()); err == nil || cancelled != "token" || enqueued != 1 {
		t.Fatalf("error=%v cancelled=%q enqueued=%d", err, cancelled, enqueued)
	}
	allowed, cancelled = false, ""
	if err := p.Process(t.Context(), vacationIntent()); err != nil || enqueued != 1 || cancelled != "" {
		t.Fatalf("limited error=%v cancelled=%q enqueued=%d", err, cancelled, enqueued)
	}
}

func TestVacationIntentProcessorRepairsCompletedDerivedReceipt(t *testing.T) {
	recorded, enqueued := 0, 0
	p := VacationIntentProcessor{
		Prepare: func(context.Context, smtp.DerivedMessage) (*smtp.MailMessage, error) {
			return &smtp.MailMessage{ID: "already-completed"}, nil
		},
		GetQueue: func(string) *queue.Message { return nil }, Completed: func(id string) bool { return id == "already-completed" },
		Enqueue: func(*smtp.MailMessage) error { enqueued++; return nil }, Release: func(string) bool { return true },
		Reserve:  func(context.Context, string, string, time.Duration) (string, bool, error) { return "", true, nil },
		Complete: func(context.Context, string, string, string) error { return nil }, Cancel: func(context.Context, string, string, string) error { return nil },
		Record: func(context.Context, string, string) error { recorded++; return nil },
	}
	if err := p.Process(t.Context(), vacationIntent()); err != nil || recorded != 1 || enqueued != 0 {
		t.Fatalf("error=%v recorded=%d enqueued=%d", err, recorded, enqueued)
	}
}

func TestVacationIntentProcessorUsesSieveTrackingKeyAndPeriod(t *testing.T) {
	for _, tc := range []struct {
		attributes map[string]string
		key        string
		period     time.Duration
	}{
		{nil, "sender@example.net", 24 * time.Hour},
		{map[string]string{smtp.AttributeVacationKey: "sieve:h1:sender@example.net", smtp.AttributeVacationPeriod: "0"}, "sieve:h1:sender@example.net", 0},
		{map[string]string{smtp.AttributeVacationKey: "sieve:h2:sender@example.net", smtp.AttributeVacationPeriod: "172800"}, "sieve:h2:sender@example.net", 48 * time.Hour},
	} {
		intent := vacationIntent()
		for name, value := range tc.attributes {
			intent.Attributes[name] = value
		}
		var reservedKey, completedKey string
		var reservedPeriod time.Duration
		p := VacationIntentProcessor{
			Prepare: func(context.Context, smtp.DerivedMessage) (*smtp.MailMessage, error) {
				return &smtp.MailMessage{ID: "derived-tracked"}, nil
			},
			GetQueue: func(string) *queue.Message { return nil }, Completed: func(string) bool { return false },
			Enqueue: func(*smtp.MailMessage) error { return nil }, Release: func(string) bool { return true },
			Reserve: func(_ context.Context, _, key string, period time.Duration) (string, bool, error) {
				reservedKey, reservedPeriod = key, period
				return "token", true, nil
			},
			Complete: func(_ context.Context, _, key, _ string) error { completedKey = key; return nil },
			Cancel:   func(context.Context, string, string, string) error { return nil },
			Record:   func(context.Context, string, string) error { return nil },
		}
		if err := p.Process(t.Context(), intent); err != nil {
			t.Fatal(err)
		}
		if reservedKey != tc.key || completedKey != tc.key || reservedPeriod != tc.period {
			t.Fatalf("attributes %v: reserved %q/%v completed %q", tc.attributes, reservedKey, reservedPeriod, completedKey)
		}
	}
}
