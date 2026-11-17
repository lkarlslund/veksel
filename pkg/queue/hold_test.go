package queue

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// gatedDelivery blocks each attempt until the test releases it with the
// attempt's result, so a hold can be placed while the message is processing.
type gatedDelivery struct {
	started chan string
	results chan error
}

func newGatedDelivery() *gatedDelivery {
	return &gatedDelivery{started: make(chan string, 4), results: make(chan error)}
}

func (g *gatedDelivery) deliver(ctx context.Context, message *Message) error {
	g.started <- message.ID
	select {
	case err := <-g.results:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *gatedDelivery) awaitStart(t *testing.T) string {
	t.Helper()
	select {
	case id := <-g.started:
		return id
	case <-time.After(5 * time.Second):
		t.Fatal("delivery attempt did not start")
		return ""
	}
}

func TestHoldDuringAttemptTakesEffectWhenAttemptEnds(t *testing.T) {
	for _, test := range []struct {
		name    string
		result  error
		status  Status
		retries int
	}{
		{name: "temporary failure", result: &DeliveryError{Class: DeliveryTemporary, Response: "try later"}, status: StatusPaused, retries: 1},
		{name: "deferred", result: &DeliveryError{Class: DeliveryDeferred, Response: "mailbox busy"}, status: StatusPaused},
		{name: "uncertain", result: &DeliveryError{Class: DeliveryUncertain, Response: "connection lost"}, status: StatusPaused, retries: 1},
		{name: "permanent failure", result: &DeliveryError{Class: DeliveryPermanent, Response: "no such user"}, status: StatusFailed, retries: 1},
		{name: "delivered", status: StatusDelivered},
	} {
		t.Run(test.name, func(t *testing.T) {
			gate := newGatedDelivery()
			q := New(&Config{Workers: 1, ProcessPeriod: time.Hour, Delivery: gate.deliver})
			defer q.Close()
			if err := q.Enqueue(&Message{ID: "m1", Direction: DirectionOutbound, Recipient: "bob@remote.test"}); err != nil {
				t.Fatal(err)
			}
			gate.awaitStart(t)
			if !q.HoldWithReason("m1", "Investigating") {
				t.Fatal("hold of a processing message was not recorded")
			}
			if q.HoldWithReason("m1", "Again") {
				t.Fatal("a second pending hold was recorded")
			}
			if message := q.Get("m1"); message.Status != StatusProcessing || message.PendingHoldReason != "Investigating" || message.PendingHoldAt.IsZero() {
				t.Fatalf("pending hold = %+v", message)
			}
			gate.results <- test.result
			if test.status == StatusDelivered {
				deadline := time.Now().Add(5 * time.Second)
				for !q.WasCompleted("m1") {
					if time.Now().After(deadline) {
						t.Fatalf("delivered message not completed: %+v", q.Get("m1"))
					}
					time.Sleep(time.Millisecond)
				}
				if q.Get("m1") != nil {
					t.Fatal("delivered message still queued")
				}
				return
			}
			waitQueueStatus(t, q, "m1", test.status)
			message := q.Get("m1")
			if message.PendingHoldReason != "" || !message.PendingHoldAt.IsZero() || message.RetryCount != test.retries || len(message.Attempts) != 1 {
				t.Fatalf("message after attempt = %+v", message)
			}
			if test.status == StatusPaused && (message.HoldReason != "Investigating" || message.HeldAt.IsZero() || !message.NextRetry.IsZero() || message.AttemptID != "") {
				t.Fatalf("held message = %+v", message)
			}
			if test.status == StatusFailed && message.HoldReason != "" {
				t.Fatalf("permanently failed message was marked held: %+v", message)
			}
		})
	}
}

func TestReleaseDuringAttemptWithdrawsPendingHold(t *testing.T) {
	gate := newGatedDelivery()
	q := New(&Config{Workers: 1, ProcessPeriod: time.Hour, RetryInitial: time.Hour, Delivery: gate.deliver})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "m1", Recipient: "bob@remote.test"}); err != nil {
		t.Fatal(err)
	}
	gate.awaitStart(t)
	if q.Release("m1") {
		t.Fatal("release of a processing message without a pending hold succeeded")
	}
	if !q.HoldWithReason("m1", "Investigating") || !q.Release("m1") {
		t.Fatal("pending hold was not placed and withdrawn")
	}
	gate.results <- &DeliveryError{Class: DeliveryTemporary, Response: "try later"}
	waitQueueStatus(t, q, "m1", StatusRetrying)
	if message := q.Get("m1"); message.PendingHoldReason != "" || message.HoldReason != "" {
		t.Fatalf("message after withdrawn hold = %+v", message)
	}
}

func TestPendingHoldIsDurableAndAppliedOnRecovery(t *testing.T) {
	backend := durableTestStore(t)
	heldAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	persisted := toDiskMessage(&Message{ID: "claimed-held", Direction: DirectionOutbound, Recipient: "bob@remote.test", Status: StatusProcessing,
		AttemptID: "attempt-1", ClaimedAt: heldAt, PendingHoldReason: "Investigating", PendingHoldAt: heldAt, CreatedAt: heldAt})
	data, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Set(t.Context(), model.NSQueue, messageKeyPrefix+persisted.ID, data); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	q, err := NewPersistent(t.Context(), backend, &Config{Delivery: func(context.Context, *Message) error {
		attempts.Add(1)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	message := q.Get("claimed-held")
	if message == nil || message.Status != StatusPaused || message.HoldReason != "Investigating" || !message.HeldAt.Equal(heldAt) || message.PendingHoldReason != "" || message.AttemptID != "" {
		t.Fatalf("recovered message = %+v", message)
	}
	if detail := ProjectMessageDetail(message); detail.HoldReason != "Investigating" || detail.PendingHoldReason != "" {
		t.Fatalf("detail = %+v", detail)
	}
	time.Sleep(10 * time.Millisecond)
	if attempts.Load() != 0 {
		t.Fatalf("held message attempted %d times", attempts.Load())
	}
}

func TestDeliveryHoldPausesInsteadOfAttempting(t *testing.T) {
	var attempts atomic.Int32
	var holding atomic.Bool
	holding.Store(true)
	q := New(&Config{Workers: 1, ProcessPeriod: time.Hour,
		DeliveryHold: func(message *Message) string {
			if holding.Load() && message.AuthenticatedActor == "alice" {
				return "account held"
			}
			return ""
		},
		Delivery: func(context.Context, *Message) error {
			attempts.Add(1)
			return nil
		}})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "alice-1", AuthenticatedActor: "alice", Recipient: "x@remote.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "alice-1", StatusPaused)
	if message := q.Get("alice-1"); message.HoldReason != "account held" || message.RetryCount != 0 || len(message.Attempts) != 0 || attempts.Load() != 0 {
		t.Fatalf("held message = %+v, attempts %d", message, attempts.Load())
	}
	if err := q.Enqueue(&Message{ID: "bob-1", AuthenticatedActor: "bob", Recipient: "y@remote.test"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !q.WasCompleted("bob-1") {
		if time.Now().After(deadline) {
			t.Fatal("unheld message was not delivered")
		}
		time.Sleep(time.Millisecond)
	}
	holding.Store(false)
	if !q.Release("alice-1") {
		t.Fatal("release rejected")
	}
	deadline = time.Now().Add(5 * time.Second)
	for !q.WasCompleted("alice-1") {
		if time.Now().After(deadline) {
			t.Fatal("released message was not delivered")
		}
		time.Sleep(time.Millisecond)
	}
}
