package queue

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/virus"
)

type receiptFailStore struct {
	store.Store
	fail atomic.Bool
}

func TestPersistentQueueRestoresPolicyAdmissionEvidence(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err := backend.CreateNamespace(t.Context(), model.NSQueue); err != nil {
		t.Fatal(err)
	}
	first, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour, Admission: func(_ context.Context, message *Message) error {
		message.Policy = mailpolicy.Result{Revision: "revision-a", Rules: []mailpolicy.RuleResult{{RuleID: "route", Matched: true}}, Actions: []mailpolicy.Action{{Type: mailpolicy.ActionRoute, Value: "relay.example"}}}
		message.PolicyRoute = "relay.example"
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Enqueue(&Message{ID: "policy-restart", Recipient: "user@example.test", NextRetry: time.Now().Add(time.Hour), Attributes: map[string]string{smtp.AttributeRequireTLS: "true"}}); err != nil {
		t.Fatal(err)
	}
	first.Close()
	restored, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	message := restored.Get("policy-restart")
	if message == nil || message.Policy.Revision != "revision-a" || message.PolicyRoute != "relay.example" || len(message.Policy.MatchedRuleIDs()) != 1 || message.Attributes[smtp.AttributeRequireTLS] != "true" {
		t.Fatalf("restored policy evidence = %+v", message)
	}
}

func TestPersistentQueueRestoresAdministrativeRouteHistory(t *testing.T) {
	backend := durableTestStore(t)
	first, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Enqueue(&Message{ID: "reroute-restart", Direction: DirectionOutbound, PolicyRoute: "policy.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Reroute("reroute-restart", "alternate.example", "owner", "temporary route outage"); err != nil {
		t.Fatal(err)
	}
	first.Close()
	restored, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	message := restored.Get("reroute-restart")
	if message == nil || message.AdministrativeRoute != "alternate.example" || message.PolicyRoute != "policy.example" || len(message.RouteChanges) != 1 || message.RouteChanges[0].Actor != "owner" {
		t.Fatalf("restored reroute evidence = %+v", message)
	}
}

func (s *receiptFailStore) Set(ctx context.Context, namespace, key string, value []byte) error {
	if strings.HasPrefix(key, receiptKeyPrefix) && s.fail.CompareAndSwap(true, false) {
		return faultstore.ErrInjected
	}
	return s.Store.Set(ctx, namespace, key, value)
}

func TestPersistentQueueAtomicAdmissionFailureIsInvisible(t *testing.T) {
	backend := durableTestStore(t)
	faults := faultstore.New(backend)
	q, err := NewPersistent(t.Context(), faults, &Config{ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	faults.Fail("batch_commit", 1)
	err = q.EnqueueBatch([]*Message{{ID: "atomic-a", Recipient: "a@example.test"}, {ID: "atomic-b", Recipient: "b@example.test"}})
	if !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("enqueue error = %v", err)
	}
	if q.Size() != 0 {
		t.Fatalf("failed admission visible in memory: %d", q.Size())
	}
	keys, err := backend.Scan(t.Context(), model.NSQueue, messageKeyPrefix)
	if err != nil || len(keys) != 0 {
		t.Fatalf("failed admission visible on disk: %v, %v", keys, err)
	}
}

func TestPersistentQueueRestoresIdempotentAcceptance(t *testing.T) {
	backend := durableTestStore(t)
	first, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	batch := []*Message{{ID: "scheduled-restart-a", Recipient: "a@example.test", NextRetry: time.Now().Add(time.Hour)}, {ID: "scheduled-restart-b", Recipient: "b@example.test", NextRetry: time.Now().Add(time.Hour)}}
	if err := first.EnqueueBatchIdempotent("scheduled:alice:restart", batch); err != nil {
		t.Fatal(err)
	}
	first.Close()
	restored, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.EnqueueBatchIdempotent("scheduled:alice:restart", []*Message{{ID: "scheduled-restart-a"}, {ID: "scheduled-restart-b"}}); err != nil {
		t.Fatalf("restored idempotent retry = %v", err)
	}
	if restored.Size() != 2 {
		t.Fatalf("restored queue size = %d, want 2", restored.Size())
	}
	keys, err := backend.Scan(t.Context(), model.NSQueue, acceptanceKeyPrefix)
	if err != nil || len(keys) != 1 {
		t.Fatalf("acceptance receipt keys = %v, %v", keys, err)
	}
}

func TestPersistentQueueRecordsUncertainAttempt(t *testing.T) {
	backend := durableTestStore(t)
	q, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour, RetryInitial: time.Hour, Delivery: func(ctx context.Context, _ *Message) error {
		RecordDeliveryRoute(ctx, "direct-mx")
		return &DeliveryError{Class: DeliveryUncertain, Response: "timeout after DATA"}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "uncertain", Recipient: "outside@example.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "uncertain", StatusRetrying)
	message := q.Get("uncertain")
	if !message.PossibleDuplicate || len(message.Attempts) != 1 || message.Attempts[0].Class != DeliveryUncertain || message.DeliveryRoute != "direct-mx" {
		t.Fatalf("uncertain message = %+v", message)
	}
	data, err := backend.Get(t.Context(), model.NSQueue, messageKeyPrefix+message.ID)
	if err != nil || !strings.Contains(string(data), `"possible_duplicate":true`) || !strings.Contains(string(data), `"delivery_route":"direct-mx"`) {
		t.Fatalf("durable uncertain state = %s, %v", data, err)
	}
}

func TestPersistentQueueUncertaintySurvivesRestartAndBackoffCaps(t *testing.T) {
	backend := durableTestStore(t)
	delivery := func(context.Context, *Message) error {
		return &DeliveryError{Class: DeliveryUncertain, EnhancedCode: "4.4.2", Response: "connection closed after DATA"}
	}
	config := &Config{ProcessPeriod: 5 * time.Millisecond, Workers: 1, MaxAge: 500 * time.Millisecond, RetryInitial: 100 * time.Millisecond, RetryMax: 150 * time.Millisecond, Delivery: delivery}
	queue, err := NewPersistent(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(&Message{ID: "uncertain-restart", EnvelopeSender: "sender@example.test", Recipient: "outside@example.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, queue, "uncertain-restart", StatusRetrying)
	beforeRestart := queue.Get("uncertain-restart")
	if beforeRestart == nil || beforeRestart.RetryCount != 1 || !beforeRestart.PossibleDuplicate || len(beforeRestart.Attempts) != 1 {
		t.Fatalf("before restart = %+v", beforeRestart)
	}
	if delay := time.Until(beforeRestart.NextRetry); delay < 50*time.Millisecond || delay > 200*time.Millisecond {
		t.Fatalf("initial backoff = %v", delay)
	}
	queue.Close()

	reopened, err := NewPersistent(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored := reopened.Get("uncertain-restart")
	if restored == nil || restored.RetryCount != 1 || !restored.PossibleDuplicate || len(restored.Attempts) != 1 {
		t.Fatalf("restored = %+v", restored)
	}
	waitQueueStatus(t, reopened, "uncertain-restart", StatusFailed)
	failed := reopened.Get("uncertain-restart")
	if failed == nil || failed.LastCode != "5.4.7" || !failed.PossibleDuplicate || len(failed.Attempts) < 3 {
		t.Fatalf("terminal uncertain message = %+v", failed)
	}
	// Every attempt before expiry kept its uncertain evidence and capped backoff.
	uncertain := failed.Attempts[:len(failed.Attempts)-1]
	for index, attempt := range uncertain {
		if attempt.Class != DeliveryUncertain || attempt.Code != "4.4.2" {
			t.Fatalf("attempt %d = %+v", index, attempt)
		}
		if index > 0 {
			gap := attempt.StartedAt.Sub(uncertain[index-1].StartedAt)
			if gap < 70*time.Millisecond || gap > 400*time.Millisecond {
				t.Fatalf("attempt %d backoff gap = %v", index, gap)
			}
		}
	}
}

func TestMaintenanceHoldDoesNotConsumeRetriesAndWakesAfterRestart(t *testing.T) {
	backend := durableTestStore(t)
	var maintenance atomic.Bool
	maintenance.Store(true)
	delivered := make(chan struct{}, 1)
	delivery := func(context.Context, *Message) error {
		if maintenance.Load() {
			return &DeliveryError{Class: DeliveryDeferred, EnhancedCode: "4.3.2", Response: "account maintenance", RetryAfter: time.Hour}
		}
		delivered <- struct{}{}
		return nil
	}
	config := &Config{ProcessPeriod: time.Hour, Workers: 1, Delivery: delivery}
	queue, err := NewPersistent(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(&Message{ID: "held", TargetOwnerID: "alice", TargetFolderID: "alice:inbox", Recipient: "alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, queue, "held", StatusHeld)
	held := queue.Get("held")
	if held == nil || held.RetryCount != 0 || len(held.Attempts) != 1 || held.Attempts[0].Class != DeliveryDeferred {
		t.Fatalf("held message = %+v", held)
	}
	queue.Close()

	reopened, err := NewPersistent(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	held = reopened.Get("held")
	if held == nil || held.Status != StatusHeld || held.RetryCount != 0 {
		t.Fatalf("restored hold = %+v", held)
	}
	maintenance.Store(false)
	if count, err := reopened.WakeOwner("bob"); err != nil || count != 0 {
		t.Fatalf("wake other owner = %d, %v", count, err)
	}
	if count, err := reopened.WakeOwner("alice"); err != nil || count != 1 {
		t.Fatalf("wake alice = %d, %v", count, err)
	}
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("woken maintenance delivery did not run")
	}
}

func TestOperatorHoldAndReleasePersist(t *testing.T) {
	backend := durableTestStore(t)
	delivered := make(chan struct{}, 1)
	events := make(chan Event, 4)
	config := &Config{ProcessPeriod: time.Hour, Workers: 1, Delivery: func(context.Context, *Message) error {
		delivered <- struct{}{}
		return nil
	}, Observer: func(_ context.Context, event Event) { events <- event }}
	queue, err := NewPersistent(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(&Message{ID: "operator-held", Recipient: "outside@example.test", NextRetry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if !queue.HoldWithReason("operator-held", "Investigating repeated remote rejection") {
		t.Fatal("hold was rejected")
	}
	if held := queue.Get("operator-held"); held == nil || held.Status != StatusPaused || held.RetryCount != 0 || !held.NextRetry.IsZero() {
		t.Fatalf("held message = %+v", held)
	}
	if event := <-events; event.Stage != "accepted" {
		t.Fatalf("initial event = %#v", event)
	}
	if event := <-events; event.Stage != "operator_hold" || event.Response != "Investigating repeated remote rejection" {
		t.Fatalf("hold event = %#v", event)
	}
	queue.Close()

	reopened, err := NewPersistent(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if held := reopened.Get("operator-held"); held == nil || held.Status != StatusPaused || held.HoldReason != "Investigating repeated remote rejection" || held.HeldAt.IsZero() {
		t.Fatalf("restored operator hold = %+v", held)
	}
	if !reopened.Release("operator-held") {
		t.Fatal("release was rejected")
	}
	if event := <-events; event.Stage != "operator_release" || event.Response != "Investigating repeated remote rejection" {
		t.Fatalf("release event = %#v", event)
	}
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("released delivery did not run")
	}
}

func durableTestStore(t *testing.T) *jsonstore.Store {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("create JSON store: %v", err)
	}
	if err := backend.CreateNamespace(t.Context(), model.NSQueue); err != nil {
		t.Fatalf("create queue namespace: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

func TestPersistentQueueRestoresCompletePayload(t *testing.T) {
	backend := durableTestStore(t)
	cfg := &Config{ProcessPeriod: time.Hour}
	q, err := NewPersistent(t.Context(), backend, cfg)
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	msg := &Message{ID: "durable-1", Kind: smtp.MailTaskVacation, Attributes: map[string]string{"user_id": "alice", "sender": "sender@example.net", "derived_kind": "vacation"}, Direction: DirectionInbound, Recipient: "alice@example.test",
		Headers: map[string]string{"Subject": "Durable"}, Body: []byte("body bytes"),
		Content: []byte("Subject: Durable\r\n\r\nbody bytes"), TargetFolderPath: "Projects/2026", TargetOwnerID: "alice"}
	if err := q.Enqueue(msg); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	q.Close()

	restored, err := NewPersistent(t.Context(), backend, cfg)
	if err != nil {
		t.Fatalf("reopen queue: %v", err)
	}
	defer restored.Close()
	got := restored.Get(msg.ID)
	if got == nil {
		t.Fatal("persisted message was not restored")
	}
	if string(got.Body) != "body bytes" || string(got.Content) != "Subject: Durable\r\n\r\nbody bytes" {
		t.Fatalf("payload changed across restart: body=%q content=%q", got.Body, got.Content)
	}
	if got.Direction != DirectionInbound || got.TargetFolderPath != "Projects/2026" || got.TargetOwnerID != "alice" || got.Kind != smtp.MailTaskVacation || got.Attributes["sender"] != "sender@example.net" {
		t.Fatalf("routing metadata changed: direction=%q path=%q owner=%q", got.Direction, got.TargetFolderPath, got.TargetOwnerID)
	}
}

func TestPersistentQueueRestoresAtomicDerivedDelivery(t *testing.T) {
	backend := durableTestStore(t)
	cfg := &Config{ProcessPeriod: time.Hour}
	q, err := NewPersistent(t.Context(), backend, cfg)
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewSMTPAdapter(q)
	if err := adapter.EnqueueBatch([]*smtp.MailMessage{
		{ID: "original-local", CorrelationID: "transaction-derived", TargetFolderID: "alice:inbox", TargetOwnerID: "alice", Content: []byte("original")},
		{ID: "derived-forward", ParentID: "original-local", CorrelationID: "transaction-derived", Recipient: "archive@example.net", Headers: map[string]string{"Subject": "forward"}, Body: []byte("body"), Outbound: true},
	}); err != nil {
		t.Fatal(err)
	}
	q.Close()

	restored, err := NewPersistent(t.Context(), backend, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	original, derived := restored.Get("original-local"), restored.Get("derived-forward")
	if original == nil || derived == nil || derived.ParentID != original.ID || derived.CorrelationID != original.CorrelationID || derived.Direction != DirectionOutbound || derived.Recipient != "archive@example.net" || string(derived.Body) != "body" {
		t.Fatalf("restored original=%+v derived=%+v", original, derived)
	}
}

func TestPersistentCompletionReceiptRejectsReplayAcrossRestart(t *testing.T) {
	backend := durableTestStore(t)
	cfg := &Config{ProcessPeriod: time.Millisecond, Workers: 1, Delivery: func(context.Context, *Message) error { return nil }, ReceiptRetention: time.Hour}
	q, err := NewPersistent(t.Context(), backend, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(&Message{ID: "completed-once", Recipient: "outside@example.net"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !q.WasCompleted("completed-once") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !q.WasCompleted("completed-once") || q.Stats().CompletionReceipts != 1 {
		t.Fatalf("completion receipt missing: %+v", q.Stats())
	}
	if err := q.Enqueue(&Message{ID: "completed-once"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same-process replay error = %v", err)
	}
	q.Close()

	restored, err := NewPersistent(t.Context(), backend, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if !restored.WasCompleted("completed-once") {
		t.Fatal("completion receipt did not survive restart")
	}
	if err := restored.Enqueue(&Message{ID: "completed-once"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("post-restart replay error = %v", err)
	}
}

func TestPersistentCompletionReceiptRetentionPrunesExpired(t *testing.T) {
	backend := durableTestStore(t)
	old := CompletionReceipt{ID: "old", CompletedAt: time.Now().UTC().Add(-2 * time.Hour)}
	recent := CompletionReceipt{ID: "recent", CompletedAt: time.Now().UTC()}
	for _, receipt := range []CompletionReceipt{old, recent} {
		data, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Set(t.Context(), model.NSQueue, receiptKeyPrefix+receipt.ID, data); err != nil {
			t.Fatal(err)
		}
	}
	q, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour, ReceiptRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if q.WasCompleted("old") || !q.WasCompleted("recent") || q.Stats().CompletionReceipts != 1 {
		t.Fatalf("receipt retention state: old=%t recent=%t stats=%+v", q.WasCompleted("old"), q.WasCompleted("recent"), q.Stats())
	}
	if _, err := backend.Get(t.Context(), model.NSQueue, receiptKeyPrefix+old.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired receipt remains: %v", err)
	}
}

func TestCompletionReceiptFailureFinalizesWithoutRedelivery(t *testing.T) {
	backend := durableTestStore(t)
	faults := &receiptFailStore{Store: backend}
	faults.fail.Store(true)
	var deliveries atomic.Int64
	q, err := NewPersistent(t.Context(), faults, &Config{ProcessPeriod: time.Millisecond, Workers: 1, Delivery: func(context.Context, *Message) error {
		deliveries.Add(1)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "receipt-fault", Recipient: "outside@example.net"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !q.WasCompleted("receipt-fault") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !q.WasCompleted("receipt-fault") || deliveries.Load() != 1 || q.Get("receipt-fault") != nil {
		t.Fatalf("completed=%t deliveries=%d queued=%+v", q.WasCompleted("receipt-fault"), deliveries.Load(), q.Get("receipt-fault"))
	}
}

func TestPersistentQueueRecoversInterruptedDelivery(t *testing.T) {
	backend := durableTestStore(t)
	now := time.Now().UTC()
	persisted := toDiskMessage(&Message{ID: "claimed-1", Direction: DirectionOutbound,
		Recipient: "outside@example.net", Status: StatusProcessing,
		CreatedAt: now, NextRetry: now.Add(time.Hour), Body: []byte("not lost")})
	data, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Set(t.Context(), model.NSQueue, messageKeyPrefix+persisted.ID, data); err != nil {
		t.Fatal(err)
	}

	q, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	defer q.Close()
	got := q.Get("claimed-1")
	if got == nil || got.Status != StatusPending || got.NextRetry.After(time.Now().UTC()) {
		t.Fatalf("interrupted delivery was not made ready: %#v", got)
	}
}

func TestPersistentQueueRemovesSuccessfulDelivery(t *testing.T) {
	backend := durableTestStore(t)
	delivered := make(chan struct{}, 1)
	q, err := NewPersistent(t.Context(), backend, &Config{
		ProcessPeriod: time.Hour,
		Delivery: func(context.Context, *Message) error {
			delivered <- struct{}{}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "success-1", Recipient: "local@example.test"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("new durable item did not wake worker")
	}
	deadline := time.Now().Add(time.Second)
	for q.Get("success-1") != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if q.Get("success-1") != nil {
		t.Fatal("successfully delivered item remains queued")
	}
	if _, err := backend.Get(t.Context(), model.NSQueue, messageKeyPrefix+"success-1"); err == nil {
		t.Fatal("successfully delivered item remains on disk")
	}
}

func TestPersistentQueueRollsBackIncompleteBatch(t *testing.T) {
	backend := durableTestStore(t)
	msg := &Message{ID: "partial-1", Recipient: "alice@example.test", Status: StatusPending,
		CreatedAt: time.Now().UTC(), NextRetry: time.Now().UTC()}
	messageData, _ := json.Marshal(toDiskMessage(msg))
	journalData, _ := json.Marshal(batchJournal{MessageIDs: []string{msg.ID, "partial-2"}})
	if err := backend.Set(t.Context(), model.NSQueue, messageKeyPrefix+msg.ID, messageData); err != nil {
		t.Fatal(err)
	}
	if err := backend.Set(t.Context(), model.NSQueue, batchKeyPrefix+"unfinished", journalData); err != nil {
		t.Fatal(err)
	}

	q, err := NewPersistent(t.Context(), backend, &Config{ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatalf("recover queue: %v", err)
	}
	defer q.Close()
	if q.Size() != 0 {
		t.Fatalf("partial batch became visible: size=%d", q.Size())
	}
}

func TestPersistentTerminalFailureAndDSNAreCommittedTogether(t *testing.T) {
	backend := durableTestStore(t)
	cfg := &Config{
		ProcessPeriod: time.Hour,
		Delivery: func(_ context.Context, message *Message) error {
			if message.ID == "dsn-original" {
				return &DeliveryError{Class: DeliveryTemporary, Response: "hold"}
			}
			return &DeliveryError{Class: DeliveryPermanent, EnhancedCode: "5.1.1", Response: "unknown"}
		},
		FailureMessage: func(failed *Message) *Message {
			return &Message{Recipient: failed.EnvelopeSender, Content: []byte("dsn")}
		},
	}
	q, err := NewPersistent(t.Context(), backend, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(&Message{ID: "original", EnvelopeSender: "sender@example.test", Recipient: "missing@example.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "original", StatusFailed)
	q.Close()

	restored, err := NewPersistent(t.Context(), backend, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	failed, notification := restored.Get("original"), restored.Get("dsn-original")
	if failed == nil || failed.FailureMessageID != "dsn-original" || notification == nil || notification.ParentID != "original" {
		t.Fatalf("failed=%#v notification=%#v", failed, notification)
	}
}

func TestTerminalFailureCommitRecoversWithoutOrphaningDSN(t *testing.T) {
	backend := durableTestStore(t)
	faults := faultstore.New(backend)
	entered, release := make(chan struct{}), make(chan struct{})
	firstConfig := &Config{
		ProcessPeriod: time.Hour,
		Delivery: func(_ context.Context, message *Message) error {
			if message.ID == "failure-original" {
				close(entered)
				<-release
			}
			return &DeliveryError{Class: DeliveryPermanent, EnhancedCode: "5.1.1", Response: "unknown"}
		},
		FailureMessage: func(failed *Message) *Message {
			return &Message{Recipient: failed.EnvelopeSender, Content: []byte("dsn")}
		},
	}
	q, err := NewPersistent(t.Context(), faults, firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(&Message{ID: "failure-original", EnvelopeSender: "sender@example.test", Recipient: "missing@example.test"}); err != nil {
		t.Fatal(err)
	}
	<-entered
	faults.Fail("batch_commit", 1)
	close(release)
	waitQueueStatus(t, q, "failure-original", StatusFailed)
	if q.Get("dsn-failure-original") != nil {
		t.Fatal("DSN became visible after its atomic commit failed")
	}
	q.Close()

	recoveryConfig := &Config{
		ProcessPeriod: 5 * time.Millisecond,
		Delivery: func(_ context.Context, message *Message) error {
			if message.ID == "dsn-failure-original" {
				return &DeliveryError{Class: DeliveryDeferred, RetryAfter: time.Hour, Response: "retain for inspection"}
			}
			return &DeliveryError{Class: DeliveryPermanent, EnhancedCode: "5.1.1", Response: "unknown"}
		},
		FailureMessage: firstConfig.FailureMessage,
	}
	restored, err := NewPersistent(t.Context(), backend, recoveryConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	waitQueueStatus(t, restored, "failure-original", StatusFailed)
	waitQueueStatus(t, restored, "dsn-failure-original", StatusHeld)
	failed, notification := restored.Get("failure-original"), restored.Get("dsn-failure-original")
	if failed.FailureMessageID != notification.ID || notification.ParentID != failed.ID || notification.CorrelationID != failed.CorrelationID {
		t.Fatalf("recovered failed=%+v notification=%+v", failed, notification)
	}
}

func TestQuarantineTaskSurvivesRestartAndDeliveryIsIdempotent(t *testing.T) {
	backend := durableTestStore(t)
	typed := model.NewTypedStore(backend, store.BackendJSON)
	if err := typed.EnsureNamespace(t.Context(), model.NSMetadata); err != nil {
		t.Fatal(err)
	}
	quarantine := virus.NewQuarantineStore(typed)
	attempts := 0
	delivery := func(ctx context.Context, message *Message) error {
		attempts++
		if _, err := quarantine.Add(ctx, &virus.QuarantineEntry{ID: "queued-" + message.ID, Sender: message.EnvelopeSender, Recipient: message.Recipient, VirusName: message.Attributes["virus_name"], MessageData: message.Content}); err != nil {
			return err
		}
		if attempts == 1 {
			return &DeliveryError{Class: DeliveryDeferred, RetryAfter: time.Hour, Response: "restart before acknowledgement"}
		}
		return nil
	}
	config := &Config{ProcessPeriod: time.Hour, Delivery: delivery}
	q, err := NewPersistent(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(&Message{ID: "quarantine-restart", Kind: "quarantine", Attributes: map[string]string{"virus_name": "EICAR"}, EnvelopeSender: "sender@example.test", Recipient: "alice@example.test", Content: []byte("infected"), TargetOwnerID: "alice"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "quarantine-restart", StatusHeld)
	q.Close()

	restored, err := NewPersistent(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.Get("quarantine-restart").Kind != "quarantine" || restored.Get("quarantine-restart").Attributes["virus_name"] != "EICAR" {
		t.Fatalf("restored task = %+v", restored.Get("quarantine-restart"))
	}
	if woken, err := restored.WakeOwner("alice"); err != nil || woken != 1 {
		t.Fatalf("wake quarantine task: %d, %v", woken, err)
	}
	deadline := time.Now().Add(time.Second)
	for restored.Get("quarantine-restart") != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	entries, err := quarantine.List(t.Context())
	if err != nil || len(entries) != 1 || entries[0].ID != "queued-quarantine-restart" || attempts != 2 {
		t.Fatalf("quarantine entries=%+v attempts=%d err=%v", entries, attempts, err)
	}
}
