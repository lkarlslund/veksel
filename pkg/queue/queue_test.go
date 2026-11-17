package queue

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

func newTestQueue(delivery DeliveryFunc, maxSize int) *Queue {
	return New(&Config{
		MaxSize:  maxSize,
		Delivery: delivery,
	})
}

func TestRequestsFailureNotificationHonorsDSNNotify(t *testing.T) {
	for _, test := range []struct {
		name   string
		notify string
		want   bool
	}{
		{name: "default", want: true},
		{name: "failure", notify: "failure", want: true},
		{name: "mixed", notify: "success,delay,failure", want: true},
		{name: "never", notify: "never", want: false},
		{name: "success only", notify: "success", want: false},
		{name: "delay only", notify: "delay", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := &Message{Attributes: map[string]string{"dsn_notify": test.notify}}
			if got := requestsFailureNotification(message); got != test.want {
				t.Fatalf("requestsFailureNotification()=%t, want %t", got, test.want)
			}
		})
	}
}

func TestDequeue(t *testing.T) {
	msg := &Message{
		EnvelopeSender: "sender@example.com",
		Recipient:      "recipient@example.com",
		Headers:        map[string]string{"Subject": "Test"},
		Body:           []byte("Hello"),
		Status:         StatusPending,
	}
	// Dequeue is the manual-consumer primitive; construct its scheduling index
	// directly so background workers cannot race this focused contract test.
	q := &Queue{msgs: []*Message{msg}}

	// Dequeue should return the message
	dequeued := q.Dequeue()
	if dequeued == nil {
		t.Fatal("Dequeue returned nil")
	}
	if dequeued.Recipient != "recipient@example.com" {
		t.Fatalf("expected recipient@example.com, got %s", dequeued.Recipient)
	}

	// Queue should now be empty
	if q.Size() != 0 {
		t.Fatalf("expected size 0, got %d", q.Size())
	}
}

func TestEnqueueFull(t *testing.T) {
	q := newTestQueue(nil, 2)
	defer q.Close()

	if err := q.Enqueue(&Message{Recipient: "a@example.com"}); err != nil {
		t.Fatalf("Enqueue 1 failed: %v", err)
	}
	if err := q.Enqueue(&Message{Recipient: "b@example.com"}); err != nil {
		t.Fatalf("Enqueue 2 failed: %v", err)
	}

	// Queue should be full now
	err := q.Enqueue(&Message{Recipient: "c@example.com"})
	if err == nil {
		t.Fatal("expected error when queue is full")
	}
}

func TestEnqueueBatchIdempotentAcceptsOneStableBatch(t *testing.T) {
	q := newTestQueue(nil, 10)
	defer q.Close()
	batch := []*Message{{ID: "scheduled-1-a", Recipient: "a@example.test", NextRetry: time.Now().Add(time.Hour)}, {ID: "scheduled-1-b", Recipient: "b@example.test", NextRetry: time.Now().Add(time.Hour)}}
	if err := q.EnqueueBatchIdempotent("scheduled:alice:job-1", batch); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueBatchIdempotent("scheduled:alice:job-1", []*Message{{ID: "scheduled-1-a"}, {ID: "scheduled-1-b"}}); err != nil {
		t.Fatalf("same stable batch retry = %v", err)
	}
	if q.Size() != 2 {
		t.Fatalf("idempotent retry size = %d, want 2", q.Size())
	}
	if err := q.EnqueueBatchIdempotent("scheduled:alice:job-1", []*Message{{ID: "different"}}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed stable batch error = %v", err)
	}
	if err := q.EnqueueBatchIdempotent("scheduled:alice:job-2", []*Message{{Recipient: "missing-id@example.test"}}); err == nil {
		t.Fatal("idempotent batch without explicit IDs was accepted")
	}
}

func TestEnqueueBatchIsAtomicWhenCapacityIsInsufficient(t *testing.T) {
	q := newTestQueue(nil, 2)
	defer q.Close()
	if err := q.Enqueue(&Message{Recipient: "existing@example.com"}); err != nil {
		t.Fatalf("enqueue existing: %v", err)
	}
	err := q.EnqueueBatch([]*Message{{Recipient: "one@example.com"}, {Recipient: "two@example.com"}})
	if err == nil {
		t.Fatal("oversized batch unexpectedly succeeded")
	}
	if q.Size() != 1 {
		t.Fatalf("queue size = %d, want existing message only", q.Size())
	}
}

func TestAdmissionMutationsAreDurableAndDetachedFromCaller(t *testing.T) {
	q := New(&Config{ProcessPeriod: time.Hour, Admission: func(_ context.Context, message *Message) error {
		message.Policy = mailpolicy.Result{Revision: "revision-a", Actions: []mailpolicy.Action{{Type: mailpolicy.ActionRoute, Value: "route-a"}}}
		message.PolicyRoute = "route-a"
		message.Headers["X-Policy"] = "applied"
		return nil
	}})
	t.Cleanup(q.Close)
	input := &Message{ID: "admitted", Headers: map[string]string{"Subject": "original"}}
	if err := q.Enqueue(input); err != nil {
		t.Fatal(err)
	}
	if input.Policy.Revision != "" || input.PolicyRoute != "" || input.Headers["X-Policy"] != "" {
		t.Fatalf("admission mutated caller-owned message: %+v", input)
	}
	got := q.Get("admitted")
	if got.Policy.Revision != "revision-a" || got.PolicyRoute != "route-a" || got.Headers["X-Policy"] != "applied" {
		t.Fatalf("admitted message = %+v", got)
	}
	got.Policy.Actions[0].Value = "mutated"
	got.Headers["X-Policy"] = "mutated"
	again := q.Get("admitted")
	if again.Policy.Actions[0].Value != "route-a" || again.Headers["X-Policy"] != "applied" {
		t.Fatalf("queue exposed admitted state: %+v", again)
	}
}

func TestAdmissionFailureRejectsWholeBatch(t *testing.T) {
	rejected := errors.New("policy rejected")
	q := New(&Config{ProcessPeriod: time.Hour, Admission: func(_ context.Context, message *Message) error {
		if message.Recipient == "blocked@example.test" {
			return rejected
		}
		message.PolicyRoute = "allowed"
		return nil
	}})
	t.Cleanup(q.Close)
	err := q.EnqueueBatch([]*Message{{ID: "allowed", Recipient: "ok@example.test"}, {ID: "blocked", Recipient: "blocked@example.test"}})
	if !errors.Is(err, rejected) {
		t.Fatalf("enqueue error = %v", err)
	}
	if q.Get("allowed") != nil || q.Get("blocked") != nil || q.Size() != 0 {
		t.Fatal("admission failure partially accepted a batch")
	}
}

func TestQueueSnapshotsDoNotAliasAuthoritativeMessage(t *testing.T) {
	q := New(&Config{ProcessPeriod: time.Hour})
	t.Cleanup(q.Close)
	if err := q.Enqueue(&Message{
		ID:         "detached",
		Attributes: map[string]string{"kind": "original"},
		Headers:    map[string]string{"Subject": "original"},
		Body:       []byte("body"),
		Content:    []byte("content"),
		Attempts:   []AttemptRecord{{ID: "attempt-original"}},
	}); err != nil {
		t.Fatal(err)
	}

	listed := q.List("")[0]
	listed.Headers["Subject"] = "changed"
	listed.Attributes["kind"] = "changed"
	listed.Body[0] = 'X'
	listed.Content[0] = 'X'
	listed.Attempts[0].ID = "changed"

	got := q.Get("detached")
	if got.Headers["Subject"] != "original" || got.Attributes["kind"] != "original" || string(got.Body) != "body" || string(got.Content) != "content" || got.Attempts[0].ID != "attempt-original" {
		t.Fatalf("List returned aliased queue state: %+v", got)
	}

	got.Headers["Subject"] = "changed-again"
	got.Body[0] = 'Y'
	if current := q.Get("detached"); current.Headers["Subject"] != "original" || string(current.Body) != "body" {
		t.Fatalf("Get returned aliased queue state: %+v", current)
	}
}

func TestReroutePreservesEvidenceAndReschedulesFailedOutboundWork(t *testing.T) {
	var observed Event
	q := &Queue{
		msgs: []*Message{{ID: "reroute-failed", Direction: DirectionOutbound, Recipient: "user@example.test", PolicyRoute: "policy.example", Attempts: []AttemptRecord{{ID: "attempt-1"}}, Status: StatusFailed, RetryCount: 5, LastError: "old failure"}},
		cfg:  Config{Observer: func(_ context.Context, event Event) { observed = event }},
	}

	change, err := q.Reroute("reroute-failed", " Alternate.Example ", "admin", "recover destination")
	if err != nil {
		t.Fatal(err)
	}
	got := q.Get("reroute-failed")
	if got.AdministrativeRoute != "alternate.example" || got.PolicyRoute != "policy.example" || got.Status != StatusPending || got.RetryCount != 0 || got.LastError != "" || len(got.Attempts) != 1 {
		t.Fatalf("rerouted message = %+v", got)
	}
	if change.Current != "alternate.example" || change.Actor != "admin" || len(got.RouteChanges) != 1 || observed.Stage != "operator_reroute" || observed.Route != "alternate.example" {
		t.Fatalf("change=%+v history=%+v event=%+v", change, got.RouteChanges, observed)
	}
	got.RouteChanges[0].Reason = "mutated"
	if q.Get("reroute-failed").RouteChanges[0].Reason != "recover destination" {
		t.Fatal("route history snapshot aliases authoritative queue state")
	}
	if _, err := q.Reroute("reroute-failed", "", "admin", "restore automatic routing"); err != nil {
		t.Fatal(err)
	}
	if got := q.Get("reroute-failed"); got.AdministrativeRoute != "" || got.PolicyRoute != "policy.example" || len(got.RouteChanges) != 2 || observed.Route != "automatic" {
		t.Fatalf("automatic reroute=%+v event=%+v", got, observed)
	}
}

func TestReroutePreservesPauseAndRejectsUnsafeMessages(t *testing.T) {
	q := &Queue{msgs: []*Message{
		{ID: "paused", Direction: DirectionOutbound, HoldReason: "maintenance"},
		{ID: "inbound", Direction: DirectionInbound},
		{ID: "processing", Direction: DirectionOutbound},
	}}
	q.msgs[q.findLocked("paused")].Status = StatusPaused
	q.msgs[q.findLocked("paused")].NextRetry = time.Time{}
	q.msgs[q.findLocked("processing")].Status = StatusProcessing
	if _, err := q.Reroute("paused", "route.example", "admin", "planned change"); err != nil {
		t.Fatal(err)
	}
	if got := q.Get("paused"); got.Status != StatusPaused || got.HoldReason != "maintenance" || !got.NextRetry.IsZero() {
		t.Fatalf("paused reroute = %+v", got)
	}
	if _, err := q.Reroute("paused", "route.example", "admin", "same"); !errors.Is(err, ErrRerouteUnchanged) {
		t.Fatalf("unchanged error = %v", err)
	}
	if _, err := q.Reroute("inbound", "route.example", "admin", "wrong direction"); !errors.Is(err, ErrRerouteDirection) {
		t.Fatalf("direction error = %v", err)
	}
	if _, err := q.Reroute("processing", "route.example", "admin", "unsafe state"); !errors.Is(err, ErrRerouteState) {
		t.Fatalf("state error = %v", err)
	}
	if _, err := q.Reroute("missing", "route.example", "admin", "missing"); !errors.Is(err, ErrRerouteNotFound) {
		t.Fatalf("missing error = %v", err)
	}
}

func TestRerouteHistoryIsBounded(t *testing.T) {
	q := &Queue{msgs: []*Message{{ID: "bounded-routes", Direction: DirectionOutbound, Status: StatusPending}}}
	for index := 0; index < MaxRouteChanges+5; index++ {
		if _, err := q.Reroute("bounded-routes", fmt.Sprintf("route-%d.example", index), "admin", "rotation"); err != nil {
			t.Fatal(err)
		}
	}
	got := q.Get("bounded-routes")
	if len(got.RouteChanges) != MaxRouteChanges || got.RouteChangesDropped != 5 || got.RouteChanges[0].Current != "route-5.example" {
		t.Fatalf("bounded route history = %d/%d first=%+v", len(got.RouteChanges), got.RouteChangesDropped, got.RouteChanges[0])
	}
}

func TestEnqueueAndDeliveryCallbacksCannotMutateQueueState(t *testing.T) {
	deliveryStarted := make(chan struct{})
	releaseDelivery := make(chan struct{})
	q := New(&Config{ProcessPeriod: time.Hour, RetryInitial: time.Hour, Delivery: func(_ context.Context, message *Message) error {
		message.Headers["Subject"] = "delivery mutation"
		message.Content[0] = 'X'
		close(deliveryStarted)
		<-releaseDelivery
		return &DeliveryError{Class: DeliveryTemporary, Response: "retry"}
	}})
	t.Cleanup(q.Close)
	input := &Message{ID: "callback-isolation", Headers: map[string]string{"Subject": "original"}, Content: []byte("content")}
	if err := q.Enqueue(input); err != nil {
		t.Fatal(err)
	}
	input.Headers["Subject"] = "caller mutation"
	input.Content[0] = 'Y'
	<-deliveryStarted
	close(releaseDelivery)
	waitQueueStatus(t, q, "callback-isolation", StatusRetrying)
	got := q.Get("callback-isolation")
	if got.Headers["Subject"] != "original" || string(got.Content) != "content" {
		t.Fatalf("callback or caller mutated authoritative message: %+v", got)
	}
}

func TestAttemptHistoryIsBoundedAndReportedInStats(t *testing.T) {
	q := New(&Config{ProcessPeriod: time.Hour, Delivery: func(context.Context, *Message) error {
		return &DeliveryError{Class: DeliveryPermanent, EnhancedCode: "5.1.1", Response: "rejected"}
	}})
	t.Cleanup(q.Close)
	attempts := make([]AttemptRecord, MaxAttemptRecords)
	for index := range attempts {
		attempts[index].ID = fmt.Sprintf("old-%d", index)
	}
	if err := q.Enqueue(&Message{ID: "bounded-attempts", Attempts: attempts, Recipient: "outside@example.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "bounded-attempts", StatusFailed)
	message := q.Get("bounded-attempts")
	if len(message.Attempts) != MaxAttemptRecords || message.AttemptsDropped != 1 {
		t.Fatalf("attempt history = %d retained, %d dropped", len(message.Attempts), message.AttemptsDropped)
	}
	if message.Attempts[0].ID != "old-0" || message.Attempts[len(message.Attempts)-1].Class != DeliveryPermanent {
		t.Fatalf("attempt evidence = first %+v, latest %+v", message.Attempts[0], message.Attempts[len(message.Attempts)-1])
	}
	stats := q.Stats()
	if stats.AttemptsRetained != MaxAttemptRecords || stats.AttemptsDropped != 1 {
		t.Fatalf("queue stats = %+v", stats)
	}
}

func TestDeliveryObserverIncludesRouteTimingAndRetryEvidence(t *testing.T) {
	events := make(chan Event, 8)
	q := New(&Config{
		ProcessPeriod: time.Hour,
		RetryInitial:  time.Hour,
		Delivery: func(ctx context.Context, _ *Message) error {
			RecordDeliveryRoute(ctx, "domain-mx:example.test")
			RecordTLSPolicy(ctx, "dane-failed mx=mx.example.test: certificate\r\nmismatch")
			time.Sleep(2 * time.Millisecond)
			return &DeliveryError{Class: DeliveryTemporary, EnhancedCode: "4.4.2", Response: "remote unavailable"}
		},
		Observer: func(_ context.Context, event Event) { events <- event },
	})
	t.Cleanup(q.Close)
	if err := q.Enqueue(&Message{ID: "trace-evidence", Recipient: "user@example.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "trace-evidence", StatusRetrying)
	var outcome Event
	for len(events) > 0 {
		event := <-events
		if event.Stage == "delivery" {
			outcome = event
		}
	}
	if outcome.Route != "domain-mx:example.test" || outcome.Destination != "domain:example.test" || outcome.OutcomeClass != string(DeliveryTemporary) ||
		outcome.TLSPolicy != "dane-failed mx=mx.example.test: certificate mismatch" {
		t.Fatalf("delivery evidence = %+v", outcome)
	}
	if outcome.DurationMillis < 1 || outcome.RetryAt.IsZero() || !outcome.RetryAt.After(outcome.Time) {
		t.Fatalf("timing/retry evidence = %+v", outcome)
	}
	message := q.Get("trace-evidence")
	if message == nil || message.DeliveryRoute != outcome.Route || message.Attempts[len(message.Attempts)-1].TLSPolicy != outcome.TLSPolicy {
		t.Fatalf("durable route = %+v", message)
	}
}

func TestDeliveryOutcomeEvidenceIsBoundedBeforePersistence(t *testing.T) {
	response := strings.Repeat("ø", 2200) + "\r\ncontrol\x00tail"
	q := New(&Config{ProcessPeriod: time.Hour, Delivery: func(context.Context, *Message) error {
		return &DeliveryError{Class: DeliveryPermanent, EnhancedCode: strings.Repeat("5", 100), Response: response}
	}})
	t.Cleanup(q.Close)
	if err := q.Enqueue(&Message{ID: "bounded-outcome", Recipient: "user@example.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "bounded-outcome", StatusFailed)
	message := q.Get("bounded-outcome")
	if message == nil || len([]rune(message.LastResponse)) != 2048 || len([]rune(message.LastCode)) != 64 || strings.ContainsAny(message.LastResponse, "\r\n\x00") {
		t.Fatalf("bounded queue evidence = %+v", message)
	}
	if len(message.Attempts) != 1 || message.Attempts[0].Response != message.LastResponse {
		t.Fatalf("bounded attempt evidence = %+v", message.Attempts)
	}
}

func TestEnqueueAutoID(t *testing.T) {
	q := newTestQueue(nil, 100)
	defer q.Close()

	msg := &Message{Recipient: "a@example.com"}
	if err := q.Enqueue(msg); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	if msg.ID == "" {
		t.Fatal("expected auto-generated ID")
	}
}

func TestTemporaryFailuresRetryUntilExpiry(t *testing.T) {
	var attempts atomic.Int32
	q := New(&Config{ProcessPeriod: 2 * time.Millisecond, Workers: 1, MaxAge: 250 * time.Millisecond,
		RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond,
		Delivery: func(context.Context, *Message) error {
			attempts.Add(1)
			return errors.New("4.4.1 connection timeout")
		}})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "temporary", Recipient: "recipient@example.com"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "temporary", StatusFailed)
	failed := q.Get("temporary")
	// The retired five-attempt cap bounced mail long before MaxAge.
	if attempts.Load() <= 5 {
		t.Fatalf("delivery attempts = %d, want retries beyond five until expiry", attempts.Load())
	}
	if failed.LastCode != "5.4.7" || failed.CompletedAt.Before(failed.ExpiresAt) {
		t.Fatalf("terminal message = %+v, want 5.4.7 expiry at or after %v", failed, failed.ExpiresAt)
	}
}

func TestRetryBackoffIsClampedToExpiry(t *testing.T) {
	q := New(&Config{ProcessPeriod: 2 * time.Millisecond, Workers: 1, MaxAge: 100 * time.Millisecond,
		RetryInitial: time.Hour, RetryMax: time.Hour,
		Delivery: func(context.Context, *Message) error { return errors.New("4.4.1 connection timeout") }})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "clamped", Recipient: "recipient@example.com"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "clamped", StatusRetrying)
	if retrying := q.Get("clamped"); retrying.NextRetry.After(retrying.ExpiresAt) {
		t.Fatalf("next retry %v is after expiry %v", retrying.NextRetry, retrying.ExpiresAt)
	}
	waitQueueStatus(t, q, "clamped", StatusFailed)
}

func TestPermanentFailure(t *testing.T) {
	var attemptCount atomic.Int32
	q := newTestQueue(func(ctx context.Context, msg *Message) error {
		attemptCount.Add(1)
		return errors.New("5.1.1 user unknown")
	}, 100)
	defer q.Close()

	msg := &Message{
		Recipient:      "recipient@example.com",
		EnvelopeSender: "sender@example.com",
		Headers:        map[string]string{"Subject": "Test"},
		Body:           []byte("Hello"),
	}
	if err := q.Enqueue(msg); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Process the message
	m := q.Dequeue()
	if m == nil {
		t.Fatal("expected message to be dequeued")
	}

	err := q.delivery(context.Background(), m)
	if err == nil {
		t.Fatal("expected error")
	}

	// Permanent failure should not be retried
	if isTemporaryFailure(err) {
		t.Fatal("expected permanent failure, got temporary")
	}
}

func TestIsTemporaryFailure(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{errors.New("4.2.2 mailbox full"), true},
		{errors.New("4.4.1 connection timeout"), true},
		{errors.New("5.1.1 user unknown"), false},
		{errors.New("5.2.1 mailbox disabled"), false},
		{errors.New("connection refused"), true},
		{errors.New("i/o timeout"), true},
		{errors.New("network is unreachable"), true},
		{errors.New("context deadline exceeded"), true},
		{errors.New("context canceled"), true},
		{errors.New("some other error"), false},
		{nil, false},
	}

	for _, tt := range tests {
		got := isTemporaryFailure(tt.err)
		if got != tt.want {
			t.Errorf("isTemporaryFailure(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestListByStatus(t *testing.T) {
	q := newTestQueue(nil, 100)
	defer q.Close()

	// Add messages with different statuses
	future := time.Now().Add(time.Hour)
	if err := q.Enqueue(&Message{Recipient: "a@example.com", NextRetry: future}); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(&Message{Recipient: "b@example.com", NextRetry: future}); err != nil {
		t.Fatal(err)
	}

	// Manually set one as retrying
	q.mu.Lock()
	if len(q.msgs) >= 2 {
		q.msgs[1].Status = StatusRetrying
	}
	q.mu.Unlock()

	pending := q.List(StatusPending)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	retrying := q.List(StatusRetrying)
	if len(retrying) != 1 {
		t.Fatalf("expected 1 retrying, got %d", len(retrying))
	}

	all := q.List("")
	if len(all) != 2 {
		t.Fatalf("expected 2 total, got %d", len(all))
	}
}

func TestGetAndRemove(t *testing.T) {
	q := newTestQueue(nil, 100)
	defer q.Close()

	msg := &Message{Recipient: "a@example.com"}
	if err := q.Enqueue(msg); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	id := msg.ID

	// Get should return the message
	got := q.Get(id)
	if got == nil {
		t.Fatal("Get returned nil for existing message")
	}
	if got.Recipient != "a@example.com" {
		t.Fatalf("expected a@example.com, got %s", got.Recipient)
	}

	// Remove should succeed
	if !q.Remove(id) {
		t.Fatal("Remove returned false for existing message")
	}

	// Get should return nil after removal
	if q.Get(id) != nil {
		t.Fatal("Get returned non-nil after removal")
	}

	// Remove should return false for non-existent
	if q.Remove("nonexistent") {
		t.Fatal("Remove returned true for non-existent message")
	}
}

func TestBackgroundProcessing(t *testing.T) {
	var delivered atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	q := newTestQueue(func(ctx context.Context, msg *Message) error {
		close(started)
		<-release
		delivered.Add(1)
		return nil
	}, 100)

	msg := &Message{
		Recipient:      "recipient@example.com",
		EnvelopeSender: "sender@example.com",
		Headers:        map[string]string{"Subject": "Test"},
		Body:           []byte("Hello"),
	}
	if err := q.Enqueue(msg); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	<-started
	if q.Size() != 1 {
		t.Fatalf("expected size 1, got %d", q.Size())
	}
	close(release)
	q.Close()
	if delivered.Load() != 1 {
		t.Fatalf("deliveries = %d, want 1", delivered.Load())
	}
}

func TestExponentialBackoff(t *testing.T) {
	// Verify backoff calculation: 1m, 2m, 4m, 8m, 16m
	expected := []time.Duration{
		1 * time.Minute,
		2 * time.Minute,
		4 * time.Minute,
		8 * time.Minute,
		16 * time.Minute,
	}
	for i, want := range expected {
		retryCount := i + 1
		got := time.Duration(1<<uint(retryCount-1)) * time.Minute
		if got != want {
			t.Errorf("backoff for retry %d: got %v, want %v", retryCount, got, want)
		}
	}
}

func TestBuildDeliveryFunc(t *testing.T) {
	var folderID, userID string
	var appended bool
	delivery := BuildDeliveryFunc(
		func(ctx context.Context, addr string) (string, string, error) {
			folderID = "user1:INBOX"
			userID = "user1"
			return folderID, userID, nil
		},
		func(ctx context.Context, fid string, data []byte, headers map[string]string) (string, error) {
			appended = true
			return "item-1", nil
		},
		func(fid string) {},
	)

	msg := &Message{
		Recipient:      "user1@example.com",
		EnvelopeSender: "sender@example.com",
		Headers:        map[string]string{"Subject": "Test"},
		Body:           []byte("Hello"),
	}

	err := delivery(context.Background(), msg)
	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if !appended {
		t.Fatal("expected message to be appended")
	}
	if folderID != "user1:INBOX" {
		t.Fatalf("expected folderID user1:INBOX, got %s", folderID)
	}
}

func TestFormatBackoff(t *testing.T) {
	tests := []struct {
		retry int
		want  string
	}{
		{0, "now"},
		{1, "1m"},
		{2, "2m"},
		{3, "4m"},
		{4, "8m"},
		{5, "16m"},
	}

	for _, tt := range tests {
		got := FormatBackoff(tt.retry)
		if got != tt.want {
			t.Errorf("FormatBackoff(%d) = %q, want %q", tt.retry, got, tt.want)
		}
	}
}

func TestSMTPAdapter(t *testing.T) {
	q := newTestQueue(nil, 100)
	defer q.Close()

	adapter := NewSMTPAdapter(q)

	// Verify the adapter is created correctly
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
	if err := adapter.Enqueue(&smtp.MailMessage{ID: "smtp-trace", CorrelationID: "transaction-1", ParentID: "submission-1", Recipient: "a@example.test", TargetFolderPath: "Projects/2026", Outbound: true, Held: true}); err != nil {
		t.Fatal(err)
	}
	message := q.Get("smtp-trace")
	if message == nil || message.CorrelationID != "transaction-1" || message.ParentID != "submission-1" || message.TargetFolderPath != "Projects/2026" || message.Direction != DirectionOutbound || message.Status != StatusPaused {
		t.Fatalf("SMTP trace metadata was not preserved: %#v", message)
	}
}

func TestQueueStatsGroupsStatusAndDirection(t *testing.T) {
	q := New(&Config{Workers: 1, ProcessPeriod: time.Hour})
	defer q.Close()
	if err := q.EnqueueBatch([]*Message{
		{ID: "in", Direction: DirectionInbound, Status: StatusPending, CreatedAt: time.Now().Add(-time.Minute), NextRetry: time.Now().Add(time.Hour)},
		{ID: "out", Direction: DirectionOutbound, Status: StatusRetrying, NextRetry: time.Now().Add(time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	stats := q.Stats()
	if stats.Size != 2 || stats.ByStatus[StatusPending] != 1 || stats.ByStatus[StatusRetrying] != 1 || stats.ByDirection[DirectionOutbound] != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if stats.OldestAgeSeconds < 59 {
		t.Fatalf("oldest age = %f", stats.OldestAgeSeconds)
	}
}

func TestPruneReceiptsIsBoundedDeterministicAndSupportsDryRun(t *testing.T) {
	q := New(&Config{ProcessPeriod: time.Hour})
	defer q.Close()
	now := time.Now().UTC()
	q.mu.Lock()
	q.completed["old-b"] = now.Add(-3 * time.Hour)
	q.completed["old-a"] = now.Add(-3 * time.Hour)
	q.completed["recent"] = now.Add(-time.Minute)
	q.mu.Unlock()

	dryRun, err := q.PruneReceipts(t.Context(), now.Add(-time.Hour), 1, true)
	if err != nil || dryRun.Examined != 1 || dryRun.Removed != 0 || len(dryRun.Items) != 1 || dryRun.Items[0].ID != "old-a" || dryRun.Items[0].Removed {
		t.Fatalf("dry run = %+v, error=%v", dryRun, err)
	}
	removed, err := q.PruneReceipts(t.Context(), now.Add(-time.Hour), 1, false)
	if err != nil || removed.Removed != 1 || removed.Items[0].ID != "old-a" || !removed.Items[0].Removed || q.WasCompleted("old-a") || !q.WasCompleted("old-b") || !q.WasCompleted("recent") {
		t.Fatalf("prune = %+v, error=%v stats=%+v", removed, err, q.Stats())
	}
	stats := q.Stats()
	if stats.CompletionReceipts != 2 || stats.OldestReceiptAgeSeconds < 2*time.Hour.Seconds() || stats.NewestReceiptAgeSeconds > 2*time.Minute.Seconds() || stats.LastReceiptPruneRemoved != 1 || stats.LastReceiptPruneAt.IsZero() {
		t.Fatalf("receipt stats = %+v", stats)
	}
}

func TestPruneReceiptsValidatesBounds(t *testing.T) {
	q := New(nil)
	defer q.Close()
	for _, test := range []struct {
		before time.Time
		limit  int
	}{{limit: 1}, {before: time.Now(), limit: 0}, {before: time.Now(), limit: 10001}} {
		if _, err := q.PruneReceipts(t.Context(), test.before, test.limit, false); err == nil {
			t.Fatalf("before=%v limit=%d accepted", test.before, test.limit)
		}
	}
}

func TestPruneReceiptsIsSafeDuringConcurrentDelivery(t *testing.T) {
	var deliveries atomic.Int64
	q := New(&Config{Workers: 4, ProcessPeriod: time.Millisecond, Delivery: func(context.Context, *Message) error {
		deliveries.Add(1)
		return nil
	}})
	defer q.Close()
	for index := range 100 {
		if err := q.Enqueue(&Message{ID: fmt.Sprintf("concurrent-receipt-%03d", index), Recipient: "outside@example.test"}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			_, _ = q.PruneReceipts(context.Background(), time.Now().UTC().Add(time.Hour), 25, false)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for deliveries.Load() != 100 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	<-done
	if deliveries.Load() != 100 {
		t.Fatalf("deliveries = %d, want 100", deliveries.Load())
	}
}

func TestTerminalFailureQueuesExactlyOneDSN(t *testing.T) {
	var notifications atomic.Int32
	q := New(&Config{
		ProcessPeriod: time.Millisecond,
		RetryInitial:  time.Millisecond,
		Delivery: func(_ context.Context, msg *Message) error {
			if strings.HasPrefix(msg.ID, "dsn-") {
				return &DeliveryError{Class: DeliveryTemporary, Response: "hold notification"}
			}
			return &DeliveryError{Class: DeliveryPermanent, EnhancedCode: "5.1.1", Response: "unknown user"}
		},
		FailureMessage: func(failed *Message) *Message {
			notifications.Add(1)
			return &Message{EnvelopeSender: "", Recipient: failed.EnvelopeSender, Content: []byte("delivery status notification")}
		},
	})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "original", EnvelopeSender: "sender@example.test", Recipient: "missing@example.test"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "original", StatusFailed)
	failed := q.Get("original")
	if failed.FailureMessageID != "dsn-original" || q.Get("dsn-original") == nil || notifications.Load() != 1 {
		t.Fatalf("failed=%#v dsn=%#v notifications=%d", failed, q.Get("dsn-original"), notifications.Load())
	}
	if !q.Retry("original") {
		t.Fatal("retry failed message")
	}
	waitQueueStatus(t, q, "original", StatusFailed)
	if notifications.Load() != 1 {
		t.Fatalf("generated %d failure notifications, want 1", notifications.Load())
	}
}

func TestTerminalFailureHonorsNotifyNever(t *testing.T) {
	var notifications atomic.Int32
	q := New(&Config{
		ProcessPeriod: time.Millisecond,
		Delivery: func(context.Context, *Message) error {
			return &DeliveryError{Class: DeliveryPermanent, EnhancedCode: "5.1.1", Response: "unknown user"}
		},
		FailureMessage: func(failed *Message) *Message {
			notifications.Add(1)
			return &Message{Recipient: failed.EnvelopeSender, Content: []byte("unexpected")}
		},
	})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "no-failure-notice", EnvelopeSender: "sender@example.test", Recipient: "missing@example.test", Attributes: map[string]string{"dsn_notify": "never"}}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "no-failure-notice", StatusFailed)
	if notifications.Load() != 0 || q.Get("no-failure-notice").FailureMessageID != "" {
		t.Fatalf("notifications=%d failed=%#v", notifications.Load(), q.Get("no-failure-notice"))
	}
}

func TestSuccessfulDeliveryQueuesRequestedDSN(t *testing.T) {
	var notifications atomic.Int32
	var invalidSource atomic.Bool
	q := New(&Config{
		ProcessPeriod: time.Millisecond,
		Delivery: func(_ context.Context, message *Message) error {
			if strings.HasPrefix(message.ID, "dsn-") {
				return &DeliveryError{Class: DeliveryDeferred, Response: "retain notification"}
			}
			return nil
		},
		FailureMessage: func(delivered *Message) *Message {
			if delivered.LastCode != "2.0.0" || delivered.Attributes["dsn_notification"] != "success" {
				invalidSource.Store(true)
			}
			notifications.Add(1)
			return &Message{Recipient: delivered.EnvelopeSender, Content: []byte("success")}
		},
	})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "success-original", EnvelopeSender: "sender@example.test", Recipient: "recipient@example.test", Attributes: map[string]string{"dsn_notify": "success"}}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "dsn-success-original", StatusHeld)
	if !q.WasCompleted("success-original") || notifications.Load() != 1 || invalidSource.Load() {
		t.Fatalf("completed=%t notifications=%d invalid_source=%t", q.WasCompleted("success-original"), notifications.Load(), invalidSource.Load())
	}
}

func TestCancelPreventsDelivery(t *testing.T) {
	var attempts atomic.Int32
	q := New(&Config{ProcessPeriod: time.Hour, Delivery: func(context.Context, *Message) error {
		attempts.Add(1)
		return nil
	}})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "cancel-me", NextRetry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if !q.Cancel("cancel-me") || q.Get("cancel-me").Status != StatusCancelled {
		t.Fatalf("cancelled message=%#v", q.Get("cancel-me"))
	}
	time.Sleep(10 * time.Millisecond)
	if attempts.Load() != 0 {
		t.Fatalf("delivery attempts=%d", attempts.Load())
	}
}

func waitQueueStatus(t *testing.T, q *Queue, id string, status Status) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if message := q.Get(id); message != nil && message.Status == status {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("message %q did not reach %q: %#v", id, status, q.Get(id))
}

func TestNewWithDelivery(t *testing.T) {
	q := NewWithDelivery(func(ctx context.Context, msg *Message) error {
		return nil
	}, 100)
	defer q.Close()

	if q == nil {
		t.Fatal("expected non-nil queue")
	}
}

func TestQueueMessageJSONMarshal(t *testing.T) {
	msg := &Message{
		ID:             "test-1",
		Recipient:      "a@example.com",
		EnvelopeSender: "sender@example.com",
		Headers:        map[string]string{"Subject": "Test"},
		Body:           []byte("Hello World"),
		Status:         StatusPending,
		RetryCount:     0,
	}

	data, err := msg.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Body should be omitted in JSON
	if len(data) == 0 {
		t.Fatal("expected non-empty JSON")
	}
}

func TestQueueConcurrentEnqueue(t *testing.T) {
	q := newTestQueue(nil, 1000)
	defer q.Close()

	const goroutines = 10
	const perGoroutine = 50
	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			for j := 0; j < perGoroutine; j++ {
				msg := &Message{
					Recipient:      fmt.Sprintf("user%d-%d@example.com", n, j),
					EnvelopeSender: "sender@example.com",
					Headers:        map[string]string{"Subject": "Test"},
					Body:           []byte("Hello"),
				}
				if err := q.Enqueue(msg); err != nil {
					t.Errorf("Enqueue failed: %v", err)
					return
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}

	expected := goroutines * perGoroutine
	if q.Size() != expected {
		t.Fatalf("expected size %d, got %d", expected, q.Size())
	}
}

func TestTypedPermanentFailureIsNotRetried(t *testing.T) {
	q := New(&Config{Workers: 1, ProcessPeriod: time.Hour, Delivery: func(context.Context, *Message) error {
		return &DeliveryError{Class: DeliveryPermanent, EnhancedCode: "5.1.1", Response: "recipient rejected"}
	}})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "permanent-typed", Recipient: "missing@example.test"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := q.Get("permanent-typed"); got != nil && got.Status == StatusFailed {
			if got.RetryCount != 1 || got.LastCode != "5.1.1" || got.LastResponse != "recipient rejected" {
				t.Fatalf("failed message = %#v", got)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("typed permanent failure was not persisted")
}

func TestQueueUsesConfiguredWorkerConcurrency(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	q := New(&Config{Workers: 2, ProcessPeriod: time.Hour, Delivery: func(_ context.Context, msg *Message) error {
		started <- msg.ID
		<-release
		return nil
	}})
	defer q.Close()
	if err := q.EnqueueBatch([]*Message{{ID: "parallel-1"}, {ID: "parallel-2"}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("queue workers did not deliver concurrently")
		}
	}
	close(release)
}

func TestQueueLimitsConcurrencyPerDestination(t *testing.T) {
	started := make(chan string, 3)
	release := make(chan struct{})
	q := New(&Config{Workers: 3, MaxPerDestination: 1, ProcessPeriod: time.Hour, Delivery: func(_ context.Context, msg *Message) error {
		started <- msg.Recipient
		<-release
		return nil
	}})
	defer q.Close()
	if err := q.EnqueueBatch([]*Message{
		{ID: "same-1", Recipient: "one@example.test"},
		{ID: "same-2", Recipient: "two@example.test"},
		{ID: "other", Recipient: "three@elsewhere.test"},
	}); err != nil {
		t.Fatal(err)
	}
	first := <-started
	second := <-started
	if deliveryDestination(&Message{Recipient: first}) == deliveryDestination(&Message{Recipient: second}) {
		close(release)
		t.Fatalf("same destination started concurrently: %q, %q", first, second)
	}
	select {
	case third := <-started:
		close(release)
		t.Fatalf("third delivery bypassed destination limit: %q", third)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
}

// TestRetryAttemptsWaitingMessageNow pulls a deferred message's next attempt
// forward without resetting its attempt history.
func TestRetryAttemptsWaitingMessageNow(t *testing.T) {
	var attempts atomic.Int32
	q := New(&Config{ProcessPeriod: 2 * time.Millisecond, Workers: 1, MaxAge: time.Hour,
		RetryInitial: time.Hour, RetryMax: time.Hour,
		Delivery: func(context.Context, *Message) error {
			if attempts.Add(1) == 1 {
				return errors.New("4.4.1 connection timeout")
			}
			return nil
		}})
	defer q.Close()
	if err := q.Enqueue(&Message{ID: "waiting", Recipient: "recipient@example.com"}); err != nil {
		t.Fatal(err)
	}
	waitQueueStatus(t, q, "waiting", StatusRetrying)
	if !q.Retry("waiting") {
		t.Fatal("retry refused a message waiting for its next attempt")
	}
	deadline := time.Now().Add(time.Second)
	for attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want the retry to attempt delivery now", attempts.Load())
	}
}
