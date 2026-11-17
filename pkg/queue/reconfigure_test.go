package queue

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func testLimits(workers int) Limits {
	return Limits{MaxSize: 100, Workers: workers, MaxPerDestination: workers, MaxAge: time.Hour,
		RetryInitial: time.Minute, RetryMax: time.Hour, ReceiptRetention: 24 * time.Hour}
}

func TestReconfigureResizesWorkersWithoutInterruptingDeliveries(t *testing.T) {
	var mu sync.Mutex
	inFlight, interrupted := 0, 0
	delivered := make(map[string]int)
	release := make(chan struct{})
	q := New(&Config{ProcessPeriod: 5 * time.Millisecond, Workers: 1, Delivery: func(ctx context.Context, message *Message) error {
		mu.Lock()
		inFlight++
		mu.Unlock()
		defer func() {
			mu.Lock()
			inFlight--
			mu.Unlock()
		}()
		select {
		case <-release:
		case <-ctx.Done():
			mu.Lock()
			interrupted++
			mu.Unlock()
			return ctx.Err()
		}
		mu.Lock()
		delivered[message.ID]++
		mu.Unlock()
		return nil
	}})
	defer q.Close()
	const total = 20
	for index := range total {
		if err := q.Enqueue(&Message{Recipient: fmt.Sprintf("user@d%d.example", index)}); err != nil {
			t.Fatal(err)
		}
	}
	current := func() int { mu.Lock(); defer mu.Unlock(); return inFlight }
	waitUntil(t, "one in-flight delivery", func() bool { return current() == 1 })

	if err := q.Reconfigure(testLimits(4)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "four in-flight deliveries", func() bool { return current() == 4 })

	if err := q.Reconfigure(testLimits(1)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if got := current(); got != 4 {
		t.Fatalf("shrinking the pool interrupted deliveries: %d in flight", got)
	}
	if got := q.runningWorker.Load(); got != 4 {
		t.Fatalf("busy workers exited before finishing: %d running", got)
	}
	close(release)
	waitUntil(t, "every message delivered", func() bool { return q.Size() == 0 })
	waitUntil(t, "retired workers to exit", func() bool { return q.runningWorker.Load() == 1 })

	mu.Lock()
	defer mu.Unlock()
	if interrupted != 0 {
		t.Fatalf("%d deliveries were interrupted", interrupted)
	}
	if len(delivered) != total {
		t.Fatalf("delivered %d distinct messages, want %d", len(delivered), total)
	}
	for id, count := range delivered {
		if count != 1 {
			t.Fatalf("message %s delivered %d times", id, count)
		}
	}
}

func TestReconfigureRetryAndAgeApplyToNewScheduling(t *testing.T) {
	q := New(&Config{ProcessPeriod: 5 * time.Millisecond, Workers: 1, RetryInitial: time.Hour, RetryMax: 2 * time.Hour, MaxAge: 24 * time.Hour,
		Delivery: func(context.Context, *Message) error {
			return &DeliveryError{Class: DeliveryTemporary, EnhancedCode: "4.4.1", Response: "try later"}
		}})
	defer q.Close()
	retrying := func(id string) func() bool {
		return func() bool { message := q.Get(id); return message != nil && message.Status == StatusRetrying }
	}
	first := &Message{Recipient: "first@remote.example"}
	if err := q.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "first retry", retrying(first.ID))
	before := q.Get(first.ID)
	if delay := time.Until(before.NextRetry); delay < 50*time.Minute {
		t.Fatalf("first retry delay = %s, want about an hour", delay)
	}

	limits := testLimits(1)
	limits.RetryInitial, limits.RetryMax, limits.MaxAge = 2*time.Second, 2*time.Second, 2*time.Hour
	if err := q.Reconfigure(limits); err != nil {
		t.Fatal(err)
	}
	second := &Message{Recipient: "second@remote.example"}
	if err := q.Enqueue(second); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "second retry", retrying(second.ID))
	after := q.Get(second.ID)
	if delay := time.Until(after.NextRetry); delay > 3*time.Second {
		t.Fatalf("second retry delay = %s, want the reconfigured 2s", delay)
	}
	if age := after.ExpiresAt.Sub(after.CreatedAt); age != 2*time.Hour {
		t.Fatalf("new message age = %s, want 2h", age)
	}
	unchanged := q.Get(first.ID)
	if !unchanged.ExpiresAt.Equal(before.ExpiresAt) || !unchanged.NextRetry.Equal(before.NextRetry) {
		t.Fatalf("existing schedule changed: expires %s -> %s, retry %s -> %s", before.ExpiresAt, unchanged.ExpiresAt, before.NextRetry, unchanged.NextRetry)
	}
}

func TestReconfigureRejectsInvalidLimits(t *testing.T) {
	q := New(&Config{ProcessPeriod: time.Hour, Workers: 2, Delivery: func(ctx context.Context, _ *Message) error {
		<-ctx.Done()
		return ctx.Err()
	}})
	defer q.Close()
	for range 3 {
		if err := q.Enqueue(&Message{Recipient: "user@remote.example"}); err != nil {
			t.Fatal(err)
		}
	}
	original := q.Limits()
	invalid := []Limits{
		func() Limits { l := testLimits(2); l.RetryInitial = 2 * l.RetryMax; return l }(),
		func() Limits { l := testLimits(0); return l }(),
		func() Limits { l := testLimits(MaxWorkers + 1); return l }(),
		func() Limits { l := testLimits(2); l.MaxSize = 2; return l }(),
		func() Limits { l := testLimits(2); l.MaxAge = 0; return l }(),
	}
	for index, limits := range invalid {
		if err := q.Reconfigure(limits); err == nil {
			t.Fatalf("case %d: invalid limits accepted", index)
		}
		if got := q.Limits(); got != original {
			t.Fatalf("case %d: limits changed after rejection: %+v", index, got)
		}
	}
	waitUntil(t, "two workers after rejected changes", func() bool { return q.runningWorker.Load() == 2 })
	q.Close()
	if err := q.Reconfigure(testLimits(2)); err == nil {
		t.Fatal("closed queue accepted reconfiguration")
	}
}
