package background

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStopCancelsAndWaitsForEveryGoroutine(t *testing.T) {
	group := New(context.Background())
	var finished atomic.Int64
	started := make(chan struct{})
	for range 8 {
		group.Go(func(ctx context.Context) {
			started <- struct{}{}
			<-ctx.Done()
			time.Sleep(time.Millisecond)
			finished.Add(1)
		})
	}
	for range 8 {
		<-started
	}
	group.Stop()
	if got := finished.Load(); got != 8 {
		t.Fatalf("finished goroutines after Stop = %d, want 8", got)
	}
	if group.Context().Err() == nil {
		t.Fatal("group context still live after Stop")
	}
}

func TestGoAfterStopDoesNotRun(t *testing.T) {
	group := New(context.Background())
	group.Stop()
	group.Stop()
	if group.Go(func(context.Context) { t.Error("ran after Stop") }) {
		t.Fatal("Go after Stop reported a started goroutine")
	}
}

func TestEveryRunsImmediatelyAndOnTicks(t *testing.T) {
	group := New(context.Background())
	var calls atomic.Int64
	group.Every(time.Millisecond, true, func() { calls.Add(1) })
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("calls = %d, want at least 3", calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
	group.Stop()
	after := calls.Load()
	time.Sleep(5 * time.Millisecond)
	if calls.Load() != after {
		t.Fatal("Every kept running after Stop")
	}
}

// TestGoRacingStop starts goroutines, including nested ones, while Stop runs;
// every goroutine that started must have returned when Stop returns.
func TestGoRacingStop(t *testing.T) {
	for range 50 {
		group := New(context.Background())
		var running atomic.Int64
		var spawners sync.WaitGroup
		for range 4 {
			spawners.Add(1)
			go func() {
				defer spawners.Done()
				for group.Go(func(ctx context.Context) {
					running.Add(1)
					defer running.Add(-1)
					group.Go(func(context.Context) {
						running.Add(1)
						running.Add(-1)
					})
					<-ctx.Done()
				}) {
				}
			}()
		}
		time.Sleep(100 * time.Microsecond)
		group.Stop()
		if got := running.Load(); got != 0 {
			t.Fatalf("goroutines still running after Stop = %d", got)
		}
		spawners.Wait()
	}
}
