package main

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/background"
)

// withTestBackground gives s a background group that stops when the test
// ends, as openRuntime does for the real server.
func withTestBackground(t *testing.T, s *server) *server {
	t.Helper()
	s.background = background.New(t.Context())
	s.ctx = s.background.Context()
	t.Cleanup(s.background.Stop)
	return s
}

// TestShutdownStopsBackgroundJobsBeforeStoresClose repeatedly opens the
// system store, starts real background jobs plus jobs that keep the store
// busy, and shuts down while they run. The store operations deliberately
// ignore the background context: every one must still find the store open,
// because the cleanup stack stops and waits for the background group before
// it closes the store. Afterwards no goroutine may be left behind.
func TestShutdownStopsBackgroundJobsBeforeStoresClose(t *testing.T) {
	const iterations, busyJobs = 20, 4
	run := func() {
		t.Helper()
		s := &server{}
		if err := s.openRuntime(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		// Real jobs touching the system store: the temporary alias cleanup
		// and the learned spam state flush, which saves once more on stop.
		s.startUserAliasCleanup()
		s.persistSpamState(spamReputationNamespace, func() ([]byte, error) { return []byte("{}"), nil })
		failures := make(chan error, busyJobs)
		busy := make(chan struct{}, busyJobs)
		for job := range busyJobs {
			s.background.Go(func(ctx context.Context) {
				key := fmt.Sprintf("job-%d", job)
				for first := true; ctx.Err() == nil; first = false {
					if err := s.store.Set(context.Background(), "stress", key, []byte("value")); err != nil {
						failures <- fmt.Errorf("set after %v: %w", ctx.Err(), err)
						return
					}
					if _, err := s.store.Scan(context.Background(), "stress", "job-"); err != nil {
						failures <- fmt.Errorf("scan after %v: %w", ctx.Err(), err)
						return
					}
					if first {
						busy <- struct{}{}
					}
				}
			})
		}
		for range busyJobs {
			<-busy
		}
		s.cleanup.run(true)
		close(failures)
		for err := range failures {
			t.Errorf("background job reached a closed store: %v", err)
		}
		if s.background.Go(func(context.Context) {}) {
			t.Error("background group accepted a job after shutdown")
		}
	}

	// The first run starts process-wide goroutines, such as the shared
	// Pebble cache, that later runs reuse.
	run()
	baseline := runtime.NumGoroutine()
	for range iterations {
		run()
		if t.Failed() {
			return
		}
	}
	const tolerance = 3
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+tolerance {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines after %d shutdowns = %d, baseline %d\n%s", iterations, runtime.NumGoroutine(), baseline, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestGracefulShutdownWaitsForBackgroundJobs runs the full startup and the
// graceful shutdown sequence with a store-bound job still active, and
// requires the job to finish before the stores close.
func TestGracefulShutdownWaitsForBackgroundJobs(t *testing.T) {
	s := startLoopbackServer(t)
	stopped := make(chan error, 1)
	running := make(chan struct{})
	s.background.Go(func(ctx context.Context) {
		close(running)
		<-ctx.Done()
		// Shutdown has begun; the store must still be open.
		stopped <- s.store.Set(context.Background(), "stress", "late", []byte("value"))
	})
	<-running
	s.shutdown()
	if err := <-stopped; err != nil {
		t.Fatalf("background job after shutdown began: %v", err)
	}
}
