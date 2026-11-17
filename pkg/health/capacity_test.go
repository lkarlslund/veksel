package health

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type capacityProbeFunc func(string) (Capacity, error)

func (fn capacityProbeFunc) Capacity(path string) (Capacity, error) { return fn(path) }

func awaitCapacity(t *testing.T, collector *CapacityCollector, now time.Time, targets []CapacityTarget, ready func([]CapacitySample) bool) []CapacitySample {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		samples := collector.Snapshot(now, targets)
		if ready(samples) {
			return samples
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for capacity collection")
	return nil
}

func TestCapacityCollectorDeduplicatesDevicesAndCachesSamples(t *testing.T) {
	var calls atomic.Int64
	collector := NewCapacityCollector(capacityProbeFunc(func(path string) (Capacity, error) {
		calls.Add(1)
		if path == "/missing" {
			return Capacity{}, errors.New("missing")
		}
		return Capacity{DeviceID: "42", TotalBytes: 1000, AvailableBytes: 200}, nil
	}), time.Minute)
	targets := []CapacityTarget{{ID: "system", Label: "System data", Path: "/data"}, {ID: "root:fast", Label: "Account root fast", Path: "/accounts"}, {ID: "root:missing", Label: "Account root missing", Path: "/missing"}}
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)

	pending := collector.Snapshot(now, targets)
	if len(pending) != 1 || !pending[0].Pending {
		t.Fatalf("initial samples = %+v, want one pending observation", pending)
	}
	first := awaitCapacity(t, collector, now, targets, func(samples []CapacitySample) bool { return len(samples) == 2 && !samples[0].Pending })
	if calls.Load() != 3 {
		t.Fatalf("calls=%d samples=%+v", calls.Load(), first)
	}
	if first[0].DeviceID != "42" || len(first[0].TargetIDs) != 2 || first[1].Error == "" || !first[0].CollectedAt.Equal(now) {
		t.Fatalf("deduplicated samples = %+v", first)
	}
	first[0].TargetIDs[0] = "mutated"
	second := collector.Snapshot(now.Add(30*time.Second), targets)
	if calls.Load() != 3 || second[0].TargetIDs[0] == "mutated" {
		t.Fatalf("cached snapshot was not detached: calls=%d samples=%+v", calls.Load(), second)
	}
	collector.Snapshot(now.Add(time.Minute), targets)
	awaitCapacity(t, collector, now.Add(time.Minute), targets, func([]CapacitySample) bool { return calls.Load() == 6 })
	if calls.Load() != 6 {
		t.Fatalf("calls after TTL=%d, want 6", calls.Load())
	}
	changedTargets := append(targets, CapacityTarget{ID: "root:new", Label: "Account root new", Path: "/new"})
	collector.Snapshot(now.Add(time.Minute+time.Second), changedTargets)
	awaitCapacity(t, collector, now.Add(time.Minute+time.Second), changedTargets, func([]CapacitySample) bool { return calls.Load() == 10 })
	if calls.Load() != 10 {
		t.Fatalf("calls after target change=%d, want 10", calls.Load())
	}
}

func TestCapacityCollectorCoalescesConcurrentRefresh(t *testing.T) {
	var calls atomic.Int64
	collector := NewCapacityCollector(capacityProbeFunc(func(string) (Capacity, error) {
		calls.Add(1)
		return Capacity{DeviceID: "7", TotalBytes: 100, AvailableBytes: 50}, nil
	}), time.Minute)
	targets := []CapacityTarget{{ID: "system", Label: "System data", Path: "/data"}}
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if samples := collector.Snapshot(now, targets); len(samples) != 1 {
				t.Errorf("samples = %+v", samples)
			}
		}()
	}
	workers.Wait()
	awaitCapacity(t, collector, now, targets, func(samples []CapacitySample) bool { return calls.Load() == 1 && !samples[0].Pending })
	if calls.Load() != 1 {
		t.Fatalf("probe calls=%d, want 1", calls.Load())
	}
}

func TestCapacityCollectorNeverBlocksHealthOnProbe(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	collector := NewCapacityCollector(capacityProbeFunc(func(string) (Capacity, error) {
		close(started)
		<-release
		return Capacity{DeviceID: "slow", TotalBytes: 100, AvailableBytes: 25}, nil
	}), time.Minute)
	targets := []CapacityTarget{{ID: "remote", Label: "Remote account root", Path: "/remote"}}
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)

	before := time.Now()
	samples := collector.Snapshot(now, targets)
	if elapsed := time.Since(before); elapsed > 50*time.Millisecond || len(samples) != 1 || !samples[0].Pending {
		t.Fatalf("initial snapshot blocked for %s or lacked pending evidence: %+v", elapsed, samples)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background probe did not start")
	}
	before = time.Now()
	_ = collector.Snapshot(now.Add(time.Second), targets)
	if elapsed := time.Since(before); elapsed > 50*time.Millisecond {
		t.Fatalf("concurrent snapshot blocked for %s", elapsed)
	}
	timedOut := collector.Snapshot(now.Add(time.Minute), targets)
	if len(timedOut) != 1 || timedOut[0].Pending || timedOut[0].Error == "" {
		t.Fatalf("long-running probe did not become explicit evidence: %+v", timedOut)
	}
	close(release)
	ready := awaitCapacity(t, collector, now, targets, func(samples []CapacitySample) bool { return len(samples) == 1 && !samples[0].Pending })
	if ready[0].DeviceID != "slow" {
		t.Fatalf("completed sample = %+v", ready)
	}
}

func TestCapacityCollectorMarksLastGoodEvidenceStale(t *testing.T) {
	var calls atomic.Int64
	secondStarted, releaseSecond, secondDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	collector := NewCapacityCollector(capacityProbeFunc(func(string) (Capacity, error) {
		if calls.Add(1) == 2 {
			close(secondStarted)
			<-releaseSecond
			close(secondDone)
		}
		return Capacity{DeviceID: "volume", TotalBytes: 100, AvailableBytes: 40}, nil
	}), time.Minute)
	targets := []CapacityTarget{{ID: "system", Label: "System data", Path: "/data"}}
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	awaitCapacity(t, collector, now, targets, func(samples []CapacitySample) bool { return len(samples) == 1 && !samples[0].Pending })
	_ = collector.Snapshot(now.Add(time.Minute), targets)
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("stale refresh did not start")
	}
	stale := collector.Snapshot(now.Add(2*time.Minute), targets)
	if len(stale) != 1 || !stale[0].Stale || stale[0].AvailableBytes != 40 {
		t.Fatalf("stale evidence = %+v", stale)
	}
	close(releaseSecond)
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("stale refresh did not finish")
	}
}

func TestCapacityObservationsApplyPolicyWithoutInventingCapacity(t *testing.T) {
	collectedAt := time.Date(2026, 8, 18, 9, 59, 0, 0, time.UTC)
	samples := []CapacitySample{
		{DeviceID: "normal", TargetIDs: []string{"system"}, TargetLabels: []string{"System data"}, TotalBytes: 1000, AvailableBytes: 500, CollectedAt: collectedAt},
		{DeviceID: "warning", TargetIDs: []string{"root:fast"}, TargetLabels: []string{"Account root fast"}, TotalBytes: 1000, AvailableBytes: 150},
		{DeviceID: "critical", TargetIDs: []string{"root:bulk"}, TargetLabels: []string{"Account root bulk"}, TotalBytes: 1000, AvailableBytes: 50},
		{DeviceID: "error:missing", TargetIDs: []string{"root:missing"}, TargetLabels: []string{"Account root missing"}, Error: "permission denied"},
	}
	observations := (Policy{StorageWarningFreePercent: 15, StorageCriticalFreePercent: 5}).CapacityObservations(samples)
	byID := make(map[string]Observation, len(observations))
	for _, observation := range observations {
		byID[observation.ID] = observation
	}
	if byID["filesystem:normal"].State != StateHealthy || byID["filesystem:normal"].Details["collected_at"] != collectedAt.Format(time.RFC3339Nano) || byID["filesystem:warning"].Severity != SeverityWarning || byID["filesystem:critical"].Severity != SeverityCritical {
		t.Fatalf("policy observations = %+v", observations)
	}
	failure := byID["filesystem:error:missing"]
	if failure.State != StateDegraded || failure.Details["total_bytes"] != "" || failure.Details["available_bytes"] != "" {
		t.Fatalf("failed probe observation = %+v", failure)
	}
}

func TestPendingCapacityObservationDoesNotOpenAnAlert(t *testing.T) {
	observations := (Policy{StorageWarningFreePercent: 15, StorageCriticalFreePercent: 5}).CapacityObservations([]CapacitySample{{
		DeviceID: "probe", TargetIDs: []string{"system"}, TargetLabels: []string{"System data"}, Pending: true,
	}})
	if len(observations) != 1 || observations[0].State != StateHealthy || observations[0].Severity != "" || observations[0].Reason == "" {
		t.Fatalf("pending observation = %+v", observations)
	}
}

func TestStaleCapacityObservationOpensWarningWithoutLosingMeasurements(t *testing.T) {
	collectedAt := time.Date(2026, 8, 18, 9, 58, 0, 0, time.UTC)
	observations := (Policy{StorageWarningFreePercent: 15, StorageCriticalFreePercent: 5}).CapacityObservations([]CapacitySample{{
		DeviceID: "volume", TargetIDs: []string{"system"}, TargetLabels: []string{"System data"},
		TotalBytes: 100, AvailableBytes: 40, CollectedAt: collectedAt, Stale: true,
	}})
	if len(observations) != 1 || observations[0].State != StateDegraded || observations[0].Severity != SeverityWarning || observations[0].Details["available_bytes"] != "40" || observations[0].Details["collected_at"] == "" {
		t.Fatalf("stale observation = %+v", observations)
	}
}

func TestOSCapacityProberReportsCurrentFilesystem(t *testing.T) {
	capacity, err := (OSCapacityProber{}).Capacity(t.TempDir())
	if err != nil {
		t.Skipf("platform capacity probe unavailable: %v", err)
	}
	if capacity.DeviceID == "" || capacity.TotalBytes == 0 || capacity.AvailableBytes > capacity.TotalBytes {
		t.Fatalf("capacity = %+v", capacity)
	}
}
