package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestConnectionGaugeTracksConcurrentOpenAndIdempotentRelease(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	collector := New(backend)
	gauge := NewConnectionGauge(collector, "imap_active_connections")
	if value, _, ok := collector.CurrentGauge("imap_active_connections"); !ok || value != 0 {
		t.Fatalf("initial gauge = %v, present=%v", value, ok)
	}

	const connections = 32
	releases := make([]func(), connections)
	var wait sync.WaitGroup
	for index := range releases {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			releases[index] = gauge.Open()
		}(index)
	}
	wait.Wait()
	if gauge.Active() != connections {
		t.Fatalf("active = %d, want %d", gauge.Active(), connections)
	}
	for _, release := range releases {
		release()
		release()
	}
	if value, _, ok := collector.CurrentGauge("imap_active_connections"); !ok || value != 0 || gauge.Active() != 0 {
		t.Fatalf("released gauge = %v, active=%d, present=%v", value, gauge.Active(), ok)
	}
}

func TestConnectionGaugeCoalescesPersistedSamples(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	collector := New(backend)
	gauge := NewConnectionGauge(collector, "smtp_active_connections")
	for range 200 {
		gauge.Open()()
	}
	release := gauge.Open()
	defer release()
	if value, _, ok := collector.CurrentGauge("smtp_active_connections"); !ok || value != 1 {
		t.Fatalf("current gauge = %v, present=%v; want 1 at once", value, ok)
	}
	if samples := collector.Query("smtp_active_connections", time.Hour); len(samples) != 1 {
		t.Fatalf("persisted %d samples during a burst, want 1", len(samples))
	}
	collector.Flush()
	samples := collector.Query("smtp_active_connections", time.Hour)
	if len(samples) != 2 || samples[1].Value != 1 {
		t.Fatalf("flushed samples = %+v, want the burst's newest value", samples)
	}
}

func TestConnectionGaugeWithoutMetricsStillTracksActive(t *testing.T) {
	gauge := NewConnectionGauge(nil, "smtp_active_connections")
	release := gauge.Open()
	if gauge.Active() != 1 {
		t.Fatalf("active = %d", gauge.Active())
	}
	release()
	if gauge.Active() != 0 {
		t.Fatalf("released active = %d", gauge.Active())
	}
}

func TestNewConnectionGaugeClearsPersistedPreRestartValue(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	collector := New(backend)
	previous := NewConnectionGauge(collector, "smtp_active_connections")
	_ = previous.Open()
	if value, _, _ := collector.CurrentGauge("smtp_active_connections"); value != 1 {
		t.Fatalf("pre-restart gauge = %v", value)
	}
	NewConnectionGauge(collector, "smtp_active_connections")
	if value, _, ok := collector.CurrentGauge("smtp_active_connections"); !ok || value != 0 {
		t.Fatalf("restart gauge = %v, present=%v", value, ok)
	}
}
