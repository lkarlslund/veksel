package health

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegistryReadinessTransitionsAndDetachedSnapshots(t *testing.T) {
	registry := New()
	first := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	observations := []Observation{
		{ID: "store", Label: "System store", Kind: "dependency", Desired: true, Required: true, State: StateHealthy, Details: map[string]string{"backend": "pebble"}},
		{ID: "imap", Label: "IMAP", Kind: "listener", State: StateDisabled},
		{ID: "queue", Label: "System queue", Kind: "dependency", Desired: true, Required: true, State: StateDegraded, Reason: "oldest item delayed"},
	}
	if err := registry.Replace(first, observations); err != nil {
		t.Fatal(err)
	}
	snapshot := registry.Snapshot(first.Add(time.Minute))
	if snapshot.Status != StatusDegraded || len(snapshot.Components) != 3 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if snapshot.Components[1].ID != "queue" || !snapshot.Components[1].Since.Equal(first) {
		t.Fatalf("ordered components = %#v", snapshot.Components)
	}
	snapshot.Components[2].Details["backend"] = "changed"
	if got := registry.Snapshot(time.Time{}).Components[2].Details["backend"]; got != "pebble" {
		t.Fatalf("registry details mutated through snapshot: %q", got)
	}

	second := first.Add(2 * time.Minute)
	observations[2].Reason = "different evidence, same state"
	if err := registry.Replace(second, observations); err != nil {
		t.Fatal(err)
	}
	if got := registry.Snapshot(second).Components[1].Since; !got.Equal(first) {
		t.Fatalf("degraded transition time = %v, want %v", got, first)
	}
	observations[2].State = StateUnavailable
	if err := registry.Replace(second, observations); err != nil {
		t.Fatal(err)
	}
	snapshot = registry.Snapshot(second)
	if snapshot.Status != StatusUnavailable || !snapshot.Components[1].Since.Equal(second) {
		t.Fatalf("unavailable snapshot = %#v", snapshot)
	}
}

func TestRegistryValidationIsAtomicAndBoundsEvidence(t *testing.T) {
	registry := New()
	now := time.Now()
	if err := registry.Replace(now, []Observation{{ID: "store", Label: "Store", Kind: "dependency", Desired: true, Required: true, State: StateHealthy}}); err != nil {
		t.Fatal(err)
	}
	invalid := []Observation{{ID: "store", Label: "Store", Kind: "dependency", State: StateHealthy}, {ID: "bad", Label: "Bad", Kind: "dependency", State: "mystery"}}
	if err := registry.Replace(now.Add(time.Minute), invalid); err == nil {
		t.Fatal("invalid replacement succeeded")
	}
	if got := registry.Snapshot(now).Components; len(got) != 1 || got[0].ID != "store" {
		t.Fatalf("failed replacement changed state: %#v", got)
	}
	long := strings.Repeat("å ", 600)
	if err := registry.Replace(now, []Observation{{ID: "bounded", Label: "Bounded", Kind: "dependency", State: StateDegraded, Reason: long, Details: map[string]string{"evidence": long}}}); err != nil {
		t.Fatal(err)
	}
	component := registry.Snapshot(now).Components[0]
	if len([]rune(component.Reason)) != maxReasonRunes+1 || len([]rune(component.Details["evidence"])) != maxDetailRunes+1 {
		t.Fatalf("evidence not bounded: reason=%d detail=%d", len([]rune(component.Reason)), len([]rune(component.Details["evidence"])))
	}
}

func TestRegistryConcurrentReplaceAndSnapshot(t *testing.T) {
	registry := New()
	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := range 250 {
				state := StateHealthy
				if iteration%3 == 0 {
					state = StateDegraded
				}
				_ = registry.Replace(time.Now(), []Observation{{ID: "component", Label: "Component", Kind: "test", Desired: true, State: state, Reason: fmt.Sprintf("worker %d", worker)}})
				_ = registry.Snapshot(time.Now())
			}
		}()
	}
	group.Wait()
	if len(registry.Snapshot(time.Now()).Components) != 1 {
		t.Fatal("concurrent registry lost component")
	}
}
