package mailpolicy

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

type backendFactory func(string) (store.Store, error)

func policyBackends() map[string]backendFactory {
	return map[string]backendFactory{
		"pebble": func(path string) (store.Store, error) { return pebblestore.New(path) },
		"badger": func(path string) (store.Store, error) { return badgerstore.New(path) },
	}
}

func TestRepositoryPersistsAcrossProductionBackendRestart(t *testing.T) {
	for name, open := range policyBackends() {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir()
			backend, err := open(path)
			if err != nil {
				t.Fatal(err)
			}
			repository := NewRepository(backend)
			initial, err := repository.Load(t.Context())
			if err != nil || initial.Revision != "initial" || len(initial.Rules) != 0 {
				t.Fatalf("initial = %+v, err = %v", initial, err)
			}
			stored, _, err := repository.Replace(t.Context(), initial.Revision, policyDocument("persisted", "route-a"))
			if err != nil {
				t.Fatal(err)
			}
			if stored.Revision == initial.Revision || len(stored.Revision) != 32 {
				t.Fatalf("revision = %q", stored.Revision)
			}
			if err := backend.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, err := open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			reloaded, err := NewRepository(reopened).Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.Revision != stored.Revision || reloaded.Rules[0].Actions[0].Value != "route-a" {
				t.Fatalf("reloaded = %+v, want revision %q", reloaded, stored.Revision)
			}
		})
	}
}

func TestServiceRejectsStaleInvalidAndFailedReplacements(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	faults := faultstore.New(backend)
	t.Cleanup(func() { _ = faults.Close() })
	service, err := NewService(t.Context(), NewRepository(faults))
	if err != nil {
		t.Fatal(err)
	}
	initial := service.Document()
	active, err := service.Replace(t.Context(), initial.Revision, policyDocument("active", "route-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Replace(t.Context(), initial.Revision, policyDocument("stale", "route-b")); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale error = %v", err)
	}
	invalid := policyDocument("invalid", "route-b")
	invalid.Rules[0].Conditions[0].Operator = "unsupported"
	if _, err := service.Replace(t.Context(), active.Revision, invalid); err == nil {
		t.Fatal("invalid policy replacement succeeded")
	}
	faults.Fail("compare_and_swap", 1)
	if _, err := service.Replace(t.Context(), active.Revision, policyDocument("failed", "route-c")); !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("write failure = %v", err)
	}
	result := service.Evaluate(Message{Direction: DirectionInbound})
	if result.Revision != active.Revision || len(result.Actions) != 1 || result.Actions[0].Value != "route-a" {
		t.Fatalf("working snapshot changed after rejected replacements: %+v", result)
	}
}

func TestServiceSerializesRevisionGuardedUpdates(t *testing.T) {
	backend, err := badgerstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	service, err := NewService(t.Context(), NewRepository(backend))
	if err != nil {
		t.Fatal(err)
	}
	expected := service.Document().Revision
	var successes atomic.Int64
	var conflicts atomic.Int64
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := service.Replace(t.Context(), expected, policyDocument(fmt.Sprintf("candidate-%d", index), fmt.Sprintf("route-%d", index)))
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrRevisionConflict):
				conflicts.Add(1)
			default:
				t.Errorf("replace: %v", err)
			}
		}(index)
	}
	wait.Wait()
	if successes.Load() != 1 || conflicts.Load() != 31 {
		t.Fatalf("successes = %d, conflicts = %d", successes.Load(), conflicts.Load())
	}
	document := service.Document()
	result := service.Evaluate(Message{Direction: DirectionInbound})
	if result.Revision != document.Revision || len(result.Actions) != 1 || result.Actions[0].Value != document.Rules[0].Actions[0].Value {
		t.Fatalf("document and compiled snapshot diverged: document=%+v result=%+v", document, result)
	}
}

func TestServiceDocumentIsDetached(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	service, err := NewService(t.Context(), NewRepository(backend))
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.Replace(t.Context(), service.Document().Revision, policyDocument("detached", "route-a"))
	if err != nil {
		t.Fatal(err)
	}
	document.Rules[0].Actions[0].Value = "mutated"
	read := service.Document()
	read.Rules[0].Conditions[0].Value = "outbound"
	result := service.Evaluate(Message{Direction: DirectionInbound})
	if len(result.Actions) != 1 || result.Actions[0].Value != "route-a" {
		t.Fatalf("service exposed mutable state: %+v", result)
	}
}

func TestServiceStatsAreRevisionScopedAndConcurrent(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	service, err := NewService(t.Context(), NewRepository(backend))
	if err != nil {
		t.Fatal(err)
	}
	document := policyDocument("stats", "route-a")
	document.Rules[0].Actions = append(document.Rules[0].Actions, Action{Type: ActionQuarantine, Value: "review"})
	active, err := service.Replace(t.Context(), service.Document().Revision, document)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < 100; index++ {
				service.Evaluate(Message{Direction: DirectionInbound})
			}
		}()
	}
	wait.Wait()
	stats := service.Stats()
	if stats.Revision != active.Revision || stats.Evaluations != 1600 || stats.Matched != 1600 || stats.Quarantined != 1600 || stats.Routed != 1600 || stats.RuleMatches["rule"] != 1600 || stats.LastEvaluatedAt.IsZero() {
		t.Fatalf("stats = %+v", stats)
	}
	next, err := service.Replace(t.Context(), active.Revision, policyDocument("next", "route-b"))
	if err != nil {
		t.Fatal(err)
	}
	stats = service.Stats()
	if stats.Revision != next.Revision || stats.Evaluations != 0 || len(stats.RuleMatches) != 0 || !stats.LastEvaluatedAt.IsZero() {
		t.Fatalf("replacement retained prior counters: %+v", stats)
	}
}

func policyDocument(name, route string) Document {
	return Document{Rules: []Rule{{
		ID: "rule", Name: name, Enabled: true,
		Conditions: []Condition{{Field: FieldDirection, Operator: OperatorEquals, Value: "inbound"}},
		Actions:    []Action{{Type: ActionRoute, Value: route}},
	}}}
}
