package dmarc

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func newTestAggregateRecorder(t *testing.T, options AggregateRecorderOptions) (*AggregateRecorder, func()) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := NewAggregateRecorder(t.Context(), backend, options)
	if err != nil {
		_ = backend.Close()
		t.Fatal(err)
	}
	return recorder, func() { _ = backend.Close() }
}

func aggregateObservation(attempt string) AggregateObservation {
	return AggregateObservation{AttemptID: attempt, Time: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		SourceIP: "192.0.2.15", HeaderFrom: "sender.example", EnvelopeFrom: "bounce.sender.example",
		Disposition: "none", DKIMAligned: true,
		DKIM: []AggregateAuthResult{{Domain: "sender.example", Selector: "mail", Result: "pass"}},
		SPF:  AggregateAuthResult{Domain: "bounce.sender.example", Result: "fail"},
		Policy: ReportingPolicy{Domain: "sender.example", Policy: "reject", SubdomainPolicy: "quarantine",
			ADKIM: "r", ASPF: "r", Percentage: 100, RUA: []string{"mailto:dmarc@reports.example"}, DiscoveryMethod: "psl"}}
}

func TestAggregateRecorderGroupsAndDeduplicates(t *testing.T) {
	recorder, closeRecorder := newTestAggregateRecorder(t, AggregateRecorderOptions{})
	defer closeRecorder()
	for _, attempt := range []string{"one", "two", "two"} {
		if err := recorder.Record(t.Context(), aggregateObservation(attempt)); err != nil {
			t.Fatal(err)
		}
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-27", "sender.example")
	if err != nil || len(aggregates) != 1 || len(aggregates[0].Rows) != 1 || aggregates[0].Rows[0].Count != 2 {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
	if aggregates[0].Rows[0].DKIM[0].Selector != "mail" || aggregates[0].Policy.RUA[0] != "mailto:dmarc@reports.example" {
		t.Fatalf("aggregate evidence = %#v", aggregates[0])
	}
}

func TestAggregateRecorderSerializesConcurrentUpdates(t *testing.T) {
	recorder, closeRecorder := newTestAggregateRecorder(t, AggregateRecorderOptions{})
	defer closeRecorder()
	const workers = 75
	var group sync.WaitGroup
	errorsOut := make(chan error, workers)
	for index := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsOut <- recorder.Record(t.Context(), aggregateObservation(fmt.Sprintf("attempt-%d", index)))
		}()
	}
	group.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-27", "")
	if err != nil || len(aggregates) != 1 || aggregates[0].Rows[0].Count != workers {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
}

func TestAggregateRecorderBoundsRowsAndIgnoresPolicyWithoutRUA(t *testing.T) {
	recorder, closeRecorder := newTestAggregateRecorder(t, AggregateRecorderOptions{MaxRows: 1})
	defer closeRecorder()
	withoutRUA := aggregateObservation("ignored")
	withoutRUA.Policy.RUA = nil
	if err := recorder.Record(t.Context(), withoutRUA); err != nil {
		t.Fatal(err)
	}
	first := aggregateObservation("one")
	second := aggregateObservation("two")
	second.SourceIP = "192.0.2.16"
	if err := recorder.Record(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-27", "")
	if err != nil || len(aggregates) != 1 || len(aggregates[0].Rows) != 1 || aggregates[0].OverflowCount != 1 {
		t.Fatalf("bounded aggregate = %#v, %v", aggregates, err)
	}
}

func TestAggregateRecorderBoundsPolicyConfigurationsPerDay(t *testing.T) {
	recorder, closeRecorder := newTestAggregateRecorder(t, AggregateRecorderOptions{MaxAggregatesPerDay: 1})
	defer closeRecorder()
	first := aggregateObservation("one")
	second := aggregateObservation("two")
	second.Policy.RUA = []string{"mailto:other@reports.example"}
	if err := recorder.Record(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-27", "")
	if err != nil || len(aggregates) != 1 {
		t.Fatalf("bounded aggregates=%#v,%v", aggregates, err)
	}
	data, err := recorder.store.Get(t.Context(), model.NSDMARCAggregates, "limit/day/2026-08-27/overflow")
	if err != nil || string(data) != "1" {
		t.Fatalf("overflow=%q,%v", data, err)
	}
}

func TestAggregateRecorderRejectsInvalidNetworkEvidence(t *testing.T) {
	recorder, closeRecorder := newTestAggregateRecorder(t, AggregateRecorderOptions{})
	defer closeRecorder()
	invalid := aggregateObservation("invalid")
	invalid.SourceIP = "not-an-ip"
	if err := recorder.Record(t.Context(), invalid); err == nil {
		t.Fatal("invalid source IP was accepted")
	}
}

func TestAggregateRecorderCleanupIsBoundedAndPreservesCutoffDay(t *testing.T) {
	recorder, closeRecorder := newTestAggregateRecorder(t, AggregateRecorderOptions{})
	defer closeRecorder()
	old := aggregateObservation("old")
	old.Time = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	current := aggregateObservation("current")
	if err := recorder.Record(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	removed, err := recorder.CleanupBefore(t.Context(), time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), 1)
	if err != nil || removed != 1 {
		t.Fatalf("first cleanup=%d,%v", removed, err)
	}
	for {
		removed, err = recorder.CleanupBefore(t.Context(), time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), 10)
		if err != nil {
			t.Fatal(err)
		}
		if removed == 0 {
			break
		}
	}
	oldAggregates, err := recorder.Aggregates(t.Context(), "2026-07-01", "")
	if err != nil || len(oldAggregates) != 0 {
		t.Fatalf("old aggregates=%#v,%v", oldAggregates, err)
	}
	currentAggregates, err := recorder.Aggregates(t.Context(), "2026-08-27", "")
	if err != nil || len(currentAggregates) != 1 {
		t.Fatalf("current aggregates=%#v,%v", currentAggregates, err)
	}
}
