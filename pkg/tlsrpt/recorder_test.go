package tlsrpt

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func testRecorder(t *testing.T, options RecorderOptions) (*Recorder, func()) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := NewRecorder(t.Context(), backend, options)
	if err != nil {
		_ = backend.Close()
		t.Fatal(err)
	}
	return recorder, func() { _ = backend.Close() }
}

func baseEvent(attempt string, success bool) Event {
	event := Event{AttemptID: attempt, Time: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC),
		Policy:      AppliedPolicy{Type: PolicyTypeSTS, Domain: "Example.Test.", Strings: []string{"version: STSv1", "mode: testing"}, MX: []string{"*.example.test"}},
		ReceivingMX: "mx.example.test", SendingMTAIP: "192.0.2.1", ReceivingIP: "192.0.2.2", Success: success}
	if !success {
		event.ResultType = ResultSTARTTLSNotSupported
	}
	return event
}

func TestRecorderAggregatesAndDeduplicatesOutcomes(t *testing.T) {
	recorder, closeRecorder := testRecorder(t, RecorderOptions{})
	defer closeRecorder()
	for _, event := range []Event{baseEvent("attempt-1", true), baseEvent("attempt-2", false), baseEvent("attempt-2", false)} {
		if err := recorder.Record(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-18", "example.test")
	if err != nil || len(aggregates) != 1 {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
	aggregate := aggregates[0]
	if aggregate.SuccessfulSessions != 1 || aggregate.FailedSessions != 1 || len(aggregate.Failures) != 1 || aggregate.Failures[0].FailedSessionCount != 1 {
		t.Fatalf("aggregate = %#v", aggregate)
	}
	if aggregate.Policy.Domain != "example.test" || aggregate.Failures[0].ReceivingMXHostname != "mx.example.test" {
		t.Fatalf("normalized aggregate = %#v", aggregate)
	}
}

func TestRecorderAllowsOverlappingFailureTypesForOneAttempt(t *testing.T) {
	recorder, closeRecorder := testRecorder(t, RecorderOptions{})
	defer closeRecorder()
	first := baseEvent("attempt-1", false)
	second := first
	second.ResultType = ResultValidationFailure
	second.FailureReasonCode = "mx-not-authorized"
	if err := recorder.Record(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-18", "example.test")
	if err != nil || len(aggregates) != 1 || aggregates[0].FailedSessions != 1 || len(aggregates[0].Failures) != 2 {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
}

func TestRecorderDeduplicationSurvivesReopen(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	first, err := NewRecorder(t.Context(), backend, RecorderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Record(t.Context(), baseEvent("attempt-1", true)); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewRecorder(t.Context(), backend, RecorderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Record(t.Context(), baseEvent("attempt-1", true)); err != nil {
		t.Fatal(err)
	}
	aggregates, err := reopened.Aggregates(t.Context(), "2026-08-18", "")
	if err != nil || len(aggregates) != 1 || aggregates[0].SuccessfulSessions != 1 {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
}

func TestRecorderSerializesConcurrentUpdates(t *testing.T) {
	recorder, closeRecorder := testRecorder(t, RecorderOptions{})
	defer closeRecorder()
	const workers = 100
	var wait sync.WaitGroup
	errorsOut := make(chan error, workers)
	wait.Add(workers)
	for index := range workers {
		go func() {
			defer wait.Done()
			errorsOut <- recorder.Record(context.Background(), baseEvent(fmt.Sprintf("attempt-%d", index), true))
		}()
	}
	wait.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-18", "")
	if err != nil || len(aggregates) != 1 || aggregates[0].SuccessfulSessions != workers {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
}

func TestRecorderBoundsFailureCardinalityAndReason(t *testing.T) {
	recorder, closeRecorder := testRecorder(t, RecorderOptions{MaxFailureKinds: 2})
	defer closeRecorder()
	for index := range 5 {
		event := baseEvent(string(rune('a'+index)), false)
		event.ReceivingMX = string(rune('a'+index)) + ".example.test"
		event.FailureReasonCode = strings.Repeat("x", 1000)
		if err := recorder.Record(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-18", "")
	if err != nil || len(aggregates) != 1 {
		t.Fatal(err)
	}
	aggregate := aggregates[0]
	var detailed int64
	for _, detail := range aggregate.Failures {
		detailed += detail.FailedSessionCount
		if len([]rune(detail.FailureReasonCode)) > maxReasonLength {
			t.Fatalf("unbounded reason length = %d", len([]rune(detail.FailureReasonCode)))
		}
	}
	if len(aggregate.Failures) != 2 || detailed != aggregate.FailedSessions || aggregate.FailureKindsDropped != 3 {
		t.Fatalf("bounded aggregate = %#v", aggregate)
	}
}

func TestRecorderSuppressionAndDomainScopedCleanup(t *testing.T) {
	recorder, closeRecorder := testRecorder(t, RecorderOptions{})
	defer closeRecorder()
	if err := recorder.Record(Suppress(t.Context()), baseEvent("suppressed", true)); err != nil {
		t.Fatal(err)
	}
	first := baseEvent("same-attempt", true)
	second := first
	second.Policy.Domain = "other.example"
	if err := recorder.Record(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.DeleteDayDomain(t.Context(), "2026-08-18", "example.test"); err != nil {
		t.Fatal(err)
	}
	// The other domain's dedupe marker must survive cleanup of example.test.
	if err := recorder.Record(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-18", "")
	if err != nil || len(aggregates) != 1 || aggregates[0].Policy.Domain != "other.example" || aggregates[0].SuccessfulSessions != 1 {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
	days, err := recorder.Days(t.Context())
	if err != nil || len(days) != 1 || days[0] != "2026-08-18" {
		t.Fatalf("Days() = %#v, %v", days, err)
	}
}

func TestRecorderRejectsInvalidPolicyDomain(t *testing.T) {
	recorder, closeRecorder := testRecorder(t, RecorderOptions{})
	defer closeRecorder()
	event := baseEvent("attempt", true)
	event.Policy.Domain = "127.0.0.1"
	if err := recorder.Record(t.Context(), event); err == nil {
		t.Fatal("invalid policy domain was accepted")
	}
}

func TestRecorderAcceptsDANEPolicyAndResultTypes(t *testing.T) {
	recorder, closeRecorder := testRecorder(t, RecorderOptions{})
	defer closeRecorder()
	policy := AppliedPolicy{Type: PolicyTypeTLSA, Domain: "example.test", Strings: []string{"3 1 1 AB01"}, MX: []string{"mx.example.test"}}
	for index, result := range []string{ResultTLSAInvalid, ResultDNSSECInvalid, ResultDANERequired} {
		event := baseEvent(fmt.Sprintf("dane-%d", index), false)
		event.Policy, event.ResultType = policy, result
		if err := recorder.Record(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	aggregates, err := recorder.Aggregates(t.Context(), "2026-08-18", "example.test")
	if err != nil || len(aggregates) != 1 || aggregates[0].Policy.Type != PolicyTypeTLSA || aggregates[0].FailedSessions != 3 {
		t.Fatalf("Aggregates() = %#v, %v", aggregates, err)
	}
	results := make(map[string]bool)
	for _, failure := range aggregates[0].Failures {
		results[failure.ResultType] = true
	}
	if !results[ResultTLSAInvalid] || !results[ResultDNSSECInvalid] || !results[ResultDANERequired] {
		t.Fatalf("DANE result types were rewritten: %#v", aggregates[0].Failures)
	}
}
