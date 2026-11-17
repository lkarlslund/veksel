package contentscan

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestEngineStatusJSONDistinguishesUnobservedFromObserved(t *testing.T) {
	observed := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	for name, status := range map[string]EngineStatus{
		"unobserved": {},
		"observed":   {LastObservedAt: observed},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			var projection map[string]json.RawMessage
			if err := json.Unmarshal(data, &projection); err != nil {
				t.Fatal(err)
			}
			_, present := projection["last_observed_at"]
			if want := !status.LastObservedAt.IsZero(); present != want {
				t.Fatalf("last_observed_at present = %t, want %t; JSON = %s", present, want, data)
			}
		})
	}
}

type scannerFunc struct {
	name string
	scan func(context.Context, Message) (Result, error)
}

type observerFunc func(Report)

func (f observerFunc) ObserveContentScan(report Report) { f(report) }

func TestPipelineObserverReceivesOneFinalNormalizedReport(t *testing.T) {
	var observed []Report
	pipeline, err := NewObserved(observerFunc(func(report Report) {
		observed = append(observed, report)
	}), Engine{
		Scanner: scannerFunc{name: "  BASELINE  ", scan: func(context.Context, Message) (Result, error) {
			return Result{Verdict: VerdictClean}, nil
		}},
		Timeout: time.Second, MaxInputBytes: 1024, FailurePolicy: FailurePolicyOpen,
	})
	if err != nil {
		t.Fatal(err)
	}
	report := pipeline.Scan(t.Context(), Message{Content: []byte("message")})
	if len(observed) != 1 {
		t.Fatalf("observer calls = %d, want 1", len(observed))
	}
	if observed[0].Decision != report.Decision || observed[0].Duration <= 0 || len(observed[0].Results) != 1 {
		t.Fatalf("observed report = %+v, returned report = %+v", observed[0], report)
	}
	if result := observed[0].Results[0]; result.Engine != "baseline" || result.Verdict != VerdictClean || result.Duration <= 0 {
		t.Fatalf("observed result = %+v", result)
	}
}

func (s scannerFunc) Name() string { return s.name }

func (s scannerFunc) Scan(ctx context.Context, message Message) (Result, error) {
	return s.scan(ctx, message)
}

func TestPipelineProducesBoundedStableEvidenceWithoutCopyingContent(t *testing.T) {
	content := []byte("message")
	scanner := scannerFunc{name: "baseline", scan: func(_ context.Context, message Message) (Result, error) {
		if &message.Content[0] != &content[0] {
			t.Fatal("pipeline copied message content")
		}
		message.Headers["Subject"] = "mutated"
		symbols := make([]Symbol, maxSymbols+10)
		for index := range symbols {
			symbols[index] = Symbol{Name: strings.Repeat("x", maxSymbolNameBytes+10), Score: math.Inf(1), Description: "unsafe\r\nevidence"}
		}
		return Result{Verdict: VerdictSpam, Score: math.NaN(), Symbols: symbols}, nil
	}}
	pipeline, err := New(Engine{Scanner: scanner, Timeout: time.Second, MaxInputBytes: 1024, FailurePolicy: FailurePolicyOpen})
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Subject": "original"}
	report := pipeline.Scan(t.Context(), Message{Content: content, Headers: headers})
	if report.Decision != DecisionAllow || len(report.Results) != 1 {
		t.Fatalf("report = %+v", report)
	}
	result := report.Results[0]
	if result.Engine != "baseline" || result.Verdict != VerdictSpam || result.Score != 0 || len(result.Symbols) != maxSymbols || len(result.Symbols[0].Name) != maxSymbolNameBytes || strings.ContainsAny(result.Symbols[0].Description, "\r\n") {
		t.Fatalf("normalized result = %+v", result)
	}
	if headers["Subject"] != "original" {
		t.Fatal("scanner mutated caller headers")
	}
}

func TestPipelineAppliesTimeoutOversizeAndFailurePolicies(t *testing.T) {
	var oversizeCalled bool
	timeout := scannerFunc{name: "timeout", scan: func(ctx context.Context, _ Message) (Result, error) {
		<-ctx.Done()
		// A buggy adapter cannot evade the pipeline deadline by returning a
		// nominal clean result after cancellation.
		return Result{Verdict: VerdictClean}, nil
	}}
	oversize := scannerFunc{name: "oversize", scan: func(context.Context, Message) (Result, error) {
		oversizeCalled = true
		return Result{Verdict: VerdictClean}, nil
	}}
	broken := scannerFunc{name: "broken", scan: func(context.Context, Message) (Result, error) {
		return Result{}, errors.New("backend\r\nunavailable")
	}}
	pipeline, err := New(
		Engine{Scanner: timeout, Timeout: time.Millisecond, MaxInputBytes: 100, FailurePolicy: FailurePolicyOpen},
		Engine{Scanner: oversize, Timeout: time.Second, MaxInputBytes: 2, FailurePolicy: FailurePolicyQuarantine},
		Engine{Scanner: broken, Timeout: time.Second, MaxInputBytes: 100, FailurePolicy: FailurePolicyDefer},
	)
	if err != nil {
		t.Fatal(err)
	}
	report := pipeline.Scan(t.Context(), Message{Content: []byte("message")})
	if report.Decision != DecisionDefer || oversizeCalled || len(report.Results) != 3 {
		t.Fatalf("report = %+v, oversize called = %t", report, oversizeCalled)
	}
	if report.Results[0].ErrorCode != "timeout" || report.Results[1].ErrorCode != "input_too_large" || report.Results[2].ErrorCode != "scanner_error" || strings.ContainsAny(report.Results[2].Error, "\r\n") {
		t.Fatalf("failure evidence = %+v", report.Results)
	}
}

func TestPipelineMalwareRequestsQuarantineAndRetainsAllResults(t *testing.T) {
	clean := scannerFunc{name: "clean", scan: func(context.Context, Message) (Result, error) {
		return Result{Verdict: VerdictClean}, nil
	}}
	malware := scannerFunc{name: "malware", scan: func(context.Context, Message) (Result, error) {
		return Result{Verdict: VerdictMalware, MalwareNames: []string{"EICAR"}}, nil
	}}
	pipeline, err := New(
		Engine{Scanner: clean, Timeout: time.Second, MaxInputBytes: 100, FailurePolicy: FailurePolicyOpen},
		Engine{Scanner: malware, Timeout: time.Second, MaxInputBytes: 100, FailurePolicy: FailurePolicyOpen},
	)
	if err != nil {
		t.Fatal(err)
	}
	report := pipeline.Scan(t.Context(), Message{Content: []byte("message")})
	if report.Decision != DecisionQuarantine || len(report.Results) != 2 || report.Results[1].MalwareNames[0] != "EICAR" {
		t.Fatalf("report = %+v", report)
	}
	status := pipeline.Status()
	if len(status) != 2 || status[0].Scans != 1 || status[0].Errors != 0 || status[0].LastVerdict != VerdictClean || status[1].LastVerdict != VerdictMalware || status[1].LastObservedAt.IsZero() {
		t.Fatalf("status = %+v", status)
	}
}

func TestNewRejectsUnsafeOrAmbiguousEngineConfiguration(t *testing.T) {
	valid := scannerFunc{name: "valid", scan: func(context.Context, Message) (Result, error) { return Result{Verdict: VerdictClean}, nil }}
	invalidName := scannerFunc{name: "bad name", scan: valid.scan}
	for name, engines := range map[string][]Engine{
		"empty":       nil,
		"nil scanner": {{Timeout: time.Second, MaxInputBytes: 1}},
		"name":        {{Scanner: invalidName, Timeout: time.Second, MaxInputBytes: 1}},
		"timeout":     {{Scanner: valid, MaxInputBytes: 1}},
		"input":       {{Scanner: valid, Timeout: time.Second}},
		"policy":      {{Scanner: valid, Timeout: time.Second, MaxInputBytes: 1, FailurePolicy: FailurePolicy(255)}},
		"duplicate": {
			{Scanner: valid, Timeout: time.Second, MaxInputBytes: 1},
			{Scanner: valid, Timeout: time.Second, MaxInputBytes: 1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(engines...); err == nil {
				t.Fatal("invalid engine configuration was accepted")
			}
		})
	}
}
