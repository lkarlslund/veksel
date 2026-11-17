package contentscan

import (
	"context"
	"errors"
	"testing"
	"time"
)

func switchPipeline(t *testing.T, name string, scan func(context.Context, Message) (Result, error)) *Pipeline {
	t.Helper()
	pipeline, err := New(Engine{Scanner: scannerFunc{name: name, scan: scan}, Timeout: time.Second, MaxInputBytes: 1024, FailurePolicy: FailurePolicyOpen})
	if err != nil {
		t.Fatal(err)
	}
	return pipeline
}

type trainerFunc func(context.Context, []byte, bool) error

func (f trainerFunc) Learn(ctx context.Context, message []byte, spam bool) error {
	return f(ctx, message, spam)
}

func TestSwitchAppliesNewPipelineToNextScan(t *testing.T) {
	var scanners Switch
	if report := scanners.Scan(t.Context(), Message{}); len(report.Results) != 0 || scanners.Status() != nil {
		t.Fatalf("empty switch scanned: %+v", report)
	}
	if err := scanners.Learn(t.Context(), nil, true); !errors.Is(err, ErrNoTrainer) || scanners.TrainingAvailable() {
		t.Fatalf("empty switch trained: %v", err)
	}

	started, release := make(chan struct{}), make(chan struct{})
	scanners.Set(switchPipeline(t, "old", func(context.Context, Message) (Result, error) {
		close(started)
		<-release
		return Result{Verdict: VerdictClean}, nil
	}), nil)
	inFlight := make(chan Report)
	go func() { inFlight <- scanners.Scan(context.Background(), Message{Content: []byte("x")}) }()
	<-started

	learned := false
	scanners.Set(switchPipeline(t, "new", func(context.Context, Message) (Result, error) {
		return Result{Verdict: VerdictMalware, MalwareNames: []string{"EICAR"}}, nil
	}), trainerFunc(func(context.Context, []byte, bool) error { learned = true; return nil }))
	next := scanners.Scan(t.Context(), Message{Content: []byte("x")})
	if len(next.Results) != 1 || next.Results[0].Engine != "new" || next.Results[0].Verdict != VerdictMalware {
		t.Fatalf("next scan = %+v, want the new pipeline", next)
	}
	close(release)
	if previous := <-inFlight; len(previous.Results) != 1 || previous.Results[0].Engine != "old" {
		t.Fatalf("in-flight scan = %+v, want the old pipeline", previous)
	}
	if err := scanners.Learn(t.Context(), []byte("x"), true); err != nil || !learned || !scanners.TrainingAvailable() {
		t.Fatalf("training after swap: %v, learned=%t", err, learned)
	}
	if status := scanners.Status(); len(status) != 1 || status[0].Name != "new" {
		t.Fatalf("status = %+v", status)
	}
}
