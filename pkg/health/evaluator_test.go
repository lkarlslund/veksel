package health

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestEvaluatorRefreshesBeforeReconciling(t *testing.T) {
	alerts, _ := testAlertStore(t)
	registry := New()
	var refreshes atomic.Int64
	evaluator, err := NewEvaluator(registry, alerts, func(context.Context) {
		refreshes.Add(1)
		if replaceErr := registry.Replace(time.Now(), []Observation{{ID: "store", Label: "Store", Kind: "dependency", Desired: true, Required: true, State: StateUnavailable}}); replaceErr != nil {
			t.Errorf("replace: %v", replaceErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	transitions, err := evaluator.Evaluate(t.Context())
	if err != nil || refreshes.Load() != 1 || len(transitions) != 1 || transitions[0].Type != TransitionOpened {
		t.Fatalf("refreshes=%d transitions=%#v err=%v", refreshes.Load(), transitions, err)
	}
}
