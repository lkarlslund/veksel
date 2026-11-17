package health

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Evaluator serializes refresh/snapshot/reconcile so an alert evaluation sees
// one coherent health generation. Scheduling remains process-owned.
type Evaluator struct {
	mu       sync.Mutex
	registry *Registry
	alerts   *AlertStore
	refresh  func(context.Context)
	now      func() time.Time
}

func NewEvaluator(registry *Registry, alerts *AlertStore, refresh func(context.Context)) (*Evaluator, error) {
	if registry == nil || alerts == nil {
		return nil, errors.New("health registry and alert store are required")
	}
	return &Evaluator{registry: registry, alerts: alerts, refresh: refresh, now: time.Now}, nil
}

func (e *Evaluator) Evaluate(ctx context.Context) ([]Transition, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.refresh != nil {
		e.refresh(ctx)
	}
	return e.alerts.Evaluate(ctx, e.registry.Snapshot(e.now()))
}
