package metrics

import (
	"sync"
	"sync/atomic"
)

// ConnectionGauge is a shared, concurrency-safe active-session counter. One
// instance may be shared by cleartext, STARTTLS, implicit-TLS, and submission
// listeners so the exported gauge remains a protocol aggregate.
type ConnectionGauge struct {
	metrics *Metrics
	name    string
	active  atomic.Int64
}

// NewConnectionGauge starts one protocol lifecycle at zero. Publishing the
// zero prevents a persisted pre-restart value from looking live.
func NewConnectionGauge(metrics *Metrics, name string) *ConnectionGauge {
	gauge := &ConnectionGauge{metrics: metrics, name: name}
	gauge.publish(0)
	return gauge
}

// Open admits one connection and returns an idempotent release function.
func (g *ConnectionGauge) Open() func() {
	if g == nil {
		return func() {}
	}
	g.publish(g.active.Add(1))
	var once sync.Once
	return func() {
		once.Do(func() { g.publish(g.active.Add(-1)) })
	}
}

// Active returns the exact in-process count.
func (g *ConnectionGauge) Active() int64 {
	if g == nil {
		return 0
	}
	return g.active.Load()
}

func (g *ConnectionGauge) publish(value int64) {
	if g != nil && g.metrics != nil && g.name != "" {
		g.metrics.SetGaugeCoalesced(g.name, float64(value))
	}
}
