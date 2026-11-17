// Package metrics provides an embedded time-series store for Veksel.
//
// It uses the existing KV store backend with a "metrics" namespace.
// Supports counters (monotonically increasing), gauges (point-in-time values),
// and histograms (latency buckets).
package metrics

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/store"
)

var logger = log.For(log.ModuleMetrics)

const (
	// NS is the store namespace used for metrics data.
	NS = "metrics"

	// Default retention period for metric samples.
	DefaultRetention = 7 * 24 * time.Hour

	// Prune interval for old samples.
	pruneInterval = time.Hour
	// Unchanged gauges are step values, so persisting every observation adds no
	// information. A heartbeat keeps long-running series visible to bounded
	// time-window queries without storing a sample per observation.
	gaugeHeartbeat = 5 * time.Minute
	// gaugeCoalesceInterval bounds how often SetGaugeCoalesced persists a
	// rapidly changing gauge, so a connection burst stores a handful of
	// samples rather than one per open and close. The background loop
	// persists a burst's final value within gaugePendingFlush.
	gaugeCoalesceInterval = time.Second
	gaugePendingFlush     = 5 * time.Second
)

// Metric type identifiers.
const (
	TypeCounter   = "counter"
	TypeGauge     = "gauge"
	TypeHistogram = "histogram"
)

// Sample is a single time-series data point.
type Sample struct {
	Timestamp time.Time         `json:"ts"`
	Value     float64           `json:"value"`
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// HistogramBuckets are the default bucket boundaries for latency histograms.
var HistogramBuckets = []float64{
	0.001, // 1ms
	0.005, // 5ms
	0.01,  // 10ms
	0.025, // 25ms
	0.05,  // 50ms
	0.1,   // 100ms
	0.25,  // 250ms
	0.5,   // 500ms
	1.0,   // 1s
	2.5,   // 2.5s
	5.0,   // 5s
	10.0,  // 10s
}

// Metrics provides thread-safe metric recording and querying.
type Metrics struct {
	store store.Store
	mu    sync.RWMutex

	// In-memory counters for efficient incrementing.
	// Key: metricKey(name, labels), Value: current count
	counters map[string]*counterState

	// In-memory histogram accumulators.
	histograms map[string]*histogramState
	gauges     map[string]gaugeState

	retention time.Duration
	// seq keeps sample keys sharing a clock reading distinct.
	seq atomic.Uint32

	// writeCtx marks every metric write unsynced: metrics are not durable
	// data, and each synced write costs a WAL fsync.
	writeCtx  context.Context
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

type gaugeState struct {
	value       float64
	persistedAt time.Time
	loaded      bool
	// pending marks a coalesced value newer than the persisted one.
	pending bool
}

// counterState tracks a single counter's in-memory value and pending flush.
type counterState struct {
	name   string
	labels map[string]string
	value  float64
}

// histogramState tracks histogram observations in memory.
type histogramState struct {
	name    string
	labels  map[string]string
	buckets []float64
	counts  []uint64 // cumulative counts per bucket
	sum     float64
	count   uint64
}

// New creates a new Metrics instance backed by the given store.
// It ensures the metrics namespace exists and starts a background
// goroutine for periodic flushing and pruning.
func New(s store.Store) *Metrics {
	m := &Metrics{
		store:      s,
		counters:   make(map[string]*counterState),
		histograms: make(map[string]*histogramState),
		gauges:     make(map[string]gaugeState),
		retention:  DefaultRetention,
		writeCtx:   store.WithoutSync(context.Background()),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}

	// Ensure the metrics namespace exists.
	if err := s.CreateNamespace(context.Background(), NS); err != nil && err != store.ErrExists {
		logger.Warn("metrics: create namespace", "error", err)
	}
	if err := m.migrateLegacy(); err != nil {
		logger.Warn("metrics: migrate stored series", "error", err)
	}

	// Start background flush/prune loop.
	go m.run()
	return m
}

// run handles periodic flushing of in-memory metrics to the store
// and pruning of old samples until Close.
func (m *Metrics) run() {
	defer close(m.done)
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	gauges := time.NewTicker(gaugePendingFlush)
	defer gauges.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-gauges.C:
			m.mu.Lock()
			m.persistPendingGaugesLocked()
			m.mu.Unlock()
		case <-ticker.C:
			m.flush()
			m.prune()
		}
	}
}

// Close stops the background loop and flushes in-memory counters and
// histograms. Call it before closing the store; it is safe to call twice.
func (m *Metrics) Close() {
	m.closeOnce.Do(func() {
		close(m.stop)
		<-m.done
		m.flush()
	})
}

// Flush writes in-memory counters and histograms to the store.
// It is exported for testing purposes.
func (m *Metrics) Flush() {
	m.flush()
}

// flush writes in-memory counters and histograms to the store in one
// unsynced batch.
func (m *Metrics) flush() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.persistPendingGaugesLocked()
	if len(m.counters) == 0 && len(m.histograms) == 0 {
		return
	}
	if err := store.Batch(m.writeCtx, m.store, m.flushLocked); err != nil {
		logger.Error("metrics: flush", "error", err)
	}
	// Clear in-memory accumulators after flush
	m.counters = make(map[string]*counterState)
	m.histograms = make(map[string]*histogramState)
}

// flushLocked writes in-memory counters and histograms using ctx. Per-sample
// failures are logged so one bad series does not discard the others.
func (m *Metrics) flushLocked(ctx context.Context) error {
	now := time.Now().UTC()

	for key, cs := range m.counters {
		sample := Sample{
			Timestamp: now,
			Value:     cs.value,
			Type:      TypeCounter,
			Name:      cs.name,
			Labels:    cs.labels,
		}
		if err := m.storeSample(ctx, key, sample); err != nil {
			logger.Error("metrics: flush counter", "name", cs.name, "error", err)
		}
	}

	for _, hs := range m.histograms {
		// Store one sample per bucket boundary
		for i, boundary := range hs.buckets {
			sample := Sample{
				Timestamp: now,
				Value:     float64(hs.counts[i]),
				Type:      TypeHistogram,
				Name:      fmt.Sprintf("%s_bucket", hs.name),
				Labels:    mergeLabels(hs.labels, map[string]string{"le": fmt.Sprintf("%.4f", boundary)}),
			}
			if err := m.storeSample(ctx, metricKeyForSample(hs.name, sample.Labels), sample); err != nil {
				logger.Error("metrics: flush histogram bucket", "name", hs.name, "error", err)
			}
		}
		// Also store sum and count
		for _, field := range []string{"sum", "count"} {
			var val float64
			if field == "sum" {
				val = hs.sum
			} else {
				val = float64(hs.count)
			}
			sample := Sample{
				Timestamp: now,
				Value:     val,
				Type:      TypeHistogram,
				Name:      fmt.Sprintf("%s_%s", hs.name, field),
				Labels:    hs.labels,
			}
			if err := m.storeSample(ctx, metricKeyForSample(sample.Name, sample.Labels), sample); err != nil {
				logger.Error("metrics: flush histogram field", "name", hs.name, "field", field, "error", err)
			}
		}
	}
	return nil
}

// prune removes samples older than the retention period in one unsynced batch.
func (m *Metrics) prune() {
	if err := store.Batch(m.writeCtx, m.store, m.pruneBatch); err != nil {
		logger.Error("metrics: prune", "error", err)
	}
}

func (m *Metrics) pruneBatch(ctx context.Context) error {
	keys, err := m.store.List(ctx, NS)
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	// A bucket expires once its whole window is older than the cutoff;
	// reads filter the remainder of the boundary bucket by timestamp.
	cutoff := time.Now().UTC().Add(-m.retention).Unix()
	width := int64(bucketWidth / time.Second)
	for _, key := range keys {
		if _, bucket, ok := parseSampleKey(key); !ok || bucket+width > cutoff {
			continue
		}
		if err := m.store.Delete(ctx, NS, key); err != nil {
			logger.Error("metrics: prune delete", "key", key, "error", err)
		}
	}
	return nil
}

// IncrementCounter increments a counter by 1.
func (m *Metrics) IncrementCounter(name string, labels map[string]string) {
	m.IncrementCounterBy(name, 1.0, labels)
}

// IncrementCounterBy increments a counter by the given amount.
func (m *Metrics) IncrementCounterBy(name string, amount float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := metricKey(name, labels)
	cs, ok := m.counters[key]
	if !ok {
		cs = &counterState{
			name:   name,
			labels: labels,
		}
		m.counters[key] = cs
	}
	cs.value += amount
}

// SetGauge sets a gauge to the given value.
func (m *Metrics) SetGauge(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := metricKey(name, labels)
	now := time.Now().UTC()
	state := m.loadGaugeLocked(key)
	if !state.pending && !state.persistedAt.IsZero() && state.value == value && now.Sub(state.persistedAt) < gaugeHeartbeat {
		m.gauges[key] = state
		return
	}
	m.persistGaugeLocked(key, name, labels, value, now, state)
}

// SetGaugeCoalesced records an unlabeled gauge like SetGauge, but persists
// it at most once per gaugeCoalesceInterval; the newest value of a burst is
// persisted by the next call after the interval or by the background loop.
// CurrentGauge sees every value at once. It suits gauges that change on
// every request, such as active connections.
func (m *Metrics) SetGaugeCoalesced(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := metricKey(name, nil)
	now := time.Now().UTC()
	state := m.loadGaugeLocked(key)
	if wait := gaugeCoalesceInterval - now.Sub(state.persistedAt); !state.persistedAt.IsZero() && wait > 0 {
		if !state.pending && state.value == value {
			return
		}
		state.value, state.pending = value, true
		m.gauges[key] = state
		return
	}
	m.persistGaugeLocked(key, name, nil, value, now, state)
}

// persistPendingGaugesLocked persists the newest value of every coalesced
// gauge not yet persisted.
func (m *Metrics) persistPendingGaugesLocked() {
	now := time.Now().UTC()
	for key, state := range m.gauges {
		// Only unlabeled SetGaugeCoalesced gauges pend; their key is the name.
		if state.pending {
			m.persistGaugeLocked(key, key, nil, state.value, now, state)
		}
	}
}

// loadGaugeLocked returns the gauge's state, reading its newest persisted
// sample the first time.
func (m *Metrics) loadGaugeLocked(key string) gaugeState {
	state := m.gauges[key]
	if !state.loaded {
		if latest, ok := m.latestSample(key); ok {
			state.value = latest.Value
			state.persistedAt = latest.Timestamp
		}
		state.loaded = true
	}
	return state
}

func (m *Metrics) persistGaugeLocked(key, name string, labels map[string]string, value float64, now time.Time, state gaugeState) {
	sample := Sample{
		Timestamp: now,
		Value:     value,
		Type:      TypeGauge,
		Name:      name,
		Labels:    labels,
	}
	if err := m.storeSample(m.writeCtx, key, sample); err != nil {
		logger.Error("metrics: set gauge", "name", name, "error", err)
		return
	}
	state.value = value
	state.persistedAt = now
	state.pending = false
	m.gauges[key] = state
}

// CurrentGauge returns the newest exact unlabeled gauge value. In-memory state
// wins; otherwise the newest persisted value is loaded for restart-safe readers.
func (m *Metrics) CurrentGauge(name string) (float64, time.Time, bool) {
	if m == nil {
		return 0, time.Time{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := metricKey(name, nil)
	state, exists := m.gauges[key]
	if !exists || !state.loaded {
		latest, ok := m.latestSample(key)
		if !ok {
			return 0, time.Time{}, false
		}
		state = gaugeState{value: latest.Value, persistedAt: latest.Timestamp, loaded: true}
		m.gauges[key] = state
	}
	return state.value, state.persistedAt, true
}

// ObserveHistogram records an observation in a histogram.
func (m *Metrics) ObserveHistogram(name string, value float64, labels map[string]string) {
	m.ObserveHistogramWithBuckets(name, value, labels, HistogramBuckets)
}

// ObserveHistogramWithBuckets records an observation with custom bucket boundaries.
func (m *Metrics) ObserveHistogramWithBuckets(name string, value float64, labels map[string]string, buckets []float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := metricKey(name, labels)
	hs, ok := m.histograms[key]
	if !ok {
		hs = &histogramState{
			name:    name,
			labels:  labels,
			buckets: buckets,
			counts:  make([]uint64, len(buckets)),
		}
		m.histograms[key] = hs
	}

	// Find the bucket this value falls into
	for i, b := range hs.buckets {
		if value <= b {
			hs.counts[i]++
			break
		}
	}
	// If value exceeds all buckets, increment the last bucket
	if value > hs.buckets[len(hs.buckets)-1] {
		hs.counts[len(hs.counts)-1]++
	}

	hs.sum += value
	hs.count++
}

// Query returns time series data for a metric name within the given time window.
func (m *Metrics) Query(name string, since time.Duration) []Sample {
	cutoff := time.Now().UTC().Add(-since)

	// Try the unlabeled series first, visiting only the window's buckets.
	if samples, err := m.samplesSince(metricKey(name, nil), cutoff); err == nil && len(samples) > 0 {
		return samples
	}

	// Otherwise collect every series whose key starts with the metric name.
	var results []Sample
	err := m.iterateSamples(name, bucketStart(cutoff), func(_ string, sample Sample) {
		if sample.Name == name && !sample.Timestamp.Before(cutoff) {
			results = append(results, sample)
		}
	})
	if err != nil {
		return nil
	}
	sortByTime(results)
	return results
}

// GetAllSamples returns all stored metric samples across all metric names.
func (m *Metrics) GetAllSamples() []Sample {
	results, err := m.allSamples()
	if err != nil {
		return nil
	}
	sortByTime(results)
	return results
}

// allSamples returns every stored sample, ordered by series and then time.
func (m *Metrics) allSamples() ([]Sample, error) {
	var results []Sample
	err := m.iterateSamples("", 0, func(_ string, sample Sample) {
		results = append(results, sample)
	})
	return results, err
}

// GetCounters returns all current counter values (from memory + store).
func (m *Metrics) GetCounters() map[string]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]float64)
	for key, cs := range m.counters {
		result[key] = cs.value
	}

	// Also load from store; samples arrive in time order per series, so
	// the latest value for each series wins.
	_ = m.iterateSamples("", 0, func(series string, sample Sample) {
		if sample.Type == TypeCounter {
			result[series] = sample.Value
		}
	})
	return result
}

// metricKey creates a store key from a metric name and labels.
func metricKey(name string, labels map[string]string) string {
	return metricKeyForSample(name, labels)
}

// metricKeyForSample creates a store key, handling special label keys.
func metricKeyForSample(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	// Build a deterministic label string
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	slices.Sort(parts)
	return name + "{" + strings.Join(parts, ",") + "}"
}

// mergeLabels merges two label maps.
func mergeLabels(base, extra map[string]string) map[string]string {
	m := make(map[string]string)
	for k, v := range base {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func sortByTime(samples []Sample) {
	slices.SortStableFunc(samples, func(a, b Sample) int {
		return a.Timestamp.Compare(b.Timestamp)
	})
}
