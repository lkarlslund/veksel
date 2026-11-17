package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func testMetrics(t *testing.T) *Metrics {
	t.Helper()
	dir := t.TempDir()
	s, err := jsonstore.New(dir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	m := New(s)
	t.Cleanup(m.Close)
	return m
}

func TestIncrementCounter(t *testing.T) {
	m := testMetrics(t)

	m.IncrementCounter("requests_total", nil)
	m.IncrementCounter("requests_total", nil)
	m.IncrementCounter("requests_total", nil)

	// Check in-memory value
	m.mu.RLock()
	key := metricKey("requests_total", nil)
	cs, ok := m.counters[key]
	m.mu.RUnlock()

	if !ok {
		t.Fatal("counter not found in memory")
	}
	if cs.value != 3 {
		t.Errorf("counter value = %f, want 3", cs.value)
	}
}

func TestIncrementCounterBy(t *testing.T) {
	m := testMetrics(t)

	m.IncrementCounterBy("bytes_total", 100, nil)
	m.IncrementCounterBy("bytes_total", 200, nil)
	m.IncrementCounterBy("bytes_total", 50, nil)

	m.mu.RLock()
	cs := m.counters["bytes_total"]
	m.mu.RUnlock()

	if cs == nil {
		t.Fatal("counter not found")
	}
	if cs.value != 350 {
		t.Errorf("counter value = %f, want 350", cs.value)
	}
}

func TestIncrementCounterWithLabels(t *testing.T) {
	m := testMetrics(t)

	m.IncrementCounter("http_requests", map[string]string{"method": "GET"})
	m.IncrementCounter("http_requests", map[string]string{"method": "POST"})
	m.IncrementCounter("http_requests", map[string]string{"method": "GET"})

	m.mu.RLock()
	getKey := metricKey("http_requests", map[string]string{"method": "GET"})
	postKey := metricKey("http_requests", map[string]string{"method": "POST"})
	getVal := m.counters[getKey].value
	postVal := m.counters[postKey].value
	m.mu.RUnlock()

	if getVal != 2 {
		t.Errorf("GET counter = %f, want 2", getVal)
	}
	if postVal != 1 {
		t.Errorf("POST counter = %f, want 1", postVal)
	}
}

func TestSetGauge(t *testing.T) {
	m := testMetrics(t)

	m.SetGauge("active_connections", 5, nil)
	m.SetGauge("active_connections", 5, nil)
	m.SetGauge("active_connections", 3, nil)
	m.SetGauge("active_connections", 7, nil)

	// Gauge samples are stored directly
	samples, err := m.loadSamples("active_connections")
	if err != nil {
		t.Fatalf("load gauge: %v", err)
	}

	if len(samples) != 3 {
		t.Fatalf("expected unchanged gauge to be coalesced into 3 transition samples, got %d", len(samples))
	}

	// Last sample should be 7
	if samples[len(samples)-1].Value != 7 {
		t.Errorf("last gauge value = %f, want 7", samples[len(samples)-1].Value)
	}
	if samples[len(samples)-1].Type != TypeGauge {
		t.Errorf("sample type = %q, want %q", samples[len(samples)-1].Type, TypeGauge)
	}
}

func TestSetGaugePersistsHeartbeatForUnchangedValue(t *testing.T) {
	m := testMetrics(t)
	m.SetGauge("queue_depth", 0, nil)
	key := metricKey("queue_depth", nil)

	m.mu.Lock()
	state := m.gauges[key]
	state.persistedAt = state.persistedAt.Add(-gaugeHeartbeat)
	m.gauges[key] = state
	m.mu.Unlock()
	m.SetGauge("queue_depth", 0, nil)

	samples, err := m.loadSamples(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("heartbeat samples = %d, want 2", len(samples))
	}
}

func TestSetGaugeReloadCoalescesRecentUnchangedValue(t *testing.T) {
	m := testMetrics(t)
	m.SetGauge("queue_depth", 0, nil)

	reloaded := New(m.store)
	reloaded.SetGauge("queue_depth", 0, nil)
	samples, err := m.loadSamples(metricKey("queue_depth", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("reloaded unchanged gauge samples = %d, want 1", len(samples))
	}
}

func TestObserveHistogram(t *testing.T) {
	m := testMetrics(t)

	m.ObserveHistogram("request_duration", 0.005, nil) // 5ms
	m.ObserveHistogram("request_duration", 0.1, nil)   // 100ms
	m.ObserveHistogram("request_duration", 2.0, nil)   // 2s

	m.mu.RLock()
	hs := m.histograms["request_duration"]
	m.mu.RUnlock()

	if hs == nil {
		t.Fatal("histogram not found")
	}
	if hs.count != 3 {
		t.Errorf("histogram count = %d, want 3", hs.count)
	}
	expectedSum := 0.005 + 0.1 + 2.0
	if hs.sum != expectedSum {
		t.Errorf("histogram sum = %f, want %f", hs.sum, expectedSum)
	}
}

func TestObserveHistogramBuckets(t *testing.T) {
	m := testMetrics(t)

	// Use simple buckets for testing
	m.ObserveHistogramWithBuckets("latency", 0.001, nil, []float64{0.001, 0.01, 0.1})
	m.ObserveHistogramWithBuckets("latency", 0.005, nil, []float64{0.001, 0.01, 0.1})
	m.ObserveHistogramWithBuckets("latency", 0.05, nil, []float64{0.001, 0.01, 0.1})
	m.ObserveHistogramWithBuckets("latency", 0.5, nil, []float64{0.001, 0.01, 0.1})

	m.mu.RLock()
	hs := m.histograms["latency"]
	m.mu.RUnlock()

	// Each observation increments exactly one bucket (the first one it fits in)
	// Bucket 0 (<=0.001): 1 observation (0.001)
	if hs.counts[0] != 1 {
		t.Errorf("bucket[0] = %d, want 1", hs.counts[0])
	}
	// Bucket 1 (<=0.01): 1 observation (0.005)
	if hs.counts[1] != 1 {
		t.Errorf("bucket[1] = %d, want 1", hs.counts[1])
	}
	// Bucket 2 (<=0.1, overflow): 2 observations (0.05 fits, 0.5 overflows to last)
	if hs.counts[2] != 2 {
		t.Errorf("bucket[2] = %d, want 2", hs.counts[2])
	}
}

func TestQueryReturnsSamples(t *testing.T) {
	m := testMetrics(t)

	// Flush counters to store
	m.IncrementCounter("test_counter", nil)
	m.Flush()

	// Query should return the flushed sample
	samples := m.Query("test_counter", 24*time.Hour)
	if len(samples) == 0 {
		t.Fatal("expected samples from query, got none")
	}
	if samples[0].Name != "test_counter" {
		t.Errorf("sample name = %q, want %q", samples[0].Name, "test_counter")
	}
	if samples[0].Value != 1 {
		t.Errorf("sample value = %f, want 1", samples[0].Value)
	}
}

func TestQueryTimeFilter(t *testing.T) {
	m := testMetrics(t)

	// Set a gauge and flush
	m.SetGauge("test_gauge", 42, nil)

	// Query with a very short window should return nothing
	samples := m.Query("test_gauge", 0)
	if len(samples) != 0 {
		t.Errorf("expected no samples with 0 duration, got %d", len(samples))
	}

	// Query with a long window should return the sample
	samples = m.Query("test_gauge", 24*time.Hour)
	if len(samples) != 1 {
		t.Errorf("expected 1 sample, got %d", len(samples))
	}
}

func TestGetCounters(t *testing.T) {
	m := testMetrics(t)

	m.IncrementCounter("counter_a", nil)
	m.IncrementCounter("counter_b", nil)
	m.IncrementCounter("counter_b", nil)

	// Flush to store
	m.Flush()
	counters := m.GetCounters()

	// counter_a should be 1
	if v, ok := counters["counter_a"]; !ok || v != 1 {
		t.Errorf("counter_a = %v, want 1", v)
	}
	// counter_b should be 2
	if v, ok := counters["counter_b"]; !ok || v != 2 {
		t.Errorf("counter_b = %v, want 2", v)
	}
}

func TestMetricKey(t *testing.T) {
	// No labels
	key := metricKey("requests", nil)
	if key != "requests" {
		t.Errorf("key = %q, want %q", key, "requests")
	}

	// With labels
	key = metricKey("requests", map[string]string{"method": "GET"})
	if key != "requests{method=GET}" {
		t.Errorf("key = %q, want %q", key, "requests{method=GET}")
	}

	// Multiple labels (sorted)
	key = metricKey("requests", map[string]string{"method": "GET", "status": "200"})
	if !strings.Contains(key, "method=GET") || !strings.Contains(key, "status=200") {
		t.Errorf("key = %q, expected to contain method=GET and status=200", key)
	}
}

func TestFlushAndReload(t *testing.T) {
	m := testMetrics(t)

	// Record some metrics
	m.IncrementCounter("page_views", nil)
	m.IncrementCounter("page_views", nil)
	m.SetGauge("cpu_usage", 75.5, nil)

	// Flush to store
	m.Flush()

	// Create a new metrics instance pointing to the same store
	m2 := New(m.store)
	defer m2.Flush()

	// Query should still find the data
	samples := m2.Query("page_views", 24*time.Hour)
	if len(samples) == 0 {
		t.Fatal("expected page_views samples after reload, got none")
	}
	if samples[0].Value != 2 {
		t.Errorf("page_views value = %f, want 2", samples[0].Value)
	}
}

func TestPruneOldSamples(t *testing.T) {
	m := testMetrics(t)

	// Set a very short retention for testing
	m.retention = -time.Hour // negative to ensure everything is pruned

	// Record and flush
	m.SetGauge("temp", 1, nil)
	m.Flush()

	// Prune should remove everything
	m.prune()

	samples := m.Query("temp", 24*time.Hour)
	if len(samples) != 0 {
		t.Errorf("expected no samples after prune, got %d", len(samples))
	}
}

// syncRecordingStore records batch commits and whether each Set was marked
// unsynced.
type syncRecordingStore struct {
	store.Store
	batches      int
	syncedWrites int
	writes       int
}

func (s *syncRecordingStore) Set(ctx context.Context, namespace, key string, value []byte) error {
	s.writes++
	if !store.SyncDisabled(ctx) {
		s.syncedWrites++
	}
	return s.Store.Set(ctx, namespace, key, value)
}

func (s *syncRecordingStore) Batch(ctx context.Context, fn func(context.Context) error) error {
	s.batches++
	return s.Store.(store.Batcher).Batch(ctx, fn)
}

func TestMetricWritesAreUnsyncedAndFlushBatched(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	recorder := &syncRecordingStore{Store: backend}
	m := New(recorder)
	t.Cleanup(m.Close)
	// Ignore the storage format marker New records.
	recorder.batches, recorder.writes, recorder.syncedWrites = 0, 0, 0

	m.SetGauge("queue_depth", 3, nil)
	m.IncrementCounter("requests_total", map[string]string{"method": "GET"})
	m.IncrementCounter("requests_total", map[string]string{"method": "POST"})
	m.ObserveHistogram("request_duration", 0.01, nil)
	m.Flush()

	if recorder.batches != 1 {
		t.Fatalf("flush batches = %d, want 1", recorder.batches)
	}
	// One gauge, two counters, and the histogram's buckets plus sum and count.
	if want := 3 + len(HistogramBuckets) + 2; recorder.writes != want {
		t.Fatalf("writes = %d, want %d", recorder.writes, want)
	}
	if recorder.syncedWrites != 0 {
		t.Fatalf("synced metric writes = %d, want 0", recorder.syncedWrites)
	}
	m.Flush()
	if recorder.batches != 1 {
		t.Fatalf("empty flush opened a batch: batches = %d", recorder.batches)
	}
}

func TestCloseFlushesCounters(t *testing.T) {
	m := testMetrics(t)
	m.IncrementCounterBy("bytes_total", 42, nil)
	m.Close()
	m.Close()

	samples, err := m.loadSamples(metricKey("bytes_total", nil))
	if err != nil {
		t.Fatalf("load flushed counter: %v", err)
	}
	if len(samples) != 1 || samples[0].Value != 42 {
		t.Fatalf("flushed counter samples = %+v, want one sample of 42", samples)
	}
}
