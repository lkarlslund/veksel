package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// writeSizeStore records the largest value written.
type writeSizeStore struct {
	store.Store
	largest int
}

func (s *writeSizeStore) Set(ctx context.Context, namespace, key string, value []byte) error {
	s.largest = max(s.largest, len(value))
	return s.Store.Set(ctx, namespace, key, value)
}

func TestAppendWritesOnlyTheNewSample(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	recorder := &writeSizeStore{Store: backend}
	m := New(recorder)
	t.Cleanup(m.Close)

	sample := Sample{Timestamp: time.Now().UTC(), Value: 1, Type: TypeGauge, Name: "g"}
	encoded, _ := json.Marshal(sample)
	for range 50 {
		if err := m.storeSample(m.writeCtx, "g", sample); err != nil {
			t.Fatal(err)
		}
	}
	if recorder.largest > len(encoded) {
		t.Fatalf("largest write = %d bytes, want one sample (%d bytes)", recorder.largest, len(encoded))
	}
	if samples, err := m.loadSamples("g"); err != nil || len(samples) != 50 {
		t.Fatalf("stored samples = %d (%v), want 50 distinct keys", len(samples), err)
	}
}

func TestParseSampleKeyToleratesSeparatorInLabels(t *testing.T) {
	m := testMetrics(t)
	series := metricKey("requests", map[string]string{"path": "/a#b#1"})
	ts := time.Date(2026, 10, 23, 5, 30, 0, 0, time.UTC)
	got, bucket, ok := parseSampleKey(m.sampleKey(series, ts))
	if !ok || got != series || bucket != bucketStart(ts) {
		t.Fatalf("parse = %q, %d, %v; want %q, %d", got, bucket, ok, series, bucketStart(ts))
	}
	for _, key := range []string{"requests", formatKey, "requests{a=b}"} {
		if _, _, ok := parseSampleKey(key); ok {
			t.Fatalf("parseSampleKey(%q) accepted a non-sample key", key)
		}
	}
}

func TestMigrateLegacySeries(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ctx := context.Background()
	if err := backend.CreateNamespace(ctx, NS); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	labels := map[string]string{"method": "GET"}
	legacy := map[string][]Sample{
		"queue_depth": {
			{Timestamp: now.Add(-DefaultRetention - time.Hour), Value: 9, Type: TypeGauge, Name: "queue_depth"},
			{Timestamp: now.Add(-2 * time.Hour), Value: 1, Type: TypeGauge, Name: "queue_depth"},
			{Timestamp: now.Add(-time.Minute), Value: 2, Type: TypeGauge, Name: "queue_depth"},
		},
		metricKey("requests", labels): {
			{Timestamp: now.Add(-time.Minute), Value: 5, Type: TypeCounter, Name: "requests", Labels: labels},
		},
	}
	for key, samples := range legacy {
		data, _ := json.Marshal(samples)
		if err := backend.Set(ctx, NS, key, data); err != nil {
			t.Fatal(err)
		}
	}

	m := New(backend)
	t.Cleanup(m.Close)
	for key := range legacy {
		if _, err := backend.Get(ctx, NS, key); err != store.ErrNotFound {
			t.Fatalf("legacy key %q survived migration: %v", key, err)
		}
	}
	samples, err := m.loadSamples("queue_depth")
	if err != nil || len(samples) != 2 || samples[0].Value != 1 || samples[1].Value != 2 {
		t.Fatalf("migrated queue_depth = %+v (%v), want the two retained samples in order", samples, err)
	}
	if got := m.Query("queue_depth", time.Hour); len(got) != 1 || got[0].Value != 2 {
		t.Fatalf("query after migration = %+v", got)
	}
	if value, _, ok := m.CurrentGauge("queue_depth"); !ok || value != 2 {
		t.Fatalf("current gauge after migration = %v, %v", value, ok)
	}
	if counters := m.GetCounters(); counters[metricKey("requests", labels)] != 5 {
		t.Fatalf("migrated counters = %v", counters)
	}

	// The format marker makes later starts skip the legacy scan.
	if err := backend.Set(ctx, NS, "late", []byte("[]")); err != nil {
		t.Fatal(err)
	}
	New(backend).Close()
	if _, err := backend.Get(ctx, NS, "late"); err != nil {
		t.Fatalf("restart rescanned for legacy series: %v", err)
	}
}

func TestPruneDeletesExpiredBuckets(t *testing.T) {
	m := testMetrics(t)
	now := time.Now().UTC()
	for _, age := range []time.Duration{DefaultRetention + 3*time.Hour, DefaultRetention + 2*time.Hour, time.Minute} {
		if err := m.storeSample(m.writeCtx, "g", Sample{Timestamp: now.Add(-age), Value: float64(age), Type: TypeGauge, Name: "g"}); err != nil {
			t.Fatal(err)
		}
	}
	m.prune()
	samples, err := m.loadSamples("g")
	if err != nil || len(samples) != 1 || samples[0].Value != float64(time.Minute) {
		t.Fatalf("samples after prune = %+v (%v), want only the recent one", samples, err)
	}
	if marker, err := m.store.Get(context.Background(), NS, formatKey); err != nil || string(marker) != formatBuckets {
		t.Fatalf("prune touched the format marker: %q, %v", marker, err)
	}
}

func TestQueryAndLatestRangeOverBuckets(t *testing.T) {
	m := testMetrics(t)
	now := time.Now().UTC()
	for _, age := range []time.Duration{5 * time.Hour, 3 * time.Hour} {
		if err := m.storeSample(m.writeCtx, "g", Sample{Timestamp: now.Add(-age), Value: float64(age / time.Hour), Type: TypeGauge, Name: "g"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := m.Query("g", time.Hour); len(got) != 0 {
		t.Fatalf("1h query = %+v, want none", got)
	}
	if got := m.Query("g", 4*time.Hour); len(got) != 1 || got[0].Value != 3 {
		t.Fatalf("4h query = %+v, want the 3h-old sample", got)
	}
	// Neither recent bucket holds a sample, so the latest comes from the
	// whole-series fallback.
	if value, _, ok := m.CurrentGauge("g"); !ok || value != 3 {
		t.Fatalf("current gauge = %v, %v; want 3", value, ok)
	}
}

// BenchmarkAppendSample shows that appending costs the same whatever the
// series already holds.
func BenchmarkAppendSample(b *testing.B) {
	for _, existing := range []int{100, 10000} {
		b.Run(fmt.Sprintf("existing=%d", existing), func(b *testing.B) {
			backend, err := pebblestore.New(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			defer backend.Close()
			m := New(backend)
			defer m.Close()
			now := time.Now().UTC()
			err = store.Batch(m.writeCtx, backend, func(ctx context.Context) error {
				for i := range existing {
					sample := Sample{Timestamp: now.Add(-time.Duration(existing-i) * time.Second), Value: float64(i), Type: TypeGauge, Name: "g"}
					if err := m.storeSample(ctx, "g", sample); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := m.storeSample(m.writeCtx, "g", Sample{Timestamp: time.Now().UTC(), Value: 1, Type: TypeGauge, Name: "g"}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
