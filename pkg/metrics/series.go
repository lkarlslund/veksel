package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// Stored layout. Every persisted sample is its own key,
//
//	<series>#<bucket>#<unix nanos><sequence>
//
// where series is metricKey(name, labels), bucket is the start of the
// sample's bucketWidth window in Unix seconds (10 digits), the timestamp is
// 19 digits, and an 8-hex-digit per-process sequence keeps samples sharing a
// clock reading distinct. The fixed-width fields keep engine key order equal
// to time order within a series. Appending is one blind write whatever the
// series length, retention deletes the keys of whole expired buckets, and
// time-bounded reads iterate only the buckets their window covers. Keys are
// parsed from the right, so label values may contain the separator, which is
// also safe in the JSON engine's file names.
//
// Earlier releases stored each series as one JSON array under the bare
// series key, so every append rewrote the whole history. migrateLegacy
// rewrites such series once and records formatKey so later starts skip the
// scan.
const (
	keySep      = "#"
	bucketWidth = time.Hour

	formatKey     = keySep + "format"
	formatBuckets = "sample-keys-v1"
)

// bucketStart returns the start of t's bucket in Unix seconds.
func bucketStart(t time.Time) int64 {
	unix := t.Unix()
	return unix - unix%int64(bucketWidth/time.Second)
}

// bucketPrefix returns the key prefix shared by series' samples in bucket.
func bucketPrefix(series string, bucket int64) string {
	return fmt.Sprintf("%s%s%010d%s", series, keySep, bucket, keySep)
}

// sampleKey returns a new, unique key for a sample of series taken at ts.
func (m *Metrics) sampleKey(series string, ts time.Time) string {
	return fmt.Sprintf("%s%019d%08x", bucketPrefix(series, bucketStart(ts)), ts.UnixNano(), m.seq.Add(1))
}

// parseSampleKey returns the series and bucket of a sample key; ok is false
// for legacy series keys and the format marker.
func parseSampleKey(key string) (series string, bucket int64, ok bool) {
	tsSep := strings.LastIndex(key, keySep)
	if tsSep <= 0 {
		return "", 0, false
	}
	bucketSep := strings.LastIndex(key[:tsSep], keySep)
	if bucketSep <= 0 {
		return "", 0, false
	}
	bucket, err := strconv.ParseInt(key[bucketSep+1:tsSep], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return key[:bucketSep], bucket, true
}

// storeSample appends a sample to series with a single write.
func (m *Metrics) storeSample(ctx context.Context, series string, sample Sample) error {
	encoded, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	return m.store.Set(ctx, NS, m.sampleKey(series, sample.Timestamp), encoded)
}

// iterateSamples calls fn, in key order, for every sample stored under
// prefix in a bucket starting at or after minBucket. Buckets are filtered
// from the key before the value is decoded.
func (m *Metrics) iterateSamples(prefix string, minBucket int64, fn func(series string, sample Sample)) error {
	return m.store.Iterate(context.Background(), NS, prefix, func(key string, value []byte) (bool, error) {
		series, bucket, ok := parseSampleKey(key)
		if !ok || bucket < minBucket {
			return true, nil
		}
		var sample Sample
		if json.Unmarshal(value, &sample) == nil {
			fn(series, sample)
		}
		return true, nil
	})
}

// loadSamples returns every stored sample of series in time order.
func (m *Metrics) loadSamples(series string) ([]Sample, error) {
	var samples []Sample
	err := m.iterateSamples(series+keySep, 0, func(_ string, sample Sample) {
		samples = append(samples, sample)
	})
	return samples, err
}

// samplesSince returns series' samples taken at or after cutoff in time
// order, iterating one bucket at a time. Buckets older than the retention
// window (plus the one prune may not have reached yet) are not visited.
func (m *Metrics) samplesSince(series string, cutoff time.Time) ([]Sample, error) {
	step := int64(bucketWidth / time.Second)
	last := bucketStart(time.Now().UTC())
	first := bucketStart(cutoff)
	if oldest := last - (int64(max(m.retention, 0)/bucketWidth)+1)*step; first < oldest {
		first = oldest
	}
	var samples []Sample
	for bucket := first; bucket <= last; bucket += step {
		err := m.iterateSamples(bucketPrefix(series, bucket), 0, func(_ string, sample Sample) {
			if !sample.Timestamp.Before(cutoff) {
				samples = append(samples, sample)
			}
		})
		if err != nil {
			return nil, err
		}
	}
	return samples, nil
}

// latestSample returns series' newest stored sample. Persisted gauges
// heartbeat well within a bucket, so the current and previous buckets
// almost always hold it; only otherwise is the whole series iterated.
func (m *Metrics) latestSample(series string) (Sample, bool) {
	var latest Sample
	found := false
	keep := func(_ string, sample Sample) { latest, found = sample, true }
	current := bucketStart(time.Now().UTC())
	for _, bucket := range []int64{current, current - int64(bucketWidth/time.Second)} {
		if err := m.iterateSamples(bucketPrefix(series, bucket), 0, keep); err != nil {
			return Sample{}, false
		}
		if found {
			return latest, true
		}
	}
	if err := m.iterateSamples(series+keySep, 0, keep); err != nil {
		return Sample{}, false
	}
	return latest, found
}

// migrateLegacy rewrites series stored as one JSON array under the bare
// series key into per-sample keys, dropping samples outside the retention
// window, in one unsynced batch. It runs once per store.
func (m *Metrics) migrateLegacy() error {
	ctx := context.Background()
	if marker, err := m.store.Get(ctx, NS, formatKey); err == nil && string(marker) == formatBuckets {
		return nil
	}
	keys, err := m.store.List(ctx, NS)
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	legacy := slices.DeleteFunc(keys, func(key string) bool {
		_, _, sample := parseSampleKey(key)
		return sample || key == formatKey
	})
	if len(legacy) == 0 {
		return m.store.Set(m.writeCtx, NS, formatKey, []byte(formatBuckets))
	}
	cutoff := time.Now().UTC().Add(-m.retention)
	return store.Batch(m.writeCtx, m.store, func(ctx context.Context) error {
		for _, key := range legacy {
			data, err := m.store.Get(ctx, NS, key)
			if err != nil {
				continue
			}
			var samples []Sample
			if json.Unmarshal(data, &samples) == nil {
				for _, sample := range samples {
					if sample.Timestamp.Before(cutoff) {
						continue
					}
					if err := m.storeSample(ctx, key, sample); err != nil {
						return fmt.Errorf("rewrite %s: %w", key, err)
					}
				}
			}
			if err := m.store.Delete(ctx, NS, key); err != nil {
				return fmt.Errorf("delete legacy %s: %w", key, err)
			}
		}
		return m.store.Set(ctx, NS, formatKey, []byte(formatBuckets))
	})
}
