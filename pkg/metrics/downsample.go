package metrics

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Range query bounds. A series never carries more than MaxRangePoints
// points, whatever its sample rate or the requested window.
const (
	DefaultRangeWindow = 24 * time.Hour
	DefaultRangePoints = 288 // five-minute steps over a day
	MaxRangePoints     = 1000
)

// Per-bucket aggregations reported with each series.
const (
	// AggregateLast reports a gauge's last value in the step and its maximum.
	AggregateLast = "last"
	// AggregateSum reports the total increase in the step. Counter and
	// histogram samples hold the increase since the previous flush (the
	// in-memory accumulator restarts after each flush), so summing them
	// keeps the series' total exact at any resolution.
	AggregateSum = "sum"
)

// RangeQuery selects a time window of stored samples, downsampled to at
// most Points steps per series. Name, when set, limits the result to one
// metric name.
type RangeQuery struct {
	Name   string
	Start  time.Time
	End    time.Time
	Points int
}

// Point is one downsampled step. Timestamp is the step's start in Unix
// seconds. Max is set for gauges only.
type Point struct {
	Timestamp int64    `json:"ts"`
	Value     float64  `json:"value"`
	Max       *float64 `json:"max,omitempty"`
}

// RangeSeries is one series' downsampled points. Steps without samples are
// omitted; gauges are step values, so a reader carries the previous point
// forward across a gap.
type RangeSeries struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Labels      map[string]string `json:"labels,omitempty"`
	Aggregation string            `json:"aggregation"`
	Samples     int               `json:"samples"`
	Points      []Point           `json:"points"`
}

// RangeResult is the answer to a RangeQuery.
type RangeResult struct {
	Start  time.Time     `json:"start"`
	End    time.Time     `json:"end"`
	Step   time.Duration `json:"-"`
	Series []RangeSeries `json:"series"`
}

// rangeStep returns the whole-second step that divides window into at most
// points steps, and the resulting step count.
func rangeStep(window time.Duration, points int) (time.Duration, int) {
	points = min(max(points, 1), MaxRangePoints)
	step := max((window+time.Duration(points)-1)/time.Duration(points), time.Second)
	step = (step + time.Second - 1).Truncate(time.Second)
	steps := int((window + step - 1) / step)
	return step, max(steps, 1)
}

// QueryRange returns every series with samples in [q.Start, q.End],
// downsampled into equal steps starting at q.Start. Only the hour buckets
// the window covers are decoded.
func (m *Metrics) QueryRange(q RangeQuery) (RangeResult, error) {
	start, end := q.Start.UTC(), q.End.UTC()
	if !end.After(start) {
		return RangeResult{}, fmt.Errorf("range end %s is not after start %s", end, start)
	}
	step, steps := rangeStep(end.Sub(start), q.Points)
	bySeries := make(map[string][]Sample)
	err := m.iterateSamples(q.Name, bucketStart(start), func(series string, sample Sample) {
		if q.Name != "" && sample.Name != q.Name {
			return
		}
		if sample.Timestamp.Before(start) || sample.Timestamp.After(end) {
			return
		}
		bySeries[series] = append(bySeries[series], sample)
	})
	if err != nil {
		return RangeResult{}, err
	}
	keys := make([]string, 0, len(bySeries))
	for key := range bySeries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := RangeResult{Start: start, End: end, Step: step, Series: make([]RangeSeries, 0, len(keys))}
	for _, key := range keys {
		samples := bySeries[key]
		sortByTime(samples)
		first := samples[0]
		aggregation := AggregateSum
		if first.Type == TypeGauge {
			aggregation = AggregateLast
		}
		result.Series = append(result.Series, RangeSeries{
			Name:        first.Name,
			Type:        first.Type,
			Labels:      first.Labels,
			Aggregation: aggregation,
			Samples:     len(samples),
			Points:      Downsample(samples, start, step, steps, aggregation),
		})
	}
	return result, nil
}

// Downsample folds time-ordered samples into steps equal steps of width
// step starting at start. Step i covers [start+i*step, start+(i+1)*step);
// a sample at the window's end falls into the last step, and samples
// outside the window are ignored. Steps without samples produce no point.
// AggregateLast keeps each step's last value and its maximum; AggregateSum
// adds the step's values. At most min(steps, MaxRangePoints) points are
// returned.
func Downsample(samples []Sample, start time.Time, step time.Duration, steps int, aggregation string) []Point {
	steps = min(steps, MaxRangePoints)
	if steps <= 0 || step <= 0 {
		return []Point{}
	}
	points := make([]Point, 0, min(len(samples), steps))
	current := -1
	for _, sample := range samples {
		offset := sample.Timestamp.Sub(start)
		if offset < 0 {
			continue
		}
		index := int(offset / step)
		if index >= steps {
			// Only the window's closing instant may round past the last step.
			if offset > time.Duration(steps)*step {
				continue
			}
			index = steps - 1
		}
		if index != current {
			current = index
			point := Point{Timestamp: start.Add(time.Duration(index) * step).Unix(), Value: sample.Value}
			if aggregation == AggregateLast {
				peak := sample.Value
				point.Max = &peak
			}
			points = append(points, point)
			continue
		}
		point := &points[len(points)-1]
		if aggregation == AggregateLast {
			point.Value = sample.Value
			*point.Max = max(*point.Max, sample.Value)
		} else {
			point.Value += sample.Value
		}
	}
	return points
}

// Retention returns how long samples are kept.
func (m *Metrics) Retention() time.Duration { return m.retention }

// ParseRangeWindow parses a window such as "15m", "24h", "7d", or a count
// of seconds.
func ParseRangeWindow(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if days, ok := strings.CutSuffix(value, "d"); ok {
		parsed, err := time.ParseDuration(days + "h")
		if err != nil {
			return 0, fmt.Errorf("invalid window %q", value)
		}
		return parsed * 24, nil
	}
	if parsed, err := time.ParseDuration(value); err == nil {
		return parsed, nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid window %q", value)
	}
	return time.Duration(seconds) * time.Second, nil
}
