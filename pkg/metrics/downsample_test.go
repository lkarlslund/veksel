package metrics

import (
	"testing"
	"time"
)

func sampleAt(start time.Time, offset time.Duration, value float64, kind string) Sample {
	return Sample{Timestamp: start.Add(offset), Value: value, Type: kind, Name: "m"}
}

func TestDownsampleGaugeKeepsLastAndMaxPerStep(t *testing.T) {
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	samples := []Sample{
		sampleAt(start, 0, 3, TypeGauge),
		sampleAt(start, 30*time.Second, 9, TypeGauge),
		sampleAt(start, 59*time.Second, 4, TypeGauge),
		// Exactly on the next step's edge: belongs to step 1, not step 0.
		sampleAt(start, time.Minute, 7, TypeGauge),
		// Step 2 is empty; step 3 has one sample.
		sampleAt(start, 3*time.Minute+time.Second, 1, TypeGauge),
	}
	points := Downsample(samples, start, time.Minute, 5, AggregateLast)
	want := []struct {
		ts         int64
		value, max float64
	}{
		{start.Unix(), 4, 9},
		{start.Add(time.Minute).Unix(), 7, 7},
		{start.Add(3 * time.Minute).Unix(), 1, 1},
	}
	if len(points) != len(want) {
		t.Fatalf("points = %+v, want %d", points, len(want))
	}
	for i, w := range want {
		got := points[i]
		if got.Timestamp != w.ts || got.Value != w.value || got.Max == nil || *got.Max != w.max {
			t.Fatalf("point %d = {%d %v %v}, want %+v", i, got.Timestamp, got.Value, got.Max, w)
		}
	}
}

func TestDownsampleCounterSumsIncreasesPerStep(t *testing.T) {
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	var samples []Sample
	total := 0.0
	for i := range 120 {
		samples = append(samples, sampleAt(start, time.Duration(i)*30*time.Second, float64(i%5), TypeCounter))
		total += float64(i % 5)
	}
	points := Downsample(samples, start, 10*time.Minute, 6, AggregateSum)
	if len(points) != 6 {
		t.Fatalf("points = %d, want 6", len(points))
	}
	sum := 0.0
	for _, point := range points {
		if point.Max != nil {
			t.Fatalf("counter point carries max: %+v", point)
		}
		sum += point.Value
	}
	if sum != total {
		t.Fatalf("downsampled total = %v, want %v", sum, total)
	}
	// The first step holds samples 0..19: four rounds of 0+1+2+3+4.
	if points[0].Value != 40 {
		t.Fatalf("first step = %v, want 40", points[0].Value)
	}
}

func TestDownsampleWindowEdges(t *testing.T) {
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	samples := []Sample{
		sampleAt(start, -time.Nanosecond, 100, TypeCounter),
		sampleAt(start, 0, 1, TypeCounter),
		// The window's closing instant joins the last step.
		sampleAt(start, 4*time.Minute, 2, TypeCounter),
		sampleAt(start, 4*time.Minute+time.Nanosecond, 100, TypeCounter),
	}
	points := Downsample(samples, start, time.Minute, 4, AggregateSum)
	if len(points) != 2 || points[0].Value != 1 || points[1].Value != 2 || points[1].Timestamp != start.Add(3*time.Minute).Unix() {
		t.Fatalf("points = %+v", points)
	}
	if got := Downsample(nil, start, time.Minute, 4, AggregateLast); len(got) != 0 {
		t.Fatalf("empty input = %+v", got)
	}
}

func TestDownsampleCapsPoints(t *testing.T) {
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	samples := make([]Sample, 0, 5000)
	for i := range 5000 {
		samples = append(samples, sampleAt(start, time.Duration(i)*time.Second, float64(i), TypeGauge))
	}
	if points := Downsample(samples, start, time.Second, 5000, AggregateLast); len(points) != MaxRangePoints {
		t.Fatalf("points = %d, want cap %d", len(points), MaxRangePoints)
	}
}

func TestRangeStep(t *testing.T) {
	cases := []struct {
		window time.Duration
		points int
		step   time.Duration
		steps  int
	}{
		{24 * time.Hour, 288, 5 * time.Minute, 288},
		{time.Hour, 7, 515 * time.Second, 7},
		{10 * time.Second, 100, time.Second, 10},
		{7 * 24 * time.Hour, 1_000_000, 605 * time.Second, 1000},
		{time.Hour, 0, time.Hour, 1},
	}
	for _, c := range cases {
		step, steps := rangeStep(c.window, c.points)
		if step != c.step || steps != c.steps || steps > MaxRangePoints {
			t.Errorf("rangeStep(%v, %d) = %v, %d; want %v, %d", c.window, c.points, step, steps, c.step, c.steps)
		}
	}
}

func TestQueryRangeGroupsAndDownsamplesSeries(t *testing.T) {
	m := testMetrics(t)
	end := time.Now().UTC().Truncate(time.Second)
	start := end.Add(-time.Hour)
	for i := range 720 {
		ts := start.Add(time.Duration(i) * 5 * time.Second)
		if err := m.storeSample(m.writeCtx, "active", Sample{Timestamp: ts, Value: float64(i % 10), Type: TypeGauge, Name: "active"}); err != nil {
			t.Fatal(err)
		}
		labels := map[string]string{"proto": "imap"}
		if err := m.storeSample(m.writeCtx, metricKey("logins", labels), Sample{Timestamp: ts, Value: 1, Type: TypeCounter, Name: "logins", Labels: labels}); err != nil {
			t.Fatal(err)
		}
	}
	// A sample before the window must not be read.
	if err := m.storeSample(m.writeCtx, "active", Sample{Timestamp: start.Add(-time.Minute), Value: 99, Type: TypeGauge, Name: "active"}); err != nil {
		t.Fatal(err)
	}

	result, err := m.QueryRange(RangeQuery{Start: start, End: end, Points: 60})
	if err != nil {
		t.Fatal(err)
	}
	if result.Step != time.Minute || len(result.Series) != 2 {
		t.Fatalf("step = %v, series = %d", result.Step, len(result.Series))
	}
	gauge, counter := result.Series[0], result.Series[1]
	if gauge.Name != "active" || gauge.Aggregation != AggregateLast || gauge.Samples != 720 || len(gauge.Points) != 60 {
		t.Fatalf("gauge = %s %s samples=%d points=%d", gauge.Name, gauge.Aggregation, gauge.Samples, len(gauge.Points))
	}
	for _, point := range gauge.Points {
		if *point.Max != 9 {
			t.Fatalf("gauge point max = %v, want 9", *point.Max)
		}
	}
	if counter.Name != "logins" || counter.Labels["proto"] != "imap" || counter.Aggregation != AggregateSum {
		t.Fatalf("counter = %+v", counter)
	}
	total := 0.0
	for _, point := range counter.Points {
		total += point.Value
	}
	if total != 720 {
		t.Fatalf("counter total = %v, want 720", total)
	}

	only, err := m.QueryRange(RangeQuery{Name: "logins", Start: start, End: end, Points: 4})
	if err != nil || len(only.Series) != 1 || only.Series[0].Name != "logins" || len(only.Series[0].Points) != 4 {
		t.Fatalf("name filter = %+v, %v", only, err)
	}
	if _, err := m.QueryRange(RangeQuery{Start: end, End: end}); err == nil {
		t.Fatal("empty window accepted")
	}
}

func TestParseRangeWindow(t *testing.T) {
	for input, want := range map[string]time.Duration{"15m": 15 * time.Minute, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "3600": time.Hour} {
		if got, err := ParseRangeWindow(input); err != nil || got != want {
			t.Errorf("ParseRangeWindow(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	for _, input := range []string{"", "soon", "1x", "d"} {
		if _, err := ParseRangeWindow(input); err == nil {
			t.Errorf("ParseRangeWindow(%q) accepted", input)
		}
	}
}
