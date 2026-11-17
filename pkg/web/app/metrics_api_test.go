package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestAdminMetricsReturnsBoundedDownsampledSeries(t *testing.T) {
	base, key, _ := operationsApp(t, func(handler *Handler, typed *model.TypedStore) {
		collector := metrics.New(typed.Store())
		t.Cleanup(collector.Close)
		// Alternating values persist every observation of the gauge.
		for i := range 2000 {
			collector.SetGauge("busy_gauge", float64(i%2), nil)
		}
		collector.IncrementCounterBy("deliveries", 3, map[string]string{"result": "ok"})
		collector.Flush()
		handler.ConfigureMetrics(collector)
	})

	var response struct {
		Start       time.Time `json:"start"`
		End         time.Time `json:"end"`
		StepSeconds int64     `json:"step_seconds"`
		Total       int       `json:"total"`
		Series      []struct {
			Name        string            `json:"name"`
			Type        string            `json:"type"`
			Labels      map[string]string `json:"labels"`
			Aggregation string            `json:"aggregation"`
			Samples     int               `json:"samples"`
			Points      []struct {
				Timestamp int64    `json:"ts"`
				Value     float64  `json:"value"`
				Max       *float64 `json:"max"`
			} `json:"points"`
		} `json:"series"`
	}
	status, body, _ := keyDo(t, http.MethodGet, base+"/api/v1/admin/metrics?window=1h&points=12", key, nil)
	if status != http.StatusOK {
		t.Fatalf("metrics = %d %s", status, body)
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.End.Sub(response.Start) != time.Hour || response.StepSeconds != 300 || response.Total != 2 || len(response.Series) != 2 {
		t.Fatalf("response = %+v", response)
	}
	gauge, counter := response.Series[0], response.Series[1]
	if gauge.Name != "busy_gauge" || gauge.Aggregation != metrics.AggregateLast || gauge.Samples != 2000 || len(gauge.Points) == 0 || len(gauge.Points) > 12 {
		t.Fatalf("gauge = %s %s samples=%d points=%d", gauge.Name, gauge.Aggregation, gauge.Samples, len(gauge.Points))
	}
	if last := gauge.Points[len(gauge.Points)-1]; last.Value != 1 || last.Max == nil || *last.Max != 1 {
		t.Fatalf("gauge last point = %+v", last)
	}
	if counter.Name != "deliveries" || counter.Labels["result"] != "ok" || counter.Aggregation != metrics.AggregateSum || len(counter.Points) != 1 || counter.Points[0].Value != 3 || counter.Points[0].Max != nil {
		t.Fatalf("counter = %+v", counter)
	}
	if len(body) > 2048 {
		t.Fatalf("response is %d bytes for 2000 stored samples", len(body))
	}

	status, body, _ = keyDo(t, http.MethodGet, base+"/api/v1/admin/metrics?name=deliveries&points=100000", key, nil)
	if status != http.StatusOK || strings.Contains(string(body), "busy_gauge") || !strings.Contains(string(body), "deliveries") {
		t.Fatalf("name filter = %d %s", status, body)
	}
	if err := json.Unmarshal(body, &response); err != nil || response.End.Sub(response.Start) != metrics.DefaultRangeWindow || response.StepSeconds != 87 {
		t.Fatalf("default window = %+v, %v", response, err)
	}
	for _, query := range []string{"window=soon", "window=0s", "points=0", "points=x", "end=yesterday"} {
		if status, body, _ := keyDo(t, http.MethodGet, base+"/api/v1/admin/metrics?"+query, key, nil); status != http.StatusBadRequest {
			t.Fatalf("%s = %d %s", query, status, body)
		}
	}
}
