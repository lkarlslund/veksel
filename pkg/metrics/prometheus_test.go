package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func testPrometheusMetrics(t *testing.T) *Metrics {
	t.Helper()
	dir := t.TempDir()
	s, err := jsonstore.New(dir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return New(s)
}

func TestPrometheusFormat(t *testing.T) {
	m := testPrometheusMetrics(t)

	// Record some metrics
	m.IncrementCounterBy("http_requests_total", 5.0, map[string]string{"method": "GET"})
	m.IncrementCounterBy("http_requests_total", 3.0, map[string]string{"method": "POST"})
	m.SetGauge("active_connections", 42.0, nil)
	m.ObserveHistogram("request_duration_seconds", 0.5, nil)

	// Flush to store
	m.Flush()

	var buf bytes.Buffer
	m.PrometheusFormat(&buf)
	output := buf.String()

	// Verify basic Prometheus format elements
	if !strings.Contains(output, "# HELP") {
		t.Error("missing HELP line")
	}
	if !strings.Contains(output, "# TYPE") {
		t.Error("missing TYPE line")
	}
	if !strings.Contains(output, "http_requests_total") {
		t.Error("missing http_requests_total metric")
	}
	if !strings.Contains(output, "active_connections") {
		t.Error("missing active_connections metric")
	}
	if !strings.Contains(output, "counter") {
		t.Error("missing counter type")
	}
	if !strings.Contains(output, "gauge") {
		t.Error("missing gauge type")
	}
}

func TestPrometheusFormatEmpty(t *testing.T) {
	m := testPrometheusMetrics(t)

	var buf bytes.Buffer
	m.PrometheusFormat(&buf)
	// Should not panic on empty metrics
}

func TestLabelKey(t *testing.T) {
	tests := []struct {
		labels map[string]string
		want   string
	}{
		{nil, ""},
		{map[string]string{}, ""},
		{map[string]string{"method": "GET"}, `method="GET"`},
		{map[string]string{"code": "200", "method": "GET"}, `code="200",method="GET"`},
	}

	for _, tt := range tests {
		got := labelKey(tt.labels)
		if got != tt.want {
			t.Errorf("labelKey(%v) = %q, want %q", tt.labels, got, tt.want)
		}
	}
}

func TestLabelsForKey(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"metric_name", ""},
		{"metric_name{method=\"GET\"}", `method="GET"`},
		{"metric_name{code=\"200\",method=\"GET\"}", `code="200",method="GET"`},
	}

	for _, tt := range tests {
		got := labelsForKey(tt.key)
		if got != tt.want {
			t.Errorf("labelsForKey(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestPrometheusFormatWithTimeRange(t *testing.T) {
	m := testPrometheusMetrics(t)

	// Add samples with different timestamps
	m.IncrementCounterBy("test_counter", 1.0, nil)
	m.Flush()

	// Wait a tick to ensure different timestamps
	time.Sleep(10 * time.Millisecond)
	m.IncrementCounterBy("test_counter", 1.0, nil)
	m.Flush()

	var buf bytes.Buffer
	m.PrometheusFormat(&buf)
	output := buf.String()

	if !strings.Contains(output, "test_counter") {
		t.Error("missing test_counter metric")
	}
}

func TestScrapeHandlerRequiresBearerToken(t *testing.T) {
	m := testPrometheusMetrics(t)
	m.SetGauge("active_connections", 1, nil)
	const token = "0123456789abcdef-scrape"
	tests := []struct {
		name          string
		configured    string
		authorization string
		want          int
	}{
		{"disabled without token", "", "Bearer " + token, http.StatusNotFound},
		{"missing credential", token, "", http.StatusUnauthorized},
		{"wrong token", token, "Bearer 0123456789abcdef-wrong", http.StatusUnauthorized},
		{"wrong scheme", token, "Basic " + token, http.StatusUnauthorized},
		{"valid token", token, "Bearer " + token, http.StatusOK},
		{"case-insensitive scheme", token, "bearer " + token, http.StatusOK},
		{"token removed live", "", "Bearer " + token, http.StatusNotFound},
		{"token rotated live", "0123456789abcdef-rotated", "Bearer " + token, http.StatusUnauthorized},
	}
	// One handler serves every case: it reads the token per request, so a
	// changed token applies without rebuilding the handler.
	var configured string
	handler := m.ScrapeHandler(func() string { return configured })
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			recorder := httptest.NewRecorder()
			configured = test.configured
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d", recorder.Code, test.want)
			}
			hasMetrics := strings.Contains(recorder.Body.String(), "active_connections")
			if hasMetrics != (test.want == http.StatusOK) {
				t.Fatalf("metrics exposed = %v for status %d", hasMetrics, recorder.Code)
			}
		})
	}
}
