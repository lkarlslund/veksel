package metrics

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// ScrapeHandler serves the Prometheus exposition to scrapers presenting the
// token returned by currentToken (read per request, so a changed token
// applies immediately) as an "Authorization: Bearer" credential, compared in
// constant time. An empty token disables the endpoint (404) so metrics are
// never anonymous.
func (m *Metrics) ScrapeHandler(currentToken func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := currentToken()
		if token == "" {
			http.NotFound(w, r)
			return
		}
		scheme, presented, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(presented)), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m.PrometheusFormat(w)
	})
}

// PrometheusFormat writes all metrics in Prometheus exposition format to w.
//
// Format reference: https://prometheus.io/docs/instrumenting/exposition_formats/
func (m *Metrics) PrometheusFormat(w io.Writer) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect all samples from the store
	samples, _ := m.allSamples()

	// Sort by name, then timestamp
	slices.SortFunc(samples, func(a, b Sample) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return a.Timestamp.Compare(b.Timestamp)
	})

	// Group by metric name
	type metricGroup struct {
		name    string
		samples []Sample
	}
	var groups []metricGroup
	var current *metricGroup
	for _, s := range samples {
		if current == nil || current.name != s.Name {
			g := metricGroup{name: s.Name, samples: []Sample{s}}
			groups = append(groups, g)
			current = &g
		} else {
			current.samples = append(current.samples, s)
		}
	}

	for _, g := range groups {
		// Determine type from the samples
		var sampleType string
		for _, s := range g.samples {
			if s.Type != "" {
				sampleType = s.Type
				break
			}
		}

		// HELP line
		fmt.Fprintf(w, "# HELP %s Metric imported from Veksel\n", g.name)
		// TYPE line
		fmt.Fprintf(w, "# TYPE %s %s\n", g.name, sampleType)

		// Output the latest value for each label set
		latest := make(map[string]float64)
		for _, s := range g.samples {
			key := labelKey(s.Labels)
			latest[key] = s.Value
		}

		for key, val := range latest {
			if key == "" {
				fmt.Fprintf(w, "%s %v\n", g.name, val)
			} else {
				fmt.Fprintf(w, "%s{%s} %v\n", g.name, key, val)
			}
		}
	}

	// Also output in-memory counters (not yet flushed)
	for key, cs := range m.counters {
		// HELP/TYPE
		fmt.Fprintf(w, "# HELP %s Metric imported from Veksel\n", cs.name)
		fmt.Fprintf(w, "# TYPE %s counter\n", cs.name)
		if key == cs.name {
			fmt.Fprintf(w, "%s %v\n", cs.name, cs.value)
		} else {
			fmt.Fprintf(w, "%s{%s} %v\n", cs.name, labelKey(cs.labels), cs.value)
		}
	}

	// Also output in-memory histograms
	for _, hs := range m.histograms {
		// HELP/TYPE
		fmt.Fprintf(w, "# HELP %s Metric imported from Veksel\n", hs.name)
		fmt.Fprintf(w, "# TYPE %s histogram\n", hs.name)

		// Bucket lines
		for i, boundary := range hs.buckets {
			bucketLabels := mergeLabels(hs.labels, map[string]string{"le": fmt.Sprintf("%.4f", boundary)})
			fmt.Fprintf(w, "%s_bucket{%s} %v\n", hs.name, labelKey(bucketLabels), float64(hs.counts[i]))
		}
		// +Inf bucket
		fmt.Fprintf(w, "%s_bucket{%s} %v\n", hs.name, labelKey(mergeLabels(hs.labels, map[string]string{"le": "+Inf"})), float64(hs.count))
		// Sum and count
		if labels := labelKey(hs.labels); labels != "" {
			fmt.Fprintf(w, "%s_sum{%s} %v\n", hs.name, labels, hs.sum)
			fmt.Fprintf(w, "%s_count{%s} %v\n", hs.name, labels, float64(hs.count))
		} else {
			fmt.Fprintf(w, "%s_sum %v\n", hs.name, hs.sum)
			fmt.Fprintf(w, "%s_count %v\n", hs.name, float64(hs.count))
		}
	}
}

// labelKey creates a Prometheus-style label string from a label map.
// Example: "method=\"GET\",code=\"200\""
func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

// labelsForKey extracts the label portion from a metric key like "name{labels}".
func labelsForKey(key string) string {
	start := strings.Index(key, "{")
	end := strings.LastIndex(key, "}")
	if start >= 0 && end > start {
		return key[start+1 : end]
	}
	return ""
}
