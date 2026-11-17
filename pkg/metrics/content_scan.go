package metrics

import "github.com/lkarlslund/veksel/pkg/contentscan"

const (
	contentScanDecisionsMetric      = "content_scan_decisions_total"
	contentScanEngineResultsMetric  = "content_scan_engine_results_total"
	contentScanEngineDurationMetric = "content_scan_engine_duration_seconds"
)

// ContentScanObserver projects normalized content-scanner reports into the
// shared metrics collector. Every label is either a validated engine name or a
// closed enum/state value; message and scanner evidence never become labels.
type ContentScanObserver struct {
	metrics *Metrics
}

// NewContentScanObserver creates a nil-safe observer for a shared collector.
func NewContentScanObserver(collector *Metrics) *ContentScanObserver {
	return &ContentScanObserver{metrics: collector}
}

// ObserveContentScan records one final pipeline decision and every normalized
// engine result. Durations are exported in Prometheus' conventional seconds.
func (o *ContentScanObserver) ObserveContentScan(report contentscan.Report) {
	if o == nil || o.metrics == nil {
		return
	}
	o.metrics.IncrementCounter(contentScanDecisionsMetric, map[string]string{
		"decision": report.Decision.String(),
	})
	for _, result := range report.Results {
		outcome := "completed"
		if result.ErrorCode != "" {
			outcome = "error"
		}
		o.metrics.IncrementCounter(contentScanEngineResultsMetric, map[string]string{
			"engine":  result.Engine,
			"outcome": outcome,
			"verdict": result.Verdict.String(),
		})
		o.metrics.ObserveHistogram(contentScanEngineDurationMetric, result.Duration.Seconds(), map[string]string{
			"engine": result.Engine,
		})
	}
}
