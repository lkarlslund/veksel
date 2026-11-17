package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/contentscan"
)

func TestContentScanObserverExportsBoundedOutcomesAndDurations(t *testing.T) {
	collector := testPrometheusMetrics(t)
	observer := NewContentScanObserver(collector)
	observer.ObserveContentScan(contentscan.Report{
		Decision: contentscan.DecisionAllow,
		Results: []contentscan.Result{
			{Engine: "builtin", Verdict: contentscan.VerdictClean, Duration: 25 * time.Millisecond},
			{Engine: "rspamd", Verdict: contentscan.VerdictSpam, Duration: 50 * time.Millisecond},
		},
	})
	observer.ObserveContentScan(contentscan.Report{
		Decision: contentscan.DecisionQuarantine,
		Results: []contentscan.Result{
			{Engine: "clamav", Verdict: contentscan.VerdictMalware, Duration: 100 * time.Millisecond, MalwareNames: []string{"sensitive-signature"}},
		},
	})
	observer.ObserveContentScan(contentscan.Report{
		Decision: contentscan.DecisionDefer,
		Results: []contentscan.Result{
			{Engine: "rspamd", Verdict: contentscan.VerdictUnknown, Duration: 250 * time.Millisecond, ErrorCode: "scanner_error", Error: "secret backend detail"},
		},
	})

	var output bytes.Buffer
	collector.PrometheusFormat(&output)
	metrics := output.String()
	for _, want := range []string{
		`content_scan_decisions_total{decision="allow"} 1`,
		`content_scan_decisions_total{decision="quarantine"} 1`,
		`content_scan_decisions_total{decision="defer"} 1`,
		`content_scan_engine_results_total{engine="builtin",outcome="completed",verdict="clean"} 1`,
		`content_scan_engine_results_total{engine="rspamd",outcome="completed",verdict="spam"} 1`,
		`content_scan_engine_results_total{engine="clamav",outcome="completed",verdict="malware"} 1`,
		`content_scan_engine_results_total{engine="rspamd",outcome="error",verdict="unknown"} 1`,
		`content_scan_engine_duration_seconds_sum{engine="builtin"} 0.025`,
		`content_scan_engine_duration_seconds_count{engine="rspamd"} 2`,
		`content_scan_engine_duration_seconds_bucket{engine="clamav",le="+Inf"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("missing %q in metrics:\n%s", want, metrics)
		}
	}
	for _, forbidden := range []string{"sensitive-signature", "secret backend detail", "scanner_error"} {
		if strings.Contains(metrics, forbidden) {
			t.Errorf("metrics leaked %q:\n%s", forbidden, metrics)
		}
	}
}

func TestContentScanObserverIsNilSafe(t *testing.T) {
	var absent *ContentScanObserver
	absent.ObserveContentScan(contentscan.Report{})
	NewContentScanObserver(nil).ObserveContentScan(contentscan.Report{})
}
