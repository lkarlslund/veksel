package metrics

import "github.com/lkarlslund/veksel/pkg/spam"

const (
	spamDNSLookupsMetric = "antispam_dns_lookups_total"
	spamActionsMetric    = "antispam_actions_total"
	spamScoreMetric      = "antispam_score"
)

// SpamObserver projects spam engine activity into the shared collector.
// Zone labels come from validated configuration and actions from a closed
// enum; message evidence never becomes a label.
type SpamObserver struct {
	metrics *Metrics
}

// NewSpamObserver creates a nil-safe observer for a shared collector.
func NewSpamObserver(collector *Metrics) *SpamObserver {
	return &SpamObserver{metrics: collector}
}

// ObserveSpamDNS counts one interpreted blocklist answer.
func (o *SpamObserver) ObserveSpamDNS(kind spam.ZoneKind, zone, outcome string) {
	if o == nil || o.metrics == nil {
		return
	}
	o.metrics.IncrementCounter(spamDNSLookupsMetric, map[string]string{"kind": string(kind), "zone": zone, "outcome": outcome})
}

// ObserveSpamResult counts the action and records the score of one check.
func (o *SpamObserver) ObserveSpamResult(result spam.Result) {
	if o == nil || o.metrics == nil {
		return
	}
	o.metrics.IncrementCounter(spamActionsMetric, map[string]string{"action": result.Action.String()})
	o.metrics.ObserveHistogramWithBuckets(spamScoreMetric, result.Score, nil, spamScoreBuckets)
}

// spamScoreBuckets span clean mail through rejection.
var spamScoreBuckets = []float64{0, 1, 2, 4, 6, 8, 10, 15, 20, 30, 50}
