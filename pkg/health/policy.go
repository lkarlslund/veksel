package health

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// Policy controls derived operational pressure without changing whether a
// dependency is required. Critical queue, storage, and certificate pressure
// is degraded with critical severity; only actual unavailability fails
// readiness.
type Policy struct {
	QueueWarningAge            time.Duration
	QueueCriticalAge           time.Duration
	WebhookWarningAge          time.Duration
	WebhookCriticalAge         time.Duration
	StorageWarningFreePercent  int
	StorageCriticalFreePercent int
	CertWarningAge             time.Duration
	CertCriticalAge            time.Duration
}

func (p Policy) Validate() error {
	if p.QueueWarningAge <= 0 || p.QueueCriticalAge <= p.QueueWarningAge {
		return errors.New("queue warning age must be positive and below critical age")
	}
	if p.WebhookWarningAge <= 0 || p.WebhookCriticalAge <= p.WebhookWarningAge {
		return errors.New("webhook warning age must be positive and below critical age")
	}
	if err := validateCapacityThresholds(p.StorageWarningFreePercent, p.StorageCriticalFreePercent); err != nil {
		return err
	}
	if p.CertCriticalAge <= 0 || p.CertWarningAge <= p.CertCriticalAge {
		return errors.New("certificate critical age must be positive and below warning age")
	}
	return nil
}

// WebhookObservation projects the dispatcher's cached, payload-free snapshot.
// Notification delivery is optional for process readiness but remains visible
// and participates in the durable alert lifecycle.
func (p Policy) WebhookObservation(now time.Time, pending, inFlight, retrying int, terminalFailed int64, oldestAge time.Duration, lastSuccess, lastFailure, lastTerminalFailure time.Time, statsError string) Observation {
	observation := Observation{
		ID: "webhook-delivery", Label: "Webhook delivery", Kind: "notification", Desired: true, Required: false, State: StateHealthy,
		Details: map[string]string{
			"pending": fmt.Sprint(pending), "in_flight": fmt.Sprint(inFlight), "retrying": fmt.Sprint(retrying),
			"terminal_failed": fmt.Sprint(terminalFailed), "oldest_age_seconds": fmt.Sprintf("%.0f", max(0, oldestAge.Seconds())),
		},
	}
	if !lastSuccess.IsZero() {
		observation.Details["last_success_at"] = lastSuccess.UTC().Format(time.RFC3339)
	}
	if !lastFailure.IsZero() {
		observation.Details["last_failure_at"] = lastFailure.UTC().Format(time.RFC3339)
	}
	if !lastTerminalFailure.IsZero() {
		observation.Details["last_terminal_failure_at"] = lastTerminalFailure.UTC().Format(time.RFC3339)
	}
	switch {
	case strings.TrimSpace(statsError) != "":
		observation.State, observation.Severity = StateDegraded, SeverityCritical
		observation.Reason = "webhook delivery statistics are unavailable"
	case oldestAge >= p.WebhookCriticalAge:
		observation.State, observation.Severity = StateDegraded, SeverityCritical
		observation.Reason = "oldest webhook delivery exceeded the critical age threshold"
	case oldestAge >= p.WebhookWarningAge:
		observation.State, observation.Severity = StateDegraded, SeverityWarning
		observation.Reason = "oldest webhook delivery exceeded the warning age threshold"
	case !lastTerminalFailure.IsZero() && lastTerminalFailure.After(lastSuccess) && now.Sub(lastTerminalFailure) >= 0 && now.Sub(lastTerminalFailure) <= p.WebhookCriticalAge:
		observation.State, observation.Severity = StateDegraded, SeverityWarning
		observation.Reason = "a webhook delivery recently exhausted its retry policy"
	}
	return observation
}

func (p Policy) QueueObservation(depth int, oldestAge time.Duration) Observation {
	observation := Observation{
		ID: "system-queue", Label: "System queue", Kind: "dependency", Desired: true, Required: true,
		State: StateHealthy, Details: map[string]string{"depth": fmt.Sprint(depth), "oldest_age_seconds": fmt.Sprintf("%.0f", max(0, oldestAge.Seconds()))},
	}
	if oldestAge >= p.QueueCriticalAge {
		observation.State, observation.Severity = StateDegraded, SeverityCritical
		observation.Reason = "oldest queued delivery exceeded the critical age threshold"
	} else if oldestAge >= p.QueueWarningAge {
		observation.State, observation.Severity = StateDegraded, SeverityWarning
		observation.Reason = "oldest queued delivery exceeded the warning age threshold"
	}
	return observation
}

// CertificateObservations reports assigned stored certificates only. Unused
// inventory cannot create operational alerts. Assignments maps stable stored
// certificate names to the protocol labels that consume them.
func (p Policy) CertificateObservations(now time.Time, certificates []model.TLSCertMetadata, assignments map[string][]string) []Observation {
	now = normalizedNow(now)
	byName := make(map[string]model.TLSCertMetadata, len(certificates))
	for _, certificate := range certificates {
		byName[certificate.Domain] = certificate
	}
	names := make([]string, 0, len(assignments))
	for name := range assignments {
		names = append(names, name)
	}
	sort.Strings(names)
	observations := make([]Observation, 0, len(names))
	for _, name := range names {
		consumers := append([]string(nil), assignments[name]...)
		sort.Strings(consumers)
		observation := Observation{
			ID: "certificate:" + name, Label: name, Kind: "certificate", Desired: true, Required: true,
			State: StateHealthy, Details: map[string]string{"assigned_to": strings.Join(consumers, ", ")},
		}
		certificate, found := byName[name]
		if !found {
			observation.State, observation.Severity = StateUnavailable, SeverityCritical
			observation.Reason = "assigned stored certificate is missing"
			observations = append(observations, observation)
			continue
		}
		remaining := certificate.NotAfter.Sub(now)
		observation.Details["expires_at"] = certificate.NotAfter.UTC().Format(time.RFC3339)
		observation.Details["remaining_seconds"] = fmt.Sprintf("%.0f", remaining.Seconds())
		switch {
		case !certificate.NotAfter.After(now):
			observation.State, observation.Severity = StateUnavailable, SeverityCritical
			observation.Reason = "assigned certificate has expired"
		case remaining <= p.CertCriticalAge:
			observation.State, observation.Severity = StateDegraded, SeverityCritical
			observation.Reason = "assigned certificate expires within the critical window"
		case remaining <= p.CertWarningAge:
			observation.State, observation.Severity = StateDegraded, SeverityWarning
			observation.Reason = "assigned certificate expires within the warning window"
		}
		observations = append(observations, observation)
	}
	return observations
}
