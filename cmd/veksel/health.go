package main

import (
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/certificates"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/health"
	webapp "github.com/lkarlslund/veksel/pkg/web/app"
)

func protocolHealthObservation(id, label string, desired bool, status webapp.ProtocolRuntimeStatus) health.Observation {
	observation := health.Observation{ID: id, Label: label, Kind: "listener", Desired: desired, Required: desired}
	if !desired {
		observation.State = health.StateDisabled
		return observation
	}
	observation.Details = map[string]string{"listeners": strings.Join(status.Listeners, ", ")}
	if status.Running {
		observation.State = health.StateHealthy
		if status.Error != "" {
			observation.State = health.StateDegraded
			observation.Reason = status.Error
		}
		return observation
	}
	observation.State = health.StateUnavailable
	observation.Reason = status.Error
	if observation.Reason == "" {
		observation.Reason = "enabled listener is not running"
	}
	return observation
}

func sharedHTTPHealthObservation(id, label string, desired, available bool) health.Observation {
	observation := health.Observation{ID: id, Label: label, Kind: "http-service", Desired: desired, Required: desired}
	if !desired {
		observation.State = health.StateDisabled
	} else if available {
		observation.State = health.StateHealthy
	} else {
		observation.State = health.StateUnavailable
		observation.Reason = "enabled service is excluded from this build"
	}
	return observation
}

func storedCertificateAssignments(cfg *config.Config) map[string][]string {
	assignments := make(map[string][]string)
	add := func(assignment, consumer string, enabled bool) {
		if !enabled || !strings.HasPrefix(assignment, certificates.StoredPrefix) {
			return
		}
		name := strings.TrimSpace(strings.TrimPrefix(assignment, certificates.StoredPrefix))
		if name != "" {
			assignments[name] = append(assignments[name], consumer)
		}
	}
	for _, listener := range cfg.HTTPListeners {
		add(listener.Certificate, "HTTP(S) listener "+listener.Name, listener.Enabled && listener.Transport == config.HTTPSTransport)
	}
	add(cfg.SmtpCertificate, "SMTP", cfg.SmtpEnabled || cfg.SmtpSubmissionEnabled || cfg.SmtpImplicitTLSEnabled)
	add(cfg.ImapCertificate, "IMAP", cfg.ImapEnabled || cfg.ImapTLSEnabled)
	add(cfg.Pop3Certificate, "POP3", cfg.Pop3Enabled || cfg.Pop3TLSEnabled)
	add(cfg.ManageSieveCertificate, "ManageSieve", cfg.ManageSieveEnabled || cfg.ManageSieveTLSEnabled)
	return assignments
}

// publishHealthTransitions streams transitions to signed-in administrators.
// Mail, webhook, and push delivery is the alert notifier's, which applies
// de-duplication, re-notify intervals, and digests.
func publishHealthTransitions(now time.Time, enabled bool, transitions []health.Transition, publish func(events.Event) error) int {
	if !enabled {
		return 0
	}
	published := 0
	for _, transition := range transitions {
		if transition.Alert.IsSilenced(now) {
			continue
		}
		eventType := "health.alert." + transition.Type
		payload := map[string]any{
			"alert_id": transition.Alert.ID, "component_id": transition.Alert.ComponentID,
			"component": transition.Alert.ComponentLabel, "severity": transition.Alert.Severity,
			"state": transition.Alert.State, "observed_state": transition.Alert.ObservedState,
			"reason": transition.Alert.Reason, "transition": transition.Type,
		}
		if publish != nil && publish(events.Event{Type: eventType, Resource: transition.Alert.ID, Data: payload, OccurredAt: now}) == nil {
			published++
		}
	}
	return published
}
