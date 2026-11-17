package health

import (
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

func testHealthPolicy() Policy {
	return Policy{QueueWarningAge: 15 * time.Minute, QueueCriticalAge: time.Hour, WebhookWarningAge: 5 * time.Minute, WebhookCriticalAge: 30 * time.Minute, StorageWarningFreePercent: 15, StorageCriticalFreePercent: 5, CertWarningAge: 30 * 24 * time.Hour, CertCriticalAge: 7 * 24 * time.Hour}
}

func TestPolicyValidatesStorageThresholdOrdering(t *testing.T) {
	policy := testHealthPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	policy.StorageCriticalFreePercent = policy.StorageWarningFreePercent
	if err := policy.Validate(); err == nil {
		t.Fatal("equal storage thresholds were accepted")
	}
}

func TestPolicyClassifiesWebhookBacklogAndRecentTerminalFailure(t *testing.T) {
	policy := testHealthPolicy()
	now := time.Now().UTC()
	critical := policy.WebhookObservation(now, 1, 0, 2, 0, 30*time.Minute, time.Time{}, time.Time{}, time.Time{}, "")
	if critical.State != StateDegraded || critical.Severity != SeverityCritical || critical.Required {
		t.Fatalf("critical observation = %#v", critical)
	}
	recentFailure := policy.WebhookObservation(now, 0, 0, 0, 1, 0, time.Time{}, now.Add(-time.Minute), now.Add(-time.Minute), "")
	if recentFailure.State != StateDegraded || recentFailure.Severity != SeverityWarning {
		t.Fatalf("recent failure observation = %#v", recentFailure)
	}
	recovered := policy.WebhookObservation(now, 0, 0, 0, 1, 0, now, now.Add(-time.Minute), now.Add(-time.Minute), "")
	if recovered.State != StateHealthy {
		t.Fatalf("recovered observation = %#v", recovered)
	}
}

func TestPolicyClassifiesQueueAgeWithoutFailingReadiness(t *testing.T) {
	policy := testHealthPolicy()
	for _, test := range []struct {
		name     string
		age      time.Duration
		state    string
		severity string
	}{
		{"fresh", time.Minute, StateHealthy, ""},
		{"warning", 15 * time.Minute, StateDegraded, SeverityWarning},
		{"critical", time.Hour, StateDegraded, SeverityCritical},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := policy.QueueObservation(3, test.age)
			if observation.State != test.state || observation.Severity != test.severity || !observation.Required {
				t.Fatalf("observation = %#v", observation)
			}
		})
	}
}

func TestPolicyReportsOnlyAssignedCertificates(t *testing.T) {
	policy := testHealthPolicy()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	certificates := []model.TLSCertMetadata{
		{Domain: "unused", NotAfter: now.Add(-time.Hour)},
		{Domain: "warning", NotAfter: now.Add(20 * 24 * time.Hour)},
		{Domain: "critical", NotAfter: now.Add(2 * 24 * time.Hour)},
		{Domain: "expired", NotAfter: now.Add(-time.Second)},
	}
	observations := policy.CertificateObservations(now, certificates, map[string][]string{
		"warning": {"HTTPS"}, "critical": {"IMAP", "SMTP"}, "expired": {"POP3"}, "missing": {"HTTPS"},
	})
	if len(observations) != 4 {
		t.Fatalf("observations = %#v", observations)
	}
	states := make(map[string]Observation)
	for _, observation := range observations {
		states[observation.ID] = observation
	}
	if states["certificate:warning"].Severity != SeverityWarning || states["certificate:critical"].Severity != SeverityCritical || states["certificate:expired"].State != StateUnavailable || states["certificate:missing"].State != StateUnavailable {
		t.Fatalf("certificate states = %#v", states)
	}
}
