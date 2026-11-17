package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
	webapp "github.com/lkarlslund/veksel/pkg/web/app"
)

func TestExtractConfiguredPort(t *testing.T) {
	tests := []struct {
		address  string
		fallback int
		want     int
	}{
		{address: "0.0.0.0:587", fallback: 25, want: 587},
		{address: "[::]:993", fallback: 143, want: 993},
		{address: ":465", fallback: 25, want: 465},
		{address: "bad", fallback: 110, want: 110},
		{address: "127.0.0.1:70000", fallback: 110, want: 110},
	}
	for _, test := range tests {
		if got := extractConfiguredPort(test.address, test.fallback); got != test.want {
			t.Errorf("extractConfiguredPort(%q, %d) = %d, want %d", test.address, test.fallback, got, test.want)
		}
	}
}

func TestSelectedOutboundRoutePrefersAdministrativeOverride(t *testing.T) {
	message := &queue.Message{PolicyRoute: "policy.example"}
	if got := selectedOutboundRoute(message); got != "policy.example" {
		t.Fatalf("policy route = %q", got)
	}
	message.AdministrativeRoute = "operator.example"
	if got := selectedOutboundRoute(message); got != "operator.example" {
		t.Fatalf("administrative route = %q", got)
	}
	message.AdministrativeRoute = ""
	if got := selectedOutboundRoute(message); got != "policy.example" {
		t.Fatalf("restored automatic route = %q", got)
	}
}

func TestStoredCertificateAssignmentsIncludeOnlyEnabledConsumers(t *testing.T) {
	cfg := config.Default()
	cfg.HTTPListeners = append(cfg.HTTPListeners, config.HTTPListener{ID: "secure", Name: "Secure", Enabled: true, Transport: config.HTTPSTransport, Address: "0.0.0.0:8443", Certificate: "stored:web", Services: []string{"web"}, LogLevel: "inherit"})
	cfg.SmtpCertificate, cfg.ImapCertificate, cfg.Pop3Certificate = "stored:mail", "acme:imap.example", "stored:legacy"
	cfg.SmtpEnabled, cfg.ImapEnabled, cfg.ImapTLSEnabled, cfg.Pop3Enabled, cfg.Pop3TLSEnabled = true, true, true, false, false
	assignments := storedCertificateAssignments(cfg)
	if len(assignments) != 2 || assignments["web"][0] != "HTTP(S) listener Secure" || assignments["mail"][0] != "SMTP" {
		t.Fatalf("assignments = %#v", assignments)
	}
}

func TestPublishHealthTransitionsHonorsPolicyAndSilence(t *testing.T) {
	now := time.Now().UTC()
	transitions := []health.Transition{
		{Type: health.TransitionOpened, Alert: health.Alert{ID: "runtime:smtp", ComponentID: "smtp", ComponentLabel: "SMTP", State: health.AlertStateActive, Severity: health.SeverityCritical}},
		{Type: health.TransitionOpened, Alert: health.Alert{ID: "runtime:imap", ComponentID: "imap", ComponentLabel: "IMAP", State: health.AlertStateActive, Severity: health.SeverityWarning, SilencedUntil: now.Add(time.Hour)}},
	}
	var types []string
	published := publishHealthTransitions(now, true, transitions, func(event events.Event) error {
		types = append(types, event.Type)
		return nil
	})
	if published != 1 || len(types) != 1 || types[0] != "health.alert.opened" {
		t.Fatalf("published=%d events=%v", published, types)
	}
	if got := publishHealthTransitions(now, true, transitions, func(events.Event) error { return errors.New("event stream unavailable") }); got != 0 {
		t.Fatalf("failed stream published=%d", got)
	}
	if got := publishHealthTransitions(now, false, transitions, func(events.Event) error { t.Fatal("published while disabled"); return nil }); got != 0 {
		t.Fatalf("disabled notifications published=%d", got)
	}
}

func TestProtocolHealthObservationUsesDesiredAndEffectiveState(t *testing.T) {
	disabled := protocolHealthObservation("imap", "IMAP", false, webapp.ProtocolRuntimeStatus{Error: "stale failure"})
	if disabled.State != health.StateDisabled || disabled.Desired || disabled.Required || disabled.Reason != "" {
		t.Fatalf("disabled observation = %#v", disabled)
	}
	down := protocolHealthObservation("smtp", "SMTP", true, webapp.ProtocolRuntimeStatus{Error: "bind failed"})
	if down.State != health.StateUnavailable || !down.Desired || !down.Required || down.Reason != "bind failed" {
		t.Fatalf("unavailable observation = %#v", down)
	}
	running := protocolHealthObservation("smtp", "SMTP", true, webapp.ProtocolRuntimeStatus{Running: true, Listeners: []string{"127.0.0.1:25"}, Error: "partial listener failed"})
	if running.State != health.StateDegraded || running.Reason != "partial listener failed" || running.Details["listeners"] != "127.0.0.1:25" {
		t.Fatalf("running observation = %#v", running)
	}
	excluded := sharedHTTPHealthObservation("ews", "EWS", true, false)
	if excluded.State != health.StateUnavailable || !strings.Contains(excluded.Reason, "excluded") {
		t.Fatalf("excluded observation = %#v", excluded)
	}
}

func TestMailPolicyAdmissionAppliesAndPersistsDecisions(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	policies, err := mailpolicy.NewService(t.Context(), mailpolicy.NewRepository(backend))
	if err != nil {
		t.Fatal(err)
	}
	replace := func(actions ...mailpolicy.Action) {
		t.Helper()
		_, err := policies.Replace(t.Context(), policies.Document().Revision, mailpolicy.Document{Rules: []mailpolicy.Rule{{
			ID: "submission", Name: "Submission policy", Enabled: true,
			Conditions: []mailpolicy.Condition{
				{Field: mailpolicy.FieldDirection, Operator: mailpolicy.OperatorEquals, Value: "submission"},
				{Field: mailpolicy.FieldAuthenticatedActor, Operator: mailpolicy.OperatorEquals, Value: "alice"},
			},
			Actions: actions,
		}}})
		if err != nil {
			t.Fatal(err)
		}
	}

	replace(
		mailpolicy.Action{Type: mailpolicy.ActionAddHeader, Header: "X-Veksel-Policy", Value: "matched"},
		mailpolicy.Action{Type: mailpolicy.ActionRoute, Value: "Relay.Example"},
	)
	message := &queue.Message{Direction: queue.DirectionOutbound, AuthenticatedActor: "alice", EnvelopeSender: "alice@example.test", Recipient: "bob@outside.test", Headers: map[string]string{"From": "alice@example.test", "Subject": "Hello"}, Body: []byte("body")}
	if err := mailPolicyAdmission(policies)(t.Context(), message); err != nil {
		t.Fatal(err)
	}
	if message.Policy.Revision != policies.Document().Revision || len(message.Policy.MatchedRuleIDs()) != 1 || message.PolicyRoute != "relay.example" || message.Headers["X-Veksel-Policy"] != "matched" {
		t.Fatalf("admitted message = %+v", message)
	}

	replace(mailpolicy.Action{Type: mailpolicy.ActionReject, Value: "blocked by test", EnhancedStatusCode: "5.7.1"})
	err = mailPolicyAdmission(policies)(t.Context(), message)
	var rejection *mailpolicy.RejectionError
	if !errors.As(err, &rejection) || rejection.Reason != "blocked by test" || rejection.EnhancedStatusCode != "5.7.1" {
		t.Fatalf("rejection = %#v, err = %v", rejection, err)
	}

	replace(mailpolicy.Action{Type: mailpolicy.ActionQuarantine, Value: "manual review"})
	message = &queue.Message{Direction: queue.DirectionOutbound, AuthenticatedActor: "alice", Recipient: "bob@outside.test", Headers: map[string]string{"Subject": "Review"}, Body: []byte("body"), TargetFolderID: "inbox", TargetOwnerID: "bob", PolicyRoute: "old"}
	if err := mailPolicyAdmission(policies)(t.Context(), message); err != nil {
		t.Fatal(err)
	}
	if message.Kind != "quarantine" || message.TargetFolderID != "" || message.TargetOwnerID != "" || message.PolicyRoute != "" || len(message.Content) == 0 || message.Attributes["scanner"] != "mail-policy" {
		t.Fatalf("quarantined message = %+v", message)
	}
}
