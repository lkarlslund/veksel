package alertnotify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type sinks struct {
	mu       sync.Mutex
	mails    []string
	subjects []string
	events   []string
	pushes   []PushBody
	auth     []string
	mailErr  error
	hookErr  error
}

func (s *sinks) channels() Channels {
	return Channels{
		Mail: func(_ context.Context, recipient string, message Message) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.mailErr != nil {
				return s.mailErr
			}
			s.mails = append(s.mails, recipient)
			s.subjects = append(s.subjects, message.Subject)
			return nil
		},
		Webhook: func(event string, _ any) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.hookErr != nil {
				return s.hookErr
			}
			s.events = append(s.events, event)
			return nil
		},
	}
}

func (s *sinks) server(t *testing.T, status int) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body PushBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode push: %v", err)
		}
		s.mu.Lock()
		s.pushes = append(s.pushes, body)
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		s.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *sinks) counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.mails), len(s.events), len(s.pushes)
}

type fixture struct {
	backend  store.Store
	alerts   *health.AlertStore
	notifier *Notifier
	sinks    *sinks
	now      time.Time
}

func newFixture(t *testing.T, policy Policy) *fixture {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	f := &fixture{backend: backend, sinks: &sinks{}, now: time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)}
	f.alerts, err = health.NewAlertStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	f.notifier = f.newNotifier(t, policy)
	return f
}

func (f *fixture) newNotifier(t *testing.T, policy Policy) *Notifier {
	t.Helper()
	notifier, err := New(f.alerts, f.backend, f.sinks.channels(), policy)
	if err != nil {
		t.Fatal(err)
	}
	notifier.now = func() time.Time { return f.now }
	return notifier
}

// observe evaluates one snapshot in which every listed component shares
// one unhealthy state.
func (f *fixture) observe(t *testing.T, ids, state, severity string) {
	t.Helper()
	var components []health.Component
	for _, id := range strings.Split(ids, ",") {
		components = append(components, health.Component{Observation: health.Observation{
			ID: id, Label: strings.ToUpper(id), Kind: "listener", Desired: true, Required: true, State: state, Severity: severity, Reason: "probe " + state,
		}, Since: f.now, ObservedAt: f.now})
	}
	if _, err := f.alerts.Evaluate(t.Context(), health.Snapshot{GeneratedAt: f.now, Components: components}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) healthy(t *testing.T) {
	t.Helper()
	if _, err := f.alerts.Evaluate(t.Context(), health.Snapshot{GeneratedAt: f.now}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) process(t *testing.T) {
	t.Helper()
	if err := f.notifier.Process(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) alert(t *testing.T, id string) health.Alert {
	t.Helper()
	alerts, err := f.alerts.List(t.Context(), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, alert := range alerts {
		if alert.ID == id {
			return alert
		}
	}
	t.Fatalf("alert %s not found", id)
	return health.Alert{}
}

// immediate is the test delivery policy; push receivers are loopback test
// servers, so private networks are allowed.
func immediate() Policy {
	return Policy{Enabled: true, Recipients: []string{"ops@example.com", "oncall@example.com"}, Digest: config.AlertDigestOff, AllowPrivateNetworks: true}
}

func TestStateChangesNotifyEveryChannelOnce(t *testing.T) {
	policy := immediate()
	f := newFixture(t, policy)
	server := f.sinks.server(t, http.StatusOK)
	policy.URL, policy.Token = server.URL+"/message", "push-secret"
	f.notifier.SetPolicy(policy)

	f.observe(t, "smtp", health.StateUnavailable, health.SeverityCritical)
	f.process(t)
	if mails, events, pushes := f.sinks.counts(); mails != 2 || events != 1 || pushes != 1 {
		t.Fatalf("opened deliveries mail=%d webhook=%d push=%d", mails, events, pushes)
	}
	if f.sinks.events[0] != "health.alert.opened" || !strings.Contains(f.sinks.subjects[0], "CRITICAL: SMTP alert opened") {
		t.Fatalf("opened event=%q subject=%q", f.sinks.events[0], f.sinks.subjects[0])
	}
	push := f.sinks.pushes[0]
	if f.sinks.auth[0] != "Bearer push-secret" || push.Event != "health.alert.opened" || push.Priority != 5 || push.Source != "veksel" || push.Data["component_id"] != "smtp" {
		t.Fatalf("push auth=%q body=%#v", f.sinks.auth[0], push)
	}
	if note := f.alert(t, "runtime:smtp").Notification; note.Pending != "" || note.LastOutcome != OutcomeSent || note.LastType != health.TransitionOpened {
		t.Fatalf("notification state = %#v", note)
	}

	// Repeated evidence is not a state change.
	f.now = f.now.Add(time.Minute)
	f.observe(t, "smtp", health.StateUnavailable, health.SeverityCritical)
	f.process(t)
	if mails, events, pushes := f.sinks.counts(); mails != 2 || events != 1 || pushes != 1 {
		t.Fatalf("repeat deliveries mail=%d webhook=%d push=%d", mails, events, pushes)
	}

	f.now = f.now.Add(time.Minute)
	f.healthy(t)
	f.process(t)
	if mails, events, pushes := f.sinks.counts(); mails != 4 || events != 2 || pushes != 2 {
		t.Fatalf("resolved deliveries mail=%d webhook=%d push=%d", mails, events, pushes)
	}
	if f.sinks.events[1] != "health.alert.resolved" || f.sinks.pushes[1].Priority != 3 || !strings.HasPrefix(f.sinks.subjects[2], "[Veksel] Resolved: SMTP") {
		t.Fatalf("resolved event=%q push=%#v subject=%q", f.sinks.events[1], f.sinks.pushes[1], f.sinks.subjects[2])
	}
}

func TestMinimumIntervalCoalescesFlapsAndLetsEscalationsThrough(t *testing.T) {
	policy := immediate()
	policy.Recipients, policy.MinInterval = nil, 30*time.Minute
	f := newFixture(t, policy)
	start := f.now

	f.observe(t, "imap", health.StateDegraded, health.SeverityWarning)
	f.process(t)
	f.now = start.Add(time.Minute)
	f.healthy(t)
	f.process(t) // deferred: inside the interval
	f.now = start.Add(2 * time.Minute)
	f.observe(t, "imap", health.StateDegraded, health.SeverityWarning)
	f.process(t) // back to the notified state: coalesced
	if _, events, _ := f.sinks.counts(); events != 1 {
		t.Fatalf("flap events = %v", f.sinks.events)
	}
	if note := f.alert(t, "runtime:imap").Notification; note.Pending != "" || note.Suppressed != 1 || note.LastOutcome != OutcomeCoalesced {
		t.Fatalf("coalesced notification = %#v", note)
	}

	f.now = start.Add(3 * time.Minute)
	f.observe(t, "imap", health.StateUnavailable, health.SeverityCritical)
	f.process(t) // escalation bypasses the interval
	f.now = start.Add(4 * time.Minute)
	f.healthy(t)
	f.process(t) // deferred
	if _, events, _ := f.sinks.counts(); events != 2 || f.sinks.events[1] != "health.alert.escalated" {
		t.Fatalf("escalation events = %v", f.sinks.events)
	}
	f.now = start.Add(40 * time.Minute)
	f.process(t)
	if _, events, _ := f.sinks.counts(); events != 3 || f.sinks.events[2] != "health.alert.resolved" {
		t.Fatalf("deferred resolution events = %v", f.sinks.events)
	}
}

func TestDailyDigestBatchesChanges(t *testing.T) {
	policy := immediate()
	policy.Recipients, policy.Digest = []string{"ops@example.com"}, config.AlertDigestDaily
	f := newFixture(t, policy)
	start := f.now
	f.process(t) // starts the digest schedule
	f.observe(t, "smtp", health.StateUnavailable, health.SeverityCritical)
	f.process(t)
	f.now = start.Add(time.Hour)
	f.observe(t, "smtp,pop3", health.StateUnavailable, health.SeverityCritical)
	f.process(t)
	if mails, events, _ := f.sinks.counts(); mails != 0 || events != 0 {
		t.Fatalf("digest sent early: mails=%d events=%d", mails, events)
	}
	status, err := f.notifier.Status(t.Context())
	if err != nil || status.Pending != 2 || !status.NextDigestAt.Equal(start.Add(24*time.Hour)) {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	f.now = start.Add(25 * time.Hour)
	f.process(t)
	if mails, events, _ := f.sinks.counts(); mails != 1 || events != 1 || f.sinks.events[0] != EventDigest || !strings.Contains(f.sinks.subjects[0], "Alert digest: 2 change(s)") {
		t.Fatalf("digest mails=%v events=%v subjects=%v", f.sinks.mails, f.sinks.events, f.sinks.subjects)
	}
	if pending, _ := f.alerts.PendingNotifications(t.Context()); len(pending) != 0 {
		t.Fatalf("pending after digest = %#v", pending)
	}
	f.now = start.Add(26 * time.Hour)
	f.process(t)
	if mails, _, _ := f.sinks.counts(); mails != 1 {
		t.Fatalf("digest repeated: %d", mails)
	}
}

func TestPendingNotificationSurvivesRestartAndIsNotRepeated(t *testing.T) {
	f := newFixture(t, immediate())
	f.observe(t, "smtp", health.StateUnavailable, health.SeverityCritical)
	// The process "crashes" before delivering: a fresh notifier on the same
	// backend picks the pending transition up.
	restarted := f.newNotifier(t, immediate())
	if err := restarted.Process(t.Context()); err != nil {
		t.Fatal(err)
	}
	again := f.newNotifier(t, immediate())
	if err := again.Process(t.Context()); err != nil {
		t.Fatal(err)
	}
	if mails, events, _ := f.sinks.counts(); mails != 2 || events != 1 {
		t.Fatalf("restart deliveries mail=%d webhook=%d", mails, events)
	}
}

func TestFailedDeliveryRetriesWithBackoff(t *testing.T) {
	f := newFixture(t, immediate())
	f.sinks.mailErr, f.sinks.hookErr = errors.New("queue full"), errors.New("store down")
	f.observe(t, "smtp", health.StateUnavailable, health.SeverityCritical)
	f.process(t)
	note := f.alert(t, "runtime:smtp").Notification
	if note.Pending != health.TransitionOpened || note.Attempts != 1 || !note.NextAttemptAt.Equal(f.now.Add(time.Minute)) || !strings.Contains(note.LastError, "queue full") {
		t.Fatalf("failed notification = %#v", note)
	}
	f.sinks.mailErr, f.sinks.hookErr = nil, nil
	f.now = f.now.Add(30 * time.Second)
	f.process(t)
	if mails, _, _ := f.sinks.counts(); mails != 0 {
		t.Fatal("retried before backoff elapsed")
	}
	f.now = f.now.Add(time.Minute)
	f.process(t)
	if mails, events, _ := f.sinks.counts(); mails != 2 || events != 1 {
		t.Fatalf("retry deliveries mail=%d webhook=%d", mails, events)
	}
}

func TestSilencedAndDisabledAlertsAreNotDelivered(t *testing.T) {
	policy := immediate()
	f := newFixture(t, policy)
	f.observe(t, "smtp", health.StateUnavailable, health.SeverityCritical)
	if _, err := f.alerts.Silence(t.Context(), "runtime:smtp", "admin", "maintenance", time.Hour, f.now); err != nil {
		t.Fatal(err)
	}
	f.process(t)
	policy.Enabled = false
	f.notifier.SetPolicy(policy)
	f.observe(t, "smtp,pop3", health.StateUnavailable, health.SeverityCritical)
	f.process(t)
	if mails, events, _ := f.sinks.counts(); mails != 0 || events != 0 {
		t.Fatalf("suppressed deliveries mail=%d webhook=%d", mails, events)
	}
	if note := f.alert(t, "runtime:smtp").Notification; note.Pending != "" || note.LastOutcome != OutcomeSilenced {
		t.Fatalf("silenced notification = %#v", note)
	}
	if note := f.alert(t, "runtime:pop3").Notification; note.Pending != "" || note.LastOutcome != OutcomeDisabled {
		t.Fatalf("disabled notification = %#v", note)
	}
	// Re-enabling does not replay transitions that happened while disabled,
	// and a resolution nobody was told about stays quiet.
	policy.Enabled = true
	f.notifier.SetPolicy(policy)
	f.healthy(t)
	f.process(t)
	if mails, events, _ := f.sinks.counts(); mails != 0 || events != 0 {
		t.Fatalf("unannounced resolution delivered mail=%d webhook=%d", mails, events)
	}
}

func TestPushSecretsStayOutOfStatusAndErrors(t *testing.T) {
	policy := immediate()
	policy.Recipients = nil
	f := newFixture(t, policy)
	server := f.sinks.server(t, http.StatusUnauthorized)
	policy.URL, policy.Token = server.URL+"/message?token=url-secret", "bearer-secret"
	f.notifier.SetPolicy(policy)
	results := f.notifier.Test(t.Context())
	if len(results) != 2 {
		t.Fatalf("test results = %#v", results)
	}
	status, err := f.notifier.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(struct {
		Results []ChannelResult
		Status  Status
	}{results, status})
	for _, secret := range []string{"url-secret", "bearer-secret", "/message"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("secret %q exposed: %s", secret, encoded)
		}
	}
	if !strings.Contains(string(encoded), "HTTP 401") || f.sinks.pushes[0].Event != EventTest {
		t.Fatalf("push failure evidence missing: %s", encoded)
	}

	policy.URL = "http://127.0.0.1:1/message?token=url-secret"
	f.notifier.SetPolicy(policy)
	for _, result := range f.notifier.Test(t.Context()) {
		if strings.Contains(result.Error, "url-secret") {
			t.Fatalf("transport error exposes URL secret: %q", result.Error)
		}
	}
}

func TestPushRefusesPrivateNetworksUnlessAllowed(t *testing.T) {
	policy := immediate()
	policy.Recipients, policy.AllowPrivateNetworks = nil, false
	f := newFixture(t, policy)
	server := f.sinks.server(t, http.StatusOK)
	policy.URL = server.URL + "/message?token=url-secret"
	f.notifier.SetPolicy(policy)
	results := f.notifier.Test(t.Context())
	if _, _, pushes := f.sinks.counts(); pushes != 0 || len(results) != 2 || results[1].OK || !strings.Contains(results[1].Error, "private") || strings.Contains(results[1].Error, "url-secret") {
		t.Fatalf("pushes = %d results = %#v", pushes, results)
	}
	policy.AllowPrivateNetworks = true
	f.notifier.SetPolicy(policy)
	if results := f.notifier.Test(t.Context()); len(results) != 2 || !results[1].OK {
		t.Fatalf("allowed push results = %#v", results)
	}
}

func TestComposeMailIsDeterministicAndAutoGenerated(t *testing.T) {
	message := Message{ID: "alert-runtime:smtp-1", Subject: "[Veksel] Résolu", Text: "line one\nline two", At: time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)}
	first := ComposeMail("Veksel Alerts <postmaster@example.com>", "ops@example.com", message)
	if string(first) != string(ComposeMail("Veksel Alerts <postmaster@example.com>", "ops@example.com", message)) {
		t.Fatal("composition is not deterministic")
	}
	for _, want := range []string{"Message-ID: <alert-runtime-smtp-1@example.com>\r\n", "Auto-Submitted: auto-generated\r\n", "Subject: =?utf-8?q?", "line one\r\nline two\r\n", "Date: Thu, 22 Oct 2026 08:00:00 +0000\r\n"} {
		if !strings.Contains(string(first), want) {
			t.Fatalf("message lacks %q:\n%s", want, first)
		}
	}
}

// A running webhook dispatcher only counts as an alert channel when some
// active subscription receives alert events; otherwise the setup checklist
// reported a delivery channel that drops every alert.
func TestWebhookChannelRequiresAlertSubscription(t *testing.T) {
	hook := func(string, any) error { return nil }
	for _, test := range []struct {
		channels Channels
		want     bool
	}{
		{Channels{}, false},
		{Channels{Webhook: hook}, true},
		{Channels{Webhook: hook, WebhookSubscribed: func(string) bool { return false }}, false},
		{Channels{Webhook: hook, WebhookSubscribed: func(event string) bool { return event == "health.alert.opened" }}, true},
	} {
		if got := test.channels.webhookConfigured(); got != test.want {
			t.Errorf("webhookConfigured() = %v, want %v", got, test.want)
		}
	}
}
