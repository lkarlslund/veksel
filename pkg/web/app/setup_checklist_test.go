package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dane"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/spam"
)

func TestSetupChecksFromEvidence(t *testing.T) {
	httpsConfig := func(certificate string, proxies ...string) *config.Config {
		cfg := config.Default()
		cfg.HTTPTrustedProxies = proxies
		if certificate != "" {
			cfg.HTTPListeners = append(cfg.HTTPListeners, config.HTTPListener{Name: "Public", Enabled: true, Transport: config.HTTPSTransport, Certificate: certificate})
		}
		return cfg
	}
	certificate := func(state, reason string) []health.Component {
		return []health.Component{{Observation: health.Observation{ID: "certificate:mail.example.test", State: state, Reason: reason, Details: map[string]string{"expires_at": "2027-01-01T00:00:00Z"}}}}
	}
	okGuidance := dnsGuidanceResponse{Domain: "example.test", Records: []dnsGuidanceRecord{{Type: "MX", Status: dnsOK}, {Type: "SPF", Status: dnsOK}, {Type: "DMARC", Status: dnsOK}, {Type: "DKIM", Status: dnsOK}}}
	missingGuidance := dnsGuidanceResponse{Domain: "other.test", Records: []dnsGuidanceRecord{{Type: "MX", Status: dnsOK}, {Type: "SPF", Status: dnsMissing}, {Type: "DMARC", Status: dnsOK}}}
	cases := []struct {
		name  string
		check func(setupEvidence) adminCheck
		in    setupEvidence
		want  string
	}{
		{"no domains", setupHostedDomain, setupEvidence{}, checkFail},
		{"domain lookup failure", setupHostedDomain, setupEvidence{DomainsErr: errors.New("store down")}, checkUnknown},
		{"only disabled domains", setupHostedDomain, setupEvidence{Domains: []model.Domain{{ID: "example.test"}}}, checkFail},
		{"hosted domain", setupHostedDomain, setupEvidence{Domains: []model.Domain{{ID: "example.test", Enabled: true}}}, checkPass},
		{"single-label host name", setupHostName, setupEvidence{ServerName: "localhost"}, checkFail},
		{"fqdn host name", setupHostName, setupEvidence{ServerName: "mail.example.test"}, checkPass},
		{"mail health unknown", setupMailTLS, setupEvidence{}, checkUnknown},
		{"smtp without certificate", setupMailTLS, setupEvidence{healthKnown: true, Health: []health.Component{{Observation: health.Observation{ID: "smtp", Label: "SMTP and submission", State: health.StateDegraded, Reason: "SMTP has no assigned certificate, so STARTTLS is unavailable"}}}}, checkFail},
		{"submission without certificate", setupMailTLS, setupEvidence{healthKnown: true, Health: []health.Component{{Observation: health.Observation{ID: "smtp", State: health.StateDegraded, Reason: "submission is enabled but no certificate is assigned"}}}}, checkFail},
		{"mail listeners with tls", setupMailTLS, setupEvidence{healthKnown: true, Health: []health.Component{{Observation: health.Observation{ID: "smtp", State: health.StateHealthy}}, {Observation: health.Observation{ID: "imap", State: health.StateDisabled, Reason: "IMAP has no assigned certificate"}}}}, checkPass},
		{"no https listener", setupHTTPSCertificate, setupEvidence{Config: httpsConfig("")}, checkFail},
		{"tls at reverse proxy", setupHTTPSCertificate, setupEvidence{Config: httpsConfig("", "10.0.0.1")}, checkWarn},
		{"acme certificate", setupHTTPSCertificate, setupEvidence{Config: httpsConfig("acme:mail.example.test")}, checkPass},
		{"valid stored certificate", setupHTTPSCertificate, setupEvidence{Config: httpsConfig("stored:mail.example.test"), Health: certificate(health.StateHealthy, ""), healthKnown: true}, checkPass},
		{"expiring certificate", setupHTTPSCertificate, setupEvidence{Config: httpsConfig("stored:mail.example.test"), Health: certificate(health.StateDegraded, "expires soon"), healthKnown: true}, checkWarn},
		{"expired certificate", setupHTTPSCertificate, setupEvidence{Config: httpsConfig("stored:mail.example.test"), Health: certificate(health.StateUnavailable, "expired"), healthKnown: true}, checkFail},
		{"certificate health unknown", setupHTTPSCertificate, setupEvidence{Config: httpsConfig("stored:mail.example.test")}, checkUnknown},
		{"dns published", setupMailDNS, setupEvidence{DNS: []dnsGuidanceResponse{okGuidance}}, checkPass},
		{"dns missing spf and dkim", setupMailDNS, setupEvidence{DNS: []dnsGuidanceResponse{okGuidance, missingGuidance}}, checkFail},
		{"dns without domains", setupMailDNS, setupEvidence{}, checkUnknown},
		{"ptr confirmed", setupReverseDNS, setupEvidence{PTR: []dnsGuidanceRecord{{Name: "192.0.2.10", Status: dnsOK, Live: []string{"mail.example.test."}}}}, checkPass},
		{"ptr mismatch", setupReverseDNS, setupEvidence{PTR: []dnsGuidanceRecord{{Name: "192.0.2.10", Status: dnsMismatch, Live: []string{"dsl-1.isp.example."}}}}, checkFail},
		{"port 25 not probed", setupOutboundPort25, setupEvidence{}, checkUnknown},
		{"port 25 open", setupOutboundPort25, setupEvidence{Port25: &port25Result{Target: "mx:25", OK: true, Banner: "220 mx"}}, checkPass},
		{"port 25 blocked", setupOutboundPort25, setupEvidence{Port25: &port25Result{Target: "mx:25", Error: "i/o timeout"}}, checkFail},
		{"backups off", setupScheduledBackups, setupEvidence{Backup: &backup.ScheduleStatus{Schedule: "off"}}, checkFail},
		{"backups inside data dir", setupScheduledBackups, setupEvidence{Backup: &backup.ScheduleStatus{Enabled: true, Downloadable: true, Directory: "/var/lib/veksel/backups"}}, checkWarn},
		{"backups failed", setupScheduledBackups, setupEvidence{Backup: &backup.ScheduleStatus{Enabled: true, Directory: "/mnt/backup", State: backup.ScheduleState{LastResult: backup.ResultFailed, LastError: "disk full"}}}, checkFail},
		{"backups elsewhere", setupScheduledBackups, setupEvidence{Backup: &backup.ScheduleStatus{Enabled: true, Schedule: "daily 02:00", Directory: "/mnt/backup"}}, checkPass},
		{"alerts unavailable", setupAlertDelivery, setupEvidence{}, checkUnknown},
		{"alerts disabled", setupAlertDelivery, setupEvidence{Alerts: &alertnotify.Status{}}, checkFail},
		{"alerts without channel", setupAlertDelivery, setupEvidence{Alerts: &alertnotify.Status{Enabled: true, Channels: []alertnotify.ChannelStatus{{Label: "Email"}}}}, checkFail},
		{"alerts by email", setupAlertDelivery, setupEvidence{Alerts: &alertnotify.Status{Enabled: true, Channels: []alertnotify.ChannelStatus{{Label: "Email", Configured: true}}}}, checkPass},
		{"validating resolver", setupLocalResolver, setupEvidence{DANE: dane.Status{Validating: dane.ValidatingYes}, Health: []health.Component{{Observation: health.Observation{ID: "antispam-dns", State: health.StateHealthy}}}}, checkPass},
		{"blocklists refuse resolver", setupLocalResolver, setupEvidence{DANE: dane.Status{Validating: dane.ValidatingYes}, Health: []health.Component{{Observation: health.Observation{ID: "antispam-dns", State: health.StateDegraded, Reason: "refused"}}}}, checkWarn},
		{"non-validating resolver", setupLocalResolver, setupEvidence{DANE: dane.Status{Validating: dane.ValidatingNo}}, checkWarn},
		{"trace unavailable", setupTestDelivery, setupEvidence{}, checkUnknown},
		{"no test delivered", setupTestDelivery, setupEvidence{TraceKnown: true}, checkWarn},
		{"test delivered", setupTestDelivery, setupEvidence{TraceKnown: true, Delivered: &messagetrace.Record{Recipient: "probe@example.net"}}, checkPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.check(tc.in)
			if got.Status != tc.want || got.ID == "" || got.Label == "" || got.Detail == "" {
				t.Fatalf("check = %+v, want status %s", got, tc.want)
			}
			if got.FixURL == "" && got.Action == "" {
				t.Fatalf("check %s offers no fix", got.ID)
			}
		})
	}
	if check := setupAdminTwoFactor(model.SecondFactors{}, nil); check.Status != checkFail {
		t.Fatalf("two-factor without factors = %+v", check)
	}
	if check := setupAdminTwoFactor(model.SecondFactors{TOTP: &model.TOTPFactor{}}, nil); check.Status != checkPass {
		t.Fatalf("two-factor with TOTP = %+v", check)
	}
}

// countingResolver counts every lookup of the wrapped fake.
type countingResolver struct {
	fakeDNSResolver
	lookups *atomic.Int64
}

func (c countingResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	c.lookups.Add(1)
	return c.fakeDNSResolver.LookupMX(ctx, name)
}

func (c countingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	c.lookups.Add(1)
	return c.fakeDNSResolver.LookupTXT(ctx, name)
}

func (c countingResolver) LookupHost(ctx context.Context, name string) ([]string, error) {
	c.lookups.Add(1)
	return c.fakeDNSResolver.LookupHost(ctx, name)
}

func (c countingResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	c.lookups.Add(1)
	return c.fakeDNSResolver.LookupAddr(ctx, addr)
}

// blocklistResolver answers DNSBL queries by name, without the trailing dot.
type blocklistResolver map[string][]string

func (b blocklistResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if answers, ok := b[strings.TrimSuffix(host, ".")]; ok {
		return answers, nil
	}
	return nil, notFound(host)
}

// setupFixture is a signed-in owner with a hosted domain, an identity, a
// DKIM-signing queue, message trace, and fake DNS for every lookup.
type setupFixture struct {
	handler   *Handler
	ts        *model.TypedStore
	server    *httptest.Server
	client    *http.Client
	csrf      string
	traces    *messagetrace.Store
	queue     *queue.Queue
	dns       *fakeDNSResolver
	lookups   *atomic.Int64
	publicKey string
}

func newSetupFixture(t *testing.T) *setupFixture {
	t.Helper()
	handler, ts := testHandler(t)
	traces, err := messagetrace.New(t.Context(), ts.Store())
	if err != nil {
		t.Fatal(err)
	}
	handler.SetMessageTrace(traces)
	mailQueue := queue.New(&queue.Config{ProcessPeriod: time.Hour, Signer: dkim.NewSigner(ts.DomainStore())})
	t.Cleanup(mailQueue.Close)
	handler.SetSystemQueue(mailQueue)
	cfg := config.Default()
	cfg.SmtpServerName = "mail.example.test"
	handler.ConfigureAdministration(cfg, nil)
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	private, public, err := dkim.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.DomainStore().SetDKIMKeys(t.Context(), "example.test", string(private), string(public), "s1"); err != nil {
		t.Fatal(err)
	}
	f := &setupFixture{handler: handler, ts: ts, traces: traces, queue: mailQueue, lookups: &atomic.Int64{}, publicKey: string(public)}
	f.dns = &fakeDNSResolver{
		mx: map[string][]*net.MX{"example.test": {{Host: "mail.example.test.", Pref: 10}}, port25ProbeDomain: {{Host: "mx.probe.example.", Pref: 5}}},
		txt: map[string][]string{
			"example.test":               {"v=spf1 mx -all"},
			"_dmarc.example.test":        {"v=DMARC1; p=reject"},
			"s1._domainkey.example.test": {dkim.DKIMDNSRecord(public)},
		},
		host: map[string][]string{"mail.example.test": {"192.0.2.10"}},
		addr: map[string][]string{"192.0.2.10": {"mail.example.test."}},
	}
	handler.SetDNSResolver(countingResolver{fakeDNSResolver: *f.dns, lookups: f.lookups})
	mux := http.NewServeMux()
	handler.Register(mux)
	f.server = serveTestApp(t, handler, mux)
	t.Cleanup(f.server.Close)
	f.client = testClient(t)
	f.csrf = setupAndLogin(t, f.server, f.client, "owner")
	if err := ts.UserStore().AddEmailAddress(t.Context(), "owner@example.test", "owner", "example.test", true); err != nil {
		t.Fatal(err)
	}
	return f
}

// setResolver replaces the fake DNS after the fixture's tables changed.
func (f *setupFixture) setResolver() {
	f.handler.SetDNSResolver(countingResolver{fakeDNSResolver: *f.dns, lookups: f.lookups})
}

func (f *setupFixture) request(t *testing.T, method, path, body string, status int) []byte {
	t.Helper()
	response := authenticatedJSON(t, f.client, method, f.server.URL+path, f.csrf, body)
	defer func() { _ = response.Body.Close() }()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != status {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, response.StatusCode, status, data)
	}
	return data
}

func checkByID(t *testing.T, checks []adminCheck, id string) adminCheck {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("no %s check in %+v", id, checks)
	return adminCheck{}
}

func TestSetupChecklistAggregatesAndCaches(t *testing.T) {
	f := newSetupFixture(t)
	checklist := decodeInto[setupChecklistResponse](t, f.request(t, http.MethodGet, "/api/v1/admin/setup-checklist", "", http.StatusOK))
	if len(checklist.Checks) != len(setupCheckIDs) {
		t.Fatalf("checks = %d, want %d: %+v", len(checklist.Checks), len(setupCheckIDs), checklist.Checks)
	}
	for index, check := range checklist.Checks {
		if check.ID != setupCheckIDs[index] {
			t.Fatalf("check %d = %s, want %s", index, check.ID, setupCheckIDs[index])
		}
	}
	for id, want := range map[string]string{
		"hosted-domain": checkPass, "host-name": checkPass, "mail-dns": checkPass, "reverse-dns": checkPass,
		"outbound-port25": checkUnknown, "scheduled-backups": checkFail, "admin-two-factor": checkFail, "test-delivery": checkWarn,
	} {
		if check := checkByID(t, checklist.Checks, id); check.Status != want {
			t.Errorf("%s = %+v, want %s", id, check, want)
		}
	}
	if checklist.Passed+checklist.Attention != len(setupCheckIDs) || len(checklist.Identities) != 1 || checklist.Identities[0] != "owner@example.test" {
		t.Fatalf("summary = %+v", checklist)
	}
	gathered := f.lookups.Load()
	if gathered == 0 {
		t.Fatal("checklist did not consult DNS")
	}
	cached := decodeInto[setupChecklistResponse](t, f.request(t, http.MethodGet, "/api/v1/admin/setup-checklist", "", http.StatusOK))
	if f.lookups.Load() != gathered || !cached.CheckedAt.Equal(checklist.CheckedAt) {
		t.Fatalf("second view re-ran DNS lookups (%d → %d)", gathered, f.lookups.Load())
	}
	f.dns.txt["example.test"] = []string{"v=spf1 ip4:198.51.100.1 -all"}
	f.setResolver()
	refreshed := decodeInto[setupChecklistResponse](t, f.request(t, http.MethodGet, "/api/v1/admin/setup-checklist?refresh=1", "", http.StatusOK))
	if f.lookups.Load() == gathered || !refreshed.CheckedAt.After(checklist.CheckedAt) {
		t.Fatal("refresh reused cached evidence")
	}
	if check := checkByID(t, refreshed.Checks, "mail-dns"); check.Status != checkFail || !strings.Contains(strings.Join(check.Items, " "), "SPF mismatch") {
		t.Fatalf("refreshed mail-dns = %+v", check)
	}
}

func TestSetupChecklistDismissalPersists(t *testing.T) {
	f := newSetupFixture(t)
	f.request(t, http.MethodPut, "/api/v1/admin/setup-checklist/dismissals", `{"id":"unknown","dismissed":true}`, http.StatusBadRequest)
	checklist := decodeInto[setupChecklistResponse](t, f.request(t, http.MethodPut, "/api/v1/admin/setup-checklist/dismissals", `{"id":"scheduled-backups","dismissed":true}`, http.StatusOK))
	if check := checkByID(t, checklist.Checks, "scheduled-backups"); !check.Dismissed || checklist.Dismissed != 1 {
		t.Fatalf("dismissed checklist = %+v", checklist)
	}
	// A fresh handler over the same store still sees the dismissal.
	restarted, err := New(f.ts)
	if err != nil {
		t.Fatal(err)
	}
	if _, dismissed := restarted.setupDismissed(t.Context())["scheduled-backups"]; !dismissed {
		t.Fatal("dismissal was not persisted")
	}
	checklist = decodeInto[setupChecklistResponse](t, f.request(t, http.MethodPut, "/api/v1/admin/setup-checklist/dismissals", `{"id":"scheduled-backups","dismissed":false}`, http.StatusOK))
	if check := checkByID(t, checklist.Checks, "scheduled-backups"); check.Dismissed || checklist.Dismissed != 0 {
		t.Fatalf("restored checklist = %+v", checklist)
	}
}

func TestSetupChecklistPort25Probe(t *testing.T) {
	f := newSetupFixture(t)
	var dialed string
	f.handler.port25Dial = func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		client, remote := net.Pipe()
		go func() {
			_, _ = remote.Write([]byte("220 mx.probe.example ESMTP ready\r\n"))
			_ = remote.Close()
		}()
		return client, nil
	}
	checklist := decodeInto[setupChecklistResponse](t, f.request(t, http.MethodPost, "/api/v1/admin/setup-checklist/port25-probe", "", http.StatusOK))
	if check := checkByID(t, checklist.Checks, "outbound-port25"); check.Status != checkPass || dialed != "mx.probe.example:25" {
		t.Fatalf("port 25 = %+v (dialed %q)", check, dialed)
	}
	f.handler.port25Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection timed out")
	}
	checklist = decodeInto[setupChecklistResponse](t, f.request(t, http.MethodPost, "/api/v1/admin/setup-checklist/port25-probe", "", http.StatusOK))
	if check := checkByID(t, checklist.Checks, "outbound-port25"); check.Status != checkFail || !strings.Contains(check.Detail, "timed out") {
		t.Fatalf("blocked port 25 = %+v", check)
	}
}

func TestSetupAndDeliverabilityRequireSystemAdministrator(t *testing.T) {
	f := newDomainAdminFixture(t)
	alice, aliceTok := loginAs(t, f.server, "alice")
	requests := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/admin/setup-checklist", ""},
		{http.MethodPut, "/api/v1/admin/setup-checklist/dismissals", `{"id":"host-name","dismissed":true}`},
		{http.MethodPost, "/api/v1/admin/setup-checklist/port25-probe", ""},
		{http.MethodPost, "/api/v1/admin/deliverability/self-test", `{"from":"dana@a.test"}`},
		{http.MethodGet, "/api/v1/admin/deliverability/messages/deliverability-test-00", ""},
	}
	for _, request := range requests {
		f.expect(t, f.dana, f.danaTok, request.method, request.path, request.body, http.StatusForbidden)
		f.expect(t, alice, aliceTok, request.method, request.path, request.body, http.StatusForbidden)
	}
}

var _ SpamBlocklists = (*spam.DNS)(nil)
