package app

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// deliverabilityFixture returns local checks for example.test with an
// active DKIM key, sending from 192.0.2.10, over fully passing fake DNS.
func deliverabilityFixture(t *testing.T) (deliverabilityChecks, *fakeDNSResolver, blocklistResolver) {
	t.Helper()
	private, public, err := dkim.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	domain := model.Domain{ID: "example.test", Enabled: true, DKIMKeys: []model.DKIMKey{{Selector: "s1", PrivateKey: string(private), PublicKey: string(public), State: model.DKIMKeyActive}}}
	resolver := &fakeDNSResolver{
		mx: map[string][]*net.MX{"example.test": {{Host: "mail.example.test.", Pref: 10}}},
		txt: map[string][]string{
			"example.test":               {"v=spf1 ip4:192.0.2.10 -all"},
			"_dmarc.example.test":        {"v=DMARC1; p=quarantine"},
			"s1._domainkey.example.test": {dkim.DKIMDNSRecord(public)},
		},
		host: map[string][]string{"mail.example.test": {"192.0.2.10"}},
		addr: map[string][]string{"192.0.2.10": {"mail.example.test."}},
	}
	zones, err := spam.ParseZones(spam.ZoneDNSBL, []string{"zen.spamhaus.org", "b.barracudacentral.org"})
	if err != nil {
		t.Fatal(err)
	}
	listings := blocklistResolver{}
	checks := deliverabilityChecks{resolver: resolver, blocklists: spam.NewDNS(listings, spam.DNSOptions{QueryTimeout: time.Second}), zones: zones,
		server: "mail.example.test", domain: domain, from: "owner@example.test", addrs: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	return checks, resolver, listings
}

func findingStatuses(findings []adminCheck) map[string]string {
	statuses := make(map[string]string, len(findings))
	for _, finding := range findings {
		statuses[finding.ID] = finding.Status
	}
	return statuses
}

func TestDeliverabilityLocalChecksPass(t *testing.T) {
	checks, _, _ := deliverabilityFixture(t)
	findings := checks.run(t.Context())
	for id, status := range findingStatuses(findings) {
		if status != checkPass {
			t.Errorf("%s = %s, want pass: %+v", id, status, findings)
		}
	}
	if len(findings) != 5 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestDeliverabilityLocalChecksFail(t *testing.T) {
	checks, resolver, listings := deliverabilityFixture(t)
	_, otherPublic, err := dkim.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	resolver.txt["example.test"] = []string{"v=spf1 ip4:198.51.100.1 -all"}
	resolver.txt["s1._domainkey.example.test"] = []string{dkim.DKIMDNSRecord(otherPublic)}
	resolver.addr["192.0.2.10"] = []string{"dsl-192-0-2-10.isp.example."}
	listings["10.2.0.192.zen.spamhaus.org"] = []string{"127.0.0.2"}
	findings := checks.run(t.Context())
	for id, want := range map[string]string{"spf": checkFail, "dkim": checkFail, "dmarc": checkFail, "reverse-dns": checkFail, "dnsbl": checkFail} {
		finding := checkByID(t, findings, id)
		if finding.Status != want || finding.Remediation == "" {
			t.Errorf("%s = %+v, want %s with remediation", id, finding, want)
		}
	}
	if items := strings.Join(checkByID(t, findings, "dnsbl").Items, " "); !strings.Contains(items, "zen.spamhaus.org") || strings.Contains(items, "barracuda") {
		t.Fatalf("dnsbl items = %q, want only the zen listing", items)
	}
}

func TestDeliverabilityDMARCMonitoringAndMissing(t *testing.T) {
	checks, resolver, _ := deliverabilityFixture(t)
	resolver.txt["_dmarc.example.test"] = []string{"v=DMARC1; p=none"}
	if finding := checks.dmarc(t.Context(), true, true); finding.Status != checkWarn {
		t.Fatalf("p=none = %+v, want warn", finding)
	}
	delete(resolver.txt, "_dmarc.example.test")
	if finding := checks.dmarc(t.Context(), true, true); finding.Status != checkFail || !strings.Contains(finding.Remediation, "_dmarc.example.test") {
		t.Fatalf("missing DMARC = %+v", finding)
	}
	checks.domain.DKIMKeys = nil
	if finding, pass := checks.dkim(t.Context()); pass || finding.Status != checkFail {
		t.Fatalf("no DKIM key = %+v", finding)
	}
}

func TestDeliverabilitySelfTestSendsAndReportsOutcome(t *testing.T) {
	f := newSetupFixture(t)
	f.handler.ConfigureSpamFiltering(nil, spam.NewDNS(blocklistResolver{}, spam.DNSOptions{QueryTimeout: time.Second}))
	f.request(t, http.MethodPost, "/api/v1/admin/deliverability/self-test", `{"from":"nobody@example.test"}`, http.StatusBadRequest)
	f.request(t, http.MethodPost, "/api/v1/admin/deliverability/self-test", `{"from":"owner@example.test","to":"someone@example.test"}`, http.StatusBadRequest)
	report := decodeInto[deliverabilityReport](t, f.request(t, http.MethodPost, "/api/v1/admin/deliverability/self-test", `{"from":"owner@example.test","to":"Probe <probe@external.example>"}`, http.StatusOK))
	if report.Domain != "example.test" || len(report.Addresses) != 1 || report.Addresses[0] != "192.0.2.10" || report.Failed != 0 || len(report.Checks) != 5 {
		t.Fatalf("report = %+v", report)
	}
	if report.TestMessage == nil || !strings.HasPrefix(report.TestMessage.QueueID, deliverabilityKind+"-") {
		t.Fatalf("test message = %+v", report.TestMessage)
	}
	id := report.TestMessage.QueueID
	queued := f.queue.Get(id)
	if queued == nil || queued.Recipient != "probe@external.example" || queued.EnvelopeSender != "owner@example.test" || queued.Kind != deliverabilityKind {
		t.Fatalf("queued message = %+v", queued)
	}
	if signature := queued.Headers["DKIM-Signature"]; !strings.Contains(signature, "d=example.test") || !strings.Contains(signature, "s=s1") {
		t.Fatalf("queued message was not DKIM-signed: %q", signature)
	}
	pending := decodeInto[deliverabilityMessage](t, f.request(t, http.MethodGet, "/api/v1/admin/deliverability/messages/"+id, "", http.StatusOK))
	if pending.Final || pending.Status != string(queue.StatusPending) {
		t.Fatalf("pending outcome = %+v", pending)
	}
	// The queue reports the remote outcome through message trace.
	base := messagetrace.Record{QueueID: id, CorrelationID: id, Kind: deliverabilityKind, Direction: string(queue.DirectionOutbound),
		EnvelopeSender: "owner@example.test", Recipient: "probe@external.example", TransportSecurity: "TLS 1.3"}
	if err := f.traces.Record(t.Context(), base, messagetrace.Event{Stage: "delivery", Status: string(queue.StatusDelivered), Code: "250",
		Response: "2.0.0 OK queued", Destination: "mx.external.example:25", TLSPolicy: "dane"}); err != nil {
		t.Fatal(err)
	}
	outcome := decodeInto[deliverabilityMessage](t, f.request(t, http.MethodGet, "/api/v1/admin/deliverability/messages/"+id, "", http.StatusOK))
	if !outcome.Final || outcome.Status != string(queue.StatusDelivered) || outcome.TLSPolicy != "dane" || outcome.Code != "250" ||
		outcome.Destination != "mx.external.example:25" || outcome.TransportSecurity != "TLS 1.3" {
		t.Fatalf("outcome = %+v", outcome)
	}
	f.request(t, http.MethodGet, "/api/v1/admin/deliverability/messages/web-other", "", http.StatusNotFound)
	checklist := decodeInto[setupChecklistResponse](t, f.request(t, http.MethodGet, "/api/v1/admin/setup-checklist?refresh=1", "", http.StatusOK))
	if check := checkByID(t, checklist.Checks, "test-delivery"); check.Status != checkPass {
		t.Fatalf("test-delivery after delivery = %+v", check)
	}
	entries, err := audit.New(f.ts).Query(t.Context(), time.Time{}, "deliverability.self_test", "owner", 10)
	if err != nil || len(entries) != 1 || entries[0].Details["to"] != "probe@external.example" || entries[0].Details["queue_id"] != id {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
}

func TestDeliverabilitySelfTestIsRateLimited(t *testing.T) {
	f := newSetupFixture(t)
	for range deliverabilityBurst {
		f.request(t, http.MethodPost, "/api/v1/admin/deliverability/self-test", `{"from":"owner@example.test"}`, http.StatusOK)
	}
	response := authenticatedJSON(t, f.client, http.MethodPost, f.server.URL+"/api/v1/admin/deliverability/self-test", f.csrf, `{"from":"owner@example.test"}`)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") == "" {
		t.Fatalf("over-limit self-test = %d (Retry-After %q)", response.StatusCode, response.Header.Get("Retry-After"))
	}
}
