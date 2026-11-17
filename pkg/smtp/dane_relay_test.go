package smtp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dane"
	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/tlsrpt"
)

// fakeDANE is a deterministic DANEPolicyResolver.
type fakeDANE struct {
	inactive bool
	mx       dane.MXResult
	hosts    map[string]dane.HostPolicy
}

func (f fakeDANE) Active() bool                             { return !f.inactive }
func (f fakeDANE) MX(context.Context, string) dane.MXResult { return f.mx }
func (f fakeDANE) HostPolicy(_ context.Context, host string, _ int) dane.HostPolicy {
	if policy, ok := f.hosts[host]; ok {
		return policy
	}
	return dane.HostPolicy{Host: host, State: dane.StateNone, Reason: "no DNSSEC-authenticated TLSA records for " + host}
}

// evidenceLog collects TLSPolicyEvidence outcomes.
type evidenceLog struct {
	mu       sync.Mutex
	outcomes []string
}

func (e *evidenceLog) record(_ context.Context, outcome string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.outcomes = append(e.outcomes, outcome)
}

func (e *evidenceLog) last() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.outcomes) == 0 {
		return ""
	}
	return e.outcomes[len(e.outcomes)-1]
}

// spkiRecord is a DANE-EE SPKI SHA-256 record for the mock server's key.
func spkiRecord(t *testing.T, srv *mockSMTPServer) dane.Record {
	t.Helper()
	leaf, err := x509.ParseCertificate(srv.tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return dane.Record{Usage: dane.UsageDANEEE, Selector: dane.SelectorSPKI, MatchingType: dane.MatchSHA256, Data: sum[:]}
}

// daneRelay returns a direct-MX client for example.test whose MX host
// mx.example.test is dialled at srv.
func daneRelay(srv *mockSMTPServer, resolver DANEPolicyResolver, reporter *recordingTLSReporter, evidence *evidenceLog) *RelayClient {
	return NewRelayClient(&RelayConfig{
		LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: "mx.example.test.", Pref: 10}}, nil
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "mx.example.test:25" {
				return nil, errors.New("unexpected dial to " + address)
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, srv.Addr())
		},
		DANE: resolver, TLSReporter: reporter, TLSPolicyEvidence: evidence.record,
	})
}

func secureMX() dane.MXResult {
	return dane.MXResult{Security: dane.Secure, Hosts: []dane.MX{{Host: "mx.example.test", Preference: 10}}}
}

func usablePolicy(records ...dane.Record) dane.HostPolicy {
	return dane.HostPolicy{Host: "mx.example.test", State: dane.StateUsable, TLSAName: "_25._tcp.mx.example.test", Records: records, Names: []string{"mx.example.test"}}
}

func TestRelayDANEVerifiedDelivery(t *testing.T) {
	srv := newMockSMTP(t, mockWithTLS(t))
	defer srv.Close()
	reporter, evidence := &recordingTLSReporter{}, &evidenceLog{}
	// The mock certificate is self-signed for another name: DANE-EE ignores
	// WebPKI, names, and dates, and DANE takes precedence over an enforcing
	// MTA-STS policy that would not authorize this MX.
	client := daneRelay(srv, fakeDANE{mx: secureMX(), hosts: map[string]dane.HostPolicy{"mx.example.test": usablePolicy(spkiRecord(t, srv))}}, reporter, evidence)
	client.cfg.MTASTS = mtastsResolverFunc(func(_ context.Context, domain string) (mtasts.Result, error) {
		return mtasts.Result{Policy: &mtasts.Policy{PolicyDomain: domain, PolicyID: "one", Mode: mtasts.ModeEnforce, MX: []string{"other.example.test"}}}, nil
	})
	if err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body")); err != nil {
		t.Fatalf("Deliver() = %v", err)
	}
	if got := evidence.last(); got != "dane-verified mx=mx.example.test tlsa=_25._tcp.mx.example.test" {
		t.Fatalf("evidence = %q", got)
	}
	events := reporter.snapshot()
	if len(events) != 1 || !events[0].Success || events[0].Policy.Type != tlsrpt.PolicyTypeTLSA || events[0].Policy.Domain != "example.test" ||
		len(events[0].Policy.Strings) != 1 || !strings.HasPrefix(events[0].Policy.Strings[0], "3 1 1 ") || events[0].Policy.MX[0] != "mx.example.test" {
		t.Fatalf("TLS report events = %#v", events)
	}
}

func TestRelayDANECertificateMismatchDefers(t *testing.T) {
	srv := newMockSMTP(t, mockWithTLS(t))
	defer srv.Close()
	reporter, evidence := &recordingTLSReporter{}, &evidenceLog{}
	wrong := dane.Record{Usage: dane.UsageDANEEE, Selector: dane.SelectorSPKI, MatchingType: dane.MatchSHA256, Data: make([]byte, 32)}
	client := daneRelay(srv, fakeDANE{mx: secureMX(), hosts: map[string]dane.HostPolicy{"mx.example.test": usablePolicy(wrong)}}, reporter, evidence)
	err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"))
	if err == nil || !strings.Contains(err.Error(), "4.7.5 DANE TLS authentication failed for MX mx.example.test") || strings.Contains(err.Error(), "5.") {
		t.Fatalf("Deliver() = %v", err)
	}
	if got := evidence.last(); !strings.HasPrefix(got, "dane-failed mx=mx.example.test: ") || !strings.Contains(got, dane.FailureNoMatch) {
		t.Fatalf("evidence = %q", got)
	}
	events := reporter.snapshot()
	if len(events) != 1 || events[0].Success || events[0].ResultType != tlsrpt.ResultTLSAInvalid || events[0].FailureReasonCode != dane.FailureNoMatch {
		t.Fatalf("TLS report events = %#v", events)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, command := range srv.commands {
		if strings.HasPrefix(command, "MAIL FROM") {
			t.Fatalf("message transmitted after DANE failure: %q", srv.commands)
		}
	}
}

func TestRelayDANERequiresSTARTTLS(t *testing.T) {
	srv := newMockSMTP(t)
	defer srv.Close()
	reporter, evidence := &recordingTLSReporter{}, &evidenceLog{}
	record := dane.Record{Usage: dane.UsageDANEEE, Selector: dane.SelectorSPKI, MatchingType: dane.MatchSHA256, Data: make([]byte, 32)}
	client := daneRelay(srv, fakeDANE{mx: secureMX(), hosts: map[string]dane.HostPolicy{"mx.example.test": usablePolicy(record)}}, reporter, evidence)
	err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"))
	if err == nil || !strings.Contains(err.Error(), "4.7.5 DANE: MX mx.example.test publishes TLSA records but does not offer STARTTLS") {
		t.Fatalf("Deliver() = %v", err)
	}
	if events := reporter.snapshot(); len(events) != 1 || events[0].ResultType != tlsrpt.ResultSTARTTLSNotSupported || events[0].Policy.Type != tlsrpt.PolicyTypeTLSA {
		t.Fatalf("TLS report events = %#v", events)
	}
}

func TestRelayDANEUnusableRecordsRequireUnauthenticatedTLS(t *testing.T) {
	srv := newMockSMTP(t, mockWithTLS(t))
	defer srv.Close()
	reporter, evidence := &recordingTLSReporter{}, &evidenceLog{}
	pkix := dane.Record{Usage: dane.UsagePKIXEE, Selector: dane.SelectorSPKI, MatchingType: dane.MatchSHA256, Data: make([]byte, 32)}
	policy := dane.HostPolicy{Host: "mx.example.test", State: dane.StateUnusable, TLSAName: "_25._tcp.mx.example.test", Records: []dane.Record{pkix}, Names: []string{"mx.example.test"}, Reason: "TLSA records are all unusable"}
	client := daneRelay(srv, fakeDANE{mx: secureMX(), hosts: map[string]dane.HostPolicy{"mx.example.test": policy}}, reporter, evidence)
	if err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body")); err != nil {
		t.Fatalf("Deliver() = %v", err)
	}
	if got := evidence.last(); !strings.HasPrefix(got, "dane-unauthenticated mx=mx.example.test") {
		t.Fatalf("evidence = %q", got)
	}
	if events := reporter.snapshot(); len(events) != 1 || events[0].ResultType != tlsrpt.ResultTLSAInvalid {
		t.Fatalf("TLS report events = %#v", events)
	}
}

func TestRelayDANEPolicyDecisions(t *testing.T) {
	tests := []struct {
		name     string
		resolver fakeDANE
		wantErr  string
		evidence string
		result   string
	}{
		{"bogus MX defers before dialling", fakeDANE{mx: dane.MXResult{Security: dane.Bogus, Err: errors.New("example.test MX lookup returned SERVFAIL")}}, "4.7.5 DANE: DNSSEC MX lookup for example.test failed", "dane-failed: example.test MX lookup returned SERVFAIL", tlsrpt.ResultDNSSECInvalid},
		{"bogus TLSA defers the host", fakeDANE{mx: secureMX(), hosts: map[string]dane.HostPolicy{"mx.example.test": {Host: "mx.example.test", State: dane.StateFailed, Reason: "SERVFAIL"}}}, "4.7.5 DANE: TLSA lookup for MX mx.example.test failed", "dane-failed mx=mx.example.test: SERVFAIL", tlsrpt.ResultDNSSECInvalid},
		{"insecure MX means no DANE", fakeDANE{mx: dane.MXResult{Security: dane.Insecure}}, "", "no-dane: MX records of example.test are not DNSSEC-signed", tlsrpt.ResultSTARTTLSNotSupported},
		{"secure MX without TLSA means no DANE", fakeDANE{mx: secureMX()}, "", "no-dane mx=mx.example.test: no DNSSEC-authenticated TLSA records for mx.example.test", tlsrpt.ResultSTARTTLSNotSupported},
		{"inactive DANE is skipped", fakeDANE{inactive: true, mx: dane.MXResult{Security: dane.Bogus}}, "", "", tlsrpt.ResultSTARTTLSNotSupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := newMockSMTP(t)
			defer srv.Close()
			reporter, evidence := &recordingTLSReporter{}, &evidenceLog{}
			err := daneRelay(srv, test.resolver, reporter, evidence).Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"))
			if test.wantErr == "" && err != nil || test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Deliver() = %v, want %q", err, test.wantErr)
			}
			if got := evidence.last(); got != test.evidence {
				t.Fatalf("evidence = %q, want %q", got, test.evidence)
			}
			events := reporter.snapshot()
			if len(events) == 0 || events[len(events)-1].ResultType != test.result {
				t.Fatalf("TLS report events = %#v", events)
			}
		})
	}
}

func TestRelayDANESatisfiesRequireTLS(t *testing.T) {
	srv := newMockSMTP(t, mockWithTLS(t), mockWithRequireTLS())
	defer srv.Close()
	evidence := &evidenceLog{}
	client := daneRelay(srv, fakeDANE{mx: secureMX(), hosts: map[string]dane.HostPolicy{"mx.example.test": usablePolicy(spkiRecord(t, srv))}}, &recordingTLSReporter{}, evidence)
	if err := client.DeliverWithOptions(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"), DSNEnvelopeOptions{RequireTLS: true}); err != nil {
		t.Fatalf("DeliverWithOptions(REQUIRETLS) = %v", err)
	}
	// Without usable TLSA (and no enforcing MTA-STS) REQUIRETLS still fails.
	plain := newMockSMTP(t)
	defer plain.Close()
	err := daneRelay(plain, fakeDANE{mx: secureMX()}, &recordingTLSReporter{}, evidence).DeliverWithOptions(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"), DSNEnvelopeOptions{RequireTLS: true})
	if err == nil || !strings.Contains(err.Error(), "5.7.30") {
		t.Fatalf("REQUIRETLS without DANE = %v", err)
	}
}
