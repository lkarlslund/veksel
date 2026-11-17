package dane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeAnswer is one canned resolver response.
type fakeAnswer struct {
	rcode  int
	secure bool
	rrs    []string
}

// fakeExchanger answers from a table keyed by "name TYPE" and records the
// queries it saw. Unknown questions get a secure NXDOMAIN.
type fakeExchanger struct {
	answers map[string]fakeAnswer
	err     error
	queries []string
}

func (f *fakeExchanger) Exchange(_ context.Context, query *dns.Msg) (*dns.Msg, error) {
	question := query.Question[0]
	key := strings.TrimSuffix(question.Name, ".") + " " + dns.TypeToString[question.Qtype]
	f.queries = append(f.queries, key)
	if opt := query.IsEdns0(); opt == nil || !opt.Do() {
		return nil, errors.New("query without the DNSSEC OK bit")
	}
	if f.err != nil {
		return nil, f.err
	}
	answer, ok := f.answers[key]
	if !ok {
		answer = fakeAnswer{rcode: dns.RcodeNameError, secure: true}
	}
	response := new(dns.Msg)
	response.SetRcode(query, answer.rcode)
	response.AuthenticatedData = answer.secure
	for _, text := range answer.rrs {
		rr, err := dns.NewRR(text)
		if err != nil {
			return nil, err
		}
		response.Answer = append(response.Answer, rr)
	}
	return response, nil
}

const usableTLSA = "3 1 1 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"

func TestMXSecurityFollowsTheADBit(t *testing.T) {
	exchanger := &fakeExchanger{answers: map[string]fakeAnswer{
		"signed.test MX":   {secure: true, rrs: []string{"signed.test. 300 IN MX 20 MX2.signed.test.", "signed.test. 300 IN MX 10 mx1.signed.test."}},
		"unsigned.test MX": {rrs: []string{"unsigned.test. 300 IN MX 10 mx.unsigned.test."}},
		"bogus.test MX":    {rcode: dns.RcodeServerFailure},
	}}
	resolver := NewResolver(exchanger)
	signed := resolver.MX(t.Context(), "signed.test")
	if signed.Security != Secure || len(signed.Hosts) != 2 || signed.Hosts[0] != (MX{Host: "mx1.signed.test", Preference: 10}) || signed.Hosts[1].Host != "mx2.signed.test" {
		t.Fatalf("signed MX = %+v", signed)
	}
	if unsigned := resolver.MX(t.Context(), "unsigned.test"); unsigned.Security != Insecure {
		t.Fatalf("unsigned MX = %+v", unsigned)
	}
	if bogus := resolver.MX(t.Context(), "bogus.test"); bogus.Security != Bogus || bogus.Err == nil || !strings.Contains(bogus.Err.Error(), "SERVFAIL") {
		t.Fatalf("bogus MX = %+v", bogus)
	}
	if implicit := resolver.MX(t.Context(), "implicit.test"); implicit.Security != Secure || len(implicit.Hosts) != 0 {
		t.Fatalf("secure NXDOMAIN MX = %+v", implicit)
	}
}

func TestHostPolicyDecisions(t *testing.T) {
	signedA := fakeAnswer{secure: true, rrs: []string{"mx.test. 300 IN A 192.0.2.1"}}
	tests := []struct {
		name    string
		answers map[string]fakeAnswer
		state   State
		reason  string
	}{
		{"insecure address records", map[string]fakeAnswer{"mx.test A": {rrs: []string{"mx.test. 300 IN A 192.0.2.1"}}}, StateNone, "not DNSSEC-signed"},
		{"bogus address records", map[string]fakeAnswer{"mx.test A": {rcode: dns.RcodeServerFailure}}, StateFailed, "SERVFAIL"},
		{"secure usable TLSA", map[string]fakeAnswer{"mx.test A": signedA, "_25._tcp.mx.test TLSA": {secure: true, rrs: []string{"_25._tcp.mx.test. 300 IN TLSA " + usableTLSA}}}, StateUsable, ""},
		{"insecure TLSA", map[string]fakeAnswer{"mx.test A": signedA, "_25._tcp.mx.test TLSA": {rrs: []string{"_25._tcp.mx.test. 300 IN TLSA " + usableTLSA}}}, StateNone, "no DNSSEC-authenticated TLSA"},
		{"bogus TLSA", map[string]fakeAnswer{"mx.test A": signedA, "_25._tcp.mx.test TLSA": {rcode: dns.RcodeServerFailure}}, StateFailed, "SERVFAIL"},
		{"secure denial of TLSA", map[string]fakeAnswer{"mx.test A": signedA}, StateNone, "no DNSSEC-authenticated TLSA"},
		{"only PKIX TLSA", map[string]fakeAnswer{"mx.test A": signedA, "_25._tcp.mx.test TLSA": {secure: true, rrs: []string{"_25._tcp.mx.test. 300 IN TLSA 1 1 1 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"}}}, StateUnusable, "unusable"},
		{"IPv6-only host", map[string]fakeAnswer{"mx.test A": {secure: true}, "mx.test AAAA": {secure: true, rrs: []string{"mx.test. 300 IN AAAA 2001:db8::1"}}, "_25._tcp.mx.test TLSA": {secure: true, rrs: []string{"_25._tcp.mx.test. 300 IN TLSA " + usableTLSA}}}, StateUsable, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := NewResolver(&fakeExchanger{answers: test.answers}).HostPolicy(t.Context(), "MX.test.", 25)
			if policy.State != test.state || !strings.Contains(policy.Reason, test.reason) {
				t.Fatalf("policy = %+v, want state %s reason %q", policy, test.state, test.reason)
			}
			if test.state == StateUsable && (policy.TLSAName != "_25._tcp.mx.test" || len(policy.Usable()) != 1 || len(policy.Names) != 1 || policy.Names[0] != "mx.test") {
				t.Fatalf("usable policy = %+v", policy)
			}
		})
	}
}

func TestHostPolicyPrefersSecureCNAMETarget(t *testing.T) {
	exchanger := &fakeExchanger{answers: map[string]fakeAnswer{
		"mx.test A":                        {secure: true, rrs: []string{"mx.test. 300 IN CNAME mail.provider.test.", "mail.provider.test. 300 IN A 192.0.2.1"}},
		"_25._tcp.mail.provider.test TLSA": {secure: true, rrs: []string{"_25._tcp.mail.provider.test. 300 IN TLSA " + usableTLSA}},
	}}
	policy := NewResolver(exchanger).HostPolicy(t.Context(), "mx.test", 25)
	if policy.State != StateUsable || policy.TLSAName != "_25._tcp.mail.provider.test" || len(policy.Names) != 2 || policy.Names[0] != "mail.provider.test" || policy.Names[1] != "mx.test" {
		t.Fatalf("CNAME policy = %+v", policy)
	}
	// Without TLSA at the target, the original name is tried next.
	delete(exchanger.answers, "_25._tcp.mail.provider.test TLSA")
	exchanger.answers["_25._tcp.mx.test TLSA"] = fakeAnswer{secure: true, rrs: []string{"_25._tcp.mx.test. 300 IN TLSA " + usableTLSA}}
	policy = NewResolver(exchanger).HostPolicy(t.Context(), "mx.test", 25)
	if policy.State != StateUsable || policy.TLSAName != "_25._tcp.mx.test" || policy.Names[0] != "mx.test" {
		t.Fatalf("CNAME fallback policy = %+v", policy)
	}
}

func writeResolvConf(t *testing.T, servers ...string) string {
	t.Helper()
	var lines []string
	for _, server := range servers {
		lines = append(lines, "nameserver "+server)
	}
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServiceTrustsOnlyLoopbackSystemResolvers(t *testing.T) {
	var built []string
	newExchanger := func(servers []string) Exchanger {
		built = servers
		return &fakeExchanger{}
	}
	remote := New(Options{ResolvConf: writeResolvConf(t, "192.0.2.53"), NewExchanger: newExchanger})
	remote.Configure(Config{Enabled: true})
	status := remote.Status()
	if status.Active || status.Source != SourceSystem || len(status.Resolvers) != 0 || len(status.Untrusted) != 1 || !strings.Contains(status.Detail, "no trusted validating resolver") {
		t.Fatalf("remote-only status = %+v", status)
	}
	if mx := remote.MX(t.Context(), "example.test"); mx.Security != Insecure {
		t.Fatalf("inactive MX = %+v", mx)
	}
	if policy := remote.HostPolicy(t.Context(), "mx.example.test", 25); policy.State != StateNone {
		t.Fatalf("inactive host policy = %+v", policy)
	}

	local := New(Options{ResolvConf: writeResolvConf(t, "127.0.0.53", "192.0.2.53", "::1"), NewExchanger: newExchanger})
	local.Configure(Config{Enabled: true})
	status = local.Status()
	if !status.Active || len(status.Resolvers) != 2 || status.Resolvers[0] != "127.0.0.53:53" || status.Resolvers[1] != "[::1]:53" || status.Validating != ValidatingUnknown {
		t.Fatalf("loopback status = %+v", status)
	}
	if len(built) != 2 {
		t.Fatalf("exchanger servers = %q", built)
	}

	local.Configure(Config{Enabled: true, Resolvers: []string{"192.0.2.10:53"}})
	if status = local.Status(); !status.Active || status.Source != SourceConfigured || status.Resolvers[0] != "192.0.2.10:53" {
		t.Fatalf("configured status = %+v", status)
	}
	local.Configure(Config{Enabled: false, Resolvers: []string{"192.0.2.10:53"}})
	if local.Active() {
		t.Fatal("disabled DANE is active")
	}
}

func TestServiceProbeDetectsValidatingResolver(t *testing.T) {
	tests := []struct {
		name       string
		answers    map[string]fakeAnswer
		err        error
		validating string
		active     bool
	}{
		{"validating", map[string]fakeAnswer{"isc.org SOA": {secure: true}, "dnssec-failed.org SOA": {rcode: dns.RcodeServerFailure}}, nil, ValidatingYes, true},
		{"no AD bit", map[string]fakeAnswer{"isc.org SOA": {}, "dnssec-failed.org SOA": {}}, nil, ValidatingNo, false},
		{"answers bogus name", map[string]fakeAnswer{"isc.org SOA": {secure: true}, "dnssec-failed.org SOA": {secure: true}}, nil, ValidatingNo, false},
		{"unreachable", nil, errors.New("connection refused"), ValidatingError, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exchanger := &fakeExchanger{answers: test.answers, err: test.err}
			service := New(Options{NewExchanger: func([]string) Exchanger { return exchanger }})
			service.Configure(Config{Enabled: true, Resolvers: []string{"127.0.0.1:53"}})
			status := service.Probe(t.Context())
			if status.Validating != test.validating || status.Active != test.active || status.CheckedAt.IsZero() || service.Active() != test.active {
				t.Fatalf("probe status = %+v", status)
			}
		})
	}
}
