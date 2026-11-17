package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
)

type fakeDNSResolver struct {
	mx   map[string][]*net.MX
	txt  map[string][]string
	host map[string][]string
	addr map[string][]string
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeDNSResolver) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	if v, ok := f.mx[n]; ok {
		return v, nil
	}
	return nil, notFound(n)
}

func (f fakeDNSResolver) LookupTXT(_ context.Context, n string) ([]string, error) {
	// Fully qualified queries (DMARC) end in a dot.
	if v, ok := f.txt[strings.TrimSuffix(n, ".")]; ok {
		return v, nil
	}
	return nil, notFound(n)
}

func (f fakeDNSResolver) LookupHost(_ context.Context, n string) ([]string, error) {
	if v, ok := f.host[n]; ok {
		return v, nil
	}
	return nil, notFound(n)
}

func (f fakeDNSResolver) LookupAddr(_ context.Context, a string) ([]string, error) {
	if v, ok := f.addr[a]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "timeout", Name: a, IsTimeout: true}
}

func TestAdminDNSGuidanceExpectedRecordsAndLiveStatus(t *testing.T) {
	handler, _ := testHandler(t)
	cfg := config.Default()
	cfg.SmtpServerName = "mail.example.test"
	handler.ConfigureAdministration(cfg, nil)
	handler.SetDNSResolver(fakeDNSResolver{
		mx:   map[string][]*net.MX{"example.test": {{Host: "other.example.net.", Pref: 10}}},
		txt:  map[string][]string{"example.test": {"v=spf1 ip4:192.0.2.0/24 -all"}},
		host: map[string][]string{"mail.example.test": {"192.0.2.10"}},
		addr: map[string][]string{},
	})
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains", csrf, `{"id":"example.test"}`)
	assertDKIMStatus(t, response, http.StatusCreated)
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys", csrf, `{"selector":"s1","revision":0}`)
	assertDKIMStatus(t, response, http.StatusCreated)

	response, err := client.Get(server.URL + "/api/v1/admin/domains/example.test/dns")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var got dnsGuidanceResponse
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Domain != "example.test" || got.ServerName != "mail.example.test" {
		t.Fatalf("response=%+v", got)
	}
	by := map[string]dnsGuidanceRecord{}
	for _, r := range got.Records {
		by[r.Type] = r
	}
	if r := by["MX"]; r.Expected != "10 mail.example.test." || r.Status != dnsMismatch || len(r.Live) != 1 {
		t.Fatalf("MX=%+v", r)
	}
	if r := by["SPF"]; r.Status != dnsOK || r.Expected != "v=spf1 mx -all" {
		t.Fatalf("SPF=%+v", r)
	}
	if r := by["DMARC"]; r.Name != "_dmarc.example.test" || r.Status != dnsMissing || !strings.Contains(r.Expected, "rua=mailto:dmarc@example.test") {
		t.Fatalf("DMARC=%+v", r)
	}
	if r := by["DKIM"]; r.Name != "s1._domainkey.example.test" || r.Status != dnsMissing || !strings.HasPrefix(r.Expected, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("DKIM=%+v", r)
	}
	if r := by["PTR"]; r.Name != "192.0.2.10" || r.Expected != "mail.example.test." || r.Status != dnsError || r.Error == "" {
		t.Fatalf("PTR=%+v", r)
	}
}

func TestDNSGuidanceStatuses(t *testing.T) {
	ctx := t.Context()
	f := fakeDNSResolver{
		mx:   map[string][]*net.MX{"a.test": {{Host: "MAIL.a.test.", Pref: 5}}},
		txt:  map[string][]string{"a.test": {"unrelated", "v=spf1 -all"}, "_dmarc.a.test": {"v=DMARC1; p=reject"}, "k._domainkey.a.test": {"v=DKIM1; k=rsa; p=AB CD"}},
		host: map[string][]string{"mail.a.test": {"192.0.2.1", "2001:db8::1"}},
		addr: map[string][]string{"192.0.2.1": {"mail.a.test."}, "2001:db8::1": {"wrong.example."}},
	}
	if r := checkMX(ctx, f, "a.test", "mail.a.test"); r.Status != dnsOK {
		t.Fatalf("MX=%+v", r)
	}
	if r := checkSPF(ctx, f, "a.test", "mail.a.test", ""); r.Status != dnsMismatch || len(r.Live) != 1 || !strings.Contains(r.Note, "does not authorize 192.0.2.1, 2001:db8::1") {
		t.Fatalf("SPF=%+v", r)
	}
	// Behind NAT the server name resolves to an internal address; with
	// smtp_public_address set only the public address is checked.
	nat := fakeDNSResolver{txt: map[string][]string{"a.test": {"v=spf1 ip4:203.0.113.8 -all"}}, host: map[string][]string{"mail.a.test": {"10.20.30.11"}}}
	if r := checkSPF(ctx, nat, "a.test", "mail.a.test", "203.0.113.8"); r.Status != dnsOK {
		t.Fatalf("SPF with public address=%+v", r)
	}
	if r := checkSPF(ctx, nat, "a.test", "mail.a.test", ""); r.Status != dnsMismatch || !strings.Contains(r.Note, "10.20.30.11") {
		t.Fatalf("SPF without public address=%+v", r)
	}
	if r := checkSPF(ctx, f, "none.test", "mail.a.test", ""); r.Status != dnsMissing {
		t.Fatalf("missing=%+v", r)
	}
	ptr := checkPTR(ctx, f, "mail.a.test")
	if len(ptr) != 2 || ptr[0].Status != dnsOK || ptr[1].Status != dnsMismatch {
		t.Fatalf("PTR=%+v", ptr)
	}
	if dkimPublicKey("v=DKIM1; k=rsa; p=AB CD") != "ABCD" {
		t.Fatal("dkimPublicKey must strip whitespace")
	}
}

func TestDNSGuidancePublicAddressFCrDNS(t *testing.T) {
	f := fakeDNSResolver{
		host: map[string][]string{"mail.a.test": {"10.0.0.5"}},
		addr: map[string][]string{"203.0.113.9": {"mail.a.test."}},
	}
	if r := checkPublicPTR(t.Context(), f, "mail.a.test", "203.0.113.9"); r.Status != dnsMismatch || !strings.Contains(r.Note, "does not resolve forward") {
		t.Fatalf("forward mismatch=%+v", r)
	}
	f.host["mail.a.test"] = []string{"203.0.113.9"}
	if r := checkPublicPTR(t.Context(), f, "mail.a.test", "203.0.113.9"); r.Status != dnsOK {
		t.Fatalf("ok=%+v", r)
	}
	f.addr["203.0.113.9"] = []string{"other.test."}
	if r := checkPublicPTR(t.Context(), f, "mail.a.test", "203.0.113.9"); r.Status != dnsMismatch {
		t.Fatalf("ptr mismatch=%+v", r)
	}
	if r := checkPublicPTR(t.Context(), f, "mail.a.test", "203.0.113.10"); r.Status == dnsOK {
		t.Fatalf("missing=%+v", r)
	}
}

func TestAdminDNSGuidanceRequiresAdmin(t *testing.T) {
	server, ts := testApp(t)
	owner := testClient(t)
	csrf := setupAndLogin(t, server, owner, "owner")
	response := authenticatedJSON(t, owner, http.MethodPost, server.URL+"/api/v1/admin/domains", csrf, `{"id":"example.test"}`)
	assertDKIMStatus(t, response, http.StatusCreated)
	if err := ts.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	ordinary := testClient(t)
	loginExistingUser(t, ordinary, server.URL, "ordinary")
	response, err := ordinary.Get(server.URL + "/api/v1/admin/domains/example.test/dns")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin status=%d", response.StatusCode)
	}
}

func TestCheckSPFSemantics(t *testing.T) {
	ctx := t.Context()
	hosts := map[string][]string{
		"mail.a.test": {"192.0.2.1", "2001:db8::1"}, "mx.a.test": {"192.0.2.1", "2001:db8::1"},
		"a.test": {"192.0.2.1", "2001:db8::1"}, "other.test": {"203.0.113.9"},
	}
	chain := map[string][]string{}
	for i := range 11 {
		chain["c"+strconv.Itoa(i)+".test"] = []string{"v=spf1 include:c" + strconv.Itoa(i+1) + ".test -all"}
	}
	txt := map[string][]string{
		"inc.test": {"v=spf1 include:_spf.vendor.test -all"}, "_spf.vendor.test": {"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"},
		"v4only.test": {"v=spf1 ip4:192.0.2.1 -all"}, "mx.test": {"v=spf1 mx -all"}, "a.test": {"v=spf1 a -all"},
		"aother.test": {"v=spf1 a:other.test -all"}, "wrong.test": {"v=spf1 mx:other.test -all"},
		"red.test": {"v=spf1 redirect=inc.test"}, "multi.test": {"v=spf1 -all", "V=SPF1 mx -all"},
		"open.test": {"v=spf1 +all"}, "neutral.test": {"v=spf1 ?all"}, "soft.test": {"v=spf1 ~all"},
		"deny.test": {"v=spf1 -ip4:192.0.2.1 +all"}, "badinc.test": {"v=spf1 include:gone.test -all"},
		"ok6.test": {"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::1 -all"},
	}
	for k, v := range chain {
		txt[k] = v
	}
	f := fakeDNSResolver{
		txt: txt, host: hosts,
		mx: map[string][]*net.MX{"mx.test": {{Host: "mx.a.test.", Pref: 1}}, "wrong.test": {{Host: "mx.a.test."}}, "other.test": {{Host: "other.test."}}},
	}
	for _, tc := range []struct {
		domain, status, contains string
	}{
		{"inc.test", dnsOK, ""}, {"v4only.test", dnsMismatch, "does not authorize"}, {"mx.test", dnsOK, ""},
		{"a.test", dnsOK, ""}, {"aother.test", dnsMismatch, ""}, {"wrong.test", dnsMismatch, ""}, {"red.test", dnsOK, ""},
		{"multi.test", dnsMismatch, "Multiple"}, {"open.test", dnsOK, "+all"}, {"neutral.test", dnsOK, "?all"},
		{"soft.test", dnsMismatch, ""}, {"deny.test", dnsMismatch, ""}, {"c0.test", dnsError, "lookup limit"},
		{"badinc.test", dnsError, "permerror"}, {"ok6.test", dnsOK, ""}, {"missing.test", dnsMissing, ""},
	} {
		r := checkSPF(ctx, f, tc.domain, "mail.a.test", "")
		if r.Status != tc.status || !strings.Contains(r.Note+r.Error, tc.contains) {
			t.Errorf("%s: %+v", tc.domain, r)
		}
	}
}
