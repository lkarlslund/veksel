package dnsserver

import (
	"context"
	"encoding/base64"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/miekg/dns"
)

type nopAudit struct{}

func (nopAudit) Log(string, string, string, map[string]string) {}

const zoneName = "example.test"

// fixture is a built-in zone served on a loopback port.
type fixture struct {
	zones  *dnsprovider.Zones
	server *Server
	addr   string
}

func newFixture(t *testing.T, settings Settings) *fixture {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	sealer, err := migration.NewStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	zones, err := dnsprovider.NewZones(t.Context(), ts, sealer, nopAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zones.Put(t.Context(), "admin", zoneName, dnsprovider.ZoneInput{Provider: dnsprovider.KindBuiltin}); err != nil {
		t.Fatal(err)
	}
	for _, rec := range []dnsprovider.Record{
		{Type: "A", Name: "mail.example.test", Value: "192.0.2.10"},
		{Type: "AAAA", Name: "mail.example.test", Value: "2001:db8::10"},
		{Type: "A", Name: "ns1.example.test", Value: "192.0.2.53"},
		{Type: "MX", Name: zoneName, Value: "10 mail.example.test."},
		{Type: "TXT", Name: zoneName, Value: "v=spf1 mx -all"},
		{Type: "TXT", Name: "s1._domainkey.example.test", Value: "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 600)},
		{Type: "CNAME", Name: "webmail.example.test", Value: "mail.example.test."},
		{Type: "CNAME", Name: "chain.example.test", Value: "webmail.example.test."},
		{Type: "CNAME", Name: "away.example.test", Value: "elsewhere.invalid."},
		{Type: "CAA", Name: zoneName, Value: `0 issue "letsencrypt.org"`},
		{Type: "SRV", Name: "_imaps._tcp.example.test", Value: "0 1 993 mail.example.test."},
	} {
		if _, err := zones.AddHostedRecord(t.Context(), "admin", zoneName, rec); err != nil {
			t.Fatalf("add %s %s: %v", rec.Type, rec.Name, err)
		}
	}
	server := New(zones.Hosted())
	server.RateLimit = -1
	if settings.Listen == "" {
		settings.Listen = "127.0.0.1:0"
	}
	settings.Enabled = true
	if settings.Nameservers == nil {
		settings.Nameservers = []string{"ns1.example.test", "ns2.example.net"}
	}
	if err := server.Apply(settings); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return &fixture{zones: zones, server: server, addr: server.Addr()}
}

func (f *fixture) query(t *testing.T, name string, qtype uint16, edit ...func(*dns.Msg)) *dns.Msg {
	t.Helper()
	return exchange(t, "udp", f.addr, name, qtype, edit...)
}

func exchange(t *testing.T, network, addr, name string, qtype uint16, edit ...func(*dns.Msg)) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	for _, apply := range edit {
		apply(msg)
	}
	reply, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second, UDPSize: 4096}).Exchange(msg, addr)
	if err != nil {
		t.Fatalf("query %s %s over %s: %v", name, dns.TypeToString[qtype], network, err)
	}
	return reply
}

func withDO(msg *dns.Msg) { msg.SetEdns0(1232, true) }

func types(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, dns.TypeToString[rr.Header().Rrtype])
	}
	return out
}

func TestAuthoritativeAnswers(t *testing.T) {
	f := newFixture(t, Settings{})

	reply := f.query(t, "mail.example.test", dns.TypeA)
	if reply.Rcode != dns.RcodeSuccess || !reply.Authoritative || reply.RecursionAvailable || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "192.0.2.10" {
		t.Fatalf("A: %v", reply)
	}
	reply = f.query(t, "EXAMPLE.test", dns.TypeMX)
	if len(reply.Answer) != 1 || reply.Answer[0].(*dns.MX).Mx != "mail.example.test." || reply.Answer[0].(*dns.MX).Preference != 10 {
		t.Fatalf("MX: %v", reply)
	}
	reply = f.query(t, zoneName, dns.TypeTXT)
	if len(reply.Answer) != 1 || strings.Join(reply.Answer[0].(*dns.TXT).Txt, "") != "v=spf1 mx -all" {
		t.Fatalf("TXT: %v", reply)
	}
	reply = f.query(t, zoneName, dns.TypeSOA)
	soa, ok := reply.Answer[0].(*dns.SOA)
	if !ok || soa.Ns != "ns1.example.test." || soa.Mbox != "hostmaster.example.test." || soa.Serial == 0 {
		t.Fatalf("SOA: %v", reply)
	}
	reply = f.query(t, zoneName, dns.TypeNS)
	if got := types(reply.Answer); !slices.Equal(got, []string{"NS", "NS"}) || len(reply.Extra) != 1 || reply.Extra[0].(*dns.A).A.String() != "192.0.2.53" {
		t.Fatalf("NS with glue: %v", reply)
	}
	reply = f.query(t, zoneName, dns.TypeCAA)
	if len(reply.Answer) != 1 || reply.Answer[0].(*dns.CAA).Value != "letsencrypt.org" {
		t.Fatalf("CAA: %v", reply)
	}
	reply = f.query(t, "_imaps._tcp.example.test", dns.TypeSRV)
	if len(reply.Answer) != 1 || reply.Answer[0].(*dns.SRV).Port != 993 {
		t.Fatalf("SRV: %v", reply)
	}

	// CNAME chains are followed within the zone; out-of-zone targets are
	// left to the resolver.
	reply = f.query(t, "chain.example.test", dns.TypeAAAA)
	if got := types(reply.Answer); !slices.Equal(got, []string{"CNAME", "CNAME", "AAAA"}) {
		t.Fatalf("CNAME chase: %v", reply)
	}
	reply = f.query(t, "away.example.test", dns.TypeA)
	if got := types(reply.Answer); !slices.Equal(got, []string{"CNAME"}) || reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("out-of-zone CNAME: %v", reply)
	}
	reply = f.query(t, "webmail.example.test", dns.TypeCNAME)
	if got := types(reply.Answer); !slices.Equal(got, []string{"CNAME"}) {
		t.Fatalf("CNAME query: %v", reply)
	}
}

func TestNegativeAnswersAndRefusal(t *testing.T) {
	f := newFixture(t, Settings{})

	reply := f.query(t, "missing.example.test", dns.TypeA)
	if reply.Rcode != dns.RcodeNameError || !reply.Authoritative || len(reply.Answer) != 0 || len(reply.Ns) != 1 || reply.Ns[0].Header().Rrtype != dns.TypeSOA || reply.Ns[0].Header().Ttl != negativeTTL {
		t.Fatalf("NXDOMAIN: %v", reply)
	}
	reply = f.query(t, "mail.example.test", dns.TypeTXT)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 || len(reply.Ns) != 1 || reply.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("NODATA: %v", reply)
	}
	// _domainkey exists only as an empty non-terminal: NODATA, not NXDOMAIN.
	reply = f.query(t, "_domainkey.example.test", dns.TypeTXT)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 {
		t.Fatalf("empty non-terminal: %v", reply)
	}
	for _, name := range []string{"example.com", "test", ".", "other-example.test"} {
		reply = f.query(t, name, dns.TypeA, func(m *dns.Msg) { m.RecursionDesired = true })
		if reply.Rcode != dns.RcodeRefused || reply.Authoritative || reply.RecursionAvailable || len(reply.Answer) != 0 {
			t.Fatalf("%s must be refused: %v", name, reply)
		}
	}
	reply = f.query(t, "mail.example.test", dns.TypeA, func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS })
	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("non-IN class: %v", reply)
	}
	// RFC 8482: ANY gets one small synthesized RRset.
	reply = f.query(t, zoneName, dns.TypeANY)
	if got := types(reply.Answer); !slices.Equal(got, []string{"HINFO"}) || reply.Answer[0].(*dns.HINFO).Cpu != "RFC8482" {
		t.Fatalf("ANY: %v", reply)
	}
	reply = f.query(t, zoneName, dns.TypeA, func(m *dns.Msg) { m.SetEdns0(1232, false); m.IsEdns0().SetVersion(1) })
	if reply.Rcode != dns.RcodeBadVers {
		t.Fatalf("EDNS version 1: %v", reply)
	}
	reply = f.query(t, zoneName, dns.TypeA, func(m *dns.Msg) { m.Opcode = dns.OpcodeNotify })
	if reply.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("NOTIFY: %v", reply)
	}
}

func TestTruncationAndTCPFallback(t *testing.T) {
	f := newFixture(t, Settings{})
	dkim := "s1._domainkey.example.test"

	reply := f.query(t, dkim, dns.TypeTXT)
	if !reply.Truncated || len(reply.Answer) != 0 {
		t.Fatalf("a 600-byte TXT must truncate without EDNS: truncated=%t answers=%d", reply.Truncated, len(reply.Answer))
	}
	reply = f.query(t, dkim, dns.TypeTXT, func(m *dns.Msg) { m.SetEdns0(4096, false) })
	if reply.Truncated || len(reply.Answer) != 1 || reply.IsEdns0() == nil || reply.IsEdns0().UDPSize() != maxUDPSize {
		t.Fatalf("EDNS answer: %v", reply)
	}
	reply = exchange(t, "tcp", f.addr, dkim, dns.TypeTXT)
	if reply.Truncated || len(reply.Answer) != 1 || len(strings.Join(reply.Answer[0].(*dns.TXT).Txt, "")) < 600 {
		t.Fatalf("TCP answer: %v", reply)
	}
}

func TestResponseRateLimiting(t *testing.T) {
	l := newLimiter(5)
	client := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 53}
	neighbour := &net.UDPAddr{IP: net.ParseIP("198.51.100.200"), Port: 53}
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 53}
	now := time.Now()
	for i := range 10 {
		if got := l.decide(client, now); got != rrlAllow {
			t.Fatalf("burst response %d: %d", i, got)
		}
	}
	if l.decide(neighbour, now) != rrlSlip || l.decide(client, now) != rrlDrop || l.decide(client, now) != rrlSlip {
		t.Fatal("the /24 shares one budget and alternates slip and drop over the limit")
	}
	if l.decide(other, now) != rrlAllow {
		t.Fatal("other networks keep their own budget")
	}
	if l.decide(client, now.Add(time.Second)) != rrlAllow {
		t.Fatal("the budget refills over time")
	}

	// Over the wire: the slipped reply is truncated and TCP still answers.
	f := newFixture(t, Settings{})
	limited := New(f.zones.Hosted())
	limited.RateLimit = 1
	if err := limited.Apply(Settings{Enabled: true, Listen: "127.0.0.1:0"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(limited.Close)
	addr := limited.Addr()
	var truncated, answered int
	for range 6 {
		msg := new(dns.Msg)
		msg.SetQuestion("mail.example.test.", dns.TypeA)
		reply, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(msg, addr)
		switch {
		case err != nil:
		case reply.Truncated:
			truncated++
		default:
			answered++
		}
	}
	if answered != 2 || truncated != 2 {
		t.Fatalf("answered=%d truncated=%d, want 2 and 2 (2 dropped)", answered, truncated)
	}
	if reply := exchange(t, "tcp", addr, "mail.example.test", dns.TypeA); len(reply.Answer) != 1 {
		t.Fatalf("TCP is not rate limited: %v", reply)
	}
}

func TestZoneTransferRequiresTSIG(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	key := &TSIGKey{Name: "xfr.example.test.", Algorithm: dns.HmacSHA256, Secret: secret}
	transfer := func(addr string, sign *TSIGKey) ([]dns.RR, error) {
		msg := new(dns.Msg)
		msg.SetAxfr(zoneName + ".")
		tr := &dns.Transfer{}
		if sign != nil {
			msg.SetTsig(sign.Name, sign.Algorithm, 300, time.Now().Unix())
			tr.TsigSecret = map[string]string{sign.Name: sign.Secret}
		}
		envelopes, err := tr.In(msg, addr)
		if err != nil {
			return nil, err
		}
		var records []dns.RR
		for envelope := range envelopes {
			if envelope.Error != nil {
				return records, envelope.Error
			}
			records = append(records, envelope.RR...)
		}
		return records, nil
	}

	f := newFixture(t, Settings{})
	if _, err := transfer(f.addr, key); err == nil {
		t.Fatal("AXFR must be refused while no transfer key is configured")
	}
	if err := f.server.Apply(Settings{Enabled: true, Listen: f.server.Status().Listen, Nameservers: []string{"ns1.example.test"}, AXFR: key}); err != nil {
		t.Fatal(err)
	}
	if _, err := transfer(f.addr, nil); err == nil {
		t.Fatal("unsigned AXFR must be refused")
	}
	wrong := *key
	wrong.Secret = base64.StdEncoding.EncodeToString([]byte("another-secret-of-32-bytes-long!"))
	if _, err := transfer(f.addr, &wrong); err == nil {
		t.Fatal("AXFR with a wrong key must be refused")
	}
	if reply := exchange(t, "udp", f.addr, zoneName, dns.TypeAXFR); reply.Rcode != dns.RcodeRefused {
		t.Fatalf("AXFR over UDP: %v", reply)
	}
	records, err := transfer(f.addr, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) < 10 || records[0].Header().Rrtype != dns.TypeSOA || records[len(records)-1].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("transfer: %v", records)
	}
	found := false
	for _, rr := range records {
		found = found || (rr.Header().Rrtype == dns.TypeMX && rr.Header().Name == zoneName+".")
	}
	if !found {
		t.Fatalf("transfer lacks the MX record: %v", records)
	}
}

func TestLiveEnableDisableAndRebind(t *testing.T) {
	f := newFixture(t, Settings{})
	first := f.addr
	settings := Settings{Enabled: true, Listen: "127.0.0.1:0", Nameservers: []string{"ns.example.net"}}

	// Changing only zone settings keeps the sockets.
	settings.Listen = f.server.Status().Listen
	if err := f.server.Apply(settings); err != nil || f.server.Addr() != first {
		t.Fatalf("apply kept %s, want %s (%v)", f.server.Addr(), first, err)
	}
	if soa := exchange(t, "udp", first, zoneName, dns.TypeSOA).Answer[0].(*dns.SOA); soa.Ns != "ns.example.net." {
		t.Fatalf("nameservers not applied live: %v", soa)
	}

	// Rebinding moves both transports and closes the old ones.
	moved := freeDualPort(t)
	settings.Listen = moved
	if err := f.server.Apply(settings); err != nil {
		t.Fatal(err)
	}
	if f.server.Addr() != moved {
		t.Fatalf("addr %s, want %s", f.server.Addr(), moved)
	}
	for _, network := range []string{"udp", "tcp"} {
		if reply := exchange(t, network, moved, "mail.example.test", dns.TypeA); len(reply.Answer) != 1 {
			t.Fatalf("%s after rebind: %v", network, reply)
		}
	}
	if conn, err := net.DialTimeout("tcp", first, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("the old TCP listener is still open")
	}

	// A failed bind leaves the running server untouched.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	settings.Listen = blocker.Addr().String()
	if err := f.server.Apply(settings); err == nil {
		t.Fatal("binding a busy port must fail")
	}
	if f.server.Addr() != moved || f.server.Status().Listen != moved {
		t.Fatalf("failed rebind changed the server: %+v", f.server.Status())
	}

	if err := f.server.Apply(Settings{}); err != nil || f.server.Addr() != "" || f.server.Status().Running {
		t.Fatalf("disable: %v %+v", err, f.server.Status())
	}
	if obs := f.server.Observation(); obs.State != "disabled" {
		t.Fatalf("observation while disabled: %+v", obs)
	}
	settings.Listen = "127.0.0.1:0"
	if err := f.server.Apply(settings); err != nil || f.server.Addr() == "" {
		t.Fatalf("re-enable: %v", err)
	}
	if obs := f.server.Observation(); obs.State != "healthy" {
		t.Fatalf("observation while running: %+v", obs)
	}
}

func TestPublishPlanDKIMAndACMEServe(t *testing.T) {
	f := newFixture(t, Settings{})
	ctx := t.Context()
	serial := func() uint32 {
		return f.query(t, zoneName, dns.TypeSOA).Answer[0].(*dns.SOA).Serial
	}
	before := serial()

	// Publishing a plan through the provider interface is served at once
	// and bumps the SOA serial.
	desired := []dnsprovider.Desired{
		{Record: dnsprovider.Record{Type: "TXT", Name: "_dmarc.example.test", Value: "v=DMARC1; p=none"}, Prefix: "v=dmarc1"},
		{Record: dnsprovider.Record{Type: "TXT", Name: "s2._domainkey.example.test", Value: "v=DKIM1; k=ed25519; p=abc"}, Prefix: "v=dkim1"},
	}
	plan, err := f.zones.Plan(ctx, zoneName, desired, dnsprovider.Scope{Purpose: zoneName})
	if err != nil || plan.Provider != dnsprovider.KindBuiltin || len(plan.Changes) != 2 || plan.Changes[0].Action != dnsprovider.ActionCreate {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if _, err := f.zones.Apply(ctx, "admin", zoneName, desired, dnsprovider.Scope{Purpose: zoneName}, dnsprovider.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if reply := f.query(t, "_dmarc.example.test", dns.TypeTXT); len(reply.Answer) != 1 {
		t.Fatalf("published DMARC not served: %v", reply)
	}
	if after := serial(); after <= before {
		t.Fatalf("serial %d did not increase from %d", after, before)
	}

	// A DKIM rotation publish (a scoped Apply) replaces the selector set.
	scope := dnsprovider.Scope{Purpose: zoneName, Match: func(rec model.DNSOwnedRecord) bool { return strings.HasSuffix(rec.Name, "._domainkey."+zoneName) }}
	rotated := []dnsprovider.Desired{{Record: dnsprovider.Record{Type: "TXT", Name: "s3._domainkey.example.test", Value: "v=DKIM1; k=ed25519; p=def"}, Prefix: "v=dkim1"}}
	if _, err := f.zones.Apply(ctx, "system", zoneName, rotated, scope, dnsprovider.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(f.query(t, "s3._domainkey.example.test", dns.TypeTXT).Answer) != 1 || f.query(t, "s2._domainkey.example.test", dns.TypeTXT).Rcode != dns.RcodeNameError {
		t.Fatal("rotation did not publish s3 and remove s2")
	}
	if len(f.query(t, "s1._domainkey.example.test", dns.TypeTXT, func(m *dns.Msg) { m.SetEdns0(4096, false) }).Answer) != 1 {
		t.Fatal("the administrator's record must survive the rotation")
	}

	// ACME DNS-01: the challenge appears, propagation sees it on this
	// server, and cleanup removes it.
	f.zones.SetPropagation(dnsprovider.Propagation{Interval: 10 * time.Millisecond, Nameservers: func(context.Context, string) ([]string, error) {
		return []string{f.addr}, nil
	}})
	challenge := "_acme-challenge.mail.example.test"
	cleanup, err := f.zones.PresentTXT(ctx, challenge, "token-value", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if reply := f.query(t, challenge, dns.TypeTXT); len(reply.Answer) != 1 || reply.Answer[0].(*dns.TXT).Txt[0] != "token-value" {
		t.Fatalf("challenge not served: %v", reply)
	}
	if err := cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if reply := f.query(t, challenge, dns.TypeTXT); reply.Rcode != dns.RcodeNameError {
		t.Fatalf("challenge still served after cleanup: %v", reply)
	}
}

func TestDNSSECSigningAndCompactDenial(t *testing.T) {
	f := newFixture(t, Settings{DNSSEC: true})

	keys := f.query(t, zoneName, dns.TypeDNSKEY, withDO)
	var dnskey *dns.DNSKEY
	var keySig *dns.RRSIG
	var keySet []dns.RR
	for _, rr := range keys.Answer {
		switch rr := rr.(type) {
		case *dns.DNSKEY:
			dnskey = rr
			keySet = append(keySet, rr)
		case *dns.RRSIG:
			keySig = rr
		}
	}
	if dnskey == nil || keySig == nil || dnskey.Algorithm != dns.ECDSAP256SHA256 || dnskey.Flags != 257 {
		t.Fatalf("DNSKEY: %v", keys)
	}
	if err := keySig.Verify(dnskey, keySet); err != nil {
		t.Fatalf("DNSKEY RRset signature: %v", err)
	}
	view, err := f.zones.HostedZone(t.Context(), zoneName)
	if err != nil || len(view.Keys) != 1 || view.Keys[0].DS != dnskey.ToDS(dns.SHA256).String() {
		t.Fatalf("DS record: %+v %v", view.Keys, err)
	}

	verify := func(section []dns.RR, rtype uint16) {
		t.Helper()
		var set []dns.RR
		var sig *dns.RRSIG
		for _, rr := range section {
			if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == rtype {
				sig = s
			} else if rr.Header().Rrtype == rtype {
				set = append(set, rr)
			}
		}
		if sig == nil || len(set) == 0 {
			t.Fatalf("no signed %s RRset in %v", dns.TypeToString[rtype], section)
		}
		if err := sig.Verify(dnskey, set); err != nil || !sig.ValidityPeriod(time.Now()) {
			t.Fatalf("%s signature: %v", dns.TypeToString[rtype], err)
		}
	}
	reply := f.query(t, "mail.example.test", dns.TypeA, withDO)
	verify(reply.Answer, dns.TypeA)

	// Nonexistent names: NOERROR with a signed NSEC proving NXNAME.
	reply = f.query(t, "nope.example.test", dns.TypeA, withDO)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 {
		t.Fatalf("compact denial rcode: %v", reply)
	}
	verify(reply.Ns, dns.TypeSOA)
	verify(reply.Ns, dns.TypeNSEC)
	for _, rr := range reply.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok {
			if nsec.Hdr.Name != "nope.example.test." || nsec.NextDomain != "\\000.nope.example.test." || !slices.Contains(nsec.TypeBitMap, typeNXNAME) {
				t.Fatalf("NXNAME NSEC: %v", nsec)
			}
		}
	}
	// NODATA lists the types that do exist.
	reply = f.query(t, "mail.example.test", dns.TypeTXT, withDO)
	verify(reply.Ns, dns.TypeNSEC)
	for _, rr := range reply.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok && (!slices.Contains(nsec.TypeBitMap, dns.TypeA) || !slices.Contains(nsec.TypeBitMap, dns.TypeAAAA) || slices.Contains(nsec.TypeBitMap, typeNXNAME)) {
			t.Fatalf("NODATA NSEC bitmap: %v", nsec)
		}
	}
	// Clients without DO get plain unsigned answers and real NXDOMAIN.
	reply = f.query(t, "nope.example.test", dns.TypeA)
	if reply.Rcode != dns.RcodeNameError || slices.Contains(types(reply.Ns), "RRSIG") {
		t.Fatalf("non-DNSSEC client: %v", reply)
	}

	// Manual rollover: the staged key is published and the old one still
	// signs; activation switches signing to the new key.
	if step, err := f.zones.RollDNSSECKey(t.Context(), "admin", zoneName); err != nil || step != "staged" {
		t.Fatalf("stage: %s %v", step, err)
	}
	if got := types(f.query(t, zoneName, dns.TypeDNSKEY, withDO).Answer); !slices.Equal(got, []string{"DNSKEY", "DNSKEY", "RRSIG"}) {
		t.Fatalf("staged DNSKEY set: %v", got)
	}
	verify(f.query(t, "mail.example.test", dns.TypeA, withDO).Answer, dns.TypeA)
	if step, err := f.zones.RollDNSSECKey(t.Context(), "admin", zoneName); err != nil || step != "activated" {
		t.Fatalf("activate: %s %v", step, err)
	}
	reply = f.query(t, zoneName, dns.TypeDNSKEY, withDO)
	if len(reply.Answer) != 2 || reply.Answer[0].(*dns.DNSKEY).KeyTag() == dnskey.KeyTag() {
		t.Fatalf("activated key set: %v", reply)
	}
	dnskey = reply.Answer[0].(*dns.DNSKEY)
	verify(f.query(t, "mail.example.test", dns.TypeA, withDO).Answer, dns.TypeA)
}

// freeDualPort returns a loopback address whose port is free for both UDP
// and TCP at the time of the call.
func freeDualPort(t *testing.T) string {
	t.Helper()
	for range 50 {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := tcp.Addr().String()
		udp, err := net.ListenPacket("udp", addr)
		_ = tcp.Close()
		if err == nil {
			_ = udp.Close()
			return addr
		}
	}
	t.Fatal("no port free for both UDP and TCP")
	return ""
}
