package spam

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// spfZone is an in-memory DNS for SPF tests. Names absent from a map do
// not exist; names in fail answer every query with a server failure.
type spfZone struct {
	txt  map[string][]string
	a    map[string][]string // A and AAAA addresses
	mx   map[string][]string
	ptr  map[string][]string
	fail map[string]bool
}

func (z *spfZone) err(name string) error {
	if z.fail[name] {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (z *spfZone) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := z.txt[name]; ok && !z.fail[name] {
		return v, nil
	}
	return nil, z.err(name)
}

func (z *spfZone) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if v, ok := z.mx[name]; ok && !z.fail[name] {
		out := make([]*net.MX, len(v))
		for i, host := range v {
			out[i] = &net.MX{Host: host + ".", Pref: uint16(10 * i)}
		}
		return out, nil
	}
	return nil, z.err(name)
}

func (z *spfZone) LookupHost(_ context.Context, name string) ([]string, error) {
	if v, ok := z.a[name]; ok && !z.fail[name] {
		return v, nil
	}
	return nil, z.err(name)
}

func (z *spfZone) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := z.ptr[addr]; ok && !z.fail[addr] {
		return v, nil
	}
	return nil, z.err(addr)
}

// LookupNetIP exercises the per-family query path.
func (z *spfZone) LookupNetIP(ctx context.Context, network, name string) ([]netip.Addr, error) {
	hosts, err := z.LookupHost(ctx, name)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, host := range hosts {
		addr := netip.MustParseAddr(host)
		if addr.Is4() == (network == "ip4") {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, z.err(name)
	}
	return out, nil
}

// hostOnly hides LookupNetIP so the LookupHost fallback is exercised.
type hostOnly struct{ SPFResolver }

// rfcZone is the RFC 7208 Appendix D.1 example zone.
func rfcZone(record string) *spfZone {
	return &spfZone{
		txt: map[string][]string{"example.com": {record}},
		a: map[string][]string{
			"example.com": {"192.0.2.10", "192.0.2.11"}, "amy.example.com": {"192.0.2.65"}, "bob.example.com": {"192.0.2.66"},
			"mail-a.example.com": {"192.0.2.129"}, "mail-b.example.com": {"192.0.2.130"}, "www.example.com": {"192.0.2.10", "192.0.2.11"},
			"mail-c.example.org": {"192.0.2.140"},
		},
		mx: map[string][]string{"example.com": {"mail-a.example.com", "mail-b.example.com"}, "example.org": {"mail-c.example.org"}},
		ptr: map[string][]string{
			"192.0.2.10": {"example.com."}, "192.0.2.11": {"example.com."}, "192.0.2.65": {"amy.example.com."},
			"192.0.2.66": {"bob.example.com."}, "192.0.2.129": {"mail-a.example.com."}, "192.0.2.130": {"mail-b.example.com."},
			"192.0.2.140": {"mail-c.example.org."}, "10.0.0.4": {"bob.example.com."},
		},
	}
}

func checkSPF(r SPFResolver, ip, sender string) SPFOutcome {
	return CheckSPF(context.Background(), r, SPFRequest{IP: netip.MustParseAddr(ip), Sender: sender, Helo: "mx.example.net", Receiver: "mx.receiver.test",
		Now: func() time.Time { return time.Unix(1700000000, 0) }})
}

// TestSPFAppendixDExamples evaluates the RFC 7208 Appendix D.2 records.
func TestSPFAppendixDExamples(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		record string
		pass   []string
		fail   []string
	}{
		{"v=spf1 +all", []string{"192.0.2.1", "203.0.113.9"}, nil},
		{"v=spf1 a -all", []string{"192.0.2.10", "192.0.2.11"}, []string{"192.0.2.65", "192.0.2.129"}},
		{"v=spf1 a:example.org -all", nil, []string{"192.0.2.10", "192.0.2.140"}},
		{"v=spf1 mx -all", []string{"192.0.2.129", "192.0.2.130"}, []string{"192.0.2.10", "192.0.2.140"}},
		{"v=spf1 mx:example.org -all", []string{"192.0.2.140"}, []string{"192.0.2.129"}},
		{"v=spf1 mx mx:example.org -all", []string{"192.0.2.129", "192.0.2.130", "192.0.2.140"}, []string{"192.0.2.10"}},
		{"v=spf1 mx/30 mx:example.org/30 -all", []string{"192.0.2.128", "192.0.2.131", "192.0.2.141", "192.0.2.143"}, []string{"192.0.2.132", "192.0.2.144"}},
		{"v=spf1 ptr -all", []string{"192.0.2.65", "192.0.2.10"}, []string{"192.0.2.140", "10.0.0.4"}},
		{"v=spf1 ip4:192.0.2.128/28 -all", []string{"192.0.2.129"}, []string{"192.0.2.65"}},
	} {
		zone := rfcZone(tc.record)
		for _, ip := range tc.pass {
			if got := checkSPF(zone, ip, "user@example.com"); got.Result != SPFPass {
				t.Errorf("%q from %s = %+v, want pass", tc.record, ip, got)
			}
		}
		for _, ip := range tc.fail {
			if got := checkSPF(zone, ip, "user@example.com"); got.Result != SPFFail {
				t.Errorf("%q from %s = %+v, want fail", tc.record, ip, got)
			}
		}
	}
}

// TestSPFRecordEvaluation covers mechanisms, qualifiers, modifiers and
// error classes, following the cases of the pyspf/openspf RFC 7208 suite.
func TestSPFRecordEvaluation(t *testing.T) {
	t.Parallel()
	longLabel := strings.Repeat("a", 63)
	tests := []struct {
		name   string
		txt    map[string][]string // merged over e.example.com defaults
		ip     string
		sender string
		want   SPFResult
	}{
		// Initial processing and record selection.
		{"no record", map[string][]string{"e.example.com": {"not spf"}}, "1.2.3.4", "", SPFNone},
		{"nxdomain", nil, "1.2.3.4", "user@missing.example.com", SPFNone},
		{"too long label", nil, "1.2.3.4", "user@" + longLabel + "a.example.com", SPFNone},
		{"63 octet label", map[string][]string{longLabel + ".example.com": {"v=spf1 -all"}}, "1.2.3.4", "user@" + longLabel + ".example.com", SPFFail},
		{"empty label", nil, "1.2.3.4", "user@a..example.com", SPFNone},
		{"single label", nil, "1.2.3.4", "user@localhost", SPFNone},
		{"domain literal", nil, "1.2.3.4", "user@[1.2.3.4]", SPFNone},
		{"txt temperror", map[string][]string{"fail.example.com": {"v=spf1 +all"}}, "1.2.3.4", "user@fail.example.com", SPFTemperror},
		{"version needs space", map[string][]string{"e.example.com": {"v=spf1mx -all"}}, "1.2.3.4", "", SPFNone},
		{"version only", map[string][]string{"e.example.com": {"v=spf1"}}, "1.2.3.4", "", SPFNeutral},
		{"version case", map[string][]string{"e.example.com": {"V=sPf1 +all"}}, "1.2.3.4", "", SPFPass},
		{"multiple records", map[string][]string{"e.example.com": {"v=spf1 +all", "v=spf1 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"non spf txt ignored", map[string][]string{"e.example.com": {"v=spf10 +all", "google-site-verification=x", "v=spf1 -all"}}, "1.2.3.4", "", SPFFail},
		{"extra spaces", map[string][]string{"e.example.com": {"v=spf1  ip4:1.1.1.1   -all "}}, "1.2.3.4", "", SPFFail},
		{"non ascii", map[string][]string{"e.example.com": {"v=spf1 a:exämple.com -all"}}, "1.2.3.4", "", SPFPermerror},
		{"control char", map[string][]string{"e.example.com": {"v=spf1 a:ex\x01ample.com -all"}}, "1.2.3.4", "", SPFPermerror},
		{"tab is not a separator", map[string][]string{"e.example.com": {"v=spf1\t-all"}}, "1.2.3.4", "", SPFNone},

		// Syntax errors anywhere make the whole record a permerror.
		{"error after match", map[string][]string{"e.example.com": {"v=spf1 +all foobar"}}, "1.2.3.4", "", SPFPermerror},
		{"unknown mechanism", map[string][]string{"e.example.com": {"v=spf1 frob -all"}}, "1.2.3.4", "", SPFPermerror},
		{"modifier name digit", map[string][]string{"e.example.com": {"v=spf1 -all 3=foo"}}, "1.2.3.4", "", SPFPermerror},
		{"unknown modifier ignored", map[string][]string{"e.example.com": {"v=spf1 moo.cow-far_out=man:dog/cat -all"}}, "1.2.3.4", "", SPFFail},
		{"unknown modifier bad macro", map[string][]string{"e.example.com": {"v=spf1 foo=%{z} -all"}}, "1.2.3.4", "", SPFPermerror},
		{"redirect is a modifier", map[string][]string{"e.example.com": {"v=spf1 redirect:t.example.com"}}, "1.2.3.4", "", SPFPermerror},
		{"duplicate redirect", map[string][]string{"e.example.com": {"v=spf1 redirect=a.example.com redirect=b.example.com"}}, "1.2.3.4", "", SPFPermerror},
		{"duplicate exp", map[string][]string{"e.example.com": {"v=spf1 exp=a.example.com exp=b.example.com -all"}}, "1.2.3.4", "", SPFPermerror},
		{"empty exp", map[string][]string{"e.example.com": {"v=spf1 exp= -all"}}, "1.2.3.4", "", SPFPermerror},

		// all and qualifiers.
		{"+all", map[string][]string{"e.example.com": {"v=spf1 +all"}}, "1.2.3.4", "", SPFPass},
		{"bare all", map[string][]string{"e.example.com": {"v=spf1 all"}}, "1.2.3.4", "", SPFPass},
		{"-all", map[string][]string{"e.example.com": {"v=spf1 -all"}}, "1.2.3.4", "", SPFFail},
		{"~all", map[string][]string{"e.example.com": {"v=spf1 ~all"}}, "1.2.3.4", "", SPFSoftfail},
		{"?all", map[string][]string{"e.example.com": {"v=spf1 ?all"}}, "1.2.3.4", "", SPFNeutral},
		{"first all wins", map[string][]string{"e.example.com": {"v=spf1 all -all"}}, "1.2.3.4", "", SPFPass},
		{"all with dot", map[string][]string{"e.example.com": {"v=spf1 -all."}}, "1.2.3.4", "", SPFPermerror},
		{"all with arg", map[string][]string{"e.example.com": {"v=spf1 -all:foobar"}}, "1.2.3.4", "", SPFPermerror},
		{"all with cidr", map[string][]string{"e.example.com": {"v=spf1 -all/8"}}, "1.2.3.4", "", SPFPermerror},
		{"minus mechanism fails", map[string][]string{"e.example.com": {"v=spf1 -ip4:1.2.3.4 +all"}}, "1.2.3.4", "", SPFFail},
		{"tilde mechanism", map[string][]string{"e.example.com": {"v=spf1 ~ip4:1.2.3.4 +all"}}, "1.2.3.4", "", SPFSoftfail},
		{"question mechanism", map[string][]string{"e.example.com": {"v=spf1 ?ip4:1.2.3.4 -all"}}, "1.2.3.4", "", SPFNeutral},
		{"default neutral", map[string][]string{"e.example.com": {"v=spf1 ip4:5.6.7.8"}}, "1.2.3.4", "", SPFNeutral},

		// ip4 and ip6.
		{"ip4 cidr", map[string][]string{"e.example.com": {"v=spf1 ip4:1.2.0.0/16 -all"}}, "1.2.3.4", "", SPFPass},
		{"ip4 /0", map[string][]string{"e.example.com": {"v=spf1 ip4:9.9.9.9/0 -all"}}, "1.2.3.4", "", SPFPass},
		{"ip4 /32", map[string][]string{"e.example.com": {"v=spf1 ip4:1.2.3.4/32 -all"}}, "1.2.3.4", "", SPFPass},
		{"ip4 /33", map[string][]string{"e.example.com": {"v=spf1 ip4:1.2.3.4/33 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"ip4 /032", map[string][]string{"e.example.com": {"v=spf1 ip4:1.2.3.4/032 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"bare ip4", map[string][]string{"e.example.com": {"v=spf1 ip4 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"ip4 port", map[string][]string{"e.example.com": {"v=spf1 ip4:1.2.3.4:8080 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"ip4 short", map[string][]string{"e.example.com": {"v=spf1 ip4:1.2.3 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"ip4 dual cidr", map[string][]string{"e.example.com": {"v=spf1 ip4:1.2.3.4//32 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"legacy ip4= syntax", map[string][]string{"e.example.com": {"v=spf1 ip4=1.2.3.4 -all"}}, "1.2.3.4", "", SPFFail},
		{"ip4 mapped client", map[string][]string{"e.example.com": {"v=spf1 ip4:1.2.3.4 -all"}}, "::ffff:1.2.3.4", "", SPFPass},
		{"ip4 does not match v6", map[string][]string{"e.example.com": {"v=spf1 ip4:0.0.0.0/0 -all"}}, "2001:db8::1", "", SPFFail},
		{"ip6 cidr", map[string][]string{"e.example.com": {"v=spf1 ip6:2001:db8::/32 -all"}}, "2001:db8:1::5", "", SPFPass},
		{"ip6 /0 not v4", map[string][]string{"e.example.com": {"v=spf1 ip6:::/0 -all"}}, "1.2.3.4", "", SPFFail},
		{"ip6 /129", map[string][]string{"e.example.com": {"v=spf1 ip6:2001:db8::/129 -all"}}, "2001:db8::1", "", SPFPermerror},
		{"ip6 with v4 network", map[string][]string{"e.example.com": {"v=spf1 ip6:1.2.3.4 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"ip6 mapped network", map[string][]string{"e.example.com": {"v=spf1 ip6:::ffff:1.2.3.0/120 -all"}}, "1.2.3.4", "", SPFPass},

		// a.
		{"a v4", map[string][]string{"e.example.com": {"v=spf1 a:h.example.com -all"}}, "1.2.3.4", "", SPFPass},
		{"a v6 uses aaaa", map[string][]string{"e.example.com": {"v=spf1 a:h.example.com -all"}}, "2001:db8::4", "", SPFPass},
		{"a cidr4", map[string][]string{"e.example.com": {"v=spf1 a:h.example.com/24 -all"}}, "1.2.3.200", "", SPFPass},
		{"a dual cidr", map[string][]string{"e.example.com": {"v=spf1 a:h.example.com/32//64 -all"}}, "2001:db8::ffff", "", SPFPass},
		{"a dual cidr v4 strict", map[string][]string{"e.example.com": {"v=spf1 a:h.example.com/32//64 -all"}}, "1.2.3.5", "", SPFFail},
		{"a implicit cidr6", map[string][]string{"e.example.com": {"v=spf1 a//33 -all"}}, "1.2.3.4", "", SPFFail},
		{"a implicit /0", map[string][]string{"e.example.com": {"v=spf1 a/0 -all"}}, "9.9.9.9", "", SPFPass},
		{"a implicit domain", map[string][]string{"e.example.com": {"v=spf1 a -all"}}, "1.2.3.10", "", SPFPass},
		{"a bad cidr4", map[string][]string{"e.example.com": {"v=spf1 a/33 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"a bad cidr6", map[string][]string{"e.example.com": {"v=spf1 a//129 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"a numeric toplabel", map[string][]string{"e.example.com": {"v=spf1 a:1.2.3.4 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"a only toplabel", map[string][]string{"e.example.com": {"v=spf1 a:museum -all"}}, "1.2.3.4", "", SPFPermerror},
		{"a only toplabel dot", map[string][]string{"e.example.com": {"v=spf1 a:museum. -all"}}, "1.2.3.4", "", SPFPermerror},
		{"a bad toplabel", map[string][]string{"e.example.com": {"v=spf1 a:foo.example.-com -all"}}, "1.2.3.4", "", SPFPermerror},
		{"a dashed toplabel", map[string][]string{"e.example.com": {"v=spf1 a:foo.example.xn--zz -all"}}, "1.2.3.4", "", SPFFail},
		{"a empty domain", map[string][]string{"e.example.com": {"v=spf1 a: -all"}}, "1.2.3.4", "", SPFPermerror},
		{"a nxdomain", map[string][]string{"e.example.com": {"v=spf1 a:nx.example.com -all"}}, "1.2.3.4", "", SPFFail},
		{"a temperror", map[string][]string{"e.example.com": {"v=spf1 a:fail.example.com -all"}}, "1.2.3.4", "", SPFTemperror},
		{"a empty label void", map[string][]string{"e.example.com": {"v=spf1 a:t.e..example.com -all"}}, "1.2.3.4", "", SPFFail},

		// mx.
		{"mx", map[string][]string{"e.example.com": {"v=spf1 mx -all"}}, "1.2.3.20", "", SPFPass},
		{"mx v6", map[string][]string{"e.example.com": {"v=spf1 mx -all"}}, "2001:db8::20", "", SPFPass},
		{"mx cidr", map[string][]string{"e.example.com": {"v=spf1 mx/30 -all"}}, "1.2.3.22", "", SPFPass},
		{"mx no implicit a", map[string][]string{"e.example.com": {"v=spf1 mx:h.example.com -all"}}, "1.2.3.4", "", SPFFail},
		{"mx null", map[string][]string{"e.example.com": {"v=spf1 mx:null.example.com -all"}}, "1.2.3.4", "", SPFFail},
		{"mx limit", map[string][]string{"e.example.com": {"v=spf1 mx:many.example.com -all"}}, "1.2.3.4", "", SPFPermerror},
		{"mx at limit", map[string][]string{"e.example.com": {"v=spf1 mx:ten.example.com -all"}}, "1.2.3.4", "", SPFPass},
		{"mx temperror", map[string][]string{"e.example.com": {"v=spf1 mx:fail.example.com -all"}}, "1.2.3.4", "", SPFTemperror},
		{"mx bad cidr", map[string][]string{"e.example.com": {"v=spf1 mx/33 -all"}}, "1.2.3.4", "", SPFPermerror},

		// ptr.
		{"ptr", map[string][]string{"e.example.com": {"v=spf1 ptr -all"}}, "1.2.3.10", "", SPFPass},
		{"ptr explicit", map[string][]string{"e.example.com": {"v=spf1 ptr:example.com -all"}}, "1.2.3.10", "", SPFPass},
		{"ptr unvalidated", map[string][]string{"e.example.com": {"v=spf1 ptr -all"}}, "1.2.3.99", "", SPFFail},
		{"ptr lookup error no match", map[string][]string{"e.example.com": {"v=spf1 ptr -all"}}, "1.2.3.66", "", SPFFail},
		{"ptr only ten names", map[string][]string{"e.example.com": {"v=spf1 ptr:example.com -all"}}, "1.2.3.77", "", SPFFail},
		{"ptr empty", map[string][]string{"e.example.com": {"v=spf1 ptr: -all"}}, "1.2.3.4", "", SPFPermerror},

		// exists.
		{"exists", map[string][]string{"e.example.com": {"v=spf1 exists:h.example.com -all"}}, "9.9.9.9", "", SPFPass},
		{"exists needs a", map[string][]string{"e.example.com": {"v=spf1 exists:v6only.example.com -all"}}, "2001:db8::4", "", SPFFail},
		{"exists empty", map[string][]string{"e.example.com": {"v=spf1 exists: -all"}}, "1.2.3.4", "", SPFPermerror},
		{"exists implicit", map[string][]string{"e.example.com": {"v=spf1 exists -all"}}, "1.2.3.4", "", SPFPermerror},
		{"exists cidr", map[string][]string{"e.example.com": {"v=spf1 exists:h.example.com/24 -all"}}, "1.2.3.4", "", SPFPermerror},

		// include.
		{"include pass", map[string][]string{"e.example.com": {"v=spf1 include:i.example.com -all"}, "i.example.com": {"v=spf1 ip4:1.2.3.4 -all"}}, "1.2.3.4", "", SPFPass},
		{"include fail no match", map[string][]string{"e.example.com": {"v=spf1 include:i.example.com ?all"}, "i.example.com": {"v=spf1 -all"}}, "1.2.3.4", "", SPFNeutral},
		{"include softfail no match", map[string][]string{"e.example.com": {"v=spf1 include:i.example.com -all"}, "i.example.com": {"v=spf1 ~all"}}, "1.2.3.4", "", SPFFail},
		{"include neutral no match", map[string][]string{"e.example.com": {"v=spf1 include:i.example.com -all"}, "i.example.com": {"v=spf1 ?all"}}, "1.2.3.4", "", SPFFail},
		{"include qualifier", map[string][]string{"e.example.com": {"v=spf1 -include:i.example.com +all"}, "i.example.com": {"v=spf1 +all"}}, "1.2.3.4", "", SPFFail},
		{"include temperror", map[string][]string{"e.example.com": {"v=spf1 include:fail.example.com -all"}, "fail.example.com": {"v=spf1 +all"}}, "1.2.3.4", "", SPFTemperror},
		{"include syntax error", map[string][]string{"e.example.com": {"v=spf1 include:i.example.com -all"}, "i.example.com": {"v=spf1 frob"}}, "1.2.3.4", "", SPFPermerror},
		{"include none", map[string][]string{"e.example.com": {"v=spf1 include:nx.example.com -all"}}, "1.2.3.4", "", SPFPermerror},
		{"include no spf", map[string][]string{"e.example.com": {"v=spf1 include:i.example.com -all"}, "i.example.com": {"hello"}}, "1.2.3.4", "", SPFPermerror},
		{"include empty", map[string][]string{"e.example.com": {"v=spf1 include: -all"}}, "1.2.3.4", "", SPFPermerror},
		{"include cidr", map[string][]string{"e.example.com": {"v=spf1 include:i.example.com/24 -all"}}, "1.2.3.4", "", SPFPermerror},
		{"include google style", map[string][]string{
			"e.example.com":           {"v=spf1 include:_spf.google.test -all"},
			"_spf.google.test":        {"v=spf1 include:_netblocks.google.test include:_netblocks2.google.test ~all"},
			"_netblocks.google.test":  {"v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"},
			"_netblocks2.google.test": {"v=spf1 ip6:2001:4860:4000::/36 ~all"},
		}, "64.233.184.27", "", SPFPass},

		// redirect.
		{"redirect", map[string][]string{"e.example.com": {"v=spf1 redirect=r.example.com"}, "r.example.com": {"v=spf1 ip4:1.2.3.4 -all"}}, "1.2.3.4", "", SPFPass},
		{"redirect result", map[string][]string{"e.example.com": {"v=spf1 redirect=r.example.com"}, "r.example.com": {"v=spf1 ~all"}}, "1.2.3.4", "", SPFSoftfail},
		{"redirect after all ignored", map[string][]string{"e.example.com": {"v=spf1 -all redirect=r.example.com"}, "r.example.com": {"v=spf1 +all"}}, "1.2.3.4", "", SPFFail},
		{"redirect none", map[string][]string{"e.example.com": {"v=spf1 redirect=nx.example.com"}}, "1.2.3.4", "", SPFPermerror},
		{"redirect loop", map[string][]string{"e.example.com": {"v=spf1 redirect=e.example.com"}}, "1.2.3.4", "", SPFPermerror},
		{"include loop", map[string][]string{"e.example.com": {"v=spf1 include:e.example.com -all"}}, "1.2.3.4", "", SPFPermerror},

		// Processing limits.
		{"ten lookups", map[string][]string{"e.example.com": {"v=spf1 " + strings.Repeat("a:x.example.com ", 9) + "a:h.example.com -all"}}, "1.2.3.4", "", SPFPass},
		{"eleven lookups", map[string][]string{"e.example.com": {"v=spf1 " + strings.Repeat("a:x.example.com ", 10) + "a:h.example.com -all"}}, "1.2.3.4", "", SPFPermerror},
		{"lookup limit spans includes", map[string][]string{"e.example.com": {"v=spf1 include:i.example.com a:h.example.com -all"}, "i.example.com": {"v=spf1 " + strings.Repeat("a:x.example.com ", 9) + "-all"}}, "1.2.3.4", "", SPFPermerror},
		{"ip and all are free", map[string][]string{"e.example.com": {"v=spf1 " + strings.Repeat("ip4:5.5.5.5 ", 30) + strings.Repeat("a:x.example.com ", 9) + "a:h.example.com -all"}}, "1.2.3.4", "", SPFPass},
		{"two voids", map[string][]string{"e.example.com": {"v=spf1 a:nx1.example.com a:nx2.example.com a:h.example.com -all"}}, "1.2.3.4", "", SPFPass},
		{"three voids", map[string][]string{"e.example.com": {"v=spf1 a:nx1.example.com a:nx2.example.com a:nx3.example.com a:h.example.com -all"}}, "1.2.3.4", "", SPFPermerror},
		{"void mx counts", map[string][]string{"e.example.com": {"v=spf1 mx:nx1.example.com exists:nx2.example.com a:nx3.example.com +all"}}, "1.2.3.4", "", SPFPermerror},

		// HELO identity for a null sender.
		{"helo pass", map[string][]string{"helo.example.com": {"v=spf1 ip4:1.2.3.4 -all"}}, "1.2.3.4", "", SPFPass},
		{"no local part", map[string][]string{"e.example.com": {"v=spf1 exists:%{l}.local.example.com -all"}, "postmaster.local.example.com": {"x"}}, "1.2.3.4", "@e.example.com", SPFPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			zone := baseZone()
			for name, values := range tc.txt {
				zone.txt[name] = values
			}
			sender := tc.sender
			if sender == "" && !strings.HasPrefix(tc.name, "helo") {
				sender = "user@e.example.com"
			}
			for _, resolver := range []SPFResolver{zone, hostOnly{zone}} {
				got := CheckSPF(context.Background(), resolver, SPFRequest{IP: netip.MustParseAddr(tc.ip), Sender: sender, Helo: "helo.example.com"})
				if got.Result != tc.want {
					t.Fatalf("%T: got %+v, want %s", resolver, got, tc.want)
				}
				if (got.Result == SPFPermerror || got.Result == SPFTemperror) != (got.Problem != "") {
					t.Fatalf("problem %q for result %s", got.Problem, got.Result)
				}
			}
		})
	}
}

// baseZone holds the hosts the evaluation table refers to.
func baseZone() *spfZone {
	zone := &spfZone{
		txt: map[string][]string{"fail.example.com": {"v=spf1 +all"}},
		a: map[string][]string{
			"e.example.com": {"1.2.3.10"}, "h.example.com": {"1.2.3.4", "2001:db8::4"}, "v6only.example.com": {"2001:db8::4"},
			"mx1.example.com": {"1.2.3.20", "2001:db8::20"}, "mx2.example.com": {"1.2.3.21"},
			"example.com": {"1.2.3.10"}, "x.example.com": {"9.9.9.9"}, "postmaster.local.example.com": {"127.0.0.2"},
			"spoof.example.com": {"1.2.3.99"},
		},
		mx: map[string][]string{
			"e.example.com": {"mx1.example.com", "mx2.example.com"}, "null.example.com": {"."},
		},
		ptr: map[string][]string{
			"1.2.3.10": {"e.example.com."}, "1.2.3.99": {"spoof.example.com.", "evil.test."},
		},
		fail: map[string]bool{"fail.example.com": true, "1.2.3.66": true},
	}
	var many []string
	for i := range 11 {
		host := "m" + strconv.Itoa(i) + ".example.com"
		many = append(many, host)
		zone.a[host] = []string{"5.5.5." + strconv.Itoa(i)}
	}
	zone.mx["many.example.com"] = many
	zone.mx["ten.example.com"] = append(append([]string{}, many[:9]...), "h.example.com")
	var ptrs []string
	for i := range 11 {
		ptrs = append(ptrs, "p"+strconv.Itoa(i)+".example.com.")
	}
	zone.ptr["1.2.3.77"] = ptrs
	zone.a["p10.example.com"] = []string{"1.2.3.77"}
	return zone
}

func TestSPFMacroExpansionAppendixD(t *testing.T) {
	t.Parallel()
	e := &spfEval{ip: netip.MustParseAddr("192.0.2.3"), sender: "strong-bad@email.example.com", local: "strong-bad", senderDomain: "email.example.com",
		helo: "mx.example.org", receiver: "rx.example.net", now: func() time.Time { return time.Unix(1700000000, 0) }}
	for macro, want := range map[string]string{
		"%{s}":                              "strong-bad@email.example.com",
		"%{o}":                              "email.example.com",
		"%{d}":                              "email.example.com",
		"%{d4}":                             "email.example.com",
		"%{d3}":                             "email.example.com",
		"%{d2}":                             "example.com",
		"%{d1}":                             "com",
		"%{dr}":                             "com.example.email",
		"%{d2r}":                            "example.email",
		"%{l}":                              "strong-bad",
		"%{l-}":                             "strong.bad",
		"%{lr}":                             "strong-bad",
		"%{lr-}":                            "bad.strong",
		"%{l1r-}":                           "strong",
		"%{ir}.%{v}._spf.%{d2}":             "3.2.0.192.in-addr._spf.example.com",
		"%{lr-}.lp._spf.%{d2}":              "bad.strong.lp._spf.example.com",
		"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}":   "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
		"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}":  "3.2.0.192.in-addr.strong.lp._spf.example.com",
		"%{d2}.trusted-domains.example.net": "example.com.trusted-domains.example.net",
		"%{S}":                              "strong-bad%40email.example.com",
		"%{h}":                              "mx.example.org",
		"%%%_%-":                            "% %20",
		"%{l-.}":                            "strong.bad",
		"%{d999}":                           "email.example.com",
	} {
		got, err := e.expand(macro, "email.example.com", false)
		if err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", macro, got, err, want)
		}
	}
	for macro, want := range map[string]string{"%{c}": "192.0.2.3", "%{r}": "rx.example.net", "%{t}": "1700000000"} {
		if got, err := e.expand(macro, "email.example.com", true); err != nil || got != want {
			t.Errorf("exp %s = %q, %v; want %q", macro, got, err, want)
		}
	}
	e.ip = netip.MustParseAddr("2001:db8::cb01")
	want := "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
	if got, err := e.expand("%{ir}.%{v}._spf.%{d2}", "email.example.com", false); err != nil || got != want {
		t.Errorf("IPv6 = %q, %v; want %q", got, err, want)
	}
}

func TestSPFMacroSyntax(t *testing.T) {
	t.Parallel()
	for _, record := range []string{
		"v=spf1 exists:%{x}.example.com", "v=spf1 exists:%{l}%{x}.example.com", "v=spf1 exists:%{l}%",
		"v=spf1 exists:%{c}.example.com", "v=spf1 exists:%{r}.example.com", "v=spf1 exists:%{t}.example.com",
		"v=spf1 exists:%{d0}.example.com", "v=spf1 exists:%{d.example.com", "v=spf1 exists:%x.example.com",
		"v=spf1 exists:%{l:}.example.com", "v=spf1 exists:%{}.example.com",
	} {
		if ParseSPFRecord(record) == nil {
			t.Errorf("%q parsed, want syntax error", record)
		}
	}
	for _, record := range []string{
		"v=spf1 exists:%{i}.%{l1r+-}.%{o}.example.com -all", "v=spf1 a:%{d}", "v=spf1 exists:%{ir}.%{v}.arpa._spf.%{d2}",
		"v=spf1 exp=%{l}.exp.example.com -all", "v=spf1 a:%{l/}.example.com/24//64", "v=spf1 include:_spf.%{d}.",
	} {
		if err := ParseSPFRecord(record); err != nil {
			t.Errorf("%q: %v", record, err)
		}
	}
}

func TestSPFMacroEvaluation(t *testing.T) {
	t.Parallel()
	zone := baseZone()
	zone.txt["e.example.com"] = []string{"v=spf1 -exists:%{lr-}.deny.example.com exists:%{ir}.%{v}._spf.%{d2} -all"}
	zone.a["4.3.2.1.in-addr._spf.example.com"] = []string{"127.0.0.2"}
	zone.a["bad.joe.deny.example.com"] = []string{"127.0.0.2"}
	if got := checkSPF(zone, "1.2.3.4", "user@e.example.com"); got.Result != SPFPass {
		t.Fatalf("exists macro = %+v", got)
	}
	if got := checkSPF(zone, "1.2.3.4", "joe-bad@e.example.com"); got.Result != SPFFail {
		t.Fatalf("deny macro = %+v", got)
	}
	// %{p} prefers the validated name of the domain; none is "unknown".
	zone.txt["e.example.com"] = []string{"v=spf1 exists:%{p}.p.example.com -all"}
	zone.a["e.example.com.p.example.com"] = []string{"127.0.0.2"}
	zone.a["unknown.p.example.com"] = []string{"127.0.0.3"}
	if got := checkSPF(zone, "1.2.3.10", "user@e.example.com"); got.Result != SPFPass {
		t.Fatalf("%%{p} = %+v", got)
	}
	if got := checkSPF(zone, "1.2.3.4", "user@e.example.com"); got.Result != SPFPass {
		t.Fatalf("%%{p} without PTR = %+v", got)
	}
	// 1.2.3.99 validates only spoof.example.com, outside the domain.
	if got := checkSPF(zone, "1.2.3.99", "user@e.example.com"); got.Result != SPFFail {
		t.Fatalf("%%{p} foreign name = %+v", got)
	}
	// Overlong expansions lose labels on the left (RFC 7208 section 7.3).
	local := strings.Repeat("x", 60) + "." + strings.Repeat("y", 60) + "." + strings.Repeat("z", 60) + "." + strings.Repeat("w", 60)
	zone.txt["e.example.com"] = []string{"v=spf1 exists:%{l}.t.example.com -all"}
	zone.a[strings.Repeat("y", 60)+"."+strings.Repeat("z", 60)+"."+strings.Repeat("w", 60)+".t.example.com"] = []string{"127.0.0.2"}
	if got := checkSPF(zone, "1.2.3.4", local+"@e.example.com"); got.Result != SPFPass {
		t.Fatalf("truncation = %+v", got)
	}
}

func TestSPFExplanation(t *testing.T) {
	t.Parallel()
	zone := baseZone()
	zone.txt["e.example.com"] = []string{"v=spf1 include:i.example.com exp=why.example.com -all"}
	zone.txt["i.example.com"] = []string{"v=spf1 exp=inner.example.com -all"}
	zone.txt["why.example.com"] = []string{"%{i} is not one of %{d}'s designated mail servers (%{c} at %{r})."}
	got := checkSPF(zone, "1.2.3.4", "user@e.example.com")
	if got.Result != SPFFail || got.Explanation != "1.2.3.4 is not one of e.example.com's designated mail servers (1.2.3.4 at mx.receiver.test)." {
		t.Fatalf("explanation = %+v", got)
	}
	for name, txt := range map[string][]string{"multiple txt": {"a", "b"}, "syntax error": {"bad %{"}, "no txt": nil} {
		if txt == nil {
			delete(zone.txt, "why.example.com")
		} else {
			zone.txt["why.example.com"] = txt
		}
		if got := checkSPF(zone, "1.2.3.4", "user@e.example.com"); got.Result != SPFFail || got.Explanation != "" {
			t.Errorf("%s: %+v", name, got)
		}
	}
	// A redirect target's own exp applies; the original's does not.
	zone.txt["e.example.com"] = []string{"v=spf1 exp=why.example.com redirect=r.example.com"}
	zone.txt["why.example.com"] = []string{"outer"}
	zone.txt["r.example.com"] = []string{"v=spf1 -all"}
	if got := checkSPF(zone, "1.2.3.4", "user@e.example.com"); got.Result != SPFFail || got.Explanation != "" || got.Mechanism != "-all" {
		t.Fatalf("redirect exp = %+v", got)
	}
}

func TestSPFOutcomeIdentity(t *testing.T) {
	t.Parallel()
	zone := baseZone()
	zone.txt["helo.example.com"] = []string{"v=spf1 ip4:1.2.3.4 -all"}
	got := CheckSPF(t.Context(), zone, SPFRequest{IP: netip.MustParseAddr("1.2.3.4"), Helo: "HELO.example.com."})
	if got.Result != SPFPass || got.Identity != SPFIdentityHelo || got.Sender != "postmaster@helo.example.com" || got.Domain != "helo.example.com" || got.Mechanism != "ip4:1.2.3.4" {
		t.Fatalf("helo = %+v", got)
	}
	if got := CheckSPF(t.Context(), zone, SPFRequest{IP: netip.MustParseAddr("1.2.3.4"), Helo: "[1.2.3.4]"}); got.Result != SPFNone {
		t.Fatalf("address literal helo = %+v", got)
	}
	if got := CheckSPF(t.Context(), zone, SPFRequest{IP: netip.MustParseAddr("1.2.3.4"), Sender: "<a@helo.example.com>", Helo: "x.test"}); got.Identity != SPFIdentityMailFrom || got.Result != SPFPass {
		t.Fatalf("mailfrom = %+v", got)
	}
	if got := CheckSPF(t.Context(), zone, SPFRequest{Sender: "a@helo.example.com"}); got.Result != SPFPermerror {
		t.Fatalf("invalid IP = %+v", got)
	}
}

func TestSPFTimeout(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	zone := baseZone()
	zone.txt["e.example.com"] = []string{"v=spf1 -all"}
	if got := CheckSPF(ctx, zone, SPFRequest{IP: netip.MustParseAddr("1.2.3.4"), Sender: "a@e.example.com"}); got.Result != SPFTemperror {
		t.Fatalf("cancelled = %+v", got)
	}
}

func TestSPFLookupLimitReported(t *testing.T) {
	t.Parallel()
	zone := baseZone()
	for i := range 12 {
		zone.txt["c"+strconv.Itoa(i)+".example.com"] = []string{"v=spf1 include:c" + strconv.Itoa(i+1) + ".example.com -all"}
	}
	got := checkSPF(zone, "1.2.3.4", "a@c0.example.com")
	if got.Result != SPFPermerror || !strings.Contains(got.Problem, "lookup limit") || got.Lookups != 11 {
		t.Fatalf("chain = %+v", got)
	}
}
