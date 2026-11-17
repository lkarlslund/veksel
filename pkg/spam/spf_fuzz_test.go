package spam

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

// wildcardZone answers every TXT query with one record and every address
// query with a fixed pair, so fuzzed includes and redirects recurse.
type wildcardZone struct{ record string }

func (z wildcardZone) LookupTXT(context.Context, string) ([]string, error) {
	return []string{z.record}, nil
}

func (z wildcardZone) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx." + name + ".", Pref: 10}}, nil
}

func (z wildcardZone) LookupHost(context.Context, string) ([]string, error) {
	return []string{"192.0.2.1", "2001:db8::1"}, nil
}

func (z wildcardZone) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"host.example.com."}, nil
}

// FuzzSPFRecord parses and evaluates arbitrary records. Evaluation must
// terminate within the lookup limit with a defined result, and a record
// that fails to parse must evaluate to permerror.
func FuzzSPFRecord(f *testing.F) {
	for _, seed := range []string{
		"v=spf1 include:_spf.google.com -all", "v=spf1 a/24//64 mx:%{d2}/30 ptr ?all",
		"v=spf1 exists:%{ir}.%{v}._spf.%{d2} redirect=%{d}", "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all",
		"v=spf1 exp=%{l}.%{o} foo=%{S}%%%_%- -all", "v=spf1 a:%{l1r-}.%{d999r+}", "v=spf1 %{", "v=spf1 ip4:1.2.3.4/33",
	} {
		f.Add(seed, "192.0.2.1", "user@example.com")
	}
	results := map[SPFResult]bool{SPFNone: true, SPFNeutral: true, SPFPass: true, SPFFail: true, SPFSoftfail: true, SPFTemperror: true, SPFPermerror: true}
	f.Fuzz(func(t *testing.T, record, ip, sender string) {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			addr = netip.MustParseAddr("192.0.2.1")
		}
		parseErr := ParseSPFRecord(record)
		got := CheckSPF(context.Background(), wildcardZone{record}, SPFRequest{IP: addr, Sender: sender, Helo: "helo.example.com"})
		if !results[got.Result] {
			t.Fatalf("undefined result %q", got.Result)
		}
		if got.Lookups > spfLookupLimit+1 {
			t.Fatalf("%d lookups exceed the limit", got.Lookups)
		}
		if parseErr != nil && isSPFRecord(record) && validSPFDomain(got.Domain) && got.Result != SPFPermerror {
			t.Fatalf("unparsable %q evaluated to %s", record, got.Result)
		}
	})
}
