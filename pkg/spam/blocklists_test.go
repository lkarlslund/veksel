package spam

import (
	"net/netip"
	"testing"
	"time"
)

func TestCheckAddressReportsListedCleanAndRefused(t *testing.T) {
	zones, err := ParseZones(ZoneDNSBL, []string{"zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{answers: map[string][]string{
		"7.113.0.203.zen.spamhaus.org": {"127.0.0.2"},
		"7.113.0.203.bl.spamcop.net":   {"127.255.255.254"},
	}}
	dns := NewDNS(resolver, DNSOptions{QueryTimeout: time.Second})
	listings := dns.CheckAddress(t.Context(), netip.MustParseAddr(publicIP), zones)
	if len(listings) != 3 {
		t.Fatalf("listings = %+v", listings)
	}
	if !listings[0].Listed || len(listings[0].Reasons) == 0 {
		t.Fatalf("zen listing = %+v, want listed with a reason", listings[0])
	}
	if listings[1].Listed || !listings[1].Refused {
		t.Fatalf("spamcop listing = %+v, want refused and not listed", listings[1])
	}
	if listings[2].Listed || listings[2].Refused || listings[2].Error != "" {
		t.Fatalf("barracuda listing = %+v, want clean", listings[2])
	}
	if stats := dns.Stats(); len(stats) != 3 {
		t.Fatalf("zone statistics = %+v, want the self-check recorded", stats)
	}
}

func TestCheckAddressQueriesIPv6Nibbles(t *testing.T) {
	zones, err := ParseZones(ZoneDNSBL, []string{"zen.spamhaus.org"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{}
	listings := NewDNS(resolver, DNSOptions{QueryTimeout: time.Second}).CheckAddress(t.Context(), netip.MustParseAddr("2001:db8::1"), zones)
	if len(listings) != 1 || listings[0].Listed {
		t.Fatalf("listings = %+v", listings)
	}
	queried := resolver.queried()
	if len(queried) != 1 || queried[0] != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.zen.spamhaus.org" {
		t.Fatalf("queried %v", queried)
	}
}
