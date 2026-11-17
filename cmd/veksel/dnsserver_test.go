package main

import (
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/miekg/dns"
)

func TestDNSServerSettingsApplyLive(t *testing.T) {
	s := startLoopbackServer(t)
	if s.dnsServer.Status().Running {
		t.Fatal("the DNS server is disabled by default")
	}
	if _, err := s.appHandler.DNSZones().Put(t.Context(), "admin", "example.test", dnsprovider.ZoneInput{Provider: dnsprovider.KindBuiltin}); err != nil {
		t.Fatal(err)
	}
	patch := func(changes map[string]any) {
		t.Helper()
		patchLive(t, s, changes)
		for _, state := range s.cfgService.ApplyStates() {
			if state.Error != "" {
				t.Fatalf("%s failed to apply: %s", state.Key, state.Error)
			}
		}
	}
	soa := func(addr string) *dns.SOA {
		t.Helper()
		msg := new(dns.Msg)
		msg.SetQuestion("example.test.", dns.TypeSOA)
		reply, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(msg, addr)
		if err != nil || len(reply.Answer) != 1 {
			t.Fatalf("SOA from %s: %v %v", addr, reply, err)
		}
		return reply.Answer[0].(*dns.SOA)
	}

	first := freeAddress(t)
	patch(map[string]any{"smtp_server_name": "mail.example.test", "dns_server_enabled": true, "dns_server_listen": first})
	if got := soa(first); got.Ns != "mail.example.test." {
		t.Fatalf("without configured nameservers the SMTP server name is the primary: %v", got)
	}
	patch(map[string]any{"dns_server_nameservers": []string{"ns1.example.net", "ns2.example.net"}})
	if got := soa(first); got.Ns != "ns1.example.net." {
		t.Fatalf("nameservers not applied live: %v", got)
	}
	moved := freeAddress(t)
	patch(map[string]any{"dns_server_listen": moved})
	if s.dnsServer.Addr() != moved {
		t.Fatalf("rebind: %s, want %s", s.dnsServer.Addr(), moved)
	}
	soa(moved)
	patch(map[string]any{"dns_server_enabled": false})
	if s.dnsServer.Status().Running {
		t.Fatal("disable did not stop the server")
	}
}
