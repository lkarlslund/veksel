package config

import (
	"net/netip"
	"testing"
)

func TestParseDestinations(t *testing.T) {
	destinations, err := ParseDestinations("key", []string{"10.20.30.13:7090", "10.0.0.0/24", "[fd00::5]:443", "192.168.1.0/24:8443"})
	if err != nil {
		t.Fatal(err)
	}
	for address, want := range map[string]bool{
		"10.20.30.13:7090": true,
		"10.20.30.13:22":   false,
		"10.0.0.77:1234":   true,
		"[fd00::5]:443":    true,
		"[fd00::5]:80":     false,
		"192.168.1.9:8443": true,
		"192.168.1.9:443":  false,
	} {
		addrPort := netip.MustParseAddrPort(address)
		allowed := false
		for _, destination := range destinations {
			allowed = allowed || destination.Allows(addrPort)
		}
		if allowed != want {
			t.Errorf("%s allowed=%v, want %v", address, allowed, want)
		}
	}
	for _, invalid := range []string{"10.0.0.5:0", "10.0.0.5:99999", "host.example:80", "[fd00::5", "10.0.0.0/33"} {
		if _, err := ParseDestinations("key", []string{invalid}); err == nil {
			t.Errorf("%q accepted", invalid)
		}
	}
}
