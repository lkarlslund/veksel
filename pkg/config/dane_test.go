package config

import (
	"slices"
	"testing"
)

func TestParseResolverAddresses(t *testing.T) {
	got, err := ParseResolverAddresses("dane_resolvers", []string{" 127.0.0.1 ", "127.0.0.53:5353", "::1", "[2001:db8::53]:53", "::ffff:192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:53", "127.0.0.53:5353", "[::1]:53", "[2001:db8::53]:53", "192.0.2.1:53"}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseResolverAddresses() = %q, want %q", got, want)
	}
	for _, invalid := range []string{"resolver.example", "127.0.0.1:0", "fe80::1%eth0", "10.0.0.0/8", ""} {
		if _, err := ParseResolverAddresses("dane_resolvers", []string{invalid}); err == nil {
			t.Errorf("ParseResolverAddresses(%q) accepted", invalid)
		}
	}
	cfg := Default()
	cfg.DaneResolvers = []string{"not-an-address"}
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate accepted an invalid dane_resolvers entry")
	}
}
