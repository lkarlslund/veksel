package mailidentity

import (
	"context"
	"errors"
	"testing"
)

type fake struct {
	hosts map[string][]string
	ptrs  map[string][]string
}

func (f fake) LookupHost(_ context.Context, h string) ([]string, error) {
	if v, ok := f.hosts[h]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

func (f fake) LookupAddr(_ context.Context, a string) ([]string, error) {
	return f.ptrs[a], nil
}

func TestValidateFQDN(t *testing.T) {
	for name, ok := range map[string]bool{
		"mail.example.com": true, "Mail.Example.com.": true, "veksel": false, "192.0.2.1": false,
		"": false, "a..b": false, "-a.example.com": false, "a b.example.com": false, "2001:db8::1": false,
	} {
		if err := ValidateFQDN(name); (err == nil) != ok {
			t.Errorf("%q: err=%v want ok=%v", name, err, ok)
		}
	}
}

func TestFCrDNS(t *testing.T) {
	ok := fake{hosts: map[string][]string{"mail.example.com": {"192.0.2.1"}}, ptrs: map[string][]string{"192.0.2.1": {"mail.example.com."}}}
	if p := FCrDNS(t.Context(), ok, "mail.example.com", "192.0.2.1"); len(p) != 0 {
		t.Fatalf("ok: %v", p)
	}
	mismatch := fake{hosts: ok.hosts, ptrs: map[string][]string{"192.0.2.1": {"other.example.net."}}}
	if p := FCrDNS(t.Context(), mismatch, "mail.example.com", "192.0.2.1"); len(p) != 1 {
		t.Fatalf("mismatch: %v", p)
	}
	missing := fake{hosts: map[string][]string{"mail.example.com": {"192.0.2.9"}}}
	if p := FCrDNS(t.Context(), missing, "mail.example.com", "192.0.2.1"); len(p) != 2 {
		t.Fatalf("missing: %v", p)
	}
	if p := FCrDNS(t.Context(), ok, "mail.example.com", "bogus"); len(p) != 1 {
		t.Fatalf("bad addr: %v", p)
	}
}

func TestProblems(t *testing.T) {
	r := fake{hosts: map[string][]string{"mail.example.com": {"192.0.2.1"}}}
	if p := Problems(t.Context(), r, "mail.example.com", ""); len(p) != 0 {
		t.Fatal(p)
	}
	if p := Problems(t.Context(), r, "veksel", ""); len(p) != 1 {
		t.Fatal(p)
	}
	if p := Problems(t.Context(), r, "nx.example.com", ""); len(p) != 1 {
		t.Fatal(p)
	}
	if p := Problems(t.Context(), r, "mail.example.com", "192.0.2.1"); len(p) != 1 {
		t.Fatalf("no ptr: %v", p)
	}
}

func TestMessageIDDomain(t *testing.T) {
	for _, tc := range []struct{ address, server, want string }{
		{"Alice <alice@Example.TEST>", "mx.example.net", "example.test"},
		{"alice@example.test", "", "example.test"},
		{"", "MX.Example.NET.", "mx.example.net"},
		{"broken@", "mx.example.net", "mx.example.net"},
		{"user@localhost", "mx.example.net", "mx.example.net"},
	} {
		if got := MessageIDDomain(tc.address, tc.server); got != tc.want {
			t.Errorf("MessageIDDomain(%q, %q) = %q, want %q", tc.address, tc.server, got, tc.want)
		}
	}
	if got := MessageIDDomain("", ""); got == "" || got == "veksel.local" {
		t.Fatalf("fallback domain = %q", got)
	}
}
