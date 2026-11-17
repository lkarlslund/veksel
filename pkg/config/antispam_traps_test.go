package config

import (
	"slices"
	"testing"
)

func TestParseSpamtraps(t *testing.T) {
	traps, err := ParseSpamtraps([]string{" Trap ", "honey.pot@Example.TEST", "trap@other.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(traps.LocalParts, []string{"trap"}) || !slices.Equal(traps.Addresses, []string{"honey.pot@example.test", "trap@other.test"}) {
		t.Fatalf("traps = %+v", traps)
	}
	for _, bad := range [][]string{{""}, {"two words"}, {"trap@"}, {"@example.test"}, {"trap@bad_domain"}, {".trap"}, {"trap", "TRAP"}} {
		if _, err := ParseSpamtraps(bad); err == nil {
			t.Errorf("ParseSpamtraps(%q) accepted", bad)
		}
	}
}

func TestParseARCTrustedSealers(t *testing.T) {
	sealers, err := ParseARCTrustedSealers([]string{"Google.com.", " microsoft.com"})
	if err != nil || !slices.Equal(sealers, []string{"google.com", "microsoft.com"}) {
		t.Fatalf("sealers = %v, %v", sealers, err)
	}
	for _, bad := range []string{"", "com", "not a domain", "exa_mple.com"} {
		if _, err := ParseARCTrustedSealers([]string{bad}); err == nil {
			t.Errorf("ParseARCTrustedSealers(%q) accepted", bad)
		}
	}
}
