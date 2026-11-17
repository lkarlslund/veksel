package compatibility

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteThunderbirdProfileIsolatedAccount(t *testing.T) {
	profile := t.TempDir()
	if err := writeThunderbirdProfile(profile, "127.0.0.1", 3143, FixtureUsername); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(profile, "prefs.js"))
	if err != nil {
		t.Fatal(err)
	}
	prefs := string(data)
	for _, expected := range []string{`"127.0.0.1"`, `3143`, `"compat"`, `"imap"`, `socketType", 0`} {
		if !strings.Contains(prefs, expected) {
			t.Errorf("profile does not contain %q", expected)
		}
	}
	if strings.Contains(prefs, FixturePassword) {
		t.Fatal("profile persisted fixture password")
	}
}

func TestThunderbirdVersionPattern(t *testing.T) {
	match := thunderbirdVersionPattern.FindStringSubmatch("Mozilla Thunderbird 153.0esr\n")
	if len(match) != 2 || match[1] != "153.0esr" {
		t.Fatalf("version match = %v", match)
	}
}
