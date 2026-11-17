package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestDefaultConfigurationReference keeps the checked-in operator reference
// byte-for-byte aligned with the document written for a new data directory.
// UPDATE_GOLDEN is test tooling only; it is never read by the server.
func TestDefaultConfigurationReference(t *testing.T) {
	want, err := defaultDocument(DefaultAt("./data"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "configuration-default.toml")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/configuration-default.toml is stale; run UPDATE_GOLDEN=1 go test ./pkg/config -run TestDefaultConfigurationReference")
	}
}

func TestConfigurationGuideDefaultsFollowManagedConfig(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	values := publicConfigValues(DefaultAt("./data"))
	rows := regexp.MustCompile("(?m)^\\| `([^`]+)` \\| (?:`([^`]*)`|(empty)) \\|").FindAllSubmatch(contents, -1)
	if len(rows) == 0 {
		t.Fatal("configuration guide contains no setting/default rows")
	}
	for _, row := range rows {
		key := string(row[1])
		value, ok := values[key]
		if !ok {
			t.Errorf("configuration guide documents unknown managed key %q", key)
			continue
		}
		want := string(row[2])
		if len(row[3]) > 0 {
			want = ""
		}
		if got := fmt.Sprint(value); got != want {
			t.Errorf("configuration guide default for %s = %q, code default = %q", key, want, got)
		}
	}
}
