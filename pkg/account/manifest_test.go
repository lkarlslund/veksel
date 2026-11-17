package account

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

func TestNewManifestNormalizesIdentity(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.FixedZone("test", 3600))
	manifest, err := NewManifest(
		" Alice ",
		" Alice Example ",
		"Alice@Example.COM",
		[]string{"alias@example.com", "ALICE@example.com", "alias@example.com"},
		store.BackendPebble,
		now,
	)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	if manifest.Login != "alice" {
		t.Fatalf("Login: got %q, want alice", manifest.Login)
	}
	if manifest.PrimaryAddress != "alice@example.com" {
		t.Fatalf("PrimaryAddress: got %q", manifest.PrimaryAddress)
	}
	wantAddresses := []string{"alias@example.com", "alice@example.com"}
	if strings.Join(manifest.Addresses, ",") != strings.Join(wantAddresses, ",") {
		t.Fatalf("Addresses: got %v, want %v", manifest.Addresses, wantAddresses)
	}
	if manifest.CreatedAt.Location() != time.UTC || manifest.UpdatedAt.Location() != time.UTC {
		t.Fatal("manifest timestamps must be UTC")
	}
}

func TestManifestRoundTripAndPermissions(t *testing.T) {
	manifest, err := NewManifest("alice", "Alice", "alice@example.com", nil, store.BackendBadger, time.Now())
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	path := filepath.Join(t.TempDir(), manifest.ID, ManifestFilename)
	if err := WriteManifest(path, manifest); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("manifest permissions: got %o, want 600", got)
	}
	got, err := ReadManifest(path)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if got.ID != manifest.ID || got.Engine != store.BackendBadger || got.Login != "alice" {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, manifest)
	}
}

func TestManifestRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), ManifestFilename)
	data := `{"schema_version":1,"unknown":true}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadManifest(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ReadManifest: got %v, want unknown field error", err)
	}
}

func TestManifestValidation(t *testing.T) {
	valid, err := NewManifest("alice", "Alice", "alice@example.com", nil, store.BackendPebble, time.Now())
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "named path ID", mutate: func(m *Manifest) { m.ID = "alice" }},
		{name: "JSON engine", mutate: func(m *Manifest) { m.Engine = store.BackendJSON }},
		{name: "uppercase login", mutate: func(m *Manifest) { m.Login = "Alice" }},
		{name: "missing generation", mutate: func(m *Manifest) { m.ActiveGeneration = "" }},
		{name: "converting without job", mutate: func(m *Manifest) { m.State = StateConverting }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := valid
			test.mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("Validate unexpectedly succeeded")
			}
		})
	}
}
