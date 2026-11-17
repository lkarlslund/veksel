package account

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

func createDiscoveredAccount(t *testing.T, root, login, address string, engine store.Backend) Manifest {
	t.Helper()
	manifest, err := NewManifest(login, login, address, nil, engine, time.Now())
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	accountPath := filepath.Join(root, manifest.ID)
	if err := os.MkdirAll(filepath.Join(accountPath, "generations", manifest.ActiveGeneration), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := WriteManifest(filepath.Join(accountPath, ManifestFilename), manifest); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	return manifest
}

func TestDiscoverAndResolve(t *testing.T) {
	root := t.TempDir()
	alice := createDiscoveredAccount(t, root, "alice", "alice@example.com", store.BackendPebble)
	bob := createDiscoveredAccount(t, root, "bob", "bob@example.com", store.BackendBadger)
	if err := os.Mkdir(filepath.Join(root, "tombstones"), 0o700); err != nil {
		t.Fatalf("Mkdir tombstones: %v", err)
	}

	catalog, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(catalog.Issues()) != 0 {
		t.Fatalf("Issues: %v", catalog.Issues())
	}
	if got, found := catalog.ByLogin(" ALICE "); !found || got.Manifest.ID != alice.ID {
		t.Fatalf("ByLogin: got %+v, found=%v", got, found)
	}
	if got, found := catalog.ByAddress("BOB@EXAMPLE.COM"); !found || got.Manifest.ID != bob.ID {
		t.Fatalf("ByAddress: got %+v, found=%v", got, found)
	}
	if len(catalog.Entries()) != 2 {
		t.Fatalf("Entries: got %d, want 2", len(catalog.Entries()))
	}
}

func TestDiscoverRejectsPathMismatchAndSymlink(t *testing.T) {
	root := t.TempDir()
	manifest := createDiscoveredAccount(t, root, "alice", "alice@example.com", store.BackendPebble)
	wrongPath := filepath.Join(root, "acc_00000000000000000000000000000000")
	if err := os.Rename(filepath.Join(root, manifest.ID), wrongPath); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, "acc_11111111111111111111111111111111")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	catalog, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(catalog.Entries()) != 0 {
		t.Fatalf("Entries: got %d, want 0", len(catalog.Entries()))
	}
	if len(catalog.Issues()) != 2 {
		t.Fatalf("Issues: got %v, want 2", catalog.Issues())
	}
}

func TestDiscoverFailsDuplicateIdentityClosed(t *testing.T) {
	root := t.TempDir()
	first := createDiscoveredAccount(t, root, "same", "first@example.com", store.BackendPebble)
	second := createDiscoveredAccount(t, root, "other", "second@example.com", store.BackendBadger)
	second.Login = first.Login
	second.UpdatedAt = second.UpdatedAt.Add(time.Second)
	if err := WriteManifest(filepath.Join(root, second.ID, ManifestFilename), second); err != nil {
		t.Fatalf("WriteManifest duplicate: %v", err)
	}
	catalog, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, found := catalog.ByID(first.ID); found {
		t.Fatal("first duplicate account remained resolvable")
	}
	if _, found := catalog.ByID(second.ID); found {
		t.Fatal("second duplicate account remained resolvable")
	}
	if _, found := catalog.ByLogin("same"); found {
		t.Fatal("duplicate login remained resolvable")
	}
}
