package jsonstore

import (
	"context"
	"os"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/storetest"
)

func TestClosedStore(t *testing.T) {
	storetest.RunClosed(t, func(t *testing.T) store.Store { return newTestStore(t) })
}

func TestRangeIteration(t *testing.T) {
	storetest.RunRangeIteration(t, func(t *testing.T) store.Store { return newTestStore(t) })
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndDeleteNamespace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.CreateNamespace(ctx, "test"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}

	if err := s.CreateNamespace(ctx, "test"); err != store.ErrExists {
		t.Fatalf("CreateNamespace duplicate: expected ErrExists, got %v", err)
	}

	exists, err := s.NamespaceExists(ctx, "test")
	if err != nil || !exists {
		t.Fatalf("NamespaceExists: exists=%v err=%v", exists, err)
	}

	ns, err := s.ListNamespaces(ctx)
	if err != nil {
		t.Fatalf("ListNamespaces: %v", err)
	}
	if len(ns) != 1 || ns[0] != "test" {
		t.Fatalf("ListNamespaces: got %v", ns)
	}

	if err := s.DeleteNamespace(ctx, "test"); err != nil {
		t.Fatalf("DeleteNamespace: %v", err)
	}

	exists, err = s.NamespaceExists(ctx, "test")
	if err != nil || exists {
		t.Fatalf("NamespaceExists after delete: exists=%v err=%v", exists, err)
	}
}

func TestCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.CreateNamespace(ctx, "items"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}

	// Put
	if err := s.Put(ctx, "items", "a", []byte("alpha")); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if err := s.Put(ctx, "items", "b", []byte("beta")); err != nil {
		t.Fatalf("Put b: %v", err)
	}

	// Put duplicate
	if err := s.Put(ctx, "items", "a", []byte("dup")); err != store.ErrExists {
		t.Fatalf("Put duplicate: expected ErrExists, got %v", err)
	}

	// Get
	val, err := s.Get(ctx, "items", "a")
	if err != nil {
		t.Fatalf("Get a: %v", err)
	}
	if string(val) != "alpha" {
		t.Fatalf("Get a: got %q", val)
	}

	// Set (overwrite)
	if err := s.Set(ctx, "items", "a", []byte("updated")); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	val, err = s.Get(ctx, "items", "a")
	if err != nil || string(val) != "updated" {
		t.Fatalf("Get a after Set: got %q err=%v", val, err)
	}

	// List
	keys, err := s.List(ctx, "items")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
		t.Fatalf("List: got %v", keys)
	}

	// Scan
	keys, err = s.Scan(ctx, "items", "a")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(keys) != 1 || keys[0] != "a" {
		t.Fatalf("Scan a*: got %v", keys)
	}

	// Delete
	if err := s.Delete(ctx, "items", "a"); err != nil {
		t.Fatalf("Delete a: %v", err)
	}
	if _, err := s.Get(ctx, "items", "a"); err != store.ErrNotFound {
		t.Fatalf("Get after delete: expected ErrNotFound, got %v", err)
	}

	// Not found
	if _, err := s.Get(ctx, "items", "nope"); err != store.ErrNotFound {
		t.Fatalf("Get missing: expected ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, "items", "nope"); err != store.ErrNotFound {
		t.Fatalf("Delete missing: expected ErrNotFound, got %v", err)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()

	// First instance: write data
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := s1.CreateNamespace(ctx, "persist"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s1.Put(ctx, "persist", "key1", []byte("value1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s1.Close()

	// Second instance: read data back
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	defer s2.Close()

	val, err := s2.Get(ctx, "persist", "key1")
	if err != nil {
		t.Fatalf("Get after reload: %v", err)
	}
	if string(val) != "value1" {
		t.Fatalf("Get after reload: got %q", val)
	}
	if err := s2.Set(ctx, "persist", "key1", []byte("updated")); err != nil {
		t.Fatalf("Set after reload: %v", err)
	}
	if err := s2.Put(ctx, "persist", "key2", []byte("value2")); err != nil {
		t.Fatalf("Put after reload: %v", err)
	}
	if err := s2.Delete(ctx, "persist", "key1"); err != nil {
		t.Fatalf("Delete after reload: %v", err)
	}
	keys, err := s2.List(ctx, "persist")
	if err != nil || len(keys) != 1 || keys[0] != "key2" {
		t.Fatalf("List after cached mutations: keys=%v err=%v", keys, err)
	}
}

func TestKeyJournalReplaysBeforeGracefulClose(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	first, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CreateNamespace(ctx, "items"); err != nil {
		t.Fatal(err)
	}
	if err := first.Put(ctx, "items", "removed", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := first.Put(ctx, "items", "retained", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := first.Delete(ctx, "items", "removed"); err != nil {
		t.Fatal(err)
	}

	baseline, err := os.ReadFile(first.keysFile("items"))
	if err != nil {
		t.Fatal(err)
	}
	if string(baseline) != "null" {
		t.Fatalf("keys.json changed before compaction: %s", baseline)
	}

	second, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := second.List(ctx, "items")
	if err != nil || len(keys) != 1 || keys[0] != "retained" {
		t.Fatalf("journal replay keys=%v err=%v", keys, err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKeyJournalCompactsAtThreshold(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	if err := s.CreateNamespace(ctx, "items"); err != nil {
		t.Fatal(err)
	}
	s.keyMutations["items"] = keyJournalCompactThreshold - 1
	if err := s.Put(ctx, "items", "key", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if s.keyMutations["items"] != 0 {
		t.Fatalf("key mutations = %d, want 0 after compaction", s.keyMutations["items"])
	}
	journal, err := os.ReadFile(s.keyJournalFile("items"))
	if err != nil || len(journal) != 0 {
		t.Fatalf("journal after compaction = %q, %v", journal, err)
	}
}

func TestBinaryValues(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.CreateNamespace(ctx, "bin"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}

	original := []byte{0x00, 0xff, 0xfe, 0x80, 0x01}
	if err := s.Put(ctx, "bin", "data", original); err != nil {
		t.Fatalf("Put: %v", err)
	}

	val, err := s.Get(ctx, "bin", "data")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if len(val) != len(original) {
		t.Fatalf("Get: length mismatch: got %d want %d", len(val), len(original))
	}
	for i := range original {
		if val[i] != original[i] {
			t.Fatalf("Get: byte mismatch at %d: got 0x%02x want 0x%02x", i, val[i], original[i])
		}
	}
}

func TestEmptyNamespace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.CreateNamespace(ctx, "empty"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}

	keys, err := s.List(ctx, "empty")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("List empty: got %v", keys)
	}
}

func TestStoreInTempDir(t *testing.T) {
	// Verify that New creates the directory if it doesn't exist.
	dir := t.TempDir() + "/nested/data"
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("data directory was not created")
	}
}
