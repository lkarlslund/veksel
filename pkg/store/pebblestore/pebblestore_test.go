package pebblestore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/cockroachdb/pebble"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

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

func ctx() context.Context {
	return context.Background()
}

// ---------------------------------------------------------------------------
// Get / Set / Put / Delete
// ---------------------------------------------------------------------------

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get(ctx(), "ns", "missing")
	if err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSetAndGet(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "key", []byte("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err := s.Get(ctx(), "ns", "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(val) != "val" {
		t.Fatalf("Get: got %q, want %q", val, "val")
	}
}

func TestSetOverwrite(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "key", []byte("v1")); err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	if err := s.Set(ctx(), "ns", "key", []byte("v2")); err != nil {
		t.Fatalf("Set v2: %v", err)
	}

	val, err := s.Get(ctx(), "ns", "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(val) != "v2" {
		t.Fatalf("Get: got %q, want v2", val)
	}
}

func TestPutNewKey(t *testing.T) {
	s := newTestStore(t)

	if err := s.Put(ctx(), "ns", "key", []byte("val")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	val, err := s.Get(ctx(), "ns", "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(val) != "val" {
		t.Fatalf("Get: got %q, want val", val)
	}
}

func TestPutDuplicate(t *testing.T) {
	s := newTestStore(t)

	if err := s.Put(ctx(), "ns", "key", []byte("v1")); err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	if err := s.Put(ctx(), "ns", "key", []byte("v2")); err != store.ErrExists {
		t.Fatalf("Put v2: expected ErrExists, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "key", []byte("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete(ctx(), "ns", "key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx(), "ns", "key"); err != store.ErrNotFound {
		t.Fatalf("Get after delete: expected ErrNotFound, got %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.Delete(ctx(), "ns", "missing"); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMultipleKeys(t *testing.T) {
	s := newTestStore(t)

	for _, k := range []string{"a", "b", "c"} {
		if err := s.Set(ctx(), "ns", k, []byte(k+"-val")); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}

	for _, k := range []string{"a", "b", "c"} {
		val, err := s.Get(ctx(), "ns", k)
		if err != nil {
			t.Fatalf("Get %s: %v", k, err)
		}
		if string(val) != k+"-val" {
			t.Fatalf("Get %s: got %q, want %s-val", k, val, k)
		}
	}
}

func TestDifferentNamespaces(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns1", "key", []byte("v1")); err != nil {
		t.Fatalf("Set ns1: %v", err)
	}
	if err := s.Set(ctx(), "ns2", "key", []byte("v2")); err != nil {
		t.Fatalf("Set ns2: %v", err)
	}

	val1, err := s.Get(ctx(), "ns1", "key")
	if err != nil || string(val1) != "v1" {
		t.Fatalf("Get ns1: got %q err=%v", val1, err)
	}
	val2, err := s.Get(ctx(), "ns2", "key")
	if err != nil || string(val2) != "v2" {
		t.Fatalf("Get ns2: got %q err=%v", val2, err)
	}
}

// ---------------------------------------------------------------------------
// List / Scan / CompareAndSwap / Iterate
// ---------------------------------------------------------------------------

func TestListEmpty(t *testing.T) {
	s := newTestStore(t)
	keys, err := s.List(ctx(), "empty")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("List: expected empty, got %v", keys)
	}
}

func TestList(t *testing.T) {
	s := newTestStore(t)

	for _, k := range []string{"charlie", "alpha", "bravo"} {
		if err := s.Set(ctx(), "ns", k, []byte("x")); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}

	keys, err := s.List(ctx(), "ns")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("List: got %d keys, want 3", len(keys))
	}
	// Keys should be sorted
	if keys[0] != "alpha" || keys[1] != "bravo" || keys[2] != "charlie" {
		t.Fatalf("List: expected sorted, got %v", keys)
	}
}

func TestListIsolation(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns1", "a", []byte("x")); err != nil {
		t.Fatalf("Set ns1: %v", err)
	}
	if err := s.Set(ctx(), "ns2", "b", []byte("x")); err != nil {
		t.Fatalf("Set ns2: %v", err)
	}

	keys, err := s.List(ctx(), "ns1")
	if err != nil {
		t.Fatalf("List ns1: %v", err)
	}
	if len(keys) != 1 || keys[0] != "a" {
		t.Fatalf("List ns1: got %v", keys)
	}
}

func TestScanEmpty(t *testing.T) {
	s := newTestStore(t)
	keys, err := s.Scan(ctx(), "ns", "pre")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("Scan: expected empty, got %v", keys)
	}
}

func TestScan(t *testing.T) {
	s := newTestStore(t)

	for _, k := range []string{"user:1", "user:2", "item:1", "user:3"} {
		if err := s.Set(ctx(), "ns", k, []byte("x")); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}

	keys, err := s.Scan(ctx(), "ns", "user:")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("Scan: got %d keys, want 3: %v", len(keys), keys)
	}
	for _, k := range keys {
		if k[:5] != "user:" {
			t.Fatalf("Scan: unexpected key %q", k)
		}
	}
}

func TestScanNoMatch(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "a", []byte("x")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	keys, err := s.Scan(ctx(), "ns", "zzz")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("Scan: expected empty, got %v", keys)
	}
}

func TestScanBoundsStopAtPrefixSuccessor(t *testing.T) {
	lower, upper := scanBounds("ns", "pre")
	if string(lower) != "ns\x00pre" || string(upper) != "ns\x00prf" {
		t.Fatalf("ordinary bounds lower=%q upper=%q", lower, upper)
	}
	lower, upper = scanBounds("ns", "pre\xff")
	if string(lower) != "ns\x00pre\xff" || string(upper) != "ns\x00prf" {
		t.Fatalf("carry bounds lower=%q upper=%q", lower, upper)
	}
	lower, upper = scanBounds("ns", "")
	if string(lower) != "ns\x00" || string(upper) != string(nsSentinelNext("ns")) {
		t.Fatalf("namespace bounds lower=%q upper=%q", lower, upper)
	}
}

func TestCompareAndSwapSuccess(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "key", []byte("old")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.CompareAndSwap(ctx(), "ns", "key", []byte("old"), []byte("new")); err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}

	val, err := s.Get(ctx(), "ns", "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(val) != "new" {
		t.Fatalf("Get: got %q, want new", val)
	}
}

func TestCompareAndSwapWrongOldValue(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "key", []byte("actual")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.CompareAndSwap(ctx(), "ns", "key", []byte("wrong"), []byte("new")); err != store.ErrPreconditionFailed {
		t.Fatalf("expected ErrPreconditionFailed, got %v", err)
	}

	// Value should be unchanged
	val, _ := s.Get(ctx(), "ns", "key")
	if string(val) != "actual" {
		t.Fatalf("value changed: got %q", val)
	}
}

func TestCompareAndSwapNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.CompareAndSwap(ctx(), "ns", "missing", []byte("old"), []byte("new")); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestIterate(t *testing.T) {
	s := newTestStore(t)

	for _, k := range []string{"a:1", "a:2", "b:1"} {
		if err := s.Set(ctx(), "ns", k, []byte(k)); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}

	var keys []string
	err := s.Iterate(ctx(), "ns", "a:", func(key string, value []byte) (bool, error) {
		keys = append(keys, key)
		return true, nil
	})
	if err != nil {
		t.Fatalf("Iterate: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("Iterate: got %d keys, want 2: %v", len(keys), keys)
	}
}

func TestIterateStopEarly(t *testing.T) {
	s := newTestStore(t)

	for i := 0; i < 5; i++ {
		k := "k:0000%d"
		if err := s.Set(ctx(), "ns", k, []byte("x")); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}

	count := 0
	err := s.Iterate(ctx(), "ns", "k:", func(key string, value []byte) (bool, error) {
		count++
		return false, nil
	})
	if err != nil {
		t.Fatalf("Iterate: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 iteration, got %d", count)
	}
}

func TestIterateCallbackError(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "a", []byte("x")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	err := s.Iterate(ctx(), "ns", "", func(key string, value []byte) (bool, error) {
		return false, store.ErrNotFound
	})
	if err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestIterateEmpty(t *testing.T) {
	s := newTestStore(t)
	count := 0
	err := s.Iterate(ctx(), "ns", "", func(key string, value []byte) (bool, error) {
		count++
		return true, nil
	})
	if err != nil {
		t.Fatalf("Iterate: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 iterations, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Namespace operations
// ---------------------------------------------------------------------------

func TestCreateNamespace(t *testing.T) {
	s := newTestStore(t)

	if err := s.CreateNamespace(ctx(), "test"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}

	// A namespace exists as soon as it is created, even while it is empty.
	exists, err := s.NamespaceExists(ctx(), "test")
	if err != nil || !exists {
		t.Fatalf("NamespaceExists (empty ns): exists=%v err=%v", exists, err)
	}

	// Add a key and check again
	if err := s.Set(ctx(), "test", "a", []byte("x")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	exists, err = s.NamespaceExists(ctx(), "test")
	if err != nil || !exists {
		t.Fatalf("NamespaceExists (with data): exists=%v err=%v", exists, err)
	}
}

func TestCreateNamespaceDuplicate(t *testing.T) {
	s := newTestStore(t)

	if err := s.CreateNamespace(ctx(), "test"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s.CreateNamespace(ctx(), "test"); err != store.ErrExists {
		t.Fatalf("CreateNamespace duplicate: expected ErrExists, got %v", err)
	}
}

func TestNamespaceExistsFalse(t *testing.T) {
	s := newTestStore(t)
	exists, err := s.NamespaceExists(ctx(), "nope")
	if err != nil || exists {
		t.Fatalf("NamespaceExists: exists=%v err=%v", exists, err)
	}
}

func TestDeleteNamespace(t *testing.T) {
	s := newTestStore(t)

	if err := s.CreateNamespace(ctx(), "test"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s.Set(ctx(), "test", "key", []byte("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.DeleteNamespace(ctx(), "test"); err != nil {
		t.Fatalf("DeleteNamespace: %v", err)
	}

	exists, err := s.NamespaceExists(ctx(), "test")
	if err != nil || exists {
		t.Fatalf("NamespaceExists after delete: exists=%v err=%v", exists, err)
	}
}

func TestDeleteNamespaceNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteNamespace(ctx(), "nope"); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListNamespaces(t *testing.T) {
	s := newTestStore(t)

	for _, ns := range []string{"charlie", "alpha", "bravo"} {
		if err := s.CreateNamespace(ctx(), ns); err != nil {
			t.Fatalf("CreateNamespace %s: %v", ns, err)
		}
	}

	namespaces, err := s.ListNamespaces(ctx())
	if err != nil {
		t.Fatalf("ListNamespaces: %v", err)
	}
	if len(namespaces) != 3 {
		t.Fatalf("ListNamespaces: got %d, want 3: %v", len(namespaces), namespaces)
	}
	// Should be sorted
	if namespaces[0] != "alpha" || namespaces[1] != "bravo" || namespaces[2] != "charlie" {
		t.Fatalf("ListNamespaces: expected sorted, got %v", namespaces)
	}
}

func TestListNamespacesEmpty(t *testing.T) {
	s := newTestStore(t)
	namespaces, err := s.ListNamespaces(ctx())
	if err != nil {
		t.Fatalf("ListNamespaces: %v", err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("ListNamespaces: expected empty, got %v", namespaces)
	}
}

func TestDeleteNamespaceRemovesKeys(t *testing.T) {
	s := newTestStore(t)

	if err := s.CreateNamespace(ctx(), "test"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s.Set(ctx(), "test", "a", []byte("x")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set(ctx(), "test", "b", []byte("x")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.DeleteNamespace(ctx(), "test"); err != nil {
		t.Fatalf("DeleteNamespace: %v", err)
	}

	keys, err := s.List(ctx(), "test")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("List after delete namespace: expected empty, got %v", keys)
	}
}

// ---------------------------------------------------------------------------
// Binary values
// ---------------------------------------------------------------------------

func TestBinaryValues(t *testing.T) {
	s := newTestStore(t)

	original := []byte{0x00, 0xff, 0xfe, 0x80, 0x01}
	if err := s.Set(ctx(), "ns", "bin", original); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err := s.Get(ctx(), "ns", "bin")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(val) != len(original) {
		t.Fatalf("length mismatch: got %d want %d", len(val), len(original))
	}
	for i := range original {
		if val[i] != original[i] {
			t.Fatalf("byte mismatch at %d: got 0x%02x want 0x%02x", i, val[i], original[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Persistence (reopen)
// ---------------------------------------------------------------------------

func TestPersistence(t *testing.T) {
	dir := t.TempDir()

	// First instance: write data
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.CreateNamespace(ctx(), "persist"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s1.Set(ctx(), "persist", "key", []byte("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	s1.Close()

	// Second instance: read data back
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	defer s2.Close()

	val, err := s2.Get(ctx(), "persist", "key")
	if err != nil {
		t.Fatalf("Get after reload: %v", err)
	}
	if string(val) != "val" {
		t.Fatalf("Get after reload: got %q", val)
	}

	exists, err := s2.NamespaceExists(ctx(), "persist")
	if err != nil || !exists {
		t.Fatalf("NamespaceExists after reload: exists=%v err=%v", exists, err)
	}
}

func TestEmptyNamespacePersistence(t *testing.T) {
	dir := t.TempDir()

	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.CreateNamespace(ctx(), "empty"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	defer s2.Close()

	exists, err := s2.NamespaceExists(ctx(), "empty")
	if err != nil || !exists {
		t.Fatalf("NamespaceExists after reload: exists=%v err=%v", exists, err)
	}
	if err := s2.CreateNamespace(ctx(), "empty"); err != store.ErrExists {
		t.Fatalf("CreateNamespace duplicate after reload: expected ErrExists, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestConcurrentWriteRead(t *testing.T) {
	s := newTestStore(t)
	const goroutines = 10
	const keysPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gID int) {
			defer wg.Done()
			for i := 0; i < keysPerGoroutine; i++ {
				k := fmt.Sprintf("g%03d:k%04d", gID, i)
				if err := s.Set(ctx(), "ns", k, []byte("val")); err != nil {
					t.Errorf("Set g=%d i=%d: %v", gID, i, err)
					return
				}
			}
		}(g)
	}

	wg.Wait()

	// Verify all keys are readable
	for g := 0; g < goroutines; g++ {
		for i := 0; i < keysPerGoroutine; i++ {
			k := fmt.Sprintf("g%03d:k%04d", g, i)
			val, err := s.Get(ctx(), "ns", k)
			if err != nil {
				t.Errorf("Get g=%d i=%d: %v", g, i, err)
			}
			if string(val) != "val" {
				t.Errorf("Get g=%d i=%d: got %q", g, i, val)
			}
		}
	}
}

func TestConcurrentDifferentNamespaces(t *testing.T) {
	s := newTestStore(t)
	const goroutines = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gID int) {
			defer wg.Done()
			ns := fmt.Sprintf("ns%03d", gID)
			if err := s.Set(ctx(), ns, "key", []byte("v")); err != nil {
				t.Errorf("Set g=%d: %v", gID, err)
				return
			}
			val, err := s.Get(ctx(), ns, "key")
			if err != nil {
				t.Errorf("Get g=%d: %v", gID, err)
			}
			if string(val) != "v" {
				t.Errorf("Get g=%d: got %q", gID, val)
			}
		}(g)
	}

	wg.Wait()
}

func TestConcurrentCompareAndSwap(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "counter", []byte("0")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 50
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			// Each goroutine tries to increment the counter via CAS
			for i := 0; i < 100; i++ {
				current, err := s.Get(ctx(), "ns", "counter")
				if err != nil {
					t.Errorf("Get: %v", err)
					return
				}
				newVal := string(current) + "1"
				if err := s.CompareAndSwap(ctx(), "ns", "counter", current, []byte(newVal)); err != nil {
					// CAS failure is expected under contention, retry
					continue
				}
				return
			}
		}()
	}

	wg.Wait()

	val, err := s.Get(ctx(), "ns", "counter")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// The value should contain exactly 50 "1"s (one per goroutine)
	ones := 0
	for _, b := range val {
		if b == '1' {
			ones++
		}
	}
	if ones != goroutines {
		t.Fatalf("expected %d increments, got %d (value: %s)", goroutines, ones, val)
	}
}

func TestConcurrentList(t *testing.T) {
	s := newTestStore(t)

	// Pre-populate
	for i := 0; i < 100; i++ {
		k := fmt.Sprintf("k%04d", i)
		if err := s.Set(ctx(), "ns", k, []byte("x")); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(10)

	for g := 0; g < 10; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				keys, err := s.List(ctx(), "ns")
				if err != nil {
					t.Errorf("List: %v", err)
					return
				}
				if len(keys) != 100 {
					t.Errorf("List: got %d keys, want 100", len(keys))
				}
			}
		}()
	}

	wg.Wait()
}

func TestConcurrentNamespaceOps(t *testing.T) {
	s := newTestStore(t)

	var wg sync.WaitGroup
	wg.Add(20)

	for g := 0; g < 20; g++ {
		go func(gID int) {
			defer wg.Done()
			ns := "ns"
			if err := s.CreateNamespace(ctx(), ns); err != nil && err != store.ErrExists {
				t.Errorf("CreateNamespace g=%d: %v", gID, err)
				return
			}
			// Only one goroutine will succeed; the rest get ErrExists.
			exists, err := s.NamespaceExists(ctx(), ns)
			if err != nil {
				t.Errorf("NamespaceExists g=%d: %v", gID, err)
				return
			}
			if !exists {
				t.Errorf("NamespaceExists g=%d: expected true", gID)
			}
		}(g)
	}

	wg.Wait()

	// Verify namespace exists
	namespaces, err := s.ListNamespaces(ctx())
	if err != nil {
		t.Fatalf("ListNamespaces: %v", err)
	}
	if len(namespaces) != 1 || namespaces[0] != "ns" {
		t.Fatalf("ListNamespaces: got %v", namespaces)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestEmptyKey(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "", []byte("val")); err != nil {
		t.Fatalf("Set empty key: %v", err)
	}

	val, err := s.Get(ctx(), "ns", "")
	if err != nil {
		t.Fatalf("Get empty key: %v", err)
	}
	if string(val) != "val" {
		t.Fatalf("Get empty key: got %q", val)
	}
}

func TestEmptyValue(t *testing.T) {
	s := newTestStore(t)

	if err := s.Set(ctx(), "ns", "key", []byte("")); err != nil {
		t.Fatalf("Set empty value: %v", err)
	}

	val, err := s.Get(ctx(), "ns", "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(val) != 0 {
		t.Fatalf("Get: expected empty, got %q", val)
	}
}

func TestSpecialCharactersInKey(t *testing.T) {
	s := newTestStore(t)

	keys := []string{"key with spaces", "key:with:colons", "key/with/slashes", "key=with=equals"}
	for _, k := range keys {
		if err := s.Set(ctx(), "ns", k, []byte("x")); err != nil {
			t.Fatalf("Set %q: %v", k, err)
		}
		val, err := s.Get(ctx(), "ns", k)
		if err != nil {
			t.Fatalf("Get %q: %v", k, err)
		}
		if string(val) != "x" {
			t.Fatalf("Get %q: got %q", k, val)
		}
	}
}

func TestLargeValue(t *testing.T) {
	s := newTestStore(t)

	data := make([]byte, 1024*1024) // 1 MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := s.Set(ctx(), "ns", "large", data); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err := s.Get(ctx(), "ns", "large")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(val) != len(data) {
		t.Fatalf("length mismatch: got %d want %d", len(val), len(data))
	}
	for i := range data {
		if val[i] != data[i] {
			t.Fatalf("byte mismatch at %d", i)
		}
	}
}

func TestBatchCommitsAtomicallyAndReadsOwnWrites(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set(ctx(), "ns", "remove", []byte("old")); err != nil {
		t.Fatal(err)
	}

	err := store.Batch(ctx(), s, func(batchCtx context.Context) error {
		if !store.InBatch(batchCtx, s) {
			return errors.New("batch context is not marked active")
		}
		if err := s.CreateNamespace(batchCtx, "temporary"); err != nil {
			return err
		}
		if exists, err := s.NamespaceExists(batchCtx, "temporary"); err != nil || !exists {
			return fmt.Errorf("temporary namespace exists=%t, err=%v", exists, err)
		}
		if err := s.DeleteNamespace(batchCtx, "temporary"); err != nil {
			return err
		}
		if err := s.Set(batchCtx, "ns", "one", []byte("1")); err != nil {
			return err
		}
		if value, err := s.Get(batchCtx, "ns", "one"); err != nil || string(value) != "1" {
			return fmt.Errorf("read own write: value=%q err=%w", value, err)
		}
		if err := s.Put(batchCtx, "ns", "one", []byte("duplicate")); !errors.Is(err, store.ErrExists) {
			return fmt.Errorf("duplicate put error = %v", err)
		}
		if err := s.Delete(batchCtx, "ns", "remove"); err != nil {
			return err
		}
		keys, err := s.List(batchCtx, "ns")
		if err != nil || len(keys) != 1 || keys[0] != "one" {
			return fmt.Errorf("batch keys = %v, err=%w", keys, err)
		}
		return store.Batch(batchCtx, s, func(nestedCtx context.Context) error {
			return s.Set(nestedCtx, "ns", "two", []byte("2"))
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"one": "1", "two": "2"} {
		value, err := s.Get(ctx(), "ns", key)
		if err != nil || string(value) != want {
			t.Fatalf("Get(%q) = %q, %v; want %q", key, value, err, want)
		}
	}
	if _, err := s.Get(ctx(), "ns", "remove"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("removed key error = %v, want not found", err)
	}
}

func TestBatchRollsBackOnError(t *testing.T) {
	s := newTestStore(t)
	wantErr := errors.New("stop")
	err := s.Batch(ctx(), func(batchCtx context.Context) error {
		if err := s.Set(batchCtx, "ns", "one", []byte("1")); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Batch error = %v, want %v", err, wantErr)
	}
	if _, err := s.Get(ctx(), "ns", "one"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back key error = %v, want not found", err)
	}
}

// Reads must not queue behind a writer: a commit can wait milliseconds for a
// WAL fsync, and every authorization check is a handful of reads. Readers
// observe the committed state from before the open batch.
func TestReadsDoNotWaitForOpenBatch(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set(ctx(), "ns", "key", []byte("before")); err != nil {
		t.Fatal(err)
	}
	opened, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseBatch := func() { releaseOnce.Do(func() { close(release) }) }
	// Cleanups run last-in first-out: release the batch before Close waits.
	t.Cleanup(releaseBatch)
	batchDone := make(chan error, 1)
	go func() {
		batchDone <- s.Batch(ctx(), func(batchCtx context.Context) error {
			if err := s.Set(batchCtx, "ns", "key", []byte("after")); err != nil {
				return err
			}
			if err := s.Set(batchCtx, "ns", "added", []byte("new")); err != nil {
				return err
			}
			close(opened)
			<-release
			return nil
		})
	}()
	<-opened

	readsDone := make(chan error, 1)
	go func() {
		readsDone <- func() error {
			if value, err := s.Get(ctx(), "ns", "key"); err != nil || string(value) != "before" {
				return fmt.Errorf("Get = %q, %v; want committed value", value, err)
			}
			if keys, err := s.List(ctx(), "ns"); err != nil || len(keys) != 1 {
				return fmt.Errorf("List = %v, %v; want only the committed key", keys, err)
			}
			if keys, err := s.Scan(ctx(), "ns", "a"); err != nil || len(keys) != 0 {
				return fmt.Errorf("Scan = %v, %v; want no uncommitted keys", keys, err)
			}
			if err := s.Iterate(ctx(), "ns", "", func(string, []byte) (bool, error) { return true, nil }); err != nil {
				return err
			}
			if _, err := s.NamespaceExists(ctx(), "ns"); err != nil {
				return err
			}
			if _, err := s.ListNamespaces(ctx()); err != nil {
				return err
			}
			return s.View(ctx(), func(viewCtx context.Context) error {
				_, err := s.Get(viewCtx, "ns", "key")
				return err
			})
		}()
	}()
	select {
	case err := <-readsDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reads waited for an uncommitted batch")
	}
	releaseBatch()
	if err := <-batchDone; err != nil {
		t.Fatal(err)
	}
	if value, err := s.Get(ctx(), "ns", "key"); err != nil || string(value) != "after" {
		t.Fatalf("Get after commit = %q, %v", value, err)
	}
}

func TestCompactPrefixReclaimsDeletedValues(t *testing.T) {
	// Background compaction could reclaim the value before CompactPrefix runs.
	s, err := open(t.TempDir(), &pebble.Options{DisableAutomaticCompactions: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.CreateNamespace(ctx, "queue"); err != nil {
		t.Fatal(err)
	}
	large := make([]byte, 8<<20)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, "queue", "folder-command/big", large); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, "queue", "other", []byte("kept")); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "queue", "folder-command/big"); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Flush(); err != nil {
		t.Fatal(err)
	}
	tableBytes := func() int64 { total := s.db.Metrics().Total(); return total.Size }
	if before := tableBytes(); before < int64(len(large)) {
		t.Fatalf("setup: tables hold %d bytes, want the deleted value still present", before)
	}
	if err := s.CompactPrefix(ctx, "queue", "folder-command/"); err != nil {
		t.Fatal(err)
	}
	if after := tableBytes(); after >= int64(len(large))/2 {
		t.Fatalf("tables hold %d bytes after compaction; deleted value was not reclaimed", after)
	}
	if value, err := s.Get(ctx, "queue", "other"); err != nil || string(value) != "kept" {
		t.Fatalf("neighbouring key = %q, %v", value, err)
	}
}

func TestUnsyncedWritesPersistAfterClose(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	unsynced := store.WithoutSync(ctx())
	if err := s1.Set(unsynced, "metrics", "single", []byte("one")); err != nil {
		t.Fatalf("unsynced Set: %v", err)
	}
	if err := store.Batch(unsynced, s1, func(batchCtx context.Context) error {
		return s1.Set(batchCtx, "metrics", "batched", []byte("two"))
	}); err != nil {
		t.Fatalf("unsynced Batch: %v", err)
	}
	if val, err := s1.Get(ctx(), "metrics", "single"); err != nil || string(val) != "one" {
		t.Fatalf("unsynced write not visible before close: %q, %v", val, err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	defer s2.Close()
	for key, want := range map[string]string{"single": "one", "batched": "two"} {
		if val, err := s2.Get(ctx(), "metrics", key); err != nil || string(val) != want {
			t.Fatalf("Get %s after reload = %q, %v; want %q", key, val, err, want)
		}
	}
}

// BenchmarkSet compares synced and unsynced single writes; the difference is
// one WAL fsync per write.
func BenchmarkSet(b *testing.B) {
	for _, mode := range []struct {
		name string
		ctx  context.Context
	}{
		{"synced", ctx()},
		{"unsynced", store.WithoutSync(ctx())},
	} {
		b.Run(mode.name, func(b *testing.B) {
			s, err := New(b.TempDir())
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			defer s.Close()
			value := []byte("sample")
			b.ResetTimer()
			for i := range b.N {
				if err := s.Set(mode.ctx, "metrics", fmt.Sprintf("key-%d", i%64), value); err != nil {
					b.Fatalf("Set: %v", err)
				}
			}
		})
	}
}
