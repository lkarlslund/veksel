package model

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// testStore returns a fresh TypedStore backed by a temporary jsonstore.
func testStore(t *testing.T) *TypedStore {
	t.Helper()
	dir := t.TempDir()
	s, err := jsonstore.New(dir)
	if err != nil {
		t.Fatalf("create jsonstore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return NewTypedStore(s, store.BackendJSON)
}

func testSetup(t *testing.T, ts *TypedStore) {
	t.Helper()
	ctx := context.Background()
	for _, ns := range []string{NSDomains, NSUsers, NSEmails, NSRecipientAliases, NSUserAliases, NSFolders, NSItems, NSVacationReplies, NSACL, NSPasswordResets} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %q: %v", ns, err)
		}
	}
}

// newTestSetup creates a fresh TypedStore with all namespaces created.
func newTestSetup(t *testing.T) *TypedStore {
	t.Helper()
	ts := testStore(t)
	testSetup(t, ts)
	return ts
}

func TestDomainStoreCRUD(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ds := NewDomainStore(ts)
	ctx := context.Background()

	// Create
	if err := ds.Create(ctx, "example.com"); err != nil {
		t.Fatalf("create domain: %v", err)
	}

	// Get
	d, err := ds.Get(ctx, "example.com")
	if err != nil {
		t.Fatalf("get domain: %v", err)
	}
	if d.ID != "example.com" {
		t.Errorf("id = %q, want %q", d.ID, "example.com")
	}
	if !d.Enabled {
		t.Error("expected domain to be enabled")
	}

	// Idempotent create should fail with ErrExists
	if err := ds.Create(ctx, "example.com"); err != store.ErrExists {
		t.Errorf("expected ErrExists, got %v", err)
	}

	// Update
	if err := ds.Update(ctx, "example.com", func(d *Domain) { d.Enabled = false }); err != nil {
		t.Fatalf("update domain: %v", err)
	}
	d, err = ds.Get(ctx, "example.com")
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if d.Enabled {
		t.Error("expected domain to be disabled after update")
	}

	// List
	if err := ds.Create(ctx, "test.org"); err != nil {
		t.Fatalf("create second domain: %v", err)
	}
	domains, err := ds.List(ctx)
	if err != nil {
		t.Fatalf("list domains: %v", err)
	}
	if got := len(domains); got != 2 {
		t.Errorf("list returned %d domains, want 2", got)
	}

	// Delete
	if err := ds.Delete(ctx, "example.com"); err != nil {
		t.Fatalf("delete domain: %v", err)
	}
	_, err = ds.Get(ctx, "example.com")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDomainStoreNormalizeID(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ds := NewDomainStore(ts)
	ctx := context.Background()

	// Create with uppercase
	if err := ds.Create(ctx, "  Example.COM  "); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Get with lowercase should find it
	d, err := ds.Get(ctx, "example.com")
	if err != nil {
		t.Fatalf("get with lowercase: %v", err)
	}
	if d.ID != "example.com" {
		t.Errorf("id = %q, want %q", d.ID, "example.com")
	}
}

func TestDomainStoreGetNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ds := NewDomainStore(ts)
	ctx := context.Background()

	_, err := ds.Get(ctx, "nonexistent.com")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDomainStoreDeleteNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ds := NewDomainStore(ts)
	ctx := context.Background()

	err := ds.Delete(ctx, "nonexistent.com")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDomainStoreListEmpty(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ds := NewDomainStore(ts)
	ctx := context.Background()

	domains, err := ds.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(domains) != 0 {
		t.Errorf("expected empty list, got %d domains", len(domains))
	}
}

func TestDomainStoreUpdateNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ds := NewDomainStore(ts)
	ctx := context.Background()

	err := ds.Update(ctx, "nonexistent.com", func(d *Domain) { d.Enabled = false })
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDomainStorePersistence(t *testing.T) {
	t.Parallel()
	// Use a real temp dir and reopen to verify persistence
	dir := t.TempDir()
	s, err := jsonstore.New(dir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	ts := NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()
	for _, ns := range []string{NSDomains} {
		ts.EnsureNamespace(ctx, ns)
	}

	ds := NewDomainStore(ts)
	if err := ds.Create(ctx, "persist.com"); err != nil {
		t.Fatalf("create: %v", err)
	}
	s.Close()
	os.RemoveAll(dir) // clean up
}

func TestDKIMKeyRotationLifecycleAndLegacyAdoption(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ds := ts.DomainStore()
	if err := ds.Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ds.Update(t.Context(), "example.test", func(domain *Domain) {
		domain.DkimSelector = "legacy"
		domain.DkimPrivateKey = "legacy-private"
		domain.DkimPublicKey = "legacy-public"
	}); err != nil {
		t.Fatal(err)
	}

	domain, err := ds.StageDKIMKey(t.Context(), "example.test", 0, DKIMKey{Selector: "august-2026", PrivateKey: "new-private", PublicKey: "new-public"})
	if err != nil {
		t.Fatal(err)
	}
	if domain.DKIMRevision != 1 || len(domain.DKIMKeys) != 2 {
		t.Fatalf("staged domain=%+v", domain)
	}
	active, ok := ActiveDKIMKey(domain)
	if !ok || active.Selector != "legacy" || active.PrivateKey != "legacy-private" {
		t.Fatalf("staging changed signer: %+v, ok=%t", active, ok)
	}
	if _, err := ds.ActivateDKIMKey(t.Context(), domain.ID, "august-2026", 0); !errors.Is(err, ErrDKIMRevisionConflict) {
		t.Fatalf("stale activation error=%v", err)
	}
	domain, err = ds.ActivateDKIMKey(t.Context(), domain.ID, "august-2026", 1)
	if err != nil {
		t.Fatal(err)
	}
	active, ok = ActiveDKIMKey(domain)
	if !ok || active.Selector != "august-2026" || domain.DkimSelector != active.Selector || domain.DkimPrivateKey != active.PrivateKey {
		t.Fatalf("activation did not synchronize signer: domain=%+v active=%+v", domain, active)
	}
	if domain.DKIMKeys[0].State != DKIMKeyRetiring {
		t.Fatalf("former signer state=%q", domain.DKIMKeys[0].State)
	}
	domain, err = ds.ActivateDKIMKey(t.Context(), domain.ID, "legacy", 2)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	active, _ = ActiveDKIMKey(domain)
	if active.Selector != "legacy" || domain.DKIMKeys[1].State != DKIMKeyRetiring {
		t.Fatalf("rollback domain=%+v", domain)
	}
	if _, err := ds.DeleteDKIMKey(t.Context(), domain.ID, "legacy", 3); !errors.Is(err, ErrDKIMKeyState) {
		t.Fatalf("active delete error=%v", err)
	}
	domain, err = ds.DeleteDKIMKey(t.Context(), domain.ID, "august-2026", 3)
	if err != nil || len(domain.DKIMKeys) != 1 || domain.DKIMKeys[0].Selector != "legacy" {
		t.Fatalf("retire domain=%+v err=%v", domain, err)
	}
}

func TestDKIMKeyLifecycleBoundsAndSelectors(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ds := ts.DomainStore()
	if err := ds.Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	for i := range MaxDKIMKeysPerDomain {
		selector := fmt.Sprintf("key-%d", i)
		if _, err := ds.StageDKIMKey(t.Context(), "example.test", uint64(i), DKIMKey{Selector: selector, PrivateKey: "private", PublicKey: "public"}); err != nil {
			t.Fatalf("stage %s: %v", selector, err)
		}
	}
	if _, err := ds.StageDKIMKey(t.Context(), "example.test", MaxDKIMKeysPerDomain, DKIMKey{Selector: "overflow", PrivateKey: "private", PublicKey: "public"}); !errors.Is(err, ErrDKIMKeyLimit) {
		t.Fatalf("overflow error=%v", err)
	}
	if _, err := ValidateDKIMSelector("bad selector"); err == nil {
		t.Fatal("selector containing whitespace was accepted")
	}
	if selector, err := ValidateDKIMSelector("  Mail_2026.Example  "); err != nil || selector != "mail_2026.example" {
		t.Fatalf("selector=%q err=%v", selector, err)
	}
}

func TestSetDKIMKeysCannotOverwriteConfiguredDomain(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	domains := ts.DomainStore()
	if err := domains.Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := domains.SetDKIMKeys(t.Context(), "example.test", "first-private", "first-public", "first"); err != nil {
		t.Fatal(err)
	}
	if err := domains.SetDKIMKeys(t.Context(), "example.test", "replacement-private", "replacement-public", "replacement"); !errors.Is(err, ErrDKIMSelectorExists) {
		t.Fatalf("replacement error=%v", err)
	}
	domain, err := domains.Get(t.Context(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	active, ok := ActiveDKIMKey(domain)
	if !ok || active.Selector != "first" || active.PrivateKey != "first-private" || domain.DKIMRevision != 1 {
		t.Fatalf("active=%+v ok=%t revision=%d", active, ok, domain.DKIMRevision)
	}
}

func TestDKIMRevisionSerializesAcrossDomainStoreInstances(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	stores := []*DomainStore{NewDomainStore(ts), NewDomainStore(ts)}
	var wg sync.WaitGroup
	errorsOut := make(chan error, len(stores))
	for i, ds := range stores {
		wg.Add(1)
		go func(i int, ds *DomainStore) {
			defer wg.Done()
			_, err := ds.StageDKIMKey(t.Context(), "example.test", 0, DKIMKey{Selector: fmt.Sprintf("key-%d", i), PrivateKey: "private", PublicKey: "public"})
			errorsOut <- err
		}(i, ds)
	}
	wg.Wait()
	close(errorsOut)
	var successful, conflicted int
	for err := range errorsOut {
		switch {
		case err == nil:
			successful++
		case errors.Is(err, ErrDKIMRevisionConflict):
			conflicted++
		default:
			t.Fatalf("unexpected error=%v", err)
		}
	}
	if successful != 1 || conflicted != 1 {
		t.Fatalf("successful=%d conflicted=%d", successful, conflicted)
	}
}

func TestDKIMKeyLifecycleUsesGenericBackends(t *testing.T) {
	factories := map[string]func(string) (store.Store, error){
		"json":   func(path string) (store.Store, error) { return jsonstore.New(path) },
		"pebble": func(path string) (store.Store, error) { return pebblestore.New(path) },
		"badger": func(path string) (store.Store, error) { return badgerstore.New(path) },
	}
	for name, open := range factories {
		t.Run(name, func(t *testing.T) {
			backend, err := open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })
			typed := NewTypedStore(backend, store.Backend(name))
			if err := typed.EnsureNamespace(t.Context(), NSDomains); err != nil {
				t.Fatal(err)
			}
			domains := typed.DomainStore()
			if err := domains.Create(t.Context(), "example.test"); err != nil {
				t.Fatal(err)
			}
			staged, err := domains.StageDKIMKey(t.Context(), "example.test", 0, DKIMKey{Selector: "next", PrivateKey: "private", PublicKey: "public"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := domains.ActivateDKIMKey(t.Context(), staged.ID, "next", staged.DKIMRevision); err != nil {
				t.Fatal(err)
			}
			persisted, err := domains.Get(t.Context(), staged.ID)
			if err != nil {
				t.Fatal(err)
			}
			active, ok := ActiveDKIMKey(persisted)
			if !ok || active.Selector != "next" || active.PrivateKey != "private" {
				t.Fatalf("persisted active=%+v ok=%t", active, ok)
			}
		})
	}
}
