package model

import (
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func TestRecipientAliasStoreLifecycleAndIdentityInvariants(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()
	if err := ts.DomainStore().Create(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alice", "bob"} {
		if err := ts.UserStore().Create(ctx, id, id, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := ts.UserStore().AddEmailAddress(ctx, id+"@example.test", id, "example.test", true); err != nil {
			t.Fatal(err)
		}
	}
	aliases := ts.RecipientAliasStore()
	alias, err := aliases.Create(ctx, " TEAM@EXAMPLE.TEST ", []string{"bob@example.test", "alice@example.test"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if alias.Address != "team@example.test" || alias.DomainID != "example.test" || len(alias.Targets) != 2 || alias.Targets[0] != "alice@example.test" {
		t.Fatalf("normalized alias = %+v", alias)
	}
	targets, err := aliases.Expand(ctx, alias.Address)
	if err != nil || len(targets) != 2 {
		t.Fatalf("expand = %v, %v", targets, err)
	}
	targets[0] = "mutated"
	again, _ := aliases.Expand(ctx, alias.Address)
	if again[0] != "alice@example.test" {
		t.Fatalf("Expand exposed stored slice: %v", again)
	}

	if err := ts.UserStore().AddEmailAddress(ctx, alias.Address, "alice", "example.test", false); err == nil {
		t.Fatal("identity was allowed to collide with alias")
	}
	if err := ts.UserStore().UpdateEmailAddress(ctx, "alice@example.test", false, false); !errors.Is(err, ErrRecipientAliasReferenced) {
		t.Fatalf("disable referenced identity error = %v", err)
	}
	if err := ts.UserStore().DeleteEmailAddress(ctx, "alice@example.test"); !errors.Is(err, ErrRecipientAliasReferenced) {
		t.Fatalf("delete referenced identity error = %v", err)
	}
	if err := ts.DomainStore().Delete(ctx, "example.test"); err == nil {
		t.Fatal("domain was deleted while it still owned a recipient alias")
	}

	alias, err = aliases.Update(ctx, alias.Address, []string{"bob@example.test"}, false)
	if err != nil || alias.Enabled {
		t.Fatalf("disable alias = %+v, %v", alias, err)
	}
	if _, err := aliases.Expand(ctx, alias.Address); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disabled expansion error = %v", err)
	}
	if err := aliases.Delete(ctx, alias.Address); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().DeleteEmailAddress(ctx, "alice@example.test"); err != nil {
		t.Fatalf("identity remained referenced after alias delete: %v", err)
	}
}

func TestRecipientAliasStoreUsesGenericBackends(t *testing.T) {
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
			for _, namespace := range []string{NSDomains, NSUsers, NSEmails, NSRecipientAliases} {
				if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
					t.Fatal(err)
				}
			}
			if err := typed.DomainStore().Create(t.Context(), "example.test"); err != nil {
				t.Fatal(err)
			}
			if err := typed.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
				t.Fatal(err)
			}
			if err := typed.UserStore().AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
				t.Fatal(err)
			}
			if _, err := typed.RecipientAliasStore().Create(t.Context(), "team@example.test", []string{"alice@example.test"}, true); err != nil {
				t.Fatal(err)
			}
			targets, err := typed.RecipientAliasStore().Expand(t.Context(), "TEAM@example.test")
			if err != nil || len(targets) != 1 || targets[0] != "alice@example.test" {
				t.Fatalf("targets=%v err=%v", targets, err)
			}
		})
	}
}

func TestRecipientAliasStoreRejectsUnsafeTargets(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()
	if err := ts.DomainStore().Create(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().AddEmailAddress(ctx, "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		address string
		targets []string
	}{
		{"external target", "external@example.test", []string{"person@remote.test"}},
		{"missing domain", "team@missing.test", []string{"alice@example.test"}},
		{"empty", "empty@example.test", nil},
		{"duplicate", "dupe@example.test", []string{"alice@example.test", "ALICE@example.test"}},
		{"self", "alice-alias@example.test", []string{"alice-alias@example.test"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ts.RecipientAliasStore().Create(ctx, test.address, test.targets, true); !errors.Is(err, ErrRecipientAliasInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
