package model

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

func userAliasFixture(t *testing.T) *TypedStore {
	t.Helper()
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
	return ts
}

func TestUserAliasCreateRandomUniqueAndPrefixed(t *testing.T) {
	ts := userAliasFixture(t)
	ctx := t.Context()
	seen := map[string]bool{}
	for range 30 {
		alias, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test"})
		if err != nil {
			t.Fatal(err)
		}
		if seen[alias.Address] {
			t.Fatalf("address %s issued twice", alias.Address)
		}
		seen[alias.Address] = true
		local := strings.TrimSuffix(alias.Address, "@example.test")
		if len(local) != userAliasSuffixLength || alias.OnInactive != UserAliasRejectInactive || !alias.Enabled {
			t.Fatalf("alias = %+v", alias)
		}
	}
	alias, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", Prefix: "Shop", Label: "webshop"})
	if err != nil || !strings.HasPrefix(alias.Address, "shop-") || alias.Label != "webshop" {
		t.Fatalf("prefixed alias = %+v, %v", alias, err)
	}
	for _, prefix := range []string{"a b", "x@y", "a+b", ".dot", "dot.", strings.Repeat("a", 25)} {
		if _, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", Prefix: prefix}); !errors.Is(err, ErrUserAliasInvalid) {
			t.Errorf("prefix %q error = %v", prefix, err)
		}
	}
}

func TestUserAliasAddressCollisions(t *testing.T) {
	ts := userAliasFixture(t)
	ctx := t.Context()
	if _, err := ts.RecipientAliasStore().Create(ctx, "team@example.test", []string{"alice@example.test"}, true); err != nil {
		t.Fatal(err)
	}
	alias, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"alice@example.test", "team@example.test", alias.Address} {
		taken, err := ts.UserAliasStore().AddressTaken(ctx, address)
		if err != nil || !taken {
			t.Fatalf("AddressTaken(%s) = %v, %v", address, taken, err)
		}
	}
	if taken, _ := ts.UserAliasStore().AddressTaken(ctx, "free@example.test"); taken {
		t.Fatal("unused address reported taken")
	}
	// A deleted alias leaves a tombstone, so the address stays reserved.
	if err := ts.UserAliasStore().Delete(ctx, alias.Address, "alice"); err != nil {
		t.Fatal(err)
	}
	if taken, _ := ts.UserAliasStore().AddressTaken(ctx, alias.Address); !taken {
		t.Fatal("tombstoned address was released")
	}
}

func TestUserAliasResolvesToOwnerAndFolder(t *testing.T) {
	ts := userAliasFixture(t)
	ctx := t.Context()
	if err := ts.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	alias, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", Prefix: "shop", FolderPath: "Archive"})
	if err != nil {
		t.Fatal(err)
	}
	route, err := ts.ResolveRecipient(ctx, alias.Address, "+")
	if err != nil || !route.UserAlias || route.Identity.UserID != "alice" || route.FolderPath != "Archive" || route.Disabled {
		t.Fatalf("route = %+v, %v", route, err)
	}
	mailbox, err := route.Mailbox()
	if err != nil || !mailbox.Enabled || mailbox.UserID != "alice" {
		t.Fatalf("mailbox = %+v, %v", mailbox, err)
	}
	// Subaddressing works on top of an alias.
	local, domain, _ := strings.Cut(alias.Address, "@")
	route, err = ts.ResolveRecipient(ctx, local+"+tag@"+domain, "+")
	if err != nil || route.Identity.UserID != "alice" || route.Detail != "tag" {
		t.Fatalf("subaddressed route = %+v, %v", route, err)
	}
	if _, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", FolderPath: "NoSuchFolder"}); !errors.Is(err, ErrUserAliasInvalid) {
		t.Fatalf("missing folder error = %v", err)
	}
}

func TestUserAliasExpiryRejectsOrDiscardsWithoutCatchAll(t *testing.T) {
	ts := userAliasFixture(t)
	ctx := t.Context()
	if err := ts.DomainStore().SetCatchAll(ctx, "example.test", "bob@example.test"); err != nil {
		t.Fatal(err)
	}
	reject, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", Expiry: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	discard, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", Expiry: time.Hour, OnInactive: UserAliasDiscardInactive})
	if err != nil {
		t.Fatal(err)
	}
	expire := func(address string) {
		t.Helper()
		past := -time.Minute
		if _, err := ts.UserAliasStore().Update(ctx, address, "alice", UserAliasUpdate{Expiry: &past}); err == nil {
			t.Fatal("negative expiry accepted")
		}
		stored, err := ts.UserAliasStore().Get(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		stored.ExpiresAt = time.Now().Add(-time.Minute)
		if err := ts.Set(ctx, NSUserAliases, address, stored); err != nil {
			t.Fatal(err)
		}
	}
	expire(reject.Address)
	expire(discard.Address)

	route, err := ts.ResolveRecipient(ctx, reject.Address, "+")
	if err != nil || !route.Disabled || route.CatchAll || route.Discard {
		t.Fatalf("expired reject route = %+v, %v", route, err)
	}
	if mailbox, _ := route.Mailbox(); mailbox.Enabled {
		t.Fatal("expired alias mailbox is enabled")
	}
	route, err = ts.ResolveRecipient(ctx, discard.Address, "+")
	if err != nil || !route.Discard || route.Disabled || route.CatchAll {
		t.Fatalf("expired discard route = %+v, %v", route, err)
	}
	if _, err := route.Mailbox(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("discard mailbox error = %v", err)
	}
	// Disabling an unexpired alias follows the same policy.
	active, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := ts.UserAliasStore().Update(ctx, active.Address, "alice", UserAliasUpdate{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if route, err := ts.ResolveRecipient(ctx, active.Address, "+"); err != nil || !route.Disabled || route.CatchAll {
		t.Fatalf("disabled route = %+v, %v", route, err)
	}
}

func TestUserAliasSendingIdentityOnlyForActiveOwner(t *testing.T) {
	ts := userAliasFixture(t)
	ctx := t.Context()
	alias, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ts.UserAliasStore().SendingIdentity(ctx, alias.Address, time.Now())
	if err != nil || identity.UserID != "alice" || !identity.Enabled || identity.ID != alias.Address {
		t.Fatalf("identity = %+v, %v", identity, err)
	}
	if _, err := ts.UserAliasStore().SendingIdentity(ctx, alias.Address, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("never-expiring alias unusable later: %v", err)
	}
	disabled := false
	if _, err := ts.UserAliasStore().Update(ctx, alias.Address, "bob", UserAliasUpdate{Enabled: &disabled}); !errors.Is(err, ErrUserAliasNotOwner) {
		t.Fatalf("other owner update = %v", err)
	}
	if err := ts.UserAliasStore().Delete(ctx, alias.Address, "bob"); !errors.Is(err, ErrUserAliasNotOwner) {
		t.Fatalf("other owner delete = %v", err)
	}
	if _, err := ts.UserAliasStore().Update(ctx, alias.Address, "alice", UserAliasUpdate{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.UserAliasStore().SendingIdentity(ctx, alias.Address, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disabled alias identity error = %v", err)
	}
}

func TestUserAliasLimitsAndAdminLock(t *testing.T) {
	ts := userAliasFixture(t)
	ctx := t.Context()
	var first UserAlias
	for i := range 2 {
		alias, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", MaxPerUser: 2})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = alias
		}
	}
	if _, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", MaxPerUser: 2}); !errors.Is(err, ErrUserAliasLimit) {
		t.Fatalf("per-user limit error = %v", err)
	}
	if _, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "bob", DomainID: "example.test", MaxPerUser: 2}); err != nil {
		t.Fatalf("other account hit the limit: %v", err)
	}
	usage, err := ts.DomainStore().Usage(ctx, "example.test")
	if err != nil || usage.Aliases != 3 {
		t.Fatalf("usage = %+v, %v", usage, err)
	}
	// Deleting frees quota; the tombstone does not count.
	if err := ts.UserAliasStore().Delete(ctx, first.Address, "alice"); err != nil {
		t.Fatal(err)
	}
	if usage, _ = ts.DomainStore().Usage(ctx, "example.test"); usage.Aliases != 2 {
		t.Fatalf("usage after delete = %+v", usage)
	}

	// Create/delete churn is bounded: tombstones count toward a retained
	// budget of userAliasRetainedFactor times the live limit.
	churn := 0
	for ; churn < 100; churn++ {
		alias, err := ts.UserAliasStore().Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", MaxPerUser: 2})
		if errors.Is(err, ErrUserAliasLimit) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := ts.UserAliasStore().Delete(ctx, alias.Address, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if churn != 2*userAliasRetainedFactor-2 {
		t.Fatalf("create/delete cycles before the retained limit = %d", churn)
	}

	locked, err := ts.UserAliasStore().SetAdminDisabled(ctx, usageAddress(t, ts, "bob"), true)
	if err != nil || locked.Enabled || !locked.AdminDisabled {
		t.Fatalf("locked = %+v, %v", locked, err)
	}
	on := true
	if _, err := ts.UserAliasStore().Update(ctx, locked.Address, "bob", UserAliasUpdate{Enabled: &on}); !errors.Is(err, ErrUserAliasLocked) {
		t.Fatalf("owner re-enable error = %v", err)
	}
	if _, err := ts.UserAliasStore().SetAdminDisabled(ctx, locked.Address, false); err != nil {
		t.Fatal(err)
	}
	if updated, err := ts.UserAliasStore().Update(ctx, locked.Address, "bob", UserAliasUpdate{Enabled: &on}); err != nil || !updated.Enabled {
		t.Fatalf("owner enable after unlock = %+v, %v", updated, err)
	}
}

func usageAddress(t *testing.T, ts *TypedStore, userID string) string {
	t.Helper()
	aliases, err := ts.UserAliasStore().ListForUser(t.Context(), userID)
	if err != nil || len(aliases) == 0 {
		t.Fatalf("aliases of %s = %v, %v", userID, aliases, err)
	}
	return aliases[0].Address
}

func TestUserAliasCleanupKeepsTombstones(t *testing.T) {
	ts := userAliasFixture(t)
	ctx := t.Context()
	aliases := ts.UserAliasStore()
	fresh, _ := aliases.Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", Expiry: time.Hour})
	stale, _ := aliases.Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test", Expiry: time.Hour, Label: "old"})
	permanent, _ := aliases.Create(ctx, UserAliasRequest{UserID: "alice", DomainID: "example.test"})

	now := time.Now()
	// Expired but inside the grace period: untouched.
	if tombstoned, purged, err := aliases.Cleanup(ctx, now.Add(2*time.Hour)); err != nil || tombstoned+purged != 0 {
		t.Fatalf("early cleanup = %d, %d, %v", tombstoned, purged, err)
	}
	later := now.Add(time.Hour + UserAliasPurgeAfter + time.Minute)
	tombstoned, purged, err := aliases.Cleanup(ctx, later)
	if err != nil || tombstoned != 2 || purged != 0 {
		t.Fatalf("cleanup = %d, %d, %v", tombstoned, purged, err)
	}
	record, err := aliases.Get(ctx, stale.Address)
	if err != nil || !record.Tombstone() || record.Label != "" {
		t.Fatalf("tombstone = %+v, %v", record, err)
	}
	if _, err := aliases.Get(ctx, permanent.Address); err != nil {
		t.Fatal(err)
	}
	if taken, _ := aliases.AddressTaken(ctx, fresh.Address); !taken {
		t.Fatal("tombstone did not reserve the address")
	}
	route, err := ts.ResolveRecipient(ctx, fresh.Address, "+")
	if err != nil || !route.Disabled || route.CatchAll {
		t.Fatalf("tombstone route = %+v, %v", route, err)
	}
	// Once the reservation lapses the record is released.
	tombstoned, purged, err = aliases.Cleanup(ctx, later.Add(UserAliasTombstoneFor+time.Hour))
	if err != nil || tombstoned != 0 || purged != 2 {
		t.Fatalf("release = %d, %d, %v", tombstoned, purged, err)
	}
	if taken, _ := aliases.AddressTaken(ctx, fresh.Address); taken {
		t.Fatal("released address still reserved")
	}
}
