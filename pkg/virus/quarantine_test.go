package virus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func newQuarantineTestStore(t *testing.T, policy QuarantinePolicy) (*QuarantineStore, *model.TypedStore) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err := backend.CreateNamespace(t.Context(), model.NSMetadata); err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStore(backend, store.BackendJSON)
	return NewQuarantineStore(typed, policy), typed
}

func TestQuarantineAccountingTracksAddReplaceDelete(t *testing.T) {
	quarantine, _ := newQuarantineTestStore(t, QuarantinePolicy{Retention: 24 * time.Hour, MaxEntries: 10, MaxBytes: 100})
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	quarantine.now = func() time.Time { return now }

	entry := &QuarantineEntry{ID: "one", MessageData: []byte("first")}
	if _, err := quarantine.Add(t.Context(), entry); err != nil {
		t.Fatal(err)
	}
	if entry.CreatedAt != now || entry.ExpiresAt != now.Add(24*time.Hour) || entry.MessageSize != 5 {
		t.Fatalf("normalized entry = %+v", entry)
	}
	status, err := quarantine.Status(t.Context())
	if err != nil || status.Entries != 1 || status.LogicalBytes != 5 || status.AccountingVersion != 2 {
		t.Fatalf("status after add = %+v, %v", status, err)
	}

	replacement := &QuarantineEntry{ID: "one", MessageData: []byte("replacement")}
	if _, err := quarantine.Add(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	status, _ = quarantine.Status(t.Context())
	if status.Entries != 1 || status.LogicalBytes != 11 || replacement.CreatedAt != now {
		t.Fatalf("status after replacement = %+v, entry = %+v", status, replacement)
	}
	if err := quarantine.Delete(t.Context(), "one"); err != nil {
		t.Fatal(err)
	}
	status, _ = quarantine.Status(t.Context())
	if status.Entries != 0 || status.LogicalBytes != 0 {
		t.Fatalf("status after delete = %+v", status)
	}
}

func TestQuarantineCapacityPrunesExpiredBeforeDeferring(t *testing.T) {
	quarantine, _ := newQuarantineTestStore(t, QuarantinePolicy{Retention: time.Hour, MaxEntries: 1, MaxBytes: 10})
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	quarantine.now = func() time.Time { return now }
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "one", MessageData: []byte("12345")}); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "two", MessageData: []byte("12")}); !errors.Is(err, ErrQuarantineCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if _, err := quarantine.Get(t.Context(), "two"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rejected entry persisted: %v", err)
	}
	stored, err := quarantine.Get(t.Context(), "one")
	if err != nil || string(stored.MessageData) != "12345" {
		t.Fatalf("capacity rollback changed existing entry: %+v, %v", stored, err)
	}

	now = now.Add(time.Hour)
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "two", MessageData: []byte("12")}); err != nil {
		t.Fatalf("add after expiry: %v", err)
	}
	if _, err := quarantine.Get(t.Context(), "one"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired entry remains: %v", err)
	}
	status, _ := quarantine.Status(t.Context())
	if status.Entries != 1 || status.LogicalBytes != 2 {
		t.Fatalf("status after prune = %+v", status)
	}
}

func TestQuarantineCleanupIsBounded(t *testing.T) {
	quarantine, _ := newQuarantineTestStore(t, QuarantinePolicy{Retention: time.Hour})
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	quarantine.now = func() time.Time { return now }
	for _, id := range []string{"one", "two", "three"} {
		if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: id, MessageData: []byte(id)}); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Hour)
	cleanup, err := quarantine.CleanupExpired(t.Context(), now, 2)
	if err != nil || cleanup.Removed != 2 {
		t.Fatalf("cleanup = %+v, %v", cleanup, err)
	}
	status, _ := quarantine.Status(t.Context())
	if status.Entries != 1 {
		t.Fatalf("status after bounded cleanup = %+v", status)
	}
}

func TestQuarantineRebuildsLegacyAccounting(t *testing.T) {
	quarantine, typed := newQuarantineTestStore(t, QuarantinePolicy{Retention: 24 * time.Hour})
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	quarantine.now = func() time.Time { return now }
	legacy := QuarantineEntry{ID: "legacy", Date: "2026-08-17T10:00:00Z", MessageSize: 7, MessageData: []byte("payload")}
	if err := typed.Set(context.Background(), model.NSMetadata, quarantineKey(legacy.ID), legacy); err != nil {
		t.Fatal(err)
	}
	status, err := quarantine.Status(t.Context())
	if err != nil || status.Entries != 1 || status.LogicalBytes != 7 {
		t.Fatalf("rebuilt status = %+v, %v", status, err)
	}
	stored, err := quarantine.Get(t.Context(), legacy.ID)
	if err != nil || stored.CreatedAt.IsZero() || stored.ExpiresAt.IsZero() {
		t.Fatalf("normalized legacy entry = %+v, %v", stored, err)
	}
}

func TestQuarantinePolicyValidation(t *testing.T) {
	for _, policy := range []QuarantinePolicy{{Retention: -time.Second}, {MaxEntries: -1}, {MaxBytes: -1}} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("policy %+v accepted", policy)
		}
	}
}

func TestQuarantineOwnerIndexIsIsolatedAndRebuilt(t *testing.T) {
	quarantine, typed := newQuarantineTestStore(t, QuarantinePolicy{Retention: 24 * time.Hour})
	quarantine.SetOwnerResolver(func(_ context.Context, recipient string) (string, error) {
		if recipient == "alice@example.test" {
			return "alice", nil
		}
		return "", store.ErrNotFound
	})
	quarantine.now = func() time.Time { return time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC) }
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "alice-one", Recipient: "alice@example.test", MessageData: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "bob-one", OwnerID: "bob", Recipient: "bob@example.test", MessageData: []byte("two")}); err != nil {
		t.Fatal(err)
	}
	alice, err := quarantine.ListForOwner(t.Context(), "ALICE")
	if err != nil || len(alice) != 1 || alice[0].ID != "alice-one" {
		t.Fatalf("Alice entries = %+v, %v", alice, err)
	}
	if err := typed.Delete(t.Context(), model.NSMetadata, quarantineAccountingKey()); err != nil {
		t.Fatal(err)
	}
	keys, err := typed.Scan(t.Context(), model.NSMetadata, quarantineOwnerPrefix("alice"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if err := typed.Delete(t.Context(), model.NSMetadata, key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := quarantine.Status(t.Context()); err != nil {
		t.Fatal(err)
	}
	alice, err = quarantine.ListForOwner(t.Context(), "alice")
	if err != nil || len(alice) != 1 {
		t.Fatalf("rebuilt Alice entries = %+v, %v", alice, err)
	}
}
