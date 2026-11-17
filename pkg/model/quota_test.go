package model

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
)

// --- QuotaInfo helper tests ---

func TestQuotaInfoCheckStorageUnlimited(t *testing.T) {
	t.Parallel()
	q := QuotaInfo{MaxStorageBytes: 0, CurrentStorageBytes: 999999}
	if !q.CheckStorage(1000) {
		t.Error("should allow when unlimited")
	}
}

func TestQuotaInfoCheckStorageWithinLimit(t *testing.T) {
	t.Parallel()
	q := QuotaInfo{MaxStorageBytes: 1000, CurrentStorageBytes: 500}
	if !q.CheckStorage(500) {
		t.Error("should allow when within limit")
	}
}

func TestQuotaInfoCheckStorageExceedsLimit(t *testing.T) {
	t.Parallel()
	q := QuotaInfo{MaxStorageBytes: 1000, CurrentStorageBytes: 900}
	if q.CheckStorage(200) {
		t.Error("should reject when exceeds limit")
	}
}

func TestQuotaInfoCheckItemsUnlimited(t *testing.T) {
	t.Parallel()
	q := QuotaInfo{MaxItems: 0, CurrentItems: 999999}
	if !q.CheckItems(1000) {
		t.Error("should allow when unlimited")
	}
}

func TestQuotaInfoCheckItemsWithinLimit(t *testing.T) {
	t.Parallel()
	q := QuotaInfo{MaxItems: 100, CurrentItems: 50}
	if !q.CheckItems(50) {
		t.Error("should allow when within limit")
	}
}

func TestQuotaInfoCheckItemsExceedsLimit(t *testing.T) {
	t.Parallel()
	q := QuotaInfo{MaxItems: 100, CurrentItems: 99}
	if q.CheckItems(2) {
		t.Error("should reject when exceeds limit")
	}
}

func TestQuotaInfoUsagePercent(t *testing.T) {
	t.Parallel()
	q := QuotaInfo{MaxStorageBytes: 1000, CurrentStorageBytes: 500}
	if got := q.StorageUsagePercent(); got != 50.0 {
		t.Errorf("StorageUsagePercent = %f, want 50.0", got)
	}

	q2 := QuotaInfo{MaxStorageBytes: 0, CurrentStorageBytes: 500}
	if got := q2.StorageUsagePercent(); got != 0 {
		t.Errorf("StorageUsagePercent (unlimited) = %f, want 0", got)
	}

	q3 := QuotaInfo{MaxItems: 100, CurrentItems: 75}
	if got := q3.ItemsUsagePercent(); got != 75.0 {
		t.Errorf("ItemsUsagePercent = %f, want 75.0", got)
	}
}

// --- UserStore quota method tests ---

func TestUserStoreUpdateQuota(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")

	// Set quota
	if err := us.UpdateQuota(ctx, "alice", 1024, 10); err != nil {
		t.Fatalf("update quota: %v", err)
	}

	u, err := us.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.MaxStorageBytes != 1024 {
		t.Errorf("max_storage_bytes = %d, want 1024", u.MaxStorageBytes)
	}
	if u.MaxItems != 10 {
		t.Errorf("max_items = %d, want 10", u.MaxItems)
	}
}

func TestUserStoreGetQuota(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	us.UpdateQuota(ctx, "alice", 2048, 20)

	q, err := us.GetQuota(ctx, "alice")
	if err != nil {
		t.Fatalf("get quota: %v", err)
	}
	if q.MaxStorageBytes != 2048 {
		t.Errorf("max_storage_bytes = %d, want 2048", q.MaxStorageBytes)
	}
	if q.MaxItems != 20 {
		t.Errorf("max_items = %d, want 20", q.MaxItems)
	}
}

func TestUserStoreGetQuotaNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	_, err := us.GetQuota(ctx, "nobody")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserStoreIncrementUsage(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	us.UpdateQuota(ctx, "alice", 1000, 10)

	// Increment usage
	if err := us.IncrementUsage(ctx, "alice", 100); err != nil {
		t.Fatalf("increment usage: %v", err)
	}

	u, _ := us.Get(ctx, "alice")
	if u.CurrentStorageBytes != 100 {
		t.Errorf("current_storage_bytes = %d, want 100", u.CurrentStorageBytes)
	}
	if u.CurrentItems != 1 {
		t.Errorf("current_items = %d, want 1", u.CurrentItems)
	}
}

func TestUserStoreDecrementUsage(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	us.UpdateQuota(ctx, "alice", 1000, 10)

	// Set usage manually
	us.Update(ctx, "alice", func(u *User) {
		u.CurrentStorageBytes = 500
		u.CurrentItems = 5
	})

	// Decrement
	if err := us.DecrementUsage(ctx, "alice", 200); err != nil {
		t.Fatalf("decrement usage: %v", err)
	}

	u, _ := us.Get(ctx, "alice")
	if u.CurrentStorageBytes != 300 {
		t.Errorf("current_storage_bytes = %d, want 300", u.CurrentStorageBytes)
	}
	if u.CurrentItems != 4 {
		t.Errorf("current_items = %d, want 4", u.CurrentItems)
	}
}

func TestUserStoreDecrementUsageNoUnderflow(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")

	// Decrement from zero — should not go negative
	if err := us.DecrementUsage(ctx, "alice", 100); err != nil {
		t.Fatalf("decrement usage: %v", err)
	}

	u, _ := us.Get(ctx, "alice")
	if u.CurrentStorageBytes != 0 {
		t.Errorf("current_storage_bytes = %d, want 0", u.CurrentStorageBytes)
	}
	if u.CurrentItems != 0 {
		t.Errorf("current_items = %d, want 0", u.CurrentItems)
	}
}

// --- ItemStore quota enforcement tests ---

func TestItemStoreAppendQuotaExceeded(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	is := NewItemStore(ts)
	is.SetUserStore(us)
	ctx := context.Background()

	// Create user with quota: 100 bytes, 5 items
	us.Create(ctx, "alice", "Alice", "pass")
	us.UpdateQuota(ctx, "alice", 100, 5)

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Append items until quota is exceeded
	for i := 0; i < 5; i++ {
		_, err := is.Append(ctx, InboxFolderID("alice"), []byte("small"), nil)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// 6th item should fail (storage: 5*5=25 bytes used, 6*5=30 would still be under 100 bytes)
	// But let's test with larger data to hit storage limit
	// Actually, 5 items already used, so 6th would exceed max_items=5
	_, err := is.Append(ctx, InboxFolderID("alice"), []byte("x"), nil)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestItemStoreAppendQuotaStorageExceeded(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	is := NewItemStore(ts)
	is.SetUserStore(us)
	ctx := context.Background()

	// Create user with quota: 20 bytes, 100 items
	us.Create(ctx, "alice", "Alice", "pass")
	us.UpdateQuota(ctx, "alice", 20, 100)

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Append 4 items of 5 bytes each = 20 bytes
	for i := 0; i < 4; i++ {
		_, err := is.Append(ctx, InboxFolderID("alice"), []byte("small"), nil)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// 5th item of 5 bytes would exceed 20 bytes
	_, err := is.Append(ctx, InboxFolderID("alice"), []byte("small"), nil)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestItemStoreAppendUnlimitedQuota(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	is := NewItemStore(ts)
	is.SetUserStore(us)
	ctx := context.Background()

	// Create user with no quota (unlimited)
	us.Create(ctx, "alice", "Alice", "pass")

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Should be able to append freely
	for i := 0; i < 10; i++ {
		_, err := is.Append(ctx, InboxFolderID("alice"), []byte("message body data"), nil)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Verify counters were updated
	u, _ := us.Get(ctx, "alice")
	if u.CurrentItems != 10 {
		t.Errorf("current_items = %d, want 10", u.CurrentItems)
	}
	if u.CurrentStorageBytes != 10*int64(len("message body data")) {
		t.Errorf("current_storage_bytes = %d, want %d", u.CurrentStorageBytes, 10*int64(len("message body data")))
	}
}

func TestItemStoreAppendWithoutQuotaEnforcement(t *testing.T) {
	t.Parallel()
	// When UserStore is not set, no quota enforcement should occur
	ts := newTestSetup(t)
	is := NewItemStore(ts) // No SetUserStore call
	ctx := context.Background()

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Should work without quota enforcement
	_, err := is.Append(ctx, InboxFolderID("alice"), []byte("msg"), nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
}

func TestItemStoreDeleteDecrementsQuota(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	is := NewItemStore(ts)
	is.SetUserStore(us)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	us.UpdateQuota(ctx, "alice", 1000, 10)

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Append an item
	itemID, err := is.Append(ctx, InboxFolderID("alice"), []byte("hello world"), nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	// Verify counters
	u, _ := us.Get(ctx, "alice")
	if u.CurrentItems != 1 {
		t.Errorf("current_items = %d, want 1", u.CurrentItems)
	}
	if u.CurrentStorageBytes != 11 {
		t.Errorf("current_storage_bytes = %d, want 11", u.CurrentStorageBytes)
	}

	// Delete the item
	if err := is.Delete(ctx, itemID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Verify counters are decremented
	u, _ = us.Get(ctx, "alice")
	if u.CurrentItems != 0 {
		t.Errorf("after delete, current_items = %d, want 0", u.CurrentItems)
	}
	if u.CurrentStorageBytes != 0 {
		t.Errorf("after delete, current_storage_bytes = %d, want 0", u.CurrentStorageBytes)
	}
}

func TestItemStoreDeleteFreesQuotaSpace(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	is := NewItemStore(ts)
	is.SetUserStore(us)
	ctx := context.Background()

	// Create user with quota: 10 items max
	us.Create(ctx, "alice", "Alice", "pass")
	us.UpdateQuota(ctx, "alice", 10000, 3)

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Fill up the quota
	var itemIDs []string
	for i := 0; i < 3; i++ {
		itemID, err := is.Append(ctx, InboxFolderID("alice"), []byte("msg"), nil)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		itemIDs = append(itemIDs, itemID)
	}

	// 4th should fail
	_, err := is.Append(ctx, InboxFolderID("alice"), []byte("msg"), nil)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded, got %v", err)
	}

	// Delete one item
	if err := is.Delete(ctx, itemIDs[0]); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Now should be able to append again
	_, err = is.Append(ctx, InboxFolderID("alice"), []byte("msg"), nil)
	if err != nil {
		t.Fatalf("append after delete: %v", err)
	}
}

func TestExtractUserID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		folderID string
		want     string
	}{
		{"alice:INBOX", "alice"},
		{"bob:INBOX/Subfolder", "bob"},
		{"user123:Sent", "user123"},
		{"no-colon", ""},
		{":path", ""},
	}

	for _, tt := range tests {
		got := extractUserID(tt.folderID)
		if got != tt.want {
			t.Errorf("extractUserID(%q) = %q, want %q", tt.folderID, got, tt.want)
		}
	}
}

func TestErrQuotaExceeded(t *testing.T) {
	t.Parallel()
	// Verify the sentinel error is properly defined
	if ErrQuotaExceeded == nil {
		t.Error("ErrQuotaExceeded should not be nil")
	}
	if !errors.Is(fmt.Errorf("wrapped: %w", ErrQuotaExceeded), ErrQuotaExceeded) {
		t.Error("wrapped ErrQuotaExceeded should match errors.Is")
	}
}
