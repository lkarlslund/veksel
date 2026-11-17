package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

// scanFixture is a mailbox with more messages than the cache holds entries.
func scanFixture(t testing.TB, messages int) (FolderSpace, AccessContext, model.Folder, []model.Item) {
	t.Helper()
	_, typed, _ := testMailService(t)
	next := NewFolderSpace(typed, authz.New(typed))
	access := UserAccess("alice", "test")
	inbox, err := next.GetFolderByPath(context.Background(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	items := make([]model.Item, messages)
	for index := range items {
		items[index], err = next.CreateItem(context.Background(), access, inbox.ID, ItemInput{Data: fmt.Appendf(nil, "Subject: scan %d\r\n\r\nbody %d", index, index)})
		if err != nil {
			t.Fatal(err)
		}
	}
	return next, access, inbox, items
}

func TestCachedFolderSpaceScanKeepsHotListings(t *testing.T) {
	next, access, inbox, items := scanFixture(t, 64)
	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 16, MaxBytes: 1 << 20})
	listing := func() {
		t.Helper()
		if _, err := cache.ListItems(t.Context(), access, inbox.ID, ItemQuery{MetadataOnly: true, RequireRead: true}); err != nil {
			t.Fatal(err)
		}
	}
	// A selected mailbox's listing is reread by every command.
	listing()
	listing()

	// One pass over four times as many messages as the cache holds.
	for _, item := range items {
		if _, err := cache.GetItem(t.Context(), access, item.ID); err != nil {
			t.Fatal(err)
		}
	}
	if stats := cache.Stats(); stats.Evictions == 0 || stats.Entries > 16 {
		t.Fatalf("scan did not fill the cache: %+v", stats)
	}

	hits := cache.Stats().Hits
	listing()
	if cache.Stats().Hits != hits+2 {
		t.Fatalf("one-pass scan evicted the hot listing or its folder: %+v", cache.Stats())
	}

	// Items a scan reads twice are reused and protected within their class,
	// but the item class yields once it holds more than half of the cache.
	for range 2 {
		for _, item := range items[:32] {
			if _, err := cache.GetItem(t.Context(), access, item.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if stats := cache.Stats(); stats.Entries > 16 {
		t.Fatalf("limits exceeded: %+v", stats)
	}
	hits = cache.Stats().Hits
	listing()
	if cache.Stats().Hits != hits+2 {
		t.Fatalf("reread items evicted the hot listing: %+v", cache.Stats())
	}
}

func TestCachedFolderSpaceBulkReadsDoNotPopulate(t *testing.T) {
	next, access, inbox, items := scanFixture(t, 4)
	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 64, MaxBytes: 1 << 20})
	if _, err := cache.GetItem(t.Context(), access, items[0].ID); err != nil {
		t.Fatal(err)
	}
	warm := cache.Stats()

	bulk := WithBulkRead(t.Context())
	for range 2 {
		for _, item := range items {
			if _, err := cache.GetItem(bulk, access, item.ID); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := cache.ListItems(bulk, access, inbox.ID, ItemQuery{}); err != nil {
			t.Fatal(err)
		}
	}
	stats := cache.Stats()
	if stats.Entries != warm.Entries {
		t.Fatalf("bulk reads populated the cache: before=%+v after=%+v", warm, stats)
	}
	// The interactively cached item is still served to the bulk reader;
	// the folder lookups each listing makes are cached as usual.
	if stats.Hits < warm.Hits+2 {
		t.Fatalf("bulk reads skipped cached entries: before=%+v after=%+v", warm, stats)
	}

	// Mutations still invalidate entries read before or during bulk reads.
	if _, err := cache.SetFlags(t.Context(), access, items[0].ID, []string{model.FlagSeen}); err != nil {
		t.Fatal(err)
	}
	item, err := cache.GetItem(bulk, access, items[0].ID)
	if err != nil || len(item.Flags) != 1 {
		t.Fatalf("bulk read after mutation = %#v, %v", item, err)
	}
}

func TestCachedFolderSpaceInvalidatesProtectedEntries(t *testing.T) {
	next, access, inbox, items := scanFixture(t, 1)
	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 16, MaxBytes: 1 << 20})
	for range 2 {
		if _, err := cache.ListItems(t.Context(), access, inbox.ID, ItemQuery{MetadataOnly: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := next.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: behind\r\n\r\nbody")}); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.SetFlags(t.Context(), access, items[0].ID, []string{model.FlagSeen}); err != nil {
		t.Fatal(err)
	}
	listed, err := cache.ListItems(t.Context(), access, inbox.ID, ItemQuery{MetadataOnly: true})
	if err != nil || len(listed) != 2 {
		t.Fatalf("protected listing survived invalidation: %d items, %v", len(listed), err)
	}
	cache.Clear()
	if stats := cache.Stats(); stats.Entries != 0 || stats.Bytes != 0 {
		t.Fatalf("clear left entries: %+v", stats)
	}
}

// BenchmarkCachedFolderSpaceMixedScan interleaves an interactive session,
// which rereads its mailbox listing, with a content scan that reads twice as
// many messages as the cache holds between two listing reads, cycling over a
// mailbox four times larger than the cache. The listing hit ratio shows how
// much the scan disturbs the interactive session.
func BenchmarkCachedFolderSpaceMixedScan(b *testing.B) {
	next, access, inbox, items := scanFixture(b, 256)
	run := func(b *testing.B, scanCtx context.Context) {
		cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 64, MaxBytes: 64 << 20})
		var listingHits, listingReads int
		b.ResetTimer()
		for index := range b.N {
			before := cache.Stats().Hits
			if _, err := cache.ListItems(b.Context(), access, inbox.ID, ItemQuery{MetadataOnly: true, RequireRead: true}); err != nil {
				b.Fatal(err)
			}
			if cache.Stats().Hits == before+2 {
				listingHits++
			}
			listingReads++
			for _, item := range items[(index*128)%len(items):][:128] {
				if _, err := cache.GetItem(scanCtx, access, item.ID); err != nil {
					b.Fatal(err)
				}
			}
		}
		b.ReportMetric(float64(listingHits)/float64(listingReads)*100, "listing-hit-%")
	}
	b.Run("scan", func(b *testing.B) { run(b, b.Context()) })
	b.Run("bulk-scan", func(b *testing.B) { run(b, WithBulkRead(b.Context())) })
}
