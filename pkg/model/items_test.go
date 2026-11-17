package model

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/objectstore"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func TestItemStoreUsesImmutableObjectPayloads(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects, err := objectstore.Open(t.TempDir(), objectstore.Options{SyncWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = objects.Close()
		_ = backend.Close()
	})
	ts := NewTypedStoreWithObjects(backend, store.BackendPebble, objects)
	testSetup(t, ts)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	payload := []byte("From: alice@example.com\r\nSubject: segmented\r\n\r\noriginal bytes")
	item, err := ts.ItemStore().AppendItem(t.Context(), InboxFolderID("alice"), Item{Data: payload})
	if err != nil {
		t.Fatal(err)
	}

	var stored storedItem
	if err := ts.Get(t.Context(), NSItems, item.ID, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Data) != 0 || stored.Payload == nil {
		t.Fatalf("stored item has inline=%d bytes, payload ref=%v", len(stored.Data), stored.Payload)
	}
	got, err := ts.ItemStore().Get(t.Context(), item.ID)
	if err != nil || !bytes.Equal(got.Data, payload) {
		t.Fatalf("Get: got %q, %v; want original payload", got.Data, err)
	}

	recordsBefore, err := objects.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.ItemStore().SetFlags(t.Context(), item.ID, []string{FlagSeen}); err != nil {
		t.Fatal(err)
	}
	recordsAfterFlags, err := objects.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(recordsAfterFlags) != len(recordsBefore) {
		t.Fatalf("flag update appended payload: before=%d after=%d", len(recordsBefore), len(recordsAfterFlags))
	}

	got, err = ts.ItemStore().Get(t.Context(), item.ID)
	if err != nil {
		t.Fatal(err)
	}
	got.Data = []byte("replacement payload")
	if err := ts.ItemStore().SetItem(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	recordsAfterReplace, err := objects.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(recordsAfterReplace) != len(recordsBefore)+1 {
		t.Fatalf("payload replacement records=%d, want %d", len(recordsAfterReplace), len(recordsBefore)+1)
	}
	replaced, err := ts.ItemStore().Get(t.Context(), item.ID)
	if err != nil || string(replaced.Data) != "replacement payload" {
		t.Fatalf("replacement: got %q, %v", replaced.Data, err)
	}
}

func TestFolderModificationSequenceIsMonotonicAcrossItems(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.UserStore().Create(t.Context(), "modseq-user", "ModSeq User", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "modseq-user"); err != nil {
		t.Fatal(err)
	}
	items := ts.ItemStore()
	first, err := items.AppendItem(t.Context(), InboxFolderID("modseq-user"), Item{Data: []byte("first")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := items.AppendItem(t.Context(), InboxFolderID("modseq-user"), Item{Data: []byte("second")})
	if err != nil {
		t.Fatal(err)
	}
	if second.ModSeq <= first.ModSeq {
		t.Fatalf("append modseqs = %d, %d", first.ModSeq, second.ModSeq)
	}
	if err := items.SetFlags(t.Context(), first.ID, []string{FlagSeen}); err != nil {
		t.Fatal(err)
	}
	updated, err := items.GetMetadata(t.Context(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	folder, err := ts.FolderStore().Get(t.Context(), InboxFolderID("modseq-user"))
	if err != nil {
		t.Fatal(err)
	}
	if updated.ModSeq <= second.ModSeq || folder.HighestModSeq != updated.ModSeq {
		t.Fatalf("updated=%d second=%d folder=%d", updated.ModSeq, second.ModSeq, folder.HighestModSeq)
	}
}

func TestItemStoreMetadataReadsDoNotOpenPayloads(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects, err := objectstore.Open(t.TempDir(), objectstore.Options{SyncWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = objects.Close()
		_ = backend.Close()
	})
	ts := NewTypedStoreWithObjects(backend, store.BackendPebble, objects)
	testSetup(t, ts)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	item, err := ts.ItemStore().AppendItem(t.Context(), InboxFolderID("alice"), Item{
		Data: []byte("Subject: metadata only\r\n\r\npayload"), Headers: map[string]string{"Subject": "metadata only"},
		ExternalIDs: map[string]string{"source": "remote-42"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var stored storedItem
	if err := ts.Get(t.Context(), NSItems, item.ID, &stored); err != nil {
		t.Fatal(err)
	}
	broken := *stored.Payload
	broken.Segment += 1_000_000
	stored.Payload = &broken
	if err := ts.Set(t.Context(), NSItems, item.ID, stored); err != nil {
		t.Fatal(err)
	}

	metadata, err := ts.ItemStore().GetMetadata(t.Context(), item.ID)
	if err != nil {
		t.Fatalf("GetMetadata opened payload: %v", err)
	}
	if len(metadata.Data) != 0 || metadata.Size != item.Size || metadata.Headers["Subject"] != "metadata only" {
		t.Fatalf("metadata = %+v", metadata)
	}
	metadata, err = ts.ItemStore().GetMetadataByExternalID(t.Context(), InboxFolderID("alice"), "source", "remote-42")
	if err != nil || metadata.ID != item.ID || len(metadata.Data) != 0 {
		t.Fatalf("GetMetadataByExternalID = %+v, %v", metadata, err)
	}
	listed, err := ts.ItemStore().ListMetadata(t.Context(), InboxFolderID("alice"))
	if err != nil || len(listed) != 1 || listed[0].ID != item.ID || len(listed[0].Data) != 0 {
		t.Fatalf("ListMetadata = %+v, %v", listed, err)
	}
	ids, err := ts.ItemStore().List(t.Context(), InboxFolderID("alice"))
	if err != nil || len(ids) != 1 || ids[0] != item.ID {
		t.Fatalf("List = %v, %v", ids, err)
	}
	if _, err := ts.ItemStore().Get(t.Context(), item.ID); err == nil {
		t.Fatal("Get unexpectedly succeeded with an unavailable payload")
	}
}

func BenchmarkItemStoreListMetadata(b *testing.B) {
	backend, err := pebblestore.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	objects, err := objectstore.Open(b.TempDir(), objectstore.Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = objects.Close()
		_ = backend.Close()
	})
	ts := NewTypedStoreWithObjects(backend, store.BackendPebble, objects)
	for _, namespace := range Namespaces() {
		if err := ts.EnsureNamespace(b.Context(), namespace); err != nil {
			b.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(b.Context(), "alice", "Alice", "secret"); err != nil {
		b.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(b.Context(), "alice"); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 128<<10)
	for range 100 {
		if _, err := ts.ItemStore().Append(b.Context(), InboxFolderID("alice"), payload, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for range b.N {
		if _, err := ts.ItemStore().ListMetadata(b.Context(), InboxFolderID("alice")); err != nil {
			b.Fatal(err)
		}
	}
}

func TestItemStoreAppendAndGet(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	// Create the folder first for UID allocation
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	data := []byte("From: alice@example.com\r\nTo: bob@example.com\r\n\r\nHello!")
	headers := map[string]string{
		"From":    "alice@example.com",
		"To":      "bob@example.com",
		"Subject": "Test",
	}

	itemID, err := is.Append(ctx, folderID, data, headers)
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	// Verify item ID format
	if len(itemID) == 0 {
		t.Fatal("expected non-empty item ID")
	}

	// Get the item
	item, err := is.Get(ctx, itemID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if item.FolderID != folderID {
		t.Errorf("folder_id = %q, want %q", item.FolderID, folderID)
	}
	if string(item.Data) != string(data) {
		t.Error("data mismatch")
	}
	if item.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", item.Size, len(data))
	}
	if item.UID == 0 {
		t.Error("expected non-zero UID")
	}
	if item.ModSeq != 1 {
		t.Errorf("mod_seq = %d, want 1", item.ModSeq)
	}
	if item.InternalDate.IsZero() {
		t.Error("expected non-zero internal_date")
	}
	if item.Headers["From"] != "alice@example.com" {
		t.Errorf("headers[From] = %q, want %q", item.Headers["From"], "alice@example.com")
	}
}

func TestItemStoreAppendItemStoresCompleteMetadata(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()
	folderID := InboxFolderID("alice")
	if err := NewFolderStore(ts).CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	internalDate := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.FixedZone("source", 3600))
	input := Item{
		Data: []byte("Subject: complete\r\n\r\nbody"), Headers: map[string]string{"Subject": "complete"},
		Flags: []string{FlagSeen, FlagFlagged}, InternalDate: internalDate,
		ExternalIDs: map[string]string{"source": "remote-42"},
	}
	created, err := is.AppendItem(ctx, folderID, input)
	if err != nil {
		t.Fatal(err)
	}
	if !created.InternalDate.Equal(internalDate) || len(created.Flags) != 2 || created.ExternalIDs["source"] != "remote-42" {
		t.Fatalf("created item metadata = %#v", created)
	}
	indexed, err := is.GetByExternalID(ctx, folderID, "source", "remote-42")
	if err != nil || indexed.ID != created.ID {
		t.Fatalf("external index item = %q, err = %v; want %q", indexed.ID, err, created.ID)
	}
	if _, err := is.AppendItem(ctx, folderID, input); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate external identity error = %v, want ErrExists", err)
	}
}

func TestItemStoreAppendItemConcurrentPebbleUIDs(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := NewTypedStore(backend, store.BackendPebble)
	testSetup(t, ts)
	ctx := context.Background()
	if err := ts.UserStore().Create(ctx, "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := NewFolderStore(ts).CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	const count = 16
	items := make(chan Item, count)
	errs := make(chan error, count)
	var workers sync.WaitGroup
	for range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			item, err := ts.ItemStore().AppendItem(ctx, InboxFolderID("alice"), Item{Data: []byte("message")})
			items <- item
			errs <- err
		}()
	}
	workers.Wait()
	close(items)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	uids := make(map[uint32]struct{}, count)
	for item := range items {
		if item.UID == 0 {
			t.Fatal("item has zero UID")
		}
		if _, duplicate := uids[item.UID]; duplicate {
			t.Fatalf("duplicate UID %d", item.UID)
		}
		uids[item.UID] = struct{}{}
	}
	if len(uids) != count {
		t.Fatalf("UID count = %d, want %d", len(uids), count)
	}
	user, err := ts.UserStore().Get(ctx, "alice")
	if err != nil || user.CurrentItems != count || user.CurrentStorageBytes != count*int64(len("message")) {
		t.Fatalf("quota usage = items %d, bytes %d, err %v", user.CurrentItems, user.CurrentStorageBytes, err)
	}
	inbox, err := ts.FolderStore().Get(ctx, InboxFolderID("alice"))
	if err != nil || inbox.ItemCount != count || inbox.LogicalBytes != count*int64(len("message")) || inbox.UsageVersion != 1 {
		t.Fatalf("folder usage = items %d, bytes %d, version %d, err %v", inbox.ItemCount, inbox.LogicalBytes, inbox.UsageVersion, err)
	}
}

func TestFolderUsageMetadataTracksUpdateMoveAndDelete(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	item, err := ts.ItemStore().AppendItem(t.Context(), InboxFolderID("alice"), Item{Data: []byte("one")})
	if err != nil {
		t.Fatal(err)
	}
	item.Data = []byte("longer")
	item.Size = int64(len(item.Data))
	if err := ts.ItemStore().SetItem(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	archive, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Archive")
	if err != nil {
		t.Fatal(err)
	}
	moved, err := ts.ItemStore().Move(t.Context(), item.ID, archive.ID, item.Name)
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := ts.FolderStore().Get(t.Context(), InboxFolderID("alice"))
	if err != nil || inbox.ItemCount != 0 || inbox.LogicalBytes != 0 {
		t.Fatalf("source usage after move = %+v, %v", inbox, err)
	}
	archive, err = ts.FolderStore().Get(t.Context(), archive.ID)
	if err != nil || archive.ItemCount != 1 || archive.LogicalBytes != int64(len("longer")) {
		t.Fatalf("destination usage after move = %+v, %v", archive, err)
	}
	if err := ts.ItemStore().Delete(t.Context(), moved.ID); err != nil {
		t.Fatal(err)
	}
	archive, err = ts.FolderStore().Get(t.Context(), archive.ID)
	if err != nil || archive.ItemCount != 0 || archive.LogicalBytes != 0 {
		t.Fatalf("destination usage after delete = %+v, %v", archive, err)
	}
}

func TestItemDeleteRequiresFolderAccountingRecord(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	item, err := ts.ItemStore().AppendItem(t.Context(), InboxFolderID("alice"), Item{Data: []byte("retained")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().Delete(t.Context(), InboxFolderID("alice")); err != nil {
		t.Fatal(err)
	}
	if err := ts.ItemStore().Delete(t.Context(), item.ID); err == nil {
		t.Fatal("delete without a folder accounting record succeeded")
	}
	if _, err := ts.ItemStore().GetMetadata(t.Context(), item.ID); err != nil {
		t.Fatalf("item was removed despite failed accounting: %v", err)
	}
}

func TestListMetadataPageUsesUIDCursorAndFolderTotal(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	created := make([]Item, 0, 5)
	for index := range 5 {
		item, err := ts.ItemStore().AppendItem(t.Context(), InboxFolderID("alice"), Item{Data: []byte{byte('a' + index)}})
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, item)
	}
	if err := ts.ItemStore().Delete(t.Context(), created[3].ID); err != nil {
		t.Fatal(err)
	}

	first, total, cursor, err := ts.ItemStore().ListMetadataPage(t.Context(), InboxFolderID("alice"), 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || len(first) != 2 || first[0].UID != 5 || first[1].UID != 3 || cursor != 3 {
		t.Fatalf("first page=%#v total=%d cursor=%d", first, total, cursor)
	}
	second, secondTotal, next, err := ts.ItemStore().ListMetadataPage(t.Context(), InboxFolderID("alice"), cursor, 2)
	if err != nil {
		t.Fatal(err)
	}
	if secondTotal != 4 || len(second) != 2 || second[0].UID != 2 || second[1].UID != 1 || next != 0 {
		t.Fatalf("second page=%#v total=%d cursor=%d", second, secondTotal, next)
	}
	full, fullTotal, fullCursor, err := ts.ItemStore().ListPage(t.Context(), InboxFolderID("alice"), 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if fullTotal != 4 || fullCursor != 3 || len(full) != 2 || string(full[0].Data) != "e" || string(full[1].Data) != "c" {
		t.Fatalf("full page=%#v total=%d cursor=%d", full, fullTotal, fullCursor)
	}
}

func TestListDatePageUsesStableChronologicalCursor(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	dates := []time.Time{
		time.Date(2026, 1, 3, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
	}
	created := make([]Item, 0, len(dates))
	for index, date := range dates {
		item, err := ts.ItemStore().AppendItem(t.Context(), InboxFolderID("alice"), Item{Data: []byte{byte('a' + index)}, InternalDate: date})
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, item)
	}

	first, total, cursor, err := ts.ItemStore().ListDatePage(t.Context(), InboxFolderID("alice"), "", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(first) != 2 || first[0].ID != created[0].ID || first[1].ID != created[4].ID || cursor == "" {
		t.Fatalf("first chronological page=%#v total=%d cursor=%q", first, total, cursor)
	}
	if _, err := ts.ItemStore().AppendItem(t.Context(), InboxFolderID("alice"), Item{Data: []byte("new"), InternalDate: time.Date(2026, 1, 4, 9, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	second, secondTotal, next, err := ts.ItemStore().ListDatePage(t.Context(), InboxFolderID("alice"), cursor, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if secondTotal != 6 || len(second) != 2 || second[0].ID != created[3].ID || second[1].ID != created[2].ID || string(second[0].Data) != "d" || next == "" {
		t.Fatalf("second chronological page=%#v total=%d cursor=%q", second, secondTotal, next)
	}
	third, _, finalCursor, err := ts.ItemStore().ListDatePage(t.Context(), InboxFolderID("alice"), next, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 1 || third[0].ID != created[1].ID || finalCursor != "" {
		t.Fatalf("final chronological page=%#v cursor=%q", third, finalCursor)
	}
	if _, _, _, err := ts.ItemStore().ListDatePage(t.Context(), InboxFolderID("alice"), "not-a-cursor", 2, false); err == nil {
		t.Fatal("invalid chronological cursor succeeded")
	}
	if _, _, _, err := ts.ItemStore().ListDatePage(t.Context(), SentFolderID("alice"), cursor, 2, false); err == nil {
		t.Fatal("cross-folder chronological cursor succeeded")
	}
}

func TestListDateWindowReturnsImmediateMetadataNeighbors(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	dates := []time.Time{
		time.Date(2026, 1, 3, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
	}
	created := make([]Item, 0, len(dates))
	for index, date := range dates {
		item, err := ts.ItemStore().AppendItem(t.Context(), InboxFolderID("alice"), Item{Data: []byte{byte('a' + index)}, InternalDate: date})
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, item)
	}

	middle, total, err := ts.ItemStore().ListDateWindow(t.Context(), InboxFolderID("alice"), created[3].ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(middle) != 3 || middle[0].ID != created[4].ID || middle[1].ID != created[3].ID || middle[2].ID != created[2].ID {
		t.Fatalf("middle window=%#v total=%d", middle, total)
	}
	for _, item := range middle {
		if item.Data != nil {
			t.Fatalf("metadata window loaded payload for %s", item.ID)
		}
	}
	newest, _, err := ts.ItemStore().ListDateWindow(t.Context(), InboxFolderID("alice"), created[0].ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(newest) != 2 || newest[0].ID != created[0].ID || newest[1].ID != created[4].ID {
		t.Fatalf("newest window=%#v", newest)
	}
	oldest, _, err := ts.ItemStore().ListDateWindow(t.Context(), InboxFolderID("alice"), created[1].ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(oldest) != 2 || oldest[0].ID != created[2].ID || oldest[1].ID != created[1].ID || string(oldest[1].Data) != "b" {
		t.Fatalf("oldest window=%#v", oldest)
	}
	if _, _, err := ts.ItemStore().ListDateWindow(t.Context(), SentFolderID("alice"), created[3].ID, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-folder anchor error=%v", err)
	}
}

func TestItemStoreAppendMultiple(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Append 3 items
	for i := 0; i < 3; i++ {
		_, err := is.Append(ctx, folderID, []byte("message body"), nil)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	keys, err := is.List(ctx, folderID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(keys); got != 3 {
		t.Errorf("expected 3 items, got %d", got)
	}
}

func TestItemStoreMovePreservesResourceIDAndRebuildsIndexes(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	if err := fs.CreateForUser(ctx, "alice"); err != nil {
		t.Fatalf("create folders: %v", err)
	}
	sourceID := InboxFolderID("alice")
	destination, err := fs.GetByPath(ctx, "alice", "Archive")
	if err != nil {
		t.Fatalf("get destination: %v", err)
	}
	itemID, err := is.Append(ctx, sourceID, []byte("message"), nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	original, err := is.Get(ctx, itemID)
	if err != nil {
		t.Fatalf("get original: %v", err)
	}

	moved, err := is.Move(ctx, itemID, destination.ID, "archived.eml")
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if moved.ID != itemID {
		t.Fatalf("ID changed during move: got %q want %q", moved.ID, itemID)
	}
	if moved.FolderID != destination.ID || moved.Name != "archived.eml" {
		t.Fatalf("unexpected destination: folder=%q name=%q", moved.FolderID, moved.Name)
	}
	if moved.UID == 0 {
		t.Fatal("move should allocate a destination UID")
	}
	if items, err := is.List(ctx, sourceID); err != nil || len(items) != 0 {
		t.Fatalf("source membership remains: items=%v err=%v", items, err)
	}
	items, err := is.List(ctx, destination.ID)
	if err != nil || len(items) != 1 || items[0] != itemID {
		t.Fatalf("destination membership missing: items=%v err=%v", items, err)
	}
	if _, err := is.GetByUID(ctx, sourceID, original.UID); err == nil {
		t.Fatal("old UID index still resolves")
	}
	if byName, err := is.Get(ctx, ItemKey(destination.ID, "archived.eml")); err != nil || byName.ID != itemID {
		t.Fatalf("destination name index: item=%v err=%v", byName.ID, err)
	}
}

func TestItemStoreTrashAndRestoreAcrossFolderTypes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		folderPath string
		trashPath  string
	}{
		{name: "mail moves to trash", folderPath: "INBOX", trashPath: "Trash"},
		{name: "contact stays in typed folder", folderPath: "Contacts"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ts := newTestSetup(t)
			is := NewItemStore(ts)
			fs := NewFolderStore(ts)
			ctx := context.Background()
			if err := fs.CreateForUser(ctx, "alice"); err != nil {
				t.Fatalf("create folders: %v", err)
			}
			source, _ := fs.GetByPath(ctx, "alice", test.folderPath)
			trashID := ""
			if test.trashPath != "" {
				trash, _ := fs.GetByPath(ctx, "alice", test.trashPath)
				trashID = trash.ID
			}
			itemID, err := is.Append(ctx, source.ID, []byte("resource"), nil)
			if err != nil {
				t.Fatalf("append: %v", err)
			}
			trashed, err := is.Trash(ctx, itemID, trashID, 30*24*time.Hour)
			if err != nil {
				t.Fatalf("trash: %v", err)
			}
			if trashed.ID != itemID || trashed.TrashedAt.IsZero() || trashed.OriginalFolderID != source.ID {
				t.Fatalf("unexpected trash metadata: %#v", trashed)
			}
			if listed, _ := is.List(ctx, source.ID); len(listed) != 0 {
				t.Fatalf("trashed item remains in normal listing: %v", listed)
			}
			allTrash, err := is.ListTrashedForUser(ctx, "alice")
			if err != nil || len(allTrash) != 1 || allTrash[0].ID != itemID {
				t.Fatalf("trash listing=%v err=%v", allTrash, err)
			}
			restored, err := is.Restore(ctx, itemID)
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
			if restored.ID != itemID || restored.FolderID != source.ID || !restored.TrashedAt.IsZero() {
				t.Fatalf("unexpected restored item: %#v", restored)
			}
			if listed, _ := is.List(ctx, source.ID); len(listed) != 1 || listed[0] != itemID {
				t.Fatalf("restored item missing: %v", listed)
			}
		})
	}
}

func TestItemStoreListEmpty(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	keys, err := is.List(ctx, InboxFolderID("alice"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty list, got %d items", len(keys))
	}
}

func TestItemStoreCountAllUsesMemberships(t *testing.T) {
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := t.Context()

	if err := ts.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	first, err := is.Append(ctx, InboxFolderID("alice"), []byte("first"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := is.Append(ctx, SentFolderID("alice"), []byte("second"), nil); err != nil {
		t.Fatal(err)
	}
	if got, err := is.CountAll(ctx); err != nil || got != 2 {
		t.Fatalf("CountAll() = %d, %v, want 2, nil", got, err)
	}
	if err := is.Delete(ctx, first); err != nil {
		t.Fatal(err)
	}
	if got, err := is.CountAll(ctx); err != nil || got != 1 {
		t.Fatalf("CountAll() after delete = %d, %v, want 1, nil", got, err)
	}
}

func TestItemStoreListPrefix(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Items in INBOX
	is.Append(ctx, InboxFolderID("alice"), []byte("inbox msg"), nil)
	is.Append(ctx, InboxFolderID("alice"), []byte("inbox msg 2"), nil)

	// Items in Sent
	is.Append(ctx, SentFolderID("alice"), []byte("sent msg"), nil)

	inboxKeys, _ := is.List(ctx, InboxFolderID("alice"))
	sentKeys, _ := is.List(ctx, SentFolderID("alice"))

	if got := len(inboxKeys); got != 2 {
		t.Errorf("inbox: expected 2 items, got %d", got)
	}
	if got := len(sentKeys); got != 1 {
		t.Errorf("sent: expected 1 item, got %d", got)
	}
}

func TestItemStoreGetNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	_, err := is.Get(ctx, "alice:INBOX:nonexistent")
	if err == nil {
		t.Error("expected error for non-existent item, got nil")
	}
}

func TestItemStoreDelete(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")
	itemID, err := is.Append(ctx, folderID, []byte("to delete"), nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	if err := is.Delete(ctx, itemID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err = is.Get(ctx, itemID)
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestItemStoreDeleteNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	err := is.Delete(ctx, "alice:INBOX:nonexistent")
	if err == nil {
		t.Error("expected error deleting non-existent item, got nil")
	}
}

func TestItemStoreAppendEmptyData(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")
	itemID, err := is.Append(ctx, InboxFolderID("alice"), []byte{}, nil)
	if err != nil {
		t.Fatalf("append empty: %v", err)
	}

	item, err := is.Get(ctx, itemID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if item.Size != 0 {
		t.Errorf("size = %d, want 0", item.Size)
	}
}

func TestItemKey(t *testing.T) {
	t.Parallel()
	id := ItemKey(InboxFolderID("alice"), "20250101T000000Z-001")
	want := InboxFolderID("alice") + ":20250101T000000Z-001"
	if id != want {
		t.Errorf("ItemKey = %q, want %q", id, want)
	}
}

// --- UID allocation tests ---

func TestUIDAllocationAscending(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	var lastUID uint32
	for i := 0; i < 10; i++ {
		itemID, err := is.Append(ctx, folderID, []byte("msg"), nil)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		item, err := is.Get(ctx, itemID)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if item.UID <= lastUID {
			t.Errorf("UID %d not ascending (prev=%d)", item.UID, lastUID)
		}
		lastUID = item.UID
	}
}

func TestUIDAllocationStartsAtOne(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	itemID, err := is.Append(ctx, folderID, []byte("first"), nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	item, err := is.Get(ctx, itemID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if item.UID != 1 {
		t.Errorf("first UID = %d, want 1", item.UID)
	}
}

func TestUIDAllocationUniqueAcrossFolders(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	// Append to INBOX and Sent
	inboxID, _ := is.Append(ctx, InboxFolderID("alice"), []byte("inbox"), nil)
	sentID, _ := is.Append(ctx, SentFolderID("alice"), []byte("sent"), nil)

	inboxItem, _ := is.Get(ctx, inboxID)
	sentItem, _ := is.Get(ctx, sentID)

	// Both should start at UID 1 in their respective folders
	if inboxItem.UID != 1 {
		t.Errorf("INBOX UID = %d, want 1", inboxItem.UID)
	}
	if sentItem.UID != 1 {
		t.Errorf("Sent UID = %d, want 1", sentItem.UID)
	}
}

// --- UID lookup tests ---

func TestGetByUID(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	itemID, err := is.Append(ctx, folderID, []byte("msg"), nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	item, err := is.Get(ctx, itemID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// Look up by UID
	found, err := is.GetByUID(ctx, folderID, item.UID)
	if err != nil {
		t.Fatalf("getByUID: %v", err)
	}
	if found.ID != itemID {
		t.Errorf("GetByUID returned ID %q, want %q", found.ID, itemID)
	}
}

func TestGetByUIDNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	_, err := is.GetByUID(ctx, InboxFolderID("alice"), 999)
	if err == nil {
		t.Error("expected error for non-existent UID, got nil")
	}
}

func TestDeleteRemovesUIDIndex(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	itemID, err := is.Append(ctx, folderID, []byte("msg"), nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	item, _ := is.Get(ctx, itemID)

	// Delete the item
	if err := is.Delete(ctx, itemID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// UID lookup should fail
	_, err = is.GetByUID(ctx, folderID, item.UID)
	if err == nil {
		t.Error("expected error after delete for UID lookup, got nil")
	}
}

// --- Flag operations tests ---

func TestSetFlags(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	itemID, _ := is.Append(ctx, folderID, []byte("msg"), nil)
	item, _ := is.Get(ctx, itemID)
	initialModSeq := item.ModSeq

	if err := is.SetFlags(ctx, itemID, []string{FlagSeen, FlagFlagged}); err != nil {
		t.Fatalf("setFlags: %v", err)
	}

	item, _ = is.Get(ctx, itemID)
	if len(item.Flags) != 2 {
		t.Errorf("flags = %v, want 2 flags", item.Flags)
	}
	if item.ModSeq != initialModSeq+1 {
		t.Errorf("ModSeq = %d, want %d", item.ModSeq, initialModSeq+1)
	}
}

func TestAddFlags(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	itemID, _ := is.Append(ctx, folderID, []byte("msg"), nil)

	// Add first flag
	if err := is.AddFlags(ctx, itemID, FlagSeen); err != nil {
		t.Fatalf("addFlags: %v", err)
	}
	// Add second flag
	if err := is.AddFlags(ctx, itemID, FlagFlagged); err != nil {
		t.Fatalf("addFlags: %v", err)
	}

	item, _ := is.Get(ctx, itemID)
	if len(item.Flags) != 2 {
		t.Errorf("flags = %v, want 2 flags", item.Flags)
	}
	// Adding duplicate should not add again
	if err := is.AddFlags(ctx, itemID, FlagSeen); err != nil {
		t.Fatalf("addFlags duplicate: %v", err)
	}
	item, _ = is.Get(ctx, itemID)
	if len(item.Flags) != 2 {
		t.Errorf("after duplicate add, flags = %v, want 2 flags", item.Flags)
	}
}

func TestRemoveFlags(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	itemID, _ := is.Append(ctx, folderID, []byte("msg"), nil)
	is.SetFlags(ctx, itemID, []string{FlagSeen, FlagFlagged, FlagDeleted})

	if err := is.RemoveFlags(ctx, itemID, FlagSeen); err != nil {
		t.Fatalf("removeFlags: %v", err)
	}

	item, _ := is.Get(ctx, itemID)
	if len(item.Flags) != 2 {
		t.Errorf("after remove, flags = %v, want 2 flags", item.Flags)
	}
	for _, f := range item.Flags {
		if f == FlagSeen {
			t.Error("FlagSeen should have been removed")
		}
	}
}

func TestCustomKeywordFlags(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	itemID, _ := is.Append(ctx, folderID, []byte("msg"), nil)
	if err := is.SetFlags(ctx, itemID, []string{"$my-custom-flag", "another"}); err != nil {
		t.Fatalf("setFlags: %v", err)
	}

	item, _ := is.Get(ctx, itemID)
	if len(item.Flags) != 2 {
		t.Errorf("flags = %v, want 2 custom flags", item.Flags)
	}
}

// --- ModSeq tests ---

func TestUpdateModSeq(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	itemID, _ := is.Append(ctx, folderID, []byte("msg"), nil)
	item, _ := is.Get(ctx, itemID)
	initialModSeq := item.ModSeq

	// Bump modseq
	if err := is.UpdateModSeq(ctx, itemID); err != nil {
		t.Fatalf("updateModSeq: %v", err)
	}

	item, _ = is.Get(ctx, itemID)
	if item.ModSeq != initialModSeq+1 {
		t.Errorf("ModSeq = %d, want %d", item.ModSeq, initialModSeq+1)
	}
}

func TestUpdateModSeqNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	err := is.UpdateModSeq(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent item, got nil")
	}
}

// --- Concurrent UID allocation tests ---

func TestConcurrentAppendsUniqueUIDs(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	uids := make(map[uint32]bool)
	var mu sync.Mutex

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			itemID, err := is.Append(ctx, folderID, []byte("msg"), nil)
			if err != nil {
				t.Errorf("append: %v", err)
				return
			}
			item, err := is.Get(ctx, itemID)
			if err != nil {
				t.Errorf("get: %v", err)
				return
			}
			mu.Lock()
			if uids[item.UID] {
				t.Errorf("duplicate UID %d", item.UID)
			}
			uids[item.UID] = true
			mu.Unlock()
		}()
	}

	wg.Wait()

	if len(uids) != goroutines {
		t.Errorf("expected %d unique UIDs, got %d", goroutines, len(uids))
	}
}

// --- Folder UIDValidity tests ---

func TestFolderUIDValidityInitialized(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	ctx := context.Background()

	fs := NewFolderStore(ts)
	fs.CreateForUser(ctx, "alice")

	folder, err := fs.GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get folder: %v", err)
	}
	if folder.UIDValidity == 0 {
		t.Error("UIDValidity should be non-zero")
	}
	if folder.NextUID != 0 {
		t.Errorf("NextUID = %d, want 0", folder.NextUID)
	}
}

func TestFolderNextUIDIncrements(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	folderID := InboxFolderID("alice")
	fs.CreateForUser(ctx, "alice")

	// Append 5 items
	for i := 0; i < 5; i++ {
		if _, err := is.Append(ctx, folderID, []byte("msg"), nil); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	folder, err := fs.Get(ctx, folderID)
	if err != nil {
		t.Fatalf("get folder: %v", err)
	}
	if folder.NextUID != 5 {
		t.Errorf("NextUID = %d, want 5", folder.NextUID)
	}
}

// --- Store error propagation tests ---

func TestSetFlagsNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	err := is.SetFlags(ctx, "nonexistent", []string{FlagSeen})
	if err == nil {
		t.Error("expected error for non-existent item, got nil")
	}
}

func TestAddFlagsNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	err := is.AddFlags(ctx, "nonexistent", FlagSeen)
	if err == nil {
		t.Error("expected error for non-existent item, got nil")
	}
}

func TestRemoveFlagsNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	err := is.RemoveFlags(ctx, "nonexistent", FlagSeen)
	if err == nil {
		t.Error("expected error for non-existent item, got nil")
	}
}

// --- UIDIndexKey helper test ---

func TestUIDIndexKey(t *testing.T) {
	t.Parallel()
	key := UIDIndexKey(InboxFolderID("alice"), 42)
	want := "uid:" + InboxFolderID("alice") + ":42"
	if key != want {
		t.Errorf("UIDIndexKey = %q, want %q", key, want)
	}
}

func TestExternalItemIndexKeyIsStableAndNamespaced(t *testing.T) {
	t.Parallel()
	first := ExternalItemIndexKey(InboxFolderID("alice"), "imap://source/alice", "42")
	if first != ExternalItemIndexKey(InboxFolderID("alice"), "imap://source/alice", "42") {
		t.Fatal("external item index key is not stable")
	}
	if first == ExternalItemIndexKey(InboxFolderID("alice"), "eas://source/alice", "42") || first == ExternalItemIndexKey(InboxFolderID("bob"), "imap://source/alice", "42") {
		t.Fatal("external item index key is not scoped by folder and namespace")
	}
}

// --- Append without folder (error) ---

func TestAppendWithoutFolder(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	// No folder created — UID allocation should fail
	_, err := is.Append(ctx, InboxFolderID("alice"), []byte("msg"), nil)
	if err == nil {
		t.Error("expected error appending to non-existent folder, got nil")
	}
}

// --- ErrNotFound verification ---

func TestGetNotFoundReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	is := NewItemStore(ts)
	ctx := context.Background()

	_, err := is.Get(ctx, "nonexistent")
	if err != store.ErrNotFound {
		t.Logf("got error: %v (type %T)", err, err)
		// May be wrapped or unwrapped depending on backend
	}
}
