package model

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

type folderOperationCountingStore struct {
	store.Store
	gets     int
	lists    int
	scans    int
	iterates int
}

// folderUnbatchedStore deliberately hides optional batching so rollback is
// also exercised for a minimal conforming store.Store implementation.
type folderUnbatchedStore struct{ store.Store }

func (s *folderOperationCountingStore) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	s.gets++
	return s.Store.Get(ctx, namespace, key)
}

func (s *folderOperationCountingStore) List(ctx context.Context, namespace string) ([]string, error) {
	s.lists++
	return s.Store.List(ctx, namespace)
}

func (s *folderOperationCountingStore) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	s.scans++
	return s.Store.Scan(ctx, namespace, prefix)
}

func (s *folderOperationCountingStore) Iterate(ctx context.Context, namespace, prefix string, fn store.IterCallback) error {
	s.iterates++
	return s.Store.Iterate(ctx, namespace, prefix, fn)
}

func (s *folderOperationCountingStore) View(ctx context.Context, fn func(context.Context) error) error {
	return store.View(ctx, s.Store, fn)
}

func (s *folderOperationCountingStore) reset() {
	s.gets, s.lists, s.scans, s.iterates = 0, 0, 0, 0
}

func TestFolderStoreCreateForUser(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	if err := fs.CreateForUser(ctx, "alice"); err != nil {
		t.Fatalf("create for user: %v", err)
	}

	folders, err := fs.ListForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("list for user: %v", err)
	}

	if got := len(folders); got != len(defaultFolders) {
		t.Fatalf("expected %d default folders, got %d", len(defaultFolders), got)
	}

	// Check INBOX exists
	found := false
	for _, f := range folders {
		if f.Path == "INBOX" {
			found = true
			if f.Type != FolderTypeMail {
				t.Errorf("INBOX type = %q, want %q", f.Type, FolderTypeMail)
			}
			if !f.Subscribed {
				t.Error("INBOX should be subscribed by default")
			}
			break
		}
	}
	if !found {
		t.Error("INBOX not found in default folders")
	}
	calendar, err := fs.GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	if !calendar.HasIndex(CalendarRangeIndex, 1) {
		t.Fatalf("calendar indexes = %#v, want attached %s index", calendar.Indexes, CalendarRangeIndex)
	}
}

func TestFolderStoreCreateForUserDuplicate(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	err := fs.CreateForUser(ctx, "alice")
	if err == nil {
		t.Error("expected error creating duplicate default folders, got nil")
	}
}

func TestFolderStoreCreate(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")

	// Create a custom folder
	if err := fs.Create(ctx, "alice", "INBOX/Work", FolderTypeMail, ""); err != nil {
		t.Fatalf("create custom folder: %v", err)
	}

	f, err := fs.GetByPath(ctx, "alice", "INBOX/Work")
	if err != nil {
		t.Fatalf("get by path: %v", err)
	}
	if f.Path != "INBOX/Work" {
		t.Errorf("path = %q, want %q", f.Path, "INBOX/Work")
	}
	if f.Name != "Work" {
		t.Errorf("name = %q, want %q", f.Name, "Work")
	}
	if f.Type != FolderTypeMail {
		t.Errorf("type = %q, want %q", f.Type, FolderTypeMail)
	}
}

func TestFolderStoreCreateEmptyPath(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	err := fs.Create(ctx, "alice", "", FolderTypeMail, "")
	if err == nil {
		t.Error("expected error for empty path, got nil")
	}
}

func TestFolderStoreCreateDuplicate(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	err := fs.Create(ctx, "alice", "INBOX", FolderTypeMail, "")
	if err == nil {
		t.Error("expected error creating duplicate folder, got nil")
	}
}

func TestFolderStoreGetByPath(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")

	f, err := fs.GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get by path: %v", err)
	}
	if f.Path != "INBOX" {
		t.Errorf("path = %q, want %q", f.Path, "INBOX")
	}
}

func TestFolderIndexesBackfillLegacyRecordsAndAvoidGlobalScans(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	counting := &folderOperationCountingStore{Store: backend}
	ts := NewTypedStore(counting, store.BackendJSON)
	testSetup(t, ts)
	legacy := Folder{ID: "legacy-folder", UserID: "alice", Name: "Legacy", Path: "Legacy", Type: FolderTypeMail}
	if err := ts.Set(t.Context(), NSFolders, legacy.ID, legacy); err != nil {
		t.Fatal(err)
	}

	if err := store.View(t.Context(), counting, func(viewCtx context.Context) error {
		got, err := ts.FolderStore().GetByPath(viewCtx, "alice", "Legacy")
		if err != nil || got.ID != legacy.ID {
			t.Fatalf("legacy lookup in view = %+v, %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := ts.Get(t.Context(), NSFolderIndexes, FolderIndexMarkerKey("alice"), &version); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("read-only view wrote migration marker: version=%d err=%v", version, err)
	}

	got, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Legacy")
	if err != nil || got.ID != legacy.ID {
		t.Fatalf("legacy lookup = %+v, %v", got, err)
	}
	var indexedID string
	if err := ts.Get(t.Context(), NSFolderIndexes, FolderPathIndexKey("alice", "Legacy"), &indexedID); err != nil || indexedID != legacy.ID {
		t.Fatalf("backfilled path index = %q, %v", indexedID, err)
	}

	counting.reset()
	if _, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Legacy"); err != nil {
		t.Fatal(err)
	}
	if counting.lists != 0 || counting.scans != 0 || counting.iterates != 0 {
		t.Fatalf("indexed path lookup enumerated storage: list=%d scan=%d iterate=%d", counting.lists, counting.scans, counting.iterates)
	}

	counting.reset()
	folders, err := ts.FolderStore().ListForUser(t.Context(), "alice")
	if err != nil || len(folders) != 1 {
		t.Fatalf("indexed account list = %+v, %v", folders, err)
	}
	if counting.lists != 0 || counting.iterates != 0 || counting.scans != 1 {
		t.Fatalf("indexed account list operations: list=%d scan=%d iterate=%d", counting.lists, counting.scans, counting.iterates)
	}
}

func TestFolderIndexesRejectNewerSchemaWithoutDowngradingMarker(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	future := FolderIndexVersion + 1
	if err := ts.Set(t.Context(), NSFolderIndexes, FolderIndexMarkerKey("alice"), future); err != nil {
		t.Fatal(err)
	}

	if _, err := ts.FolderStore().GetByPath(t.Context(), "alice", "INBOX"); err == nil {
		t.Fatal("newer folder index schema was accepted")
	}
	var retained int
	if err := ts.Get(t.Context(), NSFolderIndexes, FolderIndexMarkerKey("alice"), &retained); err != nil || retained != future {
		t.Fatalf("newer schema marker changed to %d: %v", retained, err)
	}
}

func TestFolderMoveFailureRollsBackTreeAndIndexes(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	failing := faultstore.New(backend)
	ts := NewTypedStore(folderUnbatchedStore{Store: failing}, store.BackendJSON)
	testSetup(t, ts)
	fs := ts.FolderStore()
	if err := fs.Create(t.Context(), "alice", "Projects", FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	parent, _ := fs.GetByPath(t.Context(), "alice", "Projects")
	if err := fs.Create(t.Context(), "alice", "Projects/Current", FolderTypeMail, parent.ID); err != nil {
		t.Fatal(err)
	}

	failing.Fail("set", 4)
	if err := fs.Move(t.Context(), parent.ID, "", "Renamed"); !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("move error = %v, want injected failure", err)
	}
	if _, err := fs.GetByPath(t.Context(), "alice", "Projects"); err != nil {
		t.Fatalf("original root missing after rollback: %v", err)
	}
	if _, err := fs.GetByPath(t.Context(), "alice", "Projects/Current"); err != nil {
		t.Fatalf("original child missing after rollback: %v", err)
	}
	if _, err := fs.GetByPath(t.Context(), "alice", "Renamed"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new path error = %v, want not found", err)
	}
}

func BenchmarkFolderStoreIndexedReads(b *testing.B) {
	backend, err := pebblestore.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = backend.Close() })
	ts := NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range Namespaces() {
		if err := ts.EnsureNamespace(b.Context(), namespace); err != nil {
			b.Fatal(err)
		}
	}
	for index := range 100 {
		if err := ts.FolderStore().CreateForUser(b.Context(), fmt.Sprintf("user-%03d", index)); err != nil {
			b.Fatal(err)
		}
	}

	b.Run("path-among-1200-folders", func(b *testing.B) {
		for b.Loop() {
			if _, err := ts.FolderStore().GetByPath(b.Context(), "user-050", "INBOX"); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("account-list-among-1200-folders", func(b *testing.B) {
		for b.Loop() {
			if _, err := ts.FolderStore().ListForUser(b.Context(), "user-050"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestFolderStoreGetByPathNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")

	_, err := fs.GetByPath(ctx, "alice", "NonExistent")
	if err == nil {
		t.Error("expected error for non-existent folder, got nil")
	}
}

func TestFolderStoreGet(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")

	id := FolderKey("alice", "INBOX")
	f, err := fs.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if f.Path != "INBOX" {
		t.Errorf("path = %q, want %q", f.Path, "INBOX")
	}
}

func TestFolderStoreGetNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	_, err := fs.Get(ctx, "alice:NonExistent")
	if err == nil {
		t.Error("expected error for non-existent folder, got nil")
	}
}

func TestFolderStoreListForUser(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	fs.CreateForUser(ctx, "bob")

	aliceFolders, err := fs.ListForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("list for alice: %v", err)
	}
	bobFolders, err := fs.ListForUser(ctx, "bob")
	if err != nil {
		t.Fatalf("list for bob: %v", err)
	}

	if len(aliceFolders) != len(defaultFolders) {
		t.Errorf("alice: expected %d folders, got %d", len(defaultFolders), len(aliceFolders))
	}
	if len(bobFolders) != len(defaultFolders) {
		t.Errorf("bob: expected %d folders, got %d", len(defaultFolders), len(bobFolders))
	}

	// Verify alice's folders don't include bob's
	for _, f := range aliceFolders {
		if f.UserID != "alice" {
			t.Errorf("folder user_id = %q, want %q", f.UserID, "alice")
		}
	}
}

func TestFolderStoreListForUserEmpty(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	folders, err := fs.ListForUser(ctx, "nobody")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(folders) != 0 {
		t.Errorf("expected empty list, got %d folders", len(folders))
	}
}

func TestFolderStoreDelete(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	fs.Create(ctx, "alice", "Custom", FolderTypeMail, "")

	folder, err := fs.GetByPath(ctx, "alice", "Custom")
	if err != nil {
		t.Fatalf("get custom folder: %v", err)
	}
	id := folder.ID
	if err := fs.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err = fs.Get(ctx, id)
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestFolderStoreDeleteNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	err := fs.Delete(ctx, "alice:NonExistent")
	if err == nil {
		t.Error("expected error deleting non-existent folder, got nil")
	}
}

func TestFolderMoveKeepsStableIdentityAndRewritesDescendantPaths(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()
	if err := fs.Create(ctx, "alice", "Projects", FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	projects, _ := fs.GetByPath(ctx, "alice", "Projects")
	if err := fs.Create(ctx, "alice", "Projects/2026", FolderTypeMail, projects.ID); err != nil {
		t.Fatal(err)
	}
	child, _ := fs.GetByPath(ctx, "alice", "Projects/2026")
	if err := fs.Create(ctx, "alice", "Clients", FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	clients, _ := fs.GetByPath(ctx, "alice", "Clients")

	if err := fs.Move(ctx, projects.ID, clients.ID, "Active"); err != nil {
		t.Fatalf("move: %v", err)
	}
	moved, err := fs.GetByPath(ctx, "alice", "Clients/Active")
	if err != nil || moved.ID != projects.ID {
		t.Fatalf("moved folder = %#v, err = %v", moved, err)
	}
	movedChild, err := fs.GetByPath(ctx, "alice", "Clients/Active/2026")
	if err != nil || movedChild.ID != child.ID || movedChild.ParentID != projects.ID {
		t.Fatalf("moved child = %#v, err = %v", movedChild, err)
	}
	if err := fs.Move(ctx, clients.ID, child.ID, "Loop"); err == nil {
		t.Fatal("moving a folder into its descendant succeeded")
	}
}

func TestFolderMoveProtectsSystemFolders(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	if err := fs.CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Move(t.Context(), InboxFolderID("alice"), "", "Inbox renamed"); err == nil {
		t.Fatal("renaming the system Inbox succeeded")
	}
}

func TestFolderTrashAndRestoreTree(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()
	if err := fs.CreateForUser(ctx, "alice"); err != nil {
		t.Fatalf("create defaults: %v", err)
	}
	if err := fs.Create(ctx, "alice", "Projects", FolderTypeFiles, ""); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	parent, _ := fs.GetByPath(ctx, "alice", "Projects")
	if err := fs.Create(ctx, "alice", "Projects/North", FolderTypeFiles, parent.ID); err != nil {
		t.Fatalf("create child: %v", err)
	}
	child, _ := fs.GetByPath(ctx, "alice", "Projects/North")

	if err := fs.Trash(ctx, parent.ID, 30*24*time.Hour); err != nil {
		t.Fatalf("trash: %v", err)
	}
	if _, err := fs.GetByPath(ctx, "alice", "Projects"); err == nil {
		t.Fatal("trashed folder is still active by path")
	}
	trashedChild, err := fs.Get(ctx, child.ID)
	if err != nil || trashedChild.TrashedAt.IsZero() {
		t.Fatalf("child was not trashed: %#v err=%v", trashedChild, err)
	}
	if err := fs.Restore(ctx, parent.ID); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored, err := fs.GetByPath(ctx, "alice", "Projects/North")
	if err != nil || restored.ID != child.ID || !restored.TrashedAt.IsZero() {
		t.Fatalf("child identity was not restored: %#v err=%v", restored, err)
	}
}

func TestFolderStoreNormalizeUserID(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "  Alice  ")

	folders, err := fs.ListForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(folders) != len(defaultFolders) {
		t.Errorf("expected %d folders for normalized id, got %d", len(defaultFolders), len(folders))
	}
}

func TestFolderStoreDefaultFolderTypes(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")

	expectedTypes := map[string]FolderType{
		"INBOX":             FolderTypeMail,
		"Drafts":            FolderTypeMail,
		"Sent":              FolderTypeMail,
		"Trash":             FolderTypeMail,
		"Junk":              FolderTypeMail,
		"Archive":           FolderTypeMail,
		"Calendar":          FolderTypeCalendar,
		"Contacts":          FolderTypeContacts,
		"Recent recipients": FolderTypeContacts,
		"Files":             FolderTypeFiles,
		"Sieve scripts":     FolderTypeSieve,
		"schedule-inbox":    FolderTypeScheduleInbox,
		"schedule-outbox":   FolderTypeScheduleOutbox,
		"Saved searches":    FolderTypeSavedSearch,
		"Message templates": FolderTypeMailTemplate,
	}

	folders, _ := fs.ListForUser(ctx, "alice")
	for _, f := range folders {
		want, ok := expectedTypes[f.Path]
		if !ok {
			t.Errorf("unexpected folder path %q", f.Path)
			continue
		}
		if f.Type != want {
			t.Errorf("folder %q type = %q, want %q", f.Path, f.Type, want)
		}
		if f.Type == FolderTypeSavedSearch && (!f.System || f.SpecialUse != SpecialUseSavedSearch || f.Subscribed) {
			t.Errorf("saved-search system folder = %+v", f)
		}
		if f.Type == FolderTypeMailTemplate && (!f.System || f.SpecialUse != SpecialUseMailTemplate || f.Subscribed) {
			t.Errorf("mail-template system folder = %+v", f)
		}
	}
}

func TestFolderStoreReservesSavedSearchFolderIdentity(t *testing.T) {
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	if err := fs.Create(t.Context(), "alice", "Other", FolderTypeSavedSearch, ""); err == nil {
		t.Fatal("created a saved-search folder outside its reserved path")
	}
	if err := fs.Create(t.Context(), "alice", FolderPathSavedSearch, FolderTypeSavedSearch, ""); err != nil {
		t.Fatal(err)
	}
	folder, err := fs.GetByPath(t.Context(), "alice", FolderPathSavedSearch)
	if err != nil || !folder.System || folder.SpecialUse != SpecialUseSavedSearch || folder.Subscribed {
		t.Fatalf("reserved folder=%+v err=%v", folder, err)
	}
}

func TestFolderStoreReservesMailTemplateFolderIdentity(t *testing.T) {
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	if err := fs.Create(t.Context(), "alice", "Other", FolderTypeMailTemplate, ""); err == nil {
		t.Fatal("created a mail-template folder outside its reserved path")
	}
	if err := fs.Create(t.Context(), "alice", FolderPathMailTemplate, FolderTypeMailTemplate, ""); err != nil {
		t.Fatal(err)
	}
	folder, err := fs.GetByPath(t.Context(), "alice", FolderPathMailTemplate)
	if err != nil || !folder.System || folder.SpecialUse != SpecialUseMailTemplate || folder.Subscribed {
		t.Fatalf("reserved folder=%+v err=%v", folder, err)
	}
}

func TestFolderStoreSetDefaultCalendarMovesUniqueRole(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := t.Context()
	if err := fs.CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Create(ctx, "alice", "Projects", FolderTypeCalendar, ""); err != nil {
		t.Fatal(err)
	}
	projects, _ := fs.GetByPath(ctx, "alice", "Projects")
	changed, err := fs.SetDefault(ctx, "alice", FolderTypeCalendar, projects.ID)
	if err != nil || len(changed) != 2 {
		t.Fatalf("changed=%#v error=%v", changed, err)
	}
	defaultCalendar, err := fs.SpecialFolder(ctx, "alice", SpecialUseCalendar)
	if err != nil || defaultCalendar.ID != projects.ID {
		t.Fatalf("default=%#v error=%v", defaultCalendar, err)
	}
	reopened := NewFolderStore(ts)
	persisted, err := reopened.SpecialFolder(ctx, "alice", SpecialUseCalendar)
	if err != nil || persisted.ID != projects.ID {
		t.Fatalf("persisted default=%#v error=%v", persisted, err)
	}
	original, _ := fs.GetByPath(ctx, "alice", "Calendar")
	if original.SpecialUse != "" || !original.System {
		t.Fatalf("original calendar=%#v", original)
	}
	if _, err := fs.SetDefault(ctx, "alice", FolderTypeMail, projects.ID); err == nil {
		t.Fatal("unsupported default folder type succeeded")
	}
}

func TestInboxFolderID(t *testing.T) {
	t.Parallel()
	id := InboxFolderID("alice")
	want := InboxFolderID("alice")
	if id != want {
		t.Errorf("InboxFolderID(%q) = %q, want %q", "alice", id, want)
	}
}

func TestSentFolderID(t *testing.T) {
	t.Parallel()
	id := SentFolderID("bob")
	want := SentFolderID("bob")
	if id != want {
		t.Errorf("SentFolderID(%q) = %q, want %q", "bob", id, want)
	}
}

func TestFolderKey(t *testing.T) {
	t.Parallel()
	id := FolderKey("alice", "INBOX/Work")
	want := "alice:INBOX/Work"
	if id != want {
		t.Errorf("FolderKey = %q, want %q", id, want)
	}
}
