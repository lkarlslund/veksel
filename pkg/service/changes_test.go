package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/dek"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/cryptstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

type changeScanCountingStore struct {
	store.Store
	scans int
}

func (s *changeScanCountingStore) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	s.scans++
	return s.Store.Scan(ctx, namespace, prefix)
}

func (s *changeScanCountingStore) Batch(ctx context.Context, fn func(context.Context) error) error {
	return s.Store.(store.Batcher).Batch(ctx, fn)
}

func TestFolderSpaceRecordsIncrementalItemLifecycle(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := space.GetFolderByPath(t.Context(), access, "Archive")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := space.CurrentChangeState(t.Context(), access, ChangeScope{Object: ChangeObjectItem})
	if err != nil {
		t.Fatal(err)
	}
	created, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: journal\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := space.SetFlags(t.Context(), access, created.ID, []string{model.FlagSeen})
	if err != nil {
		t.Fatal(err)
	}
	moved, err := space.MoveItem(t.Context(), access, created.ID, archive.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := space.DeleteItem(t.Context(), access, moved.ID); err != nil {
		t.Fatal(err)
	}
	page, err := space.ListChanges(t.Context(), access, ChangeScope{Object: ChangeObjectItem}, initial, 100)
	if err != nil {
		t.Fatal(err)
	}
	if page.HasMoreChanges || len(page.Records) != 4 || page.NewState != page.CurrentState {
		t.Fatalf("unexpected page: %+v", page)
	}
	want := []ChangeOperation{ChangeCreate, ChangeUpdate, ChangeMove, ChangeDestroy}
	for index, record := range page.Records {
		if len(record.Changes) != 1 || record.Changes[0].Operation != want[index] || record.Changes[0].ID != created.ID {
			t.Fatalf("record[%d] = %+v", index, record)
		}
	}
	if page.Records[1].Changes[0].ModSeq != updated.ModSeq || page.Records[2].Changes[0].PreviousFolderID != inbox.ID {
		t.Fatalf("update/move metadata missing: %+v", page.Records)
	}
}

func TestTrashChangeRetainsSourceMailboxIdentity(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: trash journal\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	state, err := space.CurrentChangeState(t.Context(), access, ChangeScope{FolderID: inbox.ID, Object: ChangeObjectItem})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.TrashItem(t.Context(), access, created.ID); err != nil {
		t.Fatal(err)
	}
	page, err := space.ListChanges(t.Context(), access, ChangeScope{FolderID: inbox.ID, Object: ChangeObjectItem}, state, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || len(page.Records[0].Changes) != 1 {
		t.Fatalf("trash changes=%+v", page)
	}
	change := page.Records[0].Changes[0]
	if change.Operation != ChangeTrash || change.PreviousFolderID != inbox.ID || change.PreviousUID != created.UID || change.PreviousModSeq <= created.ModSeq {
		t.Fatalf("trash source identity=%+v created=%+v", change, created)
	}
}

func TestFolderTreeMutationsPublishEveryDescendantAtomically(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")
	parent, err := space.CreateFolder(t.Context(), access, "Projects", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := space.CreateFolder(t.Context(), access, "Current", model.FolderTypeMail, parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := space.CurrentChangeState(t.Context(), access, ChangeScope{Object: ChangeObjectFolder})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := space.MoveFolder(t.Context(), access, parent.ID, "", "Renamed"); err != nil {
		t.Fatal(err)
	}
	state = assertFolderTreeChange(t, space, access, state, ChangeMove, parent.ID, child.ID)
	if err := space.DeleteFolder(t.Context(), access, parent.ID); err != nil {
		t.Fatal(err)
	}
	state = assertFolderTreeChange(t, space, access, state, ChangeTrash, parent.ID, child.ID)
	if _, err := space.RestoreFolder(t.Context(), access, parent.ID); err != nil {
		t.Fatal(err)
	}
	assertFolderTreeChange(t, space, access, state, ChangeRestore, parent.ID, child.ID)
	if restored, err := space.GetFolderByPath(t.Context(), access, "Renamed/Current"); err != nil || restored.ID != child.ID {
		t.Fatalf("restored child = %+v, %v", restored, err)
	}
}

func assertFolderTreeChange(t *testing.T, space *FolderSpaceService, access AccessContext, state string, operation ChangeOperation, ids ...string) string {
	t.Helper()
	page, err := space.ListChanges(t.Context(), access, ChangeScope{Object: ChangeObjectFolder}, state, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || len(page.Records[0].Changes) != len(ids) {
		t.Fatalf("%s tree change = %+v", operation, page)
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	for _, change := range page.Records[0].Changes {
		if change.Operation != operation || !want[change.ID] {
			t.Fatalf("unexpected %s change: %+v", operation, change)
		}
		delete(want, change.ID)
	}
	if len(want) != 0 {
		t.Fatalf("%s omitted folder IDs: %v", operation, want)
	}
	return page.NewState
}

func TestChangePaginationNeverSplitsMutation(t *testing.T) {
	_, ts, _ := testMailService(t)
	changes := NewChangeStore(ts)
	if err := changes.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.Batch(t.Context(), ts.Store(), func(ctx context.Context) error {
		_, err := changes.Record(ctx, []Change{{Object: ChangeObjectItem, Operation: ChangeMove, ID: "item", PreviousFolderID: "a", FolderID: "b"}, {Object: ChangeObjectItem, Operation: ChangeCreate, ID: "copy", FolderID: "b"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	page, err := changes.List(t.Context(), ChangeScope{}, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || len(page.Records[0].Changes) != 2 {
		t.Fatalf("mutation was split: %+v", page)
	}
}

func TestChangeListAtCurrentStateDoesNotScanJournal(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	counted := &changeScanCountingStore{Store: backend}
	ts := model.NewTypedStore(counted, store.BackendJSON)
	changes := NewChangeStore(ts)
	if err := changes.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := changes.Record(t.Context(), []Change{{Object: ChangeObjectItem, Operation: ChangeCreate, ID: "item", FolderID: "inbox"}}); err != nil {
		t.Fatal(err)
	}
	current, err := changes.CurrentState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	counted.scans = 0
	page, err := changes.List(t.Context(), ChangeScope{Object: ChangeObjectItem}, current, 100)
	if err != nil {
		t.Fatal(err)
	}
	if counted.scans != 0 {
		t.Fatalf("current-state poll scanned the journal %d time(s)", counted.scans)
	}
	if len(page.Records) != 0 || page.OldState != current || page.NewState != current || page.CurrentState != current || page.HasMoreChanges {
		t.Fatalf("current-state page = %+v", page)
	}
}

func TestChangeRetentionExpiresOldState(t *testing.T) {
	_, ts, _ := testMailService(t)
	changes := NewChangeStore(ts)
	changes.SetRetention(1, 1)
	if err := changes.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		if err := store.Batch(t.Context(), ts.Store(), func(ctx context.Context) error {
			_, err := changes.Record(ctx, []Change{{Object: ChangeObjectItem, Operation: ChangeCreate, ID: string(rune('a' + index)), FolderID: "inbox"}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if removed, err := changes.Prune(t.Context(), time.Now().UTC()); err != nil || removed != 1 {
		t.Fatalf("Prune = %d, %v", removed, err)
	}
	if _, err := changes.List(t.Context(), ChangeScope{}, "c1.0", 10); !errors.Is(err, ErrChangeStateExpired) {
		t.Fatalf("old state error = %v", err)
	}
	page, err := changes.List(t.Context(), ChangeScope{}, "c1.1", 10)
	if err != nil || len(page.Records) != 1 || page.Records[0].Sequence != 2 {
		t.Fatalf("retained page = %+v, %v", page, err)
	}
}

// changeJournalEngines opens every engine the change journal runs on: the
// production engines, the encrypted decorator over each, and the JSON test
// engine. Reopening a path yields the same journal.
func changeJournalEngines(t testing.TB) []struct {
	name string
	open func(string) (store.Store, error)
} {
	raw, err := dek.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := dek.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := func(open func(string) (store.Store, error)) func(string) (store.Store, error) {
		return func(path string) (store.Store, error) {
			inner, err := open(path)
			if err != nil {
				return nil, err
			}
			return cryptstore.New(inner, key, model.ProtectedKeyFamilies())
		}
	}
	pebble := func(path string) (store.Store, error) { return pebblestore.New(path) }
	badger := func(path string) (store.Store, error) { return badgerstore.New(path) }
	return []struct {
		name string
		open func(string) (store.Store, error)
	}{
		{name: "pebble", open: pebble},
		{name: "badger", open: badger},
		{name: "encrypted-pebble", open: encrypted(pebble)},
		{name: "encrypted-badger", open: encrypted(badger)},
		{name: "json", open: func(path string) (store.Store, error) { return jsonstore.New(path) }},
	}
}

func TestChangeJournalPagingPruningResetAndRestartAcrossProductionBackends(t *testing.T) {
	for _, tc := range changeJournalEngines(t) {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal")
			backend, err := tc.open(path)
			if err != nil {
				t.Fatal(err)
			}
			ts := model.NewTypedStore(backend, store.Backend(tc.name))
			changes := NewChangeStore(ts)
			changes.SetRetention(3650, 5)
			if err := changes.Ensure(t.Context()); err != nil {
				t.Fatal(err)
			}
			for sequence := 1; sequence <= 12; sequence++ {
				if err := store.Batch(t.Context(), backend, func(ctx context.Context) error {
					_, recordErr := changes.Record(ctx, []Change{{Object: ChangeObjectItem, Operation: ChangeCreate, ID: fmt.Sprintf("item-%02d", sequence), FolderID: "inbox"}})
					return recordErr
				}); err != nil {
					t.Fatal(err)
				}
			}
			first, err := changes.List(t.Context(), ChangeScope{Object: ChangeObjectItem}, "", 3)
			if err != nil || len(first.Records) != 3 || first.NewState != "c1.3" || !first.HasMoreChanges {
				t.Fatalf("first page = %+v, %v", first, err)
			}
			if err := backend.Close(); err != nil {
				t.Fatal(err)
			}

			backend, err = tc.open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = backend.Close() }()
			ts = model.NewTypedStore(backend, store.Backend(tc.name))
			changes = NewChangeStore(ts)
			changes.SetRetention(3650, 5)
			removed, err := changes.Prune(t.Context(), time.Now().UTC())
			if err != nil || removed != 7 {
				t.Fatalf("Prune = %d, %v", removed, err)
			}
			if _, err := changes.List(t.Context(), ChangeScope{}, first.NewState, 2); !errors.Is(err, ErrChangeStateExpired) {
				t.Fatalf("pre-prune cursor error = %v", err)
			}

			cursor := "c1.7"
			var got []string
			for {
				page, err := changes.List(t.Context(), ChangeScope{FolderID: "inbox", Object: ChangeObjectItem}, cursor, 2)
				if err != nil {
					t.Fatal(err)
				}
				for _, record := range page.Records {
					got = append(got, record.Changes[0].ID)
				}
				cursor = page.NewState
				if !page.HasMoreChanges {
					break
				}
			}
			want := []string{"item-08", "item-09", "item-10", "item-11", "item-12"}
			if fmt.Sprint(got) != fmt.Sprint(want) || cursor != "c1.c" {
				t.Fatalf("retained stream = %v at %q, want %v at c1.c", got, cursor, want)
			}
			reset, err := changes.CurrentState(t.Context())
			if err != nil || reset != "c1.c" {
				t.Fatalf("reset state = %q, %v", reset, err)
			}
			if err := store.Batch(t.Context(), backend, func(ctx context.Context) error {
				_, recordErr := changes.Record(ctx, []Change{{Object: ChangeObjectItem, Operation: ChangeCreate, ID: "after-reset", FolderID: "inbox"}})
				return recordErr
			}); err != nil {
				t.Fatal(err)
			}
			page, err := changes.List(t.Context(), ChangeScope{Object: ChangeObjectItem}, reset, 10)
			if err != nil || len(page.Records) != 1 || page.Records[0].Changes[0].ID != "after-reset" || page.OldState != reset || page.NewState != "c1.d" {
				t.Fatalf("post-reset page = %+v, %v", page, err)
			}
		})
	}
}
