package imap

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	vekselimap "github.com/lkarlslund/veksel/pkg/imap"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestSourceAgainstVekselIMAPServer(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@example.test\r\nTo: alice@example.test\r\nSubject: Migration\r\n\r\nbody")
	sourceItemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), raw, map[string]string{"Subject": "Migration"})
	if err != nil {
		t.Fatal(err)
	}
	server := vekselimap.New(&vekselimap.Config{
		ServerName: "migration.test", TypedStore: ts,
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	})
	listener, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	go server.Accept(ctx, listener)
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
	})

	source, err := Dial(Config{Address: listener.Addr().String(), Username: "alice", Password: "secret", TLSMode: TLSNone, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	folders, err := source.Folders(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var inboxFound bool
	for _, folder := range folders {
		if folder.ID != "INBOX" {
			continue
		}
		inboxFound = true
		page, err := collectPages(t, source, folder, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 1 || string(page.Items[0].Data) != string(raw) || !page.Done {
			t.Fatalf("page=%#v", page)
		}
		initialExternalID := page.Items[0].ID
		var initialState checkpoint
		if err := json.Unmarshal([]byte(page.Checkpoint), &initialState); err != nil {
			t.Fatal(err)
		}
		if err := ts.ItemStore().SetFlags(t.Context(), sourceItemID, []string{model.FlagSeen}); err != nil {
			t.Fatal(err)
		}
		newRaw := []byte("Subject: New after checkpoint\r\n\r\nnew body")
		newItemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), newRaw, map[string]string{"Subject": "New after checkpoint"})
		if err != nil {
			t.Fatal(err)
		}
		updatedSource, _ := ts.ItemStore().Get(t.Context(), sourceItemID)
		newSource, _ := ts.ItemStore().Get(t.Context(), newItemID)
		if updatedSource.ModSeq <= initialState.HighestModSeq || newSource.ModSeq <= initialState.HighestModSeq {
			t.Fatalf("source modseqs updated=%d new=%d checkpoint=%d", updatedSource.ModSeq, newSource.ModSeq, initialState.HighestModSeq)
		}
		changed, err := collectPages(t, source, folder, page.Checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		if len(changed.Items) != 2 || len(changed.DeletedIDs) != 0 || !changed.Done {
			t.Fatalf("changed page=%#v", changed)
		}
		changedByID := make(map[string]migration.Item, len(changed.Items))
		for _, item := range changed.Items {
			changedByID[item.ID] = item
		}
		if item, ok := changedByID[initialExternalID]; !ok || len(item.Flags) != 1 || item.Flags[0] != model.FlagSeen {
			t.Fatalf("changed initial item=%#v", item)
		}
		if err := ts.ItemStore().Delete(t.Context(), sourceItemID); err != nil {
			t.Fatal(err)
		}
		deleted, err := collectPages(t, source, folder, changed.Checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		if len(deleted.Items) != 0 || len(deleted.DeletedIDs) != 1 || deleted.DeletedIDs[0] != initialExternalID || !deleted.Done {
			t.Fatalf("deleted page=%#v", deleted)
		}
		unchanged, err := collectPages(t, source, folder, deleted.Checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		if len(unchanged.Items) != 0 || len(unchanged.DeletedIDs) != 0 || !unchanged.Done {
			t.Fatalf("unchanged page=%#v", unchanged)
		}
	}
	if !inboxFound {
		t.Fatalf("INBOX missing from %v", folders)
	}
}

func collectPages(t *testing.T, source *Source, folder migration.Folder, token string) (migration.Page, error) {
	t.Helper()
	result := migration.Page{}
	for pageNumber := 0; pageNumber < 100; pageNumber++ {
		page, err := source.Items(t.Context(), folder, token)
		if err != nil {
			return migration.Page{}, err
		}
		result.Items = append(result.Items, page.Items...)
		result.DeletedIDs = append(result.DeletedIDs, page.DeletedIDs...)
		result.Checkpoint = page.Checkpoint
		result.Done = page.Done
		if page.Done {
			return result, nil
		}
		if page.Checkpoint == token {
			t.Fatalf("page %d did not advance checkpoint", pageNumber+1)
		}
		token = page.Checkpoint
	}
	t.Fatalf("source did not complete after 100 pages")
	return migration.Page{}, nil
}

func TestUIDRangeCheckpointHelpers(t *testing.T) {
	ranges := compactUIDs([]uint32{9, 2, 3, 3, 4, 7, 10, 12})
	want := []uidRange{{Start: 2, End: 4}, {Start: 7, End: 7}, {Start: 9, End: 10}, {Start: 12, End: 12}}
	if fmt.Sprint(ranges) != fmt.Sprint(want) {
		t.Fatalf("compactUIDs = %#v, want %#v", ranges, want)
	}
	if got := uidRangePage(ranges, 3, 4); fmt.Sprint(got) != fmt.Sprint([]uint32{4, 7, 9, 10}) {
		t.Fatalf("uidRangePage = %v", got)
	}
	if !uidRangesHaveAfter(ranges, 10) || uidRangesHaveAfter(ranges, 12) {
		t.Fatalf("uidRangesHaveAfter boundary failed")
	}
	for _, test := range []struct {
		uid  uint32
		want bool
	}{{1, false}, {2, true}, {5, false}, {10, true}, {13, false}} {
		if got := uidInRanges(ranges, test.uid); got != test.want {
			t.Errorf("uidInRanges(%d) = %v, want %v", test.uid, got, test.want)
		}
	}
	if got := subtractUIDRanges(ranges, []uint32{2, 4, 7, 12}); fmt.Sprint(got) != fmt.Sprint([]uint32{3, 9, 10}) {
		t.Fatalf("subtractUIDRanges = %v", got)
	}
}
