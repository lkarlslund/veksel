package service

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestItemHistoryIsGenericBoundedAndAccounted(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")

	paths := []string{"INBOX", "Calendar", "Contacts", "Files"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			folder, err := space.GetFolderByPath(t.Context(), access, path)
			if err != nil {
				t.Fatal(err)
			}
			folder, err = space.ConfigureItemHistory(t.Context(), access, folder.ID, model.ItemHistoryPolicy{Enabled: true, RetentionDays: 3650, MaxVersions: 2})
			if err != nil {
				t.Fatal(err)
			}
			if !folder.History.Enabled || folder.HistoryUsageVersion != 1 {
				t.Fatalf("history policy/accounting = %+v/%d", folder.History, folder.HistoryUsageVersion)
			}
			item, err := space.CreateItem(t.Context(), access, folder.ID, ItemInput{Name: "entry-" + path, Data: []byte("v0")})
			if err != nil {
				t.Fatal(err)
			}
			for version := 1; version <= 3; version++ {
				item, err = space.UpdateItem(t.Context(), access, item.ID, []byte(fmt.Sprintf("v%d", version)), map[string]string{"Version": fmt.Sprint(version)})
				if err != nil {
					t.Fatal(err)
				}
			}
			versions, err := space.ListItemVersions(t.Context(), access, folder.ID, item.ID)
			if err != nil || len(versions) != 2 {
				t.Fatalf("versions = %+v, %v", versions, err)
			}
			if len(versions[0].Item.Data) != 0 || versions[0].Operation != model.ItemHistoryUpdate {
				t.Fatalf("list version = %+v", versions[0])
			}
			older, err := space.GetItemVersion(t.Context(), access, folder.ID, item.ID, versions[1].ID)
			if err != nil || string(older.Item.Data) != "v1" {
				t.Fatalf("older version = %q, %v", older.Item.Data, err)
			}
			restored, err := space.RestoreItemVersion(t.Context(), access, folder.ID, item.ID, older.ID)
			if err != nil || string(restored.Data) != "v1" || restored.ID != item.ID {
				t.Fatalf("restored = %+v, %v", restored, err)
			}
		})
	}

	usage, err := space.AccountUsage(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	if !usage.AccountingReady || usage.HistoryVersions != 8 || usage.HistoryLogicalBytes != 16 {
		t.Fatalf("history usage = %+v", usage)
	}
	user, err := ts.UserStore().Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.CurrentStorageBytes != usage.LogicalBytes {
		t.Fatalf("quota bytes=%d metadata bytes=%d", user.CurrentStorageBytes, usage.LogicalBytes)
	}
}

func TestItemHistoryDisabledDefaultsValidationAndRBAC(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	alice := UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), alice, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	item, err := space.CreateItem(t.Context(), alice, inbox.ID, ItemInput{Data: []byte("before")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.UpdateItem(t.Context(), alice, item.ID, []byte("after"), nil); err != nil {
		t.Fatal(err)
	}
	versions, err := space.ListItemVersions(t.Context(), alice, inbox.ID, item.ID)
	if err != nil || len(versions) != 0 {
		t.Fatalf("disabled versions = %+v, %v", versions, err)
	}
	configured, err := space.ConfigureItemHistory(t.Context(), alice, inbox.ID, model.ItemHistoryPolicy{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if configured.History.RetentionDays != DefaultItemHistoryRetentionDays || configured.History.MaxVersions != DefaultItemHistoryMaxVersions {
		t.Fatalf("default policy = %+v", configured.History)
	}
	if _, err := space.ConfigureItemHistory(t.Context(), alice, inbox.ID, model.ItemHistoryPolicy{Enabled: true, MaxVersions: MaxItemHistoryVersions + 1}); err == nil {
		t.Fatal("oversized history policy succeeded")
	}
	bob := UserAccess("bob", "test")
	if _, err := space.GetItemHistoryPolicy(t.Context(), bob, inbox.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-account policy read error = %v", err)
	}
	if _, err := space.ListItemVersions(t.Context(), bob, inbox.ID, item.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-account version list error = %v", err)
	}
}

func TestItemHistoryRestoresDeletedItemAndRejectsMovedLiveItem(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	archive, _ := space.GetFolderByPath(t.Context(), access, "Archive")
	if _, err := space.ConfigureItemHistory(t.Context(), access, inbox.ID, model.ItemHistoryPolicy{Enabled: true, MaxVersions: 10}); err != nil {
		t.Fatal(err)
	}

	deleted, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Name: "deleted", Data: []byte("old")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.UpdateItem(t.Context(), access, deleted.ID, []byte("new"), nil); err != nil {
		t.Fatal(err)
	}
	versions, err := space.ListItemVersions(t.Context(), access, inbox.ID, deleted.ID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("pre-delete versions = %+v, %v", versions, err)
	}
	oldVersionID := versions[0].ID
	if err := space.DeleteItem(t.Context(), access, deleted.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := space.GetItem(t.Context(), access, deleted.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted item read error = %v", err)
	}
	recreated, err := space.RestoreItemVersion(t.Context(), access, inbox.ID, deleted.ID, oldVersionID)
	if err != nil || recreated.ID == deleted.ID || string(recreated.Data) != "old" || recreated.FolderID != inbox.ID {
		t.Fatalf("recreated = %+v, %v", recreated, err)
	}

	moved, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Name: "moved", Data: []byte("source")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.MoveItem(t.Context(), access, moved.ID, archive.ID, ""); err != nil {
		t.Fatal(err)
	}
	moveVersions, err := space.ListItemVersions(t.Context(), access, inbox.ID, moved.ID)
	if err != nil || len(moveVersions) != 1 || moveVersions[0].Operation != model.ItemHistoryMove {
		t.Fatalf("move versions = %+v, %v", moveVersions, err)
	}
	if _, err := space.RestoreItemVersion(t.Context(), access, inbox.ID, moved.ID, moveVersions[0].ID); !errors.Is(err, model.ErrItemHistoryConflict) {
		t.Fatalf("moved restore error = %v", err)
	}
}

func TestItemHistoryAgePruneReleasesQuota(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	if _, err := space.ConfigureItemHistory(t.Context(), access, inbox.ID, model.ItemHistoryPolicy{Enabled: true, RetentionDays: 1}); err != nil {
		t.Fatal(err)
	}
	item, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("old")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.UpdateItem(t.Context(), access, item.ID, []byte("new"), nil); err != nil {
		t.Fatal(err)
	}
	before, _ := ts.UserStore().Get(t.Context(), "alice")
	removed, err := space.PruneItemHistory(t.Context(), time.Now().UTC().Add(48*time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("prune = %d, %v", removed, err)
	}
	after, _ := ts.UserStore().Get(t.Context(), "alice")
	if before.CurrentStorageBytes-after.CurrentStorageBytes != int64(len("old")) {
		t.Fatalf("quota before=%d after=%d", before.CurrentStorageBytes, after.CurrentStorageBytes)
	}
	folder, _ := space.GetFolder(t.Context(), access, inbox.ID)
	if folder.HistoryVersionCount != 0 || folder.HistoryLogicalBytes != 0 {
		t.Fatalf("pruned folder accounting = %+v", folder)
	}
}

func TestItemHistoryQuotaFailureRollsBackMutationAndSnapshot(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	if _, err := space.ConfigureItemHistory(t.Context(), access, inbox.ID, model.ItemHistoryPolicy{Enabled: true, MaxVersions: 10}); err != nil {
		t.Fatal(err)
	}
	item, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("old")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().UpdateQuota(t.Context(), "alice", item.Size, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := space.UpdateItem(t.Context(), access, item.ID, []byte("new"), nil); !errors.Is(err, model.ErrQuotaExceeded) {
		t.Fatalf("update error = %v", err)
	}
	current, err := space.GetItem(t.Context(), access, item.ID)
	if err != nil || string(current.Data) != "old" {
		t.Fatalf("current item = %q, %v", current.Data, err)
	}
	versions, err := space.ListItemVersions(t.Context(), access, inbox.ID, item.ID)
	if err != nil || len(versions) != 0 {
		t.Fatalf("versions after rollback = %+v, %v", versions, err)
	}
	owner, err := ts.UserStore().Get(t.Context(), "alice")
	if err != nil || owner.CurrentStorageBytes != item.Size {
		t.Fatalf("owner usage = %+v, %v", owner, err)
	}
	folder, err := space.GetFolder(t.Context(), access, inbox.ID)
	if err != nil || folder.HistoryVersionCount != 0 || folder.HistoryLogicalBytes != 0 {
		t.Fatalf("folder history usage = %+v, %v", folder, err)
	}
}
