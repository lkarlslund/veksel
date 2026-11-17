package service

import (
	"context"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func testRecipientHistory(t *testing.T) (*RecipientHistory, FolderSpace, *model.TypedStore) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{
		model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems,
		model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes,
	} {
		if err := ts.EnsureNamespace(context.Background(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	space := NewFolderSpace(ts, authz.New(ts))
	return NewRecipientHistory(space), space, ts
}

func TestRecipientHistoryCreatesAndUpdatesDeduplicatedContact(t *testing.T) {
	history, space, _ := testRecipientHistory(t)
	first := time.Date(2026, 8, 17, 8, 0, 0, 0, time.UTC)
	history.now = func() time.Time { return first }
	if err := history.Record(t.Context(), "alice", []string{
		"Ada Lovelace <ADA@example.test>, Bob <bob@example.test>",
		"ada@example.test",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	access := UserAccess("alice", "test")
	folder, err := space.GetFolderByPath(t.Context(), access, "Recent recipients")
	if err != nil {
		t.Fatal(err)
	}
	if folder.Type != model.FolderTypeContacts || folder.Subscribed || folder.ItemCount != 2 {
		t.Fatalf("recent folder = %#v", folder)
	}
	ada, err := space.GetItemByExternalID(t.Context(), access, folder.ID, recipientHistoryNamespace, "ada@example.test")
	if err != nil {
		t.Fatal(err)
	}
	contact := model.ParseVCard(ada.Data)
	if contact.FN != "Ada Lovelace" || len(contact.Emails) != 1 || contact.Emails[0] != "ada@example.test" {
		t.Fatalf("created contact = %#v", contact)
	}
	if ada.Headers["Use-Count"] != "1" || ada.Headers["Last-Used"] != first.Format(time.RFC3339Nano) {
		t.Fatalf("created headers = %#v", ada.Headers)
	}

	second := first.Add(time.Hour)
	history.now = func() time.Time { return second }
	if err := history.Record(t.Context(), "alice", []string{"Augusta Ada <Ada@Example.Test>"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	ada, err = space.GetItemByExternalID(t.Context(), access, folder.ID, recipientHistoryNamespace, "ada@example.test")
	if err != nil {
		t.Fatal(err)
	}
	contact = model.ParseVCard(ada.Data)
	if contact.FN != "Augusta Ada" || ada.Headers["Use-Count"] != "2" || ada.Headers["Last-Used"] != second.Format(time.RFC3339Nano) {
		t.Fatalf("updated contact=%#v headers=%#v", contact, ada.Headers)
	}
	folder, err = space.GetFolder(t.Context(), access, folder.ID)
	if err != nil {
		t.Fatal(err)
	}
	if folder.ItemCount != 2 {
		t.Fatalf("folder count after update = %d, want 2", folder.ItemCount)
	}
}

func TestRecipientHistoryIgnoresWhollyInvalidAddressLists(t *testing.T) {
	history, space, _ := testRecipientHistory(t)
	if err := history.Record(t.Context(), "alice", []string{"not <valid", ""}); err != nil {
		t.Fatal(err)
	}
	folder, err := space.GetFolderByPath(t.Context(), UserAccess("alice", "test"), "Recent recipients")
	if err != nil {
		t.Fatal(err)
	}
	if folder.ItemCount != 0 {
		t.Fatalf("folder count = %d, want 0", folder.ItemCount)
	}
}
