package ews

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	vekselews "github.com/lkarlslund/veksel/pkg/ews"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestSourceAgainstVekselEWSServer(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
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
	raw := []byte("From: sender@example.test\r\nTo: alice@example.test\r\nSubject: EWS migration\r\n\r\nbody")
	sourceItemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), raw, map[string]string{"Subject": "EWS migration"})
	if err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(ts, authz.New(ts))
	handler, err := vekselews.New(vekselews.Config{
		Space: space,
		Authenticate: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", context.Canceled
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", Password: "secret", HTTPClient: server.Client(), PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	folders, err := source.Folders(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var inbox migration.Folder
	for _, folder := range folders {
		if folder.Name == "INBOX" {
			inbox = folder
		}
	}
	if inbox.ID == "" {
		t.Fatalf("INBOX missing from %#v", folders)
	}
	if !inbox.EstimateKnown || inbox.Estimate != 1 {
		t.Fatalf("INBOX inventory = %#v", inbox)
	}
	page, err := source.Items(t.Context(), inbox, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || string(page.Items[0].Data) != string(raw) || !page.Done {
		t.Fatalf("page=%#v", page)
	}
	sourceExternalID := page.Items[0].ID
	unchanged, err := source.Items(t.Context(), inbox, page.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(unchanged.Items) != 0 || !unchanged.Done {
		t.Fatalf("unchanged page=%#v", unchanged)
	}
	newRaw := []byte("Subject: A newly arrived message\r\n\r\nnew message")
	if _, err := space.CreateItem(t.Context(), service.UserAccess("alice", "test"), model.InboxFolderID("alice"), service.ItemInput{Data: newRaw, Headers: map[string]string{"Subject": "A newly arrived message"}}); err != nil {
		t.Fatal(err)
	}
	newItems, err := source.Items(t.Context(), inbox, unchanged.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(newItems.Items) != 1 || string(newItems.Items[0].Data) != string(newRaw) || !newItems.Done {
		t.Fatalf("new-items page=%#v", newItems)
	}
	updatedRaw := []byte("Subject: EWS migration updated\r\n\r\nnew body")
	if _, err := space.UpdateItem(t.Context(), service.UserAccess("alice", "test"), sourceItemID, updatedRaw, map[string]string{"Subject": "EWS migration updated"}); err != nil {
		t.Fatal(err)
	}
	updated, err := source.Items(t.Context(), inbox, newItems.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Items) != 1 || string(updated.Items[0].Data) != string(updatedRaw) || !updated.Done {
		t.Fatalf("updated page=%#v", updated)
	}
	if err := space.DeleteItem(t.Context(), service.UserAccess("alice", "test"), sourceItemID); err != nil {
		t.Fatal(err)
	}
	deleted, err := source.Items(t.Context(), inbox, updated.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted.DeletedIDs) != 1 || deleted.DeletedIDs[0] != sourceExternalID || !deleted.Done {
		t.Fatalf("deleted page=%#v", deleted)
	}
}
