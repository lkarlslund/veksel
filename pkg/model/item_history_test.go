package model

import (
	"bytes"
	"testing"

	"github.com/lkarlslund/veksel/pkg/objectstore"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func TestItemHistoryReusesImmutableObjectPayload(t *testing.T) {
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
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	inbox, err := ts.FolderStore().Get(t.Context(), InboxFolderID("alice"))
	if err != nil {
		t.Fatal(err)
	}
	inbox.History = ItemHistoryPolicy{Enabled: true, RetentionDays: 30, MaxVersions: 5}
	if err := ts.FolderStore().Update(t.Context(), inbox.ID, func(folder *Folder) { folder.History = inbox.History }); err != nil {
		t.Fatal(err)
	}
	payload := []byte("Subject: retained\r\n\r\nimmutable body")
	item, err := ts.ItemStore().AppendItem(t.Context(), inbox.ID, Item{Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	recordsBefore, err := objects.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	version, captured, err := ts.ItemHistoryStore().Capture(t.Context(), item, ItemHistoryUpdate)
	if err != nil || !captured {
		t.Fatalf("Capture = %+v, %t, %v", version, captured, err)
	}
	recordsAfter, err := objects.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(recordsAfter) != len(recordsBefore) {
		t.Fatalf("history duplicated object payload: before=%d after=%d", len(recordsBefore), len(recordsAfter))
	}
	var current storedItem
	if err := ts.Get(t.Context(), NSItems, item.ID, &current); err != nil {
		t.Fatal(err)
	}
	var stored storedItemVersion
	if err := ts.Get(t.Context(), NSItemHistory, historyVersionKey(version.ID), &stored); err != nil {
		t.Fatal(err)
	}
	if current.Payload == nil || stored.Payload == nil || *current.Payload != *stored.Payload {
		t.Fatalf("current ref=%+v history ref=%+v", current.Payload, stored.Payload)
	}
	if err := ts.ItemStore().Delete(t.Context(), item.ID); err != nil {
		t.Fatal(err)
	}
	got, err := ts.ItemHistoryStore().Get(t.Context(), inbox.ID, item.ID, version.ID)
	if err != nil || !bytes.Equal(got.Item.Data, payload) {
		t.Fatalf("Get after item deletion = %q, %v", got.Item.Data, err)
	}
}
