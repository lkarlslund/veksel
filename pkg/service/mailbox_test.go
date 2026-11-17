package service

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestFolderSpaceCreateItemsRollsBackWholeBatchOnStorageFailure(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	faults := faultstore.New(backend)
	typed := model.NewTypedStore(faults, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(context.Background(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	space := NewFolderSpace(typed, authz.New(typed))
	access := UserAccess("alice", "contact-import-test")
	contacts, err := space.GetFolderByPath(t.Context(), access, "Contacts")
	if err != nil {
		t.Fatal(err)
	}
	faults.Fail("set", 3)
	if _, err := space.CreateItems(t.Context(), access, contacts.ID, []ItemInput{{Data: []byte("one")}, {Data: []byte("two")}}); !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("batch failure = %v", err)
	}
	items, err := space.ListItems(t.Context(), access, contacts.ID, ItemQuery{})
	if err != nil || len(items) != 0 {
		t.Fatalf("failed batch retained items=%+v err=%v", items, err)
	}
	usage, err := space.AccountUsage(t.Context(), access)
	if err != nil || usage.Items != 0 || usage.LogicalBytes != 0 {
		t.Fatalf("failed batch retained quota usage=%+v err=%v", usage, err)
	}
}

func TestFolderSpaceGetItemByUIDUsesIndexAndHonorsAuthorization(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	alice := UserAccess("alice", "uid-test")
	inbox, err := space.GetFolderByPath(t.Context(), alice, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := space.CreateItem(t.Context(), alice, inbox.ID, ItemInput{Data: []byte("Subject: indexed\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	indexed, err := space.GetItemByUID(t.Context(), alice, inbox.ID, created.UID)
	if err != nil || indexed.ID != created.ID || !bytes.Equal(indexed.Data, created.Data) {
		t.Fatalf("indexed item=%#v err=%v", indexed, err)
	}
	if _, err := space.GetItemByUID(t.Context(), UserAccess("bob", "uid-test"), inbox.ID, created.UID); err == nil {
		t.Fatal("cross-account UID read succeeded without delegation")
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: inbox.ID},
		Effect:    model.EffectAllow, Permissions: []string{string(authz.FolderDiscover), string(authz.FolderItemsList)},
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := space.GetItemByUID(t.Context(), UserAccess("bob", "uid-test"), inbox.ID, created.UID); err == nil {
		t.Fatal("UID read succeeded with list permission but no item-read permission")
	}
}

func BenchmarkFolderSpaceGetItemByUID(b *testing.B) {
	_, ts, _ := testMailService(b)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "uid-benchmark")
	inbox, err := space.GetFolderByPath(b.Context(), access, "INBOX")
	if err != nil {
		b.Fatal(err)
	}
	var target uint32
	for index := range 1_000 {
		created, createErr := space.CreateItem(b.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: benchmark\r\n\r\nbody")})
		if createErr != nil {
			b.Fatal(createErr)
		}
		if index == 500 {
			target = created.UID
		}
	}
	b.ResetTimer()
	b.Run("indexed", func(b *testing.B) {
		for b.Loop() {
			if _, err := space.GetItemByUID(b.Context(), access, inbox.ID, target); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("full-folder-scan", func(b *testing.B) {
		for b.Loop() {
			items, err := space.ListItems(b.Context(), access, inbox.ID, ItemQuery{})
			if err != nil {
				b.Fatal(err)
			}
			for _, item := range items {
				if item.UID == target {
					break
				}
			}
		}
	})
}

func TestFolderSpaceUsesAuthorizedWorkspace(t *testing.T) {
	_, ts, _ := testMailService(t)
	ctx := t.Context()
	space := NewFolderSpace(ts, authz.New(ts))
	alice := UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(ctx, alice, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := space.CreateItem(ctx, alice, inbox.ID, ItemInput{Data: []byte("Subject: hello\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := space.GetItem(ctx, alice, created.ID); err != nil || string(got.Data) == "" {
		t.Fatalf("GetItem() = (%q, %v)", got.Data, err)
	}

	bob := UserAccess("bob", "test")
	if _, err := space.GetItem(ctx, bob, created.ID); err == nil {
		t.Fatal("cross-account read succeeded without delegation")
	}
}

func TestFolderSpaceMetadataOnlyListOmitsPayload(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{
		Data: []byte("Subject: metadata\r\n\r\nbody"), Headers: map[string]string{"Subject": "metadata"},
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := space.ListItems(t.Context(), access, inbox.ID, ItemQuery{MetadataOnly: true})
	if err != nil || len(metadata) != 1 {
		t.Fatalf("metadata list = %+v, %v", metadata, err)
	}
	if metadata[0].ID != created.ID || len(metadata[0].Data) != 0 || metadata[0].Size != created.Size {
		t.Fatalf("metadata item = %+v", metadata[0])
	}
	full, err := space.ListItems(t.Context(), access, inbox.ID, ItemQuery{})
	if err != nil || len(full) != 1 || string(full[0].Data) != string(created.Data) {
		t.Fatalf("full list = %+v, %v", full, err)
	}
}

func TestFolderSpaceExternalIdentityIndexLifecycle(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "sync-test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := space.GetFolderByPath(t.Context(), access, "Archive")
	if err != nil {
		t.Fatal(err)
	}
	identity := map[string]string{"imap://source/alice": "uid-42"}
	created, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("message"), ExternalIDs: identity})
	if err != nil {
		t.Fatal(err)
	}
	indexed, err := space.GetItemByExternalID(t.Context(), access, inbox.ID, "imap://source/alice", "uid-42")
	if err != nil || indexed.ID != created.ID {
		t.Fatalf("indexed item=%#v err=%v", indexed, err)
	}
	if _, err := space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("duplicate"), ExternalIDs: identity}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate external identity err=%v", err)
	}
	moved, err := space.MoveItem(t.Context(), access, created.ID, archive.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.GetItemByExternalID(t.Context(), access, inbox.ID, "imap://source/alice", "uid-42"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old folder index err=%v", err)
	}
	if indexed, err = space.GetItemByExternalID(t.Context(), access, archive.ID, "imap://source/alice", "uid-42"); err != nil || indexed.ID != moved.ID {
		t.Fatalf("moved indexed item=%#v err=%v", indexed, err)
	}
	if err := space.DeleteItem(t.Context(), access, moved.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := space.GetItemByExternalID(t.Context(), access, archive.ID, "imap://source/alice", "uid-42"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted item index err=%v", err)
	}
}

func TestAccessContextRequiresPrincipals(t *testing.T) {
	if err := (AccessContext{}).Validate(); err == nil {
		t.Fatal("empty access context accepted")
	}
}
