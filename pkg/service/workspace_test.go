package service

import (
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestWorkspaceFiltersFoldersAndAuthorizesItemBodies(t *testing.T) {
	_, ts, _ := testMailService(t)
	engine := authz.New(ts)
	workspace := NewWorkspace(ts, engine)
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte("private body"), map[string]string{"Subject": "Shared"})
	if err != nil {
		t.Fatalf("append item: %v", err)
	}

	folders, err := workspace.ListFolders(t.Context(), actor, actor, authz.ActingNone)
	if err != nil {
		t.Fatalf("list initial folders: %v", err)
	}
	if containsFolder(folders, model.InboxFolderID("alice")) {
		t.Fatal("Alice folder was visible before a grant")
	}
	if _, err := workspace.GetItem(t.Context(), actor, actor, authz.ActingNone, itemID); err == nil {
		t.Fatal("Alice item body was readable before a grant")
	}
	listOnly, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: actor, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: model.InboxFolderID("alice")},
		Effect: model.EffectAllow, Permissions: []string{string(authz.FolderItemsList)},
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	if err != nil {
		t.Fatalf("create list-only grant: %v", err)
	}
	if _, err := workspace.ListFullItemPage(t.Context(), actor, actor, authz.ActingNone, model.InboxFolderID("alice"), 0, 20); err == nil {
		t.Fatal("list-only grant exposed item bodies through full-item paging")
	}
	if err := model.NewPolicyStore(ts).Delete(t.Context(), listOnly.ID); err != nil {
		t.Fatalf("delete list-only grant: %v", err)
	}
	_, err = model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: actor, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: model.InboxFolderID("alice")},
		Effect: model.EffectAllow, RoleID: authz.RoleFolderViewer,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	if err != nil {
		t.Fatalf("create folder grant: %v", err)
	}
	folders, err = workspace.ListFolders(t.Context(), actor, actor, authz.ActingNone)
	if err != nil || !containsFolder(folders, model.InboxFolderID("alice")) {
		t.Fatalf("shared folder missing: folders=%v err=%v", folders, err)
	}
	items, err := workspace.ListItems(t.Context(), actor, actor, authz.ActingNone, model.InboxFolderID("alice"))
	if err != nil || len(items) != 1 || items[0].ID != itemID {
		t.Fatalf("shared items=%v err=%v", items, err)
	}
	item, err := workspace.GetItem(t.Context(), actor, actor, authz.ActingNone, itemID)
	if err != nil || string(item.Data) != "private body" {
		t.Fatalf("shared item=%v err=%v", item, err)
	}
}

func TestWorkspaceDelegationUsesSubjectOwnership(t *testing.T) {
	_, ts, _ := testMailService(t)
	workspace := NewWorkspace(ts, authz.New(ts))
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	subject := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	_, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: actor, Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"},
		Effect: model.EffectAllow, RoleID: authz.RoleAccountDelegate,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	if err != nil {
		t.Fatalf("create delegation: %v", err)
	}
	folders, err := workspace.ListFolders(t.Context(), actor, subject, authz.ActingDelegation)
	if err != nil {
		t.Fatalf("list delegated folders: %v", err)
	}
	if !containsFolder(folders, model.InboxFolderID("alice")) || containsFolder(folders, model.InboxFolderID("bob")) {
		t.Fatalf("unexpected delegated folders: %v", folders)
	}
}

func TestWorkspaceMutationsEnforceFolderRights(t *testing.T) {
	_, ts, _ := testMailService(t)
	workspace := NewWorkspace(ts, authz.New(ts))
	alice := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	folderID := model.FolderKey("alice", "Contacts")

	itemID, err := workspace.CreateItem(t.Context(), alice, alice, authz.ActingNone, folderID, []byte("one"), nil)
	if err != nil {
		t.Fatalf("owner create: %v", err)
	}
	if _, err := workspace.CreateItem(t.Context(), alice, alice, authz.ActingNone, folderID, []byte("newer item"), nil); err != nil {
		t.Fatalf("owner create newer item: %v", err)
	}
	beforeUpdate, err := ts.FolderStore().Get(t.Context(), folderID)
	if err != nil {
		t.Fatalf("folder before update: %v", err)
	}
	if _, err := workspace.CreateItem(t.Context(), bob, bob, authz.ActingNone, folderID, []byte("forbidden"), nil); err == nil {
		t.Fatal("unprivileged create succeeded")
	}
	if _, err := workspace.UpdateItem(t.Context(), bob, bob, authz.ActingNone, itemID, []byte("forbidden"), nil); err == nil {
		t.Fatal("unprivileged update succeeded")
	}
	updated, err := workspace.UpdateItem(t.Context(), alice, alice, authz.ActingNone, itemID, []byte("two"), map[string]string{"Name": "Two"})
	if err != nil || string(updated.Data) != "two" || updated.ModSeq <= beforeUpdate.HighestModSeq {
		t.Fatalf("owner update item=%#v err=%v", updated, err)
	}
	afterUpdate, err := ts.FolderStore().Get(t.Context(), folderID)
	if err != nil || afterUpdate.HighestModSeq != updated.ModSeq {
		t.Fatalf("folder after update=%#v item mod-sequence=%d err=%v", afterUpdate, updated.ModSeq, err)
	}
	if err := workspace.DeleteItem(t.Context(), bob, bob, authz.ActingNone, itemID); err == nil {
		t.Fatal("unprivileged delete succeeded")
	}
	if err := workspace.DeleteItem(t.Context(), alice, alice, authz.ActingNone, itemID); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
}

func TestWorkspaceRecursiveMoveHonorsDescendantDeny(t *testing.T) {
	_, ts, _ := testMailService(t)
	workspace := NewWorkspace(ts, authz.New(ts))
	alice := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	root, err := workspace.CreateFolder(t.Context(), alice, alice, authz.ActingNone, "Projects", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := workspace.CreateFolder(t.Context(), alice, alice, authz.ActingNone, "Secret", model.FolderTypeMail, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := workspace.CreateFolder(t.Context(), alice, alice, authz.ActingNone, "Shared", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	bindings := []model.PolicyBinding{
		{Principal: bob, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: root.ID}, Effect: model.EffectAllow, Permissions: []string{string(authz.FolderMetadataWrite)}, Inheritance: model.InheritanceSubtree, GrantedBy: "alice"},
		{Principal: bob, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: destination.ID}, Effect: model.EffectAllow, Permissions: []string{string(authz.FolderChildrenCreate)}, Inheritance: model.InheritanceSelf, GrantedBy: "alice"},
		{Principal: bob, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: child.ID}, Effect: model.EffectDeny, Permissions: []string{string(authz.FolderMetadataWrite)}, Inheritance: model.InheritanceSelf, GrantedBy: "alice"},
	}
	for _, binding := range bindings {
		if _, err := model.NewPolicyStore(ts).Create(t.Context(), binding); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := workspace.MoveFolder(t.Context(), bob, bob, authz.ActingNone, root.ID, destination.ID, "Moved"); err == nil {
		t.Fatal("recursive move ignored an explicit deny on a descendant")
	}
	if folder, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Projects/Secret"); err != nil || folder.ID != child.ID {
		t.Fatalf("denied tree changed: %+v, %v", folder, err)
	}
}

func TestWorkspaceTrashRetentionAndFolderTreePurge(t *testing.T) {
	_, ts, _ := testMailService(t)
	workspace := NewWorkspace(ts, authz.New(ts))
	workspace.SetTrashRetentionDays(7)
	alice := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}

	parent, err := workspace.CreateFolder(t.Context(), alice, alice, authz.ActingNone, "Projects", model.FolderTypeFiles, "")
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	child, err := workspace.CreateFolder(t.Context(), alice, alice, authz.ActingNone, "Current", model.FolderTypeFiles, parent.ID)
	if err != nil {
		t.Fatalf("create child: %v", err)
	}
	itemID, err := workspace.CreateItem(t.Context(), alice, alice, authz.ActingNone, child.ID, []byte("data"), nil)
	if err != nil {
		t.Fatalf("create item: %v", err)
	}
	if err := workspace.TrashFolder(t.Context(), alice, alice, authz.ActingNone, parent.ID); err != nil {
		t.Fatalf("trash folder: %v", err)
	}
	roots, err := workspace.ListTrashedFolders(t.Context(), alice, alice, authz.ActingNone)
	if err != nil || len(roots) != 1 || roots[0].ID != parent.ID {
		t.Fatalf("trash roots = %#v, err = %v", roots, err)
	}
	if got := roots[0].PurgeAfter.Sub(roots[0].TrashedAt); got < 7*24*time.Hour-time.Second || got > 7*24*time.Hour+time.Second {
		t.Fatalf("retention = %s, want 7 days", got)
	}
	if err := workspace.PurgeFolder(t.Context(), alice, alice, authz.ActingNone, parent.ID); err != nil {
		t.Fatalf("purge folder: %v", err)
	}
	if _, err := ts.FolderStore().Get(t.Context(), parent.ID); err == nil {
		t.Fatal("purged parent still exists")
	}
	if _, err := ts.FolderStore().Get(t.Context(), child.ID); err == nil {
		t.Fatal("purged child still exists")
	}
	if _, err := ts.ItemStore().Get(t.Context(), itemID); err == nil {
		t.Fatal("item in purged tree still exists")
	}
}

func TestWorkspaceMoveKeepsItemWithinFolderType(t *testing.T) {
	_, ts, _ := testMailService(t)
	workspace := NewWorkspace(ts, authz.New(ts))
	alice := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	contactFolder := model.FolderKey("alice", "Contacts")
	itemID, err := workspace.CreateItem(t.Context(), alice, alice, authz.ActingNone, contactFolder, []byte("contact"), nil)
	if err != nil {
		t.Fatalf("create contact item: %v", err)
	}
	fileFolder, err := workspace.CreateFolder(t.Context(), alice, alice, authz.ActingNone, "Documents", model.FolderTypeFiles, "")
	if err != nil {
		t.Fatalf("create files folder: %v", err)
	}
	if _, err := workspace.MoveItem(t.Context(), alice, alice, authz.ActingNone, itemID, fileFolder.ID); err == nil {
		t.Fatal("cross-type move succeeded")
	}
}

func containsFolder(folders []model.Folder, id string) bool {
	for _, folder := range folders {
		if folder.ID == id {
			return true
		}
	}
	return false
}
