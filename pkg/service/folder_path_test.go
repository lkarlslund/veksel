package service

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestEnsureFolderPathCreatesNestedPathAndIsIdempotent(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "queue-test")

	created, err := EnsureFolderPath(t.Context(), space, access, "Projects/2026/Invoices", model.FolderTypeMail)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := EnsureFolderPath(t.Context(), space, access, "/Projects/2026/Invoices/", model.FolderTypeMail)
	if err != nil {
		t.Fatal(err)
	}
	if retried.ID != created.ID || retried.Path != "Projects/2026/Invoices" {
		t.Fatalf("retry returned %+v, first creation was %+v", retried, created)
	}
	folders, err := space.ListFolders(t.Context(), access, FolderQuery{})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, folder := range folders {
		counts[folder.Path]++
	}
	for _, path := range []string{"Projects", "Projects/2026", "Projects/2026/Invoices"} {
		if counts[path] != 1 {
			t.Fatalf("folder %q count = %d, want 1", path, counts[path])
		}
	}
}

func TestEnsureFolderPathResumesPartialHierarchy(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "queue-test")
	parent, err := space.CreateFolder(t.Context(), access, "Projects", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := EnsureFolderPath(t.Context(), space, access, "Projects/2026", model.FolderTypeMail)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.ParentID != parent.ID || leaf.Path != "Projects/2026" {
		t.Fatalf("resumed leaf = %+v, parent = %+v", leaf, parent)
	}
}

func TestEnsureFolderPathRejectsInvalidAndMismatchedPaths(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "queue-test")
	for _, path := range []string{"", "Projects//2026", "../Inbox"} {
		if _, err := EnsureFolderPath(t.Context(), space, access, path, model.FolderTypeMail); err == nil {
			t.Fatalf("path %q was accepted", path)
		}
	}
	if _, err := EnsureFolderPath(t.Context(), space, access, "Calendar", model.FolderTypeMail); err == nil {
		t.Fatal("existing calendar folder was accepted as a mail folder")
	}
}

func TestListFoldersCanIncludeCompleteTrashedTree(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "quota-test")
	parent, err := space.CreateFolder(t.Context(), access, "Projects", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := space.CreateFolder(t.Context(), access, "Old", model.FolderTypeMail, parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := space.DeleteFolder(t.Context(), access, parent.ID); err != nil {
		t.Fatal(err)
	}

	visible, err := space.ListFolders(t.Context(), access, FolderQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if containsFolder(visible, parent.ID) || containsFolder(visible, child.ID) {
		t.Fatal("trashed folders appeared in the default listing")
	}
	complete, err := space.ListFolders(t.Context(), access, FolderQuery{IncludeTrashed: true})
	if err != nil {
		t.Fatal(err)
	}
	if !containsFolder(complete, parent.ID) || !containsFolder(complete, child.ID) {
		t.Fatalf("complete listing omitted trashed tree: %v", complete)
	}
}
