package service

import (
	"fmt"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// BenchmarkAccountFolderSpaceListFolders measures the folder catalog request
// every web workspace issues on entry: one account with ~100 owned folders plus
// a second account that shares a subtree with the caller.
func BenchmarkAccountFolderSpaceListFolders(b *testing.B) {
	backend, err := pebblestore.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()
	system := model.NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range model.Namespaces() {
		if err := system.EnsureNamespace(b.Context(), namespace); err != nil {
			b.Fatal(err)
		}
	}
	manager, err := account.NewManager(b.TempDir(), store.BackendPebble)
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	for _, login := range []string{"alice", "bob"} {
		if err := system.UserStore().Create(b.Context(), login, login, "password123"); err != nil {
			b.Fatal(err)
		}
		if err := system.FolderStore().CreateForUser(b.Context(), login); err != nil {
			b.Fatal(err)
		}
	}
	space, err := NewAccountFolderSpace(b.Context(), system, manager, authz.New(system))
	if err != nil {
		b.Fatal(err)
	}
	alice, bob := UserAccess("alice", "benchmark"), UserAccess("bob", "benchmark")
	for index := range 90 {
		if _, err := space.CreateFolder(b.Context(), alice, fmt.Sprintf("Mail %03d", index), model.FolderTypeMail, ""); err != nil {
			b.Fatal(err)
		}
	}
	shared, err := space.CreateFolder(b.Context(), bob, "Shared", model.FolderTypeMail, "")
	if err != nil {
		b.Fatal(err)
	}
	for index := range 12 {
		if _, err := space.CreateFolder(b.Context(), bob, fmt.Sprintf("Child %02d", index), model.FolderTypeMail, shared.ID); err != nil {
			b.Fatal(err)
		}
	}
	if _, err := model.NewPolicyStore(system).Create(b.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: shared.ID},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderViewer, Inheritance: model.InheritanceSubtree, GrantedBy: "bob",
	}); err != nil {
		b.Fatal(err)
	}
	folders, err := space.ListFolders(b.Context(), alice, FolderQuery{})
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("visible folders: %d", len(folders))
	b.Run("unscoped", func(b *testing.B) {
		for range b.N {
			if _, err := space.ListFolders(b.Context(), alice, FolderQuery{}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("request-scoped", func(b *testing.B) {
		for range b.N {
			if _, err := space.ListFolders(authz.WithRequestScope(b.Context()), alice, FolderQuery{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
