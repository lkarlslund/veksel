package authz

import (
	"context"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func testEngine(t *testing.T) (*Engine, *model.TypedStore) {
	t.Helper()
	s, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ts := model.NewTypedStore(s, store.BackendJSON)
	for _, namespace := range []string{
		model.NSUsers, model.NSEmails, model.NSFolders, model.NSRoles,
		model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes,
		model.NSAuthorizationMetadata,
	} {
		if err := ts.EnsureNamespace(context.Background(), namespace); err != nil {
			t.Fatalf("ensure namespace %q: %v", namespace, err)
		}
	}
	return New(ts), ts
}

func createUser(t *testing.T, ts *model.TypedStore, id string) {
	t.Helper()
	if err := model.NewUserStore(ts).Create(t.Context(), id, id, "password123"); err != nil {
		t.Fatalf("create user %q: %v", id, err)
	}
}

func createFolder(t *testing.T, ts *model.TypedStore, userID, path, parentID string) model.Folder {
	t.Helper()
	fs := model.NewFolderStore(ts)
	if err := fs.Create(t.Context(), userID, path, model.FolderTypeMail, parentID); err != nil {
		t.Fatalf("create folder %q: %v", path, err)
	}
	folder, err := fs.GetByPath(t.Context(), userID, path)
	if err != nil {
		t.Fatalf("get folder %q: %v", path, err)
	}
	return folder
}

func createBinding(t *testing.T, ts *model.TypedStore, binding model.PolicyBinding) model.PolicyBinding {
	t.Helper()
	created, err := model.NewPolicyStore(ts).Create(t.Context(), binding)
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	return created
}

func check(t *testing.T, engine *Engine, actor, subject string, action Action, resource model.ResourceRef) Decision {
	t.Helper()
	decision, err := engine.Check(t.Context(), Request{
		Actor:   model.PrincipalRef{Kind: model.PrincipalUser, ID: actor},
		Subject: model.PrincipalRef{Kind: model.PrincipalUser, ID: subject},
		Action:  action, Resource: resource,
	})
	if err != nil {
		t.Fatalf("check authorization: %v", err)
	}
	return decision
}

func TestEngineFolderOwnerAndDefaultDeny(t *testing.T) {
	engine, ts := testEngine(t)
	createUser(t, ts, "alice")
	createUser(t, ts, "bob")
	inbox := createFolder(t, ts, "alice", "INBOX", "")
	resource := model.ResourceRef{Kind: model.ResourceFolder, ID: inbox.ID}

	if got := check(t, engine, "alice", "alice", FolderItemsDelete, resource); !got.Allowed || got.Reason != "resource_owner" {
		t.Fatalf("owner decision = %#v", got)
	}
	if got := check(t, engine, "bob", "bob", FolderItemsRead, resource); got.Allowed || got.Reason != "default_deny" {
		t.Fatalf("ungranted decision = %#v", got)
	}
}

func TestEngineInheritedAllowAndDenyPrecedence(t *testing.T) {
	engine, ts := testEngine(t)
	createUser(t, ts, "alice")
	createUser(t, ts, "bob")
	parent := createFolder(t, ts, "alice", "Projects", "")
	child := createFolder(t, ts, "alice", "Projects/Secret", parent.ID)
	principal := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}

	createBinding(t, ts, model.PolicyBinding{
		Principal: principal,
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: parent.ID},
		Effect:    model.EffectAllow, RoleID: RoleFolderEditor,
		Inheritance: model.InheritanceSubtree, GrantedBy: "alice",
	})
	resource := model.ResourceRef{Kind: model.ResourceFolder, ID: child.ID}
	if got := check(t, engine, "bob", "bob", FolderItemsUpdate, resource); !got.Allowed {
		t.Fatalf("inherited allow decision = %#v", got)
	}

	deny := createBinding(t, ts, model.PolicyBinding{
		Principal: principal, Resource: resource, Effect: model.EffectDeny,
		Permissions: []string{string(FolderItemsUpdate)},
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	got := check(t, engine, "bob", "bob", FolderItemsUpdate, resource)
	if got.Allowed || got.Reason != "explicit_deny" || len(got.MatchedBindingIDs) != 1 || got.MatchedBindingIDs[0] != deny.ID {
		t.Fatalf("deny decision = %#v", got)
	}
}

func TestEngineGroupGrantAndExpiration(t *testing.T) {
	engine, ts := testEngine(t)
	createUser(t, ts, "alice")
	createUser(t, ts, "bob")
	inbox := createFolder(t, ts, "alice", "INBOX", "")
	if err := model.NewGroupStore(ts).Set(t.Context(), model.Group{ID: "team", Name: "Team", Members: []string{"bob"}}); err != nil {
		t.Fatalf("create group: %v", err)
	}
	createBinding(t, ts, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalGroup, ID: "team"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: inbox.ID},
		Effect:    model.EffectAllow, RoleID: RoleFolderViewer,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	resource := model.ResourceRef{Kind: model.ResourceFolder, ID: inbox.ID}
	if got := check(t, engine, "bob", "bob", FolderItemsRead, resource); !got.Allowed {
		t.Fatalf("group decision = %#v", got)
	}

	decision, err := engine.Check(t.Context(), Request{
		Actor:  model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Action: FolderItemsRead, Resource: resource, Now: time.Now().Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("check expired grant: %v", err)
	}
	if decision.Allowed || decision.Reason != "default_deny" {
		t.Fatalf("expired decision = %#v", decision)
	}
}

func TestEngineSystemOwnerCannotBeDenied(t *testing.T) {
	engine, ts := testEngine(t)
	createUser(t, ts, "owner")
	createUser(t, ts, "alice")
	folder := createFolder(t, ts, "alice", "INBOX", "")
	principal := model.PrincipalRef{Kind: model.PrincipalUser, ID: "owner"}
	createBinding(t, ts, model.PolicyBinding{
		Principal: principal,
		Resource:  model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		Effect:    model.EffectAllow, RoleID: RoleSystemOwner,
		Inheritance: model.InheritanceSubtree, GrantedBy: "setup",
	})
	createBinding(t, ts, model.PolicyBinding{
		Principal: principal,
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID},
		Effect:    model.EffectDeny, Permissions: []string{"folder.*"},
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	resource := model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID}
	if got := check(t, engine, "owner", "owner", FolderItemsDelete, resource); !got.Allowed || got.Reason != "system_owner" {
		t.Fatalf("system owner decision = %#v", got)
	}
}

func TestEngineRequiresAuthorizedActingMode(t *testing.T) {
	engine, ts := testEngine(t)
	createUser(t, ts, "alice")
	createUser(t, ts, "bob")
	inbox := createFolder(t, ts, "alice", "INBOX", "")
	resource := model.ResourceRef{Kind: model.ResourceFolder, ID: inbox.ID}

	unauthorized, err := engine.Check(t.Context(), Request{
		Actor:   model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Subject: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Action:  FolderItemsRead, Resource: resource,
	})
	if err != nil {
		t.Fatalf("check unauthorized subject: %v", err)
	}
	if unauthorized.Allowed || unauthorized.Reason != "subject_not_authorized" {
		t.Fatalf("unauthorized subject decision = %#v", unauthorized)
	}

	createBinding(t, ts, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"},
		Effect:    model.EffectAllow, RoleID: RoleAccountDelegate,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	authorized, err := engine.Check(t.Context(), Request{
		Actor:   model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Subject: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Mode:    ActingDelegation, Action: FolderItemsRead, Resource: resource,
	})
	if err != nil {
		t.Fatalf("check delegated subject: %v", err)
	}
	if !authorized.Allowed || authorized.Reason != "resource_owner" {
		t.Fatalf("delegated subject decision = %#v", authorized)
	}
}

func TestPolicyBindingValidate(t *testing.T) {
	base := model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: "alice:INBOX"},
		Effect:    model.EffectAllow, Inheritance: model.InheritanceSelf,
	}
	tests := []struct {
		name    string
		mutate  func(*model.PolicyBinding)
		wantErr bool
	}{
		{name: "role", mutate: func(b *model.PolicyBinding) { b.RoleID = RoleFolderViewer }},
		{name: "permissions", mutate: func(b *model.PolicyBinding) { b.Permissions = []string{string(FolderItemsRead)} }},
		{name: "neither", mutate: func(*model.PolicyBinding) {}, wantErr: true},
		{name: "both", mutate: func(b *model.PolicyBinding) {
			b.RoleID = RoleFolderViewer
			b.Permissions = []string{string(FolderItemsRead)}
		}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := base
			tt.mutate(&binding)
			if got := binding.Validate(); (got != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func TestPolicyStoreRebuildIndexes(t *testing.T) {
	_, ts := testEngine(t)
	createUser(t, ts, "alice")
	binding := createBinding(t, ts, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		Effect:    model.EffectAllow, RoleID: RoleSystemOwner,
		Inheritance: model.InheritanceSubtree, GrantedBy: "setup",
	})
	indexKeys, err := ts.List(t.Context(), model.NSPolicyIndexes)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	for _, key := range indexKeys {
		if err := ts.Delete(t.Context(), model.NSPolicyIndexes, key); err != nil {
			t.Fatalf("delete index: %v", err)
		}
	}
	policies := model.NewPolicyStore(ts)
	if err := policies.RebuildIndexes(t.Context()); err != nil {
		t.Fatalf("rebuild indexes: %v", err)
	}
	bindings, err := policies.ListForPrincipal(t.Context(), binding.Principal)
	if err != nil {
		t.Fatalf("list rebuilt policy: %v", err)
	}
	if len(bindings) != 1 || bindings[0].ID != binding.ID {
		t.Fatalf("rebuilt bindings = %#v", bindings)
	}
}
