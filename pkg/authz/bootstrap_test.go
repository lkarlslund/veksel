package authz

import (
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestBootstrapCreatesFirstOwner(t *testing.T) {
	engine, ts := testEngine(t)
	bootstrap := NewBootstrap(ts)
	state, err := bootstrap.State(t.Context())
	if err != nil || state != SetupReady {
		t.Fatalf("initial state = %q, %v", state, err)
	}
	if err := bootstrap.CreateOwner(t.Context(), setupToken(t, bootstrap), "Alice", "Alice Example", "password123"); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	state, err = bootstrap.State(t.Context())
	if err != nil || state != SetupComplete {
		t.Fatalf("completed state = %q, %v", state, err)
	}
	if _, err := model.NewFolderStore(ts).GetByPath(t.Context(), "alice", "INBOX"); err != nil {
		t.Fatalf("owner inbox: %v", err)
	}
	decision, err := engine.Check(t.Context(), Request{
		Actor:    model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Action:   AuthorizationRolesWrite,
		Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
	})
	if err != nil || !decision.Allowed || decision.Reason != "system_owner" {
		t.Fatalf("owner decision = %#v, %v", decision, err)
	}
	if token, err := bootstrap.SetupToken(t.Context()); err != nil || token != "" {
		t.Fatalf("setup token after completion = %q, %v", token, err)
	}
	if err := bootstrap.CreateOwner(t.Context(), "", "bob", "Bob", "password123"); err == nil {
		t.Fatal("second setup unexpectedly succeeded")
	}
}

func setupToken(t *testing.T, bootstrap *Bootstrap) string {
	t.Helper()
	token, err := bootstrap.SetupToken(t.Context())
	if err != nil || token == "" {
		t.Fatalf("setup token = %q, %v", token, err)
	}
	return token
}

func TestBootstrapRequiresSetupToken(t *testing.T) {
	_, ts := testEngine(t)
	bootstrap := NewBootstrap(ts)
	for _, token := range []string{"", "guess", setupToken(t, NewBootstrap(ts))} {
		if err := bootstrap.CreateOwner(t.Context(), token, "mallory", "", "password123"); !errors.Is(err, ErrSetupToken) {
			t.Fatalf("token %q: error = %v, want ErrSetupToken", token, err)
		}
	}
	if state, err := bootstrap.State(t.Context()); err != nil || state != SetupReady {
		t.Fatalf("state after rejected tokens = %q, %v", state, err)
	}
}

func TestLastEnabledSystemOwnerCannotBeDisabledOrDeleted(t *testing.T) {
	_, ts := testEngine(t)
	bootstrap := NewBootstrap(ts)
	if err := bootstrap.CreateOwner(t.Context(), setupToken(t, bootstrap), "alice", "Alice", "password123"); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := ts.UserStore().Update(t.Context(), "alice", func(user *model.User) { user.Enabled = false }); !errors.Is(err, model.ErrLastSystemOwner) {
		t.Fatalf("disable error = %v, want last-owner error", err)
	}
	if err := ts.UserStore().Delete(t.Context(), "alice"); !errors.Is(err, model.ErrLastSystemOwner) {
		t.Fatalf("delete error = %v, want last-owner error", err)
	}
	createUser(t, ts, "bob")
	_, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		Effect:    model.EffectAllow, RoleID: RoleSystemOwner,
		Inheritance: model.InheritanceSubtree, GrantedBy: "alice",
	})
	if err != nil {
		t.Fatalf("grant second owner: %v", err)
	}
	if err := ts.UserStore().Update(t.Context(), "alice", func(user *model.User) { user.Enabled = false }); err != nil {
		t.Fatalf("disable with second owner: %v", err)
	}
}

func TestBootstrapBlocksExistingOwnerlessStore(t *testing.T) {
	_, ts := testEngine(t)
	createUser(t, ts, "alice")
	state, err := NewBootstrap(ts).State(t.Context())
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if state != SetupBlocked {
		t.Fatalf("state = %q, want %q", state, SetupBlocked)
	}
}

func TestBootstrapValidationDoesNotClaimSetup(t *testing.T) {
	_, ts := testEngine(t)
	bootstrap := NewBootstrap(ts)
	if err := bootstrap.CreateOwner(t.Context(), setupToken(t, bootstrap), "bad user", "", "short"); err == nil {
		t.Fatal("invalid setup unexpectedly succeeded")
	}
	state, err := bootstrap.State(t.Context())
	if err != nil || state != SetupReady {
		t.Fatalf("state after validation = %q, %v", state, err)
	}
}
