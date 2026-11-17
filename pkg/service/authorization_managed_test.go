package service

import (
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestManagedGrantUpdatesAndEffectiveProjectionAcrossResourceKinds(t *testing.T) {
	_, ts, _ := testMailService(t)
	engine := authz.New(ts)
	service := NewAuthorization(ts, engine)
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}

	account, err := service.CreateAccountDelegation(t.Context(), actor, model.PolicyBinding{
		Principal: bob, Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"},
		Effect: model.EffectAllow, RoleID: authz.RoleAccountDelegate, Inheritance: model.InheritanceSelf,
	})
	if err != nil {
		t.Fatal(err)
	}
	account, err = service.UpdateManagedGrant(t.Context(), actor, account.ID, ManagedGrantUpdate{
		Effect: model.EffectAllow, RoleID: authz.RoleAccountSearcher, Inheritance: model.InheritanceSelf,
		ExpectedUpdatedAt: account.UpdatedAt,
	})
	if err != nil || account.RoleID != authz.RoleAccountSearcher {
		t.Fatalf("account update = %+v, %v", account, err)
	}
	accountEffective, err := service.EffectiveManagedGrant(t.Context(), actor, account.ID, time.Now().UTC())
	if err != nil || len(accountEffective.Decisions) != 1 || !accountEffective.Decisions[0].Allowed || accountEffective.Decisions[0].Permission != string(authz.AccountItemsSearch) {
		t.Fatalf("account effective = %+v, %v", accountEffective, err)
	}

	identity, err := service.CreateIdentityGrant(t.Context(), actor, model.PolicyBinding{
		Principal: bob, Resource: model.ResourceRef{Kind: model.ResourceIdentity, ID: "alice@example.test"},
		Effect: model.EffectAllow, Permissions: []string{string(authz.IdentitySendOnBehalf)}, Inheritance: model.InheritanceSelf,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err = service.UpdateManagedGrant(t.Context(), actor, identity.ID, ManagedGrantUpdate{
		Effect: model.EffectAllow, Permissions: []string{string(authz.IdentitySendAs)}, Inheritance: model.InheritanceSelf,
		ExpectedUpdatedAt: identity.UpdatedAt,
	})
	if err != nil || len(identity.Permissions) != 1 || identity.Permissions[0] != string(authz.IdentitySendAs) {
		t.Fatalf("identity update = %+v, %v", identity, err)
	}
	identityEffective, err := service.EffectiveManagedGrant(t.Context(), actor, identity.ID, time.Now().UTC())
	if err != nil || len(identityEffective.Decisions) != 1 || !identityEffective.Decisions[0].Allowed {
		t.Fatalf("identity effective = %+v, %v", identityEffective, err)
	}

	if err := model.NewGroupStore(ts).Set(t.Context(), model.Group{ID: "team", Name: "Team", Members: []string{"bob"}}); err != nil {
		t.Fatal(err)
	}
	inbox := model.InboxFolderID("alice")
	groupGrant, err := service.CreateFolderGrant(t.Context(), actor, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalGroup, ID: "team"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: inbox}, Effect: model.EffectAllow,
		RoleID: authz.RoleFolderViewer, Inheritance: model.InheritanceSubtree,
	})
	if err != nil {
		t.Fatal(err)
	}
	groupEffective, err := service.EffectiveManagedGrant(t.Context(), actor, groupGrant.ID, time.Now().UTC())
	if err != nil || groupEffective.GroupMembers != 1 || len(groupEffective.Permissions) != 4 || len(groupEffective.Decisions) != 0 {
		t.Fatalf("group effective = %+v, %v", groupEffective, err)
	}
}

func TestManagedGrantUpdateRejectsUnsupportedAccess(t *testing.T) {
	_, ts, _ := testMailService(t)
	service := NewAuthorization(ts, authz.New(ts))
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	grant, err := service.CreateIdentityGrant(t.Context(), actor, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceIdentity, ID: "alice@example.test"},
		Effect:    model.EffectAllow, Permissions: []string{string(authz.IdentitySendAs)}, Inheritance: model.InheritanceSelf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateManagedGrant(t.Context(), actor, grant.ID, ManagedGrantUpdate{
		Effect: model.EffectAllow, Permissions: []string{string(authz.FolderItemsRead)}, Inheritance: model.InheritanceSelf,
		ExpectedUpdatedAt: grant.UpdatedAt,
	}); err == nil {
		t.Fatal("identity grant accepted a folder permission")
	}
	stored, err := model.NewPolicyStore(ts).Get(t.Context(), grant.ID)
	if err != nil || len(stored.Permissions) != 1 || stored.Permissions[0] != string(authz.IdentitySendAs) {
		t.Fatalf("stored grant changed after rejection: %+v, %v", stored, err)
	}
}

func TestDelegatedSendingIdentitiesResolveEffectiveDirectAndGroupGrants(t *testing.T) {
	_, ts, _ := testMailService(t)
	authorization := NewAuthorization(ts, authz.New(ts))
	users := ts.UserStore()
	ctx := t.Context()
	for _, address := range []string{"alias@example.test", "denied@example.test", "disabled@example.test", "expired@example.test", "zeta@example.test"} {
		if err := users.AddEmailAddress(ctx, address, "alice", "example.test", false); err != nil {
			t.Fatal(err)
		}
	}
	disabled, err := users.GetEmailAddress(ctx, "disabled@example.test")
	if err != nil {
		t.Fatal(err)
	}
	disabled.Enabled = false
	if err := ts.Set(ctx, model.NSEmails, model.EmailAddrKey(disabled.ID), disabled); err != nil {
		t.Fatal(err)
	}
	if err := model.NewGroupStore(ts).Set(ctx, model.Group{ID: "delegates", Name: "Delegates", Members: []string{"bob"}}); err != nil {
		t.Fatal(err)
	}
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	group := model.PrincipalRef{Kind: model.PrincipalGroup, ID: "delegates"}
	grant := func(principal model.PrincipalRef, address string, effect model.BindingEffect, expires time.Time, permissions ...authz.Action) {
		t.Helper()
		values := make([]string, len(permissions))
		for index, permission := range permissions {
			values[index] = string(permission)
		}
		if _, err := authorization.CreateIdentityGrant(ctx, actor, model.PolicyBinding{
			Principal: principal, Resource: model.ResourceRef{Kind: model.ResourceIdentity, ID: address},
			Effect: effect, Permissions: values, Inheritance: model.InheritanceSelf, ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("grant %s to %+v: %v", address, principal, err)
		}
	}
	if _, err := authorization.CreateIdentityGrant(ctx, bob, model.PolicyBinding{
		Principal: bob, Resource: model.ResourceRef{Kind: model.ResourceIdentity, ID: "bob@example.test"},
		Effect: model.EffectAllow, Permissions: []string{string(authz.IdentitySendAs)}, Inheritance: model.InheritanceSelf,
	}); err != nil {
		t.Fatal(err)
	}
	grant(bob, "alias@example.test", model.EffectAllow, time.Time{}, authz.IdentitySendAs)
	grant(group, "alias@example.test", model.EffectAllow, time.Time{}, authz.IdentitySendOnBehalf)
	grant(bob, "denied@example.test", model.EffectAllow, time.Time{}, authz.IdentitySendAs)
	grant(group, "denied@example.test", model.EffectDeny, time.Time{}, authz.IdentitySendAs)
	grant(bob, "disabled@example.test", model.EffectAllow, time.Time{}, authz.IdentitySendAs)
	grant(bob, "expired@example.test", model.EffectAllow, time.Now().Add(-time.Hour), authz.IdentitySendAs)
	grant(bob, "zeta@example.test", model.EffectAllow, time.Time{}, authz.IdentitySendOnBehalf)

	got, err := authorization.ListDelegatedSendingIdentities(ctx, bob, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Address != "alias@example.test" || len(got[0].Modes) != 2 || got[0].Modes[0] != authz.IdentitySendAs || got[0].Modes[1] != authz.IdentitySendOnBehalf || got[1].Address != "zeta@example.test" || len(got[1].Modes) != 1 || got[1].Modes[0] != authz.IdentitySendOnBehalf {
		t.Fatalf("delegated identities = %#v", got)
	}
	if _, err := authorization.ListDelegatedSendingIdentities(t.Context(), model.PrincipalRef{Kind: model.PrincipalGroup, ID: "delegates"}, time.Now()); err == nil {
		t.Fatal("group actor was accepted")
	}
}

func TestDelegatedSendingIdentitiesIgnoreRemovedCandidates(t *testing.T) {
	_, ts, _ := testMailService(t)
	authorization := NewAuthorization(ts, authz.New(ts))
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	if _, err := authorization.CreateIdentityGrant(t.Context(), actor, model.PolicyBinding{
		Principal: bob, Resource: model.ResourceRef{Kind: model.ResourceIdentity, ID: "alice@example.test"},
		Effect: model.EffectAllow, Permissions: []string{string(authz.IdentitySendAs)}, Inheritance: model.InheritanceSelf,
	}); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().DeleteEmailAddress(t.Context(), "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	got, err := authorization.ListDelegatedSendingIdentities(t.Context(), bob, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("removed delegated identity leaked: %#v", got)
	}
}
