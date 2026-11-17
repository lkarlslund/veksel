package authz

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestSystemAdminAdministersButCannotReachOwnerAccounts(t *testing.T) {
	engine, ts := testEngine(t)
	for _, id := range []string{"owner", "admin", "carol"} {
		createUser(t, ts, id)
	}
	system := model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID}
	createBinding(t, ts, model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "owner"}, Resource: system, Effect: model.EffectAllow, RoleID: RoleSystemOwner, Inheritance: model.InheritanceSubtree, GrantedBy: "test"})
	createBinding(t, ts, model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "admin"}, Resource: system, Effect: model.EffectAllow, RoleID: RoleSystemAdmin, Inheritance: model.InheritanceSubtree, GrantedBy: "test"})
	if decision := check(t, engine, "admin", "admin", SystemManage, system); !decision.Allowed {
		t.Fatalf("system.admin cannot administer: %+v", decision)
	}
	for _, action := range []Action{AuthorizationRolesWrite, AuthorizationRolesRead} {
		if decision := check(t, engine, "admin", "admin", action, system); decision.Allowed {
			t.Fatalf("system.admin holds owner authority %s: %+v", action, decision)
		}
	}
	if decision := check(t, engine, "admin", "admin", DomainAdminsManage, model.ResourceRef{Kind: model.ResourceDomain, ID: "example.test"}); !decision.Allowed {
		t.Fatalf("system.admin cannot assign domain administrators: %+v", decision)
	}
	if decision := check(t, engine, "admin", "admin", AccountImpersonate, model.ResourceRef{Kind: model.ResourceAccount, ID: "carol"}); !decision.Allowed {
		t.Fatalf("system.admin cannot impersonate an ordinary account: %+v", decision)
	}
	if decision := check(t, engine, "admin", "admin", AccountImpersonate, model.ResourceRef{Kind: model.ResourceAccount, ID: "owner"}); decision.Allowed || decision.Reason != "owner_account_protected" {
		t.Fatalf("system.admin reached the owner account: %+v", decision)
	}
	if decision := check(t, engine, "owner", "owner", AccountImpersonate, model.ResourceRef{Kind: model.ResourceAccount, ID: "admin"}); !decision.Allowed {
		t.Fatalf("owner lost unrestricted authority: %+v", decision)
	}
}

func TestDomainAdminIsScopedToItsDomain(t *testing.T) {
	engine, ts := testEngine(t)
	createUser(t, ts, "dana")
	createBinding(t, ts, model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "dana"}, Resource: model.ResourceRef{Kind: model.ResourceDomain, ID: "a.test"}, Effect: model.EffectAllow, RoleID: RoleDomainAdmin, Inheritance: model.InheritanceSubtree, GrantedBy: "test"})
	own, other := model.ResourceRef{Kind: model.ResourceDomain, ID: "a.test"}, model.ResourceRef{Kind: model.ResourceDomain, ID: "b.test"}
	for _, action := range []Action{DomainRead, DomainAccountsManage, DomainIdentitiesManage, DomainCatchAllManage, DomainTraceRead} {
		if decision := check(t, engine, "dana", "dana", action, own); !decision.Allowed {
			t.Fatalf("domain admin lacks %s on its domain: %+v", action, decision)
		}
		if decision := check(t, engine, "dana", "dana", action, other); decision.Allowed {
			t.Fatalf("domain admin holds %s on another domain: %+v", action, decision)
		}
	}
	for _, action := range []Action{DomainLimitsManage, DomainAdminsManage} {
		if decision := check(t, engine, "dana", "dana", action, own); decision.Allowed {
			t.Fatalf("domain admin may %s on its own domain: %+v", action, decision)
		}
	}
	if decision := check(t, engine, "dana", "dana", SystemManage, model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID}); decision.Allowed {
		t.Fatalf("domain admin opened system administration: %+v", decision)
	}
}
