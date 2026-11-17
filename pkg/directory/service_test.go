package directory

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// fakeDirectory answers from in-memory entries keyed by login.
type fakeDirectory struct {
	mu        sync.Mutex
	entries   map[string]Entry
	passwords map[string]string
	err       error
}

func (f *fakeDirectory) Authenticate(_ context.Context, login, password string) (Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Entry{}, f.err
	}
	entry, ok := f.entries[login]
	if !ok || password == "" || f.passwords[login] != password {
		return Entry{}, ErrInvalidCredentials
	}
	return entry, nil
}

func (f *fakeDirectory) Users(context.Context, int) ([]Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var entries []Entry
	for _, entry := range f.entries {
		entries = append(entries, entry)
	}
	return entries, nil
}

func (f *fakeDirectory) Test(context.Context) Diagnostic { return Diagnostic{OK: f.err == nil} }
func (f *fakeDirectory) Close()                          {}

func (f *fakeDirectory) set(entry Entry, password string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[entry.Login], f.passwords[entry.Login] = entry, password
}

func (f *fakeDirectory) remove(login string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, login)
}

func directoryFixture(t *testing.T) (*model.TypedStore, *Service, *fakeDirectory) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	for _, domain := range []string{"example.test", "parked.test"} {
		if err := ts.DomainStore().Create(t.Context(), domain); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.DomainStore().Update(t.Context(), "parked.test", func(d *model.Domain) { d.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	fake := &fakeDirectory{entries: map[string]Entry{}, passwords: map[string]string{}}
	service := New(ts, account.Provisioner{TS: ts}, func(Settings) (Directory, error) { return fake, nil })
	if err := service.Configure(Settings{Enabled: true, AdminGroupDN: "cn=admins,dc=example,dc=test"}); err != nil {
		t.Fatal(err)
	}
	return ts, service, fake
}

func TestAuthenticateProvisionsAccountWithHostedAddresses(t *testing.T) {
	ts, service, fake := directoryFixture(t)
	fake.set(Entry{
		DN: "uid=alice,dc=example,dc=test", GUID: "guid-alice", Login: "alice", DisplayName: "Alice Example",
		Addresses: []string{"alice@example.test", "alias@example.test", "alice@parked.test", "alice@elsewhere.test"},
	}, "secret")
	if _, err := service.Authenticate(t.Context(), "alice", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty password error = %v", err)
	}
	user, err := service.Authenticate(t.Context(), "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "alice" || user.Source != model.UserSourceLDAP || user.DirectoryDN != "uid=alice,dc=example,dc=test" || user.DirectoryID != "guid-alice" || user.DisplayName != "Alice Example" || user.PasswordHash != "" || !user.Enabled {
		t.Fatalf("provisioned user = %+v", user)
	}
	identities, err := ts.UserStore().ListEmailAddressesForUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	var addresses []string
	for _, identity := range identities {
		addresses = append(addresses, identity.ID)
		if identity.ID == "alice@example.test" && !identity.Primary {
			t.Fatal("first directory address is not primary")
		}
	}
	slices.Sort(addresses)
	if !slices.Equal(addresses, []string{"alias@example.test", "alice@example.test"}) {
		t.Fatalf("identities = %q, want only hosted, enabled domains", addresses)
	}
	if _, err := ts.FolderStore().GetByPath(t.Context(), "alice", "INBOX"); err != nil {
		t.Fatalf("provisioned account has no inbox: %v", err)
	}
	// A rename in the directory keeps the account found by its stable identity.
	fake.remove("alice")
	fake.set(Entry{DN: "uid=alice2,dc=example,dc=test", GUID: "guid-alice", Login: "alice2", DisplayName: "Alice Renamed"}, "secret")
	renamed, err := service.Authenticate(t.Context(), "alice2", "secret")
	if err != nil || renamed.ID != "alice" || renamed.DisplayName != "Alice Renamed" || renamed.DirectoryDN != "uid=alice2,dc=example,dc=test" {
		t.Fatalf("renamed entry = %+v, %v", renamed, err)
	}
}

func TestAuthenticateRefusesLocalAccountCollision(t *testing.T) {
	ts, service, fake := directoryFixture(t)
	if err := ts.UserStore().Create(t.Context(), "bob", "Local Bob", "local-password"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().AddEmailAddress(t.Context(), "bob@example.test", "bob", "example.test", true); err != nil {
		t.Fatal(err)
	}
	fake.set(Entry{DN: "uid=bob,dc=example,dc=test", GUID: "guid-bob", Login: "bob", Admin: true}, "directory-password")
	if _, err := service.Authenticate(t.Context(), "bob", "directory-password"); !errors.Is(err, ErrAccountConflict) {
		t.Fatalf("collision error = %v", err)
	}
	bob, err := ts.UserStore().Get(t.Context(), "bob")
	if err != nil || bob.Directory() || bob.DisplayName != "Local Bob" {
		t.Fatalf("local account was taken over: %+v, %v", bob, err)
	}
	bindings, _ := model.NewPolicyStore(ts).ListForPrincipal(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"})
	if len(bindings) != 0 {
		t.Fatalf("collision granted roles: %+v", bindings)
	}
	// Another directory account's address is never reassigned either.
	fake.set(Entry{DN: "uid=carol,dc=example,dc=test", Login: "carol", Addresses: []string{"bob@example.test", "carol@example.test"}}, "carol-password")
	if _, err := service.Authenticate(t.Context(), "carol", "carol-password"); err != nil {
		t.Fatal(err)
	}
	if identity, _ := ts.UserStore().GetEmailAddress(t.Context(), "bob@example.test"); identity.UserID != "bob" {
		t.Fatalf("bob's address moved to %q", identity.UserID)
	}
}

func TestAdminGroupMembershipGrantsAndRevokesOwnedRole(t *testing.T) {
	ts, service, fake := directoryFixture(t)
	policies := model.NewPolicyStore(ts)
	roles := func() (owned, manual int) {
		bindings, _ := policies.ListForPrincipal(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "dana"})
		for _, binding := range bindings {
			if directoryAdminRole(binding.RoleID) && binding.GrantedBy == grantedBy {
				owned++
			} else {
				manual++
			}
		}
		return owned, manual
	}
	fake.set(Entry{DN: "uid=dana,dc=example,dc=test", Login: "dana", Admin: true}, "pw")
	if _, err := service.Authenticate(t.Context(), "dana", "pw"); err != nil {
		t.Fatal(err)
	}
	if owned, _ := roles(); owned != 1 {
		t.Fatalf("admin group member has %d directory role bindings", owned)
	}
	// The granted role opens administration (the web UI's admin check).
	decision, err := authz.New(ts).Check(t.Context(), authz.Request{
		Actor: model.PrincipalRef{Kind: model.PrincipalUser, ID: "dana"}, Action: authz.AuthorizationRolesRead,
		Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
	})
	if err != nil || !decision.Allowed {
		t.Fatalf("admin group member cannot administer: %+v, %v", decision, err)
	}
	if _, err := service.Authenticate(t.Context(), "dana", "pw"); err != nil {
		t.Fatal(err)
	}
	if owned, _ := roles(); owned != 1 {
		t.Fatalf("repeated sign-in duplicated the role: %d", owned)
	}
	if _, err := policies.Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "dana"}, Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		Effect: model.EffectAllow, RoleID: authz.RoleSystemAdmin, Inheritance: model.InheritanceSubtree, GrantedBy: "owner",
	}); err != nil {
		t.Fatal(err)
	}
	fake.set(Entry{DN: "uid=dana,dc=example,dc=test", Login: "dana"}, "pw")
	if _, err := service.Sync(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	if owned, manual := roles(); owned != 0 || manual != 1 {
		t.Fatalf("after leaving the group: owned=%d manual=%d, want 0 and the manual grant kept", owned, manual)
	}
}

func TestAdminGroupRoleSettingGrantsSystemAdminInsteadOfOwner(t *testing.T) {
	ts, service, fake := directoryFixture(t)
	policies := model.NewPolicyStore(ts)
	directoryRoles := func() []string {
		bindings, _ := policies.ListForPrincipal(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "dana"})
		var roles []string
		for _, binding := range bindings {
			if binding.GrantedBy == grantedBy {
				roles = append(roles, binding.RoleID)
			}
		}
		return roles
	}
	fake.set(Entry{DN: "uid=dana,dc=example,dc=test", Login: "dana", Admin: true}, "pw")
	if _, err := service.Authenticate(t.Context(), "dana", "pw"); err != nil {
		t.Fatal(err)
	}
	if roles := directoryRoles(); len(roles) != 1 || roles[0] != authz.RoleSystemOwner {
		t.Fatalf("default directory role = %v, want system.owner for compatibility", roles)
	}
	if err := service.Configure(Settings{Enabled: true, AdminGroupDN: "cn=admins,dc=example,dc=test", AdminRole: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(t.Context(), "dana", "pw"); err != nil {
		t.Fatal(err)
	}
	if roles := directoryRoles(); len(roles) != 1 || roles[0] != authz.RoleSystemAdmin {
		t.Fatalf("directory role after ldap_admin_role=admin = %v, want only system.admin", roles)
	}
	engine := authz.New(ts)
	check := func(action authz.Action) bool {
		decision, err := engine.Check(t.Context(), authz.Request{
			Actor: model.PrincipalRef{Kind: model.PrincipalUser, ID: "dana"}, Action: action,
			Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		})
		return err == nil && decision.Allowed
	}
	if !check(authz.SystemManage) || check(authz.AuthorizationRolesWrite) {
		t.Fatalf("system.admin: manage=%v roles.write=%v, want administration without role assignment", check(authz.SystemManage), check(authz.AuthorizationRolesWrite))
	}
}

func TestSyncDisablesRemovedAndDisabledAccountsWithoutDeleting(t *testing.T) {
	ts, service, fake := directoryFixture(t)
	for _, login := range []string{"erin", "frank", "gina"} {
		fake.set(Entry{DN: "uid=" + login + ",dc=example,dc=test", GUID: "guid-" + login, Login: login, DisplayName: login}, "pw")
		if _, err := service.Authenticate(t.Context(), login, "pw"); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "owner", "Owner", "owner-password"); err != nil {
		t.Fatal(err)
	}
	fake.set(Entry{DN: "uid=erin,dc=example,dc=test", GUID: "guid-erin", Login: "erin", DisplayName: "Erin Updated", Addresses: []string{"erin@example.test"}}, "pw")
	fake.set(Entry{DN: "uid=frank,dc=example,dc=test", GUID: "guid-frank", Login: "frank", Disabled: true}, "pw")
	fake.remove("gina")
	result, err := service.Sync(t.Context(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if result.Accounts != 3 || result.Updated != 1 || result.Disabled != 2 || result.Failed != 0 || !result.OK {
		t.Fatalf("sync result = %+v", result)
	}
	users := ts.UserStore()
	erin, _ := users.Get(t.Context(), "erin")
	if erin.DisplayName != "Erin Updated" || !erin.Enabled {
		t.Fatalf("erin = %+v", erin)
	}
	if identity, err := users.GetEmailAddress(t.Context(), "erin@example.test"); err != nil || identity.UserID != "erin" {
		t.Fatalf("sync did not add erin's address: %+v, %v", identity, err)
	}
	for _, login := range []string{"frank", "gina"} {
		user, err := users.Get(t.Context(), login)
		if err != nil || user.Enabled || !user.DirectoryDisabled {
			t.Fatalf("%s after sync = %+v, %v (want kept and disabled)", login, user, err)
		}
		if _, err := ts.FolderStore().GetByPath(t.Context(), login, "INBOX"); err != nil {
			t.Fatalf("%s lost data: %v", login, err)
		}
	}
	if owner, _ := users.Get(t.Context(), "owner"); !owner.Enabled {
		t.Fatal("sync disabled a local account")
	}
	// Re-enabled in the directory: sync restores the account it disabled.
	fake.set(Entry{DN: "uid=frank,dc=example,dc=test", GUID: "guid-frank", Login: "frank"}, "pw")
	if result, err = service.Sync(t.Context(), "test"); err != nil || result.Enabled != 1 {
		t.Fatalf("re-enable sync = %+v, %v", result, err)
	}
	if frank, _ := users.Get(t.Context(), "frank"); !frank.Enabled || frank.DirectoryDisabled {
		t.Fatalf("frank = %+v", frank)
	}
	// An empty directory answer never disables everyone.
	fake.mu.Lock()
	fake.entries = map[string]Entry{}
	fake.mu.Unlock()
	if result, err = service.Sync(t.Context(), "test"); err != nil || result.Disabled != 0 || result.Warning == "" {
		t.Fatalf("empty directory sync = %+v, %v", result, err)
	}
	// A failed directory search changes nothing and is recorded.
	fake.err = ErrUnavailable
	if _, err := service.Sync(t.Context(), "test"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable sync error = %v", err)
	}
	status, err := service.Status(t.Context())
	if err != nil || status.LastSync == nil || status.LastSync.OK || status.Accounts != 3 || status.DisabledAccounts != 1 {
		t.Fatalf("status = %+v, %v", status, err)
	}
}

func TestDisabledDirectoryRefusesSignInAndSync(t *testing.T) {
	_, service, _ := directoryFixture(t)
	if err := service.Configure(Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(t.Context(), "alice", "pw"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled sign-in error = %v", err)
	}
	if _, err := service.Sync(t.Context(), "test"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled sync error = %v", err)
	}
}
