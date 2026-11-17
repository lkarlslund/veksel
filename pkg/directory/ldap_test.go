package directory

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	testBaseDN    = "dc=example,dc=test"
	testServiceDN = "cn=veksel,dc=example,dc=test"
	testAdminsDN  = "cn=admins,ou=groups,dc=example,dc=test"
)

func testDirectoryServer(t *testing.T) *testLDAPServer {
	t.Helper()
	server := newTestLDAPServer(t)
	server.add(testServiceDN, map[string][]string{"userPassword": {"service-secret"}})
	server.add("uid=alice,ou=people,dc=example,dc=test", map[string][]string{
		"objectClass": {"person"}, "uid": {"Alice"}, "cn": {"Alice A"}, "displayName": {"Alice Example"},
		"mail": {"alice@example.test"}, "entryUUID": {"8C2C3F38-0000-4000-8000-000000000001"}, "userPassword": {"alice-secret"},
	})
	server.add("uid=bob,ou=people,dc=example,dc=test", map[string][]string{
		"objectClass": {"person"}, "uid": {"bob"}, "cn": {"Bob"}, "mail": {"shared@example.test"}, "userPassword": {"bob-secret"},
		"userAccountControl": {"514"},
	})
	server.add("uid=carol,ou=people,dc=example,dc=test", map[string][]string{
		"objectClass": {"person"}, "uid": {"carol"}, "mail": {"shared@example.test"}, "userPassword": {"carol-secret"},
	})
	server.add(testAdminsDN, map[string][]string{"objectClass": {"groupOfNames"}, "member": {"UID=Alice,OU=People,DC=Example,DC=Test"}})
	return server
}

func testLDAPSettings(server *testLDAPServer) Settings {
	return Settings{
		Enabled: true, URLs: []string{server.url()}, CACertificate: server.caPEM,
		BindDN: testServiceDN, BindPassword: "service-secret", BaseDN: testBaseDN,
		UserFilter:   "(&(objectClass=person)(|(uid={login})(mail={login})))",
		IDAttributes: []string{"sAMAccountName", "uid"}, AdminGroupDN: testAdminsDN,
		SyncFilter: "(objectClass=person)", Timeout: 5 * time.Second,
	}
}

func TestUserFilterEscapesLogin(t *testing.T) {
	filter := UserFilter("(&(objectClass=person)(uid={login}))", " *)(uid=*)(|(uid=* ")
	if want := `(&(objectClass=person)(uid=\2a\29\28uid=\2a\29\28|\28uid=\2a))`; filter != want {
		t.Fatalf("filter = %s, want %s", filter, want)
	}
	compiled, err := ldap.CompileFilter(filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Children) != 2 {
		t.Fatalf("login changed the filter structure: %s", filter)
	}
}

func TestLDAPSearchThenBindOverStartTLS(t *testing.T) {
	server := testDirectoryServer(t)
	client, err := NewLDAP(testLDAPSettings(server))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	entry, err := client.Authenticate(t.Context(), "alice@example.test", "alice-secret")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Login != "alice" || entry.DisplayName != "Alice Example" || entry.GUID != "8c2c3f38-0000-4000-8000-000000000001" || !entry.Admin || !slices.Equal(entry.Addresses, []string{"alice@example.test"}) {
		t.Fatalf("entry = %+v", entry)
	}
	if binds := server.bindDNs(); !slices.Contains(binds, "uid=alice,ou=people,dc=example,dc=test") || binds[0] != testServiceDN {
		t.Fatalf("binds = %q, want service bind then user bind", binds)
	}
	if _, err := client.Authenticate(t.Context(), "alice", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
	// The pooled connection is rebound as the service account after a user bind.
	if _, err := client.Authenticate(t.Context(), "alice", "alice-secret"); err != nil {
		t.Fatalf("reused connection: %v", err)
	}
	if _, err := client.Authenticate(t.Context(), "*", "alice-secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wildcard login error = %v", err)
	}
	if _, err := client.Authenticate(t.Context(), "alice)(uid=*", "alice-secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("injected login error = %v", err)
	}
}

func TestLDAPRejectsEmptyPasswordAndAmbiguousLogins(t *testing.T) {
	server := testDirectoryServer(t)
	client, err := NewLDAP(testLDAPSettings(server))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	before := len(server.bindDNs())
	// The test server, like many real ones, accepts an unauthenticated bind.
	if _, err := client.Authenticate(t.Context(), "alice", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty password error = %v", err)
	}
	if binds := server.bindDNs(); len(binds) != before {
		t.Fatalf("empty password reached the directory: %q", binds[before:])
	}
	if _, err := client.Authenticate(t.Context(), "shared@example.test", "carol-secret"); !errors.Is(err, ErrAmbiguousLogin) {
		t.Fatalf("ambiguous login error = %v", err)
	}
	for _, bind := range server.bindDNs() {
		if strings.Contains(bind, "carol") {
			t.Fatal("ambiguous login bound as a matching entry")
		}
	}
}

func TestLDAPFailsOverAndRequiresTrustedCertificate(t *testing.T) {
	server := testDirectoryServer(t)
	settings := testLDAPSettings(server)
	settings.URLs = []string{"ldap://127.0.0.1:1", server.url()}
	client, err := NewLDAP(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authenticate(t.Context(), "alice", "alice-secret"); err != nil {
		t.Fatalf("failover: %v", err)
	}
	client.Close()

	settings.CACertificate = ""
	untrusted, err := NewLDAP(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	if _, err := untrusted.Authenticate(t.Context(), "alice", "alice-secret"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("untrusted certificate error = %v", err)
	}
	diagnostic := untrusted.Test(t.Context())
	if diagnostic.OK || len(diagnostic.Steps) != 1 || diagnostic.Steps[0].OK {
		t.Fatalf("diagnostic = %+v", diagnostic)
	}
}

func TestLDAPUsersAndRedactedDiagnostic(t *testing.T) {
	server := testDirectoryServer(t)
	client, err := NewLDAP(testLDAPSettings(server))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	users, err := client.Users(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	logins := map[string]Entry{}
	for _, user := range users {
		logins[user.Login] = user
	}
	if len(logins) != 3 || !logins["bob"].Disabled || logins["carol"].Disabled || !logins["alice"].Admin || logins["bob"].Admin {
		t.Fatalf("users = %+v", users)
	}
	if _, err := client.Users(t.Context(), 2); err == nil {
		t.Fatal("a sync larger than its bound returned a partial list")
	}
	diagnostic := client.Test(t.Context())
	if !diagnostic.OK || diagnostic.Transport != "starttls" || len(diagnostic.Sample) == 0 {
		t.Fatalf("diagnostic = %+v", diagnostic)
	}
	for _, step := range diagnostic.Steps {
		if strings.Contains(step.Detail, "service-secret") {
			t.Fatal("diagnostic exposes the service password")
		}
	}
}

func TestAddressesPreferMailThenPrimaryProxy(t *testing.T) {
	got := Addresses([]string{"Alice@Example.test"}, []string{"smtp:alias@example.test", "SMTP:primary@example.test", "X500:/o=ignored", "sip:alice@example.test", "smtp:ALICE@example.test"})
	if want := []string{"alice@example.test", "primary@example.test", "alias@example.test"}; !slices.Equal(got, want) {
		t.Fatalf("addresses = %q, want %q", got, want)
	}
}
