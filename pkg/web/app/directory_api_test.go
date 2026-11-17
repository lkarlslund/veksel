package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/directory"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
)

// passwordDirectory accepts "password123" for the accounts it knows.
type passwordDirectory struct{ users *model.UserStore }

func (d passwordDirectory) Authenticate(ctx context.Context, login, password string) (model.User, error) {
	if password != "password123" {
		return model.User{}, errors.New("invalid")
	}
	return d.users.Get(ctx, login)
}

type stubDirectoryControl struct{ syncs int }

func (c *stubDirectoryControl) Status(context.Context) (directory.Status, error) {
	return directory.Status{Enabled: true, Accounts: 1}, nil
}

func (c *stubDirectoryControl) Sync(context.Context, string) (directory.SyncResult, error) {
	c.syncs++
	return directory.SyncResult{OK: true, Accounts: 1}, nil
}

func (c *stubDirectoryControl) Test(context.Context) (directory.Diagnostic, error) {
	return directory.Diagnostic{OK: true, Server: "ldaps://dc.example.test"}, nil
}

func TestDirectoryAccountSignsInWithSecondFactorAndCannotChangePassword(t *testing.T) {
	f := newTwoFactorFixture(t)
	if err := f.ts.UserStore().CreateUser(t.Context(), model.User{ID: "dave", DisplayName: "Dave", Source: model.UserSourceLDAP, DirectoryDN: "uid=dave,dc=example,dc=test"}); err != nil {
		t.Fatal(err)
	}
	verifier := protocolauth.New(f.ts)
	verifier.SetDirectory(passwordDirectory{users: f.ts.UserStore()})
	f.handler.ConfigurePasswordVerifier(verifier)

	client, csrf, location := f.passwordSignIn("dave")
	if location != "/app/" {
		t.Fatalf("directory sign-in redirected to %q", location)
	}
	if status, body, _ := f.do(client, http.MethodGet, "/api/v1/user/settings", "", ""); status != http.StatusOK || !strings.Contains(body, `"source":"ldap"`) {
		t.Fatalf("settings status=%d body=%s", status, body)
	}
	if status, body, _ := f.do(client, http.MethodPatch, "/api/v1/user/profile", csrf, `{"current_password":"password123","new_password":"new-password-1"}`); status != http.StatusConflict || !strings.Contains(body, "managed by the directory") {
		t.Fatalf("self-service password change status=%d body=%s", status, body)
	}
	if status, body, _ := f.do(f.ownerClient, http.MethodPatch, "/api/v1/admin/users/dave", f.ownerCSRF, `{"display_name":"Dave","password":"new-password-1"}`); status != http.StatusConflict {
		t.Fatalf("admin password reset status=%d body=%s", status, body)
	}
	if status, body, _ := f.do(f.ownerClient, http.MethodGet, "/api/v1/admin/users", "", ""); status != http.StatusOK || !strings.Contains(body, `"source":"ldap"`) {
		t.Fatalf("admin users status=%d body=%s", status, body)
	}

	// A directory password is only the first factor.
	f.enrolTOTP("dave", client, csrf)
	if _, _, location := f.passwordSignIn("dave"); location != "/app/login/second-factor" {
		t.Fatalf("directory sign-in with a second factor redirected to %q", location)
	}
}

func TestDirectoryAdministrationAPI(t *testing.T) {
	f := newTwoFactorFixture(t)
	if status, _, _ := f.do(f.ownerClient, http.MethodGet, "/api/v1/admin/directory", "", ""); status != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured directory status=%d", status)
	}
	control := &stubDirectoryControl{}
	f.handler.ConfigureDirectory(control)
	if status, body, _ := f.do(f.ownerClient, http.MethodGet, "/api/v1/admin/directory", "", ""); status != http.StatusOK || !strings.Contains(body, `"accounts":1`) {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if status, body, _ := f.do(f.ownerClient, http.MethodPost, "/api/v1/admin/directory/test", f.ownerCSRF, "{}"); status != http.StatusOK || !strings.Contains(body, "ldaps://dc.example.test") {
		t.Fatalf("test status=%d body=%s", status, body)
	}
	if status, _, _ := f.do(f.ownerClient, http.MethodPost, "/api/v1/admin/directory/sync", f.ownerCSRF, "{}"); status != http.StatusOK || control.syncs != 1 {
		t.Fatalf("sync status=%d syncs=%d", status, control.syncs)
	}
	if err := f.ts.UserStore().Create(t.Context(), "erin", "Erin", "password123"); err != nil {
		t.Fatal(err)
	}
	client, csrf, _ := f.passwordSignIn("erin")
	if status, _, _ := f.do(client, http.MethodPost, "/api/v1/admin/directory/sync", csrf, "{}"); status != http.StatusForbidden || control.syncs != 1 {
		t.Fatalf("non-admin sync status=%d syncs=%d", status, control.syncs)
	}
}

func TestDirectoryBindPasswordIsRedacted(t *testing.T) {
	server, _, configuration, _, _ := managedTestApp(t)
	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "owner")
	secret := "directory-bind-secret-never-returned"
	response := authenticatedJSON(t, admin, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+configuration.Current().Revision+`","reason":"directory","settings":{"ldap_bind_dn":"cn=veksel,dc=example,dc=test","ldap_bind_password":"`+secret+`"}}`)
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(body), secret) {
		t.Fatalf("PATCH config status=%d body=%s", response.StatusCode, body)
	}
	if configuration.Current().Config.LdapBindPassword != secret {
		t.Fatal("bind password was not stored")
	}
	for _, path := range []string{"/api/v1/admin/settings", "/api/v1/admin/config", "/api/v1/admin/config/history?limit=5"} {
		response := authenticatedJSON(t, admin, http.MethodGet, server.URL+path, "", "")
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || strings.Contains(string(body), secret) {
			t.Fatalf("%s status=%d leaked=%t", path, response.StatusCode, strings.Contains(string(body), secret))
		}
	}
}
