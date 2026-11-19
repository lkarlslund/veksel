package app

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Support access shows and changes the supported account's personal
// settings, never the administrator's, and keeps their credentials,
// sharing and synchronization out of reach.
func TestSupportAccessSettingsAreTheSupportedAccounts(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob Example", "password123"); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) (int, string) {
		t.Helper()
		resp := authenticatedJSON(t, client, method, server.URL+path, csrf, body)
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(data)
	}
	if status, body := call(http.MethodPut, "/api/v1/session/impersonation", `{"subject_id":"bob","password":"password123","reason":"set up auto-reply"}`); status != http.StatusOK {
		t.Fatalf("impersonate status=%d body=%s", status, body)
	}

	status, body := call(http.MethodGet, "/api/v1/user/settings", "")
	if status != http.StatusOK || !strings.Contains(body, `"id":"bob"`) || !strings.Contains(body, `"support_access":true`) {
		t.Fatalf("settings during support access status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodPut, "/api/v1/user/vacation", `{"enabled":true,"subject":"Away","message":"Back Monday"}`); status != http.StatusOK {
		t.Fatalf("vacation status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodPatch, "/api/v1/user/profile", `{"current_password":"password123","new_password":"another-password"}`); status != http.StatusForbidden {
		t.Fatalf("password change during support access status=%d body=%s", status, body)
	}
	for _, path := range []string{"/api/v1/user/app-passwords", "/api/v1/user/api-keys", "/api/v1/user/two-factor", "/api/v1/user/browser-sessions", "/api/v1/user/webhooks", "/api/v1/grants", "/api/v1/share-links", "/api/v1/sync-jobs", "/api/v1/user/export"} {
		if status, body := call(http.MethodGet, path, ""); status != http.StatusForbidden || !strings.Contains(body, "support access") {
			t.Errorf("GET %s during support access status=%d body=%s", path, status, body)
		}
	}
	pages := testClient(t)
	pages.Jar = client.Jar
	pages.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := pages.Get(server.URL + "/app/settings/app-passwords")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/app/settings/profile" {
		t.Fatalf("refused settings page status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, err = pages.Get(server.URL + "/app/settings/profile")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(page), "Support access") || strings.Contains(string(page), `href="/app/settings/app-passwords"`) {
		t.Fatal("the settings page neither names support access nor hides the administrator-only sections")
	}

	bob, err := ts.UserStore().Get(t.Context(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := ts.UserStore().Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !bob.VacationEnabled || bob.VacationMessage != "Back Monday" || alice.VacationEnabled {
		t.Fatalf("auto-reply went to the wrong account: bob=%v alice=%v", bob.VacationEnabled, alice.VacationEnabled)
	}

	if status, body := call(http.MethodDelete, "/api/v1/session/impersonation", ""); status != http.StatusOK {
		t.Fatalf("stop status=%d body=%s", status, body)
	}
	status, body = call(http.MethodGet, "/api/v1/user/settings", "")
	if status != http.StatusOK || !strings.Contains(body, `"id":"alice"`) || strings.Contains(body, "support_access") {
		t.Fatalf("own settings after support access status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodGet, "/api/v1/user/app-passwords", ""); status != http.StatusOK {
		t.Fatalf("own application passwords status=%d body=%s", status, body)
	}
}
