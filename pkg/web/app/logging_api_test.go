package app

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

func TestManagedModuleLoggingAPI(t *testing.T) {
	server, _, configuration, _, _ := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	if err := logpkg.ConfigureModules(configuration.Current().Config.LogModuleLevels); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logpkg.ConfigureModules(logpkg.DefaultModuleLevels()) })

	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/logging", "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET logging status = %d", response.StatusCode)
	}
	var initial loggingResponse
	if err := json.NewDecoder(response.Body).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if initial.Revision == "" || initial.Directory == "" || initial.FilePattern != "veksel-YYYY-MM-DD.log" {
		t.Fatalf("incomplete logging response: %+v", initial)
	}
	if len(initial.Modules) != len(logpkg.DefaultModuleLevels()) {
		t.Fatalf("modules = %d, want %d", len(initial.Modules), len(logpkg.DefaultModuleLevels()))
	}

	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/logging", csrf,
		`{"revision":"`+initial.Revision+`","levels":{"imap":"trace"}}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PATCH logging status = %d", response.StatusCode)
	}
	var updated loggingResponse
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if updated.Revision == initial.Revision {
		t.Fatal("module logging patch did not advance configuration revision")
	}
	found := false
	for _, module := range updated.Modules {
		if module.ID == logpkg.ModuleIMAP {
			found = true
			if module.Level != "trace" {
				t.Fatalf("IMAP level = %q", module.Level)
			}
		}
	}
	if !found || configuration.Current().Config.LogModuleLevels["imap"] != "trace" {
		t.Fatal("IMAP module level was not persisted")
	}

	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/logging", csrf,
		`{"revision":"`+updated.Revision+`","levels":{"unknown":"debug"}}`)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown module status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestAdminLogEntriesAPI(t *testing.T) {
	server, ts, configuration, _, _ := managedTestApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "owner")
	dir := configuration.Current().Config.LogDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	contents := "2026-08-27T08:00:00Z INFO web: page opened\n" +
		"2026-08-27T09:00:00Z ERROR smtp: delivery rejected recipient=hidden\n"
	if err := os.WriteFile(filepath.Join(dir, "veksel-2026-08-27.log"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/logging/entries?module=smtp&level=error&q=recipient&limit=25", "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET entries status = %d", response.StatusCode)
	}
	var page logpkg.LogPage
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(page.Records) != 1 || page.Records[0].Module != "smtp" || page.Records[0].Level != "ERROR" {
		t.Fatalf("entries = %+v", page.Records)
	}

	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/logging/entries?module=smtp&min_level=warn&q=delivery", "", "")
	page = logpkg.LogPage{}
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(page.Records) != 1 || page.Records[0].Level != "ERROR" || page.HeadCursor == "" {
		t.Fatalf("minimum level page = %+v", page)
	}
	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/logging/entries?module=smtp&after="+page.HeadCursor, "", "")
	follow := logpkg.LogPage{}
	if err := json.NewDecoder(response.Body).Decode(&follow); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || len(follow.Records) != 0 || follow.HeadCursor == "" {
		t.Fatalf("follow status = %d page = %+v", response.StatusCode, follow)
	}

	for _, query := range []string{"?limit=201", "?level=nope", "?min_level=nope", "?module=nope", "?cursor=nope", "?after=nope", "?after=" + page.HeadCursor + "&cursor=" + page.HeadCursor} {
		response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/logging/entries"+query, "", "")
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("query %q status = %d", query, response.StatusCode)
		}
		_ = response.Body.Close()
	}

	unauthenticated, err := http.Get(server.URL + "/api/v1/admin/logging/entries")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.StatusCode)
	}
	if err := ts.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	ordinary := testClient(t)
	loginExistingUser(t, ordinary, server.URL, "ordinary")
	forbidden, err := ordinary.Get(server.URL + "/api/v1/admin/logging/entries")
	if err != nil {
		t.Fatal(err)
	}
	_ = forbidden.Body.Close()
	if forbidden.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user status = %d", forbidden.StatusCode)
	}
}
