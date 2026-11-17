package app

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestUserMCPKeyLifecycle(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys", "", `{"name":"Laptop"}`)
	if response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("create without CSRF status = %d", response.StatusCode)
	}
	response.Body.Close()

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys", csrf, `{"name":"Laptop"}`)
	if response.StatusCode != http.StatusCreated {
		response.Body.Close()
		t.Fatalf("create status = %d", response.StatusCode)
	}
	var created userAPIKeyView
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if created.Secret == "" || len(created.Scopes) != 1 || created.Scopes[0] != model.APIKeyScopeMCPRead {
		t.Fatalf("unexpected issued key: %#v", created)
	}
	originalSecret := created.Secret

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys/"+created.ID+"/rotate", "", "")
	if response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("rotate without CSRF status = %d", response.StatusCode)
	}
	response.Body.Close()
	other, _, err := model.NewAPIKeyStore(typed).CreateWithScopes(t.Context(), "bob", "Bob key", []string{model.APIKeyScopeMCPRead})
	if err != nil {
		t.Fatal(err)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys/"+other.ID+"/rotate", csrf, "")
	if response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("rotate other owner status = %d", response.StatusCode)
	}
	response.Body.Close()
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys/missing/rotate", csrf, "")
	if response.StatusCode != http.StatusNotFound {
		response.Body.Close()
		t.Fatalf("rotate missing status = %d", response.StatusCode)
	}
	response.Body.Close()

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys/"+created.ID+"/rotate", csrf, "")
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("rotate status = %d", response.StatusCode)
	}
	var rotated userAPIKeyView
	if err := json.NewDecoder(response.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if rotated.ID != created.ID || rotated.Secret == "" || rotated.Secret == originalSecret || rotated.RotationCount != 1 || rotated.RotatedAt == "" || rotated.LastUsedAt != "" {
		t.Fatalf("rotated key = %#v", rotated)
	}
	keyStore := model.NewAPIKeyStore(typed)
	if matched, err := keyStore.GetBySecret(t.Context(), originalSecret); err != nil || matched != nil {
		t.Fatalf("old secret authenticates after REST rotation: key=%+v err=%v", matched, err)
	}
	if matched, err := keyStore.GetBySecret(t.Context(), rotated.Secret); err != nil || matched == nil || matched.ID != created.ID {
		t.Fatalf("replacement does not authenticate: key=%+v err=%v", matched, err)
	}
	rotations, err := audit.New(typed).QueryReverse(t.Context(), time.Time{}, "api_key.rotate", "alice", 10)
	if err != nil || len(rotations) != 1 || rotations[0].Target != created.ID || rotations[0].Details["rotation_count"] != "1" {
		t.Fatalf("rotation audit = %#v, %v", rotations, err)
	}

	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/user/api-keys", "", "")
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("list status = %d", response.StatusCode)
	}
	var listed []userAPIKeyView
	if err := json.NewDecoder(response.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(listed) != 1 || listed[0].ID != created.ID || listed[0].Secret != "" || listed[0].RotationCount != 1 || listed[0].RotatedAt == "" {
		t.Fatalf("listed key leaks or differs: %#v", listed)
	}

	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/user/api-keys/"+created.ID, csrf, "")
	if response.StatusCode != http.StatusNoContent {
		response.Body.Close()
		t.Fatalf("revoke status = %d", response.StatusCode)
	}
	response.Body.Close()
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys/"+created.ID+"/rotate", csrf, "")
	if response.StatusCode != http.StatusConflict {
		response.Body.Close()
		t.Fatalf("rotate revoked status = %d", response.StatusCode)
	}
	response.Body.Close()

	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/user/api-keys", "", "")
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Fatalf("revoked key remained visible: %#v", listed)
	}
}

func TestUserMCPWriteKeyRequiresExplicitOptIn(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys", csrf, `{"name":"Trusted writer","write_access":true}`)
	if response.StatusCode != http.StatusCreated {
		response.Body.Close()
		t.Fatalf("create write key status = %d", response.StatusCode)
	}
	var created userAPIKeyView
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	wantScopes := []string{model.APIKeyScopeMCPRead, model.APIKeyScopeMCPWrite}
	if len(created.Scopes) != len(wantScopes) || created.Scopes[0] != wantScopes[0] || created.Scopes[1] != wantScopes[1] {
		t.Fatalf("write key scopes = %#v, want %#v", created.Scopes, wantScopes)
	}

	entries, err := audit.New(typed).QueryReverse(t.Context(), time.Time{}, "api_key.create", "alice", 10)
	if err != nil || len(entries) != 1 || entries[0].Details["scopes"] != "mcp.read,mcp.write" {
		t.Fatalf("write-key audit evidence = %#v, error = %v", entries, err)
	}
}

func TestRESTKeyScopesAreAdministratorOnlyAndCannotEscalate(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys", csrf, `{"name":"Automation","scopes":["api.read","api.write"]}`)
	var created userAPIKeyView
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || len(created.Scopes) != 2 || created.Scopes[0] != model.APIKeyScopeAPIRead || created.Scopes[1] != model.APIKeyScopeAPIWrite {
		t.Fatalf("administrator REST key: status %d, %#v", response.StatusCode, created)
	}
	if got := keyRequest(t, http.MethodGet, server.URL+"/api/v1/admin/users", created.Secret, ""); got != http.StatusOK {
		t.Fatalf("issued REST key read status = %d", got)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/api-keys", csrf, `{"name":"Bad","scopes":["root"]}`)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown scope status = %d", response.StatusCode)
	}

	// A key-manager key cannot mint or re-issue write access it lacks.
	manager := issueKey(t, typed, "alice", model.APIKeyScopeAPIRead, model.APIKeyScopeKeysManage)
	if got := keyRequest(t, http.MethodPost, server.URL+"/api/v1/user/api-keys", manager, `{"name":"Escalate","scopes":["api.write"]}`); got != http.StatusForbidden {
		t.Fatalf("escalating key status = %d", got)
	}
	if got := keyRequest(t, http.MethodPost, server.URL+"/api/v1/user/api-keys/"+created.ID+"/rotate", manager, ""); got != http.StatusForbidden {
		t.Fatalf("escalating rotation status = %d", got)
	}
	if got := keyRequest(t, http.MethodPost, server.URL+"/api/v1/user/api-keys", manager, `{"name":"Reader","scopes":["api.read"]}`); got != http.StatusCreated {
		t.Fatalf("subset key status = %d", got)
	}

	// Ordinary users can issue MCP keys only.
	if err := model.NewUserStore(typed).Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	resp, err := bob.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	bobCSRF := csrfCookieValue(t, bob, server.URL)
	resp, err = bob.PostForm(server.URL+"/app/login", url.Values{"_csrf": {bobCSRF}, "username": {"bob"}, "password": {"password123"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	response = authenticatedJSON(t, bob, http.MethodPost, server.URL+"/api/v1/user/api-keys", bobCSRF, `{"name":"Mine","scopes":["api.read"]}`)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin REST key status = %d", response.StatusCode)
	}
	response = authenticatedJSON(t, bob, http.MethodPost, server.URL+"/api/v1/user/api-keys", bobCSRF, `{"name":"Mine","scopes":["mcp.read"]}`)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("non-admin MCP key status = %d", response.StatusCode)
	}
}
