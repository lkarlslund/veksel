package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// keyRequest performs a request authenticated only by an X-API-Key.
func keyRequest(t *testing.T, method, endpoint, key, body string) int {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		request.Header.Set(apiKeyHeader, key)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode
}

func issueKey(t *testing.T, typed *model.TypedStore, userID string, scopes ...string) string {
	t.Helper()
	_, secret, err := model.NewAPIKeyStore(typed).CreateWithScopes(t.Context(), userID, "test", scopes)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestAPIKeyFrontEndAuthenticatesAdministratorsAndEnforcesScopes(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	users := model.NewUserStore(typed)
	if err := users.Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}

	adminRead := issueKey(t, typed, "alice", model.APIKeyScopeAPIRead)
	adminWrite := issueKey(t, typed, "alice", model.APIKeyScopeAPIRead, model.APIKeyScopeAPIWrite)
	adminMCP := issueKey(t, typed, "alice", model.APIKeyScopeMCPRead, model.APIKeyScopeMCPWrite)
	bobAll := issueKey(t, typed, "bob", model.APIKeyScopeAll)
	legacy := storeLegacyUserAPIKey(t, typed, "alice")

	for _, test := range []struct {
		name, method, path, key, body string
		want                          int
	}{
		{"unauthenticated", http.MethodGet, "/api/v1/admin/users", "", "", http.StatusUnauthorized},
		{"unknown key", http.MethodGet, "/api/v1/admin/users", "not-a-key", "", http.StatusUnauthorized},
		{"non-admin key on admin endpoint", http.MethodGet, "/api/v1/admin/users", bobAll, "", http.StatusForbidden},
		{"non-admin key on user endpoint", http.MethodGet, "/api/v1/user/settings", bobAll, "", http.StatusForbidden},
		{"MCP-only key", http.MethodGet, "/api/v1/admin/users", adminMCP, "", http.StatusForbidden},
		{"read key reads", http.MethodGet, "/api/v1/admin/users", adminRead, "", http.StatusOK},
		{"read key cannot write", http.MethodPost, "/api/v1/admin/domains", adminRead, `{"id":"read.test"}`, http.StatusForbidden},
		{"write key writes without CSRF", http.MethodPost, "/api/v1/admin/domains", adminWrite, `{"id":"write.test"}`, http.StatusCreated},
		{"write key cannot manage keys", http.MethodPost, "/api/v1/user/api-keys", adminWrite, `{"name":"x"}`, http.StatusForbidden},
		{"retired per-user key is refused", http.MethodGet, "/api/v1/admin/users", legacy, "", http.StatusUnauthorized},
		{"browser-only route refuses keys", http.MethodGet, "/api/v1/session", adminWrite, "", http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := keyRequest(t, test.method, server.URL+test.path, test.key, test.body); got != test.want {
				t.Fatalf("%s %s status = %d, want %d", test.method, test.path, got, test.want)
			}
		})
	}

	// Session-authenticated changes still require the CSRF token.
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains", "", `{"id":"session.test"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("session write without CSRF status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains", csrf, `{"id":"session.test"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("session write with CSRF status = %d, want %d", response.StatusCode, http.StatusCreated)
	}

	// Promotion to administrator admits Bob's key; disabling him revokes it.
	if _, err := model.NewPolicyStore(typed).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		Effect:    model.EffectAllow, RoleID: "system.owner", Inheritance: model.InheritanceSubtree,
		GrantedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if got := keyRequest(t, http.MethodGet, server.URL+"/api/v1/admin/users", bobAll, ""); got != http.StatusOK {
		t.Fatalf("promoted owner status = %d, want %d", got, http.StatusOK)
	}
	if err := users.Update(t.Context(), "bob", func(user *model.User) { user.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	if got := keyRequest(t, http.MethodGet, server.URL+"/api/v1/admin/users", bobAll, ""); got != http.StatusUnauthorized {
		t.Fatalf("disabled owner status = %d, want %d", got, http.StatusUnauthorized)
	}
}

// TestRouterRequestScopeHonoursRevocation proves that authorization checks
// share policy bindings only within one ordinary request: a grant revoked
// mid-request stays visible to that request, the next request observes the
// revocation, and changing and streaming routes are never scoped.
func TestRouterRequestScopeHonoursRevocation(t *testing.T) {
	handler, typed := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := typed.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	policies := model.NewPolicyStore(typed)
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	inbox := model.ResourceRef{Kind: model.ResourceFolder, ID: "alice:INBOX"}
	grant := func() string {
		binding, err := policies.Create(t.Context(), model.PolicyBinding{
			Principal: bob, Resource: inbox, Effect: model.EffectAllow, RoleID: authz.RoleFolderViewer,
			Inheritance: model.InheritanceSelf, GrantedBy: "alice",
		})
		if err != nil {
			t.Fatal(err)
		}
		return binding.ID
	}

	// The probe checks Bob's access, revokes his grant, and checks again.
	var grantID string
	probe := func(w http.ResponseWriter, r *http.Request) {
		allowed := func() bool {
			decision, err := handler.authorizer.Check(r.Context(), authz.Request{Actor: bob, Action: authz.FolderItemsRead, Resource: inbox})
			if err != nil {
				t.Error(err)
			}
			return decision.Allowed
		}
		before := allowed()
		if grantID != "" {
			if err := policies.Delete(r.Context(), grantID); err != nil {
				t.Error(err)
			}
			grantID = ""
		}
		_, _ = fmt.Fprintf(w, "%t %t", before, allowed())
	}
	api := apiRouter{h: handler, mux: mux}
	api.handle("GET /probe/read", probe)
	api.handle("POST /probe/change", probe)
	api.handleBulk("POST /probe/bulk", probe)
	api.stream("GET /probe/stream", probe)

	for _, tc := range []struct {
		name, method, path string
		granted            bool
		want               string
	}{
		{"read request is scoped", http.MethodGet, "/probe/read", true, "true true"},
		{"next request observes revocation", http.MethodGet, "/probe/read", false, "false false"},
		{"changing request is not scoped", http.MethodPost, "/probe/change", true, "true false"},
		{"bulk request is scoped", http.MethodPost, "/probe/bulk", true, "true true"},
		{"stream is not scoped", http.MethodGet, "/probe/stream", true, "true false"},
	} {
		if tc.granted {
			grantID = grant()
		}
		response := authenticatedJSON(t, client, tc.method, server.URL+tc.path, csrf, "")
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || string(body) != tc.want {
			t.Fatalf("%s: status=%d body=%q, want %q", tc.name, response.StatusCode, body, tc.want)
		}
	}

	streams := 0
	for _, route := range handler.apiRoutes {
		if route.Path == "/api/v1/events" {
			streams++
			if route.Scope != scopeNever {
				t.Fatalf("events route scope = %d, want scopeNever", route.Scope)
			}
		}
	}
	if streams != 1 {
		t.Fatalf("events route registered %d times, want 1", streams)
	}
}

// TestReadOnlyPostRoutesNeedOnlyReadScope proves that a read-only key can use
// POST routes that only read, cannot perform real writes, and that browser
// sessions still need a CSRF token on those routes.
func TestReadOnlyPostRoutesNeedOnlyReadScope(t *testing.T) {
	handler, typed := testHandler(t)
	handler.ConfigureSearch(&searchRecorder{})
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	read := issueKey(t, typed, "alice", model.APIKeyScopeAPIRead)

	status, archive, _ := keyDo(t, http.MethodPost, server.URL+"/api/v1/admin/backup/download?scope=system", read, nil)
	if status != http.StatusOK {
		t.Fatalf("read key backup download status = %d", status)
	}
	for _, test := range []struct {
		name, path string
		body       []byte
		want       int
	}{
		{"search query", "/api/v1/search/query", []byte(`{"text":"needle"}`), http.StatusOK},
		{"backup verify", "/api/v1/admin/backup/verify", archive, http.StatusOK},
		{"backup restore", "/api/v1/admin/backup/restore", archive, http.StatusForbidden},
		{"domain create", "/api/v1/admin/domains", []byte(`{"id":"read.test"}`), http.StatusForbidden},
		{"search rebuild", "/api/v1/search/index/rebuild", []byte(`{}`), http.StatusForbidden},
	} {
		if status, body, _ := keyDo(t, http.MethodPost, server.URL+test.path, read, test.body); status != test.want {
			t.Fatalf("%s with read key: status = %d, want %d (%s)", test.name, status, test.want, body)
		}
	}

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/search/query", "", `{"text":"needle"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("session search without CSRF status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	for _, route := range handler.apiRoutes {
		if route.ReadOnly && (route.Method != http.MethodPost || route.Access != apiAnyCredential) {
			t.Fatalf("read-only route %s %s must be a POST reachable by key", route.Method, route.Path)
		}
	}
}

// storeLegacyUserAPIKey writes a retired per-user API key hash straight into
// the user record, as releases before system schema 3 stored it, and returns
// the matching secret.
func storeLegacyUserAPIKey(t *testing.T, typed *model.TypedStore, userID string) string {
	t.Helper()
	const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hash, err := auth.HashPassword(secret)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := typed.Get(t.Context(), model.NSUsers, userID, &record); err != nil {
		t.Fatal(err)
	}
	record["api_key_hash"] = hash
	if err := typed.Set(t.Context(), model.NSUsers, userID, record); err != nil {
		t.Fatal(err)
	}
	return secret
}

// userReadCounter counts reads of user records, the only place a per-user
// API key hash could be compared.
type userReadCounter struct {
	*jsonstore.Store
	reads atomic.Int64
}

func (s *userReadCounter) count(namespace string) {
	if namespace == model.NSUsers {
		s.reads.Add(1)
	}
}

func (s *userReadCounter) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	s.count(namespace)
	return s.Store.Get(ctx, namespace, key)
}

func (s *userReadCounter) List(ctx context.Context, namespace string) ([]string, error) {
	s.count(namespace)
	return s.Store.List(ctx, namespace)
}

func (s *userReadCounter) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	s.count(namespace)
	return s.Store.Scan(ctx, namespace, prefix)
}

func (s *userReadCounter) Iterate(ctx context.Context, namespace, prefix string, fn store.IterCallback) error {
	s.count(namespace)
	return s.Store.Iterate(ctx, namespace, prefix, fn)
}

// TestInvalidAPIKeyDoesNotScanUsers proves that rejecting an unknown key
// costs only the named-key lookup: no user record is read, so no per-user
// hash can be compared, however many users hold a retired per-user key.
func TestInvalidAPIKeyDoesNotScanUsers(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	counter := &userReadCounter{Store: backend}
	handler, typed := testHandlerOn(t, counter)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	setupAndLogin(t, server, testClient(t), "alice")
	for _, user := range []string{"bob", "carol", "dave"} {
		if err := typed.UserStore().Create(t.Context(), user, user, "password123"); err != nil {
			t.Fatal(err)
		}
		storeLegacyUserAPIKey(t, typed, user)
	}
	valid := issueKey(t, typed, "alice", model.APIKeyScopeAPIRead)

	counter.reads.Store(0)
	if got := keyRequest(t, http.MethodGet, server.URL+"/api/v1/admin/users", "not-a-valid-key", ""); got != http.StatusUnauthorized {
		t.Fatalf("invalid key status = %d, want %d", got, http.StatusUnauthorized)
	}
	if reads := counter.reads.Load(); reads != 0 {
		t.Fatalf("invalid key read user records %d times", reads)
	}
	// A valid key does load its owner, which shows the counter observes reads.
	if got := keyRequest(t, http.MethodGet, server.URL+"/api/v1/admin/users", valid, ""); got != http.StatusOK {
		t.Fatalf("valid key status = %d, want %d", got, http.StatusOK)
	}
	if counter.reads.Load() == 0 {
		t.Fatal("user reads were not observed")
	}
}
