package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
)

// keyDo performs a request authenticated only by an X-API-Key and returns
// the status and body.
func keyDo(t *testing.T, method, endpoint, key string, body []byte) (int, []byte, http.Header) {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		request.Header.Set(apiKeyHeader, key)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, content, response.Header
}

// operationsApp starts an application with an administrator "admin" and
// returns the server URL, an all-scope administrator key, and the store.
func operationsApp(t *testing.T, configure func(*Handler, *model.TypedStore)) (string, string, *model.TypedStore) {
	t.Helper()
	handler, typed := testHandler(t)
	if configure != nil {
		configure(handler, typed)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	setupAndLogin(t, server, testClient(t), "admin")
	return server.URL, issueKey(t, typed, "admin", model.APIKeyScopeAll), typed
}

func TestPublicHealthProbesAndAuthenticatedBuildDetails(t *testing.T) {
	registry := health.New()
	base, key, typed := operationsApp(t, func(handler *Handler, _ *model.TypedStore) {
		handler.ConfigureBuildInfo(BuildInfo{Version: "1.2.3", Commit: "abc", StoreType: "json", StartTime: time.Now()})
		handler.ConfigureRuntimeHealth(registry, func(context.Context) {
			if err := registry.Replace(time.Now(), []health.Observation{
				{ID: "http", Label: "HTTP", Kind: "listener", Desired: true, Required: true, State: health.StateHealthy},
				{ID: "imap", Label: "IMAP", Kind: "listener", State: health.StateDisabled},
				{ID: "queue", Label: "System queue", Kind: "dependency", Desired: true, Required: true, State: health.StateUnavailable, Reason: "worker stopped"},
			}); err != nil {
				t.Errorf("replace runtime health: %v", err)
			}
		})
	})

	status, body, _ := keyDo(t, http.MethodGet, base+"/api/v1/health", "", nil)
	if status != http.StatusOK || strings.Contains(string(body), "1.2.3") {
		t.Fatalf("anonymous health = %d %s", status, body)
	}
	if status, _, _ := keyDo(t, http.MethodGet, base+"/api/v1/health", "wrong", nil); status != http.StatusUnauthorized {
		t.Fatalf("invalid key health status = %d", status)
	}
	status, body, _ = keyDo(t, http.MethodGet, base+"/api/v1/health", key, nil)
	var detailed healthResponse
	if err := json.Unmarshal(body, &detailed); err != nil || status != http.StatusOK || detailed.Version != "1.2.3" || detailed.StoreType != "json" {
		t.Fatalf("key health = %d %s", status, body)
	}
	if err := model.NewUserStore(typed).Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := keyDo(t, http.MethodGet, base+"/api/v1/health", issueKey(t, typed, "bob", model.APIKeyScopeAll), nil); status != http.StatusForbidden {
		t.Fatalf("non-admin key health status = %d", status)
	}

	status, body, _ = keyDo(t, http.MethodGet, base+"/api/v1/health/ready", "", nil)
	var ready readinessResponse
	if err := json.Unmarshal(body, &ready); err != nil || status != http.StatusServiceUnavailable || ready.Status != "unavailable" || len(ready.Components) != 3 {
		t.Fatalf("ready = %d %s", status, body)
	}
	for _, component := range ready.Components {
		if component.Name == "imap" && component.Status != "ok" || component.Name == "queue" && (component.Status != "unavailable" || component.Reason != "worker stopped") {
			t.Fatalf("component = %#v", component)
		}
	}
	if status, body, _ := keyDo(t, http.MethodGet, base+"/api/v1/health/live", "", nil); status != http.StatusOK || !strings.Contains(string(body), "alive") {
		t.Fatalf("live = %d %s", status, body)
	}
}

func TestAdminMetricsAndServerControlRequireAdministrator(t *testing.T) {
	restarts := make(chan struct{}, 1)
	base, key, _ := operationsApp(t, func(handler *Handler, typed *model.TypedStore) {
		collector := metrics.New(typed.Store())
		collector.IncrementCounter("http_requests", map[string]string{"handler": "test"})
		collector.Flush()
		handler.ConfigureMetrics(collector)
		handler.ConfigureServerControl(func() { restarts <- struct{}{} }, nil)
	})

	if status, _, _ := keyDo(t, http.MethodGet, base+"/api/v1/admin/metrics", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("anonymous metrics status = %d", status)
	}
	status, body, _ := keyDo(t, http.MethodGet, base+"/api/v1/admin/metrics", key, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "http_requests") {
		t.Fatalf("metrics = %d %s", status, body)
	}
	status, body, header := keyDo(t, http.MethodGet, base+"/api/v1/admin/metrics/prometheus", key, nil)
	if status != http.StatusOK || !strings.HasPrefix(header.Get("Content-Type"), "text/plain") || !strings.Contains(string(body), "http_requests") {
		t.Fatalf("prometheus = %d %q %s", status, header.Get("Content-Type"), body)
	}

	if status, _, _ := keyDo(t, http.MethodPost, base+"/api/v1/admin/server/restart", key, nil); status != http.StatusAccepted {
		t.Fatalf("restart status = %d", status)
	}
	select {
	case <-restarts:
	case <-time.After(time.Second):
		t.Fatal("restart callback not called")
	}
	if status, _, _ := keyDo(t, http.MethodPost, base+"/api/v1/admin/server/shutdown", key, nil); status != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured shutdown status = %d", status)
	}
}

func TestAdminSystemBackupRestoresIntoRunningServer(t *testing.T) {
	base, key, typed := operationsApp(t, nil)
	domains := model.NewDomainStore(typed)
	if err := domains.Create(t.Context(), "keep.test"); err != nil {
		t.Fatal(err)
	}

	status, archive, header := keyDo(t, http.MethodPost, base+"/api/v1/admin/backup/download?scope=system", key, nil)
	if status != http.StatusOK || header.Get("Content-Type") != "application/gzip" {
		t.Fatalf("system backup = %d %q", status, header.Get("Content-Type"))
	}
	if meta, err := backup.ValidateBackup(bytes.NewReader(archive)); err != nil || meta.Version != "v2" {
		t.Fatalf("system backup = %+v, %v", meta, err)
	}
	if status, _, _ := keyDo(t, http.MethodPost, base+"/api/v1/admin/backup/download?scope=bogus", key, nil); status != http.StatusBadRequest {
		t.Fatalf("invalid scope status = %d", status)
	}

	if err := domains.Create(t.Context(), "merge.test"); err != nil {
		t.Fatal(err)
	}
	if status, body, _ := keyDo(t, http.MethodPost, base+"/api/v1/admin/backup/restore?mode=merge", key, archive); status != http.StatusOK || !strings.Contains(string(body), `"mode":"merge"`) {
		t.Fatalf("merge restore = %d %s", status, body)
	}
	if _, err := domains.Get(t.Context(), "merge.test"); err != nil {
		t.Fatalf("merge removed newer data: %v", err)
	}
	if status, body, _ := keyDo(t, http.MethodPost, base+"/api/v1/admin/backup/restore", key, archive); status != http.StatusOK || !strings.Contains(string(body), `"mode":"replace"`) {
		t.Fatalf("replace restore = %d %s", status, body)
	}
	if _, err := domains.Get(t.Context(), "merge.test"); err == nil {
		t.Fatal("replace kept data newer than the archive")
	}
	if _, err := domains.Get(t.Context(), "keep.test"); err != nil {
		t.Fatalf("replace lost archived data: %v", err)
	}

	status, installation, _ := keyDo(t, http.MethodPost, base+"/api/v1/admin/backup/download", key, nil)
	if status != http.StatusOK {
		t.Fatalf("installation backup status = %d", status)
	}
	if status, body, _ := keyDo(t, http.MethodPost, base+"/api/v1/admin/backup/restore", key, installation); status != http.StatusBadRequest || !strings.Contains(string(body), "veksel restore") {
		t.Fatalf("live installation restore = %d %s", status, body)
	}
	if status, _, _ := keyDo(t, http.MethodPost, base+"/api/v1/admin/backup/restore?mode=bogus", key, archive); status != http.StatusBadRequest {
		t.Fatalf("invalid mode status = %d", status)
	}
}

func TestAdminUserSpamConfig(t *testing.T) {
	base, key, typed := operationsApp(t, nil)
	if err := model.NewUserStore(typed).Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	endpoint := base + "/api/v1/admin/users/bob/spam-config"
	status, body, _ := keyDo(t, http.MethodGet, endpoint, key, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"threshold":0`) { // 0 inherits the server junk threshold
		t.Fatalf("default spam config = %d %s", status, body)
	}
	status, body, _ = keyDo(t, http.MethodPut, endpoint, key, []byte(`{"enabled":true,"threshold":7.5}`))
	if status != http.StatusOK || string(bytes.TrimSpace(body)) != `{"enabled":true,"threshold":7.5}` {
		t.Fatalf("update spam config = %d %s", status, body)
	}
	if enabled, threshold, err := model.NewUserStore(typed).GetSpamConfig(t.Context(), "bob"); err != nil || !enabled || threshold != 7.5 {
		t.Fatalf("stored spam config = %v %v %v", enabled, threshold, err)
	}
	if status, _, _ := keyDo(t, http.MethodPut, endpoint, key, []byte(`{"threshold":51}`)); status != http.StatusBadRequest {
		t.Fatalf("out-of-range threshold status = %d", status)
	}
	if status, _, _ := keyDo(t, http.MethodGet, base+"/api/v1/admin/users/missing/spam-config", key, nil); status != http.StatusNotFound {
		t.Fatalf("missing user status = %d", status)
	}
}

func TestAPIReferenceDescribesRegisteredRoutesAndRequiresCredentials(t *testing.T) {
	base, key, _ := operationsApp(t, nil)
	for _, test := range []struct {
		name, path, key string
		want            int
	}{
		{"document anonymous", "/api/v1/swagger.json", "", http.StatusUnauthorized},
		{"document invalid key", "/api/v1/swagger.json", "wrong", http.StatusUnauthorized},
		{"viewer api key", "/api/docs/index.html", key, http.StatusOK},
	} {
		if status, _, _ := keyDo(t, http.MethodGet, base+test.path, test.key, nil); status != test.want {
			t.Fatalf("%s status = %d, want %d", test.name, status, test.want)
		}
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := noRedirect.Get(base + "/api/docs/index.html")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("anonymous viewer status = %d, want redirect", response.StatusCode)
	}

	status, body, _ := keyDo(t, http.MethodGet, base+"/api/v1/swagger.json", key, nil)
	var document struct {
		OpenAPI string                               `json:"openapi"`
		Paths   map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(body, &document); err != nil || status != http.StatusOK || document.OpenAPI != "3.0.3" {
		t.Fatalf("reference = %d %v", status, err)
	}
	domain := document.Paths["/api/v1/admin/domains/{id}"]["patch"]
	if domain == nil || domain["summary"] != "Admin update domain" || !strings.Contains(domain["description"].(string), "api.write") {
		t.Fatalf("domain operation = %#v", domain)
	}
	if session := document.Paths["/api/v1/session"]["get"]; session == nil || session["description"] != "Browser session only." {
		t.Fatalf("session operation = %#v", session)
	}
	if login := document.Paths["/api/v1/session/login"]["post"]; login == nil || len(login["security"].([]any)) != 0 {
		t.Fatalf("login operation = %#v", login)
	}
}

func TestHandlerSummary(t *testing.T) {
	handler := &Handler{}
	for _, test := range []struct {
		handler http.HandlerFunc
		want    string
	}{
		{handler.apiAdminDKIMKeys, "Admin DKIM keys"},
		{handler.apiWorkspaceMailAttachmentPreview, "Workspace mail attachment preview"},
		{handler.handleEvents, "Events"},
	} {
		if got := handlerSummary(test.handler); got != test.want {
			t.Errorf("handlerSummary = %q, want %q", got, test.want)
		}
	}
}
