package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/health"
)

func alertTestApp(t *testing.T) (*httptest.Server, *http.Client, string) {
	t.Helper()
	handler, ts := testHandler(t)
	registry := health.New()
	alerts, err := health.NewAlertStore(t.Context(), ts.Store())
	if err != nil {
		t.Fatal(err)
	}
	refresh := func(context.Context) {
		if replaceErr := registry.Replace(time.Now(), []health.Observation{{
			ID: "smtp", Label: "SMTP", Kind: "listener", Desired: true, Required: true,
			State: health.StateUnavailable, Severity: health.SeverityCritical, Reason: "bind failed",
		}}); replaceErr != nil {
			t.Errorf("replace health: %v", replaceErr)
		}
	}
	evaluator, err := health.NewEvaluator(registry, alerts, refresh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluator.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	handler.ConfigureRuntimeHealth(registry, refresh)
	handler.ConfigureHealthAlerts(alerts)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "admin")
	return server, admin, csrf
}

func TestAdminAlertLifecycleAPI(t *testing.T) {
	server, admin, csrf := alertTestApp(t)
	response := authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/alerts?state=active&limit=10", "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", response.StatusCode)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if strings.Contains(string(payload), `"acknowledged_at"`) || strings.Contains(string(payload), "0001-01-01") {
		t.Fatalf("unacknowledged alert exposes a false timestamp: %s", payload)
	}
	var listed adminAlertsResponse
	if err := json.Unmarshal(payload, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Alerts) != 1 || listed.Active != 1 || listed.Unacknowledged != 1 || listed.Critical != 1 || listed.Alerts[0].ID != "runtime:smtp" {
		t.Fatalf("listed alerts = %#v", listed)
	}
	response = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/alerts/runtime:smtp/acknowledge", csrf, `{}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("acknowledge status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/alerts/runtime:smtp/silence", csrf, `{"minutes":60,"reason":"planned maintenance"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("silence status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/alerts?state=active", "", "")
	if err := json.NewDecoder(response.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if listed.Unacknowledged != 0 || listed.Silenced != 1 || listed.Alerts[0].AcknowledgedBy != "admin" || listed.Alerts[0].SilenceReason != "planned maintenance" {
		t.Fatalf("operator state = %#v", listed)
	}
}

func TestAdminAlertAPIValidatesBoundsAndCSRF(t *testing.T) {
	server, admin, csrf := alertTestApp(t)
	for _, endpoint := range []string{"?state=unknown", "?limit=0", "?limit=501"} {
		response := authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/alerts"+endpoint, "", "")
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s status = %d, want 400", endpoint, response.StatusCode)
		}
	}
	response := authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/alerts/runtime:smtp/acknowledge", "", `{}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d, want 403", response.StatusCode)
	}
	response = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/alerts/runtime:smtp/silence", csrf, `{"minutes":43201,"reason":"too long"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("overlong silence status = %d, want 400", response.StatusCode)
	}
}
