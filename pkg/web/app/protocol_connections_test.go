package app

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lkarlslund/veksel/pkg/metrics"
)

func TestAdminProtocolConnectionsAreAggregateAndPrivacyBounded(t *testing.T) {
	handler, typed := testHandler(t)
	collector := metrics.New(typed.Store())
	handler.ConfigureMetrics(collector)
	releaseIMAP := metrics.NewConnectionGauge(collector, "imap_active_connections").Open()
	t.Cleanup(releaseIMAP)
	smtp := metrics.NewConnectionGauge(collector, "smtp_active_connections")
	releaseSMTP := smtp.Open()
	releaseSMTP()
	metrics.NewConnectionGauge(collector, "pop3_active_connections")

	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "admin")

	response, err := admin.Get(server.URL + "/api/v1/admin/protocol-connections")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Connections []protocolConnectionStatus `json:"connections"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(payload.Connections) != 3 {
		t.Fatalf("status=%d payload=%+v", response.StatusCode, payload)
	}
	want := map[string]int64{"imap": 1, "pop3": 0, "smtp": 0}
	for _, status := range payload.Connections {
		if status.Active != want[status.Protocol] || status.ObservedAt.IsZero() {
			t.Fatalf("connection status = %+v", status)
		}
	}
}

func TestAdminProtocolConnectionsRequireAdminAndMetrics(t *testing.T) {
	handler, typed := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "admin")
	response, err := admin.Get(server.URL + "/api/v1/admin/protocol-connections")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("missing metrics status = %d", response.StatusCode)
	}

	if err := typed.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	handler.ConfigureMetrics(metrics.New(typed.Store()))
	ordinary := testClient(t)
	loginExistingUser(t, ordinary, server.URL, "ordinary")
	response, err = ordinary.Get(server.URL + "/api/v1/admin/protocol-connections")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user status = %d", response.StatusCode)
	}
}
