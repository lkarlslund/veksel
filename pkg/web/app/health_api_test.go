package app

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/health"
)

func TestAdminHealthUnavailableWhenNotConfigured(t *testing.T) {
	server, _ := testApp(t)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "admin")
	response := authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/health", "", "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestPublishAdminEventTargetsCurrentEnabledAdministrators(t *testing.T) {
	handler, ts := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "admin")
	if err := ts.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	adminEvents, cancelAdmin := handler.events.Subscribe("admin")
	defer cancelAdmin()
	ordinaryEvents, cancelOrdinary := handler.events.Subscribe("ordinary")
	defer cancelOrdinary()
	if err := handler.PublishAdminEvent(t.Context(), events.Event{Type: "health.alert.opened", Resource: "runtime:smtp"}); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-adminEvents:
		if event.Type != "health.alert.opened" {
			t.Fatalf("admin event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("administrator did not receive health event")
	}
	select {
	case event := <-ordinaryEvents:
		t.Fatalf("ordinary user received administrator event: %#v", event)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestAdminHealthRequiresAdminAndReturnsDetailedSnapshot(t *testing.T) {
	handler, ts := testHandler(t)
	registry := health.New()
	refreshes := 0
	handler.ConfigureRuntimeHealth(registry, func(context.Context) {
		refreshes++
		if err := registry.Replace(time.Now(), []health.Observation{{
			ID: "http", Label: "HTTP", Kind: "listener", Desired: true, Required: true,
			State: health.StateHealthy, Details: map[string]string{"address": "127.0.0.1:8472"},
		}}); err != nil {
			t.Errorf("replace health: %v", err)
		}
	})
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "admin")
	if err := ts.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	ordinary := testClient(t)
	loginExistingUser(t, ordinary, server.URL, "ordinary")

	response := authenticatedJSON(t, ordinary, http.MethodGet, server.URL+"/api/v1/admin/health", "", "")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/health", "", "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("admin status = %d", response.StatusCode)
	}
	var snapshot health.Snapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if refreshes != 1 || snapshot.Status != health.StatusReady || len(snapshot.Components) != 1 || snapshot.Components[0].Details["address"] != "127.0.0.1:8472" {
		t.Fatalf("refreshes=%d snapshot=%#v", refreshes, snapshot)
	}
}
