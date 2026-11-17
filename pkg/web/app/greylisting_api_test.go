package app

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/greylist"
)

func TestAdminGreylistingLifecycleStatsAndCleanup(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	config := greylist.DefaultConfig()
	config.Enabled = true
	service, err := greylist.New(t.Context(), ts.Store(), config)
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureGreylisting(service)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	if _, err := service.Check(t.Context(), greylist.Triplet{RemoteIP: "192.0.2.10", EnvelopeFrom: "sender@example.test", Recipient: "owner@example.test"}); err != nil {
		t.Fatal(err)
	}
	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/greylisting", "", "")
	var initial greylistingResponse
	decodeResponse(t, response, &initial)
	if response.StatusCode != http.StatusOK || !initial.Config.Enabled || initial.Stats.Deferred != 1 || initial.Stats.StoredEntries != 1 || len(initial.Allows) != 0 {
		t.Fatalf("initial greylisting response = %+v status=%d", initial, response.StatusCode)
	}

	candidate, _ := json.Marshal(greylist.AllowEntry{Kind: greylist.AllowSourceCIDR, Value: "192.0.2.0/24", Comment: "trusted relay", ExpiresAt: time.Now().Add(time.Hour).UTC()})
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/greylisting/allows", csrf, string(candidate))
	var created greylist.AllowEntry
	decodeResponse(t, response, &created)
	if response.StatusCode != http.StatusCreated || created.ID == "" || created.CreatedBy != "owner" || created.Value != "192.0.2.0/24" {
		t.Fatalf("created allow = %+v status=%d", created, response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/greylisting/allows", csrf, string(candidate))
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate allow status = %d", response.StatusCode)
	}
	decision, err := service.Check(t.Context(), greylist.Triplet{RemoteIP: "192.0.2.99", EnvelopeFrom: "other@example.test", Recipient: "owner@example.test"})
	if err != nil || decision.Action != greylist.ActionBypass {
		t.Fatalf("allow decision = %+v error=%v", decision, err)
	}

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/greylisting/cleanup", csrf, `{"limit":100}`)
	var cleanup greylistCleanupResponse
	decodeResponse(t, response, &cleanup)
	if response.StatusCode != http.StatusOK || cleanup.Stats.Checks != 2 {
		t.Fatalf("cleanup response = %+v status=%d", cleanup, response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/greylisting/allows/"+created.ID, csrf, "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete allow status = %d", response.StatusCode)
	}
	allows, err := service.ListAllows(t.Context())
	if err != nil || len(allows) != 0 {
		t.Fatalf("allows after delete = %+v error=%v", allows, err)
	}
}

func TestAdminGreylistingRequiresAdministratorAndCSRF(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	service, err := greylist.New(t.Context(), ts.Store(), greylist.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureGreylisting(service)
	owner := testClient(t)
	setupAndLogin(t, server, owner, "owner")
	response := authenticatedJSON(t, owner, http.MethodPost, server.URL+"/api/v1/admin/greylisting/allows", "", `{"kind":"sender","value":"sender@example.test"}`)
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", response.StatusCode)
	}
	if err := ts.UserStore().Create(t.Context(), "reader", "Reader", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "reader"); err != nil {
		t.Fatal(err)
	}
	reader := testClient(t)
	setupAndLogin(t, server, reader, "reader")
	response = authenticatedJSON(t, reader, http.MethodGet, server.URL+"/api/v1/admin/greylisting", "", "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user status = %d", response.StatusCode)
	}
}
