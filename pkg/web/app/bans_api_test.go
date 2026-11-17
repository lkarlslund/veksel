package app

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/ban"
)

func TestAdminBansManualBanListAndUnban(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	service, err := ban.New(t.Context(), ts.Store(), audit.New(ts), nil, ban.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureBans(service)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/security/bans", csrf, `{"network":"198.51.100.0/24","duration":"2h","comment":"scanner"}`)
	var created ban.Ban
	decodeResponse(t, response, &created)
	if response.StatusCode != http.StatusCreated || created.Prefix != "198.51.100.0/24" || created.Source != ban.SourceManual || created.Actor != "owner" || created.ExpiresAt.Sub(created.CreatedAt).Hours() != 2 {
		t.Fatalf("created ban = %+v status=%d", created, response.StatusCode)
	}
	for body, want := range map[string]int{
		`{"network":"127.0.0.0/8"}`:                 http.StatusBadRequest, // loopback is exempt (and the caller's own address)
		`{"network":"not-a-network"}`:               http.StatusBadRequest,
		`{"network":"192.0.2.1","duration":"soon"}`: http.StatusBadRequest,
	} {
		response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/security/bans", csrf, body)
		_ = readResponseBody(t, response)
		if response.StatusCode != want {
			t.Fatalf("POST %s status = %d", body, response.StatusCode)
		}
	}
	service.Strike("2001:db8::1", ban.TriggerAuth) // below the threshold: not listed

	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/security/bans?q=scanner", "", "")
	var listed bansResponse
	decodeResponse(t, response, &listed)
	if response.StatusCode != http.StatusOK || !listed.Enabled || listed.Active != 1 || listed.IPv6Prefix != 64 || len(listed.Durations) != 4 || len(listed.Bans) != 1 || listed.Bans[0].Comment != "scanner" {
		t.Fatalf("listed = %+v status=%d", listed, response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/security/bans?q=nomatch", "", "")
	decodeResponse(t, response, &listed)
	if len(listed.Bans) != 0 {
		t.Fatalf("search did not filter: %+v", listed.Bans)
	}

	unban := server.URL + "/api/v1/admin/security/bans?network=" + url.QueryEscape("198.51.100.0/24")
	response = authenticatedJSON(t, client, http.MethodDelete, unban, csrf, "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusNoContent || service.Banned("198.51.100.9", "http") {
		t.Fatalf("unban status = %d", response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, unban, csrf, "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("second unban status = %d", response.StatusCode)
	}
	actions, err := audit.New(ts).Query(t.Context(), created.CreatedAt.Add(-1), "", "owner", 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range actions {
		seen[entry.Action] = true
	}
	if !seen["security.ban.add"] || !seen["security.ban.remove"] {
		t.Fatalf("audit actions = %+v", actions)
	}
}

func TestAdminBansRequireAdministratorAndCSRF(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	service, err := ban.New(t.Context(), ts.Store(), nil, nil, ban.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureBans(service)
	owner := testClient(t)
	setupAndLogin(t, server, owner, "owner")
	response := authenticatedJSON(t, owner, http.MethodPost, server.URL+"/api/v1/admin/security/bans", "", `{"network":"192.0.2.1"}`)
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden || service.Active() != 0 {
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
	response = authenticatedJSON(t, reader, http.MethodGet, server.URL+"/api/v1/admin/security/bans", "", "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user status = %d", response.StatusCode)
	}
}
