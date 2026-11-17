package app

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// A domain routes unknown recipients only to an enabled relay route that
// names the server it shares the domain with.
func TestDomainSplitDeliveryNeedsARelayRoute(t *testing.T) {
	handler, _ := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	call := func(method, path, body string, want int) []byte {
		t.Helper()
		response := authenticatedJSON(t, client, method, server.URL+path, csrf, body)
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, response.StatusCode, want, raw)
		}
		return raw
	}
	call(http.MethodPost, "/api/v1/admin/domains", `{"id":"example.test"}`, http.StatusCreated)
	split := `{"unknown_recipients":{"route":true,"check":"callout"}}`
	call(http.MethodPatch, "/api/v1/admin/domains/example.test", split, http.StatusBadRequest)
	call(http.MethodPatch, "/api/v1/admin/domains/example.test", `{"unknown_recipients":{"route":true,"check":"maybe"}}`, http.StatusBadRequest)
	call(http.MethodPost, "/api/v1/admin/routes", `{"domain":"example.test","transport":"relay","relay_host":"10.0.0.26","relay_port":25,"tls_skip_verify":true,"enabled":true}`, http.StatusCreated)
	call(http.MethodPatch, "/api/v1/admin/domains/example.test", split, http.StatusOK)

	var domains []struct {
		ID                string `json:"id"`
		UnknownRecipients struct {
			Route bool   `json:"route"`
			Check string `json:"check"`
		} `json:"unknown_recipients"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/admin/domains", "", http.StatusOK), &domains); err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || !domains[0].UnknownRecipients.Route || domains[0].UnknownRecipients.Check != "callout" {
		t.Fatalf("domains = %+v, want split delivery stored", domains)
	}
}
