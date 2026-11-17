package app

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
)

func TestAdminHTTPListenerCRUDAndBindings(t *testing.T) {
	server, _, configuration, _, _ := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/http-listeners", "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET listeners status = %d", response.StatusCode)
	}
	var current struct {
		Revision  string                `json:"revision"`
		Listeners []config.HTTPListener `json:"listeners"`
	}
	if err := json.NewDecoder(response.Body).Decode(&current); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(current.Listeners) != 1 || current.Listeners[0].ID != "default-http" {
		t.Fatalf("initial listeners = %#v", current.Listeners)
	}

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/http-listeners", csrf,
		`{"revision":"`+current.Revision+`","listener":{"id":"eas-only","name":"Mobile devices","enabled":false,"transport":"https","address":"127.0.0.1:8480","hsts_max_age_days":365,"hsts_include_subdomains":true,"hsts_preload":true,"access_log":true,"log_level":"debug","services":["eas"]}}`)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("POST listener status = %d", response.StatusCode)
	}
	var created struct {
		Revision  string                `json:"revision"`
		Listeners []config.HTTPListener `json:"listeners"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(created.Listeners) != 2 || !created.Listeners[1].AccessLog || created.Listeners[1].HSTSMaxAgeDays == nil || *created.Listeners[1].HSTSMaxAgeDays != 365 || !created.Listeners[1].HSTSIncludeSubdomains || !created.Listeners[1].HSTSPreload {
		t.Fatalf("created listeners = %#v", created.Listeners)
	}
	response = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/admin/http-listeners/eas-only", csrf,
		`{"revision":"`+created.Revision+`","listener":{"id":"eas-only","name":"Mobile devices","enabled":false,"transport":"https","address":"127.0.0.1:8480","hsts_max_age_days":0,"access_log":true,"log_level":"debug","services":["eas"]}}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PUT listener HSTS removal status = %d", response.StatusCode)
	}
	var updated struct {
		Revision  string                `json:"revision"`
		Listeners []config.HTTPListener `json:"listeners"`
	}
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if updated.Listeners[1].HSTSMaxAgeDays == nil || *updated.Listeners[1].HSTSMaxAgeDays != 0 || updated.Listeners[1].HSTSIncludeSubdomains || updated.Listeners[1].HSTSPreload {
		t.Fatalf("updated HSTS removal policy = %#v", updated.Listeners[1])
	}

	response = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/admin/http-bindings/jmap", csrf,
		`{"revision":"`+updated.Revision+`","listener_ids":["eas-only"]}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PUT binding status = %d", response.StatusCode)
	}
	var bound struct {
		Revision  string                `json:"revision"`
		Listeners []config.HTTPListener `json:"listeners"`
	}
	if err := json.NewDecoder(response.Body).Decode(&bound); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(bound.Listeners[0].Services) == len(current.Listeners[0].Services) || len(bound.Listeners[1].Services) != 2 {
		t.Fatalf("bound listeners = %#v", bound.Listeners)
	}

	response = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/admin/http-bindings/web", csrf,
		`{"revision":"`+bound.Revision+`","listener_ids":[]}`)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("web lockout status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	if len(configuration.Current().Config.HTTPListeners) != 2 {
		t.Fatal("rejected binding changed persisted configuration")
	}
}
