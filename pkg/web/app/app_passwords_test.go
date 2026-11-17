package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestUserApplicationPasswordLifecycle(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/app-passwords", "", `{"name":"Phone","protocols":["imap","dav"]}`)
	if response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("create without CSRF status = %d", response.StatusCode)
	}
	response.Body.Close()

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/app-passwords", csrf, `{"name":"Phone","protocols":["imap","dav"]}`)
	if response.StatusCode != http.StatusCreated {
		response.Body.Close()
		t.Fatalf("create status = %d", response.StatusCode)
	}
	var created userAppPasswordView
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if created.Secret == "" || created.Prefix == "" || len(created.Protocols) != 2 {
		t.Fatalf("created credential = %#v", created)
	}
	originalSecret := created.Secret

	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/user/app-passwords", "", "")
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("list status = %d", response.StatusCode)
	}
	var listing struct {
		Passwords []userAppPasswordView `json:"passwords"`
		Protocols []string              `json:"protocols"`
	}
	if err := json.NewDecoder(response.Body).Decode(&listing); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(listing.Passwords) != 1 || listing.Passwords[0].Secret != "" || len(listing.Protocols) != len(model.SupportedAppProtocols()) {
		t.Fatalf("listing leaks or differs = %#v", listing)
	}

	if err := typed.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	other, _, err := model.NewAppPasswordStore(typed).Create(t.Context(), "bob", "Other", []string{model.AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/app-passwords/"+other.ID+"/rotate", csrf, "")
	if response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("rotate foreign credential status = %d", response.StatusCode)
	}
	response.Body.Close()

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/user/app-passwords/"+created.ID+"/rotate", csrf, "")
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("rotate status = %d", response.StatusCode)
	}
	var rotated userAppPasswordView
	if err := json.NewDecoder(response.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if rotated.ID != created.ID || rotated.Secret == "" || rotated.Secret == originalSecret || rotated.RotationCount != 1 {
		t.Fatalf("rotated credential = %#v", rotated)
	}
	passwordStore := model.NewAppPasswordStore(typed)
	if matched, err := passwordStore.Authenticate(t.Context(), "alice", originalSecret, model.AppProtocolIMAP); err != nil || matched != nil {
		t.Fatalf("old secret authenticates after rotation: password=%+v err=%v", matched, err)
	}
	if matched, err := passwordStore.Authenticate(t.Context(), "alice", rotated.Secret, model.AppProtocolIMAP); err != nil || matched == nil || matched.ID != created.ID {
		t.Fatalf("replacement does not authenticate: password=%+v err=%v", matched, err)
	}

	entries, err := audit.New(typed).QueryReverse(t.Context(), time.Time{}, "app_password.rotate", "alice", 10)
	if err != nil || len(entries) != 1 || entries[0].Target != created.ID || entries[0].Details["rotation_count"] != "1" {
		t.Fatalf("rotation audit = %#v, %v", entries, err)
	}

	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/user/app-passwords/"+created.ID, csrf, "")
	if response.StatusCode != http.StatusNoContent {
		response.Body.Close()
		t.Fatalf("revoke status = %d", response.StatusCode)
	}
	response.Body.Close()
	if matched, err := passwordStore.Authenticate(t.Context(), "alice", rotated.Secret, model.AppProtocolIMAP); err != nil || matched != nil {
		t.Fatalf("revoked credential authenticates: password=%+v err=%v", matched, err)
	}
}

func TestApplicationPasswordCannotCreateBrowserSession(t *testing.T) {
	server, typed := testApp(t)
	owner := testClient(t)
	setupAndLogin(t, server, owner, "alice")
	_, secret, err := model.NewAppPasswordStore(typed).Create(t.Context(), "alice", "Mail only", []string{model.AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}

	client := testClient(t)
	response, err := client.Get(server.URL + "/api/v1/setup")
	if err != nil {
		t.Fatal(err)
	}
	var setup struct {
		CSRF string `json:"csrf"`
	}
	if err := json.NewDecoder(response.Body).Decode(&setup); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": secret})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/session/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", setup.CSRF)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("application password browser login status = %d", response.StatusCode)
	}
}

func TestApplicationPasswordSettingsPageUsesWebModals(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	response, err := client.Get(server.URL + "/app/settings/app-passwords")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body bytes.Buffer
	if _, err := body.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}
	page := body.String()
	for _, want := range []string{`data-settings-section="app-passwords"`, `aria-current="page" href="/app/settings/app-passwords"`, `id="user-app-password-settings"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("settings page missing %q", want)
		}
	}
}
