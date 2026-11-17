package app

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
)

func setupBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetupPersistsPublicHostName(t *testing.T) {
	server, _, configuration, _, handler := managedTestApp(t)
	client := testClient(t)
	resp, err := client.Get(server.URL + "/app/setup")
	if err != nil {
		t.Fatal(err)
	}
	if body := setupBody(t, resp); !strings.Contains(body, `name="host_name"`) {
		t.Fatalf("setup form lacks host_name field: %s", body)
	}
	csrf := csrfCookieValue(t, client, server.URL)
	resp, err = client.PostForm(server.URL+"/app/setup", url.Values{
		"_csrf": {csrf}, "token": {setupTokenFor(t, server)}, "username": {"alice"},
		"password": {"password123"}, "confirm": {"password123"}, "host_name": {"Mail.Example.test."},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if state, _ := handler.bootstrap.State(t.Context()); state != authz.SetupComplete {
		t.Fatalf("state=%v", state)
	}
	if got := configuration.Current().Config.SmtpServerName; got != "mail.example.test" {
		t.Fatalf("smtp_server_name=%q", got)
	}
	if got := configuration.Current().Config.ImapServerName; got == "mail.example.test" {
		t.Fatal("imap_server_name must keep deriving")
	}
}

func TestSetupRejectsInvalidHostNameBeforeOwnerCreation(t *testing.T) {
	server, _, configuration, _, handler := managedTestApp(t)
	client := testClient(t)
	resp, err := client.Get(server.URL + "/app/setup")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	csrf := csrfCookieValue(t, client, server.URL)
	before := configuration.Current().Config.SmtpServerName
	resp, err = client.PostForm(server.URL+"/app/setup", url.Values{
		"_csrf": {csrf}, "token": {setupTokenFor(t, server)}, "username": {"alice"},
		"password": {"password123"}, "confirm": {"password123"}, "host_name": {"not_a_fqdn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	status := resp.StatusCode
	body := setupBody(t, resp)
	if status != http.StatusBadRequest || !strings.Contains(body, "Public mail host name") {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if state, _ := handler.bootstrap.State(t.Context()); state != authz.SetupReady {
		t.Fatalf("owner was created despite invalid host name: %v", state)
	}
	if configuration.Current().Config.SmtpServerName != before {
		t.Fatal("configuration changed")
	}
}

func TestSetupAPIHostName(t *testing.T) {
	server, _, configuration, _, handler := managedTestApp(t)
	client := testClient(t)
	var setup struct {
		CSRF string `json:"csrf"`
	}
	lifecycleRequest(t, client, http.MethodGet, server.URL+"/api/v1/setup", "", nil, http.StatusOK, &setup)
	token := setupTokenFor(t, server)
	lifecycleRequest(t, client, http.MethodPost, server.URL+"/api/v1/setup", setup.CSRF,
		map[string]string{"token": token, "username": "owner", "password": "password123", "host_name": "localhost"}, http.StatusBadRequest, nil)
	if state, _ := handler.bootstrap.State(t.Context()); state != authz.SetupReady {
		t.Fatalf("owner created despite invalid host name: %v", state)
	}
	lifecycleRequest(t, client, http.MethodPost, server.URL+"/api/v1/setup", setup.CSRF,
		map[string]string{"token": token, "username": "owner", "password": "password123", "host_name": "mail.example.test"}, http.StatusCreated, nil)
	if got := configuration.Current().Config.SmtpServerName; got != "mail.example.test" {
		t.Fatalf("smtp_server_name=%q", got)
	}
}
