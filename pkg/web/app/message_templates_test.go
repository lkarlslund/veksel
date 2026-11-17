package app

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/messagetemplate"
)

func TestMessageTemplateAPIIsOwnerScopedCSRFProtectedAndAudited(t *testing.T) {
	handler, typed := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	alice := testClient(t)
	aliceCSRF := setupAndLogin(t, server, alice, "alice")
	if err := typed.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	bobCSRF := loginExistingUser(t, bob, server.URL, "bob")
	aliceEvents, cancelAlice := handler.events.Subscribe("alice")
	t.Cleanup(cancelAlice)
	bobEvents, cancelBob := handler.events.Subscribe("bob")
	t.Cleanup(cancelBob)

	request := `{"name":"Invoice reply","subject":"Your invoice","body":"Hello,\n\nPlease find the invoice attached."}`
	response := authenticatedJSON(t, alice, http.MethodPost, server.URL+"/api/v1/mail/templates", "", request)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", response.StatusCode)
	}
	response = authenticatedJSON(t, alice, http.MethodPost, server.URL+"/api/v1/mail/templates", aliceCSRF, request)
	var created messagetemplate.Definition
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || created.OwnerID != "alice" || created.Name != "Invoice reply" || created.Subject != "Your invoice" {
		t.Fatalf("create status=%d definition=%+v", response.StatusCode, created)
	}
	select {
	case event := <-aliceEvents:
		if event.Type != "message_template.created" || event.Resource != created.ID {
			t.Fatalf("Alice event=%+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("Alice did not receive template event")
	}
	select {
	case event := <-bobEvents:
		t.Fatalf("Bob received Alice event=%+v", event)
	default:
	}

	response, err := alice.Get(server.URL + "/api/v1/mail/templates")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	var listed struct {
		Templates []messagetemplate.Definition `json:"templates"`
		Maximum   int                          `json:"maximum"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || listed.Maximum != messagetemplate.MaxPerOwner || len(listed.Templates) != 1 || listed.Templates[0].ID != created.ID {
		t.Fatalf("list status=%d body=%s", response.StatusCode, body)
	}
	response, err = bob.Get(server.URL + "/api/v1/mail/templates")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(body), created.ID) || strings.Contains(string(body), created.Body) {
		t.Fatalf("Bob list status=%d body=%s", response.StatusCode, body)
	}

	updatedRequest := `{"name":"Receipt reply","subject":"Payment received","body":"Thank you for your payment."}`
	response = authenticatedJSON(t, bob, http.MethodPatch, server.URL+"/api/v1/mail/templates/"+created.ID, bobCSRF, updatedRequest)
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-owner update status=%d", response.StatusCode)
	}
	response = authenticatedJSON(t, alice, http.MethodPatch, server.URL+"/api/v1/mail/templates/"+created.ID, aliceCSRF, updatedRequest)
	var updated messagetemplate.Definition
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || updated.Name != "Receipt reply" || updated.Subject != "Payment received" || updated.Body != "Thank you for your payment." {
		t.Fatalf("update status=%d definition=%+v", response.StatusCode, updated)
	}

	response = authenticatedJSON(t, alice, http.MethodDelete, server.URL+"/api/v1/mail/templates/"+created.ID, aliceCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", response.StatusCode)
	}
	response = authenticatedJSON(t, alice, http.MethodDelete, server.URL+"/api/v1/mail/templates/"+created.ID, aliceCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status=%d", response.StatusCode)
	}
	for _, action := range []string{"message_template.create", "message_template.update", "message_template.delete"} {
		entries, err := audit.New(typed).QueryReverse(t.Context(), time.Time{}, action, "alice", 10)
		if err != nil || len(entries) != 1 || entries[0].Target != created.ID || len(entries[0].Details) != 0 {
			t.Fatalf("audit %s=%+v err=%v", action, entries, err)
		}
	}
}

func TestMessageTemplateAPIRejectsInvalidContentWithoutMutation(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	for _, body := range []string{
		`{"name":"Empty","subject":"","body":""}`,
		`{"name":"Bad subject","subject":"one\ntwo","body":"text"}`,
		`{"name":"","subject":"Subject","body":"text"}`,
	} {
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/mail/templates", csrf, body)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid body %s status=%d", body, response.StatusCode)
		}
	}
	response, err := client.Get(server.URL + "/api/v1/mail/templates")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var listed struct {
		Templates []messagetemplate.Definition `json:"templates"`
	}
	if err := json.NewDecoder(response.Body).Decode(&listed); err != nil || len(listed.Templates) != 0 {
		t.Fatalf("templates=%+v err=%v", listed.Templates, err)
	}
}

func TestMailPageBootstrapsMessageTemplateWebModals(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	response, err := client.Get(server.URL + "/app/mail")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `id="compose-dialog"`) || !strings.Contains(string(body), `id="confirm-dialog"`) {
		t.Fatalf("mail page status=%d", response.StatusCode)
	}
}
