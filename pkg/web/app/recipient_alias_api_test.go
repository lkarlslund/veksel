package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestAdminRecipientAliasCRUDAndAuthorization(t *testing.T) {
	server, typed := testApp(t)
	adminClient := testClient(t)
	csrf := setupAndLogin(t, server, adminClient, "admin")
	if err := typed.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alice", "bob"} {
		if err := typed.UserStore().Create(t.Context(), id, id, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := typed.UserStore().AddEmailAddress(t.Context(), id+"@example.test", id, "example.test", true); err != nil {
			t.Fatal(err)
		}
	}

	response := authenticatedJSON(t, adminClient, http.MethodPost, server.URL+"/api/v1/admin/recipient-aliases", csrf,
		`{"address":"team@example.test","targets":["bob@example.test","alice@example.test"],"enabled":true}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("create status=%d body=%s", response.StatusCode, body)
	}
	var alias model.RecipientAlias
	if err := json.NewDecoder(response.Body).Decode(&alias); err != nil || alias.Address != "team@example.test" || len(alias.Targets) != 2 {
		t.Fatalf("created alias = %+v, %v", alias, err)
	}

	response = authenticatedJSON(t, adminClient, http.MethodPut, server.URL+"/api/v1/admin/recipient-aliases/"+url.PathEscape(alias.Address), csrf,
		`{"targets":["alice@example.test"],"enabled":false}`)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("update status=%d body=%s", response.StatusCode, body)
	}
	response.Body.Close()
	stored, err := typed.RecipientAliasStore().Get(t.Context(), alias.Address)
	if err != nil || stored.Enabled || len(stored.Targets) != 1 {
		t.Fatalf("stored alias = %+v, %v", stored, err)
	}

	response = authenticatedJSON(t, adminClient, http.MethodPost, server.URL+"/api/v1/admin/recipient-aliases", csrf,
		`{"address":"external@example.test","targets":["person@remote.test"],"enabled":true}`)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("external target status = %d", response.StatusCode)
	}

	userClient := testClient(t)
	userCSRF := loginExistingUser(t, userClient, server.URL, "alice")
	response = authenticatedJSON(t, userClient, http.MethodGet, server.URL+"/api/v1/admin/recipient-aliases", "", "")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin list status = %d", response.StatusCode)
	}
	response = authenticatedJSON(t, userClient, http.MethodDelete, server.URL+"/api/v1/admin/recipient-aliases/"+url.PathEscape(alias.Address), userCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin delete status = %d", response.StatusCode)
	}

	response = authenticatedJSON(t, adminClient, http.MethodDelete, server.URL+"/api/v1/admin/recipient-aliases/"+url.PathEscape(alias.Address), csrf, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d", response.StatusCode)
	}
}
