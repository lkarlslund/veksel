package app

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/savedsearch"
)

func TestSavedSearchAPIIsOwnerScopedCSRFProtectedAndReusable(t *testing.T) {
	handler, typed := testHandler(t)
	recorder := &searchRecorder{}
	handler.ConfigureSearch(recorder)
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

	request := `{"name":"Unread from Alice","query":{"expression":"from:alice is:unread","types":["mail"],"sort":"date_desc","limit":999,"cursor":"discard"}}`
	response := authenticatedJSON(t, alice, http.MethodPost, server.URL+"/api/v1/search/saved", "", request)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", response.StatusCode)
	}
	response = authenticatedJSON(t, alice, http.MethodPost, server.URL+"/api/v1/search/saved", aliceCSRF, request)
	var created savedsearch.Definition
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || created.OwnerID != "alice" || created.Query.Cursor != "" || created.Query.Limit != 0 {
		t.Fatalf("create status=%d definition=%+v", response.StatusCode, created)
	}
	select {
	case event := <-aliceEvents:
		if event.Type != "saved_search.created" || event.Resource != created.ID {
			t.Fatalf("Alice event=%+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("Alice did not receive saved-search event")
	}
	select {
	case event := <-bobEvents:
		t.Fatalf("Bob received Alice event=%+v", event)
	default:
	}

	response, err := alice.Get(server.URL + "/api/v1/search/saved")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	var listed struct {
		SavedSearches []savedsearch.Definition `json:"saved_searches"`
		Maximum       int                      `json:"maximum"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || listed.Maximum != savedsearch.MaxPerOwner || len(listed.SavedSearches) != 1 || listed.SavedSearches[0].ID != created.ID {
		t.Fatalf("list status=%d body=%s", response.StatusCode, body)
	}
	response, err = bob.Get(server.URL + "/api/v1/search/saved")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(body), created.ID) {
		t.Fatalf("Bob list status=%d body=%s", response.StatusCode, body)
	}

	updatedRequest := `{"name":"Flagged mail","query":{"expression":"is:flagged","types":["mail"],"sort":"date_asc"}}`
	response = authenticatedJSON(t, bob, http.MethodPatch, server.URL+"/api/v1/search/saved/"+created.ID, bobCSRF, updatedRequest)
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-owner update status=%d", response.StatusCode)
	}
	response = authenticatedJSON(t, alice, http.MethodPatch, server.URL+"/api/v1/search/saved/"+created.ID, aliceCSRF, updatedRequest)
	var updated savedsearch.Definition
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || updated.Name != "Flagged mail" || updated.Query.Expression != "is:flagged" {
		t.Fatalf("update status=%d definition=%+v", response.StatusCode, updated)
	}

	queryJSON, err := json.Marshal(updated.Query)
	if err != nil {
		t.Fatal(err)
	}
	response = authenticatedJSON(t, alice, http.MethodPost, server.URL+"/api/v1/search/query", aliceCSRF, string(queryJSON))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || recorder.access.Actor.ID != "alice" || recorder.query.Expression != "is:flagged" {
		t.Fatalf("replay status=%d access=%+v query=%+v", response.StatusCode, recorder.access, recorder.query)
	}

	response = authenticatedJSON(t, alice, http.MethodDelete, server.URL+"/api/v1/search/saved/"+created.ID, aliceCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", response.StatusCode)
	}
	response = authenticatedJSON(t, alice, http.MethodDelete, server.URL+"/api/v1/search/saved/"+created.ID, aliceCSRF, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status=%d", response.StatusCode)
	}
	for _, action := range []string{"saved_search.create", "saved_search.update", "saved_search.delete"} {
		entries, err := audit.New(typed).QueryReverse(t.Context(), time.Time{}, action, "alice", 10)
		if err != nil || len(entries) != 1 || entries[0].Target != created.ID || len(entries[0].Details) != 0 {
			t.Fatalf("audit %s=%+v err=%v", action, entries, err)
		}
	}
}

func TestSavedSearchAPIRejectsInvalidDefinitionsAndCurrentQueryDoesNotMutate(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	for _, body := range []string{
		`{"name":"Empty","query":{}}`,
		`{"name":"Bad expression","query":{"expression":"after:not-a-date"}}`,
		`{"name":"Bad sort","query":{"text":"mail","sort":"random"}}`,
	} {
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/search/saved", csrf, body)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid body %s status=%d", body, response.StatusCode)
		}
	}
	response, err := client.Get(server.URL + "/api/v1/search/saved")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var listed struct {
		SavedSearches []savedsearch.Definition `json:"saved_searches"`
	}
	if err := json.NewDecoder(response.Body).Decode(&listed); err != nil || len(listed.SavedSearches) != 0 {
		t.Fatalf("saved searches=%+v err=%v", listed.SavedSearches, err)
	}
}

func TestSearchPageContainsSavedSearchWebModal(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	response, err := client.Get(server.URL + "/app/search")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	page := string(body)
	for _, required := range []string{
		`id="search-saved-toggle"`, `id="saved-search-dialog"`,
		`id="saved-search-create"`, `id="saved-search-list"`, `id="confirm-dialog"`,
	} {
		if response.StatusCode != http.StatusOK || !strings.Contains(page, required) {
			t.Fatalf("search page missing %q (status %d)", required, response.StatusCode)
		}
	}
}
