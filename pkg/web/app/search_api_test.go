package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

type searchRecorder struct {
	access         service.AccessContext
	query          service.SearchQuery
	page           service.SearchPage
	err            error
	statusAccess   service.AccessContext
	statusAccount  string
	status         service.SearchIndexStatus
	rebuildAccess  service.AccessContext
	rebuildAccount string
}

func (s *searchRecorder) Search(_ context.Context, access service.AccessContext, query service.SearchQuery) (service.SearchPage, error) {
	s.access, s.query = access, query
	if s.err != nil {
		return service.SearchPage{}, s.err
	}
	if s.page.IndexID != "" {
		return s.page, nil
	}
	return service.SearchPage{Hits: []service.SearchHit{{ItemID: "item-1", Type: model.FolderTypeMail}}, Total: 1, IndexID: "idx-test"}, nil
}

func TestContactQueryUsesServerSearchSortAndCursor(t *testing.T) {
	handler, _ := testHandler(t)
	recorder := &searchRecorder{}
	handler.ConfigureSearch(recorder)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	defer server.Close()
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	created := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts?folder_id="+url.QueryEscape(model.FolderKey("alice", "Contacts")), csrf, `{"fn":"Ada Lovelace","org":"Analytical Engines","emails":["ada@example.test","other@example.test"],"phones":["+45 12345678"],"note":"private detail","custom_fields":{"Secret":"detail"},"photo_data":"AQID","photo_type":"PNG"}`)
	var contact model.Contact
	if err := json.NewDecoder(created.Body).Decode(&contact); err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()
	recorder.page = service.SearchPage{Hits: []service.SearchHit{{ItemID: contact.ID, FolderID: contact.FolderID, Type: model.FolderTypeContacts, Name: contact.FN, ContactKind: "group", ContactMembers: 3, ContactOrg: contact.Org, ContactEmails: contact.Emails, ContactPhone: contact.Phones[0], ContactHasPhoto: true, Updated: time.Unix(123, 456)}}, Total: 1, IndexID: "idx-contacts", NextCursor: "next-page"}

	response, err := client.Get(server.URL + "/api/v1/workspace/contacts/query?folder_id=" + url.QueryEscape(contact.FolderID) + "&q=ada&sort=org&direction=desc&limit=25&cursor=previous&view=summary")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var page workspaceContactSummaryPage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(page.Contacts) != 1 || page.Contacts[0].ID != contact.ID || page.Contacts[0].Kind != "group" || page.Contacts[0].MemberCount != 3 || page.Contacts[0].Email != "ada@example.test" || page.Contacts[0].Phone != "+45 12345678" || page.Contacts[0].PhotoToken == "" || page.NextCursor != "next-page" {
		t.Fatalf("status=%d page=%+v", response.StatusCode, page)
	}
	for _, forbidden := range []string{"photo_data", "private detail", "custom_fields", "other@example.test", "addresses", "raw"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("contact summary leaks %q: %s", forbidden, body)
		}
	}
	if recorder.query.AccountID != "alice" || recorder.query.Text != "ada" || recorder.query.Sort != "contact_org_desc" || recorder.query.Cursor != "previous" || recorder.query.Limit != 25 || len(recorder.query.FolderIDs) != 1 || recorder.query.FolderIDs[0] != contact.FolderID {
		t.Fatalf("contact query = %+v", recorder.query)
	}
	response, err = client.Get(server.URL + "/api/v1/workspace/contacts/query?folder_id=" + url.QueryEscape(contact.FolderID) + "&view=full")
	if err != nil {
		t.Fatal(err)
	}
	var full workspaceContactPage
	if err := json.NewDecoder(response.Body).Decode(&full); err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || len(full.Contacts) != 1 || full.Contacts[0].Note != "private detail" || len(full.Contacts[0].PhotoData) != 0 || full.Contacts[0].PhotoToken == "" {
		t.Fatalf("full contact query status=%d page=%+v", response.StatusCode, full)
	}
	// The photograph is served separately and is cacheable at its versioned URL.
	response, err = client.Get(server.URL + full.Contacts[0].PhotoURL)
	if err != nil {
		t.Fatal(err)
	}
	photo, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Equal(photo, []byte{1, 2, 3}) || !strings.Contains(response.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("listed photo status=%d cache=%q body=%v", response.StatusCode, response.Header.Get("Cache-Control"), photo)
	}
	response, err = client.Get(server.URL + "/api/v1/workspace/contacts/query?folder_id=" + url.QueryEscape(contact.FolderID) + "&view=unknown")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid contact query view status=%d, want 400", response.StatusCode)
	}
}

func (s *searchRecorder) SearchStatus(_ context.Context, access service.AccessContext, accountID string) (service.SearchIndexStatus, error) {
	s.statusAccess, s.statusAccount = access, accountID
	if s.status.State != "" {
		return s.status, nil
	}
	return service.SearchIndexStatus{AccountID: accountID, State: "ready", Documents: 1}, nil
}

func (s *searchRecorder) RequestSearchRebuild(_ context.Context, access service.AccessContext, accountID string) error {
	s.rebuildAccess, s.rebuildAccount = access, accountID
	return nil
}

func TestSearchAPIUsesAuthenticatedAccessContext(t *testing.T) {
	handler, _ := testHandler(t)
	recorder := &searchRecorder{}
	handler.ConfigureSearch(recorder)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	defer server.Close()
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/search/query", csrf, `{"text":"needle","expression":"from:alice","types":["mail"]}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("search status = %d", response.StatusCode)
	}
	if recorder.access.Actor.ID != "alice" || recorder.access.Subject.ID != "alice" || recorder.query.Text != "needle" || recorder.query.Expression != "from:alice" {
		t.Fatalf("search invocation = access %+v, query %+v", recorder.access, recorder.query)
	}
	recorder.status = service.SearchIndexStatus{
		AccountID: "alice", State: "building", IndexID: "idx-replacement", Rebuilding: true,
		BuildStartedAt: time.Unix(100, 0).UTC(), LastResumedAt: time.Unix(200, 0).UTC(),
		ResumeCount: 2, LastCompletedFolderID: "folder-checkpoint",
	}
	response, err := client.Get(server.URL + "/api/v1/search/index/status?account_id=alice")
	if err != nil {
		t.Fatal(err)
	}
	var status service.SearchIndexStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || status.ResumeCount != 2 || status.LastCompletedFolderID != "folder-checkpoint" || recorder.statusAccess.Actor.ID != "alice" || recorder.statusAccount != "alice" {
		t.Fatalf("search status projection=%+v access=%+v account=%q HTTP=%d", status, recorder.statusAccess, recorder.statusAccount, response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/search/index/rebuild", csrf, `{"account_id":"alice"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted || recorder.rebuildAccess.Actor.ID != "alice" || recorder.rebuildAccount != "alice" {
		t.Fatalf("search rebuild access=%+v account=%q HTTP=%d", recorder.rebuildAccess, recorder.rebuildAccount, response.StatusCode)
	}
}
