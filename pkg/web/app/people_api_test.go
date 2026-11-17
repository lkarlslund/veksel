package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// peopleSearch answers contact suggestion queries from a fixed hit list,
// filtered to the requested account and folders the way the real index is,
// and mail queries from a per-account page.
type peopleSearch struct {
	mu       sync.Mutex
	contacts []service.SearchHit
	mail     map[string][]service.SearchHit
	queries  []service.SearchQuery
}

func (s *peopleSearch) Search(_ context.Context, _ service.AccessContext, query service.SearchQuery) (service.SearchPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, query)
	page := service.SearchPage{IndexID: "idx-people"}
	if slices.Contains(query.Types, model.FolderTypeMail) {
		page.Hits = s.mail[query.AccountID]
		return page, nil
	}
	for _, hit := range s.contacts {
		if slices.Contains(query.FolderIDs, hit.FolderID) {
			page.Hits = append(page.Hits, hit)
		}
	}
	return page, nil
}

func (s *peopleSearch) SearchStatus(context.Context, service.AccessContext, string) (service.SearchIndexStatus, error) {
	return service.SearchIndexStatus{}, nil
}

func (s *peopleSearch) RequestSearchRebuild(context.Context, service.AccessContext, string) error {
	return nil
}

func (s *peopleSearch) lastQuery(folderType model.FolderType) service.SearchQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := len(s.queries) - 1; index >= 0; index-- {
		if slices.Contains(s.queries[index].Types, folderType) {
			return s.queries[index]
		}
	}
	return service.SearchQuery{}
}

func appendContact(t *testing.T, ts *model.TypedStore, folderID string, contact model.Contact, headers map[string]string) string {
	t.Helper()
	id, err := ts.ItemStore().Append(t.Context(), folderID, model.ContactToVCard(contact), headers)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func getJSON[T any](t *testing.T, client *http.Client, endpoint string, want int) T {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return decodeJSONResponse[T](t, response, want)
}

func TestPersonCardCombinesOwnContactRecentMailAndUpcomingMeetings(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	f.addUser(t, "alice", "example.test")
	f.addUser(t, "bob", "example.test")
	f.addUser(t, "dave", "other.test")
	search := &peopleSearch{mail: map[string][]service.SearchHit{}}
	f.handler.ConfigureSearch(search)

	contactsID := model.FolderKey("alice", "Contacts")
	ada := model.Contact{UID: "ada-uid", FN: "Ada Lovelace", Title: "Analyst", Org: "Engines Ltd", Emails: []string{"ada@remote.test", "ada@home.test"}, Phones: []string{"+45 1234"}, Note: "private notes"}
	adaID := appendContact(t, f.ts, contactsID, ada, nil)
	recentID := appendContact(t, f.ts, model.RecentRecipientsFolderID("alice"), model.Contact{FN: "ada", Emails: []string{"ada@remote.test"}}, map[string]string{"Use-Count": "3"})
	search.contacts = []service.SearchHit{
		{ItemID: recentID, FolderID: model.RecentRecipientsFolderID("alice"), Type: model.FolderTypeContacts, Name: "ada", ContactEmails: []string{"ada@remote.test"}},
		{ItemID: adaID, FolderID: contactsID, Type: model.FolderTypeContacts, Name: ada.FN, ContactEmails: ada.Emails},
	}
	when := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	search.mail["alice"] = []service.SearchHit{{ItemID: "m1", FolderID: model.FolderKey("alice", "INBOX"), FolderName: "INBOX", Type: model.FolderTypeMail, Title: "Engine plans", Date: when.Add(-72 * time.Hour)}}

	calendarID := f.calendarID(t, "alice")
	for _, event := range []struct{ summary, start, attendee string }{
		{"Design review", when.Format(time.RFC3339), "ada@remote.test"},
		{"Unrelated", when.Add(time.Hour).Format(time.RFC3339), "carol@remote.test"},
		{"Long past", when.Add(-30 * 24 * time.Hour).Format(time.RFC3339), "ada@remote.test"},
	} {
		end, _ := time.Parse(time.RFC3339, event.start)
		body := `{"folder_id":"` + calendarID + `","summary":"` + event.summary + `","start":"` + event.start + `","end":"` + end.Add(time.Hour).Format(time.RFC3339) + `","timezone":"UTC","attendees":[{"address":"` + event.attendee + `"}]}`
		decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/events", csrf, body), http.StatusCreated)
	}

	card := getJSON[personCard](t, client, f.server.URL+"/api/v1/workspace/people/card?email="+url.QueryEscape("ADA@remote.test"), http.StatusOK)
	if card.Name != "Ada Lovelace" || card.Title != "Analyst" || card.Org != "Engines Ltd" || card.Contact == nil || card.Contact.ItemID != adaID || len(card.Emails) != 2 || card.Emails[0] != "ada@remote.test" || len(card.Phones) != 1 || card.Directory {
		t.Fatalf("card = %+v", card)
	}
	if len(card.Recent) != 1 || card.Recent[0].Subject != "Engine plans" || !card.Recent[0].Unread {
		t.Fatalf("recent = %+v", card.Recent)
	}
	mailQuery := search.lastQuery(model.FolderTypeMail)
	if mailQuery.AccountID != "alice" || mailQuery.Limit != maxCardRecentMessages || mailQuery.Sort != "date_desc" || mailQuery.Filter == nil || mailQuery.Filter.Field != "from" || mailQuery.Filter.Value != "ada@remote.test" {
		t.Fatalf("mail query = %+v", mailQuery)
	}
	if len(card.Upcoming) != 1 || card.Upcoming[0].Summary != "Design review" {
		t.Fatalf("upcoming = %+v", card.Upcoming)
	}

	// A same-domain identity is a directory entry; another domain is not.
	colleague := getJSON[personCard](t, client, f.server.URL+"/api/v1/workspace/people/card?email=bob@example.test", http.StatusOK)
	if !colleague.Directory || colleague.Name != "Bob" || colleague.Contact != nil {
		t.Fatalf("colleague card = %+v", colleague)
	}
	stranger := getJSON[personCard](t, client, f.server.URL+"/api/v1/workspace/people/card?email=dave@other.test&name="+url.QueryEscape("Dave D"), http.StatusOK)
	if stranger.Directory || stranger.Name != "Dave D" {
		t.Fatalf("stranger card = %+v", stranger)
	}

	// Bob may read Alice's address book, but cards only use his own address
	// books, his own mail, and his own calendars.
	if _, err := model.NewPolicyStore(f.ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: contactsID},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderViewer, Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	loginExistingUser(t, bob, f.server.URL, "bob")
	bobCard := getJSON[personCard](t, bob, f.server.URL+"/api/v1/workspace/people/card?email=ada@remote.test", http.StatusOK)
	if bobCard.Contact != nil || bobCard.Title != "" || len(bobCard.Recent) != 0 || len(bobCard.Upcoming) != 0 || len(bobCard.Phones) != 0 {
		t.Fatalf("bob card leaks alice data: %+v", bobCard)
	}
	if query := search.lastQuery(model.FolderTypeMail); query.AccountID != "bob" {
		t.Fatalf("bob mail query account = %q", query.AccountID)
	}
	for _, invalid := range []string{"", "not-an-address", strings.Repeat("a", 330) + "@x.test"} {
		response, err := client.Get(f.server.URL + "/api/v1/workspace/people/card?email=" + url.QueryEscape(invalid))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("card %q status = %d", invalid, response.StatusCode)
		}
	}
}

func TestContactFavoritesPersistAndRespectAuthorization(t *testing.T) {
	handler, ts := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	contactsID := model.FolderKey("alice", "Contacts")
	adaID := appendContact(t, ts, contactsID, model.Contact{FN: "Ada Lovelace", Emails: []string{"ada@remote.test"}}, nil)
	groupID := appendContact(t, ts, contactsID, model.Contact{FN: "Analysts", Kind: "group", Members: []string{"mailto:ada@remote.test"}}, nil)

	for _, id := range []string{groupID, adaID} {
		response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/contact-favorites/"+url.PathEscape(id), csrf, "")
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("star %s status = %d", id, response.StatusCode)
		}
	}
	user, err := ts.UserStore().Get(t.Context(), "alice")
	if err != nil || !slices.Equal(user.FavoriteContacts, []string{groupID, adaID}) {
		t.Fatalf("stored favorites = %v, %v", user.FavoriteContacts, err)
	}
	var listed struct {
		Favorites []favoriteContact `json:"favorites"`
	}
	listed = getJSON[struct {
		Favorites []favoriteContact `json:"favorites"`
	}](t, client, server.URL+"/api/v1/user/contact-favorites", http.StatusOK)
	if len(listed.Favorites) != 2 || listed.Favorites[0].Kind != "group" || listed.Favorites[1].Email != "ada@remote.test" || listed.Favorites[1].Addressbook != "Contacts" {
		t.Fatalf("favorites = %+v", listed.Favorites)
	}
	// Empty autocomplete queries offer the favorites first.
	suggestions := getJSON[[]peopleSuggestion](t, client, server.URL+"/api/v1/workspace/people/suggestions", http.StatusOK)
	if len(suggestions) != 2 || !suggestions[0].Favorite || suggestions[0].Kind != "group" || suggestions[1].Email != "ada@remote.test" {
		t.Fatalf("favorite suggestions = %+v", suggestions)
	}

	// Another user cannot star a contact they cannot read.
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	bobCSRF := loginExistingUser(t, bob, server.URL, "bob")
	response := authenticatedJSON(t, bob, http.MethodPut, server.URL+"/api/v1/user/contact-favorites/"+url.PathEscape(adaID), bobCSRF, "")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign star status = %d", response.StatusCode)
	}
	if bobUser, _ := ts.UserStore().Get(t.Context(), "bob"); len(bobUser.FavoriteContacts) != 0 {
		t.Fatalf("bob favorites = %v", bobUser.FavoriteContacts)
	}

	// Trashed contacts drop out of the list; unstarring persists.
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/contact?item_id="+url.QueryEscape(groupID), csrf, "")
	_ = response.Body.Close()
	listed = getJSON[struct {
		Favorites []favoriteContact `json:"favorites"`
	}](t, client, server.URL+"/api/v1/user/contact-favorites", http.StatusOK)
	if len(listed.Favorites) != 1 || listed.Favorites[0].ID != adaID {
		t.Fatalf("favorites after trash = %+v", listed.Favorites)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/user/contact-favorites/"+url.PathEscape(adaID), csrf, "")
	var removed struct {
		FavoriteIDs []string `json:"favorite_ids"`
	}
	_ = json.NewDecoder(response.Body).Decode(&removed)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !slices.Equal(removed.FavoriteIDs, []string{groupID}) {
		t.Fatalf("unstar status=%d ids=%v", response.StatusCode, removed.FavoriteIDs)
	}
}

func TestPeopleSuggestionsRankSourcesAndExpandGroups(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	f.addUser(t, "alice", "example.test")
	f.addUser(t, "adam", "example.test")
	f.addUser(t, "adele", "other.test")
	search := &peopleSearch{}
	f.handler.ConfigureSearch(search)
	contactsID, recentFolder := model.FolderKey("alice", "Contacts"), model.RecentRecipientsFolderID("alice")
	lovelaceID := appendContact(t, f.ts, contactsID, model.Contact{UID: "urn:uuid:1111", FN: "Ada Lovelace", Emails: []string{"ada@remote.test"}}, nil)
	duplicateID := appendContact(t, f.ts, recentFolder, model.Contact{FN: "ada", Emails: []string{"ada@remote.test"}}, map[string]string{"Use-Count": "2", "Last-Used": time.Now().Add(-40 * 24 * time.Hour).Format(time.RFC3339Nano)})
	byronID := appendContact(t, f.ts, recentFolder, model.Contact{FN: "Ada Byron", Emails: []string{"byron@remote.test"}}, map[string]string{"Use-Count": "9", "Last-Used": time.Now().Format(time.RFC3339Nano)})
	groupID := appendContact(t, f.ts, contactsID, model.Contact{FN: "Ada team", Kind: "group", Members: []string{"mailto:Grace@remote.test", "urn:uuid:1111", "urn:uuid:missing"}}, nil)
	search.contacts = []service.SearchHit{
		{ItemID: lovelaceID, FolderID: contactsID, Name: "Ada Lovelace", ContactEmails: []string{"ada@remote.test"}},
		{ItemID: duplicateID, FolderID: recentFolder, Name: "ada", ContactEmails: []string{"ada@remote.test"}},
		{ItemID: byronID, FolderID: recentFolder, Name: "Ada Byron", ContactEmails: []string{"byron@remote.test"}},
		{ItemID: groupID, FolderID: contactsID, Name: "Ada team", ContactKind: "group", ContactMembers: 3},
	}

	suggestions := getJSON[[]peopleSuggestion](t, client, f.server.URL+"/api/v1/workspace/people/suggestions?q=ada", http.StatusOK)
	got := make([]string, 0, len(suggestions))
	for _, suggestion := range suggestions {
		got = append(got, suggestion.Source+":"+suggestion.Name)
	}
	// Adam is a same-domain directory entry; Adele is in another domain.
	want := []string{"recent:Ada Byron", "contact:Ada Lovelace", "contact:Ada team", "directory:Adam"}
	if !slices.Equal(got, want) {
		t.Fatalf("ranking = %v, want %v (%+v)", got, want, suggestions)
	}
	if suggestions[1].Uses != 2 || suggestions[1].ItemID != lovelaceID || suggestions[2].Kind != "group" || suggestions[2].MemberCount != 3 {
		t.Fatalf("merged suggestions = %+v", suggestions)
	}

	// Starring a contact puts it first.
	response := authenticatedJSON(t, client, http.MethodPut, f.server.URL+"/api/v1/user/contact-favorites/"+url.PathEscape(lovelaceID), csrf, "")
	_ = response.Body.Close()
	suggestions = getJSON[[]peopleSuggestion](t, client, f.server.URL+"/api/v1/workspace/people/suggestions?q=ada&limit=2", http.StatusOK)
	if len(suggestions) != 2 || suggestions[0].Name != "Ada Lovelace" || !suggestions[0].Favorite {
		t.Fatalf("favorite ranking = %+v", suggestions)
	}

	expanded := getJSON[struct {
		Name       string        `json:"name"`
		Members    []groupMember `json:"members"`
		Unresolved int           `json:"unresolved"`
	}](t, client, f.server.URL+"/api/v1/workspace/people/group?item_id="+url.QueryEscape(groupID), http.StatusOK)
	if expanded.Name != "Ada team" || len(expanded.Members) != 2 || expanded.Members[0].Email != "grace@remote.test" || expanded.Members[1].Email != "ada@remote.test" || expanded.Members[1].Name != "Ada Lovelace" || expanded.Unresolved != 1 {
		t.Fatalf("expanded = %+v", expanded)
	}
	response, err := client.Get(f.server.URL + "/api/v1/workspace/people/group?item_id=" + url.QueryEscape(lovelaceID))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expanding a person status = %d", response.StatusCode)
	}
	adam := testClient(t)
	loginExistingUser(t, adam, f.server.URL, "adam")
	response, err = adam.Get(f.server.URL + "/api/v1/workspace/people/group?item_id=" + url.QueryEscape(groupID))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign group expansion status = %d", response.StatusCode)
	}
	// Adam sees no private contact of Alice, only the directory.
	adamSuggestions := getJSON[[]peopleSuggestion](t, adam, f.server.URL+"/api/v1/workspace/people/suggestions?q=a", http.StatusOK)
	for _, suggestion := range adamSuggestions {
		if suggestion.Source != "directory" || strings.HasSuffix(suggestion.Email, "other.test") {
			t.Fatalf("adam suggestions leak: %+v", adamSuggestions)
		}
	}
}

func TestSearchSuggestionsAreBoundedAndAuthorized(t *testing.T) {
	handler, ts := testHandler(t)
	search := &peopleSearch{}
	handler.ConfigureSearch(search)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	contactsID := model.FolderKey("alice", "Contacts")
	adaID := appendContact(t, ts, contactsID, model.Contact{FN: "Ada Lovelace", Emails: []string{"ada@remote.test"}}, nil)
	search.contacts = []service.SearchHit{{ItemID: adaID, FolderID: contactsID, Name: "Ada Lovelace", ContactEmails: []string{"ada@remote.test"}}}
	for index := range 12 {
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/search/saved", csrf, `{"name":"Invoices `+string(rune('A'+index))+`","query":{"expression":"invoice"}}`)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("save search status = %d", response.StatusCode)
		}
	}

	type suggestions = searchSuggestions
	result := getJSON[suggestions](t, client, server.URL+"/api/v1/search/suggestions?q="+url.QueryEscape("invoice from:ada")+"&limit=50", http.StatusOK)
	if len(result.People) != 1 || result.People[0].Value != "invoice from:ada@remote.test" || len(result.Folders) != 0 {
		t.Fatalf("people suggestions = %+v", result)
	}
	result = getJSON[suggestions](t, client, server.URL+"/api/v1/search/suggestions?q=Invoices&limit=50", http.StatusOK)
	if len(result.SavedSearches) != maxSearchSuggestions {
		t.Fatalf("saved searches = %d, want bounded %d", len(result.SavedSearches), maxSearchSuggestions)
	}
	result = getJSON[suggestions](t, client, server.URL+"/api/v1/search/suggestions?q=report+has", http.StatusOK)
	if len(result.Operators) != 1 || result.Operators[0].Value != "report has:attachment" {
		t.Fatalf("operators = %+v", result.Operators)
	}
	result = getJSON[suggestions](t, client, server.URL+"/api/v1/search/suggestions?q=inb", http.StatusOK)
	if len(result.Folders) != 1 || result.Folders[0].Name != "INBOX" {
		t.Fatalf("folders = %+v", result.Folders)
	}
	result = getJSON[suggestions](t, client, server.URL+"/api/v1/search/suggestions?q=contac&scope=calendar", http.StatusOK)
	if len(result.Folders) != 0 || len(result.People) != 0 {
		t.Fatalf("calendar scope = %+v", result)
	}
	for _, invalid := range []string{"q=" + strings.Repeat("x", maxSearchSuggestionQuery+1), "q=a&scope=everything"} {
		response, err := client.Get(server.URL + "/api/v1/search/suggestions?" + invalid)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status = %d", invalid[:min(len(invalid), 20)], response.StatusCode)
		}
	}

	// Bob sees none of Alice's saved searches, folders, or contacts.
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	loginExistingUser(t, bob, server.URL, "bob")
	result = getJSON[suggestions](t, bob, server.URL+"/api/v1/search/suggestions?q=from:ada", http.StatusOK)
	if len(result.People) != 0 || len(result.SavedSearches) != 0 {
		t.Fatalf("bob suggestions = %+v", result)
	}
	result = getJSON[suggestions](t, bob, server.URL+"/api/v1/search/suggestions?q=inb", http.StatusOK)
	if len(result.Folders) != 1 || result.Folders[0].ID != model.FolderKey("bob", "INBOX") {
		t.Fatalf("bob folders = %+v", result.Folders)
	}
}
