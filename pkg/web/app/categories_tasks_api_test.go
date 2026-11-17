package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/caldav"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/mailstate"
	"github.com/lkarlslund/veksel/pkg/model"
)

// davGet reads one DAV resource of alice through a CalDAV/CardDAV handler on
// the same FolderSpace the web app writes to.
func davGet(t *testing.T, dav *caldav.Handler, path string) string {
	t.Helper()
	request := caldav.WithAuthenticatedUser(httptest.NewRequest(http.MethodGet, path, nil), "alice")
	recorder := httptest.NewRecorder()
	dav.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%s", path, recorder.Code, recorder.Body)
	}
	return recorder.Body.String()
}

func TestMasterCategoriesApplyToMailEventsAndContacts(t *testing.T) {
	handler, ts := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	dav := caldav.NewWithFolderSpace(ts, handler.folderSpace, nil)

	// Unsaved accounts see Thunderbird's default tags as categories.
	initial := decodeTestJSON[categoriesResponse](t, mustGet(t, client, server.URL+"/api/v1/user/categories"))
	if !initial.Defaults || len(initial.Categories) != 5 || initial.Categories[1].Name != "Work" {
		t.Fatalf("default categories = %+v", initial)
	}
	for _, invalid := range []string{`{"categories":[{"name":"A"},{"name":"a"}]}`, `{"categories":[{"name":"X","color":"blue"}]}`, `{"categories":[{"name":""}]}`} {
		response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/categories", csrf, invalid)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status=%d", invalid, response.StatusCode)
		}
	}
	saved := decodeJSONResponse[categoriesResponse](t, authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/categories", csrf,
		`{"categories":[{"name":"Project North","color":"#1F77B4"},{"name":"Work","color":"#e67e22"}]}`), http.StatusOK)
	if saved.Defaults || len(saved.Categories) != 2 || saved.Categories[0].Color != "#1f77b4" {
		t.Fatalf("saved categories = %+v", saved)
	}
	if read := decodeTestJSON[categoriesResponse](t, mustGet(t, client, server.URL+"/api/v1/user/categories")); read.Defaults || len(read.Categories) != 2 {
		t.Fatalf("read categories = %+v", read)
	}

	// Mail: categories are IMAP keywords that clients round-trip.
	inbox := model.InboxFolderID("alice")
	base := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	tagged := seedMail(t, handler, inbox, "From: amy@example.net\nSubject: North plan\n\nbody\n", base)
	thunderbird := seedMail(t, handler, inbox, "From: tb@example.net\nSubject: Tagged in Thunderbird\n\nbody\n", base.Add(time.Hour), "$label2")
	seedMail(t, handler, inbox, "From: zed@example.net\nSubject: Other\n\nbody\n", base.Add(2*time.Hour))
	action := func(body string) {
		t.Helper()
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, body)
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			data, _ := io.ReadAll(response.Body)
			t.Fatalf("action %s status=%d body=%s", body, response.StatusCode, data)
		}
	}
	action(`{"action":"categorize","category":"Project North","item_ids":["` + tagged.ID + `"]}`)
	stored, err := ts.ItemStore().Get(t.Context(), tagged.ID)
	if err != nil || !slices.Contains(stored.Flags, "project_north") {
		t.Fatalf("stored flags = %v err=%v", stored.Flags, err)
	}
	list := func(query string) mailindex.Page {
		t.Helper()
		return decodeTestJSON[mailindex.Page](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/list?folder_id="+url.QueryEscape(inbox)+query))
	}
	page := list("&category=" + url.QueryEscape("project north"))
	if len(page.Items) != 1 || page.Items[0].ID != tagged.ID || !slices.Equal(page.Items[0].Categories, []string{"Project North"}) {
		t.Fatalf("category page = %+v", page.Items)
	}
	if page = list("&category=Work"); len(page.Items) != 1 || page.Items[0].ID != thunderbird.ID || !slices.Equal(page.Items[0].Categories, []string{"Work"}) {
		t.Fatalf("Thunderbird $label2 page = %+v", page.Items)
	}
	action(`{"action":"uncategorize","category":"project north","item_ids":["` + tagged.ID + `"]}`)
	if stored, _ = ts.ItemStore().Get(t.Context(), tagged.ID); slices.Contains(stored.Flags, "project_north") {
		t.Fatalf("keyword kept after uncategorize: %v", stored.Flags)
	}
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, `{"action":"categorize","item_ids":["`+tagged.ID+`"]}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("categorize without a category status=%d", response.StatusCode)
	}

	// Events: CATEGORIES served over CalDAV.
	calendarID := model.FolderKey("alice", "Calendar")
	event := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/calendar/events", csrf,
		`{"folder_id":"`+calendarID+`","summary":"Kickoff","start":"2026-10-20T09:00:00Z","end":"2026-10-20T10:00:00Z","categories":["Work"]}`), http.StatusCreated)
	action(`{"action":"categorize","category":"Project North","item_ids":["` + event.ID + `"]}`)
	eventItem, err := ts.ItemStore().Get(t.Context(), event.ID)
	if err != nil {
		t.Fatal(err)
	}
	name := eventItem.Name
	if name == "" {
		name = eventItem.ID
	}
	if body := davGet(t, dav, "/dav/alice/Calendar/"+name); !strings.Contains(body, "CATEGORIES:Work,Project North") {
		t.Fatalf("CalDAV event = %s", body)
	}

	// Contacts: CATEGORIES served over CardDAV and kept by the editor view.
	contactsID := model.FolderKey("alice", "Contacts")
	contactID, err := ts.ItemStore().Append(t.Context(), contactsID, []byte("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:ada\r\nFN:Ada Lovelace\r\nEMAIL:ada@example.net\r\nEND:VCARD\r\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	action(`{"action":"categorize","category":"Project North","item_ids":["` + contactID + `"]}`)
	contact := decodeTestJSON[model.Contact](t, mustGet(t, client, server.URL+"/api/v1/workspace/contact?item_id="+url.QueryEscape(contactID)))
	if !slices.Equal(contact.Categories, []string{"Project North"}) || contact.FN != "Ada Lovelace" {
		t.Fatalf("contact = %+v", contact)
	}
	contactItem, _ := ts.ItemStore().Get(t.Context(), contactID)
	contactName := contactItem.Name
	if contactName == "" {
		contactName = contactItem.ID
	}
	if body := davGet(t, dav, "/dav/alice/Contacts/"+contactName); !strings.Contains(body, "CATEGORIES:Project North") || !strings.Contains(body, "EMAIL:ada@example.net") {
		t.Fatalf("CardDAV card = %s", body)
	}
}

func TestTasksWorkspaceCRUDSubtasksRecurrenceAndCalDAV(t *testing.T) {
	handler, ts := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	dav := caldav.NewWithFolderSpace(ts, handler.folderSpace, nil)

	lists := decodeTestJSON[[]workspaceFolder](t, mustGet(t, client, server.URL+"/api/v1/workspace/tasks/lists"))
	if len(lists) != 1 || lists[0].Type != model.FolderTypeTasks || lists[0].Name != defaultTaskListName {
		t.Fatalf("task lists = %+v", lists)
	}
	if again := decodeTestJSON[[]workspaceFolder](t, mustGet(t, client, server.URL+"/api/v1/workspace/tasks/lists")); len(again) != 1 {
		t.Fatalf("default list created twice: %+v", again)
	}
	listID := lists[0].ID
	create := func(body string, want int) workspaceTask {
		t.Helper()
		return decodeJSONResponse[workspaceTask](t, authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/tasks", csrf, body), want)
	}
	parent := create(`{"folder_id":"`+listID+`","summary":"Prepare trip","description":"Pack light","due":"2026-11-02","start":"2026-10-30","priority":1,"categories":["Personal"],"reminder_at":"2026-11-01T08:00:00Z"}`, http.StatusCreated)
	if parent.Summary != "Prepare trip" || parent.Due != "2026-11-02" || parent.Priority != 1 || parent.ReminderAt != "2026-11-01T08:00:00Z" || parent.Completed {
		t.Fatalf("created task = %+v", parent)
	}
	child := create(`{"folder_id":"`+listID+`","summary":"Book train","related_to":"`+parent.UID+`"}`, http.StatusCreated)
	if child.RelatedTo != parent.UID {
		t.Fatalf("subtask = %+v", child)
	}
	for _, invalid := range []string{
		`{"folder_id":"` + listID + `","summary":"Grandchild","related_to":"` + child.UID + `"}`,
		`{"folder_id":"` + listID + `","summary":"Orphan","related_to":"missing"}`,
		`{"folder_id":"` + listID + `","summary":""}`,
		`{"folder_id":"` + model.FolderKey("alice", "Calendar") + `","summary":"Wrong folder"}`,
	} {
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/tasks", csrf, invalid)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status=%d", invalid, response.StatusCode)
		}
	}
	updated := decodeJSONResponse[workspaceTask](t, authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/tasks/"+url.PathEscape(parent.ID), csrf, `{"summary":"Prepare the trip","priority":0}`), http.StatusOK)
	if updated.Summary != "Prepare the trip" || updated.Priority != 0 || updated.Due != "2026-11-02" || updated.Description != "Pack light" {
		t.Fatalf("updated task = %+v", updated)
	}

	// A repeating task completes into a recorded occurrence and moves on.
	series := create(`{"folder_id":"`+listID+`","summary":"Water plants","due":"2026-10-23","recurrence":"weekly"}`, http.StatusCreated)
	completed := decodeJSONResponse[struct {
		Task       workspaceTask  `json:"task"`
		Occurrence *workspaceTask `json:"completed_occurrence"`
	}](t, authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/tasks/"+url.PathEscape(series.ID)+"/complete", csrf, `{"completed":true}`), http.StatusOK)
	if completed.Task.Due != "2026-10-30" || completed.Task.Completed || completed.Occurrence == nil || !completed.Occurrence.Completed || completed.Occurrence.Due != "2026-10-23" || completed.Occurrence.Recurrence != "none" {
		t.Fatalf("recurring completion = %+v", completed)
	}
	done := decodeJSONResponse[struct {
		Task workspaceTask `json:"task"`
	}](t, authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/tasks/"+url.PathEscape(child.ID)+"/complete", csrf, `{"completed":true}`), http.StatusOK)
	if !done.Task.Completed || done.Task.CompletedAt == "" {
		t.Fatalf("completed subtask = %+v", done.Task)
	}

	tasks := decodeTestJSON[[]workspaceTask](t, mustGet(t, client, server.URL+"/api/v1/workspace/tasks?folder_id="+url.QueryEscape(listID)))
	if len(tasks) != 4 || tasks[0].ID != series.ID || tasks[1].ID != parent.ID || !tasks[2].Completed || !tasks[3].Completed {
		t.Fatalf("task order = %+v", tasks)
	}

	// CalDAV clients see the same VTODOs and their own writes appear here.
	folder, err := ts.FolderStore().Get(t.Context(), listID)
	if err != nil {
		t.Fatal(err)
	}
	report := `<?xml version="1.0"?><C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><C:calendar-data/></D:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VTODO"/></C:comp-filter></C:filter></C:calendar-query>`
	request := caldav.WithAuthenticatedUser(httptest.NewRequest("REPORT", "/dav/alice/"+folder.Path+"/", strings.NewReader(report)), "alice")
	recorder := httptest.NewRecorder()
	dav.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMultiStatus || strings.Count(recorder.Body.String(), "BEGIN:VTODO") != 4 || !strings.Contains(recorder.Body.String(), "RELATED-TO;RELTYPE=PARENT:"+parent.UID) {
		t.Fatalf("REPORT status=%d body=%s", recorder.Code, recorder.Body)
	}
	put := caldav.WithAuthenticatedUser(httptest.NewRequest(http.MethodPut, "/dav/alice/"+folder.Path+"/from-client.ics", strings.NewReader("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Client//EN\r\nBEGIN:VTODO\r\nUID:from-client\r\nDTSTAMP:20261023T000000Z\r\nSUMMARY:Synced from phone\r\nPRIORITY:5\r\nEND:VTODO\r\nEND:VCALENDAR\r\n")), "alice")
	recorder = httptest.NewRecorder()
	dav.ServeHTTP(recorder, put)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("CalDAV PUT status=%d body=%s", recorder.Code, recorder.Body)
	}
	tasks = decodeTestJSON[[]workspaceTask](t, mustGet(t, client, server.URL+"/api/v1/workspace/tasks?folder_id="+url.QueryEscape(listID)))
	if !slices.ContainsFunc(tasks, func(task workspaceTask) bool { return task.Summary == "Synced from phone" && task.Priority == 5 }) {
		t.Fatalf("CalDAV task missing from REST list: %+v", tasks)
	}

	// Deleting a parent trashes its subtasks.
	response := authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/tasks/"+url.PathEscape(parent.ID), csrf, "")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", response.StatusCode)
	}
	tasks = decodeTestJSON[[]workspaceTask](t, mustGet(t, client, server.URL+"/api/v1/workspace/tasks?folder_id="+url.QueryEscape(listID)))
	if slices.ContainsFunc(tasks, func(task workspaceTask) bool { return task.ID == parent.ID || task.ID == child.ID }) {
		t.Fatalf("parent or subtask survived delete: %+v", tasks)
	}
}

func TestFlaggedMailSmartListCompletesFollowUps(t *testing.T) {
	handler, ts := testHandler(t)
	if _, err := handler.ConfigureMailState(t.Context(), mailstate.Config{}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	inbox := model.InboxFolderID("alice")
	message := seedMail(t, handler, inbox, "From: amy@example.net\nSubject: Contract review\n\nbody\n", time.Now().Add(-time.Hour))
	due := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, `{"action":"follow_up","item_ids":["`+message.ID+`"],"due_at":"`+due+`"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("follow up status=%d", response.StatusCode)
	}
	type followUps struct {
		Items []followUpRow `json:"items"`
	}
	rows := decodeTestJSON[followUps](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/follow-ups"))
	if len(rows.Items) != 1 || rows.Items[0].ID != message.ID || rows.Items[0].FollowUp == nil || rows.Items[0].FollowUp.DueAt == nil {
		t.Fatalf("flagged smart list = %+v", rows.Items)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, `{"action":"complete","item_ids":["`+message.ID+`"]}`)
	_ = response.Body.Close()
	if rows = decodeTestJSON[followUps](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/follow-ups")); len(rows.Items) != 0 {
		t.Fatalf("completed follow-up still listed: %+v", rows.Items)
	}
	if stored, _ := ts.ItemStore().Get(t.Context(), message.ID); slices.Contains(stored.Flags, model.FlagFlagged) {
		t.Fatalf("flag kept after completion: %v", stored.Flags)
	}
}
