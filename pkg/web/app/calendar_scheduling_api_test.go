package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
)

type schedulingFixture struct {
	handler *Handler
	ts      *model.TypedStore
	server  *httptest.Server
	mu      sync.Mutex
	sent    []imip.Outgoing
	// local holds the Inbox copies of scheduling messages for local attendees.
	local []imip.Outgoing
}

func (f *schedulingFixture) takeSent() []imip.Outgoing {
	f.mu.Lock()
	defer f.mu.Unlock()
	sent := f.sent
	f.sent = nil
	return sent
}

// newSchedulingFixture serves the app over an observed FolderSpace with iMIP
// scheduling, alice@example.test (the logged-in owner), bob@example.test in
// the same domain, and dave@other.test in another domain.
func newSchedulingFixture(t *testing.T) *schedulingFixture {
	t.Helper()
	ctx := t.Context()
	handler, ts := testHandler(t)
	for _, namespace := range model.Namespaces() {
		if err := ts.EnsureNamespace(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}
	base := service.NewFolderSpace(ts, authz.New(ts))
	automation, err := rules.NewEngine(ctx, ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(automation.Close)
	space, err := rules.NewFolderSpace(base, automation)
	if err != nil {
		t.Fatal(err)
	}
	f := &schedulingFixture{handler: handler, ts: ts}
	scheduling, err := imip.New(ctx, imip.Config{
		Space: space, Store: ts.Store(), Identity: ts.UserStore().GetEmailAddress,
		Resolve: func(ctx context.Context, address string) (model.RecipientRoute, error) {
			return ts.ResolveRecipient(ctx, address, "+")
		},
		Send: func(_ context.Context, message imip.Outgoing) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if message.Local {
				f.local = append(f.local, message)
			} else {
				f.sent = append(f.sent, message)
			}
			return nil
		},
		Resource: func(ctx context.Context, userID string) *model.ResourceProfile {
			user, err := ts.UserStore().Get(ctx, userID)
			if err != nil {
				return nil
			}
			return user.Resource
		},
		Busy: func(ctx context.Context, userID string, start, end time.Time) ([]calendarindex.BusyPeriod, error) {
			return handler.BusyPeriods(ctx, userID, nil, start, end)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	space.SetItemObserver(scheduling)
	handler.ConfigureMigrations(space, nil)
	handler.ConfigureCalendarScheduling(scheduling)
	mux := http.NewServeMux()
	handler.Register(mux)
	f.server = serveTestApp(t, handler, mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *schedulingFixture) addUser(t *testing.T, login, domain string) {
	t.Helper()
	ctx := t.Context()
	if _, err := f.ts.DomainStore().Get(ctx, domain); err != nil {
		if err := f.ts.DomainStore().Create(ctx, domain); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.ts.UserStore().Get(ctx, login); err != nil {
		if err := f.ts.UserStore().Create(ctx, login, strings.ToUpper(login[:1])+login[1:], "password123"); err != nil {
			t.Fatal(err)
		}
		if err := f.ts.FolderStore().CreateForUser(ctx, login); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.ts.UserStore().AddEmailAddress(ctx, login+"@"+domain, login, domain, true); err != nil {
		t.Fatal(err)
	}
}

func (f *schedulingFixture) calendarID(t *testing.T, user string) string {
	t.Helper()
	folder, err := f.ts.FolderStore().GetByPath(t.Context(), user, "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	return folder.ID
}

func decodeJSONResponse[T any](t *testing.T, response *http.Response, want int) T {
	t.Helper()
	defer response.Body.Close()
	var value T
	if response.StatusCode != want {
		var body map[string]any
		_ = json.NewDecoder(response.Body).Decode(&body)
		t.Fatalf("status = %d, want %d: %v", response.StatusCode, want, body)
	}
	if want != http.StatusNoContent {
		if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
			t.Fatal(err)
		}
	}
	return value
}

func TestCalendarAttendeeSaveSchedulesLocalAndExternalAttendees(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	f.addUser(t, "alice", "example.test")
	f.addUser(t, "bob", "example.test")
	ctx := t.Context()
	calendarID := f.calendarID(t, "alice")

	body := `{"folder_id":"` + calendarID + `","summary":"Design review","start":"2026-11-12T09:00:00Z","end":"2026-11-12T10:00:00Z","timezone":"UTC",
		"attendees":[{"address":"bob@example.test","role":"REQ-PARTICIPANT"},{"address":"Carol <carol@remote.test>","name":"Carol","role":"OPT-PARTICIPANT"}],
		"alarms":[15,1440],"categories":["Design"],"recurrence":"FREQ=WEEKLY;BYDAY=TH;COUNT=4"}`
	created := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/events", csrf, body), http.StatusCreated)
	if created.OrganizerAddress != "alice@example.test" || len(created.Participants) != 2 || created.Participants[1].Role != "OPT-PARTICIPANT" || created.RRule != "FREQ=WEEKLY;BYDAY=TH;COUNT=4" || len(created.Alarms) != 2 || *created.Alarms[0].MinutesBefore != 15 || created.Categories[0] != "Design" {
		t.Fatalf("created = %+v", created)
	}
	sent := f.takeSent()
	if len(sent) != 1 || sent[0].From != "alice@example.test" || len(sent[0].To) != 1 || sent[0].To[0] != "carol@remote.test" {
		t.Fatalf("external invitation = %+v", sent)
	}
	f.mu.Lock()
	local := f.local
	f.mu.Unlock()
	if len(local) != 1 || local[0].To[0] != "bob@example.test" || !strings.Contains(string(local[0].Raw), "Subject: Invitation: Design review") {
		t.Fatalf("local attendee Inbox invitation = %+v", local)
	}
	bobAccess := service.UserAccess("bob", "test")
	bobItems, err := f.handler.folderSpace.ListItems(ctx, bobAccess, f.calendarID(t, "bob"), service.ItemQuery{})
	if err != nil || len(bobItems) != 1 {
		t.Fatalf("bob's calendar = %d items, %v", len(bobItems), err)
	}
	bobCopy, err := f.handler.folderSpace.GetItem(ctx, bobAccess, bobItems[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if event, _ := calendar.Project(bobCopy.Data); event.UID != created.UID || event.OrganizerAddress != "alice@example.test" || len(event.Alarms) != 0 {
		t.Fatalf("bob's copy = %+v", event)
	}

	// The organizer reads the event with its scheduling role.
	read := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodGet, f.server.URL+"/api/v1/workspace/calendar/events/"+url.PathEscape(created.ID), csrf, ""), http.StatusOK)
	if read.Scheduling == nil || !read.Scheduling.IsOrganizer || read.Scheduling.CanRespond {
		t.Fatalf("organizer scheduling = %+v", read.Scheduling)
	}

	// Saving without attendees, alarms, or recurrence preserves them; a
	// new time updates every attendee.
	update := `{"summary":"Design review","start":"2026-11-12T11:00:00Z","end":"2026-11-12T12:00:00Z","timezone":"UTC"}`
	updated := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodPut, f.server.URL+"/api/v1/workspace/calendar/events/"+url.PathEscape(created.ID), csrf, update), http.StatusOK)
	if len(updated.Participants) != 2 || len(updated.Alarms) != 2 || updated.RRule != created.RRule || updated.Sequence != 1 {
		t.Fatalf("updated = %+v", updated)
	}
	if sent := f.takeSent(); len(sent) != 1 || !strings.Contains(string(sent[0].Raw), "Updated invitation") {
		t.Fatalf("update sent %+v", sent)
	}
	bobCopy, _ = f.handler.folderSpace.GetItem(ctx, bobAccess, bobItems[0].ID)
	if !strings.Contains(string(bobCopy.Data), "T110000Z") {
		t.Fatalf("bob's copy not updated:\n%s", bobCopy.Data)
	}

	// Removing every attendee cancels the meeting for both.
	clear := `{"summary":"Design review","start":"2026-11-12T11:00:00Z","end":"2026-11-12T12:00:00Z","timezone":"UTC","attendees":[]}`
	decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodPut, f.server.URL+"/api/v1/workspace/calendar/events/"+url.PathEscape(created.ID), csrf, clear), http.StatusOK)
	if sent := f.takeSent(); len(sent) != 1 || !strings.Contains(string(sent[0].Raw), "Cancelled: Design review") {
		t.Fatalf("cancel sent %+v", sent)
	}
	bobCopy, _ = f.handler.folderSpace.GetItem(ctx, bobAccess, bobItems[0].ID)
	if !strings.Contains(string(bobCopy.Data), "STATUS:CANCELLED") {
		t.Fatalf("bob's copy not cancelled:\n%s", bobCopy.Data)
	}

	invalid := `{"folder_id":"` + calendarID + `","summary":"x","start":"2026-11-12T09:00:00Z","attendees":[{"address":"nope"}]}`
	response := authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/events", csrf, invalid)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid attendee status = %d", response.StatusCode)
	}
}

func TestCalendarRespondCounterAndProposalDecisionAPI(t *testing.T) {
	f := newSchedulingFixture(t)
	aliceClient := testClient(t)
	aliceCSRF := setupAndLogin(t, f.server, aliceClient, "alice")
	f.addUser(t, "alice", "example.test")
	f.addUser(t, "bob", "example.test")
	body := `{"folder_id":"` + f.calendarID(t, "alice") + `","summary":"Sync","start":"2026-11-13T09:00:00Z","end":"2026-11-13T09:30:00Z","timezone":"UTC","attendees":[{"address":"bob@example.test"}]}`
	created := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, aliceClient, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/events", aliceCSRF, body), http.StatusCreated)

	bobClient := testClient(t)
	bobCSRF := loginExistingUser(t, bobClient, f.server.URL, "bob")
	bobItems, err := f.handler.folderSpace.ListItems(t.Context(), service.UserAccess("bob", "test"), f.calendarID(t, "bob"), service.ItemQuery{})
	if err != nil || len(bobItems) != 1 {
		t.Fatalf("bob's copy: %d %v", len(bobItems), err)
	}
	copyURL := f.server.URL + "/api/v1/workspace/calendar/events/" + url.PathEscape(bobItems[0].ID)
	view := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, bobClient, http.MethodGet, copyURL, bobCSRF, ""), http.StatusOK)
	if view.Scheduling == nil || !view.Scheduling.CanRespond || view.Scheduling.Response != "NEEDS-ACTION" {
		t.Fatalf("attendee scheduling = %+v", view.Scheduling)
	}
	// Bob cannot change the attendees of alice's meeting from his copy.
	response := authenticatedJSON(t, bobClient, http.MethodPut, copyURL, bobCSRF, `{"summary":"Sync","start":"2026-11-13T09:00:00Z","attendees":[]}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendee edit of a foreign meeting status = %d", response.StatusCode)
	}
	answered := decodeJSONResponse[imip.Invitation](t, authenticatedJSON(t, bobClient, http.MethodPost, copyURL+"/respond", bobCSRF, `{"response":"TENTATIVE","comment":"Might be late"}`), http.StatusOK)
	if answered.Response != "TENTATIVE" {
		t.Fatalf("answer = %+v", answered)
	}
	decodeJSONResponse[imip.Invitation](t, authenticatedJSON(t, bobClient, http.MethodPost, copyURL+"/respond", bobCSRF, `{"comment":"Afternoon?","propose_start":"2026-11-13T14:00:00Z","propose_end":"2026-11-13T14:30:00Z"}`), http.StatusOK)
	response = authenticatedJSON(t, bobClient, http.MethodPost, copyURL+"/respond", bobCSRF, `{"propose_start":"2026-11-13T14:00:00Z"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("incomplete proposal status = %d", response.StatusCode)
	}

	eventURL := f.server.URL + "/api/v1/workspace/calendar/events/" + url.PathEscape(created.ID)
	organizer := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, aliceClient, http.MethodGet, eventURL, aliceCSRF, ""), http.StatusOK)
	if organizer.Participants[0].PartStat != "TENTATIVE" || organizer.Scheduling.Comments["bob@example.test"] != "Might be late" || len(organizer.Scheduling.Proposals) != 1 || organizer.Scheduling.Proposals[0].Comment != "Afternoon?" {
		t.Fatalf("organizer view = %+v / %+v", organizer.Participants, organizer.Scheduling)
	}
	// Only the organizer decides, and only on a pending proposal.
	response = authenticatedJSON(t, bobClient, http.MethodPost, copyURL+"/proposal", bobCSRF, `{"attendee":"bob@example.test","decision":"accept"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("attendee decision status = %d", response.StatusCode)
	}
	// A reader of alice's calendar neither sees nor decides her proposals.
	f.addUser(t, "carol", "example.test")
	decodeJSONResponse[calendarShare](t, authenticatedJSON(t, aliceClient, http.MethodPost, f.server.URL+"/api/v1/workspace/calendars/"+f.calendarID(t, "alice")+"/sharing", aliceCSRF, `{"recipient":"carol@example.test","role":"folder.viewer"}`), http.StatusCreated)
	carolClient := testClient(t)
	carolCSRF := loginExistingUser(t, carolClient, f.server.URL, "carol")
	carolView := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, carolClient, http.MethodGet, eventURL, carolCSRF, ""), http.StatusOK)
	if carolView.Scheduling == nil || len(carolView.Scheduling.Proposals) != 0 || len(carolView.Scheduling.Comments) != 0 {
		t.Fatalf("viewer scheduling = %+v", carolView.Scheduling)
	}
	for _, decision := range []string{"decline", "accept"} {
		response = authenticatedJSON(t, carolClient, http.MethodPost, eventURL+"/proposal", carolCSRF, `{"attendee":"bob@example.test","decision":"`+decision+`"}`)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer %s status = %d", decision, response.StatusCode)
		}
	}
	organizer = decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, aliceClient, http.MethodGet, eventURL, aliceCSRF, ""), http.StatusOK)
	if len(organizer.Scheduling.Proposals) != 1 {
		t.Fatalf("viewer decisions dropped the proposal: %+v", organizer.Scheduling)
	}
	decodeJSONResponse[struct{}](t, authenticatedJSON(t, aliceClient, http.MethodPost, eventURL+"/proposal", aliceCSRF, `{"attendee":"bob@example.test","decision":"accept"}`), http.StatusNoContent)
	organizer = decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, aliceClient, http.MethodGet, eventURL, aliceCSRF, ""), http.StatusOK)
	if !strings.HasPrefix(organizer.DTStart, "2026-11-13T") || organizer.Sequence != 1 || len(organizer.Scheduling.Proposals) != 0 || organizer.Participants[0].PartStat != "ACCEPTED" {
		t.Fatalf("after accepting = %+v", organizer)
	}
	if start, _ := organizer.DTStart, 0; !strings.Contains(start, "14:00:00") && !strings.Contains(start, "T14:00") {
		t.Fatalf("event start = %s, want 14:00 UTC", start)
	}
	response = authenticatedJSON(t, aliceClient, http.MethodPost, eventURL+"/proposal", aliceCSRF, `{"attendee":"bob@example.test","decision":"decline"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("decision without a proposal status = %d", response.StatusCode)
	}
}

func TestCalendarFreeBusyRevealsOnlyPermittedBusyTimes(t *testing.T) {
	f := newSchedulingFixture(t)
	// The installation owner may read every calendar; the requester is an
	// ordinary account.
	setupAndLogin(t, f.server, testClient(t), "root")
	f.addUser(t, "alice", "example.test")
	f.addUser(t, "bob", "example.test")
	f.addUser(t, "dave", "other.test")
	client := testClient(t)
	loginExistingUser(t, client, f.server.URL, "alice")
	ctx := t.Context()
	put := func(user, name, ics string) {
		t.Helper()
		if _, err := f.handler.folderSpace.CreateItem(ctx, service.UserAccess(user, "test"), f.calendarID(t, user), service.ItemInput{Name: name, Data: []byte(ics)}); err != nil {
			t.Fatal(err)
		}
	}
	vevent := func(uid, start, end, extra string) string {
		return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:" + uid + "\r\nDTSTAMP:20261001T000000Z\r\nDTSTART:" + start + "\r\nDTEND:" + end + "\r\nSUMMARY:Secret " + uid + "\r\n" + extra + "END:VEVENT\r\nEND:VCALENDAR\r\n"
	}
	put("bob", "a.ics", vevent("b1", "20261116T090000Z", "20261116T100000Z", ""))
	put("bob", "b.ics", vevent("b2", "20261116T093000Z", "20261116T110000Z", ""))
	put("bob", "c.ics", vevent("b3", "20261116T130000Z", "20261116T140000Z", "STATUS:TENTATIVE\r\n"))
	put("bob", "d.ics", vevent("b4", "20261116T150000Z", "20261116T160000Z", "TRANSP:TRANSPARENT\r\n"))
	put("bob", "e.ics", vevent("b5", "20261116T170000Z", "20261116T180000Z", "STATUS:CANCELLED\r\n"))
	put("dave", "f.ics", vevent("d1", "20261116T090000Z", "20261116T100000Z", ""))

	query := url.Values{"start": {"2026-11-16T00:00:00Z"}, "end": {"2026-11-17T00:00:00Z"}, "attendee": {"bob@example.test", "dave@other.test", "zed@remote.test", "ALICE@example.test"}}
	response, err := client.Get(f.server.URL + "/api/v1/workspace/calendar/freebusy?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	raw := decodeJSONResponse[json.RawMessage](t, response, http.StatusOK)
	if strings.Contains(string(raw), "Secret") {
		t.Fatalf("free/busy leaked event details: %s", raw)
	}
	var result []freeBusyAttendee
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 4 || result[0].Status != "known" || result[1].Status != "unknown" || result[2].Status != "unknown" || result[3].Status != "known" || len(result[1].Busy) != 0 {
		t.Fatalf("free/busy = %+v", result)
	}
	bob := result[0].Busy
	if len(bob) != 2 || bob[0].Type != "BUSY" || bob[0].Start.Hour() != 9 || bob[0].End.Hour() != 11 || bob[1].Type != "BUSY-TENTATIVE" || bob[1].Start.Hour() != 13 {
		t.Fatalf("bob busy = %+v", bob)
	}

	// Sharing a calendar makes another domain's availability visible.
	if err := f.ts.FolderStore().Create(ctx, "dave", "Shared", model.FolderTypeCalendar, ""); err != nil {
		t.Fatal(err)
	}
	shared, err := f.ts.FolderStore().GetByPath(ctx, "dave", "Shared")
	if err != nil {
		t.Fatal(err)
	}
	put("dave", "g.ics", vevent("d2", "20261116T120000Z", "20261116T123000Z", ""))
	grant := authenticatedJSONAs(t, f, "dave", http.MethodPost, "/api/v1/folders/"+url.PathEscape(shared.ID)+"/grants", `{"principal":{"kind":"user","id":"alice"},"effect":"allow","role_id":"folder.viewer","inheritance":"self"}`)
	if grant != http.StatusOK && grant != http.StatusCreated {
		t.Fatalf("folder grant status = %d", grant)
	}
	response, err = client.Get(f.server.URL + "/api/v1/workspace/calendar/freebusy?" + url.Values{"start": {"2026-11-16T00:00:00Z"}, "end": {"2026-11-17T00:00:00Z"}, "attendee": {"dave@other.test"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	result = decodeJSONResponse[[]freeBusyAttendee](t, response, http.StatusOK)
	if result[0].Status != "known" || len(result[0].Busy) != 2 {
		t.Fatalf("shared free/busy = %+v", result)
	}

	for _, bad := range []url.Values{
		{"start": {"2026-11-16T00:00:00Z"}, "end": {"2026-11-16T00:00:00Z"}, "attendee": {"bob@example.test"}},
		{"start": {"2026-11-16T00:00:00Z"}, "end": {"2027-02-16T00:00:00Z"}, "attendee": {"bob@example.test"}},
		{"start": {"2026-11-16T00:00:00Z"}, "end": {"2026-11-17T00:00:00Z"}},
	} {
		response, err := client.Get(f.server.URL + "/api/v1/workspace/calendar/freebusy?" + bad.Encode())
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("query %v status = %d", bad, response.StatusCode)
		}
	}
	anonymous, err := http.Get(f.server.URL + "/api/v1/workspace/calendar/freebusy?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized && anonymous.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous free/busy status = %d", anonymous.StatusCode)
	}
}

// authenticatedJSONAs logs user in on a fresh client and performs one
// request, returning its status.
func authenticatedJSONAs(t *testing.T, f *schedulingFixture, user, method, path, body string) int {
	t.Helper()
	client := testClient(t)
	csrf := loginExistingUser(t, client, f.server.URL, user)
	response := authenticatedJSON(t, client, method, f.server.URL+path, csrf, body)
	_ = response.Body.Close()
	return response.StatusCode
}
