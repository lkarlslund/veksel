package app

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/calendarfeed"
	"github.com/lkarlslund/veksel/pkg/calendarport"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const importedCalendar = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nX-WR-CALNAME:Team\r\n" +
	"BEGIN:VTIMEZONE\r\nTZID:Europe/Copenhagen\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nRRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\nEND:STANDARD\r\nBEGIN:DAYLIGHT\r\nDTSTART:19700329T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\nRRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\nEND:DAYLIGHT\r\nEND:VTIMEZONE\r\n" +
	"BEGIN:VEVENT\r\nUID:standup@test\r\nDTSTAMP:20261101T000000Z\r\nDTSTART;TZID=Europe/Copenhagen:20261102T090000\r\nDTEND;TZID=Europe/Copenhagen:20261102T091500\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\nEXDATE;TZID=Europe/Copenhagen:20261116T090000\r\nSUMMARY:Standup\r\nEND:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nUID:standup@test\r\nDTSTAMP:20261101T000000Z\r\nRECURRENCE-ID;TZID=Europe/Copenhagen:20261109T090000\r\nDTSTART;TZID=Europe/Copenhagen:20261109T100000\r\nDTEND;TZID=Europe/Copenhagen:20261109T101500\r\nSUMMARY:Standup (moved)\r\nEND:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261220T120000Z\r\nDTEND:20261220T130000Z\r\nSUMMARY:Holiday lunch\r\nEND:VEVENT\r\n" +
	"BEGIN:VTODO\r\nUID:todo@test\r\nSUMMARY:Not an event\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"

func calendarEvents(t *testing.T, client *http.Client, base, csrf, calendarID, start, end string) []workspaceCalendarEvent {
	t.Helper()
	query := url.Values{"folder_id": {calendarID}, "start": {start}, "end": {end}}
	return decodeJSONResponse[[]workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodGet, base+"/api/v1/workspace/calendar/events?"+query.Encode(), csrf, ""), http.StatusOK)
}

func getBody(t *testing.T, client *http.Client, endpoint string) (int, string) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

func TestCalendarImportExportRoundTripKeepsRecurrenceExceptions(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	f.addUser(t, "alice", "example.test")
	calendarID := f.calendarID(t, "alice")
	importURL := f.server.URL + "/api/v1/workspace/calendar/import?folder_id=" + url.QueryEscape(calendarID)

	result := decodeJSONResponse[calendarImportResult](t, authenticatedJSON(t, client, http.MethodPost, importURL, csrf, importedCalendar), http.StatusOK)
	if result.Created != 2 || result.Updated != 0 || result.Failed != 0 || result.Skipped != 1 || result.Events != 3 {
		t.Fatalf("first import = %+v", result)
	}
	// The same file again replaces the events by UID instead of duplicating them.
	result = decodeJSONResponse[calendarImportResult](t, authenticatedJSON(t, client, http.MethodPost, importURL, csrf, importedCalendar), http.StatusOK)
	if result.Created != 0 || result.Updated != 2 {
		t.Fatalf("second import = %+v", result)
	}
	invalid := decodeJSONResponse[calendarImportResult](t, authenticatedJSON(t, client, http.MethodPost, importURL, csrf, "not a calendar"), http.StatusUnprocessableEntity)
	if len(invalid.Problems) == 0 {
		t.Fatalf("invalid import = %+v", invalid)
	}

	events := calendarEvents(t, client, f.server.URL, csrf, calendarID, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z")
	var summaries []string
	for _, event := range events {
		summaries = append(summaries, event.Summary+"@"+event.DTStart)
	}
	joined := strings.Join(summaries, ",")
	if len(events) != 3 || !strings.Contains(joined, "Standup (moved)@2026-11-09T10:00:00+01:00") || strings.Contains(joined, "2026-11-16") {
		t.Fatalf("imported occurrences = %s", joined)
	}

	status, exported := getBody(t, client, f.server.URL+"/api/v1/workspace/calendar/export?folder_id="+url.QueryEscape(calendarID))
	if status != http.StatusOK {
		t.Fatalf("export status = %d", status)
	}
	document := calendarport.Parse([]byte(exported))
	if len(document.Objects) != 2 || strings.Count(exported, "BEGIN:VTIMEZONE") != 1 || !strings.Contains(exported, "RECURRENCE-ID;TZID=Europe/Copenhagen:20261109T090000") || !strings.Contains(exported, "EXDATE;TZID=Europe/Copenhagen:20261116T090000") {
		t.Fatalf("export = %d objects:\n%s", len(document.Objects), exported)
	}
	// Re-importing the export into a new calendar reproduces the occurrences.
	folder := decodeJSONResponse[model.Folder](t, authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/folders", csrf, `{"name":"Copy","type":"calendar"}`), http.StatusCreated)
	decodeJSONResponse[calendarImportResult](t, authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/import?folder_id="+url.QueryEscape(folder.ID), csrf, exported), http.StatusOK)
	if copied := calendarEvents(t, client, f.server.URL, csrf, folder.ID, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"); len(copied) != 3 {
		t.Fatalf("round trip occurrences = %+v", copied)
	}

	query := url.Values{"folder_id": {calendarID}, "start": {"2026-12-01T00:00:00Z"}, "end": {"2027-01-01T00:00:00Z"}}
	_, ranged := getBody(t, client, f.server.URL+"/api/v1/workspace/calendar/export?"+query.Encode())
	if !strings.Contains(ranged, "Holiday lunch") || strings.Contains(ranged, "Standup") {
		t.Fatalf("range export:\n%s", ranged)
	}
}

func TestCalendarSubscriptionRefreshUsesETagAndRefusesPrivateAddresses(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	var requests, conditional atomic.Int32
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "text/calendar")
		_, _ = io.WriteString(w, importedCalendar)
	}))
	t.Cleanup(feed.Close)
	feedURL := strings.Replace(feed.URL, "http://", "webcal://", 1)
	feedURL = strings.Replace(feedURL, "webcal://", "http://", 1) // the test server speaks plain HTTP

	// Loopback feeds are refused by default; the failure is kept on the subscription.
	created := decodeJSONResponse[calendarfeed.Subscription](t, authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/subscriptions", csrf, `{"url":"`+feedURL+`/team.ics","interval":"hourly"}`), http.StatusCreated)
	if !strings.Contains(created.LastError, "private") || requests.Load() != 0 || created.Interval != calendarfeed.Hourly {
		t.Fatalf("refused subscription = %+v, requests = %d", created, requests.Load())
	}
	bad := authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/subscriptions", csrf, `{"url":"ftp://example.test/x.ics"}`)
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("ftp subscription status = %d", bad.StatusCode)
	}

	f.handler.calendarFeeds.SetAllowPrivateNetworks(true)
	refreshURL := f.server.URL + "/api/v1/workspace/calendar/subscriptions/" + created.ID + "/refresh"
	refreshed := decodeJSONResponse[calendarfeed.Subscription](t, authenticatedJSON(t, client, http.MethodPost, refreshURL, csrf, ""), http.StatusOK)
	if refreshed.LastError != "" || refreshed.Events != 2 || refreshed.LastSuccess.IsZero() {
		t.Fatalf("refreshed = %+v", refreshed)
	}
	events := calendarEvents(t, client, f.server.URL, csrf, subscriptionCalendarPrefix+created.ID, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z")
	if len(events) != 3 || !events[0].ReadOnly || !strings.HasPrefix(events[0].ID, subscriptionCalendarPrefix+created.ID+"/") {
		t.Fatalf("subscription events = %+v", events)
	}
	// An unchanged feed answers the conditional request with 304 and keeps the events.
	refreshed = decodeJSONResponse[calendarfeed.Subscription](t, authenticatedJSON(t, client, http.MethodPost, refreshURL, csrf, ""), http.StatusOK)
	if conditional.Load() != 1 || refreshed.Events != 2 || refreshed.LastError != "" {
		t.Fatalf("conditional refresh = %+v, 304s = %d", refreshed, conditional.Load())
	}
	if again := calendarEvents(t, client, f.server.URL, csrf, subscriptionCalendarPrefix+created.ID, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"); len(again) != 3 {
		t.Fatalf("events after 304 = %d", len(again))
	}
	updated := decodeJSONResponse[calendarfeed.Subscription](t, authenticatedJSON(t, client, http.MethodPatch, f.server.URL+"/api/v1/workspace/calendar/subscriptions/"+created.ID, csrf, `{"name":"Team feed","interval":"daily","color":"#336699"}`), http.StatusOK)
	if updated.Name != "Team feed" || updated.Interval != calendarfeed.Daily || updated.Color != "#336699" {
		t.Fatalf("updated = %+v", updated)
	}
	// Subscriptions are per account.
	f.addUser(t, "bob", "example.test")
	if status := authenticatedJSONAs(t, f, "bob", http.MethodGet, "/api/v1/workspace/calendar/events?folder_id="+subscriptionCalendarPrefix+created.ID+"&start=2026-11-01T00:00:00Z&end=2026-12-01T00:00:00Z", ""); status != http.StatusNotFound {
		t.Fatalf("other account reading the subscription status = %d", status)
	}
	decodeJSONResponse[struct{}](t, authenticatedJSON(t, client, http.MethodDelete, f.server.URL+"/api/v1/workspace/calendar/subscriptions/"+created.ID, csrf, ""), http.StatusNoContent)
	if list := decodeJSONResponse[[]calendarfeed.Subscription](t, authenticatedJSON(t, client, http.MethodGet, f.server.URL+"/api/v1/workspace/calendar/subscriptions", csrf, ""), http.StatusOK); len(list) != 0 {
		t.Fatalf("after delete = %+v", list)
	}
}

func TestPublishedCalendarTokenFreeBusyAndRevocation(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	f.addUser(t, "alice", "example.test")
	calendarID := f.calendarID(t, "alice")
	body := `{"folder_id":"` + calendarID + `","summary":"Dentist","start":"2026-11-20T09:00:00Z","end":"2026-11-20T10:00:00Z","timezone":"UTC"}`
	decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/events", csrf, body), http.StatusCreated)
	publishURL := f.server.URL + "/api/v1/workspace/calendars/" + calendarID + "/publish"

	full := decodeJSONResponse[calendarPublication](t, authenticatedJSON(t, client, http.MethodPost, publishURL, csrf, `{"format":"ics"}`), http.StatusCreated)
	busy := decodeJSONResponse[calendarPublication](t, authenticatedJSON(t, client, http.MethodPost, publishURL, csrf, `{"format":"freebusy"}`), http.StatusCreated)
	if !strings.HasPrefix(full.Path, "/share/calendar/v1.") || full.Publish != "ics" || busy.Publish != "freebusy" {
		t.Fatalf("publications = %+v / %+v", full, busy)
	}
	anonymous := &http.Client{}
	// A private event publishes as a busy block, and no event carries its
	// attendees, alarms, or extension properties.
	for name, ics := range map[string]string{
		"private.ics": "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:secret-uid\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261121T090000Z\r\nDTEND:20261121T100000Z\r\nSUMMARY:Therapy\r\nLOCATION:Clinic\r\nCLASS:PRIVATE\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
		"public.ics":  "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:open-uid\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261122T090000Z\r\nDTEND:20261122T100000Z\r\nSUMMARY:Standup\r\nATTENDEE:mailto:guest@elsewhere.test\r\nX-SECRET:note\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Alarm text\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
	} {
		if _, err := f.handler.folderSpace.CreateItem(t.Context(), service.UserAccess("alice", "test"), calendarID, service.ItemInput{Name: name, Data: []byte(ics)}); err != nil {
			t.Fatal(err)
		}
	}
	status, document := getBody(t, anonymous, f.server.URL+full.Path)
	if status != http.StatusOK || !strings.Contains(document, "SUMMARY:Dentist") || !strings.Contains(document, "SUMMARY:Standup") || !strings.Contains(document, "DTSTART:20261121T090000Z") {
		t.Fatalf("published feed %d:\n%s", status, document)
	}
	for _, leaked := range []string{"Therapy", "Clinic", "secret-uid", "guest@elsewhere.test", "X-SECRET", "Alarm text"} {
		if strings.Contains(document, leaked) {
			t.Fatalf("published feed leaks %q:\n%s", leaked, document)
		}
	}
	status, document = getBody(t, anonymous, f.server.URL+busy.Path)
	if status != http.StatusOK || strings.Contains(document, "Dentist") || !strings.Contains(document, "SUMMARY:Busy") || !strings.Contains(document, "DTSTART:20261120T090000Z") {
		t.Fatalf("free/busy feed %d:\n%s", status, document)
	}
	// The published token opens nothing but the feed.
	request, _ := http.NewRequest(http.MethodGet, f.server.URL+"/api/v1/public/share", nil)
	request.Header.Set("Authorization", "Share "+strings.TrimSuffix(strings.TrimPrefix(full.Path, "/share/calendar/"), ".ics"))
	if response, err := anonymous.Do(request); err != nil || response.StatusCode != http.StatusNotFound {
		t.Fatalf("published token opened the share browser: %v %v", response.StatusCode, err)
	}
	if status, _ := getBody(t, anonymous, f.server.URL+"/share/calendar/v1.forged.token.ics"); status != http.StatusNotFound {
		t.Fatalf("forged token status = %d", status)
	}
	sharingView := decodeJSONResponse[calendarSharingView](t, authenticatedJSON(t, client, http.MethodGet, f.server.URL+"/api/v1/workspace/calendars/"+calendarID+"/sharing", csrf, ""), http.StatusOK)
	if len(sharingView.Links) != 2 || sharingView.Links[0].Path != "" {
		t.Fatalf("sharing view links = %+v", sharingView.Links)
	}
	decodeJSONResponse[struct{}](t, authenticatedJSON(t, client, http.MethodDelete, f.server.URL+"/api/v1/share-links/"+full.ID, csrf, ""), http.StatusNoContent)
	if status, _ := getBody(t, anonymous, f.server.URL+full.Path); status != http.StatusNotFound {
		t.Fatalf("revoked feed status = %d", status)
	}
	if status, _ := getBody(t, anonymous, f.server.URL+busy.Path); status != http.StatusOK {
		t.Fatalf("other publication status after revoking one = %d", status)
	}
	if bad := authenticatedJSON(t, client, http.MethodPost, publishURL, csrf, `{"format":"html"}`); bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid publish format status = %d", bad.StatusCode)
	}
}

func TestCalendarSharingRolesAreEnforced(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	f.addUser(t, "alice", "example.test")
	f.addUser(t, "bob", "example.test")
	calendarID := f.calendarID(t, "alice")
	body := `{"folder_id":"` + calendarID + `","summary":"Salary talk","start":"2026-11-20T09:00:00Z","end":"2026-11-20T10:00:00Z","timezone":"UTC"}`
	decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/events", csrf, body), http.StatusCreated)
	sharingURL := f.server.URL + "/api/v1/workspace/calendars/" + calendarID + "/sharing"
	share := func(role string) calendarShare {
		return decodeJSONResponse[calendarShare](t, authenticatedJSON(t, client, http.MethodPost, sharingURL, csrf, `{"recipient":"bob@example.test","role":"`+role+`"}`), http.StatusCreated)
	}
	bobClient := testClient(t)
	bobCSRF := loginExistingUser(t, bobClient, f.server.URL, "bob")
	bobFolder := func() workspaceFolder {
		folders := decodeJSONResponse[[]workspaceFolder](t, authenticatedJSON(t, bobClient, http.MethodGet, f.server.URL+"/api/v1/workspace/folders", bobCSRF, ""), http.StatusOK)
		for _, folder := range folders {
			if folder.ID == calendarID {
				return folder
			}
		}
		t.Fatal("shared calendar is not listed for bob")
		return workspaceFolder{}
	}
	create := `{"folder_id":"` + calendarID + `","summary":"Bob's","start":"2026-11-21T09:00:00Z","end":"2026-11-21T10:00:00Z","timezone":"UTC"}`

	freeBusy := share("calendar.freebusy")
	if freeBusy.Name != "Bob" || freeBusy.RoleName != "Free/busy only" || freeBusy.Address != "bob@example.test" {
		t.Fatalf("share = %+v", freeBusy)
	}
	folder := bobFolder()
	if folder.Capabilities.ReadItems || !folder.Capabilities.FreeBusy || folder.OwnerName != "alice" {
		t.Fatalf("free/busy folder = %+v", folder)
	}
	events := calendarEvents(t, bobClient, f.server.URL, bobCSRF, calendarID, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z")
	if len(events) != 1 || events[0].Summary != "Busy" || !events[0].FreeBusyOnly || !strings.Contains(events[0].ID, "/busy/") {
		t.Fatalf("free/busy events = %+v", events)
	}
	if status := authenticatedJSONAs(t, f, "bob", http.MethodPost, "/api/v1/workspace/calendar/events", create); status == http.StatusCreated {
		t.Fatal("free/busy recipient created an event")
	}
	if status, _ := getBody(t, bobClient, f.server.URL+"/api/v1/workspace/calendar/export?folder_id="+calendarID); status != http.StatusForbidden {
		t.Fatalf("free/busy export status = %d", status)
	}

	share("folder.viewer")
	view := decodeJSONResponse[calendarSharingView](t, authenticatedJSON(t, client, http.MethodGet, sharingURL, csrf, ""), http.StatusOK)
	if len(view.Shares) != 1 || view.Shares[0].RoleID != "folder.viewer" || len(view.Roles) != 4 {
		t.Fatalf("sharing replaces the earlier role: %+v", view.Shares)
	}
	events = calendarEvents(t, bobClient, f.server.URL, bobCSRF, calendarID, "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z")
	if len(events) != 1 || events[0].Summary != "Salary talk" || events[0].FreeBusyOnly {
		t.Fatalf("viewer events = %+v", events)
	}
	if status := authenticatedJSONAs(t, f, "bob", http.MethodPost, "/api/v1/workspace/calendar/events", create); status != http.StatusForbidden {
		t.Fatalf("viewer create status = %d", status)
	}
	if status := authenticatedJSONAs(t, f, "bob", http.MethodPost, "/api/v1/workspace/calendars/"+calendarID+"/sharing", `{"recipient":"bob@example.test","role":"folder.editor"}`); status != http.StatusForbidden {
		t.Fatalf("viewer resharing status = %d", status)
	}

	editor := share("folder.editor")
	decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, bobClient, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/events", bobCSRF, create), http.StatusCreated)
	if folder := bobFolder(); !folder.Capabilities.CreateItems || folder.Capabilities.Schedule || folder.Capabilities.ManageSharing {
		t.Fatalf("editor capabilities = %+v", folder.Capabilities)
	}
	decodeJSONResponse[struct{}](t, authenticatedJSON(t, client, http.MethodDelete, sharingURL+"/"+editor.ID, csrf, ""), http.StatusNoContent)
	if status := authenticatedJSONAs(t, f, "bob", http.MethodGet, "/api/v1/workspace/calendar/events?folder_id="+calendarID+"&start=2026-11-01T00:00:00Z&end=2026-12-01T00:00:00Z", ""); status != http.StatusNotFound {
		t.Fatalf("unshared calendar status = %d", status)
	}
	if bad := authenticatedJSON(t, client, http.MethodPost, sharingURL, csrf, `{"recipient":"nobody@example.test","role":"folder.viewer"}`); bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown recipient status = %d", bad.StatusCode)
	}
	// A bare account ID of another tenant reads like an unknown name and
	// discloses no address.
	f.addUser(t, "dave", "other.test")
	foreign := authenticatedJSON(t, client, http.MethodPost, sharingURL, csrf, `{"recipient":"dave","role":"calendar.freebusy"}`)
	foreignBody, _ := io.ReadAll(foreign.Body)
	_ = foreign.Body.Close()
	if foreign.StatusCode != http.StatusBadRequest || strings.Contains(string(foreignBody), "other.test") {
		t.Fatalf("foreign account ID share = %d %s", foreign.StatusCode, foreignBody)
	}
}

func partStatOf(t *testing.T, f *schedulingFixture, itemID, address string) string {
	t.Helper()
	item, err := f.handler.folderSpace.GetItem(t.Context(), service.UserAccess("alice", "test"), itemID)
	if err != nil {
		t.Fatal(err)
	}
	return partStat(t, item.Data, address)
}

func partStat(t *testing.T, data []byte, address string) string {
	t.Helper()
	event := parseWorkspaceCalendarEvent(model.Item{Data: data})
	for _, participant := range event.Participants {
		if participant.Address == address {
			return participant.PartStat
		}
	}
	t.Fatalf("%s is not an attendee:\n%s", address, data)
	return ""
}

func TestResourceBookingAutoAcceptDeclineAndDelegateApproval(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	f.addUser(t, "alice", "example.test")
	f.addUser(t, "bob", "example.test")
	calendarID := f.calendarID(t, "alice")
	resources := f.server.URL + "/api/v1/admin/resources"
	room := decodeJSONResponse[adminResource](t, authenticatedJSON(t, client, http.MethodPost, resources, csrf, `{"id":"board","display_name":"Board room","address":"board@example.test","kind":"room","capacity":12,"location":"3rd floor","policy":"auto_accept"}`), http.StatusCreated)
	if room.Resource.Capacity != 12 || room.Address != "board@example.test" || room.CalendarID == "" {
		t.Fatalf("room = %+v", room)
	}
	if status := authenticatedJSONAs(t, f, "bob", http.MethodPost, "/api/v1/admin/resources", `{"id":"x","address":"x@example.test"}`); status != http.StatusForbidden {
		t.Fatalf("non-admin resource create status = %d", status)
	}
	if status, _ := getBody(t, &http.Client{}, f.server.URL+"/app/login"); status != http.StatusOK {
		t.Fatal("login page unavailable")
	}

	book := func(summary, start, end, attendee string) workspaceCalendarEvent {
		body := `{"folder_id":"` + calendarID + `","summary":"` + summary + `","start":"` + start + `","end":"` + end + `","timezone":"UTC","attendees":[{"address":"` + attendee + `","role":"NON-PARTICIPANT"}]}`
		return decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/workspace/calendar/events", csrf, body), http.StatusCreated)
	}
	first := book("Board meeting", "2026-11-24T09:00:00Z", "2026-11-24T10:00:00Z", "board@example.test")
	if got := partStatOf(t, f, first.ID, "board@example.test"); got != "ACCEPTED" {
		t.Fatalf("free room answered %s", got)
	}
	clash := book("Clash", "2026-11-24T09:30:00Z", "2026-11-24T10:30:00Z", "board@example.test")
	if got := partStatOf(t, f, clash.ID, "board@example.test"); got != "DECLINED" {
		t.Fatalf("conflicting booking answered %s", got)
	}
	read := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, client, http.MethodGet, f.server.URL+"/api/v1/workspace/calendar/events/"+url.PathEscape(clash.ID), csrf, ""), http.StatusOK)
	if read.Scheduling == nil || read.Scheduling.Comments["board@example.test"] != imip.ConflictComment {
		t.Fatalf("decline comment = %+v", read.Scheduling)
	}

	query := url.Values{"start": {"2026-11-24T09:15:00Z"}, "end": {"2026-11-24T09:45:00Z"}}
	rooms := decodeJSONResponse[[]calendarRoom](t, authenticatedJSON(t, client, http.MethodGet, f.server.URL+"/api/v1/workspace/calendar/rooms?"+query.Encode(), csrf, ""), http.StatusOK)
	if len(rooms) != 1 || rooms[0].Status != "busy" || rooms[0].Capacity != 12 || rooms[0].Location != "3rd floor" {
		t.Fatalf("rooms during the meeting = %+v", rooms)
	}
	query.Set("uid", first.UID)
	if rooms = decodeJSONResponse[[]calendarRoom](t, authenticatedJSON(t, client, http.MethodGet, f.server.URL+"/api/v1/workspace/calendar/rooms?"+query.Encode(), csrf, ""), http.StatusOK); rooms[0].Status != "free" {
		t.Fatalf("the edited meeting makes its own room busy: %+v", rooms)
	}
	// The room finder lists only the resources of the caller's own domains.
	f.addUser(t, "dave", "other.test")
	decodeJSONResponse[adminResource](t, authenticatedJSON(t, client, http.MethodPost, resources, csrf, `{"id":"hq","address":"hq@other.test","kind":"room"}`), http.StatusCreated)
	if rooms = decodeJSONResponse[[]calendarRoom](t, authenticatedJSON(t, client, http.MethodGet, f.server.URL+"/api/v1/workspace/calendar/rooms?"+query.Encode(), csrf, ""), http.StatusOK); len(rooms) != 1 || rooms[0].ID != "board" {
		t.Fatalf("alice's rooms include another domain: %+v", rooms)
	}
	daveClient := testClient(t)
	daveCSRF := loginExistingUser(t, daveClient, f.server.URL, "dave")
	if rooms = decodeJSONResponse[[]calendarRoom](t, authenticatedJSON(t, daveClient, http.MethodGet, f.server.URL+"/api/v1/workspace/calendar/rooms?"+query.Encode(), daveCSRF, ""), http.StatusOK); len(rooms) != 1 || rooms[0].ID != "hq" {
		t.Fatalf("dave's rooms = %+v", rooms)
	}

	// A room requiring approval waits for its delegate.
	approval := decodeJSONResponse[adminResource](t, authenticatedJSON(t, client, http.MethodPost, resources, csrf, `{"id":"lab","address":"lab@example.test","kind":"equipment","policy":"approval","delegates":["bob@example.test"]}`), http.StatusCreated)
	if len(approval.Delegates) != 1 || approval.Delegates[0] != "bob" {
		t.Fatalf("approval resource = %+v", approval)
	}
	pending := book("Lab session", "2026-11-25T09:00:00Z", "2026-11-25T10:00:00Z", "lab@example.test")
	if got := partStatOf(t, f, pending.ID, "lab@example.test"); got != "NEEDS-ACTION" {
		t.Fatalf("approval booking answered %s before approval", got)
	}
	bobClient := testClient(t)
	bobCSRF := loginExistingUser(t, bobClient, f.server.URL, "bob")
	labItems, err := f.handler.folderSpace.ListItems(t.Context(), service.UserAccess("lab", "test"), approval.CalendarID, service.ItemQuery{})
	if err != nil || len(labItems) != 1 {
		t.Fatalf("lab calendar = %d items, %v", len(labItems), err)
	}
	copyURL := f.server.URL + "/api/v1/workspace/calendar/events/" + url.PathEscape(labItems[0].ID)
	view := decodeJSONResponse[workspaceCalendarEvent](t, authenticatedJSON(t, bobClient, http.MethodGet, copyURL, bobCSRF, ""), http.StatusOK)
	if view.Scheduling == nil || !view.Scheduling.CanRespond {
		t.Fatalf("delegate view = %+v", view.Scheduling)
	}
	decodeJSONResponse[imip.Invitation](t, authenticatedJSON(t, bobClient, http.MethodPost, copyURL+"/respond", bobCSRF, `{"response":"ACCEPTED"}`), http.StatusOK)
	if got := partStatOf(t, f, pending.ID, "lab@example.test"); got != "ACCEPTED" {
		t.Fatalf("approved booking answered %s", got)
	}
	// Someone who is not a delegate cannot answer for the resource.
	decodeJSONResponse[adminResource](t, authenticatedJSON(t, client, http.MethodPatch, resources+"/lab", csrf, `{"delegates":[],"capacity":2}`), http.StatusOK)
	if status := authenticatedJSONAs(t, f, "bob", http.MethodPost, "/api/v1/workspace/calendar/events/"+url.PathEscape(labItems[0].ID)+"/respond", `{"response":"DECLINED"}`); status == http.StatusOK {
		t.Fatal("a former delegate answered for the resource")
	}
	// Resource accounts are non-interactive: no reset, no session, even with
	// a password set directly in the store.
	reset := authenticatedJSON(t, client, http.MethodPost, f.server.URL+"/api/v1/admin/users/lab/credentials/reset", csrf, `{"password":"a-new-password"}`)
	if reset.StatusCode != http.StatusConflict {
		t.Fatalf("resource credential reset status = %d", reset.StatusCode)
	}
	_ = reset.Body.Close()
	hash, err := auth.HashPassword("lab-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ts.UserStore().Update(t.Context(), "lab", func(user *model.User) { user.PasswordHash = hash }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.handler.authenticateLogin(httptest.NewRequest(http.MethodPost, "/app/login", nil), "lab", "lab-password"); err == nil {
		t.Fatal("a resource account signed in")
	}
	if _, err := f.handler.sessions.Create(t.Context(), "lab", "csrf", "127.0.0.1", "test"); !errors.Is(err, model.ErrResourceAccount) {
		t.Fatalf("resource session: %v", err)
	}
	list := decodeJSONResponse[[]adminResource](t, authenticatedJSON(t, client, http.MethodGet, resources, csrf, ""), http.StatusOK)
	if len(list) != 3 || list[2].ID != "lab" || list[2].Resource.Capacity != 2 || len(list[2].Delegates) != 0 {
		t.Fatalf("resources = %+v", list)
	}
}

func TestBirthdaysCalendarFromContacts(t *testing.T) {
	f := newSchedulingFixture(t)
	client := testClient(t)
	csrf := setupAndLogin(t, f.server, client, "alice")
	contacts, err := f.ts.FolderStore().GetByPath(t.Context(), "alice", "Contacts")
	if err != nil {
		t.Fatal(err)
	}
	access := service.UserAccess("alice", "test")
	for _, card := range []string{
		"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lovelace\r\nBDAY:1815-12-10\r\nEND:VCARD\r\n",
		"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Leap Day\r\nBDAY:--0229\r\nEND:VCARD\r\n",
		"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:No Birthday\r\nEND:VCARD\r\n",
	} {
		if _, err := f.handler.folderSpace.CreateItem(t.Context(), access, contacts.ID, service.ItemInput{Data: []byte(card)}); err != nil {
			t.Fatal(err)
		}
	}
	settings := decodeJSONResponse[calendarfeed.Settings](t, authenticatedJSON(t, client, http.MethodPut, f.server.URL+"/api/v1/workspace/calendar/settings", csrf, `{"birthdays":true}`), http.StatusOK)
	if !settings.Birthdays {
		t.Fatal("birthdays setting not saved")
	}
	if read := decodeJSONResponse[calendarfeed.Settings](t, authenticatedJSON(t, client, http.MethodGet, f.server.URL+"/api/v1/workspace/calendar/settings", csrf, ""), http.StatusOK); !read.Birthdays {
		t.Fatal("birthdays setting not read back")
	}
	events := calendarEvents(t, client, f.server.URL, csrf, birthdaysCalendarID, "2026-12-01T00:00:00Z", "2027-03-31T00:00:00Z")
	var summaries []string
	for _, event := range events {
		summaries = append(summaries, event.Summary+"@"+event.DTStart)
	}
	joined := strings.Join(summaries, ",")
	if len(events) != 2 || !events[0].AllDay || !events[0].ReadOnly || !strings.Contains(joined, "Ada Lovelace’s birthday (211)@2026-12-10") || !strings.Contains(joined, "Leap Day’s birthday@2027-02-28") {
		t.Fatalf("birthdays = %s", joined)
	}
	// A new contact appears without waiting for a cache to expire.
	if _, err := f.handler.folderSpace.CreateItem(t.Context(), access, contacts.ID, service.ItemInput{Data: []byte("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:New Friend\r\nBDAY:19900105\r\nEND:VCARD\r\n")}); err != nil {
		t.Fatal(err)
	}
	if events = calendarEvents(t, client, f.server.URL, csrf, birthdaysCalendarID, "2026-12-01T00:00:00Z", "2027-03-31T00:00:00Z"); len(events) != 3 {
		t.Fatalf("birthdays after adding a contact = %d", len(events))
	}
}
