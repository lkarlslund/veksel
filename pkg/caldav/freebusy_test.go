package caldav

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ical "github.com/emersion/go-ical"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

const freeBusyMarch = `<?xml version="1.0" encoding="utf-8"?>
<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
  <C:time-range start="20250310T000000Z" end="20250317T000000Z"/>
</C:free-busy-query>`

var freeBusyEvents = map[string]string{
	// Daily x5 from Monday; Wednesday is excluded and Tuesday is moved.
	"recurring.ics": `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:recurring@example.com
DTSTART:20250310T120000Z
DTEND:20250310T130000Z
RRULE:FREQ=DAILY;COUNT=5
EXDATE:20250312T120000Z
SUMMARY:Secret standup
END:VEVENT
BEGIN:VEVENT
UID:recurring@example.com
RECURRENCE-ID:20250311T120000Z
DTSTART:20250311T150000Z
DTEND:20250311T160000Z
SUMMARY:Secret standup (moved)
END:VEVENT
END:VCALENDAR`,
	"zoned.ics": `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:zoned@example.com
DTSTART;TZID=Europe/Copenhagen:20250311T090000
DURATION:PT90M
SUMMARY:Zoned with duration
END:VEVENT
END:VCALENDAR`,
	"overlap-a.ics": timedEvent("overlap-a", "20250313T080000Z", "20250313T090000Z", ""),
	"overlap-b.ics": timedEvent("overlap-b", "20250313T083000Z", "20250313T100000Z", ""),
	"before.ics":    timedEvent("before", "20250309T220000Z", "20250310T020000Z", ""),
	"tentative.ics": timedEvent("tentative", "20250314T160000Z", "20250314T170000Z", "STATUS:TENTATIVE"),
	"free.ics":      timedEvent("free", "20250314T180000Z", "20250314T190000Z", "TRANSP:TRANSPARENT"),
	"cancelled.ics": timedEvent("cancelled", "20250314T200000Z", "20250314T210000Z", "STATUS:CANCELLED"),
	"outside.ics":   timedEvent("outside", "20250320T080000Z", "20250320T090000Z", ""),
	"allday.ics": `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:allday@example.com
DTSTART;VALUE=DATE:20250315
DTEND;VALUE=DATE:20250316
SUMMARY:Holiday
END:VEVENT
END:VCALENDAR`,
}

func timedEvent(uid, start, end, extra string) string {
	if extra != "" {
		extra += "\n"
	}
	return "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//Test//EN\nBEGIN:VEVENT\nUID:" + uid + "@example.com\nDTSTART:" + start + "\nDTEND:" + end + "\n" + extra + "SUMMARY:Private " + uid + "\nEND:VEVENT\nEND:VCALENDAR"
}

func putFreeBusyEvents(t *testing.T, h *Handler, owner string) {
	t.Helper()
	for name, data := range freeBusyEvents {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newRequest("PUT", "/dav/"+owner+"/Calendar/"+name, data))
		if w.Code != http.StatusCreated {
			t.Fatalf("PUT %s: status = %d, body = %s", name, w.Code, w.Body.String())
		}
	}
}

// freeBusyPeriods parses a free-busy-query response as an iCalendar object
// and returns its VFREEBUSY component and "FBTYPE value" period strings.
func freeBusyPeriods(t *testing.T, body []byte) (*ical.Component, []string) {
	t.Helper()
	cal, err := ical.NewDecoder(bytes.NewReader(body)).Decode()
	if err != nil {
		t.Fatalf("parse VFREEBUSY: %v\n%s", err, body)
	}
	if len(cal.Children) != 1 || cal.Children[0].Name != ical.CompFreeBusy {
		t.Fatalf("response holds %d components, want one VFREEBUSY:\n%s", len(cal.Children), body)
	}
	var periods []string
	for _, prop := range cal.Children[0].Props.Values(ical.PropFreeBusy) {
		periods = append(periods, prop.Params.Get(ical.ParamFreeBusyType)+" "+prop.Value)
	}
	return cal.Children[0], periods
}

func TestFreeBusyQueryExpandsRecurrenceAndHonoursEventSemantics(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)
	putFreeBusyEvents(t, h, "alice")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newRequest("REPORT", "/dav/alice/Calendar/", freeBusyMarch))
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/calendar") {
		t.Fatalf("free-busy-query: status = %d, type = %q, body = %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	fb, got := freeBusyPeriods(t, w.Body.Bytes())
	if fb.Props.Get(ical.PropDateTimeStart).Value != "20250310T000000Z" || fb.Props.Get(ical.PropDateTimeEnd).Value != "20250317T000000Z" {
		t.Fatalf("VFREEBUSY range = %v/%v", fb.Props.Get(ical.PropDateTimeStart), fb.Props.Get(ical.PropDateTimeEnd))
	}
	if fb.Props.Get(ical.PropUID) == nil || fb.Props.Get(ical.PropDateTimeStamp) == nil {
		t.Fatalf("VFREEBUSY lacks UID or DTSTAMP:\n%s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "Secret") || strings.Contains(w.Body.String(), "Private") {
		t.Fatalf("free/busy leaked event details:\n%s", w.Body.String())
	}

	// All-day dates are floating: they occupy the server's local day,
	// reported as UTC date-times.
	const layout = "20060102T150405Z"
	holidayStart := time.Date(2025, 3, 15, 0, 0, 0, 0, time.Local).UTC()
	holidayEnd := time.Date(2025, 3, 16, 0, 0, 0, 0, time.Local).UTC()
	want := []string{
		"BUSY 20250310T000000Z/20250310T020000Z", // clipped to the range
		"BUSY 20250310T120000Z/20250310T130000Z", // recurrence Monday
		"BUSY 20250311T080000Z/20250311T093000Z", // TZID + DURATION
		"BUSY 20250311T150000Z/20250311T160000Z", // moved Tuesday
		"BUSY 20250313T080000Z/20250313T100000Z", // overlaps merged
		"BUSY 20250313T120000Z/20250313T130000Z", // Thursday; Wednesday excluded
		"BUSY 20250314T120000Z/20250314T130000Z",
		"BUSY-TENTATIVE 20250314T160000Z/20250314T170000Z",
		"BUSY " + holidayStart.Format(layout) + "/" + holidayEnd.Format(layout),
	}
	byStart := func(a, b string) int {
		return strings.Compare(a[strings.Index(a, " ")+1:], b[strings.Index(b, " ")+1:])
	}
	slices.SortFunc(want, byStart)
	if !slices.IsSortedFunc(got, byStart) {
		t.Errorf("FREEBUSY periods are not sorted: %q", got)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FREEBUSY =\n%q\nwant\n%q", got, want)
	}
}

func TestFreeBusyQueryRejectsMissingOrUnboundedRange(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)
	for name, body := range map[string]string{
		"missing":  `<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav"/>`,
		"inverted": `<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:time-range start="20250317T000000Z" end="20250310T000000Z"/></C:free-busy-query>`,
		"too long": `<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:time-range start="20250101T000000Z" end="20350101T000000Z"/></C:free-busy-query>`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newRequest("REPORT", "/dav/alice/Calendar/", body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s range: status = %d, want 400", name, w.Code)
		}
	}
}

func TestFreeBusyQueryOnSharedCalendarNeedsFreeBusyPrivilege(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	for _, namespace := range []string{model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatalf("ensure namespace %q: %v", namespace, err)
		}
	}
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")
	testUser(t, ts, "carol", "pass123")
	h := New(ts, &Config{Authorizer: authz.New(ts)})
	putFreeBusyEvents(t, h, "bob")
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: model.FolderKey("bob", "Calendar")},
		Effect:    model.EffectAllow, RoleID: authz.RoleCalendarFreeBusy,
		Inheritance: model.InheritanceSelf, GrantedBy: "bob",
	}); err != nil {
		t.Fatalf("grant free/busy: %v", err)
	}
	as := func(actor, method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, WithAuthenticatedUser(newRequest(method, path, body), actor))
		return w
	}

	// A free/busy sharee sees busy time and nothing else.
	w := as("alice", "REPORT", "/dav/bob/Calendar/", freeBusyMarch)
	if w.Code != http.StatusOK {
		t.Fatalf("free/busy sharee: status = %d, body = %s", w.Code, w.Body.String())
	}
	if _, periods := freeBusyPeriods(t, w.Body.Bytes()); len(periods) != 9 {
		t.Fatalf("free/busy sharee saw %d periods, want 9: %q", len(periods), periods)
	}
	if strings.Contains(w.Body.String(), "Secret") || strings.Contains(w.Body.String(), "Private") {
		t.Fatalf("free/busy leaked event details:\n%s", w.Body.String())
	}

	// The free/busy role does not reach event data through other REPORTs,
	// calendar-multitarget, or GET.
	query := `<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><C:calendar-data/></D:prop><C:filter><C:comp-filter name="VCALENDAR"/></C:filter></C:calendar-query>`
	if w := as("alice", "REPORT", "/dav/bob/Calendar/", query); w.Code != http.StatusForbidden {
		t.Fatalf("free/busy sharee calendar-query: status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
	multitarget := WithAuthenticatedUser(newRequest("REPORT", "/dav/bob/Calendar/", freeBusyEvents["free.ics"]), "alice")
	multitarget.Header.Set("Content-Type", "text/calendar")
	if w := httptest.NewRecorder(); func() int { h.ServeHTTP(w, multitarget); return w.Code }() != http.StatusForbidden {
		t.Fatalf("free/busy sharee multitarget REPORT was not forbidden")
	}
	if w := as("alice", "GET", "/dav/bob/Calendar/recurring.ics", ""); w.Code != http.StatusForbidden {
		t.Fatalf("free/busy sharee GET: status = %d, want 403", w.Code)
	}

	// Without read or read-free-busy the REPORT is forbidden.
	if w := as("carol", "REPORT", "/dav/bob/Calendar/", freeBusyMarch); w.Code != http.StatusForbidden {
		t.Fatalf("ungranted free-busy-query: status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
}
