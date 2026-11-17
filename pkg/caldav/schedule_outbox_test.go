package caldav

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ical "github.com/emersion/go-ical"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

// outboxFixture is a server with accounts in two hosted domains: alice,
// bob and the room in example.com, dave in partner.test.
type outboxFixture struct {
	t  *testing.T
	ts *model.TypedStore
	h  *Handler
}

func newOutboxFixture(t *testing.T) *outboxFixture {
	t.Helper()
	ts := testStoreSetup(t)
	ctx := t.Context()
	for _, namespace := range []string{model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes, model.NSRecipientAliases, model.NSUserAliases} {
		if err := ts.EnsureNamespace(ctx, namespace); err != nil {
			t.Fatalf("ensure namespace %q: %v", namespace, err)
		}
	}
	for _, domain := range []string{"example.com", "partner.test"} {
		if err := ts.DomainStore().Create(ctx, domain); err != nil {
			t.Fatalf("create domain %s: %v", domain, err)
		}
	}
	for user, address := range map[string]string{"alice": "alice@example.com", "bob": "bob@example.com", "room": "room@example.com", "dave": "dave@partner.test"} {
		testUser(t, ts, user, "pass123")
		if err := ts.UserStore().AddEmailAddress(ctx, address, user, address[strings.Index(address, "@")+1:], true); err != nil {
			t.Fatalf("add %s: %v", address, err)
		}
	}
	if err := ts.UserStore().AddEmailAddress(ctx, "a.smith@example.com", "alice", "example.com", false); err != nil {
		t.Fatalf("add alias identity: %v", err)
	}
	if err := ts.UserStore().Update(ctx, "room", func(user *model.User) { user.Resource = &model.ResourceProfile{Kind: model.BookableRoom} }); err != nil {
		t.Fatalf("make room: %v", err)
	}
	f := &outboxFixture{t: t, ts: ts, h: New(ts, &Config{Authorizer: authz.New(ts)})}
	f.put("bob", "busy.ics", timedEvent("bob-busy", "20250311T100000Z", "20250311T110000Z", ""))
	f.put("bob", "free.ics", timedEvent("bob-free", "20250311T140000Z", "20250311T150000Z", "TRANSP:TRANSPARENT"))
	f.put("room", "booked.ics", timedEvent("room-booked", "20250312T090000Z", "20250312T100000Z", ""))
	f.put("dave", "busy.ics", timedEvent("dave-busy", "20250313T090000Z", "20250313T100000Z", ""))
	return f
}

func (f *outboxFixture) do(actor, method, path, body, contentType string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := WithAuthenticatedUser(newRequest(method, path, body), actor)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *outboxFixture) put(owner, name, data string) {
	f.t.Helper()
	if w := f.do(owner, "PUT", "/dav/"+owner+"/Calendar/"+name, data, "text/calendar"); w.Code != http.StatusCreated {
		f.t.Fatalf("PUT %s/%s: status = %d, body = %s", owner, name, w.Code, w.Body.String())
	}
}

func (f *outboxFixture) post(actor, owner, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(actor, "POST", "/dav/"+owner+"/schedule-outbox/", body, "text/calendar; charset=utf-8")
}

func freeBusyRequestBody(organizer string, attendees ...string) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//Test//EN\r\nMETHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\n")
	b.WriteString("UID:fb-lookup-1@client.test\r\nDTSTAMP:20250301T120000Z\r\nDTSTART:20250310T000000Z\r\nDTEND:20250317T000000Z\r\n")
	b.WriteString("ORGANIZER:" + organizer + "\r\n")
	for _, attendee := range attendees {
		b.WriteString("ATTENDEE:" + attendee + "\r\n")
	}
	b.WriteString("END:VFREEBUSY\r\nEND:VCALENDAR\r\n")
	return b.String()
}

type parsedScheduleResponse struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:caldav schedule-response"`
	Responses []struct {
		Recipient struct {
			Href string `xml:"DAV: href"`
		} `xml:"urn:ietf:params:xml:ns:caldav recipient"`
		RequestStatus string `xml:"urn:ietf:params:xml:ns:caldav request-status"`
		CalendarData  string `xml:"urn:ietf:params:xml:ns:caldav calendar-data"`
	} `xml:"urn:ietf:params:xml:ns:caldav response"`
}

// scheduleResults maps each recipient to its request-status and parsed
// reply VFREEBUSY (nil without calendar-data).
func scheduleResults(t *testing.T, w *httptest.ResponseRecorder) (map[string]string, map[string]*ical.Calendar) {
	t.Helper()
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/xml") {
		t.Fatalf("outbox POST: status = %d, type = %q, body = %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	var parsed parsedScheduleResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("parse schedule-response: %v\n%s", err, w.Body.String())
	}
	statuses, replies := map[string]string{}, map[string]*ical.Calendar{}
	for _, response := range parsed.Responses {
		statuses[response.Recipient.Href] = response.RequestStatus
		if response.CalendarData == "" {
			continue
		}
		cal, err := ical.NewDecoder(strings.NewReader(response.CalendarData)).Decode()
		if err != nil {
			t.Fatalf("parse reply for %s: %v\n%s", response.Recipient.Href, err, response.CalendarData)
		}
		replies[response.Recipient.Href] = cal
	}
	return statuses, replies
}

func replyPeriods(t *testing.T, cal *ical.Calendar) []string {
	t.Helper()
	if len(cal.Children) != 1 || cal.Children[0].Name != ical.CompFreeBusy {
		t.Fatalf("reply holds %d components, want one VFREEBUSY", len(cal.Children))
	}
	var periods []string
	for _, prop := range cal.Children[0].Props.Values(ical.PropFreeBusy) {
		periods = append(periods, prop.Params.Get(ical.ParamFreeBusyType)+" "+prop.Value)
	}
	return periods
}

func TestScheduleOutboxFreeBusyRequestAnswersEachRecipient(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	w := f.post("alice", "alice", freeBusyRequestBody("mailto:a.smith@example.com",
		"mailto:bob@example.com", "MAILTO:Room@Example.com", "mailto:carol@elsewhere.test",
		"mailto:nobody@example.com", "mailto:dave@partner.test", "urn:uuid:4b1c1f2e", "mailto:bob@example.com"))
	if strings.Contains(w.Body.String(), "Private") {
		t.Fatalf("free/busy reply leaked event details:\n%s", w.Body.String())
	}
	statuses, replies := scheduleResults(t, w)
	want := map[string]string{
		"mailto:bob@example.com":      statusSuccess,
		"MAILTO:Room@Example.com":     statusSuccess,
		"mailto:carol@elsewhere.test": statusNoSchedulingFor, // external: no remote lookup
		"mailto:nobody@example.com":   statusInvalidUser,     // hosted domain, no such user
		"mailto:dave@partner.test":    statusNoAuthority,     // other domain, nothing shared
		"urn:uuid:4b1c1f2e":           statusInvalidUser,
	}
	if len(statuses) != len(want) {
		t.Fatalf("statuses = %v, want one per distinct recipient %v", statuses, want)
	}
	for recipient, status := range want {
		if statuses[recipient] != status {
			t.Errorf("%s: request-status = %q, want %q", recipient, statuses[recipient], status)
		}
	}
	if len(replies) != 2 {
		t.Fatalf("calendar-data for %d recipients, want bob and the room only", len(replies))
	}

	bob := replies["mailto:bob@example.com"]
	if method, _ := bob.Props.Text(ical.PropMethod); method != "REPLY" {
		t.Fatalf("reply METHOD = %q, want REPLY", method)
	}
	fb := bob.Children[0]
	for name, value := range map[string]string{
		ical.PropUID: "fb-lookup-1@client.test", ical.PropOrganizer: "mailto:a.smith@example.com", ical.PropAttendee: "mailto:bob@example.com",
		ical.PropDateTimeStart: "20250310T000000Z", ical.PropDateTimeEnd: "20250317T000000Z",
	} {
		if prop := fb.Props.Get(name); prop == nil || prop.Value != value {
			t.Errorf("reply %s = %+v, want %s", name, prop, value)
		}
	}
	if got := replyPeriods(t, bob); len(got) != 1 || got[0] != "BUSY 20250311T100000Z/20250311T110000Z" {
		t.Errorf("bob's busy time = %q, want only the opaque meeting", got)
	}
	if got := replyPeriods(t, replies["MAILTO:Room@Example.com"]); len(got) != 1 || got[0] != "BUSY 20250312T090000Z/20250312T100000Z" {
		t.Errorf("room's busy time = %q", got)
	}
}

func TestScheduleOutboxFreeBusyFollowsCalendarSharing(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	body := freeBusyRequestBody("mailto:alice@example.com", "mailto:dave@partner.test")
	if statuses, _ := scheduleResults(t, f.post("alice", "alice", body)); statuses["mailto:dave@partner.test"] != statusNoAuthority {
		t.Fatalf("unshared colleague in another domain: %v", statuses)
	}
	// Dave sharing his calendar's free/busy time with alice makes all of
	// his busy time visible to her, as in the web scheduling assistant.
	if _, err := model.NewPolicyStore(f.ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: model.FolderKey("dave", "Calendar")},
		Effect:    model.EffectAllow, RoleID: authz.RoleCalendarFreeBusy,
		Inheritance: model.InheritanceSelf, GrantedBy: "dave",
	}); err != nil {
		t.Fatalf("grant free/busy: %v", err)
	}
	statuses, replies := scheduleResults(t, f.post("alice", "alice", body))
	if statuses["mailto:dave@partner.test"] != statusSuccess {
		t.Fatalf("shared colleague: %v", statuses)
	}
	if got := replyPeriods(t, replies["mailto:dave@partner.test"]); len(got) != 1 || got[0] != "BUSY 20250313T090000Z/20250313T100000Z" {
		t.Fatalf("dave's busy time = %q", got)
	}
}

func TestScheduleOutboxRejectsForeignOrganizerAndOutbox(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	w := f.post("alice", "alice", freeBusyRequestBody("mailto:bob@example.com", "mailto:room@example.com"))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "organizer-allowed") {
		t.Fatalf("foreign ORGANIZER: status = %d, body = %s", w.Code, w.Body.String())
	}
	if w := f.post("alice", "alice", freeBusyRequestBody("mailto:alice@elsewhere.test", "mailto:bob@example.com")); w.Code != http.StatusForbidden {
		t.Fatalf("unowned ORGANIZER: status = %d, want 403", w.Code)
	}
	// Only the owner may send from an outbox.
	if w := f.post("alice", "bob", freeBusyRequestBody("mailto:bob@example.com", "mailto:room@example.com")); w.Code != http.StatusForbidden {
		t.Fatalf("POST to another account's outbox: status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
}

func TestScheduleOutboxRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	valid := freeBusyRequestBody("mailto:alice@example.com", "mailto:bob@example.com")
	invitation := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//Test//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:invite@client.test\r\nDTSTAMP:20250301T120000Z\r\n" +
		"DTSTART:20250311T100000Z\r\nDTEND:20250311T110000Z\r\nORGANIZER:mailto:alice@example.com\r\nATTENDEE:mailto:bob@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	tooMany := []string{}
	for range maxFreeBusyRecipients + 1 {
		tooMany = append(tooMany, "mailto:u"+strings.Repeat("x", len(tooMany))+"@example.com")
	}
	for name, test := range map[string]struct {
		body      string
		status    int
		condition string
	}{
		"not iCalendar":    {"this is not a calendar", http.StatusBadRequest, "valid-calendar-data"},
		"no method":        {strings.Replace(valid, "METHOD:REQUEST\r\n", "", 1), http.StatusBadRequest, "valid-scheduling-message"},
		"reply method":     {strings.Replace(valid, "METHOD:REQUEST", "METHOD:REPLY", 1), http.StatusBadRequest, "valid-scheduling-message"},
		"no attendee":      {freeBusyRequestBody("mailto:alice@example.com"), http.StatusBadRequest, "valid-scheduling-message"},
		"no organizer":     {strings.Replace(valid, "ORGANIZER:mailto:alice@example.com\r\n", "", 1), http.StatusBadRequest, "valid-scheduling-message"},
		"no dtend":         {strings.Replace(valid, "DTEND:20250317T000000Z\r\n", "", 1), http.StatusBadRequest, "valid-scheduling-message"},
		"inverted range":   {strings.Replace(valid, "DTEND:20250317T000000Z", "DTEND:20250301T000000Z", 1), http.StatusBadRequest, "valid-scheduling-message"},
		"too many":         {freeBusyRequestBody("mailto:alice@example.com", tooMany...), http.StatusForbidden, "max-recipients"},
		"event invitation": {invitation, http.StatusForbidden, "valid-scheduling-message"},
	} {
		w := f.post("alice", "alice", test.body)
		if w.Code != test.status || !strings.Contains(w.Body.String(), "<C:"+test.condition+"/>") {
			t.Errorf("%s: status = %d, body = %s; want %d %s", name, w.Code, w.Body.String(), test.status, test.condition)
		}
	}
	if w := f.do("alice", "POST", "/dav/alice/Calendar/", valid, "text/calendar"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST to a calendar: status = %d, want 405", w.Code)
	}
}

func TestSchedulingDiscoveryAdvertisesOutbox(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	if w := f.do("alice", "OPTIONS", "/dav/alice/", "", ""); w.Code != http.StatusOK || !strings.Contains(w.Header().Get("DAV"), "calendar-auto-schedule") {
		t.Fatalf("OPTIONS: status = %d, DAV = %q", w.Code, w.Header().Get("DAV"))
	}
	principal := f.do("alice", "PROPFIND", "/dav/alice/", `<propfind xmlns="DAV:"><allprop/></propfind>`, "")
	for _, want := range []string{
		"<C:schedule-outbox-URL><d:href>/dav/alice/schedule-outbox/</d:href>",
		"<C:schedule-inbox-URL><d:href>/dav/alice/schedule-inbox/</d:href>",
		"<C:calendar-user-address-set><d:href>mailto:alice@example.com</d:href><d:href>mailto:a.smith@example.com</d:href><d:href>/dav/alice/</d:href>",
		"<C:calendar-user-type>INDIVIDUAL</C:calendar-user-type>",
	} {
		if !strings.Contains(principal.Body.String(), want) {
			t.Errorf("principal PROPFIND lacks %s:\n%s", want, principal.Body.String())
		}
	}
	if room := f.do("room", "PROPFIND", "/dav/room/", `<propfind xmlns="DAV:"><allprop/></propfind>`, ""); !strings.Contains(room.Body.String(), "<C:calendar-user-type>ROOM</C:calendar-user-type>") {
		t.Errorf("room principal is not a ROOM:\n%s", room.Body.String())
	}

	// The outbox exists from its first lookup and grants its owner
	// schedule-send-freebusy.
	outbox := f.do("alice", "PROPFIND", "/dav/alice/schedule-outbox/", `<propfind xmlns="DAV:"><allprop/></propfind>`, "")
	if outbox.Code != http.StatusMultiStatus {
		t.Fatalf("outbox PROPFIND: status = %d, body = %s", outbox.Code, outbox.Body.String())
	}
	var parsed struct {
		Responses []struct {
			Prop struct {
				ResourceType struct {
					Outbox *struct{} `xml:"urn:ietf:params:xml:ns:caldav schedule-outbox"`
				} `xml:"DAV: resourcetype"`
				Supported []byte `xml:"DAV: supported-privilege-set"`
				Current   struct {
					Privileges []struct {
						Inner []byte `xml:",innerxml"`
					} `xml:"DAV: privilege"`
				} `xml:"DAV: current-user-privilege-set"`
			} `xml:"DAV: propstat>prop"`
		} `xml:"DAV: response"`
	}
	if err := xml.Unmarshal(outbox.Body.Bytes(), &parsed); err != nil || len(parsed.Responses) == 0 {
		t.Fatalf("parse outbox PROPFIND: %v\n%s", err, outbox.Body.String())
	}
	prop := parsed.Responses[0].Prop
	if prop.ResourceType.Outbox == nil {
		t.Errorf("outbox resourcetype lacks schedule-outbox:\n%s", outbox.Body.String())
	}
	if !bytes.Contains(outbox.Body.Bytes(), []byte("<d:supported-privilege-set>")) || !bytes.Contains(outbox.Body.Bytes(), []byte("<C:schedule-send-freebusy></C:schedule-send-freebusy>")) {
		t.Errorf("outbox does not advertise schedule-send-freebusy:\n%s", outbox.Body.String())
	}
	held := false
	for _, privilege := range prop.Current.Privileges {
		held = held || bytes.Contains(privilege.Inner, []byte("schedule-send-freebusy"))
	}
	if !held {
		t.Errorf("owner does not hold schedule-send-freebusy:\n%s", outbox.Body.String())
	}
}
