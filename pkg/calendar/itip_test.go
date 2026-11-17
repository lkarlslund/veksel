package calendar

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	ical "github.com/emersion/go-ical"
)

// sampleiTIPFolded exercises RFC 5545 folding, quoted parameters, escaped
// text, a recurrence instance and a TZID-bound DTSTART with its VTIMEZONE.
var sampleiTIPFolded = strings.Join([]string{
	"BEGIN:VCALENDAR",
	"VERSION:2.0",
	"METHOD:request",
	"PRODID:-//Test//Test//EN",
	"BEGIN:VTIMEZONE",
	"TZID:Europe/Copenhagen",
	"BEGIN:STANDARD",
	"DTSTART:19701025T030000",
	"TZOFFSETFROM:+0200",
	"TZOFFSETTO:+0100",
	"END:STANDARD",
	"END:VTIMEZONE",
	"BEGIN:VEVENT",
	"UID:meeting-003@example.com",
	"SEQUENCE:4",
	"DTSTAMP:20250601T120000Z",
	"RECURRENCE-ID;TZID=Europe/Copenhagen:20250616T100000",
	"DTSTART;TZID=Europe/Copenhagen:20250616T100000",
	"DTEND;TZID=Europe/Copenhagen:20250616T110000",
	`SUMMARY:Budget\, Q3\; review \\ planning`,
	`DESCRIPTION:Line one\nLine two`,
	`LOCATION:Room 1\, floor 2`,
	`ORGANIZER;CN="Bob, the Boss; CEO":mailto:bob@exa`,
	" mple.com",
	`ATTENDEE;CN="Smith, Alice; PhD";ROLE=req-participant;PARTSTAT=NEEDS-ACT`,
	"\tION;RSVP=TRUE;DELEGATED-FROM=\"mailto:dave@example.com\":mailto:alice@exam",
	" ple.com",
	"ATTENDEE;PARTSTAT=ACCEPTED;CN=Carol:mailto:carol@example.com",
	"END:VEVENT",
	"END:VCALENDAR",
	"",
}, "\r\n")

func decodeiTIP(t *testing.T, data []byte) (*ical.Calendar, ical.Event) {
	t.Helper()
	if !bytes.HasSuffix(data, []byte("\r\n")) || bytes.Contains(bytes.ReplaceAll(data, []byte("\r\n"), nil), []byte("\n")) {
		t.Fatalf("iTIP output must use CRLF line endings:\n%s", data)
	}
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		t.Fatalf("decode iTIP output: %v\n%s", err, data)
	}
	events := cal.Events()
	if len(events) != 1 {
		t.Fatalf("iTIP output has %d events, want 1", len(events))
	}
	return cal, events[0]
}

func propValue(t *testing.T, props ical.Props, name string) string {
	t.Helper()
	prop := props.Get(name)
	if prop == nil {
		t.Fatalf("missing %s", name)
	}
	return prop.Value
}

func attendeesByAddress(event ical.Event) map[string]ical.Prop {
	attendees := make(map[string]ical.Prop)
	for _, attendee := range event.Props.Values(ical.PropAttendee) {
		attendees[attendee.Value] = attendee
	}
	return attendees
}

func TestParseITIPFoldedAndQuoted(t *testing.T) {
	t.Parallel()
	msg, err := ParseITIP([]byte(sampleiTIPFolded))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.Method != MethodRequest || msg.UID != "meeting-003@example.com" || msg.Seq != 4 {
		t.Fatalf("method/uid/seq = %q/%q/%d", msg.Method, msg.UID, msg.Seq)
	}
	if msg.Organizer != "mailto:bob@example.com" {
		t.Errorf("organizer = %q, want unfolded address", msg.Organizer)
	}
	if want := `Budget, Q3; review \ planning`; msg.Summary != want {
		t.Errorf("summary = %q, want %q", msg.Summary, want)
	}
	if want := "Line one\nLine two"; msg.Description != want {
		t.Errorf("description = %q, want %q", msg.Description, want)
	}
	if want := "Room 1, floor 2"; msg.Location != want {
		t.Errorf("location = %q, want %q", msg.Location, want)
	}
	if want := time.Date(2025, 6, 16, 8, 0, 0, 0, time.UTC); !msg.DTStart.Equal(want) {
		t.Errorf("dtstart = %v, want %v", msg.DTStart, want)
	}
	if len(msg.Attendees) != 2 {
		t.Fatalf("attendees = %+v, want 2", msg.Attendees)
	}
	alice := msg.Attendees[0]
	if alice.CalendarAddress != "mailto:alice@example.com" || alice.CommonName != "Smith, Alice; PhD" ||
		alice.PartStat != "NEEDS-ACTION" || alice.Role != "REQ-PARTICIPANT" || !alice.Rsvp ||
		!slices.Equal(alice.DelegatedFrom, []string{"mailto:dave@example.com"}) {
		t.Errorf("folded attendee parsed as %+v", alice)
	}
	if carol := msg.Attendees[1]; carol.CalendarAddress != "mailto:carol@example.com" || carol.PartStat != PartStatAccepted || carol.Rsvp {
		t.Errorf("second attendee parsed as %+v", carol)
	}
}

func TestParseITIPRejectsMissingUID(t *testing.T) {
	t.Parallel()
	data := strings.Replace(sampleiTIPRequest, "UID:meeting-001@example.com\n", "", 1)
	if _, err := ParseITIP([]byte(data)); err == nil {
		t.Fatal("expected error for VEVENT without UID")
	}
}

func TestBuildReply(t *testing.T) {
	t.Parallel()
	msg, err := ParseITIP([]byte(sampleiTIPFolded))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	reply, err := BuildReply(msg, "MAILTO:Alice@Example.com", PartStatAccepted)
	if err != nil {
		t.Fatalf("build reply: %v", err)
	}
	cal, event := decodeiTIP(t, reply)
	if got := propValue(t, cal.Props, ical.PropMethod); got != MethodReply {
		t.Errorf("METHOD = %q", got)
	}
	if cal.Props.Get(ical.PropUID) != nil || cal.Props.Get(ical.PropOrganizer) != nil {
		t.Error("event properties must not leak to the VCALENDAR level")
	}
	if len(cal.Children) != 2 || cal.Children[0].Name != ical.CompTimezone {
		t.Error("reply should carry the VTIMEZONE referenced by copied TZIDs")
	}
	for name, want := range map[string]string{
		ical.PropUID:          "meeting-003@example.com",
		ical.PropSequence:     "4",
		ical.PropRecurrenceID: "20250616T100000",
		ical.PropOrganizer:    "mailto:bob@example.com",
	} {
		if got := propValue(t, event.Props, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if tzid := event.Props.Get(ical.PropRecurrenceID).Params.Get(ical.ParamTimezoneID); tzid != "Europe/Copenhagen" {
		t.Errorf("RECURRENCE-ID TZID = %q", tzid)
	}
	if cn := event.Props.Get(ical.PropOrganizer).Params.Get(ical.ParamCommonName); cn != "Bob, the Boss; CEO" {
		t.Errorf("ORGANIZER CN = %q", cn)
	}
	if summary, _ := event.Props.Text(ical.PropSummary); summary != `Budget, Q3; review \ planning` {
		t.Errorf("SUMMARY = %q", summary)
	}
	if event.Props.Get(ical.PropDateTimeStamp) == nil {
		t.Error("reply must carry DTSTAMP")
	}
	attendees := event.Props.Values(ical.PropAttendee)
	if len(attendees) != 1 {
		t.Fatalf("reply attendees = %d, want only the responder", len(attendees))
	}
	responder := attendees[0]
	if responder.Value != "mailto:alice@example.com" ||
		responder.Params.Get(ical.ParamParticipationStatus) != PartStatAccepted ||
		responder.Params.Get(ical.ParamCommonName) != "Smith, Alice; PhD" ||
		responder.Params.Get(ical.ParamRSVP) != "" {
		t.Errorf("responder attendee = %+v", responder)
	}
	// The source message must not be mutated by building a response.
	if msg.event.Props.Values(ical.PropAttendee)[0].Params.Get(ical.ParamParticipationStatus) != "NEEDS-ACTION" {
		t.Error("BuildReply mutated the request")
	}
}

func TestBuildReplyUninvitedResponder(t *testing.T) {
	t.Parallel()
	msg, err := ParseITIP([]byte(sampleiTIPRequest))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	reply, err := BuildReply(msg, "mailto:eve@example.com", PartStatDeclined)
	if err != nil {
		t.Fatalf("build reply: %v", err)
	}
	_, event := decodeiTIP(t, reply)
	attendees := event.Props.Values(ical.PropAttendee)
	if len(attendees) != 1 || attendees[0].Value != "mailto:eve@example.com" ||
		attendees[0].Params.Get(ical.ParamParticipationStatus) != PartStatDeclined {
		t.Errorf("reply attendees = %+v", attendees)
	}
}

func TestBuildCancel(t *testing.T) {
	t.Parallel()
	msg, err := ParseITIP([]byte(sampleiTIPFolded))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	cancel, err := BuildCancel(msg)
	if err != nil {
		t.Fatalf("build cancel: %v", err)
	}
	cal, event := decodeiTIP(t, cancel)
	if got := propValue(t, cal.Props, ical.PropMethod); got != MethodCancel {
		t.Errorf("METHOD = %q", got)
	}
	if got := propValue(t, event.Props, ical.PropSequence); got != "5" {
		t.Errorf("SEQUENCE = %q, want incremented 5", got)
	}
	if got := propValue(t, event.Props, ical.PropStatus); got != string(ical.EventCancelled) {
		t.Errorf("STATUS = %q", got)
	}
	if got := propValue(t, event.Props, ical.PropUID); got != "meeting-003@example.com" {
		t.Errorf("UID = %q", got)
	}
	attendees := attendeesByAddress(event)
	if len(attendees) != 2 {
		t.Errorf("cancel should list every removed attendee, got %d", len(attendees))
	}
}

func TestBuildCounter(t *testing.T) {
	t.Parallel()
	msg, err := ParseITIP([]byte(sampleiTIPFolded))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	newStart := time.Date(2025, 6, 16, 14, 0, 0, 0, time.UTC)
	counter, err := BuildCounter(msg, "mailto:alice@example.com", newStart, newStart.Add(time.Hour))
	if err != nil {
		t.Fatalf("build counter: %v", err)
	}
	cal, event := decodeiTIP(t, counter)
	if got := propValue(t, cal.Props, ical.PropMethod); got != MethodCounter {
		t.Errorf("METHOD = %q", got)
	}
	for name, want := range map[string]string{
		ical.PropSequence:      "4",
		ical.PropOrganizer:     "mailto:bob@example.com",
		ical.PropDateTimeStart: "20250616T140000Z",
		ical.PropDateTimeEnd:   "20250616T150000Z",
	} {
		if got := propValue(t, event.Props, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	attendees := attendeesByAddress(event)
	if got := attendees["mailto:alice@example.com"].Params.Get(ical.ParamParticipationStatus); got != PartStatTentative {
		t.Errorf("responder PARTSTAT = %q", got)
	}
	if got := attendees["mailto:carol@example.com"].Params.Get(ical.ParamParticipationStatus); got != PartStatAccepted {
		t.Errorf("other attendee PARTSTAT = %q, want unchanged", got)
	}
	if _, ok := attendees["mailto:bob@example.com"]; ok || len(attendees) != 2 {
		t.Errorf("counter attendees = %v", attendees)
	}
}

func TestBuildDeclineCounter(t *testing.T) {
	t.Parallel()
	counterMsg, err := ParseITIP([]byte(sampleiTIPCounter))
	if err != nil {
		t.Fatalf("parse counter: %v", err)
	}
	declineCounter, err := BuildDeclineCounter(counterMsg, "mailto:bob@example.com")
	if err != nil {
		t.Fatalf("build decline counter: %v", err)
	}
	cal, event := decodeiTIP(t, declineCounter)
	if got := propValue(t, cal.Props, ical.PropMethod); got != MethodDeclineCounter {
		t.Errorf("METHOD = %q", got)
	}
	if got := propValue(t, event.Props, ical.PropOrganizer); got != "mailto:bob@example.com" {
		t.Errorf("ORGANIZER = %q", got)
	}
	if got := propValue(t, event.Props, ical.PropUID); got != "meeting-002@example.com" {
		t.Errorf("UID = %q", got)
	}
	attendees := attendeesByAddress(event)
	if _, ok := attendees["mailto:alice@example.com"]; !ok || len(attendees) != 1 {
		t.Errorf("decline counter must address the countering attendee, got %v", attendees)
	}
}

var sampleiTIPRequest = `BEGIN:VCALENDAR
VERSION:2.0
METHOD:REQUEST
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:meeting-001@example.com
DTSTART:20250615T140000Z
DTEND:20250615T150000Z
SUMMARY:Team Meeting
ORGANIZER:mailto:bob@example.com
ATTENDEE:mailto:alice@example.com
END:VEVENT
END:VCALENDAR`

var sampleiTIPCounter = `BEGIN:VCALENDAR
VERSION:2.0
METHOD:COUNTER
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:meeting-002@example.com
DTSTART:20250615T160000Z
DTEND:20250615T170000Z
SUMMARY:Team Meeting Counter
ORGANIZER:mailto:alice@example.com
ATTENDEE;PARTSTAT=TENTATIVE:mailto:alice@example.com
END:VEVENT
END:VCALENDAR`
