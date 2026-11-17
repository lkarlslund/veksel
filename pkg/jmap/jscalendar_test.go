package jmap

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
)

const meetingICS = "BEGIN:VCALENDAR\r\n" +
	"VERSION:2.0\r\n" +
	"PRODID:-//Example//Client//EN\r\n" +
	"X-WR-CALNAME:Work\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:meeting-1\r\n" +
	"DTSTAMP:20261001T080000Z\r\n" +
	"CREATED:20261001T080000Z\r\n" +
	"DTSTART;TZID=Europe/Copenhagen:20261005T100000\r\n" +
	"DTEND;TZID=Europe/Copenhagen:20261005T113000\r\n" +
	"SUMMARY:Weekly sync\r\n" +
	"DESCRIPTION:Agenda\\nItems\r\n" +
	"LOCATION:Room 1\r\n" +
	"STATUS:CONFIRMED\r\n" +
	"CLASS:PRIVATE\r\n" +
	"TRANSP:TRANSPARENT\r\n" +
	"CATEGORIES:Work,Planning\r\n" +
	"SEQUENCE:2\r\n" +
	"RRULE:FREQ=WEEKLY;INTERVAL=1;BYDAY=MO;UNTIL=20261130T090000Z\r\n" +
	"EXDATE;TZID=Europe/Copenhagen:20261012T100000\r\n" +
	"ORGANIZER;CN=Alice:mailto:alice@example.test\r\n" +
	"ATTENDEE;CN=Alice;ROLE=CHAIR;PARTSTAT=ACCEPTED:mailto:alice@example.test\r\n" +
	"ATTENDEE;CN=Bob;ROLE=OPT-PARTICIPANT;PARTSTAT=TENTATIVE;RSVP=TRUE;X-NUM-GUESTS=1:mailto:bob@example.test\r\n" +
	"X-MICROSOFT-CDO-BUSYSTATUS:FREE\r\n" +
	"BEGIN:VALARM\r\n" +
	"ACTION:DISPLAY\r\n" +
	"TRIGGER:-PT15M\r\n" +
	"DESCRIPTION:Soon\r\n" +
	"X-APPLE-DEFAULT-ALARM:TRUE\r\n" +
	"END:VALARM\r\n" +
	"END:VEVENT\r\n" +
	"BEGIN:VEVENT\r\n" +
	"UID:meeting-1\r\n" +
	"DTSTAMP:20261001T080000Z\r\n" +
	"RECURRENCE-ID;TZID=Europe/Copenhagen:20261019T100000\r\n" +
	"DTSTART;TZID=Europe/Copenhagen:20261019T140000\r\n" +
	"DTEND;TZID=Europe/Copenhagen:20261019T153000\r\n" +
	"SUMMARY:Weekly sync (moved)\r\n" +
	"DESCRIPTION:Agenda\\nItems\r\n" +
	"LOCATION:Room 1\r\n" +
	"STATUS:CONFIRMED\r\n" +
	"CLASS:PRIVATE\r\n" +
	"TRANSP:TRANSPARENT\r\n" +
	"CATEGORIES:Work,Planning\r\n" +
	"SEQUENCE:2\r\n" +
	"ORGANIZER;CN=Alice:mailto:alice@example.test\r\n" +
	"ATTENDEE;CN=Alice;ROLE=CHAIR;PARTSTAT=ACCEPTED:mailto:alice@example.test\r\n" +
	"ATTENDEE;CN=Bob;ROLE=OPT-PARTICIPANT;PARTSTAT=DECLINED;RSVP=TRUE;X-NUM-GUESTS=1:mailto:bob@example.test\r\n" +
	"X-OVERRIDE-ONLY:keep\r\n" +
	"BEGIN:VALARM\r\n" +
	"ACTION:DISPLAY\r\n" +
	"TRIGGER:-PT15M\r\n" +
	"DESCRIPTION:Soon\r\n" +
	"X-APPLE-DEFAULT-ALARM:TRUE\r\n" +
	"END:VALARM\r\n" +
	"END:VEVENT\r\n" +
	"END:VCALENDAR\r\n"

func decodeICS(t *testing.T, data string) (*ical.Calendar, map[string]any) {
	t.Helper()
	cal, err := calendar.Decode([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	event, err := decodeCalendarEvent(cal)
	if err != nil {
		t.Fatal(err)
	}
	return cal, event
}

func encodeICS(t *testing.T, cal *ical.Calendar) string {
	t.Helper()
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestICalendarToJSCalendarCommonProperties(t *testing.T) {
	_, event := decodeICS(t, meetingICS)
	alice, bob := participantID("alice@example.test"), participantID("bob@example.test")
	checks := map[string]any{
		"uid": "meeting-1", "title": "Weekly sync", "description": "Agenda\nItems", "start": "2026-10-05T10:00:00", "timeZone": "Europe/Copenhagen",
		"duration": "PT1H30M", "status": "confirmed", "privacy": "private", "freeBusyStatus": "free", "sequence": 2,
		"created": "2026-10-01T08:00:00Z", "keywords": map[string]any{"Work": true, "Planning": true},
		"locations": map[string]any{"1": map[string]any{"@type": "Location", "name": "Room 1"}},
		"replyTo":   map[string]any{"imip": "mailto:alice@example.test"},
		"recurrenceRules": []any{map[string]any{"@type": "RecurrenceRule", "frequency": "weekly", "interval": 1,
			"byDay": []any{map[string]any{"@type": "NDay", "day": "mo"}}, "until": "2026-11-30T10:00:00"}},
		"alerts": map[string]any{"a1": map[string]any{"@type": "Alert", "action": "display", "trigger": map[string]any{"@type": "OffsetTrigger", "offset": "-PT15M"}}},
		"participants": map[string]any{
			alice: map[string]any{"@type": "Participant", "name": "Alice", "email": "alice@example.test", "sendTo": map[string]any{"imip": "mailto:alice@example.test"},
				"roles": map[string]any{"owner": true, "attendee": true, "chair": true}, "participationStatus": "accepted"},
			bob: map[string]any{"@type": "Participant", "name": "Bob", "email": "bob@example.test", "sendTo": map[string]any{"imip": "mailto:bob@example.test"},
				"roles": map[string]any{"attendee": true, "optional": true}, "participationStatus": "tentative", "expectReply": true}},
	}
	for key, want := range checks {
		if !reflect.DeepEqual(normalizeJSON(event[key]), normalizeJSON(want)) {
			got, _ := json.Marshal(event[key])
			t.Errorf("%s = %s", key, got)
		}
	}
	overrides := event["recurrenceOverrides"].(map[string]any)
	if !reflect.DeepEqual(overrides["2026-10-12T10:00:00"], map[string]any{"excluded": true}) {
		t.Errorf("exclusion = %#v", overrides["2026-10-12T10:00:00"])
	}
	moved := overrides["2026-10-19T10:00:00"].(map[string]any)
	if moved["start"] != "2026-10-19T14:00:00" || moved["title"] != "Weekly sync (moved)" || len(moved) != 3 {
		got, _ := json.Marshal(moved)
		t.Errorf("override patch = %s", got)
	}
	participants := moved["participants"].(map[string]any)
	if participants[bob].(map[string]any)["participationStatus"] != "declined" {
		t.Errorf("override participants = %#v", participants)
	}
}

func TestJSCalendarRoundTripPreservesUnknownICalendar(t *testing.T) {
	original, event := decodeICS(t, meetingICS)
	if err := applyPatch(event, map[string]any{"title": "Weekly sync v2", "recurrenceOverrides/2026-10-19T10:00:00/title": "Moved again",
		"alerts/a1/trigger/offset": "-PT30M"}); err != nil {
		t.Fatal(err)
	}
	cal, err := encodeCalendarEvent(event, original, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeICS(t, cal)
	for _, kept := range []string{"X-WR-CALNAME:Work", "X-MICROSOFT-CDO-BUSYSTATUS:FREE", "X-APPLE-DEFAULT-ALARM:TRUE", "X-OVERRIDE-ONLY:keep",
		"X-NUM-GUESTS=1", "SUMMARY:Weekly sync v2", "SUMMARY:Moved again", "TRIGGER:-PT30M", "EXDATE;TZID=Europe/Copenhagen:20261012T100000",
		"RECURRENCE-ID;TZID=Europe/Copenhagen:20261019T100000", "UNTIL=20261130T090000Z", "SEQUENCE:2"} {
		if !strings.Contains(encoded, kept) {
			t.Errorf("missing %q in\n%s", kept, encoded)
		}
	}
	_, again := decodeICS(t, encoded)
	for _, e := range []map[string]any{event, again} {
		delete(e, "updated")
	}
	if !reflect.DeepEqual(normalizeJSON(again), normalizeJSON(event)) {
		a, _ := json.MarshalIndent(again, "", " ")
		b, _ := json.MarshalIndent(event, "", " ")
		t.Fatalf("round trip mismatch:\n%s\nwant\n%s", a, b)
	}
}

func TestJSCalendarAllDayAndRescheduleBumpsSequence(t *testing.T) {
	event := map[string]any{"@type": "Event", "uid": "day-1", "title": "Offsite", "start": "2026-11-02T00:00:00", "showWithoutTime": true, "duration": "P2D",
		"recurrenceOverrides": map[string]any{"2026-11-09T00:00:00": map[string]any{}}}
	cal, err := encodeCalendarEvent(event, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeICS(t, cal)
	for _, want := range []string{"DTSTART;VALUE=DATE:20261102", "DTEND;VALUE=DATE:20261104", "RDATE;VALUE=DATE:20261109", "PRODID:" + calendarProductID} {
		if !strings.Contains(encoded, want) {
			t.Errorf("missing %q in\n%s", want, encoded)
		}
	}
	_, again := decodeICS(t, encoded)
	if again["showWithoutTime"] != true || again["duration"] != "P2D" || again["timeZone"] != nil {
		t.Fatalf("all-day = %#v", again)
	}

	original, meeting := decodeICS(t, meetingICS)
	meeting["start"] = "2026-10-05T11:00:00"
	cal, err = encodeCalendarEvent(meeting, original, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encodeICS(t, cal), "SEQUENCE:3") {
		t.Fatal("organizer reschedule did not raise SEQUENCE")
	}
	if _, err := encodeCalendarEvent(map[string]any{"uid": "x", "start": "2026-01-01T10:00:00", "timeZone": "Mars/Base"}, nil, time.Now()); err == nil {
		t.Fatal("unknown time zone accepted")
	}
}

func TestDurationParsing(t *testing.T) {
	for in, want := range map[string]string{"PT1H30M": "PT1H30M", "P1W": "P7D", "P1DT2H": "P1DT2H", "-PT15M": "-PT15M", "PT0S": "PT0S"} {
		d, err := parseDuration(in)
		if err != nil || d.String() != want {
			t.Errorf("%s -> %s (%v)", in, d, err)
		}
	}
	for _, bad := range []string{"", "P", "PT", "1H", "PT1D", "P1H"} {
		if _, err := parseDuration(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
