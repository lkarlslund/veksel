package calendar

import (
	"strings"
	"testing"
	"time"
)

func TestCustomRecurrenceRoundTrips(t *testing.T) {
	for _, rule := range []string{
		"FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE,FR;COUNT=10",
		"FREQ=MONTHLY;BYDAY=2TU;UNTIL=20271231T235959Z",
		"FREQ=MONTHLY;BYMONTHDAY=15",
		"FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU",
		"FREQ=DAILY;INTERVAL=3",
	} {
		data, err := Create(Update{Summary: "Rule", Start: "2026-11-02T09:00:00Z", Recurrence: ptr(strings.ToLower(rule))}, "rule", time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", rule, err)
		}
		event, err := Project(data)
		if err != nil {
			t.Fatal(err)
		}
		if event.RRule != rule || event.Recurrence != "custom" {
			t.Fatalf("rule %q projected as %q/%q", rule, event.RRule, event.Recurrence)
		}
		// Saving without a recurrence change keeps the rule verbatim.
		updated, err := UpdateExisting(data, Update{Summary: "Renamed", Start: "2026-11-02T10:00:00Z"})
		if err != nil {
			t.Fatal(err)
		}
		if again, _ := Project(updated); again.RRule != rule {
			t.Fatalf("rule %q not preserved: %q", rule, again.RRule)
		}
	}
	preset, err := Create(Update{Summary: "Weekly", Start: "2026-11-02T09:00:00Z", Recurrence: ptr("RRULE:FREQ=WEEKLY")}, "preset", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if event, _ := Project(preset); event.Recurrence != "weekly" || event.RRule != "FREQ=WEEKLY" {
		t.Fatalf("plain weekly rule projected as %+v", event)
	}
	for _, invalid := range []string{"FREQ=SOMETIMES", "BYDAY=MO", "FREQ=DAILY;INTERVAL=5000", "FREQ=WEEKLY;BYDAY=XX"} {
		if _, err := Create(Update{Summary: "Bad", Start: "2026-11-02T09:00:00Z", Recurrence: ptr(invalid)}, "bad", time.Unix(0, 0)); err == nil {
			t.Fatalf("invalid rule %q accepted", invalid)
		}
	}
}

func TestAlarmsCategoriesPersistAndReplace(t *testing.T) {
	alarms := []int{0, 15, 60, 1440, 95}
	categories := []string{"Work", " work ", "Travel", ""}
	data, err := Create(Update{Summary: "Flight", Start: "2026-11-02T09:00:00Z", Alarms: &alarms, Categories: &categories}, "flight", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TRIGGER:PT0S", "TRIGGER:-PT15M", "TRIGGER:-PT1H", "TRIGGER:-P1D", "TRIGGER:-PT95M", "CATEGORIES:Work,Travel"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %q:\n%s", want, data)
		}
	}
	event, err := Project(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Alarms) != 5 || *event.Alarms[1].MinutesBefore != 15 || *event.Alarms[3].MinutesBefore != 1440 || event.Alarms[0].Action != "DISPLAY" {
		t.Fatalf("alarms = %+v", event.Alarms)
	}
	// Omitted alarms are preserved; an empty list removes them.
	kept, err := UpdateExisting(data, Update{Summary: "Flight", Start: "2026-11-02T09:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if event, _ := Project(kept); len(event.Alarms) != 5 || len(event.Categories) != 2 {
		t.Fatalf("save without alarms changed them: %+v", event)
	}
	none := []int{}
	cleared, err := UpdateExisting(kept, Update{Summary: "Flight", Start: "2026-11-02T09:00:00Z", Alarms: &none})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cleared), "VALARM") {
		t.Fatalf("alarms not removed:\n%s", cleared)
	}
	tooEarly := []int{maxAlarmMinutes + 1}
	if _, err := UpdateExisting(kept, Update{Summary: "Flight", Start: "2026-11-02T09:00:00Z", Alarms: &tooEarly}); err == nil {
		t.Fatal("reminder beyond four weeks accepted")
	}
	absolute := []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:abs\r\nDTSTAMP:20260801T000000Z\r\nDTSTART:20261102T090000Z\r\nSUMMARY:Abs\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER;VALUE=DATE-TIME:20261102T080000Z\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	if event, err := Project(absolute); err != nil || len(event.Alarms) != 1 || event.Alarms[0].MinutesBefore != nil || event.Alarms[0].Trigger != "20261102T080000Z" {
		t.Fatalf("absolute alarm projection = %+v, %v", event.Alarms, err)
	}
}

func TestAttendeesOrganizerAndSequence(t *testing.T) {
	attendees := []AttendeeUpdate{{Address: "Bob@Example.com", Name: "Bob", Role: "req-participant"}, {Address: "mailto:carol@remote.test", Role: "OPT-PARTICIPANT"}, {Address: "bob@example.com"}}
	organizer := AttendeeUpdate{Address: "alice@example.com", Name: "Alice"}
	data, err := Create(Update{Summary: "Plan", Start: "2026-11-02T09:00:00Z", End: "2026-11-02T10:00:00Z", Attendees: &attendees, Organizer: &organizer, Organizing: true}, "plan", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	event, err := Project(data)
	if err != nil {
		t.Fatal(err)
	}
	if event.OrganizerAddress != "alice@example.com" || len(event.Participants) != 2 || event.Participants[0].Address != "bob@example.com" || event.Participants[0].Role != "REQ-PARTICIPANT" || event.Participants[1].Role != "OPT-PARTICIPANT" || event.Participants[1].PartStat != "NEEDS-ACTION" || event.Sequence != 0 {
		t.Fatalf("meeting projection = %+v", event)
	}
	// An answer recorded on the organizer copy survives a text-only save.
	accepted := []byte(strings.Replace(string(data), "PARTSTAT=NEEDS-ACTION", "PARTSTAT=ACCEPTED", 1))
	retitled, err := UpdateExisting(accepted, Update{Summary: "Plan v2", Start: "2026-11-02T09:00:00Z", End: "2026-11-02T10:00:00Z", Organizing: true})
	if err != nil {
		t.Fatal(err)
	}
	if event, _ := Project(retitled); event.Sequence != 0 || event.Participants[0].PartStat != "ACCEPTED" {
		t.Fatalf("text change bumped sequence or reset answers: %+v", event)
	}
	// A new time is a new revision: SEQUENCE increments, answers are reset.
	moved, err := UpdateExisting(retitled, Update{Summary: "Plan v2", Start: "2026-11-02T11:00:00Z", End: "2026-11-02T12:00:00Z", Organizing: true})
	if err != nil {
		t.Fatal(err)
	}
	if event, _ := Project(moved); event.Sequence != 1 || event.Participants[0].PartStat != "NEEDS-ACTION" {
		t.Fatalf("time change = %+v", event)
	}
	// An attendee moving their own copy does not create a revision.
	if copyMoved, err := UpdateExisting(moved, Update{Summary: "Plan v2", Start: "2026-11-02T13:00:00Z"}); err != nil {
		t.Fatal(err)
	} else if event, _ := Project(copyMoved); event.Sequence != 1 {
		t.Fatalf("non-organizer save bumped sequence to %d", event.Sequence)
	}
	none := []AttendeeUpdate{}
	private, err := UpdateExisting(moved, Update{Summary: "Plan v2", Start: "2026-11-02T11:00:00Z", Attendees: &none})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(private), "ATTENDEE") || strings.Contains(string(private), "ORGANIZER") {
		t.Fatalf("empty attendee list kept participants:\n%s", private)
	}
	if _, err := Create(Update{Summary: "x", Start: "2026-11-02T09:00:00Z", Attendees: &attendees}, "x", time.Unix(0, 0)); err == nil {
		t.Fatal("meeting without organizer accepted")
	}
	bad := []AttendeeUpdate{{Address: "not an address"}}
	if _, err := Create(Update{Summary: "x", Start: "2026-11-02T09:00:00Z", Attendees: &bad, Organizer: &organizer}, "x", time.Unix(0, 0)); err == nil {
		t.Fatal("invalid attendee accepted")
	}
}

func TestWithCommentAddsComment(t *testing.T) {
	msg, err := ParseITIP([]byte(sampleiTIPRequest))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := BuildReply(msg, "mailto:alice@example.com", PartStatDeclined)
	if err != nil {
		t.Fatal(err)
	}
	commented, err := WithComment(reply, "Travelling, sorry")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseITIP(commented)
	if err != nil || parsed.Comment != "Travelling, sorry" || parsed.Method != MethodReply {
		t.Fatalf("comment = %q method = %q err = %v", parsed.Comment, parsed.Method, err)
	}
}
