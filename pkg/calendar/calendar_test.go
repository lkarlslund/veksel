package calendar

import (
	"strings"
	"testing"
	"time"
)

func ptr(value string) *string { return &value }

func TestOccurrencesExpandTimezoneRecurrenceAndOverlap(t *testing.T) {
	data := []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:weekly\r\nDTSTAMP:20260801T000000Z\r\nDTSTART;TZID=Europe/Copenhagen:20260803T090000\r\nDTEND;TZID=Europe/Copenhagen:20260803T103000\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\nSUMMARY:Standup\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	start := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	got, truncated, err := Occurrences(data, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(got) != 2 {
		t.Fatalf("got %d occurrences, truncated=%v", len(got), truncated)
	}
	if got[0].Timezone != "Europe/Copenhagen" || got[0].Start != "2026-08-10T09:00:00+02:00" {
		t.Fatalf("unexpected projection: %+v", got[0])
	}
}

func TestUpdateExistingPreservesUnsupportedProperties(t *testing.T) {
	data := []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:keep\r\nDTSTAMP:20260801T000000Z\r\nDTSTART:20260820T100000Z\r\nDTEND:20260820T110000Z\r\nRRULE:FREQ=WEEKLY;BYDAY=MO,WE\r\nSUMMARY:Old\r\nORGANIZER:mailto:boss@example.test\r\nATTENDEE:mailto:user@example.test\r\nX-VEKSEL-KEEP:yes\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	updated, err := UpdateExisting(data, Update{Summary: "New", Start: "2026-08-20T12:00:00Z", End: "2026-08-20T13:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	for _, want := range []string{"SUMMARY:New", "RRULE:FREQ=WEEKLY;BYDAY=MO,WE", "ORGANIZER:mailto:boss@example.test", "ATTENDEE:mailto:user@example.test", "X-VEKSEL-KEEP:yes"} {
		if !strings.Contains(text, want) {
			t.Errorf("updated payload does not preserve %q:\n%s", want, text)
		}
	}
	projected, err := Project(updated)
	if err != nil {
		t.Fatal(err)
	}
	if projected.Organizer != "boss@example.test" || len(projected.Attendees) != 1 || projected.Attendees[0] != "user@example.test" {
		t.Fatalf("participant projection = %+v", projected)
	}
}

func TestCreateAllDayRecurringEvent(t *testing.T) {
	data, err := Create(Update{Summary: "Away", Start: "2026-08-20", End: "2026-08-23", AllDay: true, Timezone: "Europe/Copenhagen", Recurrence: ptr("yearly")}, "away", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	event, err := Project(data)
	if err != nil {
		t.Fatal(err)
	}
	if !event.AllDay || event.End != "2026-08-23" || event.Recurrence != "yearly" {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestUpdateOccurrenceMovesOnlySelectedInstance(t *testing.T) {
	data := []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:weekly\r\nDTSTAMP:20260801T000000Z\r\nDTSTART:20260803T090000Z\r\nDTEND:20260803T100000Z\r\nRRULE:FREQ=WEEKLY;COUNT=3\r\nSUMMARY:Standup\r\nLOCATION:Room A\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	updated, err := UpdateOccurrence(data, "2026-08-10T09:00:00Z", Update{
		Summary: "Standup", Location: "Room B", Start: "2026-08-10T13:15:00Z", End: "2026-08-10T14:15:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, truncated, err := Occurrences(updated, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(got) != 3 {
		t.Fatalf("got %d occurrences, truncated=%v: %+v", len(got), truncated, got)
	}
	if got[0].Start != "2026-08-03T09:00:00Z" || got[1].Start != "2026-08-10T13:15:00Z" || got[2].Start != "2026-08-17T09:00:00Z" {
		t.Fatalf("selected occurrence was not moved independently: %+v", got)
	}
	if got[1].RecurrenceID != "2026-08-10T09:00:00Z" || got[1].Location != "Room B" || got[1].Recurrence != "custom" {
		t.Fatalf("exception metadata was not preserved: %+v", got[1])
	}
	master, err := Project(updated)
	if err != nil {
		t.Fatal(err)
	}
	if master.Start != "2026-08-03T09:00:00Z" || master.Location != "Room A" {
		t.Fatalf("master was changed: %+v", master)
	}
}

func TestUpdateOccurrenceRejectsNonRecurringEvent(t *testing.T) {
	data, err := Create(Update{Summary: "One off", Start: "2026-08-20T10:00:00Z", End: "2026-08-20T11:00:00Z"}, "one", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateOccurrence(data, "2026-08-20T10:00:00Z", Update{Summary: "One off", Start: "2026-08-20T12:00:00Z", End: "2026-08-20T13:00:00Z"}); err == nil || !strings.Contains(err.Error(), "not recurring") {
		t.Fatalf("expected non-recurring rejection, got %v", err)
	}
}

func TestUpdateAllDayOccurrencePreservesDateIdentity(t *testing.T) {
	data, err := Create(Update{Summary: "Away", Start: "2026-10-25", End: "2026-10-26", AllDay: true, Recurrence: ptr("weekly")}, "away-weekly", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := Occurrences(data, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC))
	if err != nil || len(before) < 2 {
		t.Fatalf("initial all-day occurrences = %+v, err=%v", before, err)
	}
	updated, err := UpdateOccurrence(data, before[1].RecurrenceID, Update{Summary: "Away", Start: "2026-11-03", End: "2026-11-05", AllDay: true})
	if err != nil {
		t.Fatal(err)
	}
	after, _, err := Occurrences(updated, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(after) < 2 || after[1].Start != "2026-11-03" || after[1].End != "2026-11-05" || after[1].RecurrenceID != before[1].RecurrenceID {
		t.Fatalf("all-day exception identity or dates changed: before=%+v after=%+v", before, after)
	}
}
