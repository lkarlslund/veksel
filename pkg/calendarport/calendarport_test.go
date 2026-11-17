package calendarport

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestParseGroupsByUIDWithReferencedTimezones(t *testing.T) {
	data := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\n" +
		"BEGIN:VTIMEZONE\r\nTZID:Europe/Copenhagen\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n" +
		"BEGIN:VTIMEZONE\r\nTZID:America/New_York\r\nBEGIN:STANDARD\r\nDTSTART:19701101T020000\r\nTZOFFSETFROM:-0400\r\nTZOFFSETTO:-0500\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n" +
		"BEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID;TZID=Europe/Copenhagen:20261109T090000\r\nDTSTART;TZID=Europe/Copenhagen:20261109T100000\r\nSUMMARY:Moved\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:a\r\nDTSTART;TZID=Europe/Copenhagen:20261102T090000\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Weekly\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nDTSTART:20261102T090000Z\r\nSUMMARY:No UID\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:broken\r\nSUMMARY:No start\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	document := Parse([]byte(data))
	if len(document.Objects) != 2 || len(document.Problems) != 1 || document.Problems[0].UID != "broken" {
		t.Fatalf("document = %+v", document)
	}
	first := string(document.Objects[0].Data)
	if document.Objects[0].Summary != "Weekly" || document.Objects[0].Events != 2 || !strings.Contains(first, "TZID:Europe/Copenhagen") || strings.Contains(first, "America/New_York") {
		t.Fatalf("grouped object:\n%s", first)
	}
	if strings.Index(first, "RRULE") > strings.Index(first, "RECURRENCE-ID") {
		t.Fatalf("master is not first:\n%s", first)
	}
	again := Parse([]byte(data))
	if !strings.HasPrefix(document.Objects[1].UID, "import-") || again.Objects[1].UID != document.Objects[1].UID {
		t.Fatalf("derived UID is not stable: %q / %q", document.Objects[1].UID, again.Objects[1].UID)
	}

	exporter := NewExporter("Mine", 0)
	for _, object := range document.Objects {
		if err := exporter.Add(object.Data); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := exporter.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if exporter.Events() != 3 || strings.Count(buf.String(), "BEGIN:VTIMEZONE") != 1 || !strings.Contains(buf.String(), "X-WR-CALNAME:Mine") {
		t.Fatalf("export:\n%s", buf.String())
	}
	if NewExporter("", 10).Add(document.Objects[0].Data) != ErrTooLarge {
		t.Fatal("export bound not enforced")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if document := Parse([]byte("hello")); len(document.Objects) != 0 || len(document.Problems) != 1 {
		t.Fatalf("garbage = %+v", document)
	}
}

func TestBirthdays(t *testing.T) {
	for input, want := range map[string][3]int{"19850315": {1985, 3, 15}, "1985-03-15": {1985, 3, 15}, "--0315": {0, 3, 15}, "--03-15": {0, 3, 15}, "1985-03-15T00:00:00Z": {1985, 3, 15}, "--0229": {0, 2, 29}} {
		year, month, day, ok := ParseBirthday(input)
		if !ok || year != want[0] || int(month) != want[1] || day != want[2] {
			t.Errorf("ParseBirthday(%q) = %d-%d-%d %v", input, year, month, day, ok)
		}
	}
	for _, input := range []string{"", "1985-13-01", "--0230", "soon"} {
		if _, _, _, ok := ParseBirthday(input); ok {
			t.Errorf("ParseBirthday(%q) accepted", input)
		}
	}
	events := BirthdayEvents([]Birthday{{ContactID: "1", Name: "Leap", Month: time.February, Day: 29}, {ContactID: "2", Name: "Ada", Year: 2000, Month: time.January, Day: 2}},
		time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC))
	var got []string
	for _, event := range events {
		got = append(got, event.Start+" "+event.Summary)
	}
	want := "2027-01-02 Ada’s birthday (27),2027-02-28 Leap’s birthday,2028-01-02 Ada’s birthday (28),2028-02-29 Leap’s birthday"
	if strings.Join(got, ",") != want {
		t.Fatalf("birthdays = %v", got)
	}
}

func TestBusyEventRevealsOnlyTheInterval(t *testing.T) {
	event := BusyEvent(time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC), time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC), true, time.Unix(0, 0))
	if summary, _ := event.Props.Text("SUMMARY"); summary != "Tentative" || event.Props.Get("DESCRIPTION") != nil || event.Props.Get("LOCATION") != nil {
		t.Fatalf("busy event props = %+v", event.Props)
	}
}
