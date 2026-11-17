package calendar

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
)

func encodeTimezone(t *testing.T, tzid string) string {
	t.Helper()
	component, ok := TimezoneComponent(tzid, 2026)
	if !ok {
		t.Fatalf("no VTIMEZONE for %s", tzid)
	}
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//test//EN")
	cal.Children = append(cal.Children, component)
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// Generated time zones follow each zone's own rules, not a fixed US rule.
func TestTimezoneComponentFollowsZoneRules(t *testing.T) {
	for tzid, want := range map[string][]string{
		"Europe/Copenhagen": {"BEGIN:DAYLIGHT", "DTSTART:20260329T020000", "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU", "TZOFFSETFROM:+0100", "TZOFFSETTO:+0200", "TZNAME:CEST",
			"BEGIN:STANDARD", "DTSTART:20261025T030000", "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU", "TZNAME:CET"},
		"America/New_York": {"DTSTART:20260308T020000", "BYMONTH=3;BYDAY=2SU", "DTSTART:20261101T020000", "BYMONTH=11;BYDAY=1SU", "TZOFFSETTO:-0400", "TZOFFSETTO:-0500"},
		"Australia/Sydney": {"BYMONTH=4;BYDAY=1SU", "BYMONTH=10;BYDAY=1SU", "TZOFFSETTO:+1100", "TZOFFSETTO:+1000"},
		"Asia/Tokyo":       {"BEGIN:STANDARD", "TZOFFSETFROM:+0900", "TZOFFSETTO:+0900"},
	} {
		encoded := encodeTimezone(t, tzid)
		for _, fragment := range want {
			if !strings.Contains(encoded, fragment) {
				t.Errorf("%s VTIMEZONE lacks %q:\n%s", tzid, fragment, encoded)
			}
		}
	}
	if _, ok := TimezoneComponent("Mars/Olympus", 2026); ok {
		t.Fatal("unknown zone produced a VTIMEZONE")
	}
}

// Events written by the web editor carry the VTIMEZONE their TZID needs.
func TestCreateDefinesReferencedTimezone(t *testing.T) {
	data, err := Create(Update{Summary: "Sync", Start: "2026-10-26T10:00:00+01:00", End: "2026-10-26T11:00:00+01:00", Timezone: "Europe/Copenhagen"}, "sync", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "DTSTART;TZID=Europe/Copenhagen:20261026T100000") || strings.Count(text, "BEGIN:VTIMEZONE") != 1 || !strings.Contains(text, "TZID:Europe/Copenhagen") {
		t.Fatalf("event lacks its VTIMEZONE:\n%s", text)
	}
	again, err := UpdateExisting(data, Update{Summary: "Sync 2", Start: "2026-10-26T10:00:00+01:00", Timezone: "Europe/Copenhagen"})
	if err != nil || strings.Count(string(again), "BEGIN:VTIMEZONE") != 1 {
		t.Fatalf("update duplicated or dropped the VTIMEZONE (%v):\n%s", err, again)
	}
}
