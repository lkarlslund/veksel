package schedule

import (
	"testing"
	"time"
)

func TestParseAcceptsShorthandsAndCanonicalForms(t *testing.T) {
	for value, want := range map[string]string{
		"":                    "off",
		"off":                 "off",
		"daily":               "daily 03:00",
		"weekly":              "weekly sun 03:00",
		"02:30":               "daily 02:30",
		"daily 23:05":         "daily 23:05",
		"weekly mon":          "weekly mon 03:00",
		"Weekly Friday 01:15": "weekly fri 01:15",
		"sat 04:00":           "weekly sat 04:00",
		"weekly 05:00":        "weekly sun 05:00",
	} {
		parsed, err := Parse(value)
		if err != nil {
			t.Fatalf("Parse(%q): %v", value, err)
		}
		if got := parsed.String(); got != want {
			t.Errorf("Parse(%q) = %q, want %q", value, got, want)
		}
		if again, err := Parse(parsed.String()); err != nil || again != parsed {
			t.Errorf("canonical form %q does not round-trip: %+v, %v", parsed.String(), again, err)
		}
	}
	for _, value := range []string{"hourly", "25:00", "03:60", "3:5", "daily mon 03:00", "weekly someday 03:00", "03:00 04:00"} {
		if _, err := Parse(value); err == nil {
			t.Errorf("Parse(%q) accepted an invalid schedule", value)
		}
	}
}

func TestNextAndPrevious(t *testing.T) {
	loc := time.UTC
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, loc) // Thursday
	daily, _ := Parse("daily 03:00")
	if got := daily.Previous(at); !got.Equal(time.Date(2026, 10, 22, 3, 0, 0, 0, loc)) {
		t.Fatalf("daily previous = %v", got)
	}
	if got := daily.Next(at); !got.Equal(time.Date(2026, 10, 23, 3, 0, 0, 0, loc)) {
		t.Fatalf("daily next = %v", got)
	}
	slot := time.Date(2026, 10, 22, 3, 0, 0, 0, loc)
	if got := daily.Previous(slot); !got.Equal(slot) {
		t.Fatalf("previous at a slot = %v, want the slot itself", got)
	}
	if got := daily.Next(slot); !got.Equal(slot.AddDate(0, 0, 1)) {
		t.Fatalf("next at a slot = %v, want the following day", got)
	}
	weekly, _ := Parse("sun 03:00")
	if got := weekly.Previous(at); !got.Equal(time.Date(2026, 10, 18, 3, 0, 0, 0, loc)) {
		t.Fatalf("weekly previous = %v", got)
	}
	if got := weekly.Next(at); !got.Equal(time.Date(2026, 10, 25, 3, 0, 0, 0, loc)) {
		t.Fatalf("weekly next = %v", got)
	}
	if (Schedule{}).Due(time.Time{}, time.Time{}, at) || !(Schedule{}).NextRun(time.Time{}, time.Time{}, at).IsZero() {
		t.Fatal("a disabled schedule must never be due")
	}
}

func TestDueCatchesUpOnceAfterDowntime(t *testing.T) {
	loc := time.UTC
	daily, _ := Parse("daily 03:00")
	baseline := time.Date(2026, 10, 1, 12, 0, 0, 0, loc)
	if daily.Due(time.Time{}, baseline, baseline.Add(time.Hour)) {
		t.Fatal("enabling a schedule must not run immediately for a slot before it took effect")
	}
	firstSlot := time.Date(2026, 10, 2, 3, 0, 30, 0, loc)
	if !daily.Due(time.Time{}, baseline, firstSlot) {
		t.Fatal("first slot after the baseline must be due")
	}
	lastAttempt := firstSlot
	if daily.Due(lastAttempt, baseline, firstSlot.Add(time.Minute)) {
		t.Fatal("a slot must run only once")
	}
	// The server was down for three days and missed three slots.
	restart := time.Date(2026, 10, 5, 9, 0, 0, 0, loc)
	if !daily.Due(lastAttempt, baseline, restart) {
		t.Fatal("missed slots must be caught up after downtime")
	}
	if got := daily.NextRun(lastAttempt, baseline, restart); !got.Equal(restart) {
		t.Fatalf("next run while due = %v, want now", got)
	}
	lastAttempt = restart
	if daily.Due(lastAttempt, baseline, restart.Add(time.Hour)) {
		t.Fatal("catch-up must happen once, not once per missed slot")
	}
	if got := daily.NextRun(lastAttempt, baseline, restart.Add(time.Hour)); !got.Equal(time.Date(2026, 10, 6, 3, 0, 0, 0, loc)) {
		t.Fatalf("next run after catch-up = %v", got)
	}
}
