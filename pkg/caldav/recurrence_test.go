package caldav

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Sample recurring events for tests ---

var dailyEventRRULE = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:daily-recurring@example.com
DTSTART:20250101T100000Z
DTEND:20250101T110000Z
SUMMARY:Daily Standup
RRULE:FREQ=DAILY;COUNT=10
END:VEVENT
END:VCALENDAR`

var weeklyEventRRULE = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:weekly-recurring@example.com
DTSTART:20250106T140000Z
DTEND:20250106T150000Z
SUMMARY:Weekly Meeting
RRULE:FREQ=WEEKLY;COUNT=5
END:VEVENT
END:VCALENDAR`

var monthlyEventRRULE = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:monthly-recurring@example.com
DTSTART:20250115T090000Z
DTEND:20250115T100000Z
SUMMARY:Monthly Review
RRULE:FREQ=MONTHLY;COUNT=6
END:VEVENT
END:VCALENDAR`

var yearlyEventRRULE = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:yearly-recurring@example.com
DTSTART:20250704T000000Z
DTEND:20250704T235959Z
SUMMARY:Independence Day Party
RRULE:FREQ=YEARLY;COUNT=3
END:VEVENT
END:VCALENDAR`

var eventWithUNTIL = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:until-recurring@example.com
DTSTART:20250101T080000Z
DTEND:20250101T090000Z
SUMMARY:Daily Until Feb
RRULE:FREQ=DAILY;UNTIL=20250201T000000Z
END:VEVENT
END:VCALENDAR`

var eventWithEXDATE = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:exdate-recurring@example.com
DTSTART:20250101T100000Z
DTEND:20250101T110000Z
SUMMARY:Daily With Exceptions
RRULE:FREQ=DAILY;COUNT=10
EXDATE:20250103T100000Z,20250105T100000Z
END:VEVENT
END:VCALENDAR`

var eventWithRDATE = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:rdate-recurring@example.com
DTSTART:20250101T100000Z
DTEND:20250101T110000Z
SUMMARY:Event With Extra Dates
RRULE:FREQ=WEEKLY;COUNT=3
RDATE:20250201T140000Z,20250215T140000Z
END:VEVENT
END:VCALENDAR`

var eventInterval2 = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:interval2-recurring@example.com
DTSTART:20250101T100000Z
DTEND:20250101T110000Z
SUMMARY:Every Other Day
RRULE:FREQ=DAILY;INTERVAL=2;COUNT=10
END:VEVENT
END:VCALENDAR`

var eventByDay = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:byday-recurring@example.com
DTSTART:20250106T100000Z
DTEND:20250106T110000Z
SUMMARY:Mon/Wed/Fri Meeting
RRULE:FREQ=WEEKLY;COUNT=4;BYDAY=MO,WE,FR
END:VEVENT
END:VCALENDAR`

var eventByMonthDay = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:bymonthday-recurring@example.com
DTSTART:20250101T100000Z
DTEND:20250101T110000Z
SUMMARY:1st and 15th of Month
RRULE:FREQ=MONTHLY;COUNT=3;BYMONTHDAY=1,15
END:VEVENT
END:VCALENDAR`

// --- Unit tests for RRULE parsing ---

func TestParseRRuleDaily(t *testing.T) {
	t.Parallel()
	r, err := parseRRule("FREQ=DAILY;COUNT=10")
	if err != nil {
		t.Fatalf("parseRRule: %v", err)
	}
	if r.Freq != FreqDaily {
		t.Errorf("Freq = %v, want %v", r.Freq, FreqDaily)
	}
	if r.Count == nil || *r.Count != 10 {
		t.Errorf("Count = %v, want 10", r.Count)
	}
	if r.Interval != 1 {
		t.Errorf("Interval = %v, want 1", r.Interval)
	}
}

func TestParseRRuleWeeklyInterval(t *testing.T) {
	t.Parallel()
	r, err := parseRRule("FREQ=WEEKLY;INTERVAL=2;UNTIL=20250601T000000Z")
	if err != nil {
		t.Fatalf("parseRRule: %v", err)
	}
	if r.Freq != FreqWeekly {
		t.Errorf("Freq = %v, want %v", r.Freq, FreqWeekly)
	}
	if r.Interval != 2 {
		t.Errorf("Interval = %v, want 2", r.Interval)
	}
	if r.Until.IsZero() {
		t.Error("Until should not be zero")
	}
}

func TestParseRRuleMonthlyByMonthDay(t *testing.T) {
	t.Parallel()
	r, err := parseRRule("FREQ=MONTHLY;COUNT=6;BYMONTHDAY=1,15")
	if err != nil {
		t.Fatalf("parseRRule: %v", err)
	}
	if len(r.ByMonthDay) != 2 {
		t.Fatalf("ByMonthDay = %v, want [1, 15]", r.ByMonthDay)
	}
	if r.ByMonthDay[0] != 1 || r.ByMonthDay[1] != 15 {
		t.Errorf("ByMonthDay = %v, want [1, 15]", r.ByMonthDay)
	}
}

func TestParseRRuleYearlyByMonth(t *testing.T) {
	t.Parallel()
	r, err := parseRRule("FREQ=YEARLY;COUNT=3;BYMONTH=6,12")
	if err != nil {
		t.Fatalf("parseRRule: %v", err)
	}
	if len(r.ByMonth) != 2 {
		t.Fatalf("ByMonth = %v, want [6, 12]", r.ByMonth)
	}
}

func TestParseRRuleByDay(t *testing.T) {
	t.Parallel()
	r, err := parseRRule("FREQ=WEEKLY;COUNT=4;BYDAY=MO,WE,FR")
	if err != nil {
		t.Fatalf("parseRRule: %v", err)
	}
	if len(r.ByDay) != 3 {
		t.Fatalf("ByDay = %v, want [MO, WE, FR]", r.ByDay)
	}
}

func TestParseRRuleMissingFreq(t *testing.T) {
	t.Parallel()
	_, err := parseRRule("COUNT=10")
	if err == nil {
		t.Error("expected error for RRULE without FREQ")
	}
}

func TestParseRRuleUnknownFreq(t *testing.T) {
	t.Parallel()
	_, err := parseRRule("FREQ=HOURLY")
	if err == nil {
		t.Error("expected error for unknown FREQ")
	}
}

// --- Unit tests for extraction helpers ---

func TestExtractRRule(t *testing.T) {
	t.Parallel()
	rrule := extractRRule([]byte(dailyEventRRULE))
	if rrule == "" {
		t.Fatal("extractRRule returned empty string")
	}
	if !strings.Contains(strings.ToUpper(rrule), "FREQ=DAILY") {
		t.Errorf("RRULE should contain FREQ=DAILY: %s", rrule)
	}
}

func TestExtractRRuleNone(t *testing.T) {
	t.Parallel()
	rrule := extractRRule([]byte(sampleVEVENT))
	if rrule != "" {
		t.Errorf("extractRRule should return empty for non-recurring event: %s", rrule)
	}
}

func TestExtractExDateMap(t *testing.T) {
	t.Parallel()
	exDates := extractExDateMap([]byte(eventWithEXDATE))
	if len(exDates) == 0 {
		t.Fatal("extractExDateMap returned empty map")
	}
	// Should have Jan 3 and Jan 5 (plus date-only variants)
	jan3 := time.Date(2025, 1, 3, 10, 0, 0, 0, time.UTC)
	jan5 := time.Date(2025, 1, 5, 10, 0, 0, 0, time.UTC)
	if _, ok := exDates[jan3]; !ok {
		t.Errorf("EXDATE should contain Jan 3")
	}
	if _, ok := exDates[jan5]; !ok {
		t.Errorf("EXDATE should contain Jan 5")
	}
}

func TestExtractRDateTimes(t *testing.T) {
	t.Parallel()
	rDates := extractRDateTimes([]byte(eventWithRDATE))
	if len(rDates) != 2 {
		t.Fatalf("extractRDateTimes = %d, want 2", len(rDates))
	}
}

func TestHasRecurrence(t *testing.T) {
	t.Parallel()
	if !hasRecurrence([]byte(dailyEventRRULE)) {
		t.Error("should detect recurrence in daily event")
	}
	if hasRecurrence([]byte(sampleVEVENT)) {
		t.Error("should not detect recurrence in non-recurring event")
	}
}

// --- Unit tests for recurrence expansion ---

func TestExpandDailyRecurrence(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-01-10T23:59:59Z")

	occurrences := getEventOccurrences([]byte(dailyEventRRULE), rangeStart, rangeEnd)
	if len(occurrences) != 10 {
		t.Errorf("daily recurrence: got %d occurrences, want 10", len(occurrences))
	}
	// First occurrence should be Jan 1
	if len(occurrences) > 0 {
		expected := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
		if !occurrences[0].Equal(expected) {
			t.Errorf("first occurrence = %v, want %v", occurrences[0], expected)
		}
	}
}

func TestExpandWeeklyRecurrence(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-02-28T23:59:59Z")

	occurrences := getEventOccurrences([]byte(weeklyEventRRULE), rangeStart, rangeEnd)
	if len(occurrences) != 5 {
		t.Errorf("weekly recurrence: got %d occurrences, want 5", len(occurrences))
	}
}

func TestExpandMonthlyRecurrence(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-12-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(monthlyEventRRULE), rangeStart, rangeEnd)
	if len(occurrences) != 6 {
		t.Errorf("monthly recurrence: got %d occurrences, want 6", len(occurrences))
	}
	// Verify the months
	for i, occ := range occurrences {
		expectedMonth := time.Month(i + 1)
		if occ.Month() != expectedMonth {
			t.Errorf("occurrence %d: month = %v, want %v", i, occ.Month(), expectedMonth)
		}
		if occ.Day() != 15 {
			t.Errorf("occurrence %d: day = %d, want 15", i, occ.Day())
		}
	}
}

func TestExpandYearlyRecurrence(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2030-12-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(yearlyEventRRULE), rangeStart, rangeEnd)
	if len(occurrences) != 3 {
		t.Errorf("yearly recurrence: got %d occurrences, want 3", len(occurrences))
	}
	// Years should be 2025, 2026, 2027
	for i, occ := range occurrences {
		expectedYear := 2025 + i
		if occ.Year() != expectedYear {
			t.Errorf("occurrence %d: year = %d, want %d", i, occ.Year(), expectedYear)
		}
	}
}

func TestExpandUntil(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-12-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(eventWithUNTIL), rangeStart, rangeEnd)
	// UNTIL=20250201 means occurrences up to Jan 31 (31 days)
	if len(occurrences) != 31 {
		t.Errorf("UNTIL recurrence: got %d occurrences, want 31", len(occurrences))
	}
	// Last occurrence should be Jan 31
	if len(occurrences) > 0 {
		last := occurrences[len(occurrences)-1]
		expected := time.Date(2025, 1, 31, 8, 0, 0, 0, time.UTC)
		if !last.Equal(expected) {
			t.Errorf("last occurrence = %v, want %v", last, expected)
		}
	}
}

func TestExpandWithEXDATE(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-01-10T23:59:59Z")

	occurrences := getEventOccurrences([]byte(eventWithEXDATE), rangeStart, rangeEnd)
	// COUNT=10 means Jan 1-10, but EXDATE removes Jan 3 and Jan 5
	if len(occurrences) != 8 {
		t.Errorf("EXDATE recurrence: got %d occurrences, want 8 (10 - 2 exdates)", len(occurrences))
	}
	// Verify Jan 3 and Jan 5 are not in the results
	for _, occ := range occurrences {
		if occ.Day() == 3 || occ.Day() == 5 {
			t.Errorf("EXDATE: occurrence on day %d should be excluded", occ.Day())
		}
	}
}

func TestExpandWithRDATE(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-03-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(eventWithRDATE), rangeStart, rangeEnd)
	// COUNT=3 weekly from Jan 6 = Jan 6, Jan 13, Jan 20
	// Plus RDATEs: Feb 1, Feb 15
	if len(occurrences) < 5 {
		t.Errorf("RDATE recurrence: got %d occurrences, want at least 5", len(occurrences))
	}
}

func TestExpandInterval2(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-01-20T23:59:59Z")

	occurrences := getEventOccurrences([]byte(eventInterval2), rangeStart, rangeEnd)
	// INTERVAL=2 means Jan 1, 3, 5, 7, 9, 11, 13, 15, 17, 19 (10 occurrences)
	if len(occurrences) != 10 {
		t.Errorf("INTERVAL=2 recurrence: got %d occurrences, want 10", len(occurrences))
	}
	// Verify odd days
	for _, occ := range occurrences {
		if occ.Day()%2 == 0 {
			t.Errorf("INTERVAL=2: occurrence on even day %d", occ.Day())
		}
	}
}

func TestExpandByDay(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-02-28T23:59:59Z")

	occurrences := getEventOccurrences([]byte(eventByDay), rangeStart, rangeEnd)
	// COUNT=4 weekly with BYDAY=MO,WE,FR
	// Week 1 (Jan 6-10): Mon Jan 6, Wed Jan 8, Fri Jan 10
	// Week 2 (Jan 13-17): Mon Jan 13, Wed Jan 15, Fri Jan 17
	// Week 3 (Jan 20-24): Mon Jan 20, Wed Jan 22, Fri Jan 24
	// Week 4 (Jan 27-31): Mon Jan 27, Wed Jan 29, Fri Jan 31
	// Total: 12 occurrences
	if len(occurrences) == 0 {
		t.Error("BYDAY recurrence: got 0 occurrences, expected some")
	}
	// All occurrences should be Mon, Wed, or Fri
	for _, occ := range occurrences {
		dow := occ.Weekday()
		if dow != time.Monday && dow != time.Wednesday && dow != time.Friday {
			t.Errorf("BYDAY: occurrence on %s, expected Mon/Wed/Fri", dow)
		}
	}
}

func TestExpandByMonthDay(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-03-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(eventByMonthDay), rangeStart, rangeEnd)
	// COUNT=3, BYMONTHDAY=1,15
	// Jan: 1st, 15th; Feb: 1st, 15th; Mar: 1st, 15th = 6 occurrences
	if len(occurrences) != 6 {
		t.Errorf("BYMONTHDAY recurrence: got %d occurrences, want 6", len(occurrences))
	}
	// All should be on the 1st or 15th
	for _, occ := range occurrences {
		if occ.Day() != 1 && occ.Day() != 15 {
			t.Errorf("BYMONTHDAY: occurrence on day %d, expected 1 or 15", occ.Day())
		}
	}
}

func TestExpandOutOfRange(t *testing.T) {
	t.Parallel()
	// Query for a range that doesn't overlap with the event
	rangeStart, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2026-12-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(dailyEventRRULE), rangeStart, rangeEnd)
	if len(occurrences) != 0 {
		t.Errorf("out of range: got %d occurrences, want 0", len(occurrences))
	}
}

func TestExpandPartialRange(t *testing.T) {
	t.Parallel()
	// Query for only part of the recurrence range
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-05T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-01-07T23:59:59Z")

	occurrences := getEventOccurrences([]byte(dailyEventRRULE), rangeStart, rangeEnd)
	// Should get Jan 5, 6, 7 = 3 occurrences
	if len(occurrences) != 3 {
		t.Errorf("partial range: got %d occurrences, want 3", len(occurrences))
	}
}

func TestNonRecurringEventInRange(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-01-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(sampleVEVENT), rangeStart, rangeEnd)
	if len(occurrences) != 1 {
		t.Errorf("non-recurring in range: got %d occurrences, want 1", len(occurrences))
	}
}

func TestNonRecurringEventOutOfRange(t *testing.T) {
	t.Parallel()
	rangeStart, _ := time.Parse(time.RFC3339, "2025-06-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-06-30T23:59:59Z")

	occurrences := getEventOccurrences([]byte(sampleVEVENT), rangeStart, rangeEnd)
	if len(occurrences) != 0 {
		t.Errorf("non-recurring out of range: got %d occurrences, want 0", len(occurrences))
	}
}

// --- Integration tests for calendar-query with recurring events ---

func TestCalendarQueryRecurringEvent(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := t.Context()
	ts.FolderStore().Create(ctx, "alice", "MyCal", "calendar", "")

	// PUT a daily recurring event
	r := newRequest("PUT", "/dav/alice/MyCal/daily.ics", dailyEventRRULE)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Query for events in January 2025
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <calendar-data><expand start="20250101T000000Z" end="20250105T235959Z"/></calendar-data>
 </D:prop>
 <filter>
 <comp-filter name="VCALENDAR">
  <comp-filter name="VEVENT">
   <time-range start="20250101T000000Z" end="20250105T235959Z"/>
  </comp-filter>
 </comp-filter>
 </filter>
</calendar-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("calendar-query: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain the recurring event summary
	if !strings.Contains(respBody, "Daily Standup") {
		t.Errorf("calendar-query: body does not contain 'Daily Standup': %s", respBody)
	}
	// RFC 4791 9.6.5: expand returns the instances, each with a
	// RECURRENCE-ID, inside the single response for the object.
	if n := strings.Count(respBody, "<d:response>"); n != 1 {
		t.Errorf("calendar-query: %d responses for one object, want 1", n)
	}
	if !strings.Contains(respBody, "RECURRENCE-ID") {
		t.Errorf("calendar-query: body does not contain RECURRENCE-ID: %s", respBody)
	}
	// Count occurrences (should be 5 for Jan 1-5)
	occCount := strings.Count(respBody, "RECURRENCE-ID")
	if occCount != 5 {
		t.Errorf("calendar-query: found %d RECURRENCE-ID entries, want 5", occCount)
	}
}

func TestCalendarQueryRecurringWithEXDATE(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := t.Context()
	ts.FolderStore().Create(ctx, "alice", "MyCal", "calendar", "")

	// PUT a daily recurring event with EXDATE
	r := newRequest("PUT", "/dav/alice/MyCal/exdate.ics", eventWithEXDATE)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Query for events Jan 1-10
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <calendar-data><expand start="20250101T000000Z" end="20250110T235959Z"/></calendar-data>
 </D:prop>
 <filter>
 <comp-filter name="VCALENDAR">
  <comp-filter name="VEVENT">
   <time-range start="20250101T000000Z" end="20250110T235959Z"/>
  </comp-filter>
 </comp-filter>
 </filter>
</calendar-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("calendar-query: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should have 8 occurrences (10 - 2 exdates)
	occCount := strings.Count(respBody, "RECURRENCE-ID")
	if occCount != 8 {
		t.Errorf("calendar-query with EXDATE: found %d RECURRENCE-ID entries, want 8", occCount)
	}
}

func TestCalendarQueryMixedRecurringAndNonRecurring(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := t.Context()
	ts.FolderStore().Create(ctx, "alice", "MyCal", "calendar", "")

	// PUT a recurring event
	r := newRequest("PUT", "/dav/alice/MyCal/daily.ics", dailyEventRRULE)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT recurring: status = %d", w.Code)
	}

	// PUT a non-recurring event
	r = newRequest("PUT", "/dav/alice/MyCal/once.ics", sampleVEVENT)
	r.Header.Set("Content-Type", "text/calendar")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT non-recurring: status = %d", w.Code)
	}

	// Query for January 1-5
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <calendar-data/>
 </D:prop>
 <filter>
 <comp-filter name="VCALENDAR">
  <comp-filter name="VEVENT">
   <time-range start="20250101T000000Z" end="20250105T235959Z"/>
  </comp-filter>
 </comp-filter>
 </filter>
</calendar-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("calendar-query: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain both recurring and non-recurring events
	if !strings.Contains(respBody, "Daily Standup") {
		t.Error("calendar-query: body does not contain recurring event")
	}
	if !strings.Contains(respBody, "Test Event") {
		t.Error("calendar-query: body does not contain non-recurring event")
	}
}

func TestCalendarQueryRecurringNoTimeRange(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := t.Context()
	ts.FolderStore().Create(ctx, "alice", "MyCal", "calendar", "")

	// PUT a recurring event
	r := newRequest("PUT", "/dav/alice/MyCal/daily.ics", dailyEventRRULE)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d", w.Code)
	}

	// Query without time range — should return the original event
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <calendar-data/>
 </D:prop>
 <filter>
 <comp-filter name="VCALENDAR">
  <comp-filter name="VEVENT"/>
 </comp-filter>
 </filter>
</calendar-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("calendar-query: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain the event (not expanded, since no time range)
	if !strings.Contains(respBody, "Daily Standup") {
		t.Error("calendar-query: body does not contain recurring event")
	}
	// Should NOT contain RECURRENCE-ID (no expansion without time range)
	if strings.Contains(respBody, "RECURRENCE-ID") {
		t.Error("calendar-query without time range should not expand occurrences")
	}
}

// --- Helper function tests ---

func TestDaysInMonth(t *testing.T) {
	t.Parallel()
	tests := []struct {
		year  int
		month time.Month
		want  int
	}{
		{2025, time.January, 31},
		{2025, time.February, 28},
		{2024, time.February, 29}, // leap year
		{2025, time.April, 30},
		{2025, time.June, 30},
		{2025, time.December, 31},
	}
	for _, tt := range tests {
		got := daysInMonth(tt.year, tt.month)
		if got != tt.want {
			t.Errorf("daysInMonth(%d, %s) = %d, want %d", tt.year, tt.month, got, tt.want)
		}
	}
}

func TestIsLeapYear(t *testing.T) {
	t.Parallel()
	if !isLeapYear(2024) {
		t.Error("2024 should be a leap year")
	}
	if isLeapYear(2025) {
		t.Error("2025 should not be a leap year")
	}
	if !isLeapYear(2000) {
		t.Error("2000 should be a leap year")
	}
	if isLeapYear(1900) {
		t.Error("1900 should not be a leap year")
	}
}

func TestParseDayOfWeek(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  int
	}{
		{"MO", 1},
		{"TU", 2},
		{"WE", 3},
		{"TH", 4},
		{"FR", 5},
		{"SA", 6},
		{"SU", 0},
		{"2MO", 1},  // nth occurrence
		{"-1FR", 5}, // negative nth
		{"XX", -1},  // invalid
	}
	for _, tt := range tests {
		got := parseDayOfWeek(tt.input)
		if got != tt.want {
			t.Errorf("parseDayOfWeek(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestSplitICalLines(t *testing.T) {
	t.Parallel()
	// Test with folded lines
	data := []byte("BEGIN:VCALENDAR\r\nLINE1:value1\r\n LINE-continued\r\nLINE2:value2\r\nEND:VCALENDAR\r\n")
	lines := splitICalLines(data)

	if len(lines) != 4 {
		t.Fatalf("splitICalLines: got %d lines, want 4", len(lines))
	}

	// Check that folded line was unfolded
	if !strings.Contains(lines[1], "value1") || !strings.Contains(lines[1], "LINE-continued") {
		t.Errorf("folded line not unfolded: %s", lines[1])
	}
}

func TestGenerateOccurrenceICal(t *testing.T) {
	t.Parallel()
	occTime := time.Date(2025, 1, 3, 10, 0, 0, 0, time.UTC)
	occData := generateOccurrenceICal([]byte(dailyEventRRULE), occTime)

	// Should contain the occurrence time
	if !strings.Contains(string(occData), "20250103T100000Z") {
		t.Errorf("occurrence iCal should contain occurrence time: %s", string(occData))
	}

	// Should contain RECURRENCE-ID
	if !strings.Contains(string(occData), "RECURRENCE-ID:") {
		t.Errorf("occurrence iCal should contain RECURRENCE-ID: %s", string(occData))
	}

	// Should still contain the original UID
	if !strings.Contains(string(occData), "daily-recurring@example.com") {
		t.Errorf("occurrence iCal should contain original UID: %s", string(occData))
	}
}

func TestGenerateOccurrenceICalAllDay(t *testing.T) {
	t.Parallel()
	allDayEvent := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:allday-rec@example.com
DTSTART;VALUE=DATE:20250101
DTEND;VALUE=DATE:20250102
SUMMARY:All Day Event
RRULE:FREQ=DAILY;COUNT=5
END:VEVENT
END:VCALENDAR`

	occTime := time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC)
	occData := generateOccurrenceICal([]byte(allDayEvent), occTime)

	// Should contain the occurrence date
	if !strings.Contains(string(occData), "20250103") {
		t.Errorf("all-day occurrence iCal should contain occurrence date: %s", string(occData))
	}

	// Should contain RECURRENCE-ID with VALUE=DATE
	if !strings.Contains(string(occData), "RECURRENCE-ID;VALUE=DATE:") {
		t.Errorf("all-day occurrence iCal should contain RECURRENCE-ID;VALUE=DATE: %s", string(occData))
	}
}

func TestExtractRRuleFromEventWithEXDATE(t *testing.T) {
	t.Parallel()
	// Verify that extractRRule correctly finds RRULE even when EXDATE is present
	rrule := extractRRule([]byte(eventWithEXDATE))
	if rrule == "" {
		t.Fatal("extractRRule returned empty for event with EXDATE")
	}
	if !strings.Contains(strings.ToUpper(rrule), "FREQ=DAILY") {
		t.Errorf("RRULE should contain FREQ=DAILY: %s", rrule)
	}
}

func TestExpandMonthlyFeb29(t *testing.T) {
	t.Parallel()
	// Test monthly recurrence starting on Feb 29
	feb29Event := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:feb29@example.com
DTSTART:20240229T100000Z
DTEND:20240229T110000Z
SUMMARY:Leap Day Event
RRULE:FREQ=MONTHLY;COUNT=14
END:VEVENT
END:VCALENDAR`

	rangeStart, _ := time.Parse(time.RFC3339, "2024-02-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-03-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(feb29Event), rangeStart, rangeEnd)
	if len(occurrences) == 0 {
		t.Fatal("got 0 occurrences for Feb 29 monthly event")
	}
	// In non-leap year Feb, day 29 should clamp to day 28
	for _, occ := range occurrences {
		if occ.Month() == time.February {
			if occ.Day() == 29 && !isLeapYear(occ.Year()) {
				t.Errorf("Feb 29 in non-leap year %d should clamp to Feb 28", occ.Year())
			}
		}
	}
}

func TestExpandYearlyFeb29(t *testing.T) {
	t.Parallel()
	// Test yearly recurrence on Feb 29
	feb29Yearly := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:feb29-yearly@example.com
DTSTART:20240229T100000Z
DTEND:20240229T110000Z
SUMMARY:Leap Day Birthday
RRULE:FREQ=YEARLY;COUNT=5
END:VEVENT
END:VCALENDAR`

	rangeStart, _ := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2032-12-31T23:59:59Z")

	occurrences := getEventOccurrences([]byte(feb29Yearly), rangeStart, rangeEnd)
	// Should have occurrences for 2024, 2028 (leap years within COUNT=5)
	// Actually COUNT=5 means 2024, 2025, 2026, 2027, 2028
	// But non-leap years should clamp to Feb 28
	if len(occurrences) != 5 {
		t.Errorf("yearly Feb 29: got %d occurrences, want 5", len(occurrences))
	}
}

func TestEventMatchesTimeRangeRecurring(t *testing.T) {
	t.Parallel()
	// eventMatchesTimeRange should still work for recurring events
	// (it checks the base DTSTART)
	rangeStart, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	rangeEnd, _ := time.Parse(time.RFC3339, "2025-01-31T23:59:59Z")

	if !eventMatchesTimeRange([]byte(dailyEventRRULE), rangeStart, rangeEnd) {
		t.Error("recurring event should match its start month")
	}
}
