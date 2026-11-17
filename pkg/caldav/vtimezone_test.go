package caldav

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Sample VTIMEZONE data for tests ---

var sampleVTimezoneNY = `BEGIN:VTIMEZONE
TZID:America/New_York
BEGIN:DAYLIGHT
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
DTSTART:20070311T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU
TZNAME:EDT
END:DAYLIGHT
BEGIN:STANDARD
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
DTSTART:20071104T020000
RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU
TZNAME:EST
END:STANDARD
END:VTIMEZONE`

var sampleVTimezoneInCalendar = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VTIMEZONE
TZID:America/Chicago
BEGIN:STANDARD
TZOFFSETFROM:-0500
TZOFFSETTO:-0600
DTSTART:20071104T020000
RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU
TZNAME:CST
END:STANDARD
BEGIN:DAYLIGHT
TZOFFSETFROM:-0600
TZOFFSETTO:-0500
DTSTART:20070311T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU
TZNAME:CDT
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
UID:tz-event@example.com
DTSTART;TZID=America/Chicago:20250101T100000
DTEND;TZID=America/Chicago:20250101T110000
SUMMARY:Chicago Meeting
END:VEVENT
END:VCALENDAR`

var timezoneEventNY = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:tz-ny-event@example.com
DTSTART;TZID=America/New_York:20250101T100000
DTEND;TZID=America/New_York:20250101T110000
SUMMARY:New York Meeting
END:VEVENT
END:VCALENDAR`

// --- Tests for VTIMEZONE parsing ---

func TestParseVTimezone(t *testing.T) {
	t.Parallel()
	vtz, err := parseVTimezone([]byte(sampleVTimezoneNY))
	if err != nil {
		t.Fatalf("parseVTimezone: %v", err)
	}

	if vtz.TzID != "America/New_York" {
		t.Errorf("TzID = %q, want %q", vtz.TzID, "America/New_York")
	}

	if len(vtz.Daylight) != 1 {
		t.Fatalf("Daylight = %d, want 1", len(vtz.Daylight))
	}

	if len(vtz.Standard) != 1 {
		t.Fatalf("Standard = %d, want 1", len(vtz.Standard))
	}

	// Check DAYLIGHT offsets
	dl := vtz.Daylight[0]
	if dl.TzOffsetFrom != -5*time.Hour {
		t.Errorf("Daylight TzOffsetFrom = %v, want %v", dl.TzOffsetFrom, -5*time.Hour)
	}
	if dl.TzOffsetTo != -4*time.Hour {
		t.Errorf("Daylight TzOffsetTo = %v, want %v", dl.TzOffsetTo, -4*time.Hour)
	}

	// Check STANDARD offsets
	st := vtz.Standard[0]
	if st.TzOffsetFrom != -4*time.Hour {
		t.Errorf("Standard TzOffsetFrom = %v, want %v", st.TzOffsetFrom, -4*time.Hour)
	}
	if st.TzOffsetTo != -5*time.Hour {
		t.Errorf("Standard TzOffsetTo = %v, want %v", st.TzOffsetTo, -5*time.Hour)
	}
}

func TestParseVTimezoneMissingTZID(t *testing.T) {
	t.Parallel()
	data := `BEGIN:VTIMEZONE
BEGIN:STANDARD
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
DTSTART:19700101T000000
END:STANDARD
END:VTIMEZONE`
	_, err := parseVTimezone([]byte(data))
	if err == nil {
		t.Error("expected error for VTIMEZONE without TZID")
	}
}

func TestParseTZOffset(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"-0500", -5 * time.Hour},
		{"+0100", 1 * time.Hour},
		{"+0000", 0},
		{"-0430", -(4*time.Hour + 30*time.Minute)},
		{"+0530", 5*time.Hour + 30*time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseTZOffset(tt.input)
			if got != tt.want {
				t.Errorf("parseTZOffset(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatTZOffset(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input time.Duration
		want  string
	}{
		{-5 * time.Hour, "-0500"},
		{1 * time.Hour, "+0100"},
		{0, "+0000"},
		{-(4*time.Hour + 30*time.Minute), "-0430"},
		{5*time.Hour + 30*time.Minute, "+0530"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatTZOffset(tt.input)
			if got != tt.want {
				t.Errorf("formatTZOffset(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Tests for VTIMEZONE generation ---

func TestGenerateVTimezone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tzName string
		wantIn []string
	}{
		{
			"America/New_York",
			[]string{"TZID:America/New_York", "BEGIN:DAYLIGHT", "BEGIN:STANDARD", "BEGIN:VTIMEZONE", "END:VTIMEZONE"},
		},
		{
			"Europe/London",
			// European zones change on the last Sunday, not the US second Sunday.
			[]string{"TZID:Europe/London", "BEGIN:VTIMEZONE", "END:VTIMEZONE", "BYMONTH=3;BYDAY=-1SU", "BYMONTH=10;BYDAY=-1SU"},
		},
		{
			"Asia/Tokyo",
			[]string{"TZID:Asia/Tokyo", "BEGIN:VTIMEZONE", "END:VTIMEZONE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.tzName, func(t *testing.T) {
			data, err := generateVTimezone(tt.tzName)
			if err != nil {
				t.Fatalf("generateVTimezone(%q): %v", tt.tzName, err)
			}

			for _, want := range tt.wantIn {
				if !strings.Contains(data, want) {
					t.Errorf("generateVTimezone(%q): missing %q in output:\n%s", tt.tzName, want, data)
				}
			}
		})
	}
}

func TestGenerateVTimezoneUnknown(t *testing.T) {
	t.Parallel()
	_, err := generateVTimezone("Mars/Olympus")
	if err == nil {
		t.Error("expected error for unknown timezone")
	}
}

func TestGenerateVTimezoneNoDST(t *testing.T) {
	t.Parallel()
	// Asia/Tokyo has no DST
	data, err := generateVTimezone("Asia/Tokyo")
	if err != nil {
		t.Fatalf("generateVTimezone(Asia/Tokyo): %v", err)
	}

	if !strings.Contains(data, "BEGIN:VTIMEZONE") {
		t.Error("should contain BEGIN:VTIMEZONE")
	}
	if !strings.Contains(data, "TZID:Asia/Tokyo") {
		t.Error("should contain TZID:Asia/Tokyo")
	}
	// Fixed offset timezones should have STANDARD but no DAYLIGHT
	if !strings.Contains(data, "BEGIN:STANDARD") {
		t.Error("should contain BEGIN:STANDARD for fixed offset timezone")
	}
}

// --- Tests for timezone-aware datetime extraction ---

func TestExtractDTStartWithTZ(t *testing.T) {
	t.Parallel()
	tm, tzID := extractDTStartWithTZ([]byte(timezoneEventNY))
	if tzID != "America/New_York" {
		t.Errorf("TZID = %q, want %q", tzID, "America/New_York")
	}
	// The time values should be Jan 1, 2025, 10:00
	if tm.Year() != 2025 || tm.Month() != 1 || tm.Day() != 1 || tm.Hour() != 10 || tm.Minute() != 0 {
		t.Errorf("extractDTStartWithTZ = %v, want 2025-01-01T10:00:00", tm)
	}
}

func TestExtractDTEndWithTZ(t *testing.T) {
	t.Parallel()
	tm, tzID := extractDTEndWithTZ([]byte(timezoneEventNY))
	if tzID != "America/New_York" {
		t.Errorf("TZID = %q, want %q", tzID, "America/New_York")
	}
	if tm.Year() != 2025 || tm.Month() != 1 || tm.Day() != 1 || tm.Hour() != 11 || tm.Minute() != 0 {
		t.Errorf("extractDTEndWithTZ = %v, want 2025-01-01T11:00:00", tm)
	}
}

func TestExtractDTStartNoTZ(t *testing.T) {
	t.Parallel()
	// UTC event should have no TZID
	tm, tzID := extractDTStartWithTZ([]byte(sampleVEVENT))
	if tzID != "" {
		t.Errorf("TZID = %q, want empty", tzID)
	}
	if tm.Year() != 2025 || tm.Month() != 1 || tm.Day() != 1 || tm.Hour() != 10 {
		t.Errorf("extractDTStartWithTZ = %v, want 2025-01-01T10:00:00Z", tm)
	}
}

// --- Tests for timezone conversion ---

func TestConvertToLocalTime(t *testing.T) {
	t.Parallel()
	// Parse a time that represents 10:00 AM in New York
	srcTime := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)

	// Convert from America/New_York to UTC
	result := convertToLocalTime(srcTime, "America/New_York", "")
	// 10:00 AM EST = 15:00 UTC
	if result.Hour() != 15 {
		t.Errorf("convertToLocalTime(NY->UTC): hour = %d, want 15", result.Hour())
	}

	// Convert from America/New_York to Europe/London
	result2 := convertToLocalTime(srcTime, "America/New_York", "Europe/London")
	// 10:00 AM EST = 15:00 UTC = 15:00 GMT (in January, London is on GMT)
	if result2.Hour() != 15 {
		t.Errorf("convertToLocalTime(NY->London): hour = %d, want 15", result2.Hour())
	}
}

func TestConvertToLocalTimeSummer(t *testing.T) {
	t.Parallel()
	// July 1, 2025, 14:00 in London (BST = UTC+1)
	srcTime := time.Date(2025, 7, 1, 14, 0, 0, 0, time.UTC)

	// Convert from Europe/London to UTC
	result := convertToLocalTime(srcTime, "Europe/London", "")
	// 14:00 BST = 13:00 UTC
	if result.Hour() != 13 {
		t.Errorf("convertToLocalTime(London summer->UTC): hour = %d, want 13", result.Hour())
	}
}

func TestConvertEventToTimezone(t *testing.T) {
	t.Parallel()
	dtStart, dtEnd, isAllDay := convertEventToTimezone([]byte(timezoneEventNY), "Europe/London")

	if isAllDay {
		t.Error("event should not be all-day")
	}

	// 10:00 AM EST (Jan 1) = 15:00 UTC = 15:00 GMT
	if dtStart.Hour() != 15 {
		t.Errorf("dtStart hour = %d, want 15", dtStart.Hour())
	}
	if dtEnd.Hour() != 16 {
		t.Errorf("dtEnd hour = %d, want 16", dtEnd.Hour())
	}
}

func TestGetEventLocalTimes(t *testing.T) {
	t.Parallel()
	start, end := getEventLocalTimes([]byte(timezoneEventNY), "")

	// Converting to UTC: 10:00 AM EST = 15:00 UTC
	if start.Hour() != 15 {
		t.Errorf("start hour = %d, want 15", start.Hour())
	}
	if end.Hour() != 16 {
		t.Errorf("end hour = %d, want 16", end.Hour())
	}
}

// --- Tests for VTIMEZONE extraction from iCalendar ---

func TestExtractVTimezoneFromICal(t *testing.T) {
	t.Parallel()
	vtz, err := extractVTimezoneFromICal([]byte(sampleVTimezoneInCalendar))
	if err != nil {
		t.Fatalf("extractVTimezoneFromICal: %v", err)
	}

	if vtz.TzID != "America/Chicago" {
		t.Errorf("TzID = %q, want %q", vtz.TzID, "America/Chicago")
	}

	if len(vtz.Standard) != 1 {
		t.Errorf("Standard = %d, want 1", len(vtz.Standard))
	}
	if len(vtz.Daylight) != 1 {
		t.Errorf("Daylight = %d, want 1", len(vtz.Daylight))
	}
}

func TestExtractVTimezoneFromICalNotFound(t *testing.T) {
	t.Parallel()
	_, err := extractVTimezoneFromICal([]byte(sampleVEVENT))
	if err == nil {
		t.Error("expected error when no VTIMEZONE is present")
	}
}

// --- Tests for timezone collection ---

func TestCollectTimezonesFromEvent(t *testing.T) {
	t.Parallel()
	tzIDs := collectTimezonesFromEvent([]byte(timezoneEventNY))
	if len(tzIDs) != 1 {
		t.Fatalf("collectTimezonesFromEvent: got %d timezones, want 1", len(tzIDs))
	}
	// TZIDs are uppercased in collectTimezonesFromEvent for dedup purposes
	if tzIDs[0] != "AMERICA/NEW_YORK" {
		t.Errorf("timezone = %q, want %q", tzIDs[0], "AMERICA/NEW_YORK")
	}
}

func TestCollectTimezonesFromEventMultiple(t *testing.T) {
	t.Parallel()
	multiTZEvent := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:multi-tz@example.com
DTSTART;TZID=America/New_York:20250101T100000
DTEND;TZID=America/Los_Angeles:20250101T130000
SUMMARY:Cross-Country Call
END:VEVENT
END:VCALENDAR`

	tzIDs := collectTimezonesFromEvent([]byte(multiTZEvent))
	if len(tzIDs) != 2 {
		t.Fatalf("collectTimezonesFromEvent: got %d timezones, want 2", len(tzIDs))
	}
}

func TestCollectTimezonesFromEventNone(t *testing.T) {
	t.Parallel()
	tzIDs := collectTimezonesFromEvent([]byte(sampleVEVENT))
	if len(tzIDs) != 0 {
		t.Errorf("collectTimezonesFromEvent: got %d timezones, want 0", len(tzIDs))
	}
}

// --- Tests for fixed offset detection ---

func TestIsFixedOffset(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tzName string
		want   bool
	}{
		{"Asia/Tokyo", true},
		{"UTC", true},
		{"America/New_York", false},
		{"Europe/London", false},
	}

	for _, tt := range tests {
		t.Run(tt.tzName, func(t *testing.T) {
			got := isFixedOffset(tt.tzName)
			if got != tt.want {
				t.Errorf("isFixedOffset(%q) = %v, want %v", tt.tzName, got, tt.want)
			}
		})
	}
}

// --- Tests for event time range matching with timezones ---

func TestEventMatchesTimeRangeWithTimezone(t *testing.T) {
	t.Parallel()
	// Event at 10:00 AM EST on Jan 1, 2025 = 15:00 UTC
	// Query range: Jan 1, 2025, 00:00 - 23:59 UTC
	startT, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	endT, _ := time.Parse(time.RFC3339, "2025-01-01T23:59:59Z")

	if !eventMatchesTimeRange([]byte(timezoneEventNY), startT, endT) {
		t.Error("timezone-aware event should match Jan 1 UTC time range")
	}
}

func TestEventMatchesTimeRangeWithTimezoneNoMatch(t *testing.T) {
	t.Parallel()
	// Event at 10:00 AM EST on Jan 1, 2025 = 15:00 UTC
	// Query range: Dec 31, 2024
	startT, _ := time.Parse(time.RFC3339, "2024-12-31T00:00:00Z")
	endT, _ := time.Parse(time.RFC3339, "2024-12-31T23:59:59Z")

	if eventMatchesTimeRange([]byte(timezoneEventNY), startT, endT) {
		t.Error("timezone-aware event should not match Dec 31 UTC time range")
	}
}

// --- Tests for generateOccurrenceICalWithTZ ---

func TestGenerateOccurrenceICalWithTZ(t *testing.T) {
	t.Parallel()
	occTime := time.Date(2025, 1, 3, 10, 0, 0, 0, time.UTC)
	occData := generateOccurrenceICalWithTZ([]byte(dailyEventRRULE), occTime, "America/New_York")

	// Should contain the occurrence time with TZID
	if !strings.Contains(string(occData), "TZID=America/New_York") {
		t.Errorf("occurrence iCal should contain TZID=America/New_York: %s", string(occData))
	}

	// Should contain RECURRENCE-ID with TZID
	if !strings.Contains(string(occData), "RECURRENCE-ID;TZID=America/New_York:") {
		t.Errorf("occurrence iCal should contain RECURRENCE-ID with TZID: %s", string(occData))
	}

	// Should still contain the original UID
	if !strings.Contains(string(occData), "daily-recurring@example.com") {
		t.Errorf("occurrence iCal should contain original UID: %s", string(occData))
	}
}

func TestGenerateOccurrenceICalWithTZPreservesAllDay(t *testing.T) {
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
	occData := generateOccurrenceICalWithTZ([]byte(allDayEvent), occTime, "America/New_York")

	// All-day events should still use VALUE=DATE
	if !strings.Contains(string(occData), "VALUE=DATE") {
		t.Errorf("all-day occurrence should preserve VALUE=DATE: %s", string(occData))
	}
}

// --- Integration test: VTIMEZONE GET endpoint ---

func TestVTimezoneGet(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// GET a known timezone
	r := newRequest("GET", "/dav/alice/timezone/America/New_York", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET VTIMEZONE: status = %d, want %d", w.Code, http.StatusOK)
	}

	if w.Header().Get("Content-Type") != "text/calendar; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", w.Header().Get("Content-Type"), "text/calendar; charset=utf-8")
	}

	body := w.Body.String()
	if !strings.Contains(body, "BEGIN:VTIMEZONE") {
		t.Errorf("VTIMEZONE response missing BEGIN:VTIMEZONE: %s", body)
	}
	if !strings.Contains(body, "TZID:America/New_York") {
		t.Errorf("VTIMEZONE response missing TZID: %s", body)
	}
}

func TestVTimezoneGetNotFound(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// GET an unknown timezone
	r := newRequest("GET", "/dav/alice/timezone/Mars/Olympus", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("GET unknown VTIMEZONE: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestVTimezoneGetCaching(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("GET", "/dav/alice/timezone/America/New_York", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// VTIMEZONE responses should be cacheable
	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl == "" {
		t.Error("VTIMEZONE response should have Cache-Control header")
	}
}

// --- Integration test: timezone-aware calendar query ---

func TestCalendarQueryWithTimezoneEvent(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := t.Context()
	ts.FolderStore().Create(ctx, "alice", "MyCal", "calendar", "")

	// PUT a timezone-aware event
	r := newRequest("PUT", "/dav/alice/MyCal/tz-event.ics", timezoneEventNY)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Query for events on Jan 1, 2025 (UTC)
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <calendar-data/>
 </D:prop>
 <filter>
 <comp-filter name="VCALENDAR">
  <comp-filter name="VEVENT">
   <time-range start="20250101T000000Z" end="20250101T235959Z"/>
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
	// The event at 10:00 AM EST = 15:00 UTC should match
	if !strings.Contains(respBody, "New York Meeting") {
		t.Errorf("calendar-query: body does not contain timezone-aware event: %s", respBody)
	}
}

// --- Tests for formatICalTime ---

func TestFormatICalTime(t *testing.T) {
	t.Parallel()
	tm := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)

	// UTC format
	utc := formatICalTime(tm, "")
	if utc != "20250101T100000Z" {
		t.Errorf("formatICalTime(UTC) = %q, want %q", utc, "20250101T100000Z")
	}

	// Local format (no Z suffix)
	local := formatICalTime(tm, "America/New_York")
	if local != "20250101T100000" {
		t.Errorf("formatICalTime(local) = %q, want %q", local, "20250101T100000")
	}
}

func TestRoundDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input time.Duration
		want  time.Duration
	}{
		{5 * time.Minute, 5 * time.Minute},
		{5*time.Minute + 20*time.Second, 5 * time.Minute},
		{5*time.Minute + 30*time.Second, 6 * time.Minute},
		{5*time.Minute + 45*time.Second, 6 * time.Minute},
		{0, 0},
	}

	for _, tt := range tests {
		got := roundDuration(tt.input)
		if got != tt.want {
			t.Errorf("roundDuration(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
