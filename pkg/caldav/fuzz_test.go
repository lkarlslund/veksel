package caldav

import (
	"strings"
	"testing"
	"time"
)

// FuzzVCARD feeds random bytes into vCard parsing functions.
func FuzzVCARD(f *testing.F) {
	// Seed corpus
	seeds := []string{
		"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:abc123\r\nFN:John Doe\r\nEMAIL:john@example.com\r\nEND:VCARD",
		"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:def456\r\nFN:Jane Doe\r\nTEL:+1234567890\r\nEND:VCARD",
		"BEGIN:VCARD\r\nUID:\r\nFN:\r\nEND:VCARD",
		"BEGIN:vcard\r\nUID:test\r\nEND:VCARD",
		"BEGIN:VCARD\r\nUID:test\r\nN:Doe;John\r\nFN:John Doe\r\nEMAIL;TYPE=INTERNET:john@example.com\r\nEND:VCARD",
		// Multi-line vCard property
		"BEGIN:VCARD\r\nUID:test\r\nADR;TYPE=HOME:;;123 Main St\r\n ;Anytown;CA;12345;USA\r\nEND:VCARD",
		// Empty / malformed
		"",
		"BEGIN:VCARD",
		"BEGIN:VCARD\r\nUID:abc123",
		"END:VCARD",
		"\x00\xff\xfe",
		strings.Repeat("BEGIN:VCARD\r\nUID:"+strings.Repeat("A", 1000)+"\r\n", 10),
		// vCard with unusual characters
		"BEGIN:VCARD\r\nUID:test\r\nFN:José García\r\nEND:VCARD",
		// Continuation lines
		"BEGIN:VCARD\r\nUID:test\r\nNOTE:This is a long\r\n note that continues\r\nEND:VCARD",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		data := []byte(input)

		// Exercise containsVCARD
		_ = containsVCARD(data)

		// Exercise extractVCARDUID
		uid := extractVCARDUID(data)
		_ = uid

		// Exercise vCardPropertyMatches with various property names
		for _, prop := range []string{"FN", "EMAIL", "TEL", "UID", "N", "ADR", "NOTE", "ORG", "TITLE"} {
			_ = vCardPropertyMatches(data, prop, "test")
			_ = vCardPropertyMatches(data, prop, "")
		}

		// Exercise lineScanner directly
		scanner := newLineScanner(data)
		for scanner.scan() {
			_ = scanner.line()
		}
	})
}

var fuzzICalSeeds = []string{
	"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//Test//EN\r\nBEGIN:VEVENT\r\nUID:event1\r\nDTSTART:20240101T090000Z\r\nDTEND:20240101T100000Z\r\nSUMMARY:Test Event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
	"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:r1\r\nDTSTART;TZID=Europe/Copenhagen:20240101T090000\r\nDTEND;TZID=Europe/Copenhagen:20240101T100000\r\nRRULE:FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE,2FR;COUNT=20\r\nEXDATE:20240115T080000Z\r\nRDATE:20240301T080000Z,20240302T080000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
	"BEGIN:VEVENT\r\nUID:m\r\nDTSTART;VALUE=DATE:20240131\r\nRRULE:FREQ=MONTHLY;BYMONTHDAY=31,-1,15;UNTIL=20251231T000000Z\r\nEND:VEVENT\r\n",
	"BEGIN:VEVENT\r\nUID:y\r\nDTSTART:20240229T120000Z\r\nRRULE:FREQ=YEARLY;BYMONTH=2,8;COUNT=9\r\nEND:VEVENT\r\n",
	"BEGIN:VEVENT\r\nDTSTART:20240101T000000Z\r\nRRULE:FREQ=DAILY;COUNT=9223372036854775807\r\nEND:VEVENT\r\n",
	"BEGIN:VEVENT\r\nDTSTART:20240101T000000Z\r\nRRULE:FREQ=MONTHLY;COUNT=2000000000;BYMONTHDAY=1\r\nEND:VEVENT\r\n",
	"BEGIN:VEVENT\r\nDTSTART:20240101T000000Z\r\nRRULE:FREQ=WEEKLY;BYDAY=" + strings.Repeat("MO,", 2000) + "TU\r\nEND:VEVENT\r\n",
	"BEGIN:VTODO\r\nUID:t\r\nDUE:20240105T000000Z\r\nEND:VTODO\r\n",
	"BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VTIMEZONE\r\nTZID:Custom\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nRRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nTZNAME:CET\r\nEND:STANDARD\r\nBEGIN:DAYLIGHT\r\nDTSTART:19700329T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\nEND:DAYLIGHT\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nDTSTART;TZID=Custom:20240601T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
	"BEGIN:VEVENT\r\nDTSTART:20240101T000000Z\r\nRRULE:FREQ=DAILY;INTERVAL=-5;UNTIL=garbage\r\nEND:VEVENT",
	"BEGIN:VEVENT\r\nDTSTART:20240101\r\n folded:value\r\nEND:VEVENT",
	"",
	"BEGIN:VCALENDAR",
	"\x00\xff\xfe",
}

// FuzzICalendar feeds arbitrary iCalendar data through the CalDAV property
// extractors, time-range and free-busy matching, timezone handling and
// recurrence expansion. Expansion must stay bounded however large COUNT,
// INTERVAL or the BY* lists are.
func FuzzICalendar(f *testing.F) {
	for _, seed := range fuzzICalSeeds {
		f.Add(seed)
	}
	rangeStart := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	rangeEnd := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, input string) {
		data := []byte(input)
		_ = extractUID(data)
		_ = extractMethod(data)
		_ = extractIsAllDay(data)
		_ = containsVEVENT(data)
		_ = requestedComponents(data)
		_ = eventMatchesTimeRange(data, rangeStart, rangeEnd)
		_ = taskMatchesTimeRange(data, rangeStart, rangeEnd)
		_, _ = extractVTimezoneFromICal(data)
		_, _ = parseVTimezone(data)
		_ = collectTimezonesFromEvent(data)
		_, _, _ = convertEventToTimezone(data, "Europe/Copenhagen")
		_ = hasRecurrence(data)

		occurrences := getEventOccurrences(data, rangeStart, rangeEnd)
		// One year holds at most 366 days of 31 BYMONTHDAY values; RDATEs
		// add at most one occurrence per listed value.
		if limit := 366*62 + len(extractRDateTimes(data)) + 1; len(occurrences) > limit {
			t.Fatalf("expanded %d occurrences in one year from %q", len(occurrences), input)
		}
		if len(occurrences) > 0 {
			_ = generateOccurrenceICal(data, occurrences[0])
		}
		if rule := extractRRule(data); rule != "" {
			_, _ = parseRRule(rule)
		}
	})
}

// FuzzWebDAVXML feeds request bodies into every WebDAV, CalDAV and CardDAV
// XML request parser.
func FuzzWebDAVXML(f *testing.F) {
	for _, seed := range []string{
		`<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><D:resourcetype/></D:prop></D:propfind>`,
		`<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:time-range start="20240101T000000Z" end="20240201T000000Z"/></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>`,
		`<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/></D:prop><D:href>/dav/a.ics</D:href><D:href>/dav/b.ics</D:href></C:calendar-multiget>`,
		`<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:time-range start="20240101T000000Z" end="20240102T000000Z"/></C:free-busy-query>`,
		`<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav"><CR:filter><CR:prop-filter name="EMAIL"><CR:text-match>a@b</CR:text-match></CR:prop-filter></CR:filter></CR:addressbook-query>`,
		`<!DOCTYPE x [<!ENTITY a "aaaa">]><D:propfind xmlns:D="DAV:">&a;</D:propfind>`,
		strings.Repeat("<a>", 2000),
		"",
		"<",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = parsePropfind(strings.NewReader(input))
		_, _ = parseCalendarQuery(strings.NewReader(input))
		_, _ = parseMultiget(strings.NewReader(input))
		_, _ = parseFreeBusyQuery(strings.NewReader(input))
		_, _ = parseScheduleInboxQuery(strings.NewReader(input))
		_, _ = parseScheduleOutboxQuery(strings.NewReader(input))
		if query, err := parseAddressbookQuery(strings.NewReader(input)); err == nil {
			_ = extractCardDAVFilters(query.Filter)
		}
		_, _ = parseCardDAVMultiget(strings.NewReader(input))
		_ = parseDestinationParts(parseDestination(input))
	})
}
