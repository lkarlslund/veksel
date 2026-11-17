package calendar

import (
	"strings"
	"testing"
	"time"
)

// FuzzDecode feeds untrusted iCalendar bytes (CalDAV uploads, iMIP mail,
// imports) through the guarded decoder and the event, task, iTIP and
// occurrence projections. Nothing may panic, and occurrence expansion stays
// within its per-item cap.
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTAMP:20240101T000000Z\r\nDTSTART;TZID=Europe/Copenhagen:20240101T090000\r\nDTEND;TZID=Europe/Copenhagen:20240101T100000\r\nRRULE:FREQ=DAILY;COUNT=5000\r\nEXDATE;TZID=Europe/Copenhagen:20240102T090000\r\nSUMMARY:Stand-up\r\nORGANIZER;CN=\"Boss, The\":mailto:boss@example.com\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT;DELEGATED-FROM=\"mailto:a@x\",\"mailto:b@x\":mailto:me@example.com\r\nCATEGORIES:Work,Daily\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
		"BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t1\r\nDUE;VALUE=DATE:20240105\r\nRRULE:FREQ=WEEKLY\r\nSTATUS:NEEDS-ACTION\r\nEND:VTODO\r\nEND:VCALENDAR\r\n",
		"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nX;A=\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
		"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nX;A=\"b\"c:v\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
		"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nX;CN=" + strings.Repeat("a", 4000) + ":v\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
		strings.Repeat("BEGIN:X\r\n", 100),
		"0;0=",
		"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\nBEGIN:VCALENDAR\r\n",
		"",
	} {
		f.Add(seed)
	}
	rangeStart := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	rangeEnd := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, input string) {
		data := []byte(input)
		_, _ = Decode(data)
		_, _ = Project(data)
		_, _ = ProjectTask(data)
		_ = IsTask(data)
		_ = ItemCategories(data)
		if message, err := ParseITIP(data); err == nil {
			_, _ = BuildReply(message, "me@example.com", "ACCEPTED")
			_, _ = BuildCancel(message)
		}
		if occurrences, _, err := Occurrences(data, rangeStart, rangeEnd); err == nil && len(occurrences) > maxOccurrencesPerItem+1 {
			t.Fatalf("expanded %d occurrences, over the per-item cap", len(occurrences))
		}
	})
}

// TestDecoderRejectsGoICalPanics pins the go-ical inputs that panic or decode
// in quadratic time without the guarded decoder.
func TestDecoderRejectsGoICalPanics(t *testing.T) {
	for _, input := range []string{
		"0;0=",
		"BEGIN:VCALENDAR\r\nX;A=b\r\nEND:VCALENDAR\r\n",
		"BEGIN:VCALENDAR\r\nX;A=\"b\"c:v\r\nEND:VCALENDAR\r\n",
		"BEGIN:VCALENDAR\r\nX;A=" + strings.Repeat("a", maxParamValueBytes+1) + ":v\r\nEND:VCALENDAR\r\n",
		strings.Repeat("BEGIN:VCALENDAR\r\n", maxComponentDepth+1),
	} {
		if _, err := NewDecoder([]byte(input)).Decode(); err == nil {
			t.Errorf("decoded %.60q", input)
		}
	}
	valid := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nATTENDEE;CN=\"A, B\";ROLE=CHAIR,X:mailto:a@b\r\n folded\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if _, err := NewDecoder([]byte(valid)).Decode(); err != nil {
		t.Fatalf("valid calendar: %v", err)
	}
}
