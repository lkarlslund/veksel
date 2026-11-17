package calendarindex

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	ical "github.com/emersion/go-ical"
)

func TestEncodeVFreeBusyReplyCarriesITIPPartiesFoldedAndEscaped(t *testing.T) {
	start := mustTime(t, "2026-08-18T00:00:00Z")
	end := start.Add(24 * time.Hour)
	long := "mailto:" + strings.Repeat("very-long-local-part.", 5) + "@example.com"
	periods := []BusyPeriod{{Start: start.Add(9 * time.Hour), End: start.Add(10 * time.Hour), Type: BusyType}}
	encoded := EncodeVFreeBusyReply(periods, start, end, start, "req;1,a@test", "-//Test//EN",
		FreeBusyReply{Organizer: "mailto:org@example.com\r\nX-INJECTED:1", Attendee: long})
	for _, line := range strings.Split(strings.TrimSuffix(string(encoded), "\r\n"), "\r\n") {
		if len(line) > 75 {
			t.Fatalf("unfolded %d-octet line %q", len(line), line)
		}
	}
	cal, err := ical.NewDecoder(bytes.NewReader(encoded)).Decode()
	if err != nil {
		t.Fatalf("decode reply: %v\n%s", err, encoded)
	}
	if method, _ := cal.Props.Text(ical.PropMethod); method != "REPLY" {
		t.Fatalf("METHOD = %q, want REPLY", method)
	}
	fb := cal.Children[0]
	if uid, _ := fb.Props.Text(ical.PropUID); uid != "req;1,a@test" {
		t.Errorf("UID = %q, want the request UID round-tripped", uid)
	}
	if got := fb.Props.Get(ical.PropAttendee).Value; got != long {
		t.Errorf("ATTENDEE = %q, want %q", got, long)
	}
	if fb.Props.Get("X-INJECTED") != nil || fb.Props.Get(ical.PropOrganizer).Value != "mailto:org@example.comX-INJECTED:1" {
		t.Errorf("organizer value was not confined to its line:\n%s", encoded)
	}
	if len(fb.Props.Values(ical.PropFreeBusy)) != 1 {
		t.Errorf("FREEBUSY periods = %d, want 1", len(fb.Props.Values(ical.PropFreeBusy)))
	}
}

func TestEncodeVFreeBusyClipsMergesAndTypesPeriods(t *testing.T) {
	start := mustTime(t, "2026-08-18T00:00:00Z")
	end := mustTime(t, "2026-08-19T00:00:00Z")
	stamp := mustTime(t, "2026-08-01T12:00:00Z")
	local := time.FixedZone("CEST", 2*60*60)
	periods := []BusyPeriod{
		// Out of order, overlapping, partly outside the range, and in a
		// non-UTC zone: the output must be sorted, merged, clipped, UTC.
		{Start: mustTime(t, "2026-08-18T14:00:00Z"), End: mustTime(t, "2026-08-18T15:00:00Z"), Type: BusyType},
		{Start: mustTime(t, "2026-08-17T22:00:00Z"), End: mustTime(t, "2026-08-18T01:00:00Z"), Type: BusyType},
		{Start: time.Date(2026, 8, 18, 16, 30, 0, 0, local), End: time.Date(2026, 8, 18, 18, 0, 0, 0, local), Type: BusyType},
		{Start: mustTime(t, "2026-08-18T09:00:00Z"), End: mustTime(t, "2026-08-18T10:00:00Z"), Type: BusyTentativeType},
		{Start: mustTime(t, "2026-08-18T23:00:00Z"), End: mustTime(t, "2026-08-19T02:00:00Z"), Type: ""},
		{Start: mustTime(t, "2026-08-20T09:00:00Z"), End: mustTime(t, "2026-08-20T10:00:00Z"), Type: BusyType},
	}
	encoded := EncodeVFreeBusy(periods, start, end, stamp, "fb-1@test", "-//Test//EN")
	if !bytes.HasSuffix(encoded, []byte("END:VCALENDAR\r\n")) {
		t.Fatalf("encoded object is not CRLF terminated:\n%s", encoded)
	}
	cal, err := ical.NewDecoder(bytes.NewReader(encoded)).Decode()
	if err != nil {
		t.Fatalf("decode VFREEBUSY: %v\n%s", err, encoded)
	}
	if len(cal.Children) != 1 || cal.Children[0].Name != ical.CompFreeBusy {
		t.Fatalf("calendar children = %+v, want one VFREEBUSY", cal.Children)
	}
	if cal.Props.Get(ical.PropDateTimeStamp) != nil || cal.Props.Get(ical.PropUID) != nil {
		t.Fatalf("DTSTAMP/UID must live in the VFREEBUSY, not the VCALENDAR:\n%s", encoded)
	}
	fb := cal.Children[0]
	for name, want := range map[string]string{
		ical.PropUID: "fb-1@test", ical.PropDateTimeStamp: "20260801T120000Z",
		ical.PropDateTimeStart: "20260818T000000Z", ical.PropDateTimeEnd: "20260819T000000Z",
	} {
		if prop := fb.Props.Get(name); prop == nil || prop.Value != want {
			t.Fatalf("%s = %+v, want %s", name, prop, want)
		}
	}
	var got []string
	for _, prop := range fb.Props.Values(ical.PropFreeBusy) {
		got = append(got, prop.Params.Get(ical.ParamFreeBusyType)+" "+prop.Value)
	}
	want := []string{
		"BUSY 20260818T000000Z/20260818T010000Z",
		"BUSY-TENTATIVE 20260818T090000Z/20260818T100000Z",
		"BUSY 20260818T140000Z/20260818T160000Z",
		"BUSY 20260818T230000Z/20260819T000000Z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FREEBUSY = %q, want %q\n%s", got, want, encoded)
	}
}

func TestEncodeVFreeBusyWithoutBusyTime(t *testing.T) {
	start := mustTime(t, "2026-08-18T00:00:00Z")
	encoded := EncodeVFreeBusy(nil, start, start.Add(time.Hour), start, "fb-2@test", "-//Test//EN")
	cal, err := ical.NewDecoder(bytes.NewReader(encoded)).Decode()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cal.Children) != 1 || len(cal.Children[0].Props.Values(ical.PropFreeBusy)) != 0 {
		t.Fatalf("empty range encoded as:\n%s", encoded)
	}
}
