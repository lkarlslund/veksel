package eas

import (
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/service"
)

func TestTimeZoneRulesMatchWindowsDefinition(t *testing.T) {
	copenhagen, err := time.LoadLocation("Europe/Copenhagen")
	if err != nil {
		t.Skip("no time zone database")
	}
	client, ok := decodeTimeZone(westEuropeTimeZone())
	if !ok {
		t.Fatal("client time zone did not decode")
	}
	if derived := timeZoneFor(copenhagen, 2026); !sameRules(derived, client) {
		t.Fatalf("timeZoneFor(Copenhagen) = %#v, want rules of %#v", derived, client)
	}
	if location := matchLocation(client, 2026, copenhagen); location != copenhagen {
		t.Fatalf("matchLocation preferred = %v", location)
	}
	if location := matchLocation(client, 2026, nil); location == nil || !sameRules(timeZoneFor(location, 2026), client) {
		t.Fatalf("matchLocation = %v", location)
	}
	for _, test := range []struct {
		instant time.Time
		offset  int
	}{
		{time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC), 3600},
		{time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC), 7200},
		{time.Date(2026, 3, 29, 0, 59, 0, 0, time.UTC), 3600},
		{time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC), 7200},
		{time.Date(2026, 10, 25, 0, 59, 0, 0, time.UTC), 7200},
		{time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC), 3600},
	} {
		if got := client.offset(test.instant); got != test.offset {
			t.Errorf("offset(%v) = %d, want %d", test.instant, got, test.offset)
		}
	}
	if utc := timeZoneFor(time.UTC, 2026); utc.Bias != 0 || utc.hasDaylight() {
		t.Fatalf("UTC zone = %#v", utc)
	}
}

const recurringMeeting = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n" +
	"BEGIN:VEVENT\r\nUID:standup-1@example.test\r\nDTSTAMP:20261001T080000Z\r\n" +
	"DTSTART;TZID=Europe/Copenhagen:20261005T093000\r\nDTEND;TZID=Europe/Copenhagen:20261005T094500\r\n" +
	"RRULE:FREQ=WEEKLY;BYDAY=MO,WE;UNTIL=20261231T225959Z\r\nEXDATE;TZID=Europe/Copenhagen:20261012T093000\r\n" +
	"SUMMARY:Standup\r\nLOCATION:Room 2\r\nDESCRIPTION:Daily status\r\nCLASS:PRIVATE\r\n" +
	"ORGANIZER;CN=Bob:mailto:bob@example.test\r\n" +
	"ATTENDEE;CN=Alice;PARTSTAT=ACCEPTED;ROLE=REQ-PARTICIPANT:mailto:alice@example.test\r\n" +
	"ATTENDEE;CN=Carol;PARTSTAT=DECLINED;ROLE=OPT-PARTICIPANT:mailto:carol@example.org\r\n" +
	"BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nDESCRIPTION:Reminder\r\nEND:VALARM\r\nEND:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nUID:standup-1@example.test\r\nRECURRENCE-ID;TZID=Europe/Copenhagen:20261014T093000\r\n" +
	"DTSTART;TZID=Europe/Copenhagen:20261014T110000\r\nDTEND;TZID=Europe/Copenhagen:20261014T111500\r\nSUMMARY:Standup (moved)\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

func initialKey(t *testing.T, handler *Handler, folderID string) string {
	t.Helper()
	root := decodeResponse(t, easRequest(t, handler, "Sync", E(0, "Sync", E(0, "Collections", E(0, "Collection", T(0, "SyncKey", "0"), T(0, "CollectionId", encodeServerID("f:", folderID)))))))
	return nodeText(root, "SyncKey")
}

// TestCalendarItemRendersRecurrenceExceptionsAndAttendees checks the
// MS-ASCAL rendering of a received recurring meeting.
func TestCalendarItemRendersRecurrenceExceptionsAndAttendees(t *testing.T) {
	if _, err := time.LoadLocation("Europe/Copenhagen"); err != nil {
		t.Skip("no time zone database")
	}
	handler, space := testEASHandler(t)
	handler.account = &fakeAccount{}
	access := service.UserAccess("alice", "test")
	calendarFolder, _ := space.GetFolderByPath(t.Context(), access, "Calendar")
	if _, err := space.CreateItem(t.Context(), access, calendarFolder.ID, service.ItemInput{Data: []byte(recurringMeeting)}); err != nil {
		t.Fatal(err)
	}
	root := decodeResponse(t, easCall{command: "Sync", version: "14.1", body: easSyncRequest(encodeServerID("f:", calendarFolder.ID), initialKey(t, handler, calendarFolder.ID), 100)}.do(t, handler))
	data := root.Descendant("ApplicationData")
	if data == nil {
		t.Fatalf("Sync = %#v", root)
	}
	tz, ok := decodeTimeZone(childText(data, "TimeZone"))
	if !ok || tz.Bias != -60 || !tz.hasDaylight() {
		t.Fatalf("TimeZone = %#v", tz)
	}
	checks := map[string]string{
		"StartTime": "20261005T073000Z", "EndTime": "20261005T074500Z", "Subject": "Standup", "UID": "standup-1@example.test",
		"Location": "Room 2", "OrganizerEmail": "bob@example.test", "Sensitivity": "2", "BusyStatus": "2",
		"AllDayEvent": "0", "Reminder": "10", "MeetingStatus": "3", "ResponseType": "3",
	}
	for tag, want := range checks {
		if got := childText(data, tag); got != want {
			t.Errorf("%s = %q, want %q", tag, got, want)
		}
	}
	recurrence := data.Child("Recurrence")
	if childText(recurrence, "Type") != "1" || childText(recurrence, "DayOfWeek") != "10" || childText(recurrence, "Until") != "20261231T225959Z" {
		t.Errorf("Recurrence = %#v", recurrence)
	}
	exceptions := data.Child("Exceptions").ChildrenNamed("Exception")
	if len(exceptions) != 2 || childText(exceptions[0], "Deleted") != "1" || childText(exceptions[0], "ExceptionStartTime") != "20261012T073000Z" ||
		childText(exceptions[1], "ExceptionStartTime") != "20261014T073000Z" || childText(exceptions[1], "StartTime") != "20261014T090000Z" || childText(exceptions[1], "Subject") != "Standup (moved)" {
		t.Errorf("Exceptions = %#v", data.Child("Exceptions"))
	}
	var statuses []string
	for _, attendee := range data.Child("Attendees").ChildrenNamed("Attendee") {
		statuses = append(statuses, childText(attendee, "Email")+"="+childText(attendee, "AttendeeStatus")+"/"+childText(attendee, "AttendeeType"))
	}
	if strings.Join(statuses, ",") != "alice@example.test=3/1,carol@example.org=4/2" {
		t.Errorf("Attendees = %v", statuses)
	}
	if !strings.Contains(nodeValue(data.Descendant("Data")), "Daily status") {
		t.Errorf("Body = %#v", data.Descendant("Body"))
	}
}

// TestAllDayEventAndDeletedOccurrenceFromClient replays an all-day event
// sent as local midnight in UTC, then a Change deleting one occurrence.
func TestAllDayEventAndDeletedOccurrenceFromClient(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	calendarFolder, _ := space.GetFolderByPath(t.Context(), access, "Calendar")
	collectionID := encodeServerID("f:", calendarFolder.ID)
	key := initialSync(t, handler, collectionID)
	request := easSyncRequest(collectionID, key, 100)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands", E(0, "Add", T(0, "ClientId", "day-1"), E(0, "ApplicationData",
		T(4, "TimeZone", westEuropeTimeZone()), T(4, "AllDayEvent", "1"),
		T(4, "StartTime", "20261223T230000Z"), T(4, "EndTime", "20261224T230000Z"), T(4, "Subject", "Christmas Eve"),
		E(4, "Recurrence", T(4, "Type", "5"), T(4, "Interval", "1"), T(4, "MonthOfYear", "12"), T(4, "DayOfMonth", "24"), T(4, "Until", "20301223T230000Z")),
	))))
	response := decodeResponse(t, easRequest(t, handler, "Sync", request))
	serverID := nodeText(response.Descendant("Responses"), "ServerId")
	itemID, err := decodeServerID(serverID, "i:")
	if err != nil {
		t.Fatalf("Add = %#v", response)
	}
	item, _ := space.GetItem(t.Context(), access, itemID)
	for _, want := range []string{"DTSTART;VALUE=DATE:20261224", "DTEND;VALUE=DATE:20261225", "RRULE:FREQ=YEARLY;BYMONTH=12;BYMONTHDAY=24;UNTIL=20301224"} {
		if !strings.Contains(string(item.Data), want) {
			t.Errorf("all-day event lacks %q:\n%s", want, item.Data)
		}
	}
	change := easSyncRequest(collectionID, nodeText(response, "SyncKey"), 100)
	change.Descendant("Collection").Children = append(change.Descendant("Collection").Children, E(0, "Commands", E(0, "Change", T(0, "ServerId", serverID), E(0, "ApplicationData",
		T(4, "TimeZone", westEuropeTimeZone()), T(4, "AllDayEvent", "1"),
		T(4, "StartTime", "20261223T230000Z"), T(4, "EndTime", "20261224T230000Z"), T(4, "Subject", "Christmas Eve"),
		E(4, "Recurrence", T(4, "Type", "5"), T(4, "Interval", "1"), T(4, "MonthOfYear", "12"), T(4, "DayOfMonth", "24")),
		E(4, "Exceptions", E(4, "Exception", T(4, "Deleted", "1"), T(4, "ExceptionStartTime", "20271223T230000Z"))),
	))))
	changed := decodeResponse(t, easRequest(t, handler, "Sync", change))
	if changed.Descendant("Responses") != nil || changed.Descendant("Commands") != nil {
		t.Fatalf("Change = %#v", changed)
	}
	item, _ = space.GetItem(t.Context(), access, itemID)
	if !strings.Contains(string(item.Data), "EXDATE;VALUE=DATE:20271224") {
		t.Fatalf("deleted occurrence missing:\n%s", item.Data)
	}
}
