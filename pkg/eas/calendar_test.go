package eas

import (
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/service"
)

// westEuropeTimeZone is the TIME_ZONE_INFORMATION iOS and Windows send for
// Central European time: bias -60, DST from the last Sunday of March 02:00
// to the last Sunday of October 03:00.
func westEuropeTimeZone() string {
	buffer := make([]byte, timeZoneSize)
	binary.LittleEndian.PutUint32(buffer[0:], uint32(0xFFFFFFC4))
	systemTime{Month: 10, DayOfWeek: 0, Day: 5, Hour: 3}.put(buffer[68:84])
	systemTime{Month: 3, DayOfWeek: 0, Day: 5, Hour: 2}.put(buffer[152:168])
	binary.LittleEndian.PutUint32(buffer[168:], uint32(0xFFFFFFC4))
	return base64.StdEncoding.EncodeToString(buffer)
}

func initialSync(t *testing.T, handler *Handler, collectionID string) string {
	t.Helper()
	first := decodeResponse(t, easRequest(t, handler, "Sync", E(0, "Sync", E(0, "Collections", E(0, "Collection", T(0, "SyncKey", "0"), T(0, "CollectionId", collectionID))))))
	second := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(first, "SyncKey"), 100)))
	return nodeText(second, "SyncKey")
}

// TestSyncAddRecurringMeetingFromClient replays the Sync Add an iOS client
// sends for a new weekly meeting and checks the stored iCalendar, the
// ClientId response, and that the item is not echoed back as an Add.
func TestSyncAddRecurringMeetingFromClient(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	calendarFolder, err := space.GetFolderByPath(t.Context(), access, "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	collectionID := encodeServerID("f:", calendarFolder.ID)
	key := initialSync(t, handler, collectionID)
	start := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC) // 09:00 CET, a Tuesday
	add := E(0, "Add", T(0, "ClientId", "client-1"), E(0, "ApplicationData",
		T(4, "TimeZone", westEuropeTimeZone()), T(4, "AllDayEvent", "0"), T(4, "BusyStatus", "2"),
		T(4, "StartTime", start.Format(easCompactFormat)), T(4, "EndTime", start.Add(time.Hour).Format(easCompactFormat)),
		T(4, "Subject", "Weekly sync"), T(4, "Location", "Room 1"), T(4, "Reminder", "15"),
		T(4, "UID", "client-uid-1@example.test"),
		E(4, "Recurrence", T(4, "Type", "1"), T(4, "Interval", "1"), T(4, "DayOfWeek", strconv.Itoa(1<<int(time.Tuesday))), T(4, "Occurrences", "10")),
		E(17, "Body", T(17, "Type", "1"), T(17, "Data", "Agenda")),
	))
	request := easSyncRequest(collectionID, key, 100)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands", add))
	response := decodeResponse(t, easRequest(t, handler, "Sync", request))
	responses := response.Descendant("Responses")
	if responses == nil || nodeText(responses, "ClientId") != "client-1" || nodeText(responses, "Status") != "1" || nodeText(responses, "ServerId") == "" {
		t.Fatalf("Sync Add response = %#v", response)
	}
	if response.Descendant("Commands") != nil {
		t.Fatalf("client Add echoed back: %#v", response.Descendant("Commands"))
	}
	itemID, err := decodeServerID(nodeText(responses, "ServerId"), "i:")
	if err != nil {
		t.Fatal(err)
	}
	item, err := space.GetItem(t.Context(), access, itemID)
	if err != nil {
		t.Fatal(err)
	}
	ics := string(item.Data)
	for _, want := range []string{"UID:client-uid-1@example.test", "SUMMARY:Weekly sync", "LOCATION:Room 1", "DTSTART;TZID=", "T090000", "RRULE:FREQ=WEEKLY;BYDAY=TU;COUNT=10", "TRIGGER:-PT15M", "DESCRIPTION:Agenda"} {
		if !strings.Contains(ics, want) {
			t.Errorf("stored iCalendar lacks %q:\n%s", want, ics)
		}
	}
	next := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(response, "SyncKey"), 100)))
	if next.Descendant("Commands") != nil {
		t.Fatalf("client Add echoed on the next Sync: %#v", next)
	}
}
