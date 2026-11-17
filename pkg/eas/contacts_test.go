package eas

import (
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/service"
)

const storedContact = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:dana-1\r\nFN:Dana Holm\r\nN:Holm;Dana;;;\r\n" +
	"EMAIL;TYPE=INTERNET:dana@example.org\r\nTEL;TYPE=CELL:+45 11 22 33 44\r\nTEL;TYPE=WORK,VOICE:+45 70 00 00 00\r\n" +
	"ADR;TYPE=HOME:;;Nørregade 1;København;;1165;Danmark\r\nORG:Acme;Sales\r\nTITLE:Seller\r\nBDAY:1990-02-03\r\n" +
	"X-CUSTOM:keep me\r\nNOTE:Met at the fair\r\nEND:VCARD\r\n"

// TestContactRoundTrip renders a stored vCard as MS-ASCNTC and applies a
// client Change without losing properties EAS does not model.
func TestContactRoundTrip(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	contacts, _ := space.GetFolderByPath(t.Context(), access, "Contacts")
	item, err := space.CreateItem(t.Context(), access, contacts.ID, service.ItemInput{Data: []byte(storedContact)})
	if err != nil {
		t.Fatal(err)
	}
	collectionID := encodeServerID("f:", contacts.ID)
	root := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, initialKey(t, handler, contacts.ID), 100)))
	data := root.Descendant("ApplicationData")
	for tag, want := range map[string]string{
		"FirstName": "Dana", "LastName": "Holm", "FileAs": "Dana Holm", "Email1Address": "dana@example.org",
		"MobilePhoneNumber": "+45 11 22 33 44", "BusinessPhoneNumber": "+45 70 00 00 00", "HomeAddressStreet": "Nørregade 1",
		"HomeAddressCity": "København", "HomeAddressPostalCode": "1165", "CompanyName": "Acme", "Department": "Sales",
		"JobTitle": "Seller", "Birthday": "1990-02-03T12:00:00.000Z",
	} {
		if got := childText(data, tag); got != want {
			t.Errorf("%s = %q, want %q", tag, got, want)
		}
	}
	change := easSyncRequest(collectionID, nodeText(root, "SyncKey"), 100)
	change.Descendant("Collection").Children = append(change.Descendant("Collection").Children, E(0, "Commands", E(0, "Change",
		T(0, "ServerId", encodeServerID("i:", item.ID)), E(0, "ApplicationData",
			T(1, "FirstName", "Dana"), T(1, "LastName", "Holm-Berg"), T(1, "FileAs", "Holm-Berg, Dana"),
			T(1, "Email1Address", "\"Dana Holm-Berg\" <dana@example.org>"), T(1, "MobilePhoneNumber", "+45 99 88 77 66"),
			T(1, "Birthday", "1990-02-02T23:00:00.000Z"), E(17, "Body", T(17, "Type", "1"), T(17, "Data", "Updated note"))))))
	changed := decodeResponse(t, easRequest(t, handler, "Sync", change))
	if changed.Descendant("Responses") != nil {
		t.Fatalf("Change = %#v", changed)
	}
	stored, _ := space.GetItem(t.Context(), access, item.ID)
	card := string(stored.Data)
	for _, want := range []string{"UID:dana-1", "X-CUSTOM:keep me", "N:Holm-Berg;Dana;;;", "FN:Dana Holm-Berg", "EMAIL;TYPE=internet:dana@example.org", "+45 99 88 77 66", "BDAY:1990-02-03", "NOTE:Updated note"} {
		if !strings.Contains(card, want) {
			t.Errorf("updated vCard lacks %q:\n%s", want, card)
		}
	}
	if strings.Contains(card, "+45 11 22 33 44") {
		t.Errorf("replaced phone number kept:\n%s", card)
	}
}

// TestTaskRoundTrip renders a VTODO as MS-ASTASK and creates one from a
// client Add.
func TestTaskRoundTrip(t *testing.T) {
	handler, space := testEASHandler(t)
	handler.account = &fakeAccount{}
	access := service.UserAccess("alice", "test")
	tasks, err := space.CreateFolder(t.Context(), access, "Tasks", "tasks", "")
	if err != nil {
		t.Fatal(err)
	}
	folders := folderSyncIDs(t, handler)
	if folders["Tasks"] == nil || nodeText(folders["Tasks"], "Type") != "7" {
		t.Fatalf("tasks folder = %#v", folders["Tasks"])
	}
	collectionID := encodeServerID("f:", tasks.ID)
	key := initialSync(t, handler, collectionID)
	request := easSyncRequest(collectionID, key, 100)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands", E(0, "Add", T(0, "ClientId", "t-1"), E(0, "ApplicationData",
		E(17, "Body", T(17, "Type", "1"), T(17, "Data", "Two copies")), T(9, "Subject", "Print report"), T(9, "Importance", "2"),
		T(9, "UtcDueDate", "2026-11-04T23:00:00.000Z"), T(9, "DueDate", "2026-11-05T00:00:00.000Z"), T(9, "Complete", "0"),
		T(9, "ReminderSet", "1"), T(9, "ReminderTime", "2026-11-05T07:00:00.000Z")))))
	response := decodeResponse(t, easRequest(t, handler, "Sync", request))
	itemID, err := decodeServerID(nodeText(response.Descendant("Responses"), "ServerId"), "i:")
	if err != nil {
		t.Fatalf("Add = %#v", response)
	}
	item, _ := space.GetItem(t.Context(), access, itemID)
	task, err := calendar.ProjectTask(item.Data)
	if err != nil || task.Summary != "Print report" || task.Due != "2026-11-05" || task.Priority != 1 || task.Description != "Two copies" || task.ReminderAt == "" {
		t.Fatalf("stored task = %#v, %v\n%s", task, err, item.Data)
	}
	fetched := decodeResponse(t, easRequest(t, handler, "ItemOperations", E(20, "ItemOperations", E(20, "Fetch", T(20, "Store", "Mailbox"), T(0, "CollectionId", collectionID), T(0, "ServerId", encodeServerID("i:", itemID))))))
	properties := fetched.Descendant("Properties")
	if childText(properties, "Subject") != "Print report" || childText(properties, "DueDate") != "2026-11-05T00:00:00.000Z" || childText(properties, "Importance") != "2" || childText(properties, "Complete") != "0" {
		t.Fatalf("fetched task = %#v", properties)
	}
}
