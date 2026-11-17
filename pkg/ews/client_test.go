package ews

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// TestGetFolderAnswersEachDistinguishedFolder replays the batched GetFolder
// Mac Mail sends at account setup. A folder the account lacks (Outbox) once
// failed the whole request with a SOAP fault; each ID now gets its own
// response message, in order.
func TestGetFolderAnswersEachDistinguishedFolder(t *testing.T) {
	handler, _ := testHandler(t)
	response := ewsRequest(t, handler, `<m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds>`+
		`<t:DistinguishedFolderId Id="msgfolderroot"/><t:DistinguishedFolderId Id="inbox"/><t:DistinguishedFolderId Id="outbox"/>`+
		`<t:DistinguishedFolderId Id="sentitems"/><t:DistinguishedFolderId Id="deleteditems"/><t:DistinguishedFolderId Id="calendar"/></m:FolderIds></m:GetFolder>`)
	body := response.Body.String()
	if response.Code != 200 || strings.Contains(body, "Fault") || strings.Count(body, "<m:GetFolderResponseMessage ") != 6 {
		t.Fatalf("GetFolder = %d %s", response.Code, body)
	}
	messages := strings.Split(body, "<m:GetFolderResponseMessage ")[1:]
	for index, want := range []string{"Top of Information Store", "INBOX", "ErrorFolderNotFound", "Sent", "Trash", "<t:CalendarFolder>"} {
		if !strings.Contains(messages[index], want) {
			t.Errorf("message %d lacks %q: %s", index, want, messages[index])
		}
	}
	if !strings.Contains(messages[1], `<t:ParentFolderId Id="`+encodeID("f:", rootFolderID)+`"/>`) || !strings.Contains(messages[1], "<t:UnreadCount>0</t:UnreadCount>") {
		t.Errorf("INBOX lacks parent or counts: %s", messages[1])
	}
}

// TestFolderHierarchyHidesInternalFolders keeps Files, Sieve, scheduling,
// saved-search and template folders out of the EWS hierarchy.
func TestFolderHierarchyHidesInternalFolders(t *testing.T) {
	handler, _ := testHandler(t)
	for _, operation := range []string{
		`<m:SyncFolderHierarchy><m:FolderShape><t:BaseShape>AllProperties</t:BaseShape></m:FolderShape></m:SyncFolderHierarchy>`,
		`<m:FindFolder Traversal="Deep"><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape><m:ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/></m:ParentFolderIds></m:FindFolder>`,
	} {
		body := ewsRequest(t, handler, operation).Body.String()
		for _, hidden := range []string{"Sieve scripts", "schedule-inbox", "Saved searches", "Message templates", ">Files<"} {
			if strings.Contains(body, hidden) {
				t.Errorf("hierarchy exposes %q: %s", hidden, body)
			}
		}
		if !strings.Contains(body, "INBOX") || !strings.Contains(body, "<t:ContactsFolder>") {
			t.Errorf("hierarchy lacks mail or contacts folders: %s", body)
		}
	}
}

// TestUpdateItemMarksReadInBatch replays how Mac Mail marks several
// messages read: one UpdateItem with an ItemChange per message setting
// message:IsRead. Only one change, and no IsRead, used to be accepted.
func TestUpdateItemMarksReadInBatch(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	var changes strings.Builder
	var items []model.Item
	for _, subject := range []string{"one", "two"} {
		item, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("From: Bob <bob@example.test>\r\nTo: alice@example.test\r\nSubject: " + subject + "\r\n\r\nbody")})
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, item)
		changes.WriteString(`<t:ItemChange><t:ItemId Id="` + encodeID("i:", item.ID) + `" ChangeKey="` + strconv.FormatUint(item.ModSeq, 10) + `"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="message:IsRead"/><t:Message><t:IsRead>true</t:IsRead></t:Message></t:SetItemField></t:Updates></t:ItemChange>`)
	}
	missing := `<t:ItemChange><t:ItemId Id="` + encodeID("i:", "gone") + `" ChangeKey="1"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="message:IsRead"/><t:Message><t:IsRead>true</t:IsRead></t:Message></t:SetItemField></t:Updates></t:ItemChange>`
	response := ewsRequest(t, handler, `<m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AutoResolve"><m:ItemChanges>`+changes.String()+missing+`</m:ItemChanges></m:UpdateItem>`)
	body := response.Body.String()
	if strings.Count(body, `ResponseClass="Success"`) != 2 || strings.Count(body, `ResponseClass="Error"`) != 1 || !strings.Contains(body, "ErrorItemNotFound") {
		t.Fatalf("UpdateItem = %s", body)
	}
	for _, item := range items {
		stored, _ := space.GetItem(t.Context(), access, item.ID)
		if !hasFlag(stored.Flags, model.FlagSeen) {
			t.Fatalf("item %s not marked read", item.ID)
		}
	}
	get := ewsRequest(t, handler, `<m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="message:IsRead"/><t:FieldURI FieldURI="message:From"/></t:AdditionalProperties></m:ItemShape><m:ItemIds><t:ItemId Id="`+encodeID("i:", items[0].ID)+`"/></m:ItemIds></m:GetItem>`).Body.String()
	for _, want := range []string{"<t:IsRead>true</t:IsRead>", "<t:Name>Bob</t:Name><t:EmailAddress>bob@example.test</t:EmailAddress>", `<t:ParentFolderId Id="` + encodeID("f:", inbox.ID) + `"/>`, "<t:ItemClass>IPM.Note</t:ItemClass>"} {
		if !strings.Contains(get, want) {
			t.Errorf("GetItem lacks %q: %s", want, get)
		}
	}
	if strings.Contains(get, "<t:MimeContent") {
		t.Errorf("IdOnly GetItem returned MimeContent: %s", get)
	}
}

// TestGetUserAvailabilityRendersLocalFreeBusy replays the scheduling
// assistant request of Outlook for Mac: a W. Europe time zone, a local time
// window, and a merged view.
func TestGetUserAvailabilityRendersLocalFreeBusy(t *testing.T) {
	handler, _ := testHandler(t)
	var gotStart, gotEnd time.Time
	handler.freeBusy = func(_ context.Context, access service.AccessContext, address string, start, end time.Time) ([]BusyPeriod, bool, error) {
		gotStart, gotEnd = start, end
		if address != "bob@example.test" || access.Actor.ID != "alice" {
			return nil, false, nil
		}
		return []BusyPeriod{{Start: time.Date(2026, 7, 6, 7, 0, 0, 0, time.UTC), End: time.Date(2026, 7, 6, 8, 0, 0, 0, time.UTC)}}, true, nil
	}
	request := `<m:GetUserAvailabilityRequest><t:TimeZone><t:Bias>-60</t:Bias><t:StandardTime><t:Bias>0</t:Bias><t:Time>03:00:00</t:Time><t:DayOrder>5</t:DayOrder><t:Month>10</t:Month><t:DayOfWeek>Sunday</t:DayOfWeek></t:StandardTime><t:DaylightTime><t:Bias>-60</t:Bias><t:Time>02:00:00</t:Time><t:DayOrder>5</t:DayOrder><t:Month>3</t:Month><t:DayOfWeek>Sunday</t:DayOfWeek></t:DaylightTime></t:TimeZone>` +
		`<m:MailboxDataArray><t:MailboxData><t:Email><t:Address>bob@example.test</t:Address></t:Email><t:AttendeeType>Required</t:AttendeeType></t:MailboxData><t:MailboxData><t:Email><t:Address>stranger@example.org</t:Address></t:Email><t:AttendeeType>Required</t:AttendeeType></t:MailboxData></m:MailboxDataArray>` +
		`<t:FreeBusyViewOptions><t:TimeWindow><t:StartTime>2026-07-06T08:00:00</t:StartTime><t:EndTime>2026-07-06T11:00:00</t:EndTime></t:TimeWindow><t:MergedFreeBusyIntervalInMinutes>60</t:MergedFreeBusyIntervalInMinutes><t:RequestedView>DetailedMerged</t:RequestedView></t:FreeBusyViewOptions></m:GetUserAvailabilityRequest>`
	body := ewsRequest(t, handler, request).Body.String()
	if !gotStart.Equal(time.Date(2026, 7, 6, 6, 0, 0, 0, time.UTC)) || !gotEnd.Equal(time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("window = %v - %v", gotStart, gotEnd)
	}
	for _, want := range []string{"<t:MergedFreeBusy>020</t:MergedFreeBusy>", "<t:StartTime>2026-07-06T09:00:00</t:StartTime>", "<t:BusyType>Busy</t:BusyType>", "ErrorNoFreeBusyAccess"} {
		if !strings.Contains(body, want) {
			t.Errorf("availability lacks %q: %s", want, body)
		}
	}
}

// TestResolveNamesSearchesDirectoryAndContacts replays recipient
// completion.
func TestResolveNamesSearchesDirectoryAndContacts(t *testing.T) {
	handler, space := testHandler(t)
	handler.directory = func(_ context.Context, _ string, query string, _ int) ([]DirectoryEntry, error) {
		if strings.Contains("bob builder", strings.ToLower(query)) {
			return []DirectoryEntry{{Name: "Bob Builder", Address: "bob@example.test"}}, nil
		}
		return nil, nil
	}
	access := service.UserAccess("alice", "test")
	contacts, _ := space.GetFolderByPath(t.Context(), access, "Contacts")
	if _, err := space.CreateItem(t.Context(), access, contacts.ID, service.ItemInput{Data: []byte("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bobby Tables\r\nEMAIL:bobby@example.org\r\nEND:VCARD\r\n")}); err != nil {
		t.Fatal(err)
	}
	body := ewsRequest(t, handler, `<m:ResolveNames ReturnFullContactData="false"><m:UnresolvedEntry>bob</m:UnresolvedEntry></m:ResolveNames>`).Body.String()
	if !strings.Contains(body, "ErrorNameResolutionMultipleResults") || !strings.Contains(body, "<t:EmailAddress>bob@example.test</t:EmailAddress>") || !strings.Contains(body, "<t:EmailAddress>bobby@example.org</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Contact") {
		t.Fatalf("ResolveNames = %s", body)
	}
	none := ewsRequest(t, handler, `<m:ResolveNames ReturnFullContactData="false"><m:UnresolvedEntry>zzz</m:UnresolvedEntry></m:ResolveNames>`).Body.String()
	if !strings.Contains(none, "ErrorNameResolutionNoResults") {
		t.Fatalf("ResolveNames without matches = %s", none)
	}
}

// TestDeleteItemReportsMissingItemPerMessage keeps one stale ID from
// failing a batch delete.
func TestDeleteItemReportsMissingItemPerMessage(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	item, _ := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: x\r\n\r\n")})
	body := ewsRequest(t, handler, `<m:DeleteItem DeleteType="MoveToDeletedItems"><m:ItemIds><t:ItemId Id="`+encodeID("i:", "gone")+`"/><t:ItemId Id="`+encodeID("i:", item.ID)+`"/></m:ItemIds></m:DeleteItem>`).Body.String()
	if strings.Contains(body, "Fault") || strings.Count(body, "<m:DeleteItemResponseMessage ") != 2 || !strings.Contains(body, `ResponseClass="Success"`) {
		t.Fatalf("DeleteItem = %s", body)
	}
	if _, err := space.GetItem(t.Context(), access, item.ID); err == nil {
		if stored, _ := space.GetItem(t.Context(), access, item.ID); stored.TrashedAt.IsZero() && stored.FolderID == inbox.ID {
			t.Fatal("existing item was not deleted")
		}
	}
}
