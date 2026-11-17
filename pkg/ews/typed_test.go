package ews

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// typedFixture is an EWS handler with account profiles, a recording
// meeting responder and an in-memory vacation responder.
type typedFixture struct {
	handler *Handler
	space   *service.FolderSpaceService
	mu      sync.Mutex
	answers []string
	oof     OutOfOffice
}

const (
	outlookHeader  = `<t:RequestServerVersion Version="Exchange2010_SP2"/><t:TimeZoneContext><t:TimeZoneDefinition Id="W. Europe Standard Time"/></t:TimeZoneContext>`
	macMail2007    = `<t:RequestServerVersion Version="Exchange2007_SP1"/>`
	outlookVersion = `<t:RequestServerVersion Version="Exchange2010_SP2"/>`
)

func newTypedFixture(t *testing.T) *typedFixture {
	t.Helper()
	base, space := testHandler(t)
	f := &typedFixture{space: space}
	handler, err := New(Config{
		Space: space, Authenticate: base.authenticate,
		Profile: func(_ context.Context, userID string) (Profile, error) {
			return Profile{DisplayName: strings.ToUpper(userID[:1]) + userID[1:], Addresses: []string{userID + "@example.com"}, TimeZone: "Europe/Berlin"}, nil
		},
		Respond: func(_ context.Context, _ service.AccessContext, itemID, partStat string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.answers = append(f.answers, itemID+":"+partStat)
			return nil
		},
		OutOfOffice: func(context.Context, string) (OutOfOffice, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.oof, nil
		},
		SetOutOfOffice: func(_ context.Context, _ string, oof OutOfOffice) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.oof = oof
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.handler = handler
	return f
}

func (f *typedFixture) call(t *testing.T, header, operation string) string {
	t.Helper()
	body := `<s:Envelope xmlns:s="` + soapNS + `" xmlns:m="` + msgNS + `" xmlns:t="` + typeNS + `"><s:Header>` + header + `</s:Header><s:Body>` + operation + `</s:Body></s:Envelope>`
	request := httptest.NewRequest(http.MethodPost, "/EWS/Exchange.asmx", strings.NewReader(body))
	request.SetBasicAuth("alice", "secret")
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	text := recorder.Body.String()
	if recorder.Code != http.StatusOK || strings.Contains(text, "Fault>") {
		t.Fatalf("status=%d body=%s", recorder.Code, text)
	}
	return text
}

func (f *typedFixture) folder(t *testing.T, path string) model.Folder {
	t.Helper()
	folder, err := f.space.GetFolderByPath(t.Context(), service.UserAccess("alice", "test"), path)
	if err != nil {
		t.Fatal(err)
	}
	return folder
}

func (f *typedFixture) only(t *testing.T, path string) model.Item {
	t.Helper()
	items, err := f.space.ListItems(t.Context(), service.UserAccess("alice", "test"), f.folder(t, path).ID, service.ItemQuery{})
	if err != nil || len(items) != 1 {
		t.Fatalf("%s holds %d items (%v), want 1", path, len(items), err)
	}
	return items[0]
}

var itemIDPattern = regexp.MustCompile(`<t:ItemId Id="([^"]+)" ChangeKey="(\d+)"/>`)

func itemIDs2(t *testing.T, body string) [][]string {
	t.Helper()
	matches := itemIDPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		t.Fatalf("no ItemId in %s", body)
	}
	return matches
}

func requireAll(t *testing.T, label, text string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("%s lacks %q:\n%s", label, want, text)
		}
	}
}

// outlookMeeting is the CreateItem Outlook for Mac sends for a recurring
// meeting: local times with StartTimeZone, an HTML body and attendees.
const outlookMeeting = `<m:CreateItem SendMeetingInvitations="SendToAllAndSaveCopy"><m:SavedItemFolderId><t:DistinguishedFolderId Id="calendar"/></m:SavedItemFolderId><m:Items><t:CalendarItem>` +
	`<t:Subject>Weekly sync</t:Subject><t:Body BodyType="HTML">&lt;p&gt;Agenda &amp;amp; notes&lt;/p&gt;</t:Body><t:Categories><t:String>Work</t:String></t:Categories>` +
	`<t:ReminderIsSet>true</t:ReminderIsSet><t:ReminderMinutesBeforeStart>10</t:ReminderMinutesBeforeStart>` +
	`<t:Start>2026-11-02T10:00:00</t:Start><t:End>2026-11-02T10:30:00</t:End><t:IsAllDayEvent>false</t:IsAllDayEvent><t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus><t:Location>Room 4</t:Location>` +
	`<t:RequiredAttendees><t:Attendee><t:Mailbox><t:Name>Bob</t:Name><t:EmailAddress>bob@example.com</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType></t:Mailbox></t:Attendee></t:RequiredAttendees>` +
	`<t:OptionalAttendees><t:Attendee><t:Mailbox><t:EmailAddress>carol@remote.test</t:EmailAddress></t:Mailbox></t:Attendee></t:OptionalAttendees>` +
	`<t:Recurrence><t:WeeklyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>Monday</t:DaysOfWeek></t:WeeklyRecurrence><t:NumberedRecurrence><t:StartDate>2026-11-02</t:StartDate><t:NumberOfOccurrences>5</t:NumberOfOccurrences></t:NumberedRecurrence></t:Recurrence>` +
	`<t:StartTimeZone Id="W. Europe Standard Time"/><t:EndTimeZone Id="W. Europe Standard Time"/>` +
	`</t:CalendarItem></m:Items></m:CreateItem>`

func TestCreateItemStoresOutlookMeetingAsICalendar(t *testing.T) {
	f := newTypedFixture(t)
	body := f.call(t, outlookVersion, outlookMeeting)
	requireAll(t, "CreateItem response", body, `<m:Items><t:CalendarItem><t:ItemId Id="`)
	stored := string(f.only(t, "Calendar").Data)
	for _, want := range []string{
		"DTSTART;TZID=Europe/Berlin:20261102T100000", "DTEND;TZID=Europe/Berlin:20261102T103000",
		"RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=5", "SUMMARY:Weekly sync", "LOCATION:Room 4", "Agenda & notes",
		"ORGANIZER;CN=Alice:mailto:alice@example.com", "mailto:bob@example.com", "OPT-PARTICIPANT", "TRIGGER:-PT10M",
		"BEGIN:VTIMEZONE", "CATEGORIES:Work",
	} {
		if !strings.Contains(stored, want) {
			t.Errorf("stored event lacks %q:\n%s", want, stored)
		}
	}
}

func TestFindItemCalendarViewExpandsAndPagesOccurrences(t *testing.T) {
	f := newTypedFixture(t)
	f.call(t, outlookVersion, outlookMeeting)
	// The macOS Calendar asks for one window at a time with an IdOnly shape
	// and the calendar properties it shows.
	view := func(max string) string {
		return f.call(t, outlookHeader, `<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:Subject"/><t:FieldURI FieldURI="calendar:Start"/><t:FieldURI FieldURI="calendar:End"/><t:FieldURI FieldURI="calendar:IsRecurring"/><t:FieldURI FieldURI="calendar:CalendarItemType"/></t:AdditionalProperties></m:ItemShape>`+
			`<m:CalendarView MaxEntriesReturned="`+max+`" StartDate="2026-11-01T00:00:00Z" EndDate="2026-12-31T00:00:00Z"/><m:ParentFolderIds><t:DistinguishedFolderId Id="calendar"/></m:ParentFolderIds></m:FindItem>`)
	}
	paged := view("3")
	requireAll(t, "paged view", paged, `TotalItemsInView="3" IncludesLastItemInRange="false"`, `<t:Start>2026-11-02T09:00:00Z</t:Start>`, `<t:Start>2026-11-16T09:00:00Z</t:Start>`)
	if strings.Contains(paged, "2026-11-23T09:00:00Z") {
		t.Fatalf("paged view returned more than MaxEntriesReturned:\n%s", paged)
	}
	full := view("50")
	requireAll(t, "full view", full, `TotalItemsInView="5" IncludesLastItemInRange="true"`, `<t:CalendarItemType>Occurrence</t:CalendarItemType>`, `<t:Start>2026-11-30T09:00:00Z</t:Start>`, `<t:IsRecurring>true</t:IsRecurring>`)
	ids := itemIDs2(t, full)
	occurrence := f.call(t, outlookVersion, `<m:GetItem><m:ItemShape><t:BaseShape>AllProperties</t:BaseShape></m:ItemShape><m:ItemIds><t:ItemId Id="`+ids[1][1]+`"/></m:ItemIds></m:GetItem>`)
	requireAll(t, "occurrence", occurrence, `<t:CalendarItemType>Occurrence</t:CalendarItemType>`, `<t:OriginalStart>2026-11-09T09:00:00Z</t:OriginalStart>`, `<t:RecurrenceId>2026-11-09T09:00:00Z</t:RecurrenceId>`)
}

func TestOccurrencesUpdateAndDeleteThroughOccurrenceItemID(t *testing.T) {
	f := newTypedFixture(t)
	created := f.call(t, outlookVersion, outlookMeeting)
	master := itemIDs2(t, created)[0]
	// Outlook moves the second instance by an hour and cancels the third.
	update := `<m:UpdateItem ConflictResolution="AutoResolve" SendMeetingInvitationsOrCancellations="SendToAllAndSaveCopy"><m:ItemChanges><t:ItemChange><t:OccurrenceItemId RecurringMasterId="` + master[1] + `" InstanceIndex="2"/><t:Updates>` +
		`<t:SetItemField><t:FieldURI FieldURI="item:Subject"/><t:CalendarItem><t:Subject>Moved sync</t:Subject></t:CalendarItem></t:SetItemField>` +
		`<t:SetItemField><t:FieldURI FieldURI="calendar:Start"/><t:CalendarItem><t:Start>2026-11-09T10:00:00Z</t:Start></t:CalendarItem></t:SetItemField>` +
		`<t:SetItemField><t:FieldURI FieldURI="calendar:End"/><t:CalendarItem><t:End>2026-11-09T10:30:00Z</t:End></t:CalendarItem></t:SetItemField>` +
		`<t:SetItemField><t:ExtendedFieldURI PropertySetId="00062008-0000-0000-c000-000000000046" PropertyId="34070" PropertyType="Boolean"/><t:CalendarItem><t:ExtendedProperty/></t:CalendarItem></t:SetItemField>` +
		`</t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>`
	requireAll(t, "occurrence update", f.call(t, outlookVersion, update), `ResponseClass="Success"`)
	requireAll(t, "occurrence delete", f.call(t, outlookVersion, `<m:DeleteItem DeleteType="MoveToDeletedItems" SendMeetingCancellations="SendToAllAndSaveCopy"><m:ItemIds><t:OccurrenceItemId RecurringMasterId="`+master[1]+`" InstanceIndex="3"/></m:ItemIds></m:DeleteItem>`), `ResponseClass="Success"`)
	stored := string(f.only(t, "Calendar").Data)
	requireAll(t, "stored series", stored, "RECURRENCE-ID;TZID=Europe/Berlin:20261109T100000", "SUMMARY:Moved sync", "EXDATE;TZID=Europe/Berlin:20261116T100000", "SEQUENCE:2")
	got := f.call(t, outlookVersion, `<m:GetItem><m:ItemShape><t:BaseShape>AllProperties</t:BaseShape></m:ItemShape><m:ItemIds><t:ItemId Id="`+master[1]+`"/></m:ItemIds></m:GetItem>`)
	requireAll(t, "master", got, `<t:CalendarItemType>RecurringMaster</t:CalendarItemType>`,
		`<t:WeeklyRecurrence><t:Interval>1</t:Interval><t:DaysOfWeek>Monday</t:DaysOfWeek></t:WeeklyRecurrence><t:NumberedRecurrence><t:StartDate>2026-11-02</t:StartDate><t:NumberOfOccurrences>5</t:NumberOfOccurrences></t:NumberedRecurrence>`,
		`<t:ModifiedOccurrences><t:Occurrence>`, `<t:Start>2026-11-09T10:00:00Z</t:Start>`, `<t:OriginalStart>2026-11-09T09:00:00Z</t:OriginalStart>`,
		`<t:DeletedOccurrences><t:DeletedOccurrence><t:Start>2026-11-16T09:00:00Z</t:Start></t:DeletedOccurrence></t:DeletedOccurrences>`,
		`<t:StartTimeZone Id="W. Europe Standard Time"`, `<t:MyResponseType>Organizer</t:MyResponseType>`, `<t:IsMeeting>true</t:IsMeeting>`)
}

const invitation = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:invite-1\r\nDTSTAMP:20261001T080000Z\r\nDTSTART:20261105T130000Z\r\nDTEND:20261105T140000Z\r\nSUMMARY:Budget\r\n" +
	"ORGANIZER;CN=Bob:mailto:bob@example.com\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:alice@example.com\r\nATTENDEE;PARTSTAT=ACCEPTED;ROLE=OPT-PARTICIPANT:mailto:dave@remote.test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

func TestGetItemPresentsInvitationAndAcceptItemAnswersIt(t *testing.T) {
	f := newTypedFixture(t)
	access := service.UserAccess("alice", "test")
	item, err := f.space.CreateItem(t.Context(), access, f.folder(t, "Calendar").ID, service.ItemInput{Data: []byte(invitation)})
	if err != nil {
		t.Fatal(err)
	}
	got := f.call(t, macMail2007, `<m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="calendar:MyResponseType"/><t:FieldURI FieldURI="calendar:Organizer"/><t:FieldURI FieldURI="item:ResponseObjects"/></t:AdditionalProperties></m:ItemShape><m:ItemIds><t:ItemId Id="`+encodeID("i:", item.ID)+`"/></m:ItemIds></m:GetItem>`)
	requireAll(t, "invitation", got, `<t:MyResponseType>NoResponseReceived</t:MyResponseType>`, `<t:IsResponseRequested>true</t:IsResponseRequested>`,
		`<t:ResponseObjects><t:AcceptItem/><t:TentativelyAcceptItem/><t:DeclineItem/>`, `<t:Organizer><t:Mailbox><t:Name>Bob</t:Name><t:EmailAddress>bob@example.com</t:EmailAddress>`,
		`<t:OptionalAttendees><t:Attendee><t:Mailbox><t:EmailAddress>dave@remote.test</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType></t:Mailbox><t:ResponseType>Accept</t:ResponseType>`,
		`<t:MeetingTimeZone TimeZoneName="UTC">`, `<t:AppointmentState>3</t:AppointmentState>`)
	if strings.Contains(got, "StartTimeZone") {
		t.Fatalf("Exchange 2007 response carries StartTimeZone:\n%s", got)
	}
	f.call(t, outlookVersion, `<m:CreateItem MessageDisposition="SendAndSaveCopy"><m:Items><t:AcceptItem><t:ReferenceItemId Id="`+encodeID("i:", item.ID)+`"/></t:AcceptItem></m:Items></m:CreateItem>`)
	if len(f.answers) != 1 || f.answers[0] != item.ID+":ACCEPTED" {
		t.Fatalf("answers = %v", f.answers)
	}
}

func TestExchange2007MeetingTimeZoneAndAllDayEvents(t *testing.T) {
	f := newTypedFixture(t)
	// Mac Mail (Exchange 2007 SP1) describes the zone by its rules only.
	pacific := `<t:MeetingTimeZone><t:BaseOffset>PT8H</t:BaseOffset><t:Standard><t:Offset>PT0M</t:Offset><t:RelativeYearlyRecurrence><t:DaysOfWeek>Sunday</t:DaysOfWeek><t:DayOfWeekIndex>First</t:DayOfWeekIndex><t:Month>November</t:Month></t:RelativeYearlyRecurrence><t:Time>02:00:00</t:Time></t:Standard>` +
		`<t:Daylight><t:Offset>-PT1H</t:Offset><t:RelativeYearlyRecurrence><t:DaysOfWeek>Sunday</t:DaysOfWeek><t:DayOfWeekIndex>Second</t:DayOfWeekIndex><t:Month>March</t:Month></t:RelativeYearlyRecurrence><t:Time>02:00:00</t:Time></t:Daylight></t:MeetingTimeZone>`
	f.call(t, macMail2007, `<m:CreateItem SendMeetingInvitations="SendToNone"><m:Items><t:CalendarItem><t:Subject>Call</t:Subject><t:Start>2026-07-01T09:00:00</t:Start><t:End>2026-07-01T10:00:00</t:End>`+pacific+`</t:CalendarItem></m:Items></m:CreateItem>`)
	f.call(t, outlookHeader, `<m:CreateItem SendMeetingInvitations="SendToNone"><m:Items><t:CalendarItem><t:Subject>Holiday</t:Subject><t:Start>2026-12-24T00:00:00</t:Start><t:End>2026-12-25T00:00:00</t:End><t:IsAllDayEvent>true</t:IsAllDayEvent></t:CalendarItem></m:Items></m:CreateItem>`)
	items, err := f.space.ListItems(t.Context(), service.UserAccess("alice", "test"), f.folder(t, "Calendar").ID, service.ItemQuery{})
	if err != nil || len(items) != 2 {
		t.Fatalf("calendar holds %d items (%v)", len(items), err)
	}
	var call, holiday string
	for _, item := range items {
		if strings.Contains(string(item.Data), "Holiday") {
			holiday = string(item.Data)
		} else {
			call = string(item.Data)
		}
	}
	// 09:00 Pacific daylight time is 16:00 UTC; the event is stored in the
	// account zone with no IANA name known for the rules.
	if !strings.Contains(call, "DTSTART;TZID=Europe/Berlin:20260701T180000") {
		t.Errorf("rule-based zone stored wrongly:\n%s", call)
	}
	requireAll(t, "all-day event", holiday, "DTSTART;VALUE=DATE:20261224", "DTEND;VALUE=DATE:20261225")
	got := f.call(t, outlookHeader, `<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:CalendarView StartDate="2026-12-20T00:00:00Z" EndDate="2026-12-31T00:00:00Z"/><m:ParentFolderIds><t:DistinguishedFolderId Id="calendar"/></m:ParentFolderIds></m:FindItem>`)
	requireAll(t, "all-day view", got, `<t:Start>2026-12-23T23:00:00Z</t:Start><t:End>2026-12-24T23:00:00Z</t:End>`, `<t:IsAllDayEvent>true</t:IsAllDayEvent>`)
}

func TestContactsRoundTripIndexedFieldsAndPhoto(t *testing.T) {
	f := newTypedFixture(t)
	create := `<m:CreateItem><m:SavedItemFolderId><t:DistinguishedFolderId Id="contacts"/></m:SavedItemFolderId><m:Items><t:Contact>` +
		`<t:FileAs>Doe, Jane</t:FileAs><t:GivenName>Jane</t:GivenName><t:CompanyName>Acme</t:CompanyName>` +
		`<t:EmailAddresses><t:Entry Key="EmailAddress1">jane@acme.test</t:Entry><t:Entry Key="EmailAddress2">SMTP:jd@home.test</t:Entry></t:EmailAddresses>` +
		`<t:PhysicalAddresses><t:Entry Key="Business"><t:Street>1 Main St</t:Street><t:City>Springfield</t:City><t:CountryOrRegion>USA</t:CountryOrRegion><t:PostalCode>12345</t:PostalCode></t:Entry></t:PhysicalAddresses>` +
		`<t:PhoneNumbers><t:Entry Key="MobilePhone">+1 555 0100</t:Entry><t:Entry Key="BusinessPhone">+1 555 0101</t:Entry></t:PhoneNumbers>` +
		`<t:Birthday>1980-05-17T00:00:00Z</t:Birthday><t:Department>R&amp;D</t:Department><t:JobTitle>Engineer</t:JobTitle><t:Surname>Doe</t:Surname>` +
		`</t:Contact></m:Items></m:CreateItem>`
	id := itemIDs2(t, f.call(t, outlookVersion, create))[0]
	requireAll(t, "stored card", string(f.only(t, "Contacts").Data), "FN:Jane Doe", "N:Doe;Jane;;;", "ORG:Acme;R&D", "EMAIL;TYPE=internet:jane@acme.test", "jd@home.test", "TEL;TYPE=cell:+1 555 0100", "BDAY:1980-05-17", "Springfield", "TITLE:Engineer")
	update := `<m:UpdateItem ConflictResolution="AlwaysOverwrite"><m:ItemChanges><t:ItemChange><t:ItemId Id="` + id[1] + `" ChangeKey="` + id[2] + `"/><t:Updates>` +
		`<t:SetItemField><t:IndexedFieldURI FieldURI="contacts:PhoneNumber" FieldIndex="MobilePhone"/><t:Contact><t:PhoneNumbers><t:Entry Key="MobilePhone">+1 555 0199</t:Entry></t:PhoneNumbers></t:Contact></t:SetItemField>` +
		`<t:DeleteItemField><t:IndexedFieldURI FieldURI="contacts:PhysicalAddress:City" FieldIndex="Business"/></t:DeleteItemField>` +
		`<t:DeleteItemField><t:IndexedFieldURI FieldURI="contacts:EmailAddress" FieldIndex="EmailAddress2"/></t:DeleteItemField>` +
		`<t:SetItemField><t:FieldURI FieldURI="contacts:JobTitle"/><t:Contact><t:JobTitle>Lead</t:JobTitle></t:Contact></t:SetItemField>` +
		`</t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>`
	f.call(t, outlookVersion, update)
	photo := []byte("\xff\xd8\xff\xe0fake-jpeg")
	attach := f.call(t, outlookVersion, `<m:CreateAttachment><m:ParentItemId Id="`+id[1]+`"/><m:Attachments><t:FileAttachment><t:Name>ContactPicture.jpg</t:Name><t:IsContactPhoto>true</t:IsContactPhoto><t:Content>`+base64.StdEncoding.EncodeToString(photo)+`</t:Content></t:FileAttachment></m:Attachments></m:CreateAttachment>`)
	requireAll(t, "photo attachment", attach, `RootItemId="`+id[1]+`"`)
	got := f.call(t, outlookVersion, `<m:GetItem><m:ItemShape><t:BaseShape>AllProperties</t:BaseShape></m:ItemShape><m:ItemIds><t:ItemId Id="`+id[1]+`"/></m:ItemIds></m:GetItem>`)
	requireAll(t, "contact", got, `<t:ItemClass>IPM.Contact</t:ItemClass>`, `<t:DisplayName>Jane Doe</t:DisplayName>`, `<t:CompleteName><t:FirstName>Jane</t:FirstName><t:LastName>Doe</t:LastName><t:FullName>Jane Doe</t:FullName></t:CompleteName>`,
		`<t:EmailAddresses><t:Entry Key="EmailAddress1">jane@acme.test</t:Entry></t:EmailAddresses>`,
		`<t:Entry Key="Business"><t:Street>1 Main St</t:Street><t:CountryOrRegion>USA</t:CountryOrRegion><t:PostalCode>12345</t:PostalCode></t:Entry>`,
		`<t:Entry Key="MobilePhone">+1 555 0199</t:Entry>`, `<t:Entry Key="BusinessPhone">+1 555 0101</t:Entry>`,
		`<t:Birthday>1980-05-17T12:00:00Z</t:Birthday>`, `<t:Department>R&amp;D</t:Department>`, `<t:JobTitle>Lead</t:JobTitle>`, `<t:Surname>Doe</t:Surname>`,
		`<t:IsContactPhoto>true</t:IsContactPhoto>`, `<t:HasPicture>true</t:HasPicture>`)
	photoID := regexp.MustCompile(`<t:FileAttachment><t:AttachmentId Id="([^"]+)"`).FindStringSubmatch(got)
	if photoID == nil {
		t.Fatalf("no photo attachment in %s", got)
	}
	fetched := f.call(t, outlookVersion, `<m:GetAttachment><m:AttachmentIds><t:AttachmentId Id="`+photoID[1]+`"/></m:AttachmentIds></m:GetAttachment>`)
	requireAll(t, "photo", fetched, `<t:Content>`+base64.StdEncoding.EncodeToString(photo)+`</t:Content>`)
}

func TestTasksRoundTripStatusAndDates(t *testing.T) {
	f := newTypedFixture(t)
	if _, err := f.space.CreateFolder(t.Context(), service.UserAccess("alice", "test"), "Tasks", model.FolderTypeTasks, ""); err != nil {
		t.Fatal(err)
	}
	created := f.call(t, outlookHeader, `<m:CreateItem><m:SavedItemFolderId><t:DistinguishedFolderId Id="tasks"/></m:SavedItemFolderId><m:Items><t:Task><t:Subject>File report</t:Subject><t:Importance>High</t:Importance><t:DueDate>2026-11-20T00:00:00</t:DueDate><t:StartDate>2026-11-10T00:00:00</t:StartDate><t:PercentComplete>50</t:PercentComplete><t:Status>InProgress</t:Status></t:Task></m:Items></m:CreateItem>`)
	id := itemIDs2(t, created)[0]
	requireAll(t, "stored task", string(f.only(t, "Tasks").Data), "BEGIN:VTODO", "SUMMARY:File report", "DUE;VALUE=DATE:20261120", "DTSTART;VALUE=DATE:20261110", "STATUS:IN-PROCESS", "PERCENT-COMPLETE:50", "PRIORITY:1")
	f.call(t, outlookVersion, `<m:UpdateItem ConflictResolution="AutoResolve"><m:ItemChanges><t:ItemChange><t:ItemId Id="`+id[1]+`" ChangeKey="`+id[2]+`"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="task:Status"/><t:Task><t:Status>Completed</t:Status></t:Task></t:SetItemField></t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>`)
	listed := f.call(t, outlookHeader, `<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>AllProperties</t:BaseShape></m:ItemShape><m:ParentFolderIds><t:DistinguishedFolderId Id="tasks"/></m:ParentFolderIds></m:FindItem>`)
	requireAll(t, "task", listed, `<t:Task>`, `<t:ItemClass>IPM.Task</t:ItemClass>`, `<t:Importance>High</t:Importance>`, `<t:CompleteDate>`, `<t:DueDate>2026-11-19T23:00:00Z</t:DueDate>`, `<t:IsComplete>true</t:IsComplete>`, `<t:PercentComplete>100</t:PercentComplete>`, `<t:StartDate>2026-11-09T23:00:00Z</t:StartDate>`, `<t:Status>Completed</t:Status>`)
}

func TestSyncFolderItemsPresentsCalendarAndContactTypes(t *testing.T) {
	f := newTypedFixture(t)
	f.call(t, outlookVersion, outlookMeeting)
	f.call(t, outlookVersion, `<m:CreateItem><m:Items><t:Contact><t:GivenName>Max</t:GivenName><t:EmailAddresses><t:Entry Key="EmailAddress1">max@example.org</t:Entry></t:EmailAddresses></t:Contact></m:Items></m:CreateItem>`)
	calendarSync := f.call(t, outlookVersion, `<m:SyncFolderItems><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape><m:SyncFolderId><t:DistinguishedFolderId Id="calendar"/></m:SyncFolderId><m:MaxChangesReturned>100</m:MaxChangesReturned></m:SyncFolderItems>`)
	requireAll(t, "calendar sync", calendarSync, `<t:Create><t:CalendarItem>`, `<t:ItemClass>IPM.Appointment</t:ItemClass>`, `<t:CalendarItemType>RecurringMaster</t:CalendarItemType>`)
	contactSync := f.call(t, outlookVersion, `<m:SyncFolderItems><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape><m:SyncFolderId><t:DistinguishedFolderId Id="contacts"/></m:SyncFolderId><m:MaxChangesReturned>100</m:MaxChangesReturned></m:SyncFolderItems>`)
	requireAll(t, "contact sync", contactSync, `<t:Create><t:Contact>`, `<t:DisplayName>Max</t:DisplayName>`, `<t:Entry Key="EmailAddress1">max@example.org</t:Entry>`)
}

func TestUserOofSettingsMapToVacationResponder(t *testing.T) {
	f := newTypedFixture(t)
	got := f.call(t, outlookVersion, `<m:GetUserOofSettingsRequest><t:Mailbox><t:Address>alice@example.com</t:Address></t:Mailbox></m:GetUserOofSettingsRequest>`)
	requireAll(t, "disabled", got, `<t:OofState>Disabled</t:OofState>`, `<m:AllowExternalOof>All</m:AllowExternalOof>`)
	f.call(t, outlookVersion, `<m:SetUserOofSettingsRequest><t:Mailbox><t:Address>alice@example.com</t:Address></t:Mailbox><t:UserOofSettings><t:OofState>Scheduled</t:OofState><t:ExternalAudience>All</t:ExternalAudience>`+
		`<t:Duration><t:StartTime>2026-12-20T00:00:00Z</t:StartTime><t:EndTime>2027-01-03T00:00:00Z</t:EndTime></t:Duration><t:InternalReply><t:Message>&lt;html&gt;&lt;body&gt;Away until January&lt;/body&gt;&lt;/html&gt;</t:Message></t:InternalReply></t:UserOofSettings></m:SetUserOofSettingsRequest>`)
	if !f.oof.Enabled || f.oof.Message != "Away until January" || !f.oof.Start.Equal(time.Date(2026, 12, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("stored OOF = %+v", f.oof)
	}
	got = f.call(t, outlookVersion, `<m:GetUserOofSettingsRequest><t:Mailbox><t:Address>alice@example.com</t:Address></t:Mailbox></m:GetUserOofSettingsRequest>`)
	requireAll(t, "scheduled", got, `<t:OofState>Scheduled</t:OofState>`, `<t:StartTime>2026-12-20T00:00:00Z</t:StartTime>`, `<t:InternalReply><t:Message>Away until January</t:Message>`)
	denied := f.call(t, outlookVersion, `<m:GetUserOofSettingsRequest><t:Mailbox><t:Address>bob@example.com</t:Address></t:Mailbox></m:GetUserOofSettingsRequest>`)
	requireAll(t, "other mailbox", denied, `<m:ResponseCode>ErrorAccessDenied</m:ResponseCode>`)
}

func TestMessageAttachmentsCreateGetAndDelete(t *testing.T) {
	f := newTypedFixture(t)
	access := service.UserAccess("alice", "test")
	raw := []byte("Subject: Draft\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSee attached.\r\n")
	draft, err := f.space.CreateItem(t.Context(), access, f.folder(t, "Drafts").ID, service.ItemInput{Data: raw, Headers: model.ParseItemHeaders(raw)})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("quarterly,numbers\n1,2\n")
	created := f.call(t, outlookVersion, `<m:CreateAttachment><m:ParentItemId Id="`+encodeID("i:", draft.ID)+`"/><m:Attachments><t:FileAttachment><t:Name>report.csv</t:Name><t:ContentType>text/csv</t:ContentType><t:Content>`+base64.StdEncoding.EncodeToString(content)+`</t:Content></t:FileAttachment></m:Attachments></m:CreateAttachment>`)
	attachmentID := regexp.MustCompile(`<t:AttachmentId Id="([^"]+)" RootItemId`).FindStringSubmatch(created)
	if attachmentID == nil {
		t.Fatalf("no attachment ID in %s", created)
	}
	got := f.call(t, outlookVersion, `<m:GetItem><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ItemIds><t:ItemId Id="`+encodeID("i:", draft.ID)+`"/></m:ItemIds></m:GetItem>`)
	requireAll(t, "message", got, `<t:Attachments><t:FileAttachment><t:AttachmentId Id="`+attachmentID[1]+`"/><t:Name>report.csv</t:Name><t:ContentType>text/csv</t:ContentType>`, `<t:HasAttachments>true</t:HasAttachments>`, "See attached.")
	fetched := f.call(t, outlookVersion, `<m:GetAttachment><m:AttachmentIds><t:AttachmentId Id="`+attachmentID[1]+`"/></m:AttachmentIds></m:GetAttachment>`)
	requireAll(t, "attachment", fetched, `<t:Content>`+base64.StdEncoding.EncodeToString(content)+`</t:Content>`)
	f.call(t, outlookVersion, `<m:DeleteAttachment><m:AttachmentIds><t:AttachmentId Id="`+attachmentID[1]+`"/></m:AttachmentIds></m:DeleteAttachment>`)
	updated, err := f.space.GetItem(t.Context(), access, draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := service.ProjectMIME(updated.Data)
	if err != nil || len(projection.Attachments) != 0 || !strings.Contains(projection.Text, "See attached.") {
		t.Fatalf("after delete: attachments=%v text=%q err=%v\n%s", projection.Attachments, projection.Text, err, updated.Data)
	}
}

func TestDeleteItemSendToNoneMarksContextSilent(t *testing.T) {
	ctx := t.Context()
	if quietScheduling(ctx, "SendToAllAndSaveCopy") != ctx {
		t.Fatal("SendToAllAndSaveCopy must keep implicit scheduling")
	}
	if quietScheduling(ctx, "SendToNone") == ctx {
		t.Fatal("SendToNone must silence implicit scheduling")
	}
}
