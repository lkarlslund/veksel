package ews

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// seedFindItemInbox stores messages received on consecutive days at noon
// UTC, in an order that differs from both date and subject order.
func seedFindItemInbox(t *testing.T, space *service.FolderSpaceService) {
	t.Helper()
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	messages := []struct {
		day     int
		from    string
		subject string
		body    string
		seen    bool
	}{
		{3, "Carol Example <carol@example.test>", "Charlie invoice", "Payment due Friday.", true},
		{1, "Ann Example <ann@example.test>", "Alpha report", "Quarterly numbers attached.", false},
		{5, "Ann Example <ann@example.test>", "Echo meeting", "Agenda for the planning session.", false},
		{2, "Bob Example <bob@example.test>", "Bravo invoice", "Second reminder.", true},
		{4, "Bob Example <bob@example.test>", "Delta notes", "Notes from the call.", false},
	}
	for _, message := range messages {
		received := time.Date(2026, 11, message.day, 12, 0, 0, 0, time.UTC)
		raw := "From: " + message.from + "\r\nTo: alice@example.test\r\nSubject: " + message.subject +
			"\r\nDate: " + received.Format(time.RFC1123Z) + "\r\n\r\n" + message.body + "\r\n"
		var flags []string
		if message.seen {
			flags = []string{model.FlagSeen}
		}
		if _, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte(raw), InternalDate: received, Flags: flags}); err != nil {
			t.Fatal(err)
		}
	}
}

var subjectPattern = regexp.MustCompile(`<t:Subject>([^<]*)</t:Subject>`)

func findItemSubjects(t *testing.T, handler http.Handler, inner string) (string, []string) {
	t.Helper()
	response := ewsRequest(t, handler, `<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:Subject"/><t:FieldURI FieldURI="item:Preview"/></t:AdditionalProperties></m:ItemShape>`+
		inner+`</m:FindItem>`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	var subjects []string
	for _, match := range subjectPattern.FindAllStringSubmatch(body, -1) {
		subjects = append(subjects, match[1])
	}
	return body, subjects
}

const inboxParent = `<m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></m:ParentFolderIds>`

func TestFindItemQueryStringFiltersAndSorts(t *testing.T) {
	handler, space := testHandler(t)
	seedFindItemInbox(t, space)
	sortDescending := `<m:SortOrder><t:FieldOrder Order="Descending"><t:FieldURI FieldURI="item:DateTimeReceived"/></t:FieldOrder></m:SortOrder>`
	page := `<m:IndexedPageItemView MaxEntriesReturned="25" Offset="0" BasePoint="Beginning"/>`
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{"date range", `received:>=2026-11-02 AND received:<2026-11-05`, "Delta notes|Charlie invoice|Bravo invoice"},
		{"timestamps", `received:>=2026-11-03T12:00:00Z AND received:<2026-11-04T12:00:00Z`, "Charlie invoice"},
		{"whole day", `received:2026-11-04`, "Delta notes"},
		{"range", `received:2026-11-02..2026-11-03`, "Charlie invoice|Bravo invoice"},
		{"sender and dates", `from:"Ann Example" AND received:>=2026-11-02`, "Echo meeting"},
		{"sender address", `from:bob@example.test`, "Delta notes|Bravo invoice"},
		{"free term", `invoice`, "Charlie invoice|Bravo invoice"},
		{"body term", `agenda`, "Echo meeting"},
		{"phrase", `"planning session"`, "Echo meeting"},
		{"or", `subject:alpha OR subject:echo`, "Echo meeting|Alpha report"},
		{"not", `invoice NOT from:carol`, "Bravo invoice"},
		{"nothing in range", `received:>=2026-12-01`, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, subjects := findItemSubjects(t, handler, page+sortDescending+inboxParent+`<m:QueryString>`+escape(test.query)+`</m:QueryString>`)
			if got := strings.Join(subjects, "|"); got != test.want {
				t.Fatalf("subjects = %q, want %q\n%s", got, test.want, body)
			}
			if count := len(subjects); !strings.Contains(body, `TotalItemsInView="`+strconv.Itoa(count)+`"`) {
				t.Fatalf("TotalItemsInView does not count the matches: %s", body)
			}
		})
	}
}

func TestFindItemRestrictionAndSortOrder(t *testing.T) {
	handler, space := testHandler(t)
	seedFindItemInbox(t, space)
	isGreater := func(field, value string) string {
		return `<t:IsGreaterThanOrEqualTo><t:FieldURI FieldURI="` + field + `"/><t:FieldURIOrConstant><t:Constant Value="` + value + `"/></t:FieldURIOrConstant></t:IsGreaterThanOrEqualTo>`
	}
	isLess := func(field, value string) string {
		return `<t:IsLessThan><t:FieldURI FieldURI="` + field + `"/><t:FieldURIOrConstant><t:Constant Value="` + value + `"/></t:FieldURIOrConstant></t:IsLessThan>`
	}
	tests := []struct {
		name        string
		restriction string
		order       string
		want        string
	}{
		{
			"date window ascending",
			`<t:And>` + isGreater("item:DateTimeReceived", "2026-11-02T00:00:00Z") + isLess("item:DateTimeReceived", "2026-11-05T00:00:00Z") + `</t:And>`,
			`<t:FieldOrder Order="Ascending"><t:FieldURI FieldURI="item:DateTimeReceived"/></t:FieldOrder>`,
			"Bravo invoice|Charlie invoice|Delta notes",
		},
		{
			"unread by subject",
			`<t:IsEqualTo><t:FieldURI FieldURI="message:IsRead"/><t:FieldURIOrConstant><t:Constant Value="false"/></t:FieldURIOrConstant></t:IsEqualTo>`,
			`<t:FieldOrder Order="Ascending"><t:FieldURI FieldURI="item:Subject"/></t:FieldOrder>`,
			"Alpha report|Delta notes|Echo meeting",
		},
		{
			"item class prefix",
			`<t:Contains ContainmentMode="Prefixed" ContainmentComparison="IgnoreCase"><t:FieldURI FieldURI="item:ItemClass"/><t:Constant Value="ipm.note"/></t:Contains>`,
			`<t:FieldOrder Order="Descending"><t:FieldURI FieldURI="item:Subject"/></t:FieldOrder>`,
			"Echo meeting|Delta notes|Charlie invoice|Bravo invoice|Alpha report",
		},
		{
			"not and or",
			`<t:Not><t:Or><t:Contains ContainmentMode="Substring" ContainmentComparison="IgnoreCase"><t:FieldURI FieldURI="item:Subject"/><t:Constant Value="INVOICE"/></t:Contains>` +
				`<t:Contains ContainmentMode="FullString" ContainmentComparison="IgnoreCase"><t:FieldURI FieldURI="message:From"/><t:Constant Value="ann@example.test"/></t:Contains></t:Or></t:Not>`,
			`<t:FieldOrder Order="Ascending"><t:FieldURI FieldURI="item:DateTimeReceived"/></t:FieldOrder>`,
			"Delta notes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, subjects := findItemSubjects(t, handler, `<m:IndexedPageItemView MaxEntriesReturned="10" Offset="0" BasePoint="Beginning"/><m:Restriction>`+test.restriction+`</m:Restriction><m:SortOrder>`+test.order+`</m:SortOrder>`+inboxParent)
			if got := strings.Join(subjects, "|"); got != test.want {
				t.Fatalf("subjects = %q, want %q\n%s", got, test.want, body)
			}
		})
	}
}

func TestFindItemPagesFilteredSortedResults(t *testing.T) {
	handler, space := testHandler(t)
	seedFindItemInbox(t, space)
	order := `<m:SortOrder><t:FieldOrder Order="Descending"><t:FieldURI FieldURI="item:DateTimeReceived"/></t:FieldOrder></m:SortOrder>`
	query := `<m:QueryString>received:>=2026-11-02</m:QueryString>`
	body, subjects := findItemSubjects(t, handler, `<m:IndexedPageItemView MaxEntriesReturned="2" Offset="2" BasePoint="Beginning"/>`+order+inboxParent+query)
	if got := strings.Join(subjects, "|"); got != "Charlie invoice|Bravo invoice" {
		t.Fatalf("second page = %q\n%s", got, body)
	}
	if !strings.Contains(body, `TotalItemsInView="4"`) || !strings.Contains(body, `IndexedPagingOffset="4"`) || !strings.Contains(body, `IncludesLastItemInRange="true"`) {
		t.Fatalf("paging attributes: %s", body)
	}
	body, subjects = findItemSubjects(t, handler, `<m:IndexedPageItemView MaxEntriesReturned="1" Offset="0" BasePoint="End"/>`+order+inboxParent+query)
	if got := strings.Join(subjects, "|"); got != "Bravo invoice" || !strings.Contains(body, `IncludesLastItemInRange="false"`) {
		t.Fatalf("page from the end = %q\n%s", got, body)
	}
}

func TestFindItemRejectsFiltersItCannotEvaluate(t *testing.T) {
	handler, space := testHandler(t)
	seedFindItemInbox(t, space)
	tests := []struct {
		name, inner, code string
	}{
		{"unknown field", `<m:Restriction><t:Exists><t:FieldURI FieldURI="item:Flag"/></t:Exists></m:Restriction>`, "ErrorUnsupportedPathForQuery"},
		{"extended property", `<m:Restriction><t:Exists><t:ExtendedFieldURI PropertyTag="0x0E07" PropertyType="Integer"/></t:Exists></m:Restriction>`, "ErrorUnsupportedPathForQuery"},
		{"bitmask", `<m:Restriction><t:Excludes><t:FieldURI FieldURI="item:Size"/><t:Bitmask Value="1"/></t:Excludes></m:Restriction>`, "ErrorInvalidRestriction"},
		{"bad date", `<m:QueryString>received:&gt;=last-tuesday</m:QueryString>`, "ErrorInvalidRestriction"},
		{"unknown property", `<m:QueryString>folder:archive</m:QueryString>`, "ErrorInvalidRestriction"},
		{"sort field", `<m:SortOrder><t:FieldOrder Order="Ascending"><t:FieldURI FieldURI="item:Flag"/></t:FieldOrder></m:SortOrder>`, "ErrorUnsupportedPathForQuery"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, subjects := findItemSubjects(t, handler, inboxParent+test.inner)
			if len(subjects) != 0 || !strings.Contains(body, test.code) || !strings.Contains(body, `ResponseClass="Error"`) {
				t.Fatalf("want %s and no items:\n%s", test.code, body)
			}
		})
	}
}

func TestFindItemReturnsPreview(t *testing.T) {
	handler, space := testHandler(t)
	seedFindItemInbox(t, space)
	body, _ := findItemSubjects(t, handler, inboxParent+`<m:QueryString>subject:alpha</m:QueryString>`)
	if !strings.Contains(body, `<t:Preview>Quarterly numbers attached.</t:Preview>`) {
		t.Fatalf("preview missing: %s", body)
	}
}

// A narrow shape that names the body gets it: IdOnly plus AdditionalProperties
// returns exactly the requested properties, the body included.
func TestIdOnlyShapeReturnsRequestedBody(t *testing.T) {
	handler, space := testHandler(t)
	seedFindItemInbox(t, space)
	find := ewsRequest(t, handler, `<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>`+inboxParent+`<m:QueryString>subject:alpha</m:QueryString></m:FindItem>`).Body.String()
	id := regexp.MustCompile(`<t:ItemId Id="([^"]+)"`).FindStringSubmatch(find)
	if id == nil {
		t.Fatalf("no item: %s", find)
	}
	getItem := func(shape string) string {
		t.Helper()
		return ewsRequest(t, handler, `<m:GetItem><m:ItemShape>`+shape+`</m:ItemShape><m:ItemIds><t:ItemId Id="`+id[1]+`"/></m:ItemIds></m:GetItem>`).Body.String()
	}
	tests := []struct {
		name, shape string
		body, mime  bool
	}{
		{"IdOnly", `<t:BaseShape>IdOnly</t:BaseShape>`, false, false},
		{"IdOnly item:Body", `<t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:Body"/></t:AdditionalProperties>`, true, false},
		{"IdOnly item:TextBody", `<t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:TextBody"/></t:AdditionalProperties>`, true, false},
		{"IdOnly item:MimeContent", `<t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:MimeContent"/></t:AdditionalProperties>`, false, true},
		{"IdOnly IncludeMimeContent", `<t:BaseShape>IdOnly</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent>`, false, true},
		{"Default", `<t:BaseShape>Default</t:BaseShape>`, true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := getItem(test.shape)
			if got := strings.Contains(response, `<t:Body BodyType="Text">Quarterly numbers attached.`); got != test.body {
				t.Errorf("body present = %v, want %v: %s", got, test.body, response)
			}
			if got := strings.Contains(response, `<t:MimeContent`); got != test.mime {
				t.Errorf("MIME content present = %v, want %v: %s", got, test.mime, response)
			}
		})
	}
	found, _ := findItemSubjects(t, handler, inboxParent+`<m:QueryString>subject:alpha</m:QueryString>`)
	if strings.Contains(found, `<t:Body`) {
		t.Fatalf("FindItem without a requested body returned one: %s", found)
	}
	withBody := ewsRequest(t, handler, `<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:Body"/></t:AdditionalProperties></m:ItemShape>`+inboxParent+`<m:QueryString>subject:alpha</m:QueryString></m:FindItem>`).Body.String()
	if !strings.Contains(withBody, `<t:Body BodyType="Text">Quarterly numbers attached.`) {
		t.Fatalf("FindItem IdOnly with item:Body returned no body: %s", withBody)
	}
}

// Subjects encoded in charsets other than UTF-8 and ISO-8859-1 reach EWS
// clients decoded.
func TestFindItemDecodesWindows1252Subject(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	raw := "From: ann@example.test\r\nTo: alice@example.test\r\nSubject: =?Windows-1252?Q?Re:_Offer_=96_p=E5_vej?=\r\n =?Windows-1252?Q?_til_dig?=\r\n\r\nBody\r\n"
	if _, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte(raw)}); err != nil {
		t.Fatal(err)
	}
	_, subjects := findItemSubjects(t, handler, inboxParent)
	if len(subjects) != 1 || subjects[0] != "Re: Offer – på vej til dig" {
		t.Fatalf("subjects = %q", subjects)
	}
}
