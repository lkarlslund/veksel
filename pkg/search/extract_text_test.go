package search

import (
	"strings"
	"testing"

	"github.com/blevesearch/bleve/v2"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestContactAndCalendarValuesAreTextSearchable(t *testing.T) {
	t.Parallel()
	index, err := bleve.NewMemOnly(indexMapping())
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	vcard := model.ContactToVCard(model.Contact{
		FN: "Ada Lovelace", Org: "Navy", Emails: []string{"ada@analytical.example"}, Phones: []string{"+45 2345 6789"},
		Note: "Likes engines", PhotoData: []byte("PHOTOPAYLOAD"), PhotoType: "PNG",
	})
	ical := []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:e1\r\nSUMMARY:Kickoff\r\nLOCATION;LANGUAGE=en:Meeting room\\, Aarhus\r\nDESCRIPTION:Agenda for the\r\n  harbour visit\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	for _, item := range []struct {
		folder model.Folder
		id     string
		data   []byte
	}{
		{model.Folder{ID: "contacts", Type: model.FolderTypeContacts}, "c1", vcard},
		{model.Folder{ID: "cal", Type: model.FolderTypeCalendar}, "e1", ical},
	} {
		if err := index.Index(item.id, extract(item.folder, model.Item{ID: item.id, FolderID: item.folder.ID, Data: item.data}, 0)); err != nil {
			t.Fatal(err)
		}
	}
	for query, want := range map[string]string{
		"navy": "c1", "example": "c1", "ada": "c1", "6789": "c1", "engines": "c1",
		"aarhus": "e1", "kickoff": "e1", "harbour": "e1",
		"photopayload": "", "org:navy": "", "location": "", "summary": "",
	} {
		// Production queries always name their fields; the mapping keeps no
		// composite _all field.
		match := bleve.NewMatchQuery(query)
		match.SetField("content")
		result, err := index.Search(bleve.NewSearchRequest(match))
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(result.Hits) == 1 {
			got = result.Hits[0].ID
		}
		if len(result.Hits) > 1 || got != want {
			t.Errorf("query %q hits = %v, want %q", query, result.Hits, want)
		}
	}
}

// Snippets quote what a person recognizes, never storage names, item
// headers, or raw iCalendar values such as UIDs and stamps.
func TestSnippetTextOmitsInternalValues(t *testing.T) {
	t.Parallel()
	task := model.Item{ID: "itm_task", Name: "20261023T013934Z-001", Headers: map[string]string{"X-Veksel-Command-ID": "4026fa0a", "UID": "web-task-1@veksel", "SUMMARY": "Call Dave"},
		Data: []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:web-task-1@veksel\r\nDTSTAMP:20261023T013934Z\r\nSUMMARY:Call Dave\r\nDESCRIPTION:About the contract\r\nEND:VTODO\r\nEND:VCALENDAR\r\n")}
	contact := model.Item{ID: "itm_card", Name: "card.vcf", Headers: map[string]string{"X-Veksel-Command-ID": "4026fa0a", "Name": "Dave Doe"},
		Data: model.ContactToVCard(model.Contact{FN: "Dave Doe", GivenName: "Dave", FamilyName: "Doe", Org: "Sender Inc", Emails: []string{"dave@example.test"}})}
	invitation := model.Item{ID: "itm_mail", Name: "20261023T005945Z-005", Data: []byte(strings.Join([]string{
		"From: Dave Doe <dave@example.test>", "To: alice@example.test", "Subject: Invitation: Design review", "MIME-Version: 1.0",
		"Content-Type: text/calendar; method=REQUEST; charset=utf-8", "",
		"BEGIN:VCALENDAR", "METHOD:REQUEST", "BEGIN:VEVENT", "UID:web-task-1@veksel", "DTSTART:20261023T013934Z", "SUMMARY:Design review",
		"LOCATION:Room 4", "ORGANIZER;CN=Dave Doe:mailto:dave@example.test", "END:VEVENT", "END:VCALENDAR", "",
	}, "\r\n"))}
	for _, test := range []struct {
		folder model.Folder
		item   model.Item
		want   string
	}{
		{model.Folder{ID: "inbox", Type: model.FolderTypeMail}, invitation, "Room 4"},
		{model.Folder{ID: "tasks", Type: model.FolderTypeTasks}, task, "About the contract"},
		{model.Folder{ID: "contacts", Type: model.FolderTypeContacts}, contact, "dave@example.test"},
	} {
		doc := extract(test.folder, test.item, 0)
		text := snippetText(doc, test.item.Data)
		if len(snippets(text, "dave")) != 1 {
			t.Fatalf("%s: no snippet in %q", test.folder.Type, text)
		}
		for _, internal := range []string{"20261023T013934Z", "X-Veksel-Command-ID", "4026fa0a", "web-task-1", "Doe;Dave"} {
			if strings.Contains(text, internal) {
				t.Errorf("%s snippet text quotes %q: %q", test.folder.Type, internal, text)
			}
		}
		if !strings.Contains(text, test.want) {
			t.Errorf("%s snippet text lacks %q: %q", test.folder.Type, test.want, text)
		}
	}
}
