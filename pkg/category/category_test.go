package category

import (
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestKeywordFollowsThunderbird(t *testing.T) {
	for name, want := range map[string]string{
		"Important": "$label1", "work": "$label2", "To Do": "$label4",
		"Project X": "project_x", "Café": "caf&AOk-", "A&B": "a&-b", "(draft)": "_draft_",
	} {
		if got := Keyword(name); got != want {
			t.Errorf("Keyword(%q) = %q, want %q", name, got, want)
		}
	}
	list := []model.Category{{Name: "Project X", Color: "#112233"}}
	if name, ok := NameForKeyword("PROJECT_X", list); !ok || name != "Project X" {
		t.Fatalf("NameForKeyword = %q %v", name, ok)
	}
	if name, ok := NameForKeyword("$Label3", nil); !ok || name != "Personal" {
		t.Fatalf("default label = %q %v", name, ok)
	}
	if _, ok := NameForKeyword(`\Flagged`, list); ok {
		t.Fatal("system flag resolved to a category")
	}
}

func TestNormalizeRejectsInvalidLists(t *testing.T) {
	list, err := Normalize([]model.Category{{Name: "  Red   team ", Color: "#AABBCC"}, {Name: "Blue"}})
	if err != nil || list[0].Name != "Red team" || list[0].Color != "#aabbcc" {
		t.Fatalf("list=%v err=%v", list, err)
	}
	for _, invalid := range [][]model.Category{{{Name: ""}}, {{Name: "a"}, {Name: "A"}}, {{Name: "x", Color: "red"}}, {{Name: "a,b"}}} {
		if _, err := Normalize(invalid); err == nil {
			t.Errorf("Normalize(%v) accepted", invalid)
		}
	}
}

func TestApplyAcrossFolderTypes(t *testing.T) {
	message := model.Item{Flags: []string{model.FlagSeen}}
	change, err := Apply(model.FolderTypeMail, message, "Project X", true)
	if err != nil || !change.Changed || !slices.Contains(change.Flags, "project_x") {
		t.Fatalf("mail change = %+v err=%v", change, err)
	}
	message.Flags = change.Flags
	if !Has(model.FolderTypeMail, message, "project x") {
		t.Fatal("mail category not found")
	}
	if got := ItemCategories(model.FolderTypeMail, message, []model.Category{{Name: "Project X"}}); !slices.Equal(got, []string{"Project X"}) {
		t.Fatalf("mail categories = %v", got)
	}
	change, _ = Apply(model.FolderTypeMail, message, "Project X", false)
	if slices.Contains(change.Flags, "project_x") || !slices.Contains(change.Flags, model.FlagSeen) {
		t.Fatalf("removed flags = %v", change.Flags)
	}

	card := model.Item{Data: []byte("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c\r\nFN:Ada\r\nX-CUSTOM:keep\r\nEND:VCARD\r\n")}
	change, err = Apply(model.FolderTypeContacts, card, "Friends", true)
	if err != nil || !change.Changed {
		t.Fatal(err)
	}
	card.Data = change.Data
	if !Has(model.FolderTypeContacts, card, "friends") || !strings.Contains(string(card.Data), "X-CUSTOM:keep") {
		t.Fatal("contact category missing")
	}
	if contact := model.ParseVCard(card.Data); contact.FN != "Ada" {
		t.Fatalf("contact changed: %+v", contact)
	}

	todo := model.Item{Data: []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VTODO\r\nUID:t\r\nDTSTAMP:20260101T000000Z\r\nSUMMARY:Do\r\nEND:VTODO\r\nEND:VCALENDAR\r\n")}
	change, err = Apply(model.FolderTypeTasks, todo, "Errands", true)
	if err != nil || !Has(model.FolderTypeTasks, model.Item{Data: change.Data}, "Errands") {
		t.Fatalf("task change err=%v data=%s", err, change.Data)
	}
	if _, err := Apply(model.FolderTypeFiles, model.Item{}, "x", true); err == nil {
		t.Fatal("files accepted a category")
	}
}
