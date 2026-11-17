package contactport

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestDetectFormat(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		explicit string
		name     string
		want     Format
		wantErr  bool
	}{
		{name: "people.vcf", want: FormatVCard},
		{name: "people.VCARD", want: FormatVCard},
		{name: "people.csv", want: FormatCSV},
		{explicit: "csv", name: "people.bin", want: FormatCSV},
		{explicit: "json", name: "people.json", wantErr: true},
		{name: "people.txt", wantErr: true},
	} {
		got, err := DetectFormat(test.explicit, test.name)
		if (err != nil) != test.wantErr || got != test.want {
			t.Errorf("DetectFormat(%q, %q) = %q, %v", test.explicit, test.name, got, err)
		}
	}
}

func TestParseVCardBundlePreservesOpaqueProperties(t *testing.T) {
	t.Parallel()
	input := []byte("BEGIN:VCARD\nVERSION:4.0\nFN:Åse Example\nitem1.EMAIL;TYPE=work:ase@example.test\nX-VENDOR;P=opaque:value\nEND:VCARD\n\nBEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bob\r\n NOTE folded\r\nEND:VCARD\r\n")
	document := Parse(FormatVCard, input)
	if !document.Valid() || len(document.Contacts) != 2 || !slices.Equal(document.Names, []string{"Åse Example", "BobNOTE folded"}) {
		t.Fatalf("parsed document = %+v", document)
	}
	if !bytes.Contains(document.Contacts[0], []byte("X-VENDOR;P=opaque:value")) || !bytes.Contains(document.Contacts[0], []byte("item1.EMAIL;TYPE=work:ase@example.test")) {
		t.Fatalf("opaque fields not retained:\n%s", document.Contacts[0])
	}
}

func TestParseVCardReportsWholeDocumentDefects(t *testing.T) {
	t.Parallel()
	input := []byte("outside\nBEGIN:VCARD\nVERSION:2.1\nFN:Old\nEND:VCARD\nBEGIN:VCARD\nVERSION:3.0\nFN:Open\n")
	document := Parse(FormatVCard, input)
	if document.Valid() || len(document.Problems) != 3 {
		t.Fatalf("problems = %+v", document.Problems)
	}
	for _, phrase := range []string{"outside", "VERSION", "missing END"} {
		if !problemContains(document.Problems, phrase) {
			t.Errorf("missing %q in %+v", phrase, document.Problems)
		}
	}
}

func TestParseVCardBoundsDocumentCardAndCount(t *testing.T) {
	t.Parallel()
	oversized := Parse(FormatVCard, bytes.Repeat([]byte("x"), MaxDocumentBytes+1))
	if oversized.Valid() || !problemContains(oversized.Problems, "exceeds") {
		t.Fatalf("oversized document = %+v", oversized)
	}
	largeCard := []byte("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:" + strings.Repeat("x", MaxContactBytes) + "\r\nEND:VCARD\r\n")
	cardResult := Parse(FormatVCard, largeCard)
	if cardResult.Valid() || !problemContains(cardResult.Problems, "exceeds") {
		t.Fatalf("oversized card problems = %+v", cardResult.Problems)
	}
	var bundle strings.Builder
	for range MaxContacts + 1 {
		bundle.WriteString("BEGIN:VCARD\nVERSION:3.0\nFN:X\nEND:VCARD\n")
	}
	countResult := Parse(FormatVCard, []byte(bundle.String()))
	if countResult.Valid() || len(countResult.Contacts) != MaxContacts || !problemContains(countResult.Problems, "exceeds") {
		t.Fatalf("over-count result = contacts %d problems %+v", len(countResult.Contacts), countResult.Problems)
	}
}

func TestCSVExportImportRoundTrip(t *testing.T) {
	t.Parallel()
	original := model.Contact{
		FN: "=Formula Name", Prefix: "Dr", GivenName: "Åse", MiddleName: "Q", FamilyName: "Example", Suffix: "III", Nickname: "Ace",
		Emails: []string{"ase@example.test", "other@example.test"}, Phones: []string{"+4512345678"}, Org: "Example A/S", Department: "R&D", Title: "Engineer", Role: "Builder",
		Birthday: "1990-01-02", URL: "https://example.test", Categories: []string{"work", "friends"}, Note: "line one\nline two",
		Addresses:    []model.ContactAddress{{Type: "home", Street: "Home 1", Locality: "City", Region: "Region", PostalCode: "1234", Country: "DK"}, {Type: "work", Street: "Work 2", Locality: "Town", Country: "DK"}},
		CustomFields: map[string]string{"Badge": "42", "Desk": "North"},
	}
	var output bytes.Buffer
	exporter, err := NewExporter(&output, FormatCSV)
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Write(model.NewContactVCard(original)); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(output.Bytes())).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][0] != "'=Formula Name" || rows[1][8] != "'+4512345678" {
		t.Fatalf("exported rows = %#v, %v", rows, err)
	}
	document := Parse(FormatCSV, output.Bytes())
	if !document.Valid() || len(document.Contacts) != 1 {
		t.Fatalf("round-trip document = %+v", document)
	}
	got := model.ParseVCard(document.Contacts[0])
	if got.FN != original.FN || !slices.Equal(got.Emails, original.Emails) || !slices.Equal(got.Phones, original.Phones) || got.Note != original.Note || !slices.Equal(got.Categories, original.Categories) || len(got.Addresses) != 2 {
		t.Fatalf("round-trip contact = %+v", got)
	}
	if encoded, _ := json.Marshal(got.CustomFields); string(encoded) != `{"BADGE":"42","DESK":"North"}` {
		t.Fatalf("custom fields = %s", encoded)
	}
}

func TestParseCSVRejectsLossyOrMalformedRows(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{name: "unknown header", data: "Full Name,Secret\nAlice,value\n", want: "unsupported"},
		{name: "missing name columns", data: "Emails\na@example.test\n", want: "requires Full Name"},
		{name: "empty name", data: "Full Name,Emails\n,a@example.test\n", want: "name is empty"},
		{name: "custom not object", data: "Full Name,Custom Fields\nAlice,null\n", want: "JSON object"},
		{name: "duplicate", data: "Full Name,full-name\nAlice,Alice\n", want: "duplicated"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := Parse(FormatCSV, []byte(test.data))
			if document.Valid() || !problemContains(document.Problems, test.want) {
				t.Fatalf("document = %+v", document)
			}
		})
	}
}

func TestVCardExporterPreservesPayloadAndRejectsInvalidCard(t *testing.T) {
	t.Parallel()
	card := []byte("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Alice\r\nX-OPAQUE:value\r\nEND:VCARD")
	var output bytes.Buffer
	exporter, err := NewExporter(&output, FormatVCard)
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Write(card); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != string(card)+"\r\n" {
		t.Fatalf("vCard output = %q", got)
	}
	if err := exporter.Write([]byte("not a card")); err == nil {
		t.Fatal("invalid export card accepted")
	}
}

func TestCSVColumnsReturnsCopy(t *testing.T) {
	t.Parallel()
	columns := CSVColumns()
	columns[0] = "changed"
	if CSVColumns()[0] == "changed" {
		t.Fatal("CSVColumns exposed mutable package state")
	}
}

func problemContains(problems []Problem, phrase string) bool {
	for _, problem := range problems {
		if strings.Contains(problem.Message, phrase) {
			return true
		}
	}
	return false
}

func FuzzParse(f *testing.F) {
	f.Add("vcard", []byte("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Alice\r\nEND:VCARD\r\n"))
	f.Add("csv", []byte("Full Name,Emails\nAlice,alice@example.test\n"))
	f.Fuzz(func(t *testing.T, rawFormat string, data []byte) {
		format := Format(rawFormat)
		document := Parse(format, data)
		if document.Valid() {
			for _, card := range document.Contacts {
				if err := model.ValidateContactVCard(card); err != nil {
					t.Fatalf("valid parse returned invalid vCard: %v", err)
				}
			}
		}
	})
}
