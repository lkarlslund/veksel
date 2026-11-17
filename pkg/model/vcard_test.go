package model

import (
	"bytes"
	"strings"
	"testing"
)

const testVCARD = `BEGIN:VCARD
VERSION:3.0
UID:contact-001@example.com
FN:John Doe
N:Doe;John;;;
EMAIL;TYPE=INTERNET:john@example.com
TEL;TYPE=WORK:+1-555-0101
ORG:Acme Corp
NOTE:A friendly contact
URL:https://example.com/john
BDAY:19900101
END:VCARD`

const testVCARD4 = `BEGIN:VCARD
VERSION:4.0
UID:contact-002@example.com
FN:Jane Smith
N:Smith;Jane;;;
EMAIL;type=internet:jane@example.com
TEL;type=work:+1-555-0202
END:VCARD`

func TestParseVCardBasic(t *testing.T) {
	t.Parallel()
	c := ParseVCard([]byte(testVCARD))

	if c.FN != "John Doe" {
		t.Errorf("FN = %q, want %q", c.FN, "John Doe")
	}
	if c.N != "Doe;John;;;" {
		t.Errorf("N = %q, want %q", c.N, "Doe;John;;;")
	}
	if c.UID != "contact-001@example.com" {
		t.Errorf("UID = %q, want %q", c.UID, "contact-001@example.com")
	}
	if c.Org != "Acme Corp" {
		t.Errorf("Org = %q, want %q", c.Org, "Acme Corp")
	}
	if c.Note != "A friendly contact" {
		t.Errorf("Note = %q, want %q", c.Note, "A friendly contact")
	}
	if c.URL != "https://example.com/john" {
		t.Errorf("URL = %q, want %q", c.URL, "https://example.com/john")
	}
	if c.Birthday != "19900101" {
		t.Errorf("Birthday = %q, want %q", c.Birthday, "19900101")
	}
}

func TestParseVCardEmails(t *testing.T) {
	t.Parallel()
	c := ParseVCard([]byte(testVCARD))
	if len(c.Emails) != 1 {
		t.Fatalf("expected 1 email, got %d", len(c.Emails))
	}
	if c.Emails[0] != "john@example.com" {
		t.Errorf("email = %q, want %q", c.Emails[0], "john@example.com")
	}
}

func TestParseVCardPhones(t *testing.T) {
	t.Parallel()
	c := ParseVCard([]byte(testVCARD))
	if len(c.Phones) != 1 {
		t.Fatalf("expected 1 phone, got %d", len(c.Phones))
	}
	if c.Phones[0] != "+1-555-0101" {
		t.Errorf("phone = %q, want %q", c.Phones[0], "+1-555-0101")
	}
}

func TestParseVCard4(t *testing.T) {
	t.Parallel()
	c := ParseVCard([]byte(testVCARD4))
	if c.FN != "Jane Smith" {
		t.Errorf("FN = %q, want %q", c.FN, "Jane Smith")
	}
	if len(c.Emails) != 1 {
		t.Fatalf("expected 1 email, got %d", len(c.Emails))
	}
	if c.Emails[0] != "jane@example.com" {
		t.Errorf("email = %q, want %q", c.Emails[0], "jane@example.com")
	}
}

func TestContactGroupVCard4RoundTrip(t *testing.T) {
	t.Parallel()
	original := Contact{
		UID: "group-1", FN: "Project team", Kind: "group",
		Members:    []string{"mailto:ada@example.test", "urn:uuid:member-2", "https://directory.example.test/member/3"},
		Categories: []string{"work"},
	}
	data := ContactToVCard(original)
	for _, want := range []string{"VERSION:4.0", "UID;VALUE=text:group-1", "KIND:group", "MEMBER:mailto:ada@example.test", "MEMBER:urn:uuid:member-2"} {
		if !bytes.Contains(data, []byte(want)) {
			t.Fatalf("group vCard is missing %q:\n%s", want, data)
		}
	}
	parsed := ParseVCard(data)
	if parsed.Kind != "group" || parsed.FN != original.FN || len(parsed.Members) != 3 || parsed.Members[2] != original.Members[2] {
		t.Fatalf("parsed group = %#v", parsed)
	}
	if err := ValidateContactVCard(data); err != nil {
		t.Fatalf("generated group is not structurally valid: %v", err)
	}
}

func TestParseVCardRecognizesGroupedMemberProperty(t *testing.T) {
	t.Parallel()
	data := []byte("BEGIN:VCARD\r\nVERSION:4.0\r\nKIND:group\r\nFN:Team\r\nitem1.MEMBER;PREF=1:urn:uuid:member\r\nEND:VCARD\r\n")
	contact := ParseVCard(data)
	if contact.Kind != "group" || len(contact.Members) != 1 || contact.Members[0] != "urn:uuid:member" {
		t.Fatalf("grouped member projection = %#v", contact)
	}
	if !VCardMatchesSearch(data, "uuid:member") {
		t.Fatal("grouped MEMBER value was not searchable")
	}
}

func TestParseVCardEmpty(t *testing.T) {
	t.Parallel()
	c := ParseVCard([]byte("not a vcard"))
	if c.FN != "" {
		t.Errorf("expected empty FN, got %q", c.FN)
	}
}

func TestParseVCardMultiLine(t *testing.T) {
	t.Parallel()
	// vCard with continuation line
	vcard := `BEGIN:VCARD
VERSION:3.0
FN:John
 N:Doe;John;;;
EMAIL;TYPE=INTERNET:john@example.com
TEL;TYPE=WORK:+1-555-0101
END:VCARD`
	c := ParseVCard([]byte(vcard))
	if c.FN != "John" {
		t.Errorf("FN = %q, want %q", c.FN, "John")
	}
	// N should include the continuation
	if c.N != "Doe;John;;;" {
		t.Errorf("N = %q, want %q", c.N, "Doe;John;;;")
	}
}

func TestVCardMatchesSearch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{"empty query", "", true},
		{"match FN", "john", true},
		{"match FN uppercase", "JOHN", true},
		{"match email", "john@example.com", true},
		{"match email partial", "example.com", true},
		{"match phone", "555-0101", true},
		{"match org", "acme", true},
		{"match note", "friendly", true},
		{"no match", "nonexistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VCardMatchesSearch([]byte(testVCARD), tt.query)
			if got != tt.want {
				t.Errorf("VCardMatchesSearch(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

func TestVCardMatchesSearchOtherCard(t *testing.T) {
	t.Parallel()
	// Searching for "jane" in John's card should not match
	if VCardMatchesSearch([]byte(testVCARD), "jane") {
		t.Error("should not match 'jane' in John's card")
	}

	// Searching for "jane" in Jane's card should match
	if !VCardMatchesSearch([]byte(testVCARD4), "jane") {
		t.Error("should match 'jane' in Jane's card")
	}
}

func TestVCardMatchesSearchNProperty(t *testing.T) {
	t.Parallel()
	// Search for "Doe" should match the N property
	if !VCardMatchesSearch([]byte(testVCARD), "Doe") {
		t.Error("should match 'Doe' in N property")
	}
}

func TestVCardMatchesSearchUID(t *testing.T) {
	t.Parallel()
	if !VCardMatchesSearch([]byte(testVCARD), "contact-001") {
		t.Error("should match UID containing 'contact-001'")
	}
}

func TestParseVCardMultipleEmails(t *testing.T) {
	t.Parallel()
	vcard := `BEGIN:VCARD
VERSION:3.0
FN:Multi Email
EMAIL;TYPE=INTERNET:work@example.com
EMAIL;TYPE=HOME:home@example.com
END:VCARD`
	c := ParseVCard([]byte(vcard))
	if len(c.Emails) != 2 {
		t.Fatalf("expected 2 emails, got %d", len(c.Emails))
	}
	if c.Emails[0] != "work@example.com" {
		t.Errorf("email[0] = %q, want %q", c.Emails[0], "work@example.com")
	}
	if c.Emails[1] != "home@example.com" {
		t.Errorf("email[1] = %q, want %q", c.Emails[1], "home@example.com")
	}
}

func TestParseVCardMultiplePhones(t *testing.T) {
	t.Parallel()
	vcard := `BEGIN:VCARD
VERSION:3.0
FN:Multi Phone
TEL;TYPE=WORK:+1-555-0101
TEL;TYPE=HOME:+1-555-0202
TEL;TYPE=CELL:+1-555-0303
END:VCARD`
	c := ParseVCard([]byte(vcard))
	if len(c.Phones) != 3 {
		t.Fatalf("expected 3 phones, got %d", len(c.Phones))
	}
}

func TestExtendedContactRoundTrip(t *testing.T) {
	t.Parallel()
	original := Contact{
		UID: "extended@example.test", FN: "Dr Ada Lovelace", Prefix: "Dr", GivenName: "Ada", FamilyName: "Lovelace",
		Nickname: "Enchantress", Org: "Analytical Engines", Department: "Research", Title: "Mathematician", Role: "Founder",
		Emails: []string{"ada@example.test"}, Phones: []string{"+45 12 34 56 78"}, Birthday: "1815-12-10",
		Addresses:    []ContactAddress{{Type: "work", Street: "1 Engine Way", Locality: "London", PostalCode: "W1", Country: "UK"}},
		CustomFields: map[string]string{"Favourite colour": "teal"}, PhotoData: make([]byte, 256), PhotoType: "PNG",
	}
	for i := range original.PhotoData {
		original.PhotoData[i] = byte(i)
	}

	parsed := ParseVCard(ContactToVCard(original))
	if parsed.GivenName != original.GivenName || parsed.FamilyName != original.FamilyName || parsed.Department != original.Department || parsed.Title != original.Title {
		t.Fatalf("extended fields did not round trip: %#v", parsed)
	}
	if len(parsed.Addresses) != 1 || parsed.Addresses[0].Street != "1 Engine Way" || parsed.Addresses[0].Type != "work" {
		t.Fatalf("address did not round trip: %#v", parsed.Addresses)
	}
	if parsed.CustomFields["FAVOURITE-COLOUR"] != "teal" {
		t.Fatalf("custom fields did not round trip: %#v", parsed.CustomFields)
	}
	if !bytes.Equal(parsed.PhotoData, original.PhotoData) {
		t.Fatalf("photo did not round trip: got %d bytes, want %d", len(parsed.PhotoData), len(original.PhotoData))
	}
}

func TestParseVCardTrimWhitespace(t *testing.T) {
	t.Parallel()
	vcard := "  FN:  John Doe  \n"
	c := ParseVCard([]byte(vcard))
	// Value should be trimmed
	if c.FN != "John Doe" {
		t.Errorf("FN = %q, want %q", c.FN, "John Doe")
	}
}

func TestVCardMatchesSearchCaseInsensitive(t *testing.T) {
	t.Parallel()
	// Case insensitive search
	if !VCardMatchesSearch([]byte(testVCARD), "JOHN DOE") {
		t.Error("should match 'JOHN DOE' case-insensitively")
	}
	if !VCardMatchesSearch([]byte(testVCARD), "John Doe") {
		t.Error("should match 'John Doe'")
	}
}

func TestVCardMatchesSearchSpecialChars(t *testing.T) {
	t.Parallel()
	// Search with special characters in email
	if !VCardMatchesSearch([]byte(testVCARD), "john@") {
		t.Error("should match 'john@' in email")
	}
}

func TestVCardMatchesSearchNoFalsePositives(t *testing.T) {
	t.Parallel()
	// Should not match properties that are not in searchProperties
	vcard := `BEGIN:VCARD
VERSION:3.0
FN:John
ADR:123 Main St
END:VCARD`
	// "Main St" is in ADR, not searched
	if VCardMatchesSearch([]byte(vcard), "Main St") {
		t.Error("should not match ADR property")
	}
}

func TestParseVCardWithLineContinuation(t *testing.T) {
	t.Parallel()
	// Long email that wraps
	vcard := "BEGIN:VCARD\nVERSION:3.0\nFN:Test\nEMAIL;TYPE=INTERNET:very-long-\n address@example.com\nEND:VCARD"
	c := ParseVCard([]byte(vcard))
	if len(c.Emails) != 1 {
		t.Fatalf("expected 1 email, got %d", len(c.Emails))
	}
	// Continuation should be joined
	if !strings.Contains(c.Emails[0], "very-long-") {
		t.Errorf("email should contain continuation: %q", c.Emails[0])
	}
}

// --- CATEGORIES tests ---

func TestParseVCardCategories(t *testing.T) {
	t.Parallel()
	vcard := `BEGIN:VCARD
VERSION:3.0
FN:Grouped Contact
CATEGORIES:work,friends,family
END:VCARD`
	c := ParseVCard([]byte(vcard))
	if len(c.Categories) != 3 {
		t.Fatalf("expected 3 categories, got %d", len(c.Categories))
	}
	if c.Categories[0] != "work" {
		t.Errorf("Categories[0] = %q, want %q", c.Categories[0], "work")
	}
	if c.Categories[1] != "friends" {
		t.Errorf("Categories[1] = %q, want %q", c.Categories[1], "friends")
	}
	if c.Categories[2] != "family" {
		t.Errorf("Categories[2] = %q, want %q", c.Categories[2], "family")
	}
}

func TestParseVCardSingleCategory(t *testing.T) {
	t.Parallel()
	vcard := `BEGIN:VCARD
VERSION:4.0
FN:Single Group
CATEGORIES:work
END:VCARD`
	c := ParseVCard([]byte(vcard))
	if len(c.Categories) != 1 {
		t.Fatalf("expected 1 category, got %d", len(c.Categories))
	}
	if c.Categories[0] != "work" {
		t.Errorf("Categories[0] = %q, want %q", c.Categories[0], "work")
	}
}

func TestParseVCardNoCategories(t *testing.T) {
	t.Parallel()
	c := ParseVCard([]byte(testVCARD))
	if len(c.Categories) != 0 {
		t.Errorf("expected 0 categories, got %d", len(c.Categories))
	}
}

func TestParseCategoriesEmpty(t *testing.T) {
	t.Parallel()
	cats := parseCategories("")
	if len(cats) != 0 {
		t.Errorf("expected nil categories, got %v", cats)
	}
}

func TestParseCategoriesWithSpaces(t *testing.T) {
	t.Parallel()
	cats := parseCategories(" work , friends , family ")
	if len(cats) != 3 {
		t.Fatalf("expected 3 categories, got %d", len(cats))
	}
	if cats[0] != "work" {
		t.Errorf("Categories[0] = %q, want %q", cats[0], "work")
	}
}

// --- PHOTO tests ---

func TestParseVCardPhotoBinary(t *testing.T) {
	t.Parallel()
	// Base64-encoded "hello" = "aGVsbG8="
	vcard := `BEGIN:VCARD
VERSION:3.0
FN:Photo Contact
PHOTO;TYPE=JPEG;VALUE=binary:aGVsbG8=
END:VCARD`
	c := ParseVCard([]byte(vcard))
	if c.PhotoType != "JPEG" {
		t.Errorf("PhotoType = %q, want %q", c.PhotoType, "JPEG")
	}
	if string(c.PhotoData) != "hello" {
		t.Errorf("PhotoData = %q, want %q", string(c.PhotoData), "hello")
	}
}

func TestParseVCardPhotoPNG(t *testing.T) {
	t.Parallel()
	// Base64-encoded "png-data" = "cG5nLWRhdGE="
	vcard := `BEGIN:VCARD
VERSION:4.0
FN:PNG Photo
PHOTO;type=png;VALUE=binary:cG5nLWRhdGE=
END:VCARD`
	c := ParseVCard([]byte(vcard))
	if c.PhotoType != "png" {
		t.Errorf("PhotoType = %q, want %q", c.PhotoType, "png")
	}
	if string(c.PhotoData) != "png-data" {
		t.Errorf("PhotoData = %q, want %q", string(c.PhotoData), "png-data")
	}
}

func TestParseVCardPhotoURI(t *testing.T) {
	t.Parallel()
	vcard := `BEGIN:VCARD
VERSION:4.0
FN:URI Photo
PHOTO;TYPE=JPEG;VALUE=uri:http://example.com/photo.jpg
END:VCARD`
	c := ParseVCard([]byte(vcard))
	if c.PhotoType != "JPEG" {
		t.Errorf("PhotoType = %q, want %q", c.PhotoType, "JPEG")
	}
	if c.PhotoURI != "http://example.com/photo.jpg" {
		t.Errorf("PhotoURI = %q, want %q", c.PhotoURI, "http://example.com/photo.jpg")
	}
	if len(c.PhotoData) != 0 {
		t.Errorf("PhotoData = %q, want no binary data", string(c.PhotoData))
	}
}

func TestParseVCardNoPhoto(t *testing.T) {
	t.Parallel()
	c := ParseVCard([]byte(testVCARD))
	if len(c.PhotoData) != 0 {
		t.Errorf("expected no photo data, got %v", c.PhotoData)
	}
	if c.PhotoType != "" {
		t.Errorf("expected no photo type, got %q", c.PhotoType)
	}
}

// --- Category matching tests ---

func TestContactHasCategory(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cats     []string
		category string
		want     bool
	}{
		{"exact match", []string{"work", "friends"}, "work", true},
		{"case insensitive", []string{"Work", "Friends"}, "work", true},
		{"no match", []string{"work", "friends"}, "family", false},
		{"empty category", []string{"work"}, "", false},
		{"empty categories", nil, "work", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Contact{Categories: tt.cats}
			got := ContactHasCategory(c, tt.category)
			if got != tt.want {
				t.Errorf("ContactHasCategory(%v, %q) = %v, want %v", tt.cats, tt.category, got, tt.want)
			}
		})
	}
}

func TestVCardHasCategory(t *testing.T) {
	t.Parallel()
	vcard := `BEGIN:VCARD
VERSION:3.0
FN:Grouped Contact
CATEGORIES:work,friends,family
END:VCARD`

	tests := []struct {
		name     string
		category string
		want     bool
	}{
		{"match work", "work", true},
		{"match friends", "friends", true},
		{"match family", "family", true},
		{"case insensitive", "WORK", true},
		{"no match", "colleagues", false},
		{"empty category", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VCardHasCategory([]byte(vcard), tt.category)
			if got != tt.want {
				t.Errorf("VCardHasCategory(%q) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestVCardHasCategoryNoCategories(t *testing.T) {
	t.Parallel()
	if VCardHasCategory([]byte(testVCARD), "work") {
		t.Error("should not match category in vCard without CATEGORIES")
	}
}

func TestVCardHasCategoryMultiLine(t *testing.T) {
	t.Parallel()
	// vCard with line before CATEGORIES
	vcard := `BEGIN:VCARD
VERSION:3.0
FN:Test
EMAIL;TYPE=INTERNET:test@example.com
CATEGORIES:engineering,backend
END:VCARD`
	if !VCardHasCategory([]byte(vcard), "engineering") {
		t.Error("should match engineering category")
	}
	if !VCardHasCategory([]byte(vcard), "backend") {
		t.Error("should match backend category")
	}
	if VCardHasCategory([]byte(vcard), "frontend") {
		t.Error("should not match frontend category")
	}
}
