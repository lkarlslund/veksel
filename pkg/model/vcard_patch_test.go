package model

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	vcard "github.com/emersion/go-vcard"
)

func TestPatchContactVCardPreservesUnmanagedPropertiesAndParameters(t *testing.T) {
	t.Parallel()
	original := []byte("BEGIN:VCARD\r\n" +
		"VERSION:3.0\r\n" +
		"UID:stable-id\r\n" +
		"FN;LANGUAGE=da:Old Name\r\n" +
		"N:Doe;Old;;;\r\n" +
		"EMAIL;TYPE=HOME,PREF:old@example.test\r\n" +
		"TEL;TYPE=CELL;PREF=1:+4512345678\r\n" +
		"ADR;TYPE=HOME:;;Old Street;Town;;;DK\r\n" +
		"ADR;TYPE=OTHER:;;Preserved Road;Elsewhere;;;DK\r\n" +
		"KIND:group\r\n" +
		"item1.MEMBER;PREF=1:urn:uuid:member\r\n" +
		"IMPP;TYPE=HOME:xmpp:old@example.test\r\n" +
		"ANNIVERSARY:2000-01-02\r\n" +
		"X-ABUID:vendor-value\r\n" +
		"X-VEKSEL-LOYALTY:old\r\n" +
		"PHOTO;VALUE=URI:https://example.test/photo.jpg\r\n" +
		"NOTE:old\r\n" +
		"END:VCARD\r\n")
	update := ParseVCard(original)
	update.FN = "New, Name"
	update.GivenName = "New"
	update.FamilyName = "Name"
	update.Note = "line one\nline two; exact"
	update.Addresses[0].Street = "New Street"
	update.CustomFields = map[string]string{"loyalty": "new"}

	got, err := PatchContactVCard(original, update, false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"VERSION:3.0", "UID:stable-id", "FN;LANGUAGE=da:New\\, Name",
		"EMAIL;TYPE=HOME,PREF:old@example.test", "TEL;TYPE=CELL;PREF=1:+4512345678",
		"ADR;TYPE=HOME:;;New Street;Town;;;DK", "ADR;TYPE=OTHER:;;Preserved Road;Elsewhere;;;DK",
		"KIND:group", "item1.MEMBER;PREF=1:urn:uuid:member", "IMPP;TYPE=HOME:xmpp:old@example.test",
		"ANNIVERSARY:2000-01-02", "X-ABUID:vendor-value", "X-VEKSEL-LOYALTY:new",
		"PHOTO;VALUE=URI:https://example.test/photo.jpg", "NOTE:line one\\nline two\\; exact",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("patched card is missing %q:\n%s", want, text)
		}
	}
	decoder := vcard.NewDecoder(bytes.NewReader(got))
	card, err := decoder.Decode()
	if err != nil {
		t.Fatalf("go-vcard cannot decode result: %v\n%s", err, got)
	}
	if card.Value(vcard.FieldFormattedName) != "New, Name" {
		t.Errorf("decoded FN = %q", card.Value(vcard.FieldFormattedName))
	}
}

func TestPatchContactVCardPreservesVersionAndPhotoUntilExplicitChange(t *testing.T) {
	t.Parallel()
	original := []byte("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:id\r\nFN:Name\r\nPHOTO;VALUE=uri:https://example.test/p\r\nEND:VCARD\r\n")
	contact := ParseVCard(original)
	contact.FN = "Changed"
	got, err := PatchContactVCard(original, contact, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("VERSION:4.0")) || !bytes.Contains(got, []byte("PHOTO;VALUE=uri:https://example.test/p")) {
		t.Fatalf("version or URI photo was not preserved:\n%s", got)
	}
	contact.PhotoURI = ""
	contact.PhotoData = []byte("image")
	contact.PhotoType = "jpeg"
	got, err = PatchContactVCard(original, contact, true)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("https://example.test/p")) || !bytes.Contains(got, []byte("PHOTO;MEDIATYPE=image/jpeg:data:image/jpeg;base64,aW1hZ2U=")) {
		t.Fatalf("photo replacement failed:\n%s", got)
	}
	parsed := ParseVCard(got)
	if !bytes.Equal(parsed.PhotoData, []byte("image")) || parsed.PhotoType != "JPEG" {
		t.Fatalf("vCard 4 data URI photo did not parse: %#v", parsed)
	}
}

func TestPatchContactGroupMembersPreservesOpaqueProperties(t *testing.T) {
	t.Parallel()
	original := []byte("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:group\r\nKIND:group\r\nFN:Old team\r\nitem1.MEMBER;PREF=1:urn:uuid:kept\r\nMEMBER:mailto:removed@example.test\r\nX-APPLE-CUSTOM:opaque\r\nEND:VCARD\r\n")
	update := ParseVCard(original)
	update.FN = "New team"
	update.Members = []string{"urn:uuid:kept", "mailto:added@example.test"}
	got, err := PatchContactVCard(original, update, false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"KIND:group", "FN:New team", "item1.MEMBER;PREF=1:urn:uuid:kept", "MEMBER:mailto:added@example.test", "X-APPLE-CUSTOM:opaque"} {
		if !strings.Contains(text, want) {
			t.Errorf("patched group is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "removed@example.test") {
		t.Fatalf("removed member survived patch:\n%s", text)
	}
}

func TestPatchContactGroupRequiresVCard4(t *testing.T) {
	t.Parallel()
	original := []byte("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:id\r\nFN:Team\r\nEND:VCARD\r\n")
	if _, err := PatchContactVCard(original, Contact{FN: "Team", Kind: "group", Members: []string{"mailto:a@example.test"}}, false); err == nil {
		t.Fatal("vCard 3 group update succeeded")
	}
	if _, err := PatchContactVCard(original, Contact{FN: "Person", Members: []string{"mailto:a@example.test"}}, false); err == nil {
		t.Fatal("individual MEMBER update succeeded")
	}
}

func TestPatchContactVCardRejectsUnsafeInput(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"FN:No envelope\r\n",
		"BEGIN:VCARD\r\nVERSION:2.1\r\nUID:id\r\nFN:Name\r\nEND:VCARD\r\n",
		"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:id\r\nEND:VCARD\r\n",
	} {
		if _, err := PatchContactVCard([]byte(input), Contact{FN: "Changed"}, false); err == nil {
			t.Errorf("PatchContactVCard(%q) succeeded", input)
		}
	}
}

func TestPatchContactVCardAcceptsValidCardWithoutOptionalUID(t *testing.T) {
	t.Parallel()
	original := []byte("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:No UID\r\nEND:VCARD\r\n")
	got, err := PatchContactVCard(original, Contact{FN: "Still no UID"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("UID:")) || !bytes.Contains(got, []byte("FN:Still no UID")) {
		t.Fatalf("optional UID handling changed the card:\n%s", got)
	}
}

func TestContactToVCardEscapesAndFoldsUTF8(t *testing.T) {
	t.Parallel()
	card := ContactToVCard(Contact{UID: "id", FN: strings.Repeat("Å", 60) + ", name", Note: "one\ntwo;three"})
	for _, line := range strings.Split(strings.TrimSuffix(string(card), "\r\n"), "\r\n") {
		if len(line) > 75 {
			t.Errorf("physical line has %d bytes: %q", len(line), line)
		}
		if !utf8.ValidString(line) {
			t.Errorf("fold split a UTF-8 rune: %q", line)
		}
	}
	decoder := vcard.NewDecoder(bytes.NewReader(card))
	decoded, err := decoder.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Value(vcard.FieldFormattedName) != strings.Repeat("Å", 60)+", name" {
		t.Errorf("formatted name did not round-trip: %q", decoded.Value(vcard.FieldFormattedName))
	}
}
