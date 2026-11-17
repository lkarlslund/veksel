package jmap

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const appleCard = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"PRODID:-//Apple Inc.//iOS 17//EN\r\n" +
	"UID:card-1\r\n" +
	"N:Doe;Jane;Q.;Dr.;PhD\r\n" +
	"FN:Dr. Jane Q. Doe\r\n" +
	"NICKNAME:JD\r\n" +
	"ORG:Example Corp;Research\r\n" +
	"TITLE:Scientist\r\n" +
	"ROLE:Lead\r\n" +
	"EMAIL;TYPE=INTERNET;TYPE=WORK;TYPE=pref:jane@example.com\r\n" +
	"item1.EMAIL;TYPE=INTERNET:jane@home.example\r\n" +
	"item1.X-ABLabel:_$!<Other>!$_\r\n" +
	"TEL;TYPE=CELL;TYPE=VOICE:+1 555 0100\r\n" +
	"TEL;TYPE=WORK;TYPE=FAX:+1 555 0101\r\n" +
	"ADR;TYPE=HOME:;Apt 4;1 Main St;Springfield;IL;62701;USA\r\n" +
	"NOTE:Line one\\nLine two\\, with comma\r\n" +
	"BDAY:1985-04-12\r\n" +
	"BDAY;VALUE=text:circa 1900\r\n" +
	"URL;TYPE=WORK:https://example.com/jane\r\n" +
	"CATEGORIES:friends,work\r\n" +
	"PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRg==\r\n" +
	"X-SOCIALPROFILE;TYPE=twitter;X-USER=jane:https://twitter.com/jane\r\n" +
	"X-CUSTOM;X-PARAM=\"a;b\":opaque value\r\n" +
	"END:VCARD\r\n"

func decodeCard(t *testing.T, data string, itemID string) (*vcardDoc, map[string]any) {
	t.Helper()
	doc, err := parseVCard([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	card, _ := decodeContact(doc, itemID)
	return doc, card
}

func TestVCardToJSContactCommonProperties(t *testing.T) {
	_, card := decodeCard(t, appleCard, "item-1")
	want := map[string]any{
		"@type": "Card", "version": "1.0", "uid": "card-1", "prodId": "-//Apple Inc.//iOS 17//EN",
		"name": map[string]any{"full": "Dr. Jane Q. Doe", "components": []any{
			map[string]any{"kind": "surname", "value": "Doe"}, map[string]any{"kind": "given", "value": "Jane"},
			map[string]any{"kind": "given2", "value": "Q."}, map[string]any{"kind": "title", "value": "Dr."},
			map[string]any{"kind": "credential", "value": "PhD"}}},
		"nicknames":     map[string]any{"k1": map[string]any{"name": "JD"}},
		"organizations": map[string]any{"o1": map[string]any{"name": "Example Corp", "units": []any{map[string]any{"name": "Research"}}}},
		"titles":        map[string]any{"t1": map[string]any{"name": "Scientist", "kind": "title"}, "t2": map[string]any{"name": "Lead", "kind": "role"}},
		"emails": map[string]any{
			"e1": map[string]any{"address": "jane@example.com", "contexts": map[string]any{"work": true}, "pref": 1},
			"e2": map[string]any{"address": "jane@home.example"}},
		"phones": map[string]any{
			"p1": map[string]any{"number": "+1 555 0100", "features": map[string]any{"mobile": true, "voice": true}},
			"p2": map[string]any{"number": "+1 555 0101", "features": map[string]any{"fax": true}, "contexts": map[string]any{"work": true}}},
		"addresses": map[string]any{"a1": map[string]any{"contexts": map[string]any{"private": true}, "components": []any{
			map[string]any{"kind": "apartment", "value": "Apt 4"}, map[string]any{"kind": "name", "value": "1 Main St"},
			map[string]any{"kind": "locality", "value": "Springfield"}, map[string]any{"kind": "region", "value": "IL"},
			map[string]any{"kind": "postcode", "value": "62701"}, map[string]any{"kind": "country", "value": "USA"}}}},
		"notes":         map[string]any{"n1": map[string]any{"note": "Line one\nLine two, with comma"}},
		"anniversaries": map[string]any{"d1": map[string]any{"kind": "birth", "date": map[string]any{"@type": "PartialDate", "year": 1985, "month": 4, "day": 12}}},
		"links":         map[string]any{"l1": map[string]any{"uri": "https://example.com/jane", "contexts": map[string]any{"work": true}}},
		"keywords":      map[string]any{"friends": true, "work": true},
		"media":         map[string]any{"m1": map[string]any{"kind": "photo", "mediaType": "image/jpeg", "blobId": "item-1-media.m1"}},
	}
	if !reflect.DeepEqual(normalizeJSON(card), normalizeJSON(want)) {
		got, _ := json.MarshalIndent(card, "", " ")
		t.Fatalf("card mismatch:\n%s", got)
	}
}

func TestJSContactPatchPreservesUnknownVCardProperties(t *testing.T) {
	original, card := decodeCard(t, appleCard, "item-1")
	if err := applyPatch(card, map[string]any{
		"emails/e1/address":     "jane.doe@example.com",
		"notes/n1/note":         "Updated; note",
		"phones/p2":             nil,
		"keywords/vip":          true,
		"anniversaries/d1/date": map[string]any{"@type": "PartialDate", "month": 4, "day": 12},
		"example.com:custom":    map[string]any{"level": 3},
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := encodeContact(card, original, "item-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(updated.encode())
	for _, kept := range []string{"VERSION:3.0", "item1.X-ABLabel:_$!<Other>!$_", "X-SOCIALPROFILE;TYPE=twitter;X-USER=jane:https://twitter.com/jane",
		`X-CUSTOM;X-PARAM="a;b":opaque value`, "BDAY;VALUE=text:circa 1900", "PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRg==",
		"item1.EMAIL;TYPE=INTERNET:jane@home.example", "EMAIL;TYPE=INTERNET,work,pref:jane.doe@example.com"} {
		if !strings.Contains(encoded, kept) {
			t.Errorf("missing %q in\n%s", kept, encoded)
		}
	}
	if strings.Contains(encoded, "0101") {
		t.Errorf("removed phone survived:\n%s", encoded)
	}
	reparsed, err := parseVCard(updated.encode())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := decodeContact(reparsed, "item-1")
	delete(again, "updated")
	delete(card, "updated")
	if !reflect.DeepEqual(normalizeJSON(again), normalizeJSON(card)) {
		a, _ := json.MarshalIndent(again, "", " ")
		b, _ := json.MarshalIndent(card, "", " ")
		t.Fatalf("round trip mismatch:\n%s\nwant\n%s", a, b)
	}
	if again["example.com:custom"].(map[string]any)["level"] != float64(3) {
		t.Fatalf("JSPROP lost: %#v", again["example.com:custom"])
	}
}

func TestJSContactCreatesGroupCardWithStableKeys(t *testing.T) {
	card := map[string]any{"@type": "Card", "uid": "urn:uuid:group-1", "kind": "group", "name": map[string]any{"full": "Team"},
		"members": map[string]any{"urn:uuid:a": true, "urn:uuid:b": true},
		"emails":  map[string]any{"work": map[string]any{"address": "team@example.com", "pref": 2}}}
	doc, err := encodeContact(card, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(doc.encode())
	for _, want := range []string{"VERSION:4.0", "KIND:group", "MEMBER:urn:uuid:a", "MEMBER:urn:uuid:b", "EMAIL;PREF=2;PROP-ID=work:team@example.com", "FN:Team"} {
		if !strings.Contains(encoded, want) {
			t.Errorf("missing %q in\n%s", want, encoded)
		}
	}
	_, again := decodeCard(t, encoded, "x")
	if again["emails"].(map[string]any)["work"] == nil || again["kind"] != "group" || len(again["members"].(map[string]any)) != 2 {
		t.Fatalf("round trip = %#v", again)
	}
	if _, err := encodeContact(map[string]any{"uid": "x", "members": map[string]any{"urn:uuid:a": true}}, nil, "", nil); err == nil {
		t.Fatal("members accepted without kind group")
	}
}

func TestJSContactEmbedsUploadedPhotoBlob(t *testing.T) {
	card := map[string]any{"uid": "p", "name": map[string]any{"full": "Photo"}, "media": map[string]any{"m1": map[string]any{"kind": "photo", "blobId": "upload-1"}}}
	doc, err := encodeContact(card, nil, "", func(id string) ([]byte, string, error) {
		if id != "upload-1" {
			t.Fatalf("blob %q", id)
		}
		return []byte{0xff, 0xd8, 0xff}, "image/jpeg", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data := doc.encode()
	if !strings.Contains(string(data), "PHOTO:data:image/jpeg;base64,/9j/") {
		t.Fatalf("photo not embedded:\n%s", data)
	}
	payload, mediaType, ok := contactMedia(data, "item", "m1")
	if !ok || mediaType != "image/jpeg" || len(payload) != 3 {
		t.Fatalf("media = %v %q %v", payload, mediaType, ok)
	}
}

func TestVCardFoldingAndEscapingRoundTrip(t *testing.T) {
	long := strings.Repeat("æøå ", 40)
	card := map[string]any{"uid": "f", "name": map[string]any{"full": "Fold"}, "notes": map[string]any{"n1": map[string]any{"note": long + "; ,\\"}}}
	doc, err := encodeContact(card, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	data := string(doc.encode())
	for _, line := range strings.Split(data, "\r\n") {
		if len(line) > 75 {
			t.Fatalf("unfolded line %q", line)
		}
	}
	_, again := decodeCard(t, data, "f")
	if got := again["notes"].(map[string]any)["n1"].(map[string]any)["note"]; got != long+"; ,\\" {
		t.Fatalf("note = %q", got)
	}
}
