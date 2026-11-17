package eas

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestWBXMLRoundTripAcrossCodePages(t *testing.T) {
	want := E(0, "Sync",
		E(0, "Collections",
			E(0, "Collection",
				T(0, "SyncKey", "42"),
				E(0, "ApplicationData", T(2, "Subject", "Hej verden"), O(17, "Data", []byte{0, 1, 2})),
			),
		),
	)
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tag != "Sync" || got.Descendant("SyncKey").Text != "42" || got.Descendant("Subject").Text != "Hej verden" {
		t.Fatalf("decoded tree = %#v", got)
	}
	data := got.Descendant("Data").Opaque
	if len(data) != 3 || data[2] != 2 {
		t.Fatalf("opaque data = %v", data)
	}
}

func TestWBXMLRoundTripEAS16EmailFields(t *testing.T) {
	want := E(0, "ApplicationData",
		T(2, "ReplyTo", "reply@example.test"),
		T(2, "Flag", "follow-up"),
		T(22, "ConversationId", "conversation"),
		T(22, "IsDraft", "1"),
		T(22, "Bcc", "hidden@example.test"),
	)
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"ReplyTo", "Flag", "ConversationId", "IsDraft", "Bcc"} {
		if got.Descendant(tag) == nil {
			t.Errorf("decoded document is missing %s", tag)
		}
	}
}

func TestWBXMLRoundTripPersonalInformationFields(t *testing.T) {
	want := E(0, "ApplicationData",
		T(1, "BusinessFaxNumber", "+45 12345678"),
		T(1, "FileAs", "Doe, Jane"),
		T(4, "UID", "event-1"),
		T(4, "OnlineMeetingConfLink", "https://meet.example.test/1"),
		T(9, "Subject", "Follow up"),
		T(12, "NickName", "JD"),
		T(23, "MessageClass", "IPM.StickyNote"),
	)
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"BusinessFaxNumber", "FileAs", "UID", "OnlineMeetingConfLink", "Subject", "NickName", "MessageClass"} {
		if got.Descendant(tag) == nil {
			t.Errorf("decoded document is missing %s", tag)
		}
	}
}

func TestWBXMLDecodePreservesUnknownOptionalElement(t *testing.T) {
	got, err := Decode([]byte{0x03, 0x01, 0x6A, 0x00, 0x00, 0x19, 0x3F})
	if err != nil {
		t.Fatal(err)
	}
	if got.Page != 25 || got.Tag != "_Unknown_25_3F" {
		t.Fatalf("decoded unknown element=%#v", got)
	}
}

func TestWBXMLDecodeDistinguishesMissingTrailingEndsFromPayloadTruncation(t *testing.T) {
	encoded, err := Encode(E(0, "Sync", E(0, "Collections", E(0, "Collection", T(0, "SyncKey", "42")))))
	if err != nil {
		t.Fatal(err)
	}
	_, structuralErr := Decode(encoded[:len(encoded)-3])
	var suffix *MissingTrailingEndError
	if !errors.Is(structuralErr, ErrMissingTrailingEnd) || !errors.As(structuralErr, &suffix) || suffix.Page != 0 || suffix.Tag != "Collection" || suffix.Depth != 3 {
		t.Fatalf("missing closing elements error = %v, suffix=%#v", structuralErr, suffix)
	}

	opaque, err := Encode(O(17, "Data", []byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(opaque[:len(opaque)-4]); err == nil || errors.Is(err, ErrMissingTrailingEnd) {
		t.Fatalf("truncated opaque error = %v, want non-structural failure", err)
	}
}

func TestWBXMLDecodePrefixStopsBeforeMalformedApplicationData(t *testing.T) {
	document := E(0, "Sync", E(0, "Collections", E(0, "Collection",
		T(0, "SyncKey", "next-key"),
		E(0, "Commands", E(0, "Add",
			T(0, "ServerId", "broken-item"),
			E(0, "ApplicationData", T(17, "Latitude", "55.6761")),
		)),
	)))
	encoded, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	marker := append([]byte("55.6761"), 0)
	end := bytes.Index(encoded, marker)
	if end < 0 {
		t.Fatal("fixture marker is missing")
	}
	malformed := encoded[:end+len(marker)]
	if _, err := Decode(malformed); !errors.Is(err, ErrMissingTrailingEnd) {
		t.Fatalf("full decode error = %v", err)
	}
	prefix, err := DecodePrefix(malformed, 0, "ApplicationData")
	if err != nil {
		t.Fatal(err)
	}
	collection := prefix.Descendant("Collection")
	command := collection.Child("Commands").Child("Add")
	if collection.Child("SyncKey").Text != "next-key" || command.Child("ServerId").Text != "broken-item" || command.Child("ApplicationData") == nil || len(command.Child("ApplicationData").Children) != 0 {
		t.Fatalf("prefix = %#v", prefix)
	}
	if _, err := DecodePrefix(malformed[:8], 0, "ApplicationData"); err == nil {
		t.Fatal("malformed envelope prefix succeeded")
	}
}

// TestDecodeBoundsNestingAndStringRuns pins two hostile shapes: one byte per
// nested open tag once recursed without limit, and a long run of inline
// string tokens was concatenated quadratically.
func TestDecodeBoundsNestingAndStringRuns(t *testing.T) {
	seed, err := Encode(E(7, "FolderSync", T(7, "SyncKey", "0")))
	if err != nil {
		t.Fatal(err)
	}
	// seed is header, page switch, FolderSync (with content), SyncKey ...
	header, open := seed[:6], seed[6]
	deep := append(bytes.Clone(header), bytes.Repeat([]byte{open}, 200000)...)
	if _, err := Decode(deep); err == nil {
		t.Fatal("decoded 200000 nested elements")
	}

	runs := append(bytes.Clone(header), open)
	runs = append(runs, bytes.Repeat([]byte{wbxmlString, 'a', 0}, 200000)...)
	runs = append(runs, wbxmlEnd)
	start := time.Now()
	node, err := Decode(runs)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second || len(node.Text) != 200000 {
		t.Fatalf("decoded %d text bytes in %v", len(node.Text), elapsed)
	}
}

// TestWBXMLSettingsTokensMatchMSASWBXML replays the bytes an iOS client sends
// for Settings/DeviceInformation. The Settings code page once had every token
// from Get (0x07) to PhoneNumber shifted by two, so a real client's Model
// decoded as Password and its FriendlyName as Model.
func TestWBXMLSettingsTokensMatchMSASWBXML(t *testing.T) {
	raw := []byte{0x03, 0x01, 0x6A, 0x00, 0x00, 0x12,
		0x45,       // Settings
		0x56,       // DeviceInformation
		0x48,       // Set
		0x57, 0x03, // Model
	}
	raw = append(raw, "iPhone15,2"...)
	raw = append(raw, 0x00, 0x01, 0x59, 0x03) // END Model, FriendlyName
	raw = append(raw, "Alice"...)
	raw = append(raw, 0x00, 0x01, 0x5A, 0x03) // END FriendlyName, OS
	raw = append(raw, "iOS 18.1"...)
	raw = append(raw, 0x00, 0x01, 0x01, 0x01, 0x01)
	root, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	set := root.Child("DeviceInformation").Child("Set")
	if set == nil || nodeText(set, "Model") != "iPhone15,2" || nodeText(set, "FriendlyName") != "Alice" || nodeText(set, "OS") != "iOS 18.1" {
		t.Fatalf("decoded Settings = %#v", root)
	}
	for tag, want := range map[string]byte{"Get": 0x07, "Set": 0x08, "Oof": 0x09, "UserInformation": 0x1D, "EmailAddresses": 0x1E, "SmtpAddress": 0x1F, "PrimarySmtpAddress": 0x23} {
		if got := reverseCodePages[18][tag]; got != want {
			t.Errorf("Settings %s token = %#x, want %#x", tag, got, want)
		}
	}
	if got := reverseCodePages[14]["AccountOnlyRemoteWipe"]; got != 0x3B {
		t.Errorf("AccountOnlyRemoteWipe token = %#x, want 0x3b", got)
	}
}

// TestWBXMLCalendarTimeZoneName pins the MS-ASCAL element name: the table
// once spelled it Timezone, so encoding calendar:TimeZone failed and every
// calendar item a client sent decoded under a name nothing looked up.
func TestWBXMLCalendarTimeZoneName(t *testing.T) {
	encoded, err := Encode(E(0, "ApplicationData", T(4, "TimeZone", "xP///w==")))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || decoded.Child("TimeZone") == nil || reverseCodePages[4]["TimeZone"] != 0x05 {
		t.Fatalf("calendar TimeZone = %#v, %v", decoded, err)
	}
}

// TestWBXMLCodePagesHaveUniqueNames keeps the encoder's reverse map total: a
// duplicated name inside one page would silently encode as the wrong token.
func TestWBXMLCodePagesHaveUniqueNames(t *testing.T) {
	for page, tags := range codePages {
		if len(reverseCodePages[page]) != len(tags) {
			t.Errorf("page %d has duplicate tag names", page)
		}
	}
	for _, page := range []byte{10, 11, 15, 16, 25} {
		if len(codePages[page]) == 0 {
			t.Errorf("code page %d is missing", page)
		}
	}
}

func FuzzDecodeWBXML(f *testing.F) {
	seed, _ := Encode(E(7, "FolderSync", T(7, "SyncKey", "0")))
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(data)
	})
}
