package model

import (
	"bytes"
	"io"
	"maps"
	"strings"
	"testing"
	"time"
)

// FuzzMessageHeaders checks the RFC 5322 header splitter and parsers on
// arbitrary messages, and that header rewriting keeps the message parseable.
func FuzzMessageHeaders(f *testing.F) {
	for _, seed := range []string{
		"From: a@example.com\r\nSubject: =?UTF-8?Q?caf=C3=A9?=\r\n folded\r\nReceived: one\r\nReceived: two\r\n\r\nbody",
		"Subject: x\n\nbody\r\n\r\nmore",
		"no header separator",
		" leading continuation\r\nA: b\r\n\r\n",
		"A:\r\nB : c\r\n\tfold\r\n\r\n",
		"\r\n\r\n",
		"",
		"Subject: " + strings.Repeat(" x\r\n", 100) + "\r\n",
		"Content-Transfer-Encoding: base64\r\n\r\naGVsbG8=",
	} {
		f.Add(seed, "replacement value")
	}
	f.Fuzz(func(t *testing.T, message, value string) {
		data := []byte(message)
		head, body := SplitHeaderBody(data)
		if !bytes.Equal(append(append([]byte(nil), head...), body...), data) {
			t.Fatalf("head %q and body %q do not rebuild %q", head, body, data)
		}
		headers, parsedBody := ParseMessageHeaders(data)
		_ = ParseItemHeaders(data)
		_ = ParseHeaderValues(data)
		for _, value := range headers {
			_ = DecodeHeaderValue(value)
		}

		rebuilt := RebuildMessage(data, headers, parsedBody)
		again, againBody := ParseMessageHeaders(rebuilt)
		if !maps.Equal(again, headers) || !bytes.Equal(againBody, parsedBody) {
			t.Fatalf("rebuilding %q gave %q: headers %v, want %v", data, rebuilt, again, headers)
		}

		replaced := ReplaceHeaderField(data, "X-Fuzz", value)
		if values := ParseHeaderValues(replaced)["x-fuzz"]; len(values) != 1 {
			t.Fatalf("replacing X-Fuzz in %q with %q left %d fields: %q", data, value, len(values), replaced)
		}
		built := BuildMessage(map[string]string{"X-Fuzz": value}, nil)
		if values := ParseHeaderValues(built)["x-fuzz"]; len(values) != 1 {
			t.Fatalf("building X-Fuzz: %q gave %d fields: %q", value, len(values), built)
		}

		for _, encoding := range []string{"base64", "quoted-printable", "7bit"} {
			_, _ = io.Copy(io.Discard, TransferDecoder(bytes.NewReader(body), encoding))
		}
	})
}

// FuzzVCard parses arbitrary vCards with the contact projection, search
// matcher and structural validator, and checks that patching a valid card
// keeps it valid.
func FuzzVCard(f *testing.F) {
	for _, seed := range []string{
		"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:abc\r\nFN:John Doe\r\nN:Doe;John;;;\r\nEMAIL;TYPE=INTERNET:john@example.com\r\nTEL;TYPE=CELL:+1 555\r\nADR;TYPE=HOME:;;1 Main St;Town;;123;USA\r\nCATEGORIES:a,b\\,c\r\nEND:VCARD\r\n",
		"BEGIN:VCARD\r\nVERSION:4.0\r\nKIND:group\r\nFN:Team\r\nMEMBER:urn:uuid:1\r\nPHOTO:data:image/png;base64,iVBORw0KGgo=\r\nEND:VCARD\r\n",
		"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Fold\r\nNOTE:long\r\n  note\r\n\tmore\r\nitem1.X-CUSTOM;X-PARAM=\"a:b\":v\r\nEND:VCARD\r\n",
		"BEGIN:VCARD\r\nVERSION:3.0\r\nVERSION:4.0\r\nFN:x\r\nEND:VCARD",
		"BEGIN:VCARD\r\nFN:\r\nEND:VCARD",
		"",
		"\x00\xff",
	} {
		f.Add(seed, "john")
	}
	f.Fuzz(func(t *testing.T, card, query string) {
		data := []byte(card)
		contact := ParseVCard(data)
		_ = VCardMatchesSearch(data, query)
		_ = VCardHasCategory(data, query)
		_ = ContactHasCategory(contact, query)
		if ValidateContactVCard(data) == nil {
			if strings.TrimSpace(contact.FN) == "" {
				contact.FN = "Name"
			}
			patched, err := PatchContactVCard(data, contact, true)
			if err != nil {
				return
			}
			if err := ValidateContactVCard(patched); err != nil {
				t.Fatalf("patching %q produced invalid %q: %v", data, patched, err)
			}
			categories, err := PatchContactCategories(data, []string{query})
			if err == nil {
				if err := ValidateContactVCard(categories); err != nil {
					t.Fatalf("patching categories of %q produced invalid %q: %v", data, categories, err)
				}
			}
		}
	})
}

// FuzzIndexFold checks that case-insensitive match ranges always index the
// searched string itself, whatever lowering does to byte lengths.
func FuzzIndexFold(f *testing.F) {
	for _, seed := range [][2]string{{"Hello World", "world"}, {"İİİ x", "x"}, {"\xff\xfe needle", "NEEDLE"}, {"ȺȺ a", "ⱥ a"}, {"", "x"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, s, substr string) {
		start, end := IndexFold(s, substr)
		if start == -1 && end == -1 {
			return
		}
		if start < 0 || end < start || end > len(s) {
			t.Fatalf("IndexFold(%q, %q) = %d, %d", s, substr, start, end)
		}
	})
}

// TestHeaderAndVCardUnfoldingStayLinear guards against unfolding that
// appended each continuation line to a string, copying the value once per
// folded line: 400k folds once took minutes.
func TestHeaderAndVCardUnfoldingStayLinear(t *testing.T) {
	folds := strings.Repeat(" b\r\n", 400000)
	start := time.Now()
	headers, _ := ParseMessageHeaders([]byte("Subject: a\r\n" + folds + "\r\nbody"))
	if len(headers["Subject"]) != len("a")+400000*2 {
		t.Fatalf("unfolded subject has %d bytes", len(headers["Subject"]))
	}
	contact := ParseVCard([]byte("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:x\r\nNOTE:a\r\n" + folds + "END:VCARD\r\n"))
	if err := ValidateContactVCard([]byte("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:x\r\nNOTE:a\r\n" + folds + "END:VCARD\r\n")); err != nil {
		t.Fatal(err)
	}
	if len(contact.Note) == 0 {
		t.Fatal("folded NOTE was lost")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("unfolding 400k continuation lines took %v", elapsed)
	}
}
