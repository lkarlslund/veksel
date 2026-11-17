package model

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestBuildMessageRefusesHeaderInjection(t *testing.T) {
	t.Parallel()
	subject := "Out of office\r\nFrom: ceo@example.com\nBcc: victim@example.net\rX: y"
	for name, message := range map[string][]byte{
		"build":   BuildMessage(map[string]string{"From": "user@example.com", "Subject": subject}, []byte("away")),
		"rebuild": RebuildMessage([]byte("From: user@example.com\r\nSubject: hi\r\n\r\n"), map[string]string{"From": "user@example.com", "Subject": subject}, []byte("away")),
		"replace": ReplaceHeaderField([]byte("From: user@example.com\r\nSubject: hi\r\n\r\naway"), "Subject", subject),
	} {
		values := ParseHeaderValues(message)
		if from := values["from"]; len(from) != 1 || from[0] != "user@example.com" || len(values["bcc"]) != 0 || len(values["x"]) != 0 {
			t.Fatalf("%s: injected fields in\n%s", name, message)
		}
	}
	// A fold (a break followed by white space) stays a fold.
	folded := BuildMessage(map[string]string{"Subject": "a\r\n\tb"}, nil)
	if string(folded) != "Subject: a\r\n\tb\r\n\r\n" {
		t.Fatalf("folded = %q", folded)
	}
}

func TestSplitHeaderBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, head, body string
		nilBody              bool
	}{
		{name: "crlf", in: "A: 1\r\n\r\nbody\r\n", head: "A: 1\r\n\r\n", body: "body\r\n"},
		{name: "lf only", in: "A: 1\n\nbody\n", head: "A: 1\n\n", body: "body\n"},
		{name: "no separator", in: "A: 1\r\nB: 2\r\n", head: "A: 1\r\nB: 2\r\n", nilBody: true},
		{name: "lf separator before crlf in body", in: "A: 1\n\nx\r\n\r\ny", head: "A: 1\n\n", body: "x\r\n\r\ny"},
		{name: "empty body", in: "A: 1\r\n\r\n", head: "A: 1\r\n\r\n", body: ""},
	}
	for _, tt := range tests {
		head, body := SplitHeaderBody([]byte(tt.in))
		if string(head) != tt.head || string(body) != tt.body || (body == nil) != tt.nilBody {
			t.Errorf("%s: head=%q body=%q (nil=%v)", tt.name, head, body, body == nil)
		}
	}
}

func TestParseMessageHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		headers map[string]string
		body    string
	}{
		{"crlf", "From: a@x\r\nSubject: Hi\r\n\r\nBody", map[string]string{"From": "a@x", "Subject": "Hi"}, "Body"},
		{"lf only keeps whole body", "From: a@x\n\nBody", map[string]string{"From": "a@x"}, "Body"},
		{"folded with colons", "Received: from a\r\n\tby b; 12:30:00\r\n  +0000\r\nX: y\r\n\r\n", map[string]string{"Received": "from a by b; 12:30:00 +0000", "X": "y"}, ""},
		{"duplicate last wins", "X: 1\r\nX: 2\r\n\r\n", map[string]string{"X": "2"}, ""},
		{"original case kept", "mESSage-ID: <1>\r\n\r\n", map[string]string{"mESSage-ID": "<1>"}, ""},
		{"no separator", "From: a@x\r\nSubject: Empty", map[string]string{"From": "a@x", "Subject": "Empty"}, ""},
		{"encoded words not decoded", "Subject: =?UTF-8?Q?h=C3=A9?=\r\n\r\n", map[string]string{"Subject": "=?UTF-8?Q?h=C3=A9?="}, ""},
		{"garbage line ignored", "nocolon\r\nA: 1\r\n\r\n", map[string]string{"A": "1"}, ""},
	}
	for _, tt := range tests {
		headers, body := ParseMessageHeaders([]byte(tt.in))
		if !reflect.DeepEqual(headers, tt.headers) || string(body) != tt.body || body == nil {
			t.Errorf("%s: headers=%v body=%q", tt.name, headers, body)
		}
	}
}

func TestParseItemHeaders(t *testing.T) {
	t.Parallel()
	got := ParseItemHeaders([]byte("message-id: <1>\nSUBJECT: a\n b\nReceived: one\nReceived: two\n\nX-Body: no\n"))
	want := map[string]string{"Message-Id": "<1>", "Subject": "a b", "Received": "one"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseHeaderValues(t *testing.T) {
	t.Parallel()
	got := ParseHeaderValues([]byte("Received: one\r\nreceived: two\r\n three\r\nTo: a@x\r\n\r\nX: body\r\n"))
	want := map[string][]string{"received": {"one", "two three"}, "to": {"a@x"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRebuildMessagePreservesOrderAndRepeatedFields(t *testing.T) {
	t.Parallel()
	original := []byte("Received: from c by d;\n\tTue, 1 Jan 2026 00:00:01 +0000\r\n" +
		"Received: from a by b; Tue, 1 Jan 2026 00:00:00 +0000\r\n" +
		"From: a@x\r\nSubject: old\r\nX-Drop: peer\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\nbody\r\n")
	headers, body := ParseMessageHeaders(original)
	headers["Subject"] = "new"
	delete(headers, "X-Drop")
	headers["X-Added"] = "yes"
	headers["Authentication-Results"] = "mx; none"
	got := string(RebuildMessage(original, headers, body))
	want := "Authentication-Results: mx; none\r\nX-Added: yes\r\n" +
		"Received: from c by d;\r\n\tTue, 1 Jan 2026 00:00:01 +0000\r\n" +
		"Received: from a by b; Tue, 1 Jan 2026 00:00:00 +0000\r\n" +
		"From: a@x\r\nSubject: new\r\nX-Dup: 1\r\nX-Dup: 2\r\n\r\nbody\r\n"
	if got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	if values := ParseHeaderValues([]byte(got))["received"]; len(values) != 2 {
		t.Fatalf("Received fields = %q", values)
	}
	// A changed repeated field collapses to its new value at the first position.
	headers["X-Dup"] = "3"
	if got := string(RebuildMessage(original, headers, body)); !strings.Contains(got, "Subject: new\r\nX-Dup: 3\r\n\r\n") {
		t.Fatalf("changed repeated field: %q", got)
	}
	if got := string(PrependHeaderField([]byte("A: 1\r\n\r\nx"), "Received: from a\r\n\tby b")); got != "Received: from a\r\n\tby b\r\nA: 1\r\n\r\nx" {
		t.Fatalf("PrependHeaderField = %q", got)
	}
}

func TestDecodeHeaderValue(t *testing.T) {
	t.Parallel()
	if got := DecodeHeaderValue("=?UTF-8?Q?h=C3=A9llo?= world"); got != "héllo world" {
		t.Errorf("decoded = %q", got)
	}
	if got := DecodeHeaderValue("=?bogus?x?zz?="); got != "=?bogus?x?zz?=" {
		t.Errorf("undecodable value changed: %q", got)
	}
}

func TestTransferDecoder(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"base64":            "aGk=",
		" Quoted-Printable": "h=69",
		"7bit":              "hi",
		"":                  "hi",
	}
	for encoding, in := range tests {
		out, err := io.ReadAll(TransferDecoder(strings.NewReader(in), encoding))
		if err != nil || string(out) != "hi" {
			t.Errorf("%q: out=%q err=%v", encoding, out, err)
		}
	}
}
