package imap

import (
	"strings"
	"testing"
)

func TestBodySectionHeaderFieldsNotAndFoldedValues(t *testing.T) {
	message := []byte("From: sender@example.com\r\nSubject: A long\r\n folded value\r\nX-Ignore: no\r\n\r\nBody\r\n")
	got, err := bodySection(message, "HEADER.FIELDS.NOT (X-IGNORE)")
	if err != nil {
		t.Fatalf("bodySection: %v", err)
	}
	want := "From: sender@example.com\r\nSubject: A long\r\n folded value\r\n\r\n"
	if string(got) != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestBodySectionHeaderFields(t *testing.T) {
	message := []byte("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Headers\r\nX-Custom: custom-value\r\n\r\nBody\r\n")
	got, err := bodySection(message, "HEADER.FIELDS (SUBJECT X-CUSTOM)")
	if err != nil {
		t.Fatalf("bodySection: %v", err)
	}
	want := "Subject: Headers\r\nX-Custom: custom-value\r\n\r\n"
	if string(got) != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestBodySectionMultipartParts(t *testing.T) {
	message := strings.Join([]string{
		"MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=parts",
		"",
		"--parts",
		"Content-Type: text/plain",
		"X-Part: first",
		"",
		"First body",
		"--parts",
		"Content-Type: text/html",
		"",
		"<p>Second body</p>",
		"--parts--",
		"",
	}, "\r\n")
	got, err := bodySection([]byte(message), "2")
	if err != nil {
		t.Fatalf("BODY[2]: %v", err)
	}
	if string(got) != "<p>Second body</p>" {
		t.Errorf("BODY[2] = %q", got)
	}
	mimeHeader, err := bodySection([]byte(message), "1.MIME")
	if err != nil {
		t.Fatalf("BODY[1.MIME]: %v", err)
	}
	if !strings.Contains(string(mimeHeader), "Content-Type: text/plain\r\n") || !strings.Contains(string(mimeHeader), "X-Part: first\r\n") {
		t.Errorf("BODY[1.MIME] = %q", mimeHeader)
	}
}

func TestParseBodyFetchPartialAndMalformed(t *testing.T) {
	request, ok, err := parseBodyFetch("BODY.PEEK[TEXT]<12.34>")
	if err != nil || !ok {
		t.Fatalf("parseBodyFetch: ok=%v err=%v", ok, err)
	}
	if request.section != "TEXT" || !request.partial || request.partialFrom != 12 || request.partialSize != 34 {
		t.Fatalf("request = %#v", request)
	}
	for _, token := range []string{"BODY[TEXT", "BODY[TEXT]garbage", "BODY[TEXT]<x.1>", "BODY[TEXT]<1.-2>", "BODY[TEXT]<1.0>"} {
		if _, ok, err := parseBodyFetch(token); !ok || err == nil {
			t.Errorf("parseBodyFetch(%q): ok=%v err=%v, want recognized error", token, ok, err)
		}
	}
}

func TestExtractLFOnlyMessageSections(t *testing.T) {
	message := []byte("Subject: LF only\nX-Test: yes\n\nBody\n")
	if got := string(extractHeaders(message)); got != "Subject: LF only\nX-Test: yes\n\n" {
		t.Errorf("headers = %q", got)
	}
	if got := string(extractBody(message)); got != "Body\n" {
		t.Errorf("body = %q", got)
	}
}
