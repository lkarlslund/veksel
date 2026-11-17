package service

import (
	"bytes"
	"strings"
	"testing"
)

func TestSubmissionMIMERoundTrip(t *testing.T) {
	attachments := []SubmissionAttachment{
		{Name: "report ø.pdf", ContentType: "application/pdf", Data: []byte("pdf payload")},
		{Name: "notes.txt", ContentType: "text/plain; charset=utf-8", Data: []byte("notes")},
	}
	contentType, body, err := BuildSubmissionMIME("Hello world", "", attachments)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@example.test\r\nSubject: Files\r\nImportance: low\r\nX-Priority: 5\r\nMIME-Version: 1.0\r\nContent-Type: " + contentType + "\r\nX-Veksel-Send-Mode: send_as\r\nX-Veksel-Require-TLS: true\r\n\r\n")
	raw = append(raw, body...)
	parsed, err := ParseSubmissionMIME(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Body != "Hello world" || parsed.Mode != SendAs || parsed.Importance != MailImportanceLow || !parsed.RequireTLS || len(parsed.Attachments) != 2 {
		t.Fatalf("parsed submission = %+v", parsed)
	}
	for index := range attachments {
		if parsed.Attachments[index].Name != attachments[index].Name || parsed.Attachments[index].ContentType != strings.Split(attachments[index].ContentType, ";")[0] || !bytes.Equal(parsed.Attachments[index].Data, attachments[index].Data) {
			t.Fatalf("attachment %d = %+v", index, parsed.Attachments[index])
		}
	}
}

func TestSubmissionMIMERejectsUnsafeOrOversizedAttachments(t *testing.T) {
	if _, _, err := BuildSubmissionMIME("", "", []SubmissionAttachment{{Name: "", Data: []byte("x")}}); err == nil {
		t.Fatal("empty attachment name was accepted")
	}
	if _, _, err := BuildSubmissionMIME("", "", []SubmissionAttachment{{Name: "large.bin", Data: make([]byte, MaxSubmissionAttachmentBytes+1)}}); err == nil {
		t.Fatal("oversized attachment was accepted")
	}
	many := make([]SubmissionAttachment, MaxSubmissionAttachments+1)
	if _, _, err := BuildSubmissionMIME("", "", many); err == nil {
		t.Fatal("too many attachments were accepted")
	}
}
