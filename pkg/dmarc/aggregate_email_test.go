package dmarc

import (
	"bytes"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestBuildAggregateEmailUsesAlignedStableIdentityAndGZIPAttachment(t *testing.T) {
	report := AggregateMailReport{Recipient: "reports@external.test", PolicyDomain: "sender.example", SubmitterDomain: "receiver.test", ReportID: "stable-report", Filename: "report.xml.gz", GZIP: []byte("gzip-data")}
	message, err := BuildAggregateEmail(report, time.Date(2026, 8, 28, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("From") != "dmarc@receiver.test" || parsed.Header.Get("To") != report.Recipient || !strings.Contains(parsed.Header.Get("Message-ID"), report.ReportID) || !strings.HasPrefix(parsed.Header.Get("Content-Type"), "multipart/mixed;") {
		t.Fatalf("headers=%#v", parsed.Header)
	}
	body := string(message)
	if !strings.Contains(body, "Content-Type: application/gzip") || !strings.Contains(body, "Z3ppcC1kYXRh") {
		t.Fatalf("message=%s", body)
	}
}
