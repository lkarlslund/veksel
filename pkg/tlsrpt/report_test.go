package tlsrpt

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestBuildReportProducesStableStandardsShape(t *testing.T) {
	aggregates := []Aggregate{{ID: "b", Day: "2026-08-18", Policy: AppliedPolicy{Type: PolicyTypeSTS, Domain: "example.test", Strings: []string{"version: STSv1", "mode: testing"}, MX: []string{"*.example.test"}},
		SuccessfulSessions: 12, FailedSessions: 2, Failures: []FailureDetail{{ResultType: ResultSTARTTLSNotSupported, ReceivingMXHostname: "mx.example.test", FailedSessionCount: 2}}}}
	metadata := ReportMetadata{OrganizationName: "Veksel Test", ContactInfo: "postmaster@sender.test", SubmitterDomain: "sender.test"}
	report, filename, err := BuildReport("2026-08-18", aggregates, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if report.DateRange.Start.Format("2006-01-02T15:04:05Z07:00") != "2026-08-18T00:00:00Z" || report.DateRange.End.Format("2006-01-02T15:04:05Z07:00") != "2026-08-19T00:00:00Z" {
		t.Fatalf("date range = %#v", report.DateRange)
	}
	if !strings.HasPrefix(report.ReportID, "veksel-") || !strings.HasPrefix(filename, "sender.test!example.test!") || !strings.HasSuffix(filename, ".json.gz") {
		t.Fatalf("report id %q filename %q", report.ReportID, filename)
	}
	compressed, err := MarshalReportGZIP(report)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	policies, ok := decoded["policies"].([]any)
	if !ok || len(policies) != 1 {
		t.Fatalf("JSON = %s", data)
	}
	policy := policies[0].(map[string]any)
	summary := policy["summary"].(map[string]any)
	if summary["total-successful-session-count"] != float64(12) || summary["total-failure-session-count"] != float64(2) {
		t.Fatalf("summary = %#v", summary)
	}

	second, secondFilename, err := BuildReport("2026-08-18", aggregates, metadata)
	if err != nil || second.ReportID != report.ReportID || secondFilename != filename {
		t.Fatalf("unstable report = %#v %q %v", second, secondFilename, err)
	}
	secondCompressed, err := MarshalReportGZIP(second)
	if err != nil || !bytes.Equal(compressed, secondCompressed) {
		t.Fatal("gzip output is not deterministic")
	}
}

func TestBuildReportEmitsEmptyFailureArray(t *testing.T) {
	report, _, err := BuildReport("2026-08-18", []Aggregate{{
		ID:  "a",
		Day: "2026-08-18",
		Policy: AppliedPolicy{
			Type:   PolicyTypeNoPolicyFound,
			Domain: "example.test",
		},
		SuccessfulSessions: 1,
	}}, ReportMetadata{OrganizationName: "Veksel", ContactInfo: "postmaster@sender.test", SubmitterDomain: "sender.test"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"failure-details":[]`)) {
		t.Fatalf("report uses a nullable failure list: %s", data)
	}
}

func TestBuildEmailMessageCreatesMultipartTLSReport(t *testing.T) {
	input := MailReport{Recipient: "reports@example.test", PolicyDomain: "example.test", SubmitterDomain: "sender.test",
		ReportID: "veksel-abcdef", Filename: "sender.test!example.test!1!2!abc.json.gz", GZIP: []byte("compressed-report")}
	message, err := BuildEmailMessage(input, time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("TLS-Report-Domain") != "example.test" || parsed.Header.Get("TLS-Report-Submitter") != "sender.test" || parsed.Header.Get("Message-ID") != "<veksel-abcdef@sender.test>" {
		t.Fatalf("headers = %#v", parsed.Header)
	}
	mediaType, parameters, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/report" || parameters["report-type"] != "tlsrpt" {
		t.Fatalf("Content-Type = %q, %v", parsed.Header.Get("Content-Type"), err)
	}
	parts := multipart.NewReader(parsed.Body, parameters["boundary"])
	if _, err := parts.NextPart(); err != nil {
		t.Fatal(err)
	}
	machine, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if machine.Header.Get("Content-Type") != "application/tlsrpt+gzip" || !strings.Contains(machine.Header.Get("Content-Disposition"), input.Filename) {
		t.Fatalf("machine headers = %#v", machine.Header)
	}
	decoded := base64.NewDecoder(base64.StdEncoding, machine)
	payload, err := io.ReadAll(decoded)
	if err != nil || !bytes.Equal(payload, input.GZIP) {
		t.Fatalf("payload = %q, %v", payload, err)
	}
}

func TestBuildReportRejectsMixedOrInvalidMetadata(t *testing.T) {
	base := Aggregate{ID: "a", Day: "2026-08-18", Policy: AppliedPolicy{Type: PolicyTypeNoPolicyFound, Domain: "example.test"}}
	metadata := ReportMetadata{OrganizationName: "Veksel", ContactInfo: "postmaster@sender.test", SubmitterDomain: "sender.test"}
	for _, test := range []struct {
		name       string
		aggregates []Aggregate
		metadata   ReportMetadata
	}{
		{name: "no aggregates", metadata: metadata},
		{name: "mixed domains", aggregates: []Aggregate{base, {ID: "b", Day: base.Day, Policy: AppliedPolicy{Domain: "other.test"}}}, metadata: metadata},
		{name: "display contact", aggregates: []Aggregate{base}, metadata: ReportMetadata{OrganizationName: "Veksel", ContactInfo: "Admin <postmaster@sender.test>", SubmitterDomain: "sender.test"}},
		{name: "IP submitter", aggregates: []Aggregate{base}, metadata: ReportMetadata{OrganizationName: "Veksel", ContactInfo: "postmaster@sender.test", SubmitterDomain: "127.0.0.1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := BuildReport("2026-08-18", test.aggregates, test.metadata); err == nil {
				t.Fatal("BuildReport accepted invalid input")
			}
		})
	}
}
