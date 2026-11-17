package tlsrpt

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/mtasts"
)

// ReportMetadata identifies the system producing TLS reports.
type ReportMetadata struct {
	OrganizationName string
	ContactInfo      string
	SubmitterDomain  string
}

// Report is the RFC 8460 I-JSON aggregate report.
type Report struct {
	OrganizationName string          `json:"organization-name"`
	DateRange        ReportDateRange `json:"date-range"`
	ContactInfo      string          `json:"contact-info"`
	ReportID         string          `json:"report-id"`
	Policies         []ReportPolicy  `json:"policies"`
}

type ReportDateRange struct {
	Start time.Time `json:"start-datetime"`
	End   time.Time `json:"end-datetime"`
}

type ReportPolicy struct {
	Policy         ReportPolicyDescription `json:"policy"`
	Summary        ReportSummary           `json:"summary"`
	FailureDetails []FailureDetail         `json:"failure-details"`
}

type ReportPolicyDescription struct {
	Type    string   `json:"policy-type"`
	Strings []string `json:"policy-string"`
	Domain  string   `json:"policy-domain"`
	MX      []string `json:"mx-host"`
}

type ReportSummary struct {
	Successful int64 `json:"total-successful-session-count"`
	Failure    int64 `json:"total-failure-session-count"`
}

// BuildReport converts one domain/day's durable aggregates into a stable
// standards-shaped report and recommended filename.
func BuildReport(day string, aggregates []Aggregate, metadata ReportMetadata) (Report, string, error) {
	start, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return Report{}, "", errors.New("TLS report day must use YYYY-MM-DD")
	}
	if len(aggregates) == 0 {
		return Report{}, "", errors.New("TLS report requires at least one aggregate")
	}
	organization, contact, submitter, err := validateReportMetadata(metadata)
	if err != nil {
		return Report{}, "", err
	}
	domain := aggregates[0].Policy.Domain
	for _, aggregate := range aggregates {
		if aggregate.Day != day || aggregate.Policy.Domain != domain {
			return Report{}, "", errors.New("TLS report aggregates must share one day and policy domain")
		}
	}
	sort.Slice(aggregates, func(i, j int) bool { return aggregates[i].ID < aggregates[j].ID })
	reportID := deterministicReportID(submitter, domain, day)
	report := Report{OrganizationName: organization, ContactInfo: contact, ReportID: reportID,
		DateRange: ReportDateRange{Start: start.UTC(), End: start.Add(24 * time.Hour).UTC()}, Policies: make([]ReportPolicy, 0, len(aggregates))}
	for _, aggregate := range aggregates {
		failures := append([]FailureDetail{}, aggregate.Failures...)
		sort.Slice(failures, func(i, j int) bool { return failureDigest(failures[i]) < failureDigest(failures[j]) })
		report.Policies = append(report.Policies, ReportPolicy{
			Policy: ReportPolicyDescription{Type: aggregate.Policy.Type, Strings: nonNilStrings(aggregate.Policy.Strings),
				Domain: aggregate.Policy.Domain, MX: nonNilStrings(aggregate.Policy.MX)},
			Summary:        ReportSummary{Successful: aggregate.SuccessfulSessions, Failure: aggregate.FailedSessions},
			FailureDetails: failures,
		})
	}
	filename := fmt.Sprintf("%s!%s!%d!%d!%s.json.gz", submitter, domain, start.Unix(), start.Add(24*time.Hour).Unix(), reportID[len("veksel-"):len("veksel-")+12])
	return report, filename, nil
}

func validateReportMetadata(metadata ReportMetadata) (organization, contact, submitter string, err error) {
	submitter, err = mtasts.CanonicalDomain(metadata.SubmitterDomain)
	if err != nil {
		return "", "", "", errors.New("TLS report submitter domain is invalid")
	}
	address, err := mail.ParseAddress(strings.TrimSpace(metadata.ContactInfo))
	if err != nil || address.Address != strings.TrimSpace(metadata.ContactInfo) {
		return "", "", "", errors.New("TLS report contact must be one addr-spec")
	}
	organization = bound(strings.TrimSpace(metadata.OrganizationName), 256)
	if organization == "" {
		return "", "", "", errors.New("TLS report organization is required")
	}
	return organization, address.Address, submitter, nil
}

// MarshalReportGZIP returns deterministic gzip-compressed I-JSON suitable for
// application/tlsrpt+gzip delivery.
func MarshalReportGZIP(report Report) ([]byte, error) {
	data, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	writer.Header.ModTime = time.Time{}
	writer.Header.OS = 255
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}

// BuildEmailMessage constructs the RFC 8460 multipart/report body. Callers
// must add a DKIM signature before enqueueing it.
func BuildEmailMessage(report MailReport, date time.Time) ([]byte, error) {
	to, err := mail.ParseAddress(report.Recipient)
	if err != nil || to.Address != report.Recipient {
		return nil, errors.New("TLS report recipient must be one addr-spec")
	}
	submitter, err := mtasts.CanonicalDomain(report.SubmitterDomain)
	if err != nil {
		return nil, errors.New("TLS report submitter domain is invalid")
	}
	policyDomain, err := mtasts.CanonicalDomain(report.PolicyDomain)
	if err != nil {
		return nil, errors.New("TLS report policy domain is invalid")
	}
	if report.ReportID == "" || strings.ContainsAny(report.ReportID, "\r\n<>") || report.Filename == "" || strings.ContainsAny(report.Filename, "\r\n\"") || len(report.GZIP) == 0 {
		return nil, errors.New("TLS report email metadata is invalid")
	}
	boundary := "veksel-tlsrpt-" + deterministicReportID(submitter, policyDomain, report.ReportID)[len("veksel-"):]
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, err
	}
	humanHeader := textproto.MIMEHeader{}
	humanHeader.Set("Content-Type", `text/plain; charset="us-ascii"`)
	humanHeader.Set("Content-Transfer-Encoding", "7bit")
	human, err := writer.CreatePart(humanHeader)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(human, "This is an aggregate SMTP TLS report from %s.\r\n", submitter); err != nil {
		return nil, err
	}
	machineHeader := textproto.MIMEHeader{}
	machineHeader.Set("Content-Type", "application/tlsrpt+gzip")
	machineHeader.Set("Content-Transfer-Encoding", "base64")
	machineHeader.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, report.Filename))
	machine, err := writer.CreatePart(machineHeader)
	if err != nil {
		return nil, err
	}
	encoder := base64.NewEncoder(base64.StdEncoding, &lineWriter{writer: machine, width: 76})
	if _, err := encoder.Write(report.GZIP); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	from := "tlsrpt@" + submitter
	var message bytes.Buffer
	fmt.Fprintf(&message, "From: %s\r\n", from)
	fmt.Fprintf(&message, "To: %s\r\n", report.Recipient)
	fmt.Fprintf(&message, "Date: %s\r\n", date.UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&message, "Message-ID: <%s@%s>\r\n", report.ReportID, submitter)
	fmt.Fprintf(&message, "Subject: Report Domain: %s Submitter: %s Report-ID: <%s@%s>\r\n", policyDomain, submitter, report.ReportID, submitter)
	fmt.Fprintf(&message, "TLS-Report-Domain: %s\r\n", policyDomain)
	fmt.Fprintf(&message, "TLS-Report-Submitter: %s\r\n", submitter)
	message.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&message, "Content-Type: multipart/report; report-type=\"tlsrpt\"; boundary=\"%s\"\r\n\r\n", boundary)
	message.Write(body.Bytes())
	return message.Bytes(), nil
}

type lineWriter struct {
	writer io.Writer
	width  int
	column int
}

func (w *lineWriter) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		remaining := w.width - w.column
		if remaining == 0 {
			if _, err := io.WriteString(w.writer, "\r\n"); err != nil {
				return written, err
			}
			w.column = 0
			remaining = w.width
		}
		count := min(remaining, len(data))
		n, err := w.writer.Write(data[:count])
		written += n
		w.column += n
		data = data[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func deterministicReportID(submitter, domain, day string) string {
	digest := sha256.Sum256([]byte(submitter + "\x00" + domain + "\x00" + day))
	return "veksel-" + hex.EncodeToString(digest[:16])
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string(nil), values...)
}
