package dmarc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

// BuildAggregateEmail creates the standards-shaped MIME message. The caller
// must DKIM-sign it with the aligned submitter domain before durable enqueue.
func BuildAggregateEmail(report AggregateMailReport, date time.Time) ([]byte, error) {
	recipient, err := mail.ParseAddress(report.Recipient)
	if err != nil || recipient.Address != report.Recipient {
		return nil, errors.New("DMARC report recipient must be one addr-spec")
	}
	submitter, err := normalizeReportDomain(report.SubmitterDomain)
	if err != nil {
		return nil, errors.New("DMARC report submitter domain is invalid")
	}
	policy, err := normalizeReportDomain(report.PolicyDomain)
	if err != nil {
		return nil, errors.New("DMARC report policy domain is invalid")
	}
	if report.ReportID == "" || strings.ContainsAny(report.ReportID, "\r\n<>") || report.Filename == "" || strings.ContainsAny(report.Filename, "\r\n\"") || len(report.GZIP) == 0 {
		return nil, errors.New("DMARC report email metadata is invalid")
	}
	boundary := "veksel-dmarc-" + digestStrings(report.ReportID, report.Recipient)[:32]
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
	fmt.Fprintf(human, "This is a DMARC aggregate report from %s for %s.\r\n", submitter, policy)
	attachmentHeader := textproto.MIMEHeader{}
	attachmentHeader.Set("Content-Type", "application/gzip")
	attachmentHeader.Set("Content-Transfer-Encoding", "base64")
	attachmentHeader.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, report.Filename))
	attachment, err := writer.CreatePart(attachmentHeader)
	if err != nil {
		return nil, err
	}
	encoder := base64.NewEncoder(base64.StdEncoding, &aggregateLineWriter{writer: attachment, width: 76})
	if _, err := encoder.Write(report.GZIP); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	var message bytes.Buffer
	fmt.Fprintf(&message, "From: dmarc@%s\r\nTo: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\n", submitter, report.Recipient, date.UTC().Format(time.RFC1123Z), report.ReportID, submitter)
	fmt.Fprintf(&message, "Subject: Report Domain: %s Submitter: %s Report-ID: <%s>\r\n", policy, submitter, report.ReportID)
	fmt.Fprintf(&message, "Auto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", boundary)
	message.Write(body.Bytes())
	return message.Bytes(), nil
}

type aggregateLineWriter struct {
	writer        interface{ Write([]byte) (int, error) }
	width, column int
}

func (w *aggregateLineWriter) Write(data []byte) (int, error) {
	for index, value := range data {
		if w.column == w.width {
			if _, err := w.writer.Write([]byte("\r\n")); err != nil {
				return index, err
			}
			w.column = 0
		}
		if _, err := w.writer.Write([]byte{value}); err != nil {
			return index, err
		}
		w.column++
	}
	return len(data), nil
}
