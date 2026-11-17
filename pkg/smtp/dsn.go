package smtp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DSN status codes per RFC 3834.
// The first digit indicates the class:
//
//	2.x.x — Success
//	4.x.x — Temporary failure (delay, retry later)
//	5.x.x — Permanent failure (do not retry)
//
// Common secondary/tertiary codes:
//
//	5.1.1 — User unknown (mailbox does not exist)
//	5.1.2 — Domain not found
//	4.2.2 — Mailbox full
//	4.4.1 — Connection timeout
//	5.2.1 — Mailbox disabled

// DSNStatus represents a Delivery Status Notification status code.
type DSNStatus struct {
	Code    string // e.g. "5.1.1"
	Success bool
	Message string // human-readable explanation
}

// Well-known DSN status codes.
var (
	DSNUserUnknown       = DSNStatus{Code: "5.1.1", Success: false, Message: "User unknown"}
	DSNDomainNotFound    = DSNStatus{Code: "5.1.2", Success: false, Message: "Domain not found"}
	DSNMailboxDisabled   = DSNStatus{Code: "5.2.1", Success: false, Message: "Mailbox disabled"}
	DSNMailboxFull       = DSNStatus{Code: "4.2.2", Success: false, Message: "Mailbox full"}
	DSNConnectionTimeout = DSNStatus{Code: "4.4.1", Success: false, Message: "Connection timeout"}
	DSNDeliveryOK        = DSNStatus{Code: "2.0.0", Success: true, Message: "Delivered"}
)

// DSNRequest holds the original message information needed to generate a bounce.
type DSNRequest struct {
	From              string            // RFC 5322 From; MAILER-DAEMON@ServerName when empty
	EnvelopeSender    string            // original MAIL FROM address
	Recipient         string            // RCPT TO address that failed
	OriginalMessageID string            // Message-ID of the original message
	OriginalHeaders   map[string]string // headers of the original message
	Status            DSNStatus         // DSN status code
	DiagnosticCode    string            // additional diagnostic info (optional)
	ServerName        string            // server hostname for Message-ID generation
	EnvelopeID        string
	OriginalRecipient string
	ReturnMode        string
	OriginalContent   []byte
	OriginalBody      []byte
}

// GenerateDSN creates a bounce message per RFC 3461/3834.
// The returned bytes form a complete RFC 5322 message that can be delivered
// to the sender's mailbox.
func GenerateDSN(req DSNRequest) []byte {
	now := time.Now().UTC()
	dsnID := generateMessageID("", req.ServerName)

	var sb strings.Builder

	// RFC 5322 envelope headers
	from := req.From
	if from == "" {
		from = "Mail Delivery System <MAILER-DAEMON@" + req.ServerName + ">"
	}
	fmt.Fprintf(&sb, "From: %s\r\n", from)
	fmt.Fprintf(&sb, "To: %s\r\n", req.EnvelopeSender)
	fmt.Fprintf(&sb, "Subject: %s notice: %s\r\n", dsnSubjectPrefix(req.Status), req.Recipient)
	fmt.Fprintf(&sb, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&sb, "Message-ID: %s\r\n", dsnID)
	fmt.Fprintf(&sb, "Auto-Submitted: auto-replied\r\n")
	fmt.Fprintf(&sb, "MIME-Version: 1.0\r\n")

	// Multi-part report: human-readable part + machine-readable DSN part
	// A random boundary: the returned original is copied in verbatim and
	// must not be able to close the report and add parts of its own.
	token := make([]byte, 12)
	_, _ = rand.Read(token)
	boundary := "veksel-dsn-" + hex.EncodeToString(token)
	fmt.Fprintf(&sb, "Content-Type: multipart/report; report-type=delivery-status; boundary=\"%s\"\r\n", boundary)
	fmt.Fprintf(&sb, "\r\n")

	// --- Human-readable notification ---
	fmt.Fprintf(&sb, "--%s\r\n", boundary)
	fmt.Fprintf(&sb, "Content-Type: text/plain; charset=UTF-8\r\n")
	fmt.Fprintf(&sb, "Content-Transfer-Encoding: 7bit\r\n")
	fmt.Fprintf(&sb, "\r\n")

	if !req.Status.Success {
		fmt.Fprintf(&sb, "This is an automatically generated Delivery Status Notification.\r\n")
		fmt.Fprintf(&sb, "\r\n")
		fmt.Fprintf(&sb, "The following message could not be delivered:\r\n")
		fmt.Fprintf(&sb, "  Recipient: %s\r\n", req.Recipient)
		fmt.Fprintf(&sb, "  Reason: %s\r\n", cleanDSNValue(req.Status.Message))
		if req.DiagnosticCode != "" {
			fmt.Fprintf(&sb, "  Details: %s\r\n", cleanDSNValue(req.DiagnosticCode))
		}
		fmt.Fprintf(&sb, "\r\n")
		fmt.Fprintf(&sb, "The original message follows:\r\n")
	} else {
		fmt.Fprintf(&sb, "This is an automatically generated Delivery Status Notification.\r\n")
		fmt.Fprintf(&sb, "\r\n")
		fmt.Fprintf(&sb, "The message was successfully delivered to %s.\r\n", req.Recipient)
		fmt.Fprintf(&sb, "\r\n")
	}
	fmt.Fprintf(&sb, "\r\n")

	// --- Machine-readable DSN (RFC 3461 message/delivery-status) ---
	fmt.Fprintf(&sb, "--%s\r\n", boundary)
	fmt.Fprintf(&sb, "Content-Type: message/delivery-status\r\n")
	fmt.Fprintf(&sb, "\r\n")

	// Original-Envelope-From (RFC 3461)
	fmt.Fprintf(&sb, "Original-Envelope-From: %s\r\n", formatAddr(req.EnvelopeSender))
	if req.EnvelopeID != "" {
		fmt.Fprintf(&sb, "Original-Envelope-ID: %s\r\n", cleanDSNValue(req.EnvelopeID))
	}

	// Original-Recipient (RFC 3461) — RFC 2045 addr-spec
	originalRecipient := "rfc822;" + req.Recipient
	if req.OriginalRecipient != "" {
		originalRecipient = req.OriginalRecipient
	}
	fmt.Fprintf(&sb, "Original-Recipient: %s\r\n", cleanDSNValue(originalRecipient))

	// Final-Recipient (RFC 3461) — ietf-token with SMTP hostname
	fmt.Fprintf(&sb, "Final-Recipient: rfc822;%s\r\n", req.Recipient)

	// Action: delayed, failed, relayed, or processed
	action := "failed"
	if req.Status.Success {
		action = "processed"
	} else if strings.HasPrefix(req.Status.Code, "4.") {
		action = "delayed"
	}
	fmt.Fprintf(&sb, "Action: %s\r\n", action)

	// Status: the DSN status code
	fmt.Fprintf(&sb, "Status: %s\r\n", req.Status.Code)

	// Diagnostic-Code (optional, x-smtprcptto for the original RCPT TO)
	if req.DiagnosticCode != "" {
		fmt.Fprintf(&sb, "Diagnostic-Code: smtp; %s\r\n", cleanDSNValue(req.DiagnosticCode))
	} else {
		fmt.Fprintf(&sb, "Diagnostic-Code: smtp; %s\r\n", cleanDSNValue(req.Status.Message))
	}

	// Original-Message-ID (RFC 3461) — Message-ID from the original message
	if req.OriginalMessageID != "" {
		fmt.Fprintf(&sb, "Original-Message-ID: %s\r\n", cleanDSNValue(req.OriginalMessageID))
	}

	// Reporting-MTA (RFC 3461) — identifier of this server
	fmt.Fprintf(&sb, "Reporting-MTA: dns;%s\r\n", req.ServerName)

	// Arrival date
	fmt.Fprintf(&sb, "Arrival-Date: %s\r\n", now.Format(time.RFC1123Z))

	writeReturnedContent(&sb, boundary, req)

	// End boundary
	fmt.Fprintf(&sb, "--%s--\r\n", boundary)

	return []byte(sb.String())
}

func writeReturnedContent(builder *strings.Builder, boundary string, request DSNRequest) {
	if strings.EqualFold(request.ReturnMode, "hdrs") {
		fmt.Fprintf(builder, "--%s\r\nContent-Type: text/rfc822-headers\r\n\r\n", boundary)
		writeDSNHeaders(builder, request.OriginalHeaders)
		fmt.Fprint(builder, "\r\n")
		return
	}
	fmt.Fprintf(builder, "--%s\r\nContent-Type: message/rfc822\r\n\r\n", boundary)
	if len(request.OriginalContent) > 0 {
		content := strings.ReplaceAll(strings.ReplaceAll(string(request.OriginalContent), "\r\n", "\n"), "\r", "\n")
		fmt.Fprint(builder, strings.ReplaceAll(content, "\n", "\r\n"), "\r\n")
		return
	}
	writeDSNHeaders(builder, request.OriginalHeaders)
	fmt.Fprint(builder, "\r\n")
	body := strings.ReplaceAll(strings.ReplaceAll(string(request.OriginalBody), "\r\n", "\n"), "\r", "\n")
	fmt.Fprint(builder, strings.ReplaceAll(body, "\n", "\r\n"), "\r\n")
}

func writeDSNHeaders(builder *strings.Builder, headers map[string]string) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(builder, "%s: %s\r\n", cleanDSNValue(key), cleanDSNValue(headers[key]))
	}
}

func cleanDSNValue(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", "")
}

// formatAddr formats an email address for DSN headers.
// Empty string becomes empty (null sender).
func formatAddr(addr string) string {
	if addr == "" {
		return ""
	}
	return addr
}

// dsnSubjectPrefix returns the subject prefix based on success/failure.
func dsnSubjectPrefix(status DSNStatus) string {
	if status.Success {
		return "Delivery"
	}
	if strings.HasPrefix(status.Code, "4.") {
		return "Delayed"
	}
	return "Undelivered"
}
