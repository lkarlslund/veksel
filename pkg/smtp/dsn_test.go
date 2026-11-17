package smtp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// --- Message-ID generation tests ---

func TestGenerateMessageID(t *testing.T) {
	t.Parallel()
	id := generateMessageID("", "mail.example.com")
	if fromID := generateMessageID("Alice <alice@example.test>", "mail.example.com"); !strings.HasSuffix(fromID, "@example.test>") {
		t.Errorf("Message-ID %q should use the sender's domain", fromID)
	}

	// Must be enclosed in angle brackets
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, ">") {
		t.Fatalf("Message-ID %q should be enclosed in angle brackets", id)
	}

	// Must contain @hostname
	if !strings.Contains(id, "@mail.example.com>") {
		t.Errorf("Message-ID %q should contain @mail.example.com>", id)
	}

	// Inner part should be non-empty
	inner := strings.Trim(id, "<>")
	if at := strings.LastIndex(inner, "@"); at <= 0 {
		t.Errorf("Message-ID local part is empty or malformed: %q", id)
	}
}

func TestMessageIDAddedWhenMissing(t *testing.T) {
	t.Parallel()
	var receivedHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	// Message without Message-ID
	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: No ID\r\n\r\nBody\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	msgID := receivedHeaders["Message-ID"]
	if msgID == "" {
		t.Fatal("expected auto-generated Message-ID, got empty string")
	}
	if !strings.HasPrefix(msgID, "<") || !strings.HasSuffix(msgID, ">") {
		t.Errorf("Message-ID %q should be enclosed in angle brackets", msgID)
	}
}

func TestMessageIDPreserved(t *testing.T) {
	t.Parallel()
	var receivedHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("Message-ID: <custom@client.com>\r\n\r\nbody\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if receivedHeaders["Message-ID"] != "<custom@client.com>" {
		t.Errorf("Message-ID = %q, want %q", receivedHeaders["Message-ID"], "<custom@client.com>")
	}
}

// --- DSN generation tests ---

func TestGenerateDSN_UserUnknown(t *testing.T) {
	req := DSNRequest{
		EnvelopeSender:    "sender@example.com",
		Recipient:         "nobody@example.com",
		OriginalMessageID: "<orig@client.com>",
		Status:            DSNUserUnknown,
		DiagnosticCode:    "User unknown: nobody@example.com",
		ServerName:        "mail.veksel",
	}

	dsn := GenerateDSN(req)
	dsnStr := string(dsn)

	// Check envelope headers
	// The null sender belongs in the envelope; the header names a mailbox
	// a DKIM signature can align with.
	if !strings.Contains(dsnStr, "From: Mail Delivery System <MAILER-DAEMON@mail.veksel>\r\n") {
		t.Error("DSN should be from MAILER-DAEMON at the server name")
	}
	req.From = "MAILER-DAEMON@example.com"
	if !strings.Contains(string(GenerateDSN(req)), "From: MAILER-DAEMON@example.com\r\n") {
		t.Error("DSN should use the requested From")
	}
	if !strings.Contains(dsnStr, "To: sender@example.com") {
		t.Error("DSN should have To: sender@example.com")
	}
	if !strings.Contains(dsnStr, "Auto-Submitted: auto-replied") {
		t.Error("DSN should have Auto-Submitted: auto-replied")
	}
	if !strings.Contains(dsnStr, "Message-ID:") {
		t.Error("DSN should have Message-ID")
	}

	// Check subject prefix for permanent failure
	if !strings.Contains(dsnStr, "Undelivered notice:") {
		t.Errorf("DSN subject should contain 'Undelivered notice:', got: %s", extractHeader(dsnStr, "Subject"))
	}

	// Check multipart/report content type
	if !strings.Contains(dsnStr, "Content-Type: multipart/report") {
		t.Error("DSN should be multipart/report")
	}
	if !strings.Contains(dsnStr, "report-type=delivery-status") {
		t.Error("DSN should have report-type=delivery-status")
	}

	// Check machine-readable DSN part
	if !strings.Contains(dsnStr, "Content-Type: message/delivery-status") {
		t.Error("DSN should contain message/delivery-status part")
	}

	// Check RFC 3461 required fields
	if !strings.Contains(dsnStr, "Original-Envelope-From: sender@example.com") {
		t.Error("DSN should have Original-Envelope-From")
	}
	if !strings.Contains(dsnStr, "Original-Recipient: rfc822;nobody@example.com") {
		t.Error("DSN should have Original-Recipient")
	}
	if !strings.Contains(dsnStr, "Final-Recipient: rfc822;nobody@example.com") {
		t.Error("DSN should have Final-Recipient")
	}
	if !strings.Contains(dsnStr, "Action: failed") {
		t.Error("DSN should have Action: failed for 5.x.x status")
	}
	if !strings.Contains(dsnStr, "Status: 5.1.1") {
		t.Error("DSN should have Status: 5.1.1")
	}
	if !strings.Contains(dsnStr, "Reporting-MTA: dns;mail.veksel") {
		t.Error("DSN should have Reporting-MTA")
	}
	if !strings.Contains(dsnStr, "Original-Message-ID: <orig@client.com>") {
		t.Error("DSN should have Original-Message-ID")
	}
	if !strings.Contains(dsnStr, "Diagnostic-Code: smtp;") {
		t.Error("DSN should have Diagnostic-Code")
	}
	if !strings.Contains(dsnStr, "Arrival-Date:") {
		t.Error("DSN should have Arrival-Date")
	}
}

func TestGenerateDSNHonorsEnvelopeAndReturnPreferences(t *testing.T) {
	base := DSNRequest{
		EnvelopeSender: "sender@example.test", Recipient: "current@example.test", EnvelopeID: "job+2Bid",
		OriginalRecipient: "rfc822;old+40example.test", OriginalHeaders: map[string]string{"Subject": "Original", "From": "sender@example.test"},
		OriginalBody: []byte("secret body"), Status: DSNUserUnknown, ServerName: "mx.example.test",
	}
	headersOnly := base
	headersOnly.ReturnMode = "hdrs"
	generated := string(GenerateDSN(headersOnly))
	for _, expected := range []string{"Original-Envelope-ID: job+2Bid", "Original-Recipient: rfc822;old+40example.test", "Content-Type: text/rfc822-headers", "Subject: Original"} {
		if !strings.Contains(generated, expected) {
			t.Fatalf("headers-only DSN missing %q:\n%s", expected, generated)
		}
	}
	if strings.Contains(generated, "secret body") {
		t.Fatal("RET=HDRS DSN leaked the original body")
	}
	base.ReturnMode = "full"
	generated = string(GenerateDSN(base))
	if !strings.Contains(generated, "Content-Type: message/rfc822") || !strings.Contains(generated, "secret body") {
		t.Fatalf("RET=FULL DSN omitted original message:\n%s", generated)
	}
}

func TestGenerateDSN_TemporaryFailure(t *testing.T) {
	req := DSNRequest{
		EnvelopeSender: "sender@example.com",
		Recipient:      "full@example.com",
		Status:         DSNMailboxFull,
		DiagnosticCode: "Mailbox full",
		ServerName:     "mail.veksel",
	}

	dsn := GenerateDSN(req)
	dsnStr := string(dsn)

	// Subject prefix for temporary failure
	if !strings.Contains(dsnStr, "Delayed notice:") {
		t.Errorf("DSN subject should contain 'Delayed notice:', got: %s", extractHeader(dsnStr, "Subject"))
	}

	// Action for 4.x.x
	if !strings.Contains(dsnStr, "Action: delayed") {
		t.Error("DSN should have Action: delayed for 4.x.x status")
	}

	if !strings.Contains(dsnStr, "Status: 4.2.2") {
		t.Error("DSN should have Status: 4.2.2")
	}
}

func TestGenerateDSN_Success(t *testing.T) {
	req := DSNRequest{
		EnvelopeSender: "sender@example.com",
		Recipient:      "alice@example.com",
		Status:         DSNDeliveryOK,
		ServerName:     "mail.veksel",
	}

	dsn := GenerateDSN(req)
	dsnStr := string(dsn)

	// Subject prefix for success
	if !strings.Contains(dsnStr, "Delivery notice:") {
		t.Errorf("DSN subject should contain 'Delivery notice:', got: %s", extractHeader(dsnStr, "Subject"))
	}

	// Action for 2.x.x
	if !strings.Contains(dsnStr, "Action: processed") {
		t.Error("DSN should have Action: processed for 2.x.x status")
	}

	if !strings.Contains(dsnStr, "Status: 2.0.0") {
		t.Error("DSN should have Status: 2.0.0")
	}
}

func TestGenerateDSN_NullSender(t *testing.T) {
	req := DSNRequest{
		EnvelopeSender: "",
		Recipient:      "nobody@example.com",
		Status:         DSNUserUnknown,
		ServerName:     "mail.veksel",
	}

	dsn := GenerateDSN(req)
	dsnStr := string(dsn)

	// Should still generate a valid DSN even with null sender
	if !strings.Contains(dsnStr, "To: ") {
		t.Error("DSN should have To header (even if empty)")
	}
	if !strings.Contains(dsnStr, "Original-Envelope-From: ") {
		t.Error("DSN should have Original-Envelope-From (even if empty)")
	}
}

func TestGenerateDSN_RFC3461Compliance(t *testing.T) {
	req := DSNRequest{
		EnvelopeSender:    "sender@example.com",
		Recipient:         "nobody@example.com",
		OriginalMessageID: "<abc123@client.com>",
		Status:            DSNUserUnknown,
		DiagnosticCode:    "550 5.1.1 <nobody@example.com>: Recipient address rejected: User unknown in virtual mailbox table",
		ServerName:        "mail.veksel",
	}

	dsn := GenerateDSN(req)
	dsnStr := string(dsn)

	// RFC 3461 required fields for message/delivery-status
	requiredFields := []string{
		"Original-Envelope-From:",
		"Original-Recipient:",
		"Final-Recipient:",
		"Action:",
		"Status:",
		"Reporting-MTA:",
		"Arrival-Date:",
	}

	for _, field := range requiredFields {
		if !strings.Contains(dsnStr, field) {
			t.Errorf("DSN missing required RFC 3461 field: %s", field)
		}
	}

	// Check that the diagnostic code is included
	if !strings.Contains(dsnStr, "550 5.1.1") {
		t.Error("DSN should include the full diagnostic code")
	}

	// Check Original-Message-ID
	if !strings.Contains(dsnStr, "Original-Message-ID: <abc123@client.com>") {
		t.Error("DSN should include Original-Message-ID from the original message")
	}
}

func TestDSNStatusCodes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		status    DSNStatus
		wantClass byte
	}{
		{"user unknown", DSNUserUnknown, '5'},
		{"domain not found", DSNDomainNotFound, '5'},
		{"mailbox disabled", DSNMailboxDisabled, '5'},
		{"mailbox full", DSNMailboxFull, '4'},
		{"connection timeout", DSNConnectionTimeout, '4'},
		{"delivery ok", DSNDeliveryOK, '2'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.status.Code) == 0 || tt.status.Code[0] != tt.wantClass {
				t.Errorf("status %q code=%q, want class %c.x.x", tt.name, tt.status.Code, tt.wantClass)
			}
		})
	}
}

// --- Bounce delivery integration tests ---

func TestDSN_NoBounceOnUnknownRecipient(t *testing.T) {
	var dsnDelivered bool

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "alice@example.com" {
					return "alice:INBOX", "alice", nil
				}
				return "", "", fmt.Errorf("unknown user")
			},
			ResolveSender: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "sender@example.com" {
					return "sender:INBOX", "sender", nil
				}
				return "", "", fmt.Errorf("not managed")
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				if folderID == "sender:INBOX" {
					dsnDelivered = true
				}
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")

	// A recipient rejected during the SMTP transaction was never accepted, so the
	// synchronous 550 is the complete failure report and must not cause a DSN.
	code, _ := c.send("RCPT TO:<nobody@example.com>")
	if code != 550 {
		t.Fatalf("RCPT TO unknown: code=%d, want 550", code)
	}

	if dsnDelivered {
		t.Fatal("unexpected DSN for a recipient rejected before message acceptance")
	}
}

func TestDSN_NoBounceOnDeliveryFailureBeforeAcceptance(t *testing.T) {
	var dsnDelivered bool
	callCount := 0

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			ResolveSender: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "sender@example.com" {
					return "sender:INBOX", "sender", nil
				}
				return "", "", fmt.Errorf("not managed")
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				callCount++
				if folderID == "sender:INBOX" {
					dsnDelivered = true
					return "dsn-1", nil
				}
				// First call is the actual delivery — fail it
				if callCount == 1 {
					return "", fmt.Errorf("storage error")
				}
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\nMessage-ID: <orig@client.com>\r\n\r\nBody\r\n.\r\n")
	code, _, _ := c.readReply()
	// Delivery failed, so we expect 451
	if code != 451 {
		t.Fatalf("DATA end: code=%d, want 451", code)
	}

	if dsnDelivered {
		t.Fatal("unexpected DSN after DATA returned 451 without accepting the message")
	}
}

func TestDSN_NoBounceForNullSender(t *testing.T) {
	var dsnDelivered bool

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "", "", fmt.Errorf("unknown")
			},
			ResolveSender: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				if folderID == "sender:INBOX" {
					dsnDelivered = true
				}
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	// Null sender (bounce mail itself)
	c.send("MAIL FROM:<>")

	// Even though recipient is unknown, no DSN should be sent for null sender
	code, _ := c.send("RCPT TO:<nobody@example.com>")
	if code != 550 {
		t.Fatalf("RCPT TO unknown: code=%d, want 550", code)
	}

	if dsnDelivered {
		t.Error("DSN should not be delivered for null envelope sender")
	}
}

func TestDSN_NoBounceForUnmanagedSender(t *testing.T) {
	var dsnDelivered bool

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "", "", fmt.Errorf("unknown")
			},
			ResolveSender: func(ctx context.Context, addr string) (string, string, error) {
				// Sender is not a managed user
				return "", "", fmt.Errorf("not managed")
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				dsnDelivered = true
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<external@other.com>")

	code, _ := c.send("RCPT TO:<nobody@example.com>")
	if code != 550 {
		t.Fatalf("RCPT TO unknown: code=%d, want 550", code)
	}

	// DSN should not be delivered because sender is not managed
	// (no AppendMessage call should happen for DSN)
	if dsnDelivered {
		t.Error("DSN should not be delivered for unmanaged sender")
	}
}

// Helper: extract a header value from raw message text.
func extractHeader(msg, header string) string {
	lines := strings.Split(msg, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, header+":") {
			return strings.TrimPrefix(line, header+":")
		}
	}
	return ""
}

// --- DSN format validation tests ---

func TestDSN_UsesCRLF(t *testing.T) {
	req := DSNRequest{
		EnvelopeSender: "sender@example.com",
		Recipient:      "nobody@example.com",
		Status:         DSNUserUnknown,
		ServerName:     "mail.veksel",
	}

	dsn := GenerateDSN(req)
	dsnStr := string(dsn)

	// Replace all CRLF with empty string — if there are bare LF remaining,
	// the message uses mixed line endings.
	normalized := strings.ReplaceAll(dsnStr, "\r\n", "")
	if strings.Contains(normalized, "\n") {
		t.Error("DSN contains bare LF not preceded by CR (mixed line endings)")
	}
}

func TestDSN_BoundaryFormat(t *testing.T) {
	// The bounced message and the remote diagnostic cannot close the report
	// early or add parts of their own.
	original := "From: a@example.net\r\nSubject: x\r\n\r\nhello\r\n------=_Part_DSN_Report\r\nContent-Type: text/html\r\n\r\n<b>log in at https://evil</b>\r\n------=_Part_DSN_Report--\r\n"
	req := DSNRequest{
		EnvelopeSender:  "sender@example.com",
		Recipient:       "nobody@example.com",
		Status:          DSNUserUnknown,
		DiagnosticCode:  "550 no\r\nX-Injected: yes",
		ServerName:      "mail.veksel",
		OriginalContent: []byte(original),
	}
	message, err := mail.ReadMessage(bytes.NewReader(GenerateDSN(req)))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/report" || params["boundary"] == "" {
		t.Fatalf("content type %q %v", mediaType, err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	var types []string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(part)
		types = append(types, part.Header.Get("Content-Type"))
		if strings.Contains(string(content), "\nX-Injected") {
			t.Fatalf("diagnostic injected a field:\n%s", content)
		}
		if part.Header.Get("Content-Type") == "message/rfc822" && !strings.Contains(string(content), "https://evil") {
			t.Fatalf("returned message truncated:\n%s", content)
		}
	}
	if strings.Join(types, ",") != "text/plain; charset=UTF-8,message/delivery-status,message/rfc822" {
		t.Fatalf("parts = %q", types)
	}
	if other := GenerateDSN(req); bytes.Contains(other, []byte(params["boundary"])) {
		t.Fatal("DSN boundaries repeat")
	}
}

// --- End-to-end SMTP test with DSN ---

func TestDSN_FullSMTPFlow(t *testing.T) {
	var deliveredMessages []struct {
		folderID string
		headers  map[string]string
		data     []byte
	}

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "alice@example.com" {
					return "alice:INBOX", "alice", nil
				}
				return "", "", fmt.Errorf("unknown user")
			},
			ResolveSender: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "sender@example.com" {
					return "sender:INBOX", "sender", nil
				}
				return "", "", fmt.Errorf("not managed")
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				deliveredMessages = append(deliveredMessages, struct {
					folderID string
					headers  map[string]string
					data     []byte
				}{folderID, headers, data})
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")

	// Valid recipient
	c.send("RCPT TO:<alice@example.com>")
	// Invalid recipient — rejected synchronously without generating a DSN.
	c.send("RCPT TO:<nobody@example.com>")

	c.send("DATA")
	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if len(deliveredMessages) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(deliveredMessages))
	}

	if deliveredMessages[0].folderID != "alice:INBOX" {
		t.Errorf("delivery folder = %q, want %q", deliveredMessages[0].folderID, "alice:INBOX")
	}
	if deliveredMessages[0].headers["Subject"] != "Test" {
		t.Errorf("delivery subject = %q, want %q", deliveredMessages[0].headers["Subject"], "Test")
	}
}

// Test that connection timeout DSN (4.4.1) produces correct action
func TestDSN_ConnectionTimeout(t *testing.T) {
	req := DSNRequest{
		EnvelopeSender: "sender@example.com",
		Recipient:      "remote@example.com",
		Status:         DSNConnectionTimeout,
		DiagnosticCode: "Connection timed out",
		ServerName:     "mail.veksel",
	}

	dsn := GenerateDSN(req)
	dsnStr := string(dsn)

	if !strings.Contains(dsnStr, "Action: delayed") {
		t.Error("DSN for 4.4.1 should have Action: delayed")
	}
	if !strings.Contains(dsnStr, "Status: 4.4.1") {
		t.Error("DSN should have Status: 4.4.1")
	}
	if !strings.Contains(dsnStr, "Delayed notice:") {
		t.Error("DSN subject should say 'Delayed' for 4.x.x")
	}
}

// Test domain not found DSN
func TestDSN_DomainNotFound(t *testing.T) {
	req := DSNRequest{
		EnvelopeSender: "sender@example.com",
		Recipient:      "user@nonexistent.invalid",
		Status:         DSNDomainNotFound,
		DiagnosticCode: "Domain nonexistent.invalid not found",
		ServerName:     "mail.veksel",
	}

	dsn := GenerateDSN(req)
	dsnStr := string(dsn)

	if !strings.Contains(dsnStr, "Action: failed") {
		t.Error("DSN for 5.1.2 should have Action: failed")
	}
	if !strings.Contains(dsnStr, "Status: 5.1.2") {
		t.Error("DSN should have Status: 5.1.2")
	}
}

// A DATA transaction rejected with 451 was never accepted, so the connected
// client retries it and Veksel must not also generate a backscatter DSN.
func TestNoDSNForDeliveryFailureBeforeAcceptance(t *testing.T) {
	var dsnMessages []struct {
		folderID string
		data     []byte
	}

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			ResolveSender: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "sender@example.com" {
					return "sender:INBOX", "sender", nil
				}
				return "", "", fmt.Errorf("not managed")
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				dsnMessages = append(dsnMessages, struct {
					folderID string
					data     []byte
				}{folderID, data})

				if folderID == "sender:INBOX" {
					return "dsn-1", nil
				}
				// Fail the actual delivery
				return "", fmt.Errorf("resolve recipient: storage failure")
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\nMessage-ID: <orig@client.com>\r\n\r\nBody\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 451 {
		t.Fatalf("DATA end: code=%d, want 451", code)
	}

	if len(dsnMessages) != 1 {
		t.Fatalf("unaccepted transaction generated a DSN: %#v", dsnMessages)
	}
}
