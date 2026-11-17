package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestEHLOReplyEndsWithLastKeyword replays the EHLO exchange Python smtplib
// parsed as an extension named "END": the final line must be the last
// keyword, and the recipient limit uses the RFC 9422 LIMITS syntax rather
// than the malformed "RCPT TO;100" keyword.
func TestEHLOReplyEndsWithLastKeyword(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{ServerName: "test.veksel", MaxRecipients: 100})
	c.writeCmd("EHLO client.example")
	var lines []string
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	if last := lines[len(lines)-1]; last != "250 LIMITS RCPTMAX=100" {
		t.Fatalf("final EHLO line = %q, want the last keyword; reply %q", last, lines)
	}
	for _, line := range lines {
		if strings.Contains(line, "End") || strings.Contains(line, ";") {
			t.Fatalf("malformed EHLO keyword line %q in %q", line, lines)
		}
	}
}

// TestEnhancedStatusCodesWithMultiDigitDetail replays "AUTH PLAIN" before
// STARTTLS on submission, which answered "538 5.7.11 5.7.11 Encryption
// required ..." because a three-part code with a two-digit detail was not
// recognised as already present.
func TestEnhancedStatusCodesWithMultiDigitDetail(t *testing.T) {
	t.Parallel()
	session := &Session{ehloGiven: true}
	for _, text := range []string{"5.7.11 Encryption required", "5.7.30 REQUIRETLS needed", "4.7.112 Try later"} {
		if got := session.enhancedReply(538, text); got != text {
			t.Fatalf("enhancedReply(%q) = %q", text, got)
		}
	}
	if got := session.enhancedReply(538, session.enhancedReply(538, "Encryption required")); got != "5.7.11 Encryption required" {
		t.Fatalf("double application = %q", got)
	}
	if hasEnhancedStatusCode("1.2.3 not a class") || hasEnhancedStatusCode("5.7.1234 too long") || hasEnhancedStatusCode("Encryption") {
		t.Fatal("invalid status code accepted")
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		AuthMechanisms: []string{"PLAIN"}, RequireTLSForAuth: true,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
	})
	c.send("EHLO client.example")
	if code, text := c.send("AUTH PLAIN AGFsaWNlAHNlY3JldA=="); code != 538 || text != "5.7.11 Encryption required for requested authentication mechanism" {
		t.Fatalf("AUTH before TLS = %d %q", code, text)
	}
}

// TestNonPipeliningClientCanAddressManyRecipients replays Python smtplib
// sending one message to 30 recipients and then several messages in one
// session: without PIPELINING every RCPT is its own command batch, and the
// generic 20-command burst closed the connection with 421.
func TestNonPipeliningClientCanAddressManyRecipients(t *testing.T) {
	t.Parallel()
	delivered := 0
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel", MaxRecipients: 100, RateLimitCommands: true,
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil },
			AppendMessage: func(context.Context, string, []byte, map[string]string) (string, error) {
				delivered++
				return fmt.Sprintf("item-%d", delivered), nil
			},
		},
	})
	t.Cleanup(cleanup)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &tc{Conn: conn, r: bufio.NewReader(conn)}
	if _, err := c.readLine(); err != nil {
		t.Fatal(err)
	}
	c.send("HELO client.example")
	for message := range 5 {
		if code, text := c.send("MAIL FROM:<sender@remote.example>"); code != 250 {
			t.Fatalf("message %d MAIL = %d %s", message, code, text)
		}
		for recipient := range 40 {
			if code, text := c.send(fmt.Sprintf("RCPT TO:<alice+%d@example.test>", recipient)); code != 250 {
				t.Fatalf("message %d recipient %d = %d %s", message, recipient, code, text)
			}
		}
		if code, text := c.send("DATA"); code != 354 {
			t.Fatalf("message %d DATA = %d %s", message, code, text)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if code, text := c.send("Subject: many\r\n\r\nbody\r\n."); code != 250 {
			t.Fatalf("message %d end of data = %d %s", message, code, text)
		}
	}
}

// TestSecondAUTHIsRefused replays AUTH LOGIN sent again after a successful
// AUTH on port 465: the server started a new exchange instead of answering
// 503 as RFC 4954 section 4 requires.
func TestSecondAUTHIsRefused(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel", AuthMechanisms: []string{"PLAIN", "LOGIN"}, SaslIrEnabled: true,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
	})
	c.send("EHLO client.example")
	if code, text := c.send("AUTH PLAIN AGFsaWNlAHNlY3JldA=="); code != 235 {
		t.Fatalf("first AUTH = %d %s", code, text)
	}
	if code, text := c.send("AUTH LOGIN YWxpY2U="); code != 503 || !strings.HasPrefix(text, "5.5.1 ") {
		t.Fatalf("second AUTH = %d %s", code, text)
	}
}
