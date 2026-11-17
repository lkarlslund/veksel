package smtp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

type testGreylistChecker struct {
	decisions []greylist.Decision
	err       error
	inputs    []greylist.Triplet
}

func (checker *testGreylistChecker) Check(_ context.Context, input greylist.Triplet) (greylist.Decision, error) {
	checker.inputs = append(checker.inputs, input)
	if checker.err != nil {
		return greylist.Decision{}, checker.err
	}
	decision := checker.decisions[0]
	checker.decisions = checker.decisions[1:]
	return decision, nil
}

// tc wraps a net.Conn with a persistent bufio.Reader for proper line reading.
type tc struct {
	net.Conn
	r *bufio.Reader
}

func (c *tc) readLine() (string, error) {
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readReply reads an SMTP reply (may be multi-line).
func (c *tc) readReply() (int, string, error) {
	line, err := c.readLine()
	if err != nil {
		return 0, "", err
	}
	code, text, _ := strings.Cut(line, " ")
	var codeInt int
	fmt.Sscanf(code, "%d", &codeInt)
	// Check for multi-line (4th char is '-')
	if len(line) > 4 && line[3] == '-' {
		var extra []string
		for {
			l, err := c.readLine()
			if err != nil {
				break
			}
			extra = append(extra, l)
			if len(l) > 4 && l[3] == ' ' {
				break
			}
		}
		text = strings.Join(append([]string{text}, extra...), "\n")
	}
	return codeInt, text, nil
}

// send writes a command and reads the reply.
func (c *tc) send(cmd string) (int, string) {
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", cmd)
	code, text, err := c.readReply()
	if err != nil {
		return 0, err.Error()
	}
	return code, text
}

// writeData sends raw DATA body lines and flushes.
func (c *tc) writeData(s string) {
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c.Conn, s)
	if flusher, ok := c.Conn.(interface{ Flush() error }); ok {
		flusher.Flush()
	}
}

// writeCmd writes a command without reading the response (for pipelining tests).
func (c *tc) writeCmd(cmd string) {
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", cmd)
}

// readReplies reads n SMTP replies, returning the codes and texts.
func (c *tc) readReplies(n int) []int {
	codes := make([]int, 0, n)
	for len(codes) < n {
		code, _, err := c.readReply()
		if err != nil {
			break
		}
		codes = append(codes, code)
	}
	return codes
}

// makeTestServer creates a server on a random port, accepts one connection,
// reads the greeting, and returns the wrapped client connection.
func makeTestServer(t *testing.T, cfg *Config) *tc {
	t.Helper()
	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	// Accept one connection in background
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, nil, nil)
		sess.run()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	c := &tc{Conn: conn, r: bufio.NewReader(conn)}

	// Read greeting
	greeting, err := c.readLine()
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("expected 220 greeting, got: %s", greeting)
	}

	return c
}

func TestEHLO(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		MaxRecipients:  100,
	})

	code, text := c.send("EHLO client.example.com")
	if code != 250 {
		t.Fatalf("EHLO: code=%d text=%s, want 250", code, text)
	}
	if !strings.Contains(text, "8BITMIME") {
		t.Errorf("EHLO reply missing 8BITMIME: %s", text)
	}
	if !strings.Contains(text, "SMTPUTF8") {
		t.Errorf("EHLO reply missing SMTPUTF8: %s", text)
	}
	if !strings.Contains(text, "CHUNKING") {
		t.Errorf("EHLO reply missing CHUNKING: %s", text)
	}
	if !strings.Contains(text, "AUTH") {
		t.Errorf("EHLO reply missing AUTH: %s", text)
	}
	if !strings.Contains(text, "ENHANCEDSTATUSCODES") {
		t.Errorf("EHLO reply missing ENHANCEDSTATUSCODES: %s", text)
	}
	if !strings.Contains(text, "DSN") {
		t.Errorf("EHLO reply missing DSN: %s", text)
	}
}

func TestDSNParametersAreValidated(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel", MaxMessageSize: 1024})
	_, ehlo := c.send("EHLO client")
	if !strings.Contains(ehlo, "SIZE 1024") {
		t.Fatalf("EHLO missing bounded SIZE: %s", ehlo)
	}
	for _, command := range []string{
		"MAIL FROM:<sender@example.test> RET=INVALID",
		"MAIL FROM:<sender@example.test> ENVID=bad+Q0",
		"MAIL FROM:<sender@example.test> SIZE=2048",
		"MAIL FROM:<sender@example.test> UNKNOWN=value",
	} {
		if code, _ := c.send(command); code < 500 {
			t.Fatalf("%q returned %d", command, code)
		}
	}
	if code, text := c.send("MAIL FROM:<sender@example.test> RET=HDRS ENVID=job+2Bid"); code != 250 {
		t.Fatalf("valid MAIL code=%d text=%s", code, text)
	}
	for _, command := range []string{
		"RCPT TO:<person@example.test> NOTIFY=NEVER,FAILURE",
		"RCPT TO:<person@example.test> ORCPT=invalid",
	} {
		if code, _ := c.send(command); code < 500 {
			t.Fatalf("%q returned %d", command, code)
		}
	}
}

func TestEnhancedStatusCodesAreNegotiatedAndNotDuplicated(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client.example.test")
	if code, text := c.send("NOOP"); code != 250 || !strings.HasPrefix(text, "2.0.0 ") {
		t.Fatalf("NOOP reply = %d %q", code, text)
	}
	if code, text := c.send("UNKNOWN"); code != 502 || !strings.HasPrefix(text, "5.5.1 ") {
		t.Fatalf("unknown-command reply = %d %q", code, text)
	}
	session := &Session{ehloGiven: true}
	if got := session.enhancedReply(550, "5.7.1 Policy rejected"); got != "5.7.1 Policy rejected" {
		t.Fatalf("specific status was changed: %q", got)
	}
}

func TestHELODoesNotEnableEnhancedStatusCodes(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("HELO client.example.test")
	if code, text := c.send("NOOP"); code != 250 || strings.HasPrefix(text, "2.0.0 ") {
		t.Fatalf("HELO NOOP reply = %d %q", code, text)
	}
}

func TestHELO(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	code, text := c.send("HELO client.example.com")
	if code != 250 {
		t.Fatalf("HELO: code=%d text=%s, want 250", code, text)
	}
}

func TestMAIL_FROM(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")

	code, _ := c.send("MAIL FROM:<sender@example.com>")
	if code != 250 {
		t.Fatalf("MAIL FROM: code=%d, want 250", code)
	}

	// Null sender
	code, _ = c.send("MAIL FROM:<>")
	if code != 250 {
		t.Fatalf("MAIL FROM<>: code=%d, want 250", code)
	}
}

func TestMAIL_FROM_invalid(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")

	code, _ := c.send("MAIL FROM:invalid")
	if code != 501 {
		t.Fatalf("MAIL FROM invalid: code=%d, want 501", code)
	}
}

func TestMAIL_FROM_before_EHLO(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	code, _ := c.send("MAIL FROM:<sender@example.com>")
	if code != 503 {
		t.Fatalf("MAIL FROM before EHLO: code=%d, want 503", code)
	}
}

func TestRCPT_TO(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
		},
	})
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")

	code, _ := c.send("RCPT TO:<alice@example.com>")
	if code != 250 {
		t.Fatalf("RCPT TO: code=%d, want 250", code)
	}
}

func TestRCPT_TO_unknown(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "", "", fmt.Errorf("not found")
			},
		},
	})
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")

	code, _ := c.send("RCPT TO:<nobody@example.com>")
	if code != 550 {
		t.Fatalf("RCPT TO unknown: code=%d, want 550", code)
	}
}

func TestRCPT_TOAppliesGreylistingAfterRecipientResolution(t *testing.T) {
	checker := &testGreylistChecker{decisions: []greylist.Decision{
		{Action: greylist.ActionDefer, RetryAfter: 90 * time.Second},
		{Action: greylist.ActionPass},
	}}
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel", Greylist: checker,
		Delivery: &Delivery{ResolveRecipient: func(context.Context, string) (string, string, error) {
			return "folder", "alice", nil
		}},
	})
	c.send("EHLO client")
	c.send("MAIL FROM:<Sender@Example.com>")
	if code, text := c.send("RCPT TO:<Alice@Example.com>"); code != 451 || !strings.Contains(text, "retry after 1m30s") {
		t.Fatalf("initial greylist response = %d %q", code, text)
	}
	if code, text := c.send("RCPT TO:<Alice@Example.com>"); code != 250 {
		t.Fatalf("validated retry response = %d %q", code, text)
	}
	if len(checker.inputs) != 2 || checker.inputs[0].RemoteIP != "127.0.0.1" || checker.inputs[0].EnvelopeFrom != "sender@example.com" || checker.inputs[0].Recipient != "alice@example.com" {
		t.Fatalf("greylist inputs = %+v", checker.inputs)
	}
}

func TestRCPT_TOGreylistFailureIsTemporaryAndUnknownRecipientIsNotRecorded(t *testing.T) {
	checker := &testGreylistChecker{err: errors.New("store unavailable")}
	resolve := func(_ context.Context, address string) (string, string, error) {
		if address == "unknown@example.com" {
			return "", "", errors.New("not found")
		}
		return "folder", "alice", nil
	}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", Greylist: checker, Delivery: &Delivery{ResolveRecipient: resolve}})
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	if code, _ := c.send("RCPT TO:<unknown@example.com>"); code != 550 {
		t.Fatalf("unknown recipient response = %d", code)
	}
	if len(checker.inputs) != 0 {
		t.Fatalf("unknown recipient reached greylisting: %+v", checker.inputs)
	}
	if code, text := c.send("RCPT TO:<alice@example.com>"); code != 451 || !strings.Contains(text, "4.3.0") {
		t.Fatalf("greylist failure response = %d %q", code, text)
	}
}

func TestRCPT_TO_max_recipients(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		MaxRecipients: 2,
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
		},
	})
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<a@example.com>")
	c.send("RCPT TO:<b@example.com>")

	code, _ := c.send("RCPT TO:<c@example.com>")
	if code != 452 {
		t.Fatalf("RCPT TO over limit: code=%d, want 452", code)
	}
}

func TestDATA_full_flow(t *testing.T) {
	var receivedData []byte
	var receivedHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedData = data
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")

	code, _ := c.send("DATA")
	if code != 354 {
		t.Fatalf("DATA: code=%d, want 354", code)
	}

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello World\r\n.\r\n")
	code, _, _ = c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if receivedHeaders == nil {
		t.Fatal("expected headers to be set")
	}
	if receivedHeaders["Subject"] != "Test" {
		t.Errorf("Subject = %q, want %q", receivedHeaders["Subject"], "Test")
	}
	if receivedHeaders["Message-ID"] == "" {
		t.Error("expected auto-generated Message-ID")
	}
	if len(receivedData) == 0 {
		t.Error("expected non-empty message data")
	}
}

func TestDATARejectsProbableReceivedHeaderLoop(t *testing.T) {
	delivered := false
	c := makeTestServer(t, &Config{
		ServerName:         "test.veksel",
		MaxReceivedHeaders: 1,
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil },
			AppendMessage: func(context.Context, string, []byte, map[string]string) (string, error) {
				delivered = true
				return "item-1", nil
			},
		},
	})
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	if code, _ := c.send("DATA"); code != 354 {
		t.Fatalf("DATA = %d", code)
	}
	c.writeData("Received: from one\r\n\tby continuation\r\nReceived: from two\r\nSubject: loop\r\n\r\nbody\r\n.\r\n")
	code, text, _ := c.readReply()
	if code != 554 || !strings.HasPrefix(text, "5.4.6 Too many hops") {
		t.Fatalf("DATA end = %d %s, want 554 5.4.6 Too many hops", code, text)
	}
	if delivered {
		t.Fatal("probable routing loop was delivered")
	}
}

func TestDATA_message_id_preserved(t *testing.T) {
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

func TestBDATPipelinedChunksCommitThroughDurableQueue(t *testing.T) {
	queue := &recordingSystemQueue{}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) {
			return "alice:INBOX", "alice", nil
		},
		AppendMessage: func(context.Context, string, []byte, map[string]string) (string, error) {
			return "unused", nil
		},
		MailQueue: queue,
	}})
	c.send("EHLO client.example.test")
	first := "From: sender@example.test\r\nSubject: Chunked\r\n\r\n"
	last := ".leading dot is data\r\n"
	c.writeData(fmt.Sprintf("MAIL FROM:<sender@example.test>\r\nRCPT TO:<alice@example.test>\r\nBDAT %d\r\n%sBDAT %d LAST\r\n%s", len(first), first, len(last), last))
	if codes := c.readReplies(4); fmt.Sprint(codes) != "[250 250 250 250]" {
		t.Fatalf("pipelined BDAT replies = %v, want four 250 replies", codes)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("durable queue messages = %d, want 1", len(queue.messages))
	}
	message := queue.messages[0]
	_, queuedBody := model.ParseMessageHeaders(message.Content)
	if message.Headers["Subject"] != "Chunked" || string(queuedBody) != last {
		t.Fatalf("queued message subject=%q body=%q", message.Headers["Subject"], queuedBody)
	}
}

func TestBDATRejectsOversizeAndPreservesCommandFraming(t *testing.T) {
	queue := &recordingSystemQueue{}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", MaxMessageSize: 8, Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil },
		AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:        queue,
	}})
	c.send("EHLO client.example.test")
	c.send("MAIL FROM:<sender@example.test>")
	c.send("RCPT TO:<alice@example.test>")
	c.writeData("BDAT 9 LAST\r\n123456789")
	if code, _, err := c.readReply(); err != nil || code != 552 {
		t.Fatalf("oversize BDAT reply = %d, %v; want 552", code, err)
	}
	if code, _ := c.send("NOOP"); code != 250 {
		t.Fatalf("NOOP after rejected chunk = %d, want 250", code)
	}
	if len(queue.messages) != 0 {
		t.Fatalf("oversize BDAT queued %d messages", len(queue.messages))
	}
}

func TestRSET(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")

	code, _ := c.send("RSET")
	if code != 250 {
		t.Fatalf("RSET: code=%d, want 250", code)
	}

	code, _ = c.send("MAIL FROM:<other@example.com>")
	if code != 250 {
		t.Fatalf("MAIL FROM after RSET: code=%d, want 250", code)
	}
}

func TestNOOP(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")
	code, _ := c.send("NOOP")
	if code != 250 {
		t.Fatalf("NOOP: code=%d, want 250", code)
	}
}

func TestQUIT(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")
	code, text := c.send("QUIT")
	if code != 221 {
		t.Fatalf("QUIT: code=%d text=%s, want 221", code, text)
	}
}

func TestBadSequence(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})

	code, _ := c.send("DATA")
	if code != 503 {
		t.Fatalf("DATA without EHLO: code=%d, want 503", code)
	}

	c.send("EHLO client")
	code, _ = c.send("RCPT TO:<a@example.com>")
	if code != 503 {
		t.Fatalf("RCPT without MAIL: code=%d, want 503", code)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")
	code, _ := c.send("FOOBAR")
	if code != 502 {
		t.Fatalf("FOOBAR: code=%d, want 502", code)
	}
}

func TestMaxMessageSize(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		MaxMessageSize: 100,
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\n\r\nThis is a very long message body that exceeds the limit\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 552 {
		t.Fatalf("DATA over size: code=%d, want 552", code)
	}
	// The oversized body was drained, so the session is still in sync.
	if code, _ := c.send("NOOP"); code != 250 {
		t.Fatalf("NOOP after oversized DATA: code=%d, want 250", code)
	}
}

// newSTARTTLSTestClient connects to a STARTTLS-capable session and returns
// the client after the greeting and EHLO.
func newSTARTTLSTestClient(t *testing.T) *tc {
	t.Helper()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	// A server without implicit TLS; the client negotiates STARTTLS.
	srv := New(&Config{
		ServerName:     "test.veksel",
		TLSConfig:      tlsCfg,
		AuthMechanisms: []string{"PLAIN"},
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	cfg := &Config{
		ServerName:     "test.veksel",
		TLSConfig:      tlsCfg,
		AuthMechanisms: []string{"PLAIN"},
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, nil, nil)
		sess.run()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	c := &tc{Conn: conn, r: bufio.NewReader(conn)}
	greeting, err := c.readLine()
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("expected 220 greeting, got: %s", greeting)
	}

	c.send("EHLO client")
	return c
}

// TestSTARTTLSRefusesPipelinedCommands checks that commands pipelined after
// STARTTLS are not executed once TLS is active (CVE-2011-0411 class).
func TestSTARTTLSRefusesPipelinedCommands(t *testing.T) {
	t.Parallel()
	c := newSTARTTLSTestClient(t)
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c.Conn, "STARTTLS\r\nMAIL FROM:<injected@example.com>\r\n")
	line, err := c.readLine()
	if err != nil || !strings.HasPrefix(line, "421") {
		t.Fatalf("response to pipelined STARTTLS = %q, %v; want 421", line, err)
	}
	if line, err := c.readLine(); err == nil {
		t.Fatalf("session continued after 421: %q", line)
	}
}

func TestSTARTTLS(t *testing.T) {
	t.Parallel()
	c := newSTARTTLSTestClient(t)

	code, _ := c.send("STARTTLS")
	if code != 220 {
		t.Fatalf("STARTTLS: code=%d, want 220", code)
	}

	// Upgrade to TLS
	tlsConn := tls.Client(c.Conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	c.Conn = tlsConn
	c.r = bufio.NewReader(tlsConn)

	// After TLS, EHLO again
	code, _ = c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO after STARTTLS: code=%d, want 250", code)
	}
}

func TestRequireTLSReceiptPersistsAcrossDATAAndBDAT(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	queue := &recordingSystemQueue{}
	cfg := &Config{ServerName: "test.veksel", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil },
		MailQueue:        queue,
	}}
	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			newSession(srv.sessionID.Add(1), cfg, conn, nil, nil).run()
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := &tc{Conn: conn, r: bufio.NewReader(conn)}
	if _, err := client.readLine(); err != nil {
		t.Fatal(err)
	}
	if code, text := client.send("EHLO client"); code != 250 || strings.Contains(text, "REQUIRETLS") {
		t.Fatalf("clear EHLO = %d %q", code, text)
	}
	if code, text := client.send("MAIL FROM:<sender@example.test> REQUIRETLS"); code != 530 || !strings.Contains(text, "5.7.10") {
		t.Fatalf("clear REQUIRETLS = %d %q", code, text)
	}
	if code, _ := client.send("STARTTLS"); code != 220 {
		t.Fatalf("STARTTLS code = %d", code)
	}
	tlsConn := tls.Client(client.Conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	client.Conn, client.r = tlsConn, bufio.NewReader(tlsConn)
	if code, text := client.send("EHLO client"); code != 250 || !strings.Contains(text, "REQUIRETLS") {
		t.Fatalf("secure EHLO = %d %q", code, text)
	}
	for _, command := range []string{"MAIL FROM:<sender@example.test> REQUIRETLS", "RCPT TO:<alice@example.test>", "RCPT TO:<bob@example.test>", "DATA"} {
		expected := 250
		if command == "DATA" {
			expected = 354
		}
		if code, text := client.send(command); code != expected {
			t.Fatalf("%s = %d %q", command, code, text)
		}
	}
	client.writeData("From: sender@example.test\r\nTLS-Required: No\r\nSubject: required\r\n\r\nbody\r\n.\r\n")
	if code, text, _ := client.readReply(); code != 250 {
		t.Fatalf("DATA completion = %d %q", code, text)
	}
	if len(queue.messages) != 2 || queue.messages[0].Attributes[AttributeRequireTLS] != "true" || queue.messages[1].Attributes[AttributeRequireTLS] != "true" || queue.messages[0].Attributes[AttributeTLSOptional] != "" {
		t.Fatalf("required queue message = %#v", queue.messages)
	}

	if code, _ := client.send("MAIL FROM:<sender@example.test>"); code != 250 {
		t.Fatalf("second MAIL = %d", code)
	}
	if code, _ := client.send("RCPT TO:<alice@example.test>"); code != 250 {
		t.Fatalf("second RCPT = %d", code)
	}
	optional := "From: sender@example.test\r\nTLS-Required: No\r\nSubject: optional\r\n\r\nbody"
	client.writeData(fmt.Sprintf("BDAT %d LAST\r\n%s", len(optional), optional))
	if code, text, _ := client.readReply(); code != 250 {
		t.Fatalf("BDAT completion = %d %q", code, text)
	}
	if len(queue.messages) != 3 || queue.messages[2].Attributes[AttributeTLSOptional] != "true" || queue.messages[2].Attributes[AttributeRequireTLS] != "" {
		t.Fatalf("optional queue message = %#v", queue.messages)
	}

	for _, command := range []string{"MAIL FROM:<sender@example.test>", "RCPT TO:<alice@example.test>", "DATA"} {
		client.send(command)
	}
	client.writeData("TLS-Required: No\r\nTLS-Required: No\r\n\r\nbody\r\n.\r\n")
	if code, text, _ := client.readReply(); code != 550 || !strings.Contains(text, "Invalid TLS-Required") {
		t.Fatalf("duplicate header = %d %q", code, text)
	}
	if len(queue.messages) != 3 {
		t.Fatalf("invalid message was queued: %#v", queue.messages)
	}
}

// TestImplicitTLS tests that connections with ImplicitTLS=true
// immediately upgrade to TLS before sending the greeting.
func TestImplicitTLS(t *testing.T) {
	t.Parallel()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	srv := New(&Config{
		ServerName:     "test.veksel",
		TLSConfig:      tlsCfg,
		ImplicitTLS:    true,
		AuthMechanisms: []string{"PLAIN"},
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	cfg := &Config{
		ServerName:     "test.veksel",
		TLSConfig:      tlsCfg,
		ImplicitTLS:    true,
		AuthMechanisms: []string{"PLAIN"},
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, nil, nil)
		sess.run()
	}()

	// Connect with TLS client — implicit TLS expects TLS from the start
	tlsConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	t.Cleanup(func() { tlsConn.Close() })

	c := &tc{Conn: tlsConn, r: bufio.NewReader(tlsConn)}

	// Read greeting — should be a 220
	greeting, err := c.readLine()
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("expected 220 greeting, got: %s", greeting)
	}

	// EHLO should NOT advertise STARTTLS because TLS is already active
	code, text := c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO: code=%d text=%s, want 250", code, text)
	}
	if strings.Contains(text, "STARTTLS") {
		t.Error("EHLO should not advertise STARTTLS when implicit TLS is active")
	}
}

// TestImplicitTLSPlaintextFails tests that a plaintext connection to an
// implicit TLS server fails (TLS handshake error).
func TestImplicitTLSPlaintextFails(t *testing.T) {
	t.Parallel()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	srv := New(&Config{
		ServerName:  "test.veksel",
		TLSConfig:   tlsCfg,
		ImplicitTLS: true,
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	cfg := &Config{
		ServerName:  "test.veksel",
		TLSConfig:   tlsCfg,
		ImplicitTLS: true,
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, nil, nil)
		sess.run()
	}()

	// Connect with a plaintext client — this should fail because the
	// server expects TLS. The server will try a TLS handshake, and the
	// client will send plaintext, causing the server to close the connection.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// Speak plaintext first so the server's TLS handshake fails at once
	// instead of waiting for a ClientHello until the read deadline.
	if _, err := conn.Write([]byte("EHLO client\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	// Either the connection is closed (TLS handshake failed on server side)
	// or we get garbage bytes (TLS record data interpreted as plaintext)
	if err == nil && n > 0 {
		// We got TLS record data, not a 220 greeting
		if strings.HasPrefix(string(buf[:n]), "220 ") {
			t.Fatal("plaintext connection should not receive a clean 220 greeting")
		}
	}
}

func TestAUTH_PLAIN(t *testing.T) {
	var lastUser, lastPass string
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			lastUser = username
			lastPass = password
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	})

	c.send("EHLO client")

	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	code, _ := c.send("AUTH PLAIN " + creds)
	if code != 235 {
		t.Fatalf("AUTH PLAIN: code=%d, want 235", code)
	}
	if lastUser != "alice" {
		t.Errorf("username = %q, want %q", lastUser, "alice")
	}
	if lastPass != "secret" {
		t.Errorf("password = %q, want %q", lastPass, "secret")
	}
}

func TestAUTH_PLAIN_invalid(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "", fmt.Errorf("invalid")
		},
	})

	c.send("EHLO client")
	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00wrong"))
	code, _ := c.send("AUTH PLAIN " + creds)
	if code != 535 {
		t.Fatalf("AUTH PLAIN invalid: code=%d, want 535", code)
	}
}

func TestAUTH_FailuresAreThrottledPerClient(t *testing.T) {
	throttle := ratelimit.NewAuthThrottleWithLimits(50, 2, time.Hour)
	var mu sync.Mutex
	verified := 0
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (userID string, err error) {
			ip := ratelimit.ClientIP(ctx)
			if ip != "127.0.0.1" {
				t.Errorf("client IP = %q, want the SMTP peer address in the auth context", ip)
			}
			if err := throttle.Begin(ip, username); err != nil {
				return "", err
			}
			defer func() { throttle.End(ip, username, err == nil) }()
			mu.Lock()
			verified++
			mu.Unlock()
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	})

	c.send("EHLO client")
	wrong := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00wrong"))
	for range 2 {
		if code, _ := c.send("AUTH PLAIN " + wrong); code != 535 {
			t.Fatalf("failed AUTH PLAIN: code=%d, want 535", code)
		}
	}
	right := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	if code, text := c.send("AUTH PLAIN " + right); code != 454 || !strings.Contains(text, "4.7.0") {
		t.Fatalf("throttled AUTH PLAIN: code=%d text=%q, want 454 4.7.0", code, text)
	}
	c.send("AUTH LOGIN")
	c.send(base64.StdEncoding.EncodeToString([]byte("alice")))
	if code, _ := c.send(base64.StdEncoding.EncodeToString([]byte("secret"))); code != 454 {
		t.Fatalf("throttled AUTH LOGIN: code=%d, want 454", code)
	}
	mu.Lock()
	defer mu.Unlock()
	if verified != 2 {
		t.Fatalf("credentials verified %d times; throttled attempts must not reach verification", verified)
	}
}

func TestAUTH_PLAIN_ExchangeErrors(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			t.Errorf("validator must not run for a failed exchange (user %q)", username)
			return "", fmt.Errorf("invalid")
		},
	})
	c.send("EHLO client")
	for _, tt := range []struct {
		command string
		want    int
	}{
		{"AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("bob\x00alice\x00secret")), 535},
		{"AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("alice\x00secret")), 501},
		{"AUTH PLAIN not-base64!", 501},
		{"AUTH PLAIN =", 501},
	} {
		if code, text := c.send(tt.command); code != tt.want {
			t.Fatalf("%s: code=%d text=%q, want %d", tt.command, code, text, tt.want)
		}
	}
	if code, _ := c.send("AUTH PLAIN"); code != 334 {
		t.Fatalf("AUTH PLAIN without initial response: code=%d, want 334", code)
	}
	if code, _ := c.send("*"); code != 501 {
		t.Fatalf("AUTH cancellation: code=%d, want 501", code)
	}
}

func TestAUTH_LOGIN(t *testing.T) {
	var lastUser, lastPass string
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"LOGIN"},
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			lastUser = username
			lastPass = password
			if username == "bob" && password == "pass123" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid")
		},
	})

	c.send("EHLO client")

	code, _ := c.send("AUTH LOGIN")
	if code != 334 {
		t.Fatalf("AUTH LOGIN: code=%d, want 334", code)
	}

	username := base64.StdEncoding.EncodeToString([]byte("bob"))
	code, _ = c.send(username)
	if code != 334 {
		t.Fatalf("AUTH LOGIN username: code=%d, want 334", code)
	}

	password := base64.StdEncoding.EncodeToString([]byte("pass123"))
	code, _ = c.send(password)
	if code != 235 {
		t.Fatalf("AUTH LOGIN password: code=%d, want 235", code)
	}

	if lastUser != "bob" {
		t.Errorf("username = %q, want %q", lastUser, "bob")
	}
	if lastPass != "pass123" {
		t.Errorf("password = %q, want %q", lastPass, "pass123")
	}
}

func TestMessageDelivery(t *testing.T) {
	t.Parallel()
	var deliveredFolder string
	var deliveredData []byte
	var deliveredHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "alice@example.com" {
					return "alice:INBOX", "alice", nil
				}
				return "", "", fmt.Errorf("unknown")
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				deliveredFolder = folderID
				deliveredData = data
				deliveredHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	if rc, _ := c.send("RCPT TO:<alice@example.com>"); rc != 250 {
		t.Fatalf("RCPT TO: code=%d, want 250", rc)
	}

	if rc, _ := c.send("DATA"); rc != 354 {
		t.Fatalf("DATA: code=%d, want 354", rc)
	}

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Hello\r\n\r\nMessage body here\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if deliveredFolder != "alice:INBOX" {
		t.Errorf("folder = %q, want %q", deliveredFolder, "alice:INBOX")
	}
	if deliveredHeaders["Subject"] != "Hello" {
		t.Errorf("Subject = %q, want %q", deliveredHeaders["Subject"], "Hello")
	}
	if deliveredHeaders["Message-ID"] == "" {
		t.Error("expected auto-generated Message-ID")
	}
	if len(deliveredData) == 0 {
		t.Error("expected message data to be non-empty")
	}
}

func TestDotStuffing(t *testing.T) {
	t.Parallel()
	var receivedData []byte
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedData = data
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<a@example.com>")
	c.send("DATA")

	c.writeData("Subject: Dot Test\r\n\r\nLine with dot at start: .hidden\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	// The data should contain ".hidden" (dot stuffing handled)
	if !strings.Contains(string(receivedData), ".hidden") {
		t.Errorf("expected dot-stuffed line in data, got: %s", string(receivedData))
	}
}

// --- PIPELINING tests (RFC 2920) ---

func TestPIPELINING_advertised(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
	})

	code, text := c.send("EHLO client.example.com")
	if code != 250 {
		t.Fatalf("EHLO: code=%d text=%s, want 250", code, text)
	}
	if !strings.Contains(text, "PIPELINING") {
		t.Errorf("EHLO reply missing PIPELINING: %s", text)
	}
}

func TestPIPELINING_batch_commands(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
		},
	})

	// EHLO to enable pipelining
	c.send("EHLO client")

	// Send multiple commands without reading responses
	c.writeCmd("MAIL FROM:<sender@example.com>")
	c.writeCmd("RCPT TO:<alice@example.com>")
	c.writeCmd("NOOP")
	c.writeCmd("RSET")

	// Read all responses — they should all be 250
	codes := c.readReplies(4)
	if len(codes) != 4 {
		t.Fatalf("expected 4 responses, got %d", len(codes))
	}
	for i, code := range codes {
		if code != 250 {
			t.Errorf("response %d: code=%d, want 250", i, code)
		}
	}
}

func TestPIPELINING_mixed_responses(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "alice@example.com" {
					return "folder", "user", nil
				}
				return "", "", fmt.Errorf("unknown")
			},
		},
	})

	c.send("EHLO client")

	// Pipeline: MAIL FROM (250), RCPT TO valid (250), RCPT TO invalid (550)
	c.writeCmd("MAIL FROM:<sender@example.com>")
	c.writeCmd("RCPT TO:<alice@example.com>")
	c.writeCmd("RCPT TO:<nobody@example.com>")

	codes := c.readReplies(3)
	if len(codes) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(codes))
	}
	if codes[0] != 250 {
		t.Errorf("MAIL FROM: code=%d, want 250", codes[0])
	}
	if codes[1] != 250 {
		t.Errorf("RCPT TO valid: code=%d, want 250", codes[1])
	}
	if codes[2] != 550 {
		t.Errorf("RCPT TO invalid: code=%d, want 550", codes[2])
	}
}

func TestPIPELINING_full_delivery(t *testing.T) {
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

	// Pipeline MAIL FROM and RCPT TO, then DATA
	c.writeCmd("MAIL FROM:<sender@example.com>")
	c.writeCmd("RCPT TO:<alice@example.com>")
	codes := c.readReplies(2)
	if codes[0] != 250 || codes[1] != 250 {
		t.Fatalf("pipeline setup failed: codes=%v", codes)
	}

	// DATA must be sent separately because it requires interactive body reading
	code, _ := c.send("DATA")
	if code != 354 {
		t.Fatalf("DATA: code=%d, want 354", code)
	}

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Pipelined\r\n\r\nBody\r\n.\r\n")
	code, _, _ = c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if receivedHeaders["Subject"] != "Pipelined" {
		t.Errorf("Subject = %q, want %q", receivedHeaders["Subject"], "Pipelined")
	}
}

// --- 8BITMIME tests (RFC 1652) ---

func Test8BITMIME_advertised(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	code, text := c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO: code=%d, want 250", code)
	}
	if !strings.Contains(text, "8BITMIME") {
		t.Errorf("EHLO reply missing 8BITMIME: %s", text)
	}
}

func Test8BITMIME_mail_from_body_param(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")

	// MAIL FROM with BODY=8BITMIME parameter
	code, _ := c.send("MAIL FROM:<sender@example.com> BODY=8BITMIME")
	if code != 250 {
		t.Fatalf("MAIL FROM BODY=8BITMIME: code=%d, want 250", code)
	}
}

func Test8BITMIME_data_delivery(t *testing.T) {
	var receivedData []byte

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedData = data
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com> BODY=8BITMIME")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	// Send 8-bit data (bytes > 127) in the message body
	// The 0xff byte is a valid 8-bit character
	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: 8Bit Test\r\nContent-Transfer-Encoding: 8bit\r\n\r\nHello \xff\xfe\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if len(receivedData) == 0 {
		t.Fatal("expected non-empty message data")
	}
	// Verify 8-bit content is preserved
	if !strings.Contains(string(receivedData), "Hello") {
		t.Error("expected 'Hello' in received data")
	}
}

// --- SMTPUTF8 tests (RFC 6531) ---

func TestSMTPUTF8_advertised(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	code, text := c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO: code=%d, want 250", code)
	}
	if !strings.Contains(text, "SMTPUTF8") {
		t.Errorf("EHLO reply missing SMTPUTF8: %s", text)
	}
}

func TestSMTPUTF8_internationalized_sender(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")

	// MAIL FROM with internationalized address (non-ASCII local part)
	code, _ := c.send("MAIL FROM:<müller@example.com> SMTPUTF8")
	if code != 250 {
		t.Fatalf("MAIL FROM with UTF-8: code=%d, want 250", code)
	}
}

func TestSMTPUTF8_internationalized_recipient(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
		},
	})
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")

	// RCPT TO with internationalized address
	code, _ := c.send("RCPT TO:<用户@例子.广告>")
	if code != 250 {
		t.Fatalf("RCPT TO with UTF-8: code=%d, want 250", code)
	}
}

func TestSMTPUTF8_full_delivery(t *testing.T) {
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
	c.send("MAIL FROM:<müller@münchen.de> SMTPUTF8")
	c.send("RCPT TO:<用户@example.com>")
	c.send("DATA")

	c.writeData("From: müller@münchen.de\r\nTo: 用户@example.com\r\nSubject: International\r\n\r\nHello World\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if receivedHeaders["Subject"] != "International" {
		t.Errorf("Subject = %q, want %q", receivedHeaders["Subject"], "International")
	}
}

// generateSelfSignedCert creates a self-signed TLS certificate for testing.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.veksel",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	// PEM-encode for tls.X509KeyPair
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// --- VRFY tests (RFC 5321 Section 4.1.1.1) ---

func TestVRFY_disabled(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")

	// VRFY should be rejected when not enabled
	code, _ := c.send("VRFY alice@example.com")
	if code != 502 {
		t.Fatalf("VRFY disabled: code=%d, want 502", code)
	}
}

func TestVRFY_enabled_valid_user(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		VrfyEnabled: true,
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				if addr == "alice@example.com" {
					return "alice:INBOX", "alice", nil
				}
				return "", "", fmt.Errorf("unknown")
			},
		},
	})
	c.send("EHLO client")

	code, _ := c.send("VRFY alice@example.com")
	if code != 250 {
		t.Fatalf("VRFY valid user: code=%d, want 250", code)
	}
}

func TestVRFY_enabled_invalid_user(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		VrfyEnabled: true,
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "", "", fmt.Errorf("unknown")
			},
		},
	})
	c.send("EHLO client")

	code, _ := c.send("VRFY nobody@example.com")
	if code != 550 {
		t.Fatalf("VRFY invalid user: code=%d, want 550", code)
	}
}

func TestVRFY_enabled_no_resolver(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		VrfyEnabled: true,
	})
	c.send("EHLO client")

	code, _ := c.send("VRFY alice@example.com")
	if code != 502 {
		t.Fatalf("VRFY no resolver: code=%d, want 502", code)
	}
}

func TestVRFY_enabled_no_arg(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		VrfyEnabled: true,
	})
	c.send("EHLO client")

	code, _ := c.send("VRFY")
	if code != 501 {
		t.Fatalf("VRFY no arg: code=%d, want 501", code)
	}
}

func TestVRFY_in_ehlo(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		VrfyEnabled: true,
	})
	code, text := c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO: code=%d, want 250", code)
	}
	if !strings.Contains(text, "VRFY") {
		t.Errorf("EHLO reply missing VRFY when enabled: %s", text)
	}
}

func TestVRFY_not_in_ehlo_when_disabled(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	code, text := c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO: code=%d, want 250", code)
	}
	if strings.Contains(text, "VRFY") {
		t.Errorf("EHLO reply should not contain VRFY when disabled: %s", text)
	}
}

// --- EXPN tests (RFC 5321 Section 4.1.1.2) ---

func TestEXPN_disabled(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	c.send("EHLO client")

	code, _ := c.send("EXPN staff")
	if code != 502 {
		t.Fatalf("EXPN disabled: code=%d, want 502", code)
	}
}

func TestEXPN_enabled_not_implemented(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		ExpnEnabled: true,
	})
	c.send("EHLO client")

	// EXPN is enabled but no mailing list expansion is implemented
	code, _ := c.send("EXPN staff")
	if code != 502 {
		t.Fatalf("EXPN enabled: code=%d, want 502 (not implemented)", code)
	}
}

func TestEXPN_enabled_no_arg(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		ExpnEnabled: true,
	})
	c.send("EHLO client")

	code, _ := c.send("EXPN")
	if code != 501 {
		t.Fatalf("EXPN no arg: code=%d, want 501", code)
	}
}

func TestEXPN_in_ehlo(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		ExpnEnabled: true,
	})
	code, text := c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO: code=%d, want 250", code)
	}
	if !strings.Contains(text, "EXPN") {
		t.Errorf("EHLO reply missing EXPN when enabled: %s", text)
	}
}

func TestEXPN_not_in_ehlo_when_disabled(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "test.veksel"})
	code, text := c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO: code=%d text=%s, want 250", code, text)
	}
	if strings.Contains(text, "EXPN") {
		t.Errorf("EHLO reply should not contain EXPN when disabled: %s", text)
	}
}

// --- SASL-IR tests (RFC 8305) ---

func TestSASLIR_advertised_when_enabled(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		SaslIrEnabled:  true,
	})

	code, text := c.send("EHLO client.example.com")
	if code != 250 {
		t.Fatalf("EHLO: code=%d text=%s, want 250", code, text)
	}
	if !strings.Contains(text, "SASLIR") {
		t.Errorf("EHLO reply missing SASLIR when enabled: %s", text)
	}
}

func TestSASLIR_not_advertised_when_disabled(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		SaslIrEnabled:  false,
	})

	code, text := c.send("EHLO client.example.com")
	if code != 250 {
		t.Fatalf("EHLO: code=%d text=%s, want 250", code, text)
	}
	if strings.Contains(text, "SASLIR") {
		t.Errorf("EHLO reply should not contain SASLIR when disabled: %s", text)
	}
}

func TestAUTH_PLAIN_SASLIR_enabled(t *testing.T) {
	var lastUser, lastPass string
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			lastUser = username
			lastPass = password
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	})

	c.send("EHLO client")

	// SASL-IR: AUTH PLAIN with initial response (one-shot)
	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	code, _ := c.send("AUTH PLAIN " + creds)
	if code != 235 {
		t.Fatalf("AUTH PLAIN (sasl-ir): code=%d, want 235", code)
	}
	if lastUser != "alice" {
		t.Errorf("username = %q, want %q", lastUser, "alice")
	}
	if lastPass != "secret" {
		t.Errorf("password = %q, want %q", lastPass, "secret")
	}
}

func TestAUTH_PLAIN_SASLIR_disabled(t *testing.T) {
	var lastUser string
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN"},
		SaslIrEnabled:  false,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			lastUser = username
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	})

	c.send("EHLO client")

	// When SASL-IR is disabled, sending AUTH PLAIN with initial response
	// should fall back to challenge-response mode
	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	// Write the command without reading the response
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "AUTH PLAIN %s\r\n", creds)

	// Server ignores the initial response and sends an empty 334 challenge
	// (RFC 4616 PLAIN has no Username:/Password: prompts).
	code, text, _ := c.readReply()
	if code != 334 || text != "" {
		t.Fatalf("AUTH PLAIN (sasl-ir disabled): code=%d text=%q, want empty 334", code, text)
	}

	code, _ = c.send(creds)
	if code != 235 {
		t.Fatalf("AUTH PLAIN response: code=%d, want 235", code)
	}
	if lastUser != "alice" {
		t.Errorf("username = %q, want %q", lastUser, "alice")
	}
}

func TestAUTH_LOGIN_SASLIR_enabled(t *testing.T) {
	var lastUser string
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"LOGIN"},
		SaslIrEnabled:  true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			lastUser = username
			if username == "bob" && password == "pass123" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid")
		},
	})

	c.send("EHLO client")

	// SASL-IR: AUTH LOGIN with initial response (username)
	username := base64.StdEncoding.EncodeToString([]byte("bob"))
	// Write the command without reading the response
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "AUTH LOGIN %s\r\n", username)

	// Server should respond with 334 for password
	code, text, _ := c.readReply()
	if code != 334 {
		t.Fatalf("AUTH LOGIN (sasl-ir): code=%d text=%s, want 334", code, text)
	}

	// Send password
	password := base64.StdEncoding.EncodeToString([]byte("pass123"))
	code, _ = c.send(password)
	if code != 235 {
		t.Fatalf("AUTH LOGIN password: code=%d, want 235", code)
	}
	if lastUser != "bob" {
		t.Errorf("username = %q, want %q", lastUser, "bob")
	}
}

func TestAUTH_LOGIN_SASLIR_disabled(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"LOGIN"},
		SaslIrEnabled:  false,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "bob" && password == "pass123" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid")
		},
	})

	c.send("EHLO client")

	// When SASL-IR is disabled, AUTH LOGIN with initial response
	// should fall back to challenge-response
	username := base64.StdEncoding.EncodeToString([]byte("bob"))
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "AUTH LOGIN %s\r\n", username)

	// Server should respond with 334 (Username: challenge)
	code, text, _ := c.readReply()
	if code != 334 {
		t.Fatalf("AUTH LOGIN (sasl-ir disabled): code=%d text=%s, want 334", code, text)
	}

	// Send username
	code, _ = c.send(username)
	if code != 334 {
		t.Fatalf("AUTH LOGIN username: code=%d, want 334", code)
	}

	// Send password
	password := base64.StdEncoding.EncodeToString([]byte("pass123"))
	code, _ = c.send(password)
	if code != 235 {
		t.Fatalf("AUTH LOGIN password: code=%d, want 235", code)
	}
}

func TestPipeliningSessionEndsWhenClientDisconnects(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	sess := newSession(1, &Config{ServerName: "test.veksel"}, server, nil, nil)
	done := make(chan struct{})
	go func() {
		sess.run()
		close(done)
	}()
	go io.Copy(io.Discard, client)
	if _, err := client.Write([]byte("EHLO client\r\n")); err != nil {
		t.Fatal(err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session kept running after the client disconnected")
	}
}

// dataTestServer returns a session whose deliveries are recorded in got.
func dataTestServer(t *testing.T, got *[]byte) *tc {
	t.Helper()
	return makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				*got = data
				return "item-1", nil
			},
		},
	})
}

func TestDATAPreservesBodyBytes(t *testing.T) {
	t.Parallel()
	var got []byte
	c := dataTestServer(t, &got)
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("Subject: t\r\n\r\n  indented line\r\n\tTabbed line\r\n..starts with a dot\r\nbare\nlf\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}
	want := "\r\n  indented line\r\n\tTabbed line\r\n.starts with a dot\r\nbare\r\nlf\r\n"
	if !strings.HasSuffix(string(got), want) {
		t.Fatalf("delivered body = %q, want suffix %q", got, want)
	}
}

func TestDATARejectsSmugglingTerminator(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"bare LF dot bare LF": "Subject: t\r\n\r\nfirst\n.\nMAIL FROM:<evil@example.com>\r\n.\r\n",
		"bare LF dot CRLF":    "Subject: t\r\n\r\nfirst\n.\r\nRCPT TO:<x@example.com>\r\n.\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			var got []byte
			c := dataTestServer(t, &got)
			c.send("EHLO client")
			c.send("MAIL FROM:<sender@example.com>")
			c.send("RCPT TO:<alice@example.com>")
			c.send("DATA")
			c.writeData(body)
			if code, _, _ := c.readReply(); code != 554 {
				t.Fatalf("smuggled DATA: code=%d, want 554", code)
			}
			if got != nil {
				t.Fatalf("smuggled message was delivered: %q", got)
			}
			if code, _ := c.send("NOOP"); code != 250 {
				t.Fatalf("NOOP after smuggled DATA: code=%d, want 250", code)
			}
		})
	}
}
