package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// makeRequireTLSServer starts a STARTTLS-capable server that refuses
// cleartext authentication. The returned counter records validator calls.
func makeRequireTLSServer(t *testing.T) (*tc, *atomic.Int32) {
	t.Helper()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	calls := new(atomic.Int32)
	c := makeTestServer(t, &Config{
		ServerName:        "test.veksel",
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		RequireTLSForAuth: true,
		SaslIrEnabled:     true,
		AuthValidator: func(context.Context, string, string) (string, error) {
			calls.Add(1)
			return "alice", nil
		},
		OAuth2Validator: func(context.Context, string, string) (string, error) {
			calls.Add(1)
			return "alice", nil
		},
		TypedStore: setupTestStore(t),
	})
	return c, calls
}

func capabilityTokens(t *testing.T, c *tc, tag string) []string {
	t.Helper()
	c.sendNoTag(tag + " CAPABILITY")
	var caps []string
	for _, line := range c.readUntagged() {
		if rest, ok := strings.CutPrefix(line, "* CAPABILITY "); ok {
			caps = strings.Fields(rest)
		} else if strings.HasPrefix(line, tag+" ") && !strings.HasPrefix(line, tag+" OK") {
			t.Fatalf("CAPABILITY failed: %s", line)
		}
	}
	if caps == nil {
		t.Fatal("no CAPABILITY response")
	}
	return caps
}

func startTLS(t *testing.T, c *tc) {
	t.Helper()
	if _, code, text := c.send("S1", "STARTTLS"); code != "OK" {
		t.Fatalf("STARTTLS = %s %s", code, text)
	}
	tlsConn := tls.Client(c.Conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	c.Conn = tlsConn
	c.r = bufio.NewReader(tlsConn)
}

func TestRequireTLSAdvertisesLoginDisabledBeforeTLS(t *testing.T) {
	t.Parallel()
	c, _ := makeRequireTLSServer(t)

	caps := capabilityTokens(t, c, "C1")
	if !slices.Contains(caps, "LOGINDISABLED") || !slices.Contains(caps, "STARTTLS") {
		t.Fatalf("cleartext capabilities = %v, want LOGINDISABLED and STARTTLS", caps)
	}
	for _, forbidden := range []string{"AUTH=PLAIN", "AUTH=LOGIN", "AUTH=XOAUTH2"} {
		if slices.Contains(caps, forbidden) {
			t.Fatalf("cleartext capabilities advertise %s: %v", forbidden, caps)
		}
	}

	startTLS(t, c)
	caps = capabilityTokens(t, c, "C2")
	if slices.Contains(caps, "LOGINDISABLED") || slices.Contains(caps, "STARTTLS") {
		t.Fatalf("TLS capabilities = %v, want neither LOGINDISABLED nor STARTTLS", caps)
	}
	for _, want := range []string{"AUTH=PLAIN", "AUTH=LOGIN", "AUTH=XOAUTH2"} {
		if !slices.Contains(caps, want) {
			t.Fatalf("TLS capabilities = %v, missing %s", caps, want)
		}
	}
}

func TestRequireTLSRefusesCleartextAuthentication(t *testing.T) {
	t.Parallel()
	c, calls := makeRequireTLSServer(t)

	plain := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	for _, command := range []string{
		"LOGIN alice secret",
		"AUTHENTICATE PLAIN " + plain,
		"AUTHENTICATE PLAIN",
		"AUTHENTICATE LOGIN",
		"AUTHENTICATE XOAUTH2 dG9rZW4=",
	} {
		_, code, text := c.send("A1", command)
		if code != "NO" || !strings.HasPrefix(text, "[PRIVACYREQUIRED]") {
			t.Fatalf("%s = %s %s, want NO [PRIVACYREQUIRED]", command, code, text)
		}
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("validator called %d times before TLS", got)
	}
	if _, code, _ := c.send("A2", "SELECT INBOX"); code == "OK" {
		t.Fatal("session became authenticated after refused cleartext login")
	}
}

// TestStartTLSRefusesPipelinedCleartext checks that a command sent in the
// same cleartext write as STARTTLS is neither lost nor executed after the TLS
// upgrade; the session ends instead.
func TestStartTLSRefusesPipelinedCleartext(t *testing.T) {
	t.Parallel()
	c, calls := makeRequireTLSServer(t)

	c.sendNoTag("S1 STARTTLS\r\nA1 LOGIN alice secret")
	line, err := c.readLine()
	if err != nil || !strings.HasPrefix(line, "* BYE ") {
		t.Fatalf("response to pipelined STARTTLS = %q, %v; want BYE", line, err)
	}
	if line, err := c.readLine(); err == nil {
		t.Fatalf("session continued after BYE: %q", line)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("validator called %d times for injected LOGIN", got)
	}
}

func TestRequireTLSAllowsLoginAfterStartTLS(t *testing.T) {
	t.Parallel()
	c, calls := makeRequireTLSServer(t)

	startTLS(t, c)
	if _, code, text := c.send("A1", "LOGIN alice secret"); code != "OK" {
		t.Fatalf("LOGIN after STARTTLS = %s %s", code, text)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("validator calls = %d, want 1", got)
	}
}

func TestAuthenticatePasswordExchangeErrors(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		SaslIrEnabled: true,
		AuthValidator: func(context.Context, string, string) (string, error) {
			calls.Add(1)
			return "alice", nil
		},
		TypedStore: setupTestStore(t),
	})
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for i, tt := range []struct{ command, code, text string }{
		{"AUTHENTICATE PLAIN " + b64("bob\x00alice\x00secret"), "NO", "[AUTHORIZATIONFAILED]"},
		{"AUTHENTICATE PLAIN " + b64("alice\x00secret"), "BAD", "Invalid PLAIN credentials"},
		{"AUTHENTICATE PLAIN %%%", "BAD", "Invalid base64"},
		{"AUTHENTICATE PLAIN =", "BAD", "Invalid PLAIN credentials"},
	} {
		tag := "E" + string(rune('A'+i))
		if _, code, text := c.send(tag, tt.command); code != tt.code || !strings.Contains(text, tt.text) {
			t.Fatalf("%s: %s %s, want %s %s", tt.command, code, text, tt.code, tt.text)
		}
	}

	c.sendNoTag("C1 AUTHENTICATE LOGIN")
	if line, err := c.readContinuation(); err != nil || line != "+ "+b64("Username:") {
		t.Fatalf("LOGIN challenge = %q, %v", line, err)
	}
	c.sendNoTag("*")
	if _, code, text := c.readResponse(); code != "BAD" || !strings.Contains(text, "canceled") {
		t.Fatalf("cancel: %s %s, want BAD canceled", code, text)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("validator ran %d times for failed exchanges", got)
	}

	if _, code, text := c.send("OK1", "AUTHENTICATE PLAIN "+b64("alice\x00alice\x00secret")); code != "OK" {
		t.Fatalf("PLAIN with matching authzid: %s %s", code, text)
	}
}
