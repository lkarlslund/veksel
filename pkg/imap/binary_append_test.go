package imap

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// TestBinaryAppendLiteral8AndFetchRoundTrip: with BINARY (RFC 3516) a
// message holding NUL octets is appended as a literal8 and stored
// unmodified, and FETCH BINARY decodes its parts.
func TestBinaryAppendLiteral8AndFetchRoundTrip(t *testing.T) {
	t.Parallel()
	session := &Session{cfg: &Config{}}
	advertised := false
	for _, capability := range session.buildCapabilities() {
		advertised = advertised || capability == "BINARY"
	}
	if !advertised {
		t.Fatal("BINARY not advertised")
	}
	c := newUTF8TestClient(t)
	message := "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n" +
		"--x\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n\x00\x01\xff\x00\r\n" +
		"--x\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8A\r\n--x--\r\n"
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c.Conn, "A2 APPEND INBOX ~{%d}\r\n", len(message))
	if _, err := c.readContinuation(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c.Conn, "%s\r\n", message)
	if _, code, text := c.readResponse(); code != "OK" {
		t.Fatalf("APPEND literal8: %s %s", code, text)
	}
	// A literal8 may be non-synchronizing too (RFC 7888 LITERAL+).
	fmt.Fprintf(c.Conn, "A3 APPEND INBOX (\\Seen) ~{%d+}\r\n%s\r\n", len(message), message)
	if _, code, text := c.readResponse(); code != "OK" {
		t.Fatalf("APPEND non-synchronizing literal8: %s %s", code, text)
	}
	c.send("A4", "SELECT INBOX")
	if got := fetchOneLiteral(t, c, "A5", "FETCH 2 BINARY.PEEK[]"); string(got) != message {
		t.Fatalf("stored message changed: %q", got)
	}
	if got := fetchOneLiteral(t, c, "A6", "FETCH 1 BINARY.PEEK[1]"); !bytes.Equal(got, []byte{0, 1, 0xff, 0}) {
		t.Fatalf("binary part = %q", got)
	}
	if got := fetchOneLiteral(t, c, "A7", "FETCH 1 BINARY.PEEK[2]"); string(got) != "Hello\x00" {
		t.Fatalf("base64 part = %q", got)
	}
	if lines := c.sendAndCollect("A8", "FETCH 1 BINARY.SIZE[2]"); !containsSubstring(lines, "BINARY.SIZE[2] 6") {
		t.Fatalf("BINARY.SIZE: %q", lines)
	}
}
