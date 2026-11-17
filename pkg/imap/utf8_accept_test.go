package imap

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newUTF8TestClient(t *testing.T) *tc {
	t.Helper()
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    setupTestStore(t),
	})
	c.send("A1", "LOGIN alice secret")
	return c
}

// fetchOneLiteral sends a FETCH of one literal item and returns its octets.
func fetchOneLiteral(t *testing.T, c *tc, tag, command string) []byte {
	t.Helper()
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c.Conn, "%s %s\r\n", tag, command)
	var data []byte
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(line, tag+" OK") {
				t.Fatalf("%s: %q", command, line)
			}
			return data
		}
		line = strings.TrimRight(line, "\r\n")
		if open := strings.LastIndexByte(line, '{'); open >= 0 && strings.HasSuffix(line, "}") && data == nil {
			size, err := strconv.Atoi(line[open+1 : len(line)-1])
			if err != nil {
				t.Fatalf("literal size in %q: %v", line, err)
			}
			data = make([]byte, size)
			if _, err := io.ReadFull(c.r, data); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestUTF8AcceptIsAdvertisedAndEnabled(t *testing.T) {
	t.Parallel()
	session := &Session{cfg: &Config{}}
	found := false
	for _, capability := range session.buildCapabilities() {
		found = found || capability == "UTF8=ACCEPT"
	}
	if !found {
		t.Fatal("UTF8=ACCEPT not advertised")
	}
	c := newUTF8TestClient(t)
	lines := c.sendAndCollect("A2", "ENABLE UTF8=ACCEPT")
	if !containsLine(lines, "* ENABLED UTF8=ACCEPT") {
		t.Fatalf("ENABLE UTF8=ACCEPT: %q", lines)
	}
}

// TestUTF8AcceptMailboxNames: before ENABLE UTF8=ACCEPT mailbox names are
// modified UTF-7 on the wire; after it they are UTF-8 (RFC 6855 3), both for
// names the client sends and the names in LIST responses.
func TestUTF8AcceptMailboxNames(t *testing.T) {
	t.Parallel()
	c := newUTF8TestClient(t)
	if _, code, text := c.send("A2", `CREATE "&AMk-t&AOk-"`); code != "OK" {
		t.Fatalf("CREATE modified UTF-7: %s %s", code, text)
	}
	if lines := c.sendAndCollect("A3", `LIST "" "*t*"`); !containsSubstring(lines, `"&AMk-t&AOk-"`) {
		t.Fatalf("LIST before ENABLE: %q", lines)
	}
	c.send("A4", "ENABLE UTF8=ACCEPT")
	if lines := c.sendAndCollect("A5", `LIST "" "*t*"`); !containsSubstring(lines, `"Été"`) || containsSubstring(lines, "&AMk-") {
		t.Fatalf("LIST after ENABLE: %q", lines)
	}
	if _, code, text := c.send("A6", `CREATE "Ünïcode"`); code != "OK" {
		t.Fatalf("CREATE UTF-8: %s %s", code, text)
	}
	if _, code, text := c.send("A7", `SELECT "Ünïcode"`); code != "OK" {
		t.Fatalf("SELECT UTF-8: %s %s", code, text)
	}
}

// TestUTF8AcceptAppendForm: APPEND takes "UTF8 (~{n})" only after ENABLE
// UTF8=ACCEPT, and a message with 8-bit headers is returned unmodified.
func TestUTF8AcceptAppendForm(t *testing.T) {
	t.Parallel()
	c := newUTF8TestClient(t)
	message := "Subject: Grüße aus Köln\r\nFrom: Jörg <jörg@example.org>\r\n\r\nHallo\r\n"
	if _, code, _ := c.send("A2", fmt.Sprintf("APPEND INBOX UTF8 (~{%d}", len(message))); code != "BAD" {
		t.Fatalf("APPEND UTF8 before ENABLE answered %s", code)
	}
	if _, code, _ := c.send("A3", "NOOP"); code != "OK" {
		t.Fatal("session did not continue after a refused APPEND UTF8")
	}
	c.send("A4", "ENABLE UTF8=ACCEPT")
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c.Conn, "A5 APPEND INBOX (\\Seen) UTF8 (~{%d+}\r\n%s)\r\n", len(message), message)
	if _, code, text := c.readResponse(); code != "OK" || !strings.Contains(text, "APPENDUID") {
		t.Fatalf("APPEND UTF8: %s %s", code, text)
	}
	c.send("A6", "SELECT INBOX")
	if got := fetchOneLiteral(t, c, "A7", "FETCH 1 BODY.PEEK[]"); string(got) != message {
		t.Fatalf("8-bit message changed:\n%q\nwant\n%q", got, message)
	}
	fmt.Fprintf(c.Conn, "A8 APPEND INBOX UTF8 (~{%d+}\r\n%s\r\n", len(message), message)
	if _, code, _ := c.readResponse(); code != "BAD" {
		t.Fatalf("APPEND UTF8 without ) answered %s", code)
	}
}

func (c *tc) sendAndCollect(tag, command string) []string {
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c.Conn, "%s %s\r\n", tag, command)
	return c.readUntagged()
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if strings.TrimRight(line, "\r\n") == want {
			return true
		}
	}
	return false
}

func containsSubstring(lines []string, want string) bool {
	for _, line := range lines {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
}
