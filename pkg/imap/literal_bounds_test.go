package imap

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// streamLiterals writes count non-synchronizing literals of size bytes, each
// announcing the next, and never ends the command.
func streamLiterals(c *tc, prefix string, count, size int) {
	go func() {
		chunk := strings.Repeat("x", size)
		_ = c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintf(c.Conn, "%s{%d+}\r\n", prefix, size); err != nil {
			return
		}
		for range count {
			if _, err := fmt.Fprintf(c.Conn, "%s {%d+}\r\n", chunk, size); err != nil {
				return
			}
		}
	}()
}

// TestCommandLiteralsAreBoundedInTotal: every literal of a command is capped,
// but a command could chain literals without end, each spliced into one
// line held in memory. The command line as a whole stays bounded.
func TestCommandLiteralsAreBoundedInTotal(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{ServerName: "test.veksel", TypedStore: setupTestStore(t)})
	streamLiterals(c, "A1 LOGIN ", maxCommandLineLength/4096+16, 4096)
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("server kept reading an endless chain of literals: %v", err)
		}
		if strings.HasPrefix(line, "* BYE") {
			return
		}
	}
}

// TestSearchLiteralsAreBoundedInTotal is the same for SEARCH, which reads
// its own literals.
func TestSearchLiteralsAreBoundedInTotal(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    setupTestStore(t),
	})
	c.send("A1", "LOGIN alice secret")
	c.send("A2", "SELECT INBOX")
	streamLiterals(c, "A3 SEARCH SUBJECT ", maxSearchLiteralSize/4096+16, 4096)
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("server kept reading an endless chain of SEARCH literals: %v", err)
		}
		if strings.HasPrefix(line, "A3 BAD") || strings.HasPrefix(line, "* BYE") {
			return
		}
	}
}

// injectedLiteral is literal content that reads as commands if a server
// takes it for input after refusing the command that announced it.
const injectedLiteral = "x1 CREATE Injected\r\nx2 LOGOUT\r\n"

// expectNotInjected reads through the response tagged tag and fails if any
// command hidden in injectedLiteral was executed.
func expectNotInjected(t *testing.T, c *tc, tag string) {
	t.Helper()
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("waiting for %s: %v", tag, err)
		}
		if strings.HasPrefix(line, "x1 ") || strings.HasPrefix(line, "x2 ") || strings.HasPrefix(line, "* BYE") {
			t.Fatalf("literal content was executed as a command: %q", line)
		}
		if strings.HasPrefix(line, tag+" ") {
			return
		}
	}
}

// TestRefusedCommandSkipsItsNonSynchronizingLiteral: APPEND and SEARCH read
// their own literals, and a command refused before that (no mailbox
// selected, unknown mailbox) left a non-synchronizing literal in the input,
// where its content was parsed as commands.
func TestRefusedCommandSkipsItsNonSynchronizingLiteral(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    setupTestStore(t),
	})
	c.send("A1", "LOGIN alice secret")
	commands := []string{
		"A2 SEARCH SUBJECT {%d+}\r\n%s CHARSET {%d+}\r\n%s\r\n",
		"A3 APPEND Missing {%d+}\r\n%s {%d+}\r\n%s\r\n",
	}
	for index, command := range commands {
		tag := fmt.Sprintf("A%d", index+2)
		fmt.Fprintf(c.Conn, command, len(injectedLiteral), injectedLiteral, len(injectedLiteral), injectedLiteral)
		expectNotInjected(t, c, tag)
	}
	c.sendNoTag(`A4 LIST "" Injected`)
	expectNotInjected(t, c, "A4")
	if _, code, text := c.send("A5", "NOOP"); code != "OK" {
		t.Fatalf("session did not continue after skipping the literals: %s %s", code, text)
	}
}

// TestLargeNonSynchronizingLiteralsAreRead: LITERAL+ (RFC 7888) allows
// non-synchronizing literals over 4096 bytes, in commands whose literals are
// spliced (LOGIN) and in those that read their own (SEARCH), and a refused
// APPEND skips one up to its limit without executing its content.
func TestLargeNonSynchronizingLiteralsAreRead(t *testing.T) {
	t.Parallel()
	password := strings.Repeat("p", 5000)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, _ string, secret string) (string, error) {
			if secret != password {
				return "", fmt.Errorf("bad password")
			}
			return "alice", nil
		},
		TypedStore: setupTestStore(t),
	})
	fmt.Fprintf(c.Conn, "A1 LOGIN alice {%d+}\r\n%s\r\n", len(password), password)
	expectTagged(t, c, "A1", "OK")
	c.send("A2", "SELECT INBOX")
	subject := strings.Repeat("s", 6000)
	fmt.Fprintf(c.Conn, "A3 SEARCH SUBJECT {%d+}\r\n%s\r\n", len(subject), subject)
	expectTagged(t, c, "A3", "OK")
	literal := injectedLiteral + strings.Repeat("y", 20000)
	fmt.Fprintf(c.Conn, "A4 APPEND Missing {%d+}\r\n%s\r\n", len(literal), literal)
	expectNotInjected(t, c, "A4")
	if _, code, text := c.send("A5", "NOOP"); code != "OK" {
		t.Fatalf("session did not continue after skipping the literal: %s %s", code, text)
	}
}

// expectTagged reads through the response tagged tag and fails unless it
// completed with status.
func expectTagged(t *testing.T, c *tc, tag, status string) {
	t.Helper()
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("waiting for %s: %v", tag, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(line, tag+" "+status) {
				t.Fatalf("%s: %q", tag, line)
			}
			return
		}
	}
}

// TestOversizedNonSynchronizingSearchLiteralEndsSession: a non-synchronizing
// literal over the SEARCH literal budget is refused, and its content,
// already sent, is not read, so the session ends without executing it.
func TestOversizedNonSynchronizingSearchLiteralEndsSession(t *testing.T) {
	t.Parallel()
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    setupTestStore(t),
	})
	c.send("A1", "LOGIN alice secret")
	c.send("A2", "SELECT INBOX")
	literal := injectedLiteral + strings.Repeat("y", maxSearchLiteralSize)
	go func() {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c.Conn, "A3 SEARCH SUBJECT {%d+}\r\n%s\r\n", len(literal), literal)
	}()
	sawBAD := false
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("session neither ended nor answered: %v", err)
		}
		if strings.HasPrefix(line, "x1 ") || strings.HasPrefix(line, "x2 ") {
			t.Fatalf("literal content was executed as a command: %q", line)
		}
		sawBAD = sawBAD || strings.HasPrefix(line, "A3 BAD")
		if strings.HasPrefix(line, "* BYE") {
			if !sawBAD {
				t.Fatal("SEARCH was not answered BAD before the session ended")
			}
			return
		}
	}
}
