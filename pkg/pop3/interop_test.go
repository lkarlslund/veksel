package pop3

import (
	"context"
	"strings"
	"testing"
)

// TestRepliesEndWithCRLF replays the raw greeting and single-line replies:
// RFC 1939 terminates every response line with CRLF, and Veksel wrote a bare
// LF, which strict clients never see as a complete line.
func TestRepliesEndWithCRLF(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()
	c := newPop3Client(t, addr) // consumes the greeting
	defer c.close()
	for _, command := range []string{"CAPA", "USER alice", "PASS secret", "NOOP", "FOO"} {
		c.w.WriteString(command + "\r\n")
		c.w.Flush()
		line, err := c.r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("%s reply %q does not end with CRLF", command, line)
		}
		if command == "CAPA" {
			if _, err := c.readUntilDot(); err != nil {
				t.Fatal(err)
			}
		}
		if command == "NOOP" && !strings.HasPrefix(line, "+OK") {
			t.Fatalf("NOOP in the transaction state = %q", line)
		}
	}
}

// TestDeletedMessagesFollowRFC1939 replays a client exchange where DELE 1
// was repeated and RETR 1, LIST and STAT still served the deleted message.
// Deleted messages must be refused and not counted until RSET.
func TestDeletedMessagesFollowRFC1939(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()
	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	for _, subject := range []string{"one", "two"} {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte("Subject: "+subject+"\r\n\r\nline one\r\nline two\r\n.dot line\r\n"), nil); err != nil {
			t.Fatal(err)
		}
	}
	c := newPop3Client(t, addr)
	defer c.close()
	c.cmd("USER alice")
	c.cmd("PASS secret")
	statBefore, _ := c.cmd("STAT")
	if resp, _ := c.cmd("DELE 1"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("DELE 1 = %q", resp)
	}
	for _, command := range []string{"DELE 1", "RETR 1", "TOP 1 0", "LIST 1", "UIDL 1"} {
		if resp, _ := c.cmd(command); !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("%s after DELE 1 = %q, want -ERR", command, resp)
		}
	}
	if resp, _ := c.cmd("STAT"); !strings.HasPrefix(resp, "+OK 1 ") {
		t.Fatalf("STAT after DELE 1 = %q (before %q)", resp, statBefore)
	}
	c.cmd("LIST")
	if listing, _ := c.readUntilDot(); strings.HasPrefix(listing, "1 ") || !strings.HasPrefix(listing, "2 ") {
		t.Fatalf("LIST after DELE 1 = %q", listing)
	}
	c.cmd("RSET")
	if resp, _ := c.cmd("STAT"); resp != statBefore {
		t.Fatalf("STAT after RSET = %q, want %q", resp, statBefore)
	}

	// TOP msg n returns the header, the separating blank line and exactly n
	// body lines; it returned n bytes ("TOP 2 1" gave "l").
	c.cmd("TOP 2 1")
	top, _ := c.readUntilDot()
	if top != "Subject: two\n\nline one\n" {
		t.Fatalf("TOP 2 1 = %q", top)
	}
	c.cmd("TOP 2 3")
	if top, _ = c.readUntilDot(); !strings.HasSuffix(top, "line two\n..dot line\n") {
		t.Fatalf("TOP 2 3 = %q, want dot-stuffed body lines", top)
	}
}

// TestMessageNumbersStayStableDuringSession replays a POP3 session while
// another client removed a message: message numbers were recomputed on
// every command, so DELE 2 marked a different message than the client saw.
func TestMessageNumbersStayStableDuringSession(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()
	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	var ids []string
	for _, subject := range []string{"first", "second", "third"} {
		item, err := ts.ItemStore().Append(ctx, folder.ID, []byte("Subject: "+subject+"\r\n\r\nbody\r\n"), nil)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, item)
	}
	c := newPop3Client(t, addr)
	defer c.close()
	c.cmd("USER alice")
	c.cmd("PASS secret")
	c.cmd("UIDL")
	before, _ := c.readUntilDot()
	if err := ts.ItemStore().Delete(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	c.cmd("UIDL")
	if after, _ := c.readUntilDot(); after != before {
		t.Fatalf("UIDL changed during the session:\nbefore %q\nafter  %q", before, after)
	}
	c.cmd("TOP 2 0")
	if top, _ := c.readUntilDot(); !strings.Contains(top, "Subject: second") {
		t.Fatalf("message 2 = %q, want the second message", top)
	}
	if resp, _ := c.cmd("RETR 1"); !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("RETR of a message removed elsewhere = %q", resp)
	}
}
