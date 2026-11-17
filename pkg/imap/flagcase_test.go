package imap

import (
	"context"
	"strings"
	"testing"
)

// STORE must keep the model's canonical system-flag spelling and the client's
// keyword case. OfflineIMAP and web/JMAP code compare against these values, and
// ItemStore.RemoveFlags is case sensitive, so an upper-cased "\SEEN" could never
// be unset from the web UI.
func TestStorePreservesFlagCase(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Case\r\n\r\nBody\r\n"
	if _, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg)); code != "OK" {
		t.Fatalf("APPEND: code=%s", code)
	}
	for _, command := range []string{"STORE 1 +FLAGS (\\seen $Forwarded)", "UID STORE 1 FLAGS (\\Flagged $MyLabel)"} {
		c.sendNoTag("A004 " + command)
		lines := c.readUntagged()
		joined := strings.Join(lines, "\n")
		if !strings.Contains(lines[len(lines)-1], "A004 OK") {
			t.Fatalf("%s: %q", command, joined)
		}
		if strings.Contains(joined, "\\SEEN") || strings.Contains(joined, "\\FLAGGED") || strings.Contains(joined, "$FORWARDED") || strings.Contains(joined, "$MYLABEL") {
			t.Fatalf("%s: flags were upper-cased: %q", command, joined)
		}
		if !strings.Contains(joined, "\\Seen") && !strings.Contains(joined, "\\Flagged") {
			t.Fatalf("%s: canonical system flag missing: %q", command, joined)
		}
	}
}
