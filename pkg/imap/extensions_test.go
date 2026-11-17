package imap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/service"
)

// sharedServer accepts any number of sessions on one server so tests can
// observe one session's changes from another.
type sharedServer struct {
	t      *testing.T
	cfg    *Config
	server *Server
	addr   string
}

func newSharedServer(t *testing.T, withIndex bool) *sharedServer {
	t.Helper()
	ts := setupTestStore(t)
	cfg := &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		TypedStore: ts,
	}
	if withIndex {
		cfg.MailIndex = mailindex.New(ts.Store())
	}
	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Accept(t.Context(), ln)
	t.Cleanup(func() { srv.Close() })
	return &sharedServer{t: t, cfg: cfg, server: srv, addr: ln.Addr().String()}
}

// client opens a logged-in session.
func (s *sharedServer) client() *tc {
	s.t.Helper()
	conn, err := net.Dial("tcp", s.addr)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { conn.Close() })
	c := &tc{Conn: conn, r: bufio.NewReader(conn)}
	if _, err := c.readLine(); err != nil {
		s.t.Fatalf("greeting: %v", err)
	}
	if _, code, text := c.send("L001", "LOGIN alice secret"); code != "OK" {
		s.t.Fatalf("LOGIN: %s %s", code, text)
	}
	return c
}

// run sends a command and returns every response line through the tagged one.
func (c *tc) run(t *testing.T, tag, command string) string {
	t.Helper()
	c.sendNoTag(tag + " " + command)
	var lines []string
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("%s: %v (got %q)", command, err, lines)
		}
		lines = append(lines, line)
		c.consumeLiteral(line)
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func (c *tc) mustOK(t *testing.T, tag, command string) string {
	t.Helper()
	out := c.run(t, tag, command)
	if !strings.Contains(out, tag+" OK") {
		t.Fatalf("%s failed:\n%s", command, out)
	}
	return out
}

func (c *tc) mustAppend(t *testing.T, mailbox, message string) {
	t.Helper()
	if _, code, text := c.appendMsg("AP01", mailbox, nil, "", []byte(message)); code != "OK" {
		t.Fatalf("APPEND %s: %s %s", mailbox, code, text)
	}
}

// expectLine waits for an unsolicited line containing want.
func (c *tc) expectLine(t *testing.T, want string) string {
	t.Helper()
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("waiting for %q: %v", want, err)
		}
		if strings.Contains(line, want) {
			return line
		}
	}
}

func submatch(t *testing.T, pattern, text string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("no match for %s in:\n%s", pattern, text)
	}
	return m[1]
}

const threadRoot = "Message-ID: <root@example.com>\r\nFrom: a@example.com\r\nSubject: Plans\r\n\r\nFirst body\r\n"
const threadReply = "Message-ID: <reply@example.com>\r\nIn-Reply-To: <root@example.com>\r\nReferences: <root@example.com>\r\nFrom: b@example.com\r\nSubject: Re: Plans\r\n\r\nSecond body\r\n"

func TestExtensionCapabilities(t *testing.T) {
	c := newSharedServer(t, false).client()
	out := c.mustOK(t, "C1", "CAPABILITY")
	for _, capability := range []string{"OBJECTID", "PREVIEW", "SAVEDATE", "NOTIFY", "IDLE", "CONDSTORE"} {
		if !strings.Contains(out, " "+capability) {
			t.Errorf("CAPABILITY lacks %s: %s", capability, out)
		}
	}
}

func TestObjectIDsAreStableAcrossMove(t *testing.T) {
	c := newSharedServer(t, false).client()
	c.mustAppend(t, "INBOX", threadRoot)
	c.mustAppend(t, "INBOX", threadReply)
	c.mustAppend(t, "INBOX", "Message-ID: <other@example.com>\r\nSubject: Else\r\n\r\nx\r\n")

	selected := c.mustOK(t, "S1", "SELECT INBOX")
	inboxID := submatch(t, `\[MAILBOXID \(([A-Za-z0-9_-]+)\)\]`, selected)
	status := c.mustOK(t, "S2", "STATUS INBOX (MAILBOXID MESSAGES)")
	if got := submatch(t, `MAILBOXID \(([A-Za-z0-9_-]+)\)`, status); got != inboxID {
		t.Fatalf("STATUS MAILBOXID = %q, SELECT said %q", got, inboxID)
	}

	fetched := c.mustOK(t, "F1", "UID FETCH 1:3 (EMAILID THREADID)")
	ids := regexp.MustCompile(`EMAILID \(([A-Za-z0-9_-]+)\) THREADID \(([A-Za-z0-9_-]+)\)`).FindAllStringSubmatch(fetched, -1)
	if len(ids) != 3 {
		t.Fatalf("FETCH response:\n%s", fetched)
	}
	if ids[0][1] == ids[1][1] || ids[0][2] != ids[1][2] || ids[0][2] == ids[2][2] {
		t.Fatalf("email IDs must differ and the reply must share the root's thread: %v", ids)
	}
	if !regexp.MustCompile(`^thr-[0-9a-f]+$`).MatchString(ids[0][2]) {
		t.Fatalf("thread ID %q is not the shared pkg/threading form", ids[0][2])
	}

	// SEARCH finds a message by either ID.
	if out := c.mustOK(t, "X1", "UID SEARCH EMAILID "+ids[1][1]); !strings.Contains(out, "* SEARCH 2\n") {
		t.Fatalf("SEARCH EMAILID:\n%s", out)
	}
	if out := c.mustOK(t, "X2", "UID SEARCH THREADID "+ids[0][2]); !strings.Contains(out, "* SEARCH 1 2\n") {
		t.Fatalf("SEARCH THREADID:\n%s", out)
	}

	c.mustOK(t, "M0", "CREATE Projects")
	c.mustOK(t, "M1", "UID MOVE 1:2 Projects")
	archive := c.mustOK(t, "S3", "SELECT Projects")
	archiveID := submatch(t, `\[MAILBOXID \(([A-Za-z0-9_-]+)\)\]`, archive)
	if archiveID == inboxID {
		t.Fatalf("different mailboxes share MAILBOXID %q", archiveID)
	}
	moved := c.mustOK(t, "F2", "FETCH 1:2 (EMAILID THREADID)")
	after := regexp.MustCompile(`EMAILID \(([A-Za-z0-9_-]+)\) THREADID \(([A-Za-z0-9_-]+)\)`).FindAllStringSubmatch(moved, -1)
	if len(after) != 2 || after[0][1] != ids[0][1] || after[1][1] != ids[1][1] || after[0][2] != ids[0][2] || after[1][2] != ids[1][2] {
		t.Fatalf("IDs changed across MOVE:\nbefore %v\nafter  %v", ids, after)
	}
	if out := c.mustOK(t, "X3", "SEARCH EMAILID "+ids[0][1]); !strings.Contains(out, "* SEARCH 1\n") {
		t.Fatalf("SEARCH EMAILID after MOVE:\n%s", out)
	}
	// A mailbox rename keeps its ID.
	c.mustOK(t, "R1", "UNSELECT")
	c.mustOK(t, "R2", "RENAME Projects Old")
	if renamed := c.mustOK(t, "R3", "STATUS Old (MAILBOXID)"); submatch(t, `MAILBOXID \(([A-Za-z0-9_-]+)\)`, renamed) != archiveID {
		t.Fatalf("MAILBOXID changed across RENAME:\n%s", renamed)
	}
}

func TestPreviewAndLazy(t *testing.T) {
	message := "From: a@example.com\r\nSubject: Hi\r\n\r\nHello   there,\r\n   this is the body.\r\n"
	t.Run("computed without a stored projection", func(t *testing.T) {
		c := newSharedServer(t, false).client()
		c.mustAppend(t, "INBOX", message)
		c.mustOK(t, "S1", "SELECT INBOX")
		if out := c.mustOK(t, "F1", "FETCH 1 (PREVIEW)"); !strings.Contains(out, `PREVIEW "Hello there, this is the body."`) {
			t.Fatalf("PREVIEW:\n%s", out)
		}
		// LAZY never pays for computing a preview that is not stored.
		if out := c.mustOK(t, "F2", "FETCH 1 (PREVIEW (LAZY))"); !strings.Contains(out, "PREVIEW NIL") {
			t.Fatalf("PREVIEW (LAZY) without a stored preview:\n%s", out)
		}
	})
	t.Run("stored projection answers LAZY", func(t *testing.T) {
		c := newSharedServer(t, true).client()
		c.mustAppend(t, "INBOX", message)
		c.mustOK(t, "S1", "SELECT INBOX")
		if out := c.mustOK(t, "F1", "UID FETCH 1 (PREVIEW (LAZY) UID)"); !strings.Contains(out, `PREVIEW "Hello there, this is the body."`) {
			t.Fatalf("stored PREVIEW (LAZY):\n%s", out)
		}
	})
	t.Run("long and non-ASCII previews are bounded and literal", func(t *testing.T) {
		c := newSharedServer(t, false).client()
		c.mustAppend(t, "INBOX", "Subject: Long\r\n\r\n"+strings.Repeat("Grüße ", 100)+"\r\n")
		c.mustOK(t, "S1", "SELECT INBOX")
		c.sendNoTag("F1 FETCH 1 (PREVIEW)")
		line, err := c.readLine()
		if err != nil {
			t.Fatal(err)
		}
		size := submatch(t, `PREVIEW \{(\d+)\}`, line)
		var n int
		fmt.Sscanf(size, "%d", &n)
		if n == 0 || n > 4*(mailindex.PreviewRunes+1) {
			t.Fatalf("preview literal size %d not bounded: %q", n, line)
		}
		c.consumeLiteral(line)
		c.expectLine(t, "F1 OK")
	})
}

func TestSaveDateFollowsMove(t *testing.T) {
	srv := newSharedServer(t, false)
	c := srv.client()
	old := "01-Jan-2020 10:00:00 +0000"
	if _, code, text := c.appendMsg("AP01", "INBOX", nil, old, []byte(threadRoot)); code != "OK" {
		t.Fatalf("APPEND: %s %s", code, text)
	}
	access := service.UserAccess("alice", "test")
	inbox, err := srv.cfg.FolderSpace.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	item, err := srv.cfg.FolderSpace.GetItemByUID(t.Context(), access, inbox.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if item.SavedAt.IsZero() {
		t.Fatal("new items record their save time")
	}
	// Backdate the save time so the move below is observable at day resolution.
	item.SavedAt = time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := srv.cfg.TypedStore.ItemStore().SetItem(t.Context(), item); err != nil {
		t.Fatal(err)
	}

	c.mustOK(t, "S1", "SELECT INBOX")
	out := c.mustOK(t, "F1", "FETCH 1 (INTERNALDATE SAVEDATE)")
	if !strings.Contains(out, `INTERNALDATE "01-Jan-2020 10:00:00 +0000"`) || !strings.Contains(out, `SAVEDATE "04-Mar-2021 05:06:07 +0000"`) {
		t.Fatalf("FETCH SAVEDATE before move:\n%s", out)
	}
	for search, want := range map[string]string{
		"SAVEDBEFORE 05-Mar-2021":    "* SEARCH 1\n",
		"SAVEDBEFORE 04-Mar-2021":    "* SEARCH\n",
		"SAVEDON 04-Mar-2021":        "* SEARCH 1\n",
		"SAVEDSINCE 05-Mar-2021":     "* SEARCH\n",
		"NOT SAVEDSINCE 04-Mar-2021": "* SEARCH\n",
		"BEFORE 01-Jan-2021":         "* SEARCH 1\n",
	} {
		if got := c.mustOK(t, "Q1", "SEARCH "+search); !strings.Contains(got+"\n", want) {
			t.Errorf("SEARCH %s = %q, want %q", search, got, strings.TrimSpace(want))
		}
	}

	c.mustOK(t, "M1", "MOVE 1 Archive")
	c.mustOK(t, "S2", "SELECT Archive")
	out = c.mustOK(t, "F2", "FETCH 1 (INTERNALDATE SAVEDATE)")
	year := time.Now().UTC().Format("2006")
	if !strings.Contains(out, `INTERNALDATE "01-Jan-2020 10:00:00 +0000"`) || !strings.Contains(out, "-"+year+" ") || strings.Contains(out, "SAVEDATE \"04-Mar-2021") {
		t.Fatalf("SAVEDATE after move should be the time it entered Archive:\n%s", out)
	}
	if got := c.mustOK(t, "Q2", "SEARCH SAVEDSINCE 01-Jan-"+year); !strings.Contains(got, "* SEARCH 1\n") {
		t.Fatalf("SAVEDSINCE after move: %s", got)
	}
}

func TestNotifySyntaxErrors(t *testing.T) {
	c := newSharedServer(t, false).client()
	for command, want := range map[string]string{
		"NOTIFY":                                   "BAD",
		"NOTIFY SET":                               "BAD",
		"NOTIFY SET (selected (MessageNew))":       "BAD",
		"NOTIFY SET (selected (FlagChange))":       "BAD",
		"NOTIFY SET (bogus (MessageNew))":          "BAD",
		"NOTIFY SET (subtree (MessageNew))":        "BAD",
		"NOTIFY SET (selected (AnnotationChange))": "NO [BADEVENT (AnnotationChange)]",
		"NOTIFY SET (inboxes NONE)":                "OK",
		"NOTIFY NONE":                              "OK",
	} {
		if out := c.run(t, "N1", command); !strings.Contains(out, "N1 "+want) {
			t.Errorf("%s -> %s, want %s", command, out, want)
		}
	}
}

func TestNotifySelectedMailboxFromAnotherSession(t *testing.T) {
	srv := newSharedServer(t, false)
	watcher, actor := srv.client(), srv.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	watcher.mustOK(t, "N1", `NOTIFY SET (selected (MessageNew (UID FLAGS) MessageExpunge FlagChange))`)
	actor.mustOK(t, "S1", "SELECT INBOX")

	// Delivered between commands, without the watcher asking for anything.
	actor.mustAppend(t, "INBOX", threadRoot)
	watcher.expectLine(t, "* 1 EXISTS")
	if line := watcher.expectLine(t, "FETCH"); !strings.Contains(line, "* 1 FETCH (UID 1 FLAGS (") {
		t.Fatalf("MessageNew attributes = %q", line)
	}

	actor.mustOK(t, "A2", `STORE 1 +FLAGS (\Seen \Deleted)`)
	watcher.expectLine(t, `* 1 FETCH (UID 1 FLAGS (`)
	actor.mustOK(t, "A3", "EXPUNGE")
	watcher.expectLine(t, "* 1 EXPUNGE")

	// The watcher still works as a normal session afterwards.
	watcher.mustOK(t, "W1", "NOOP")
}

func TestNotifyNonSelectedMailboxesAndFilters(t *testing.T) {
	srv := newSharedServer(t, false)
	watcher, actor := srv.client(), srv.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	watcher.mustOK(t, "N1", `NOTIFY SET STATUS (selected (MessageNew MessageExpunge)) (subtree Archive (MessageNew MessageExpunge FlagChange)) (inboxes (MessageNew MessageExpunge)) (personal (MailboxName SubscriptionChange))`)

	actor.mustAppend(t, "Archive", threadRoot)
	line := watcher.expectLine(t, `* STATUS "Archive"`)
	if !strings.Contains(line, "MESSAGES 1") || !strings.Contains(line, "UIDNEXT 2") || !strings.Contains(line, "UIDVALIDITY") {
		t.Fatalf("MessageNew STATUS = %q", line)
	}

	// Mailboxes outside every filter stay quiet; a later watched one proves it.
	actor.mustAppend(t, "Junk", threadRoot)
	actor.mustOK(t, "A1", "SELECT Archive")
	actor.mustOK(t, "A2", `STORE 1 +FLAGS (\Seen)`)
	if line := watcher.expectLine(t, `* STATUS`); !strings.Contains(line, `"Archive"`) || !strings.Contains(line, "UNSEEN 0") {
		t.Fatalf("expected the Archive FlagChange STATUS before anything about Junk, got %q", line)
	}
	actor.mustOK(t, "A3", `STORE 1 +FLAGS (\Deleted)`)
	watcher.expectLine(t, `* STATUS "Archive"`)
	actor.mustOK(t, "A4", "EXPUNGE")
	if line := watcher.expectLine(t, `* STATUS`); !strings.Contains(line, `"Archive"`) || !strings.Contains(line, "MESSAGES 0") {
		t.Fatalf("MessageExpunge STATUS = %q", line)
	}

	// Mailbox names and subscriptions.
	actor.mustOK(t, "C1", "CREATE Projects")
	if line := watcher.expectLine(t, `LIST`); !strings.Contains(line, `"Projects"`) {
		t.Fatalf("MailboxName create = %q", line)
	}
	actor.mustOK(t, "C2", "RENAME Projects Work")
	if line := watcher.expectLine(t, `LIST`); !strings.Contains(line, `"Work"`) || !strings.Contains(line, `("OLDNAME" ("Projects"))`) {
		t.Fatalf("MailboxName rename = %q", line)
	}
	actor.mustOK(t, "C3", "UNSUBSCRIBE Archive")
	if line := watcher.expectLine(t, `LIST`); !strings.Contains(line, `"Archive"`) || strings.Contains(line, `\Subscribed`) {
		t.Fatalf("SubscriptionChange = %q", line)
	}
	actor.mustOK(t, "C4", "DELETE Work")
	if line := watcher.expectLine(t, `LIST`); !strings.Contains(line, `\NonExistent`) || !strings.Contains(line, `"Work"`) {
		t.Fatalf("MailboxName delete = %q", line)
	}

	// NOTIFY NONE ends delivery.
	watcher.mustOK(t, "N2", "NOTIFY NONE")
	actor.mustAppend(t, "Archive", threadRoot)
	time.Sleep(10 * wakeSettle)
	if out := watcher.mustOK(t, "W1", "NOOP"); strings.Contains(out, "STATUS") {
		t.Fatalf("event delivered after NOTIFY NONE:\n%s", out)
	}
}

func TestNotifySetStatusReportsCurrentState(t *testing.T) {
	srv := newSharedServer(t, false)
	c := srv.client()
	c.mustAppend(t, "Archive", threadRoot)
	out := c.mustOK(t, "N1", `NOTIFY SET STATUS (mailboxes (Archive) (MessageNew MessageExpunge))`)
	if !strings.Contains(out, `* STATUS "Archive" (MESSAGES 1 UIDNEXT 2`) || strings.Contains(out, `"INBOX"`) {
		t.Fatalf("NOTIFY SET STATUS:\n%s", out)
	}
}

func TestNotifyDeliversWhileIdle(t *testing.T) {
	srv := newSharedServer(t, false)
	watcher, actor := srv.client(), srv.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	watcher.mustOK(t, "N1", `NOTIFY SET (selected (MessageNew MessageExpunge)) (personal (MessageNew MessageExpunge))`)
	watcher.sendNoTag("I1 IDLE")
	if line, err := watcher.readLine(); err != nil || !strings.HasPrefix(line, "+") {
		t.Fatalf("IDLE continuation = %q %v", line, err)
	}

	actor.mustAppend(t, "Archive", threadRoot)
	watcher.expectLine(t, `* STATUS "Archive"`)
	actor.mustAppend(t, "INBOX", threadReply)
	// The selected mailbox is reported once, not once per registration.
	watcher.expectLine(t, "* 1 EXISTS")

	watcher.sendNoTag("DONE")
	out := watcher.expectLine(t, "I1 OK")
	if strings.Contains(out, "EXISTS") {
		t.Fatalf("unexpected completion %q", out)
	}
	if extra := watcher.mustOK(t, "W1", "NOOP"); strings.Contains(extra, "EXISTS") {
		t.Fatalf("selected EXISTS delivered twice:\n%s", extra)
	}
}

func TestNotifyIgnoresOwnChangesAndIDLEWithoutNotifyStillWorks(t *testing.T) {
	srv := newSharedServer(t, false)
	watcher, actor := srv.client(), srv.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	watcher.mustOK(t, "N1", `NOTIFY SET (selected (MessageNew MessageExpunge))`)
	out := watcher.run(t, "A1", "STORE 1 +FLAGS (\\Seen)") // no messages: nothing to store
	if !strings.Contains(out, "A1 OK") {
		t.Fatalf("STORE: %s", out)
	}
	watcher.mustAppend(t, "INBOX", threadRoot)
	time.Sleep(10 * wakeSettle)
	// Its own APPEND is answered once, with the command's own EXISTS.
	if out := watcher.mustOK(t, "W1", "NOOP"); strings.Contains(out, "EXISTS") {
		t.Fatalf("own change echoed back:\n%s", out)
	}

	// Plain IDLE (no NOTIFY) keeps delivering the selected mailbox.
	watcher.mustOK(t, "N2", "NOTIFY NONE")
	watcher.sendNoTag("I1 IDLE")
	if line, err := watcher.readLine(); err != nil || !strings.HasPrefix(line, "+") {
		t.Fatalf("IDLE continuation = %q %v", line, err)
	}
	actor.mustOK(t, "S2", "SELECT INBOX")
	actor.mustAppend(t, "INBOX", threadReply)
	watcher.expectLine(t, "* 2 EXISTS")
	watcher.sendNoTag("DONE")
	watcher.expectLine(t, "I1 OK")
}

func TestNotifyBurstIsCoalescedWithoutOverflow(t *testing.T) {
	srv := newSharedServer(t, false)
	watcher := srv.client()
	watcher.mustOK(t, "N1", `NOTIFY SET (personal (MessageNew MessageExpunge))`)
	archive, err := srv.cfg.FolderSpace.GetFolderByPath(t.Context(), service.UserAccess("alice", "test"), "Archive")
	if err != nil {
		t.Fatal(err)
	}
	srv.server.NotifyExists(archive.ID) // nothing changed: nothing to report
	deliverTestMessage(t, srv.cfg.TypedStore, archive.ID)
	// Far more announcements than any queue would hold report the one change.
	for range 1000 {
		srv.server.NotifyExists(archive.ID)
	}
	watcher.expectLine(t, `* STATUS "Archive" (MESSAGES 1`)
	time.Sleep(10 * wakeSettle)
	if out := watcher.mustOK(t, "W1", "NOOP"); strings.Contains(out, "STATUS") || strings.Contains(out, "OVERFLOW") {
		t.Fatalf("burst reported more than once:\n%s", out)
	}
}
