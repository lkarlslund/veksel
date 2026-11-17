package imap

import (
	"bufio"
	"compress/flate"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// interopServer starts a multi-session server for alice and returns a dialer
// for logged-in clients. The tests in this file replay exchanges recorded
// while auditing Veksel against real mail clients.
func interopServer(t *testing.T) (*model.TypedStore, func() *tc) {
	t.Helper()
	ts := setupTestStore(t)
	_, _, dial := makeMultiSessionServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		TypedStore: ts,
	})
	return ts, func() *tc {
		c := dial()
		if _, code, text := c.send("L1", "LOGIN alice secret"); code != "OK" {
			t.Fatalf("LOGIN: %s %s", code, text)
		}
		return c
	}
}

// exchange sends one command line and returns every response line up to and
// including the tagged completion.
func (c *tc) exchange(t *testing.T, tag, command string) []string {
	t.Helper()
	if _, err := fmt.Fprintf(c.Conn, "%s %s\r\n", tag, command); err != nil {
		t.Fatal(err)
	}
	lines := c.readUntagged()
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], tag+" ") {
		t.Fatalf("%s %s: no tagged completion in %q", tag, command, lines)
	}
	return lines
}

func completion(lines []string) string { return lines[len(lines)-1] }

func requireLine(t *testing.T, lines []string, want string) {
	t.Helper()
	for _, line := range lines {
		if line == want {
			return
		}
	}
	t.Fatalf("missing %q in:\n%s", want, strings.Join(lines, "\n"))
}

func forbidPrefix(t *testing.T, lines []string, prefix string) {
	t.Helper()
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			t.Fatalf("unexpected %q in:\n%s", line, strings.Join(lines, "\n"))
		}
	}
}

// TestListEmptyPatternReturnsDelimiter replays the first command Thunderbird,
// Apple Mail, and Outlook send after login: LIST "" "" asks for the hierarchy
// delimiter and received no LIST response at all.
func TestListEmptyPatternReturnsDelimiter(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	lines := c.exchange(t, "A1", `LIST "" ""`)
	if len(lines) != 2 || lines[0] != `* LIST (\Noselect) "/" ""` || !strings.HasPrefix(lines[1], "A1 OK") {
		t.Fatalf(`LIST "" "" = %q`, lines)
	}
}

// TestSelectAdvertisesSeenFlag replays SELECT INBOX: FLAGS and PERMANENTFLAGS
// omitted \Seen, so clients that honour PERMANENTFLAGS refused to keep read
// state on the server.
func TestSelectAdvertisesSeenFlag(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	lines := c.exchange(t, "A1", "SELECT INBOX")
	requireLine(t, lines, `* FLAGS (\Answered \Flagged \Deleted \Seen \Draft $Label1 $Label2 $Label3 $Label4)`)
	requireLine(t, lines, `* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft $Label1 $Label2 $Label3 $Label4 \*)] Permanent flags`)
}

// TestCreateBuildsIntermediateHierarchy replays CREATE "a/b/c/d" and a
// modified UTF-7 path whose parents did not exist: only the last segment was
// created, at the top level. A trailing delimiter failed outright, and the
// failed command then blocked server start.
func TestCreateBuildsIntermediateHierarchy(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	for _, command := range []string{`CREATE "a/b/c/d"`, `CREATE "&AMYA+ADl-ble/Gr&APg-d"`, `CREATE "Trailing/"`, `RENAME "a/b/c/d" "x/y/z"`} {
		if line := completion(c.exchange(t, "A1", command)); !strings.HasPrefix(line, "A1 OK") {
			t.Fatalf("%s = %q", command, line)
		}
	}
	lines := c.exchange(t, "A2", `LIST "" "*"`)
	listed := make(map[string]bool)
	for _, line := range lines {
		if index := strings.LastIndex(line, ` "`); strings.HasPrefix(line, "* LIST ") && index >= 0 {
			listed[line[index+1:]] = true
		}
	}
	for _, want := range []string{`"a"`, `"a/b"`, `"a/b/c"`, `"&AMYA+ADl-ble"`, `"&AMYA+ADl-ble/Gr&APg-d"`, `"Trailing"`, `"x"`, `"x/y"`, `"x/y/z"`} {
		if !listed[want] {
			t.Fatalf("LIST is missing %s:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	for _, line := range lines {
		if strings.HasSuffix(line, ` "d"`) || strings.HasSuffix(line, ` "Gr&APg-d"`) || strings.HasSuffix(line, ` "a/b/c/d"`) {
			t.Fatalf("mailbox created at the wrong level: %q", line)
		}
	}
	if line := completion(c.exchange(t, "A3", `CREATE "a/b"`)); !strings.HasPrefix(line, "A3 NO [ALREADYEXISTS]") {
		t.Fatalf("CREATE of an existing mailbox = %q", line)
	}
	if line := completion(c.exchange(t, "A4", `CREATE "a//b"`)); !strings.HasPrefix(line, "A4 BAD") {
		t.Fatalf("CREATE with an empty segment = %q", line)
	}
}

func appendTestMessages(t *testing.T, c *tc, count int) {
	t.Helper()
	for index := range count {
		msg := fmt.Sprintf("From: bob@example.test\r\nSubject: message %d\r\nDate: Thu, 22 Oct 2026 10:0%d:00 +0000\r\n\r\nbody %d\r\n", index, index, index)
		if _, code, text := c.appendMsg(fmt.Sprintf("P%d", index), "INBOX", nil, "", []byte(msg)); code != "OK" {
			t.Fatalf("APPEND %d: %s %s", index, code, text)
		}
	}
}

// TestStatusAnswersRecentAndHighestModSeq replays Thunderbird's folder check
// "STATUS folder (UIDNEXT MESSAGES UNSEEN RECENT HIGHESTMODSEQ)", which was
// refused with BAD for both RECENT (IMAP4rev1) and HIGHESTMODSEQ (CONDSTORE).
func TestStatusAnswersRecentAndHighestModSeq(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	appendTestMessages(t, c, 2)
	lines := c.exchange(t, "A1", "STATUS INBOX (UIDNEXT MESSAGES UNSEEN RECENT HIGHESTMODSEQ)")
	if !strings.HasPrefix(completion(lines), "A1 OK") || !strings.HasPrefix(lines[0], `* STATUS "INBOX" (UIDNEXT 3 MESSAGES 2 UNSEEN 2 RECENT `) || !strings.Contains(lines[0], " HIGHESTMODSEQ ") {
		t.Fatalf("STATUS = %q", lines)
	}
	lines = c.exchange(t, "A2", `LIST "" "INBOX" RETURN (STATUS (MESSAGES HIGHESTMODSEQ))`)
	if !strings.HasPrefix(completion(lines), "A2 OK") || !strings.Contains(strings.Join(lines, "\n"), "(STATUS (MESSAGES 2 HIGHESTMODSEQ ") {
		t.Fatalf("LIST-STATUS = %q", lines)
	}
}

// TestFetchChangedSinceAndVanished replays the CONDSTORE/QRESYNC resync
// commands Thunderbird and K-9 send: the parenthesized fetch modifier was
// left half-parsed ("unknown data item (FLAGS)") and VANISHED was refused.
func TestFetchChangedSinceAndVanished(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	appendTestMessages(t, c, 3)
	c.exchange(t, "A0", "ENABLE QRESYNC")
	lines := c.exchange(t, "A1", "SELECT INBOX")
	requireLine(t, lines, "* 3 EXISTS")
	lines = c.exchange(t, "A2", "FETCH 1:* (FLAGS) (CHANGEDSINCE 0)")
	if !strings.HasPrefix(completion(lines), "A2 OK") || len(lines) != 4 || !strings.Contains(lines[0], "MODSEQ (") {
		t.Fatalf("FETCH CHANGEDSINCE = %q", lines)
	}
	c.exchange(t, "A3", `UID STORE 2 +FLAGS.SILENT (\Deleted)`)
	c.exchange(t, "A4", "UID EXPUNGE 2")
	lines = c.exchange(t, "A5", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)")
	requireLine(t, lines, "* VANISHED (EARLIER) 2")
	if !strings.HasPrefix(completion(lines), "A5 OK") || !strings.Contains(lines[1], "UID 3") || !strings.Contains(lines[1], "MODSEQ (") {
		t.Fatalf("UID FETCH VANISHED = %q", lines)
	}
	if line := completion(c.exchange(t, "A6", "FETCH 1 (FLAGS) (CHANGEDSINCE 1 VANISHED)")); !strings.HasPrefix(line, "A6 BAD") {
		t.Fatalf("VANISHED without UID = %q", line)
	}
}

// TestUIDFetchAlwaysReturnsUID replays Apple Mail style header fetches
// ("UID FETCH n (BODY.PEEK[HEADER.FIELDS (...)])") whose responses lacked
// the UID that RFC 3501 6.4.8 requires, plus the ALL macro, which was not
// expanded, and a full-range UID set that was expanded value by value.
func TestUIDFetchAlwaysReturnsUID(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	appendTestMessages(t, c, 2)
	c.exchange(t, "A1", "SELECT INBOX")
	lines := c.exchange(t, "A2", "UID FETCH 2 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
	if !strings.HasPrefix(lines[0], "* 2 FETCH (UID 2 BODY[HEADER.FIELDS (SUBJECT)] {") {
		t.Fatalf("UID FETCH = %q", lines)
	}
	lines = c.exchange(t, "A3", "FETCH 1 ALL")
	if !strings.HasPrefix(lines[0], "* 1 FETCH (FLAGS () INTERNALDATE ") || !strings.Contains(lines[0], " RFC822.SIZE ") || !strings.Contains(lines[0], " ENVELOPE (") {
		t.Fatalf("FETCH ALL = %q", lines)
	}
	lines = c.exchange(t, "A4", "UID FETCH 1:4294967295 (FLAGS)")
	if len(lines) != 3 || !strings.HasPrefix(completion(lines), "A4 OK") {
		t.Fatalf("UID FETCH 1:4294967295 = %q", lines)
	}
}

// TestConditionalStoreKeepsFlags replays "STORE 1 (UNCHANGEDSINCE 1) +FLAGS
// (\Answered)", which was not parsed and replaced the message's flags with
// an empty list. A conditional store on a changed message must leave it
// alone and report it in [MODIFIED]; malformed STOREs are BAD.
func TestConditionalStoreKeepsFlags(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	appendTestMessages(t, c, 1)
	c.exchange(t, "A1", "SELECT INBOX")
	c.exchange(t, "A2", `STORE 1 FLAGS (\Seen $Forwarded)`)
	lines := c.exchange(t, "A3", `STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\Answered)`)
	if !strings.HasPrefix(completion(lines), "A3 OK [MODIFIED 1]") {
		t.Fatalf("conditional STORE = %q", lines)
	}
	lines = c.exchange(t, "A4", "FETCH 1 (FLAGS)")
	if !strings.HasPrefix(lines[0], `* 1 FETCH (FLAGS (\Seen $Forwarded)`) {
		t.Fatalf("flags after conditional STORE = %q", lines)
	}
	lines = c.exchange(t, "A5", `STORE 1 (UNCHANGEDSINCE 999999) +FLAGS (\Answered)`)
	if !strings.HasPrefix(completion(lines), "A5 OK STORE") || !strings.Contains(lines[0], `\Answered`) || !strings.Contains(lines[0], "MODSEQ (") {
		t.Fatalf("satisfied conditional STORE = %q", lines)
	}
	for index, command := range []string{`STORE 1 X-FLAGS (\Seen)`, `STORE 1 +FLAGS (\Recent)`, `STORE 1 (UNCHANGEDSINCE) +FLAGS (\Seen)`} {
		tag := fmt.Sprintf("B%d", index)
		if line := completion(c.exchange(t, tag, command)); !strings.HasPrefix(line, tag+" BAD") {
			t.Fatalf("%s = %q", command, line)
		}
	}
	if lines = c.exchange(t, "A6", "FETCH 1 (FLAGS)"); !strings.Contains(lines[0], `\Seen`) {
		t.Fatalf("flags after malformed STOREs = %q", lines)
	}
}

// TestCopyPreservesFlags replays COPY of a read, flagged message: the copy
// arrived unread and unflagged although RFC 3501 6.4.7 preserves flags.
func TestCopyPreservesFlags(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	appendTestMessages(t, c, 1)
	c.exchange(t, "A1", "SELECT INBOX")
	c.exchange(t, "A2", `STORE 1 +FLAGS (\Seen \Flagged $Label1)`)
	c.exchange(t, "A3", "COPY 1 Archive")
	c.exchange(t, "A4", "UID COPY 1 Trash")
	for _, mailbox := range []string{"Archive", "Trash"} {
		c.exchange(t, "A5", "SELECT "+mailbox)
		lines := c.exchange(t, "A6", "FETCH 1 (FLAGS)")
		for _, flag := range []string{`\Seen`, `\Flagged`, "$Label1"} {
			if !strings.Contains(lines[0], flag) {
				t.Fatalf("%s copy flags = %q, missing %s", mailbox, lines[0], flag)
			}
		}
	}
}

// TestCommandsAcceptLiterals replays LOGIN as K-9 and Thunderbird send it
// for a password with 8-bit or quote characters: "LOGIN {5}" followed by the
// literal. Only APPEND and SEARCH read literals, so every other command
// failed with "Expected: LOGIN username password".
func TestCommandsAcceptLiterals(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	password := "pæss \"w\\rd\""
	_, _, dial := makeMultiSessionServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, username, candidate string) (string, error) {
			if username == "alice" && candidate == password {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials for %q", candidate)
		},
		TypedStore: ts,
	})
	c := dial()
	fmt.Fprintf(c.Conn, "A1 LOGIN {5}\r\n")
	if line, err := c.readContinuation(); err != nil {
		t.Fatalf("continuation for username literal: %q %v", line, err)
	}
	fmt.Fprintf(c.Conn, "alice {%d}\r\n", len(password))
	if line, err := c.readContinuation(); err != nil {
		t.Fatalf("continuation for password literal: %q %v", line, err)
	}
	fmt.Fprintf(c.Conn, "%s\r\n", password)
	if _, code, text := c.readResponse(); code != "OK" {
		t.Fatalf("LOGIN with literals: %s %s", code, text)
	}
	// LITERAL- non-synchronizing literals need no continuation.
	fmt.Fprintf(c.Conn, "A2 CREATE {7+}\r\nq\"uoted\r\n")
	if _, code, text := c.readResponse(); code != "OK" {
		t.Fatalf("CREATE with a LITERAL- name: %s %s", code, text)
	}
	lines := c.exchange(t, "A3", `LIST "" "q*"`)
	requireLine(t, lines, `* LIST (\HasNoChildren \Subscribed) "/" "q\"uoted"`)
	fmt.Fprintf(c.Conn, "A4 SELECT {5}\r\n")
	if _, err := c.readContinuation(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c.Conn, "INBOX\r\n")
	if _, code, text := c.readResponse(); code != "OK" {
		t.Fatalf("SELECT with a literal: %s %s", code, text)
	}
	fmt.Fprintf(c.Conn, "A5 CREATE {3+}\r\na\nb\r\n")
	if _, code, _ := c.readResponse(); code != "BAD" {
		t.Fatalf("literal with LF = %s, want BAD", code)
	}
	if line := completion(c.exchange(t, "A6", "NOOP")); !strings.HasPrefix(line, "A6 OK") {
		t.Fatalf("session after refused literal: %q", line)
	}
}

// TestNoopReportsChangesFromOtherSessions replays a client that polls with
// NOOP (Outlook, Apple Mail with IDLE off): mail delivered by another
// session was never announced, and a message expunged elsewhere silently
// renumbered the mailbox so "FETCH 2" returned a different message.
func TestNoopReportsChangesFromOtherSessions(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	poller, other := dial(), dial()
	appendTestMessages(t, other, 3)
	requireLine(t, poller.exchange(t, "A1", "SELECT INBOX"), "* 3 EXISTS")
	other.exchange(t, "B1", "SELECT INBOX")

	appendTestMessages(t, other, 1)
	lines := poller.exchange(t, "A2", "NOOP")
	requireLine(t, lines, "* 4 EXISTS")

	other.exchange(t, "B2", `STORE 2 +FLAGS.SILENT (\Deleted)`)
	other.exchange(t, "B3", "EXPUNGE")
	other.exchange(t, "B4", `STORE 3 +FLAGS (\Flagged)`)
	// FETCH must not carry EXPUNGE, and its sequence numbers are still the
	// ones the poller knows: message 3 is UID 3, the expunged one is skipped.
	lines = poller.exchange(t, "A3", "FETCH 2:3 (UID)")
	forbidPrefix(t, lines, "* 2 EXPUNGE")
	requireLine(t, lines, "* 3 FETCH (UID 3)")
	forbidPrefix(t, lines, "* 2 FETCH (UID 3)")
	// Flag changes may be reported during FETCH, numbered in the old view.
	requireLine(t, lines, `* 4 FETCH (UID 4 FLAGS (\Flagged))`)
	lines = poller.exchange(t, "A4", "NOOP")
	if len(lines) != 2 || lines[0] != "* 2 EXPUNGE" {
		t.Fatalf("NOOP after the expunge = %q", lines)
	}
	lines = poller.exchange(t, "A5", "FETCH 2 (UID)")
	requireLine(t, lines, "* 2 FETCH (UID 3)")
	if lines = poller.exchange(t, "A6", "NOOP"); len(lines) != 1 {
		t.Fatalf("NOOP repeated changes: %q", lines)
	}
}

// TestSortAndThreadHoldBackExpunge: non-UID SORT and THREAD return sequence
// numbers, so like SEARCH they must not carry EXPUNGE (RFC 5256, RFC 3501
// 7.4.1); their results still number the expunged message, and the
// EXPUNGE follows on NOOP. UID SORT may carry it.
func TestSortAndThreadHoldBackExpunge(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	poller, other := dial(), dial()
	appendTestMessages(t, other, 3)
	requireLine(t, poller.exchange(t, "A1", "SELECT INBOX"), "* 3 EXISTS")
	other.exchange(t, "B1", "SELECT INBOX")

	expunge := func(tag string, seq int) {
		other.exchange(t, tag+"a", fmt.Sprintf(`STORE %d +FLAGS.SILENT (\Deleted)`, seq))
		other.exchange(t, tag+"b", "EXPUNGE")
	}
	expunge("B2", 2)
	lines := poller.exchange(t, "A2", "SORT (ARRIVAL) UTF-8 ALL")
	forbidPrefix(t, lines, "* 2 EXPUNGE")
	requireLine(t, lines, "* SORT 1 3")
	lines = poller.exchange(t, "A3", "THREAD ORDEREDSUBJECT UTF-8 ALL")
	forbidPrefix(t, lines, "* 2 EXPUNGE")
	lines = poller.exchange(t, "A4", "NOOP")
	requireLine(t, lines, "* 2 EXPUNGE")

	expunge("B3", 1)
	lines = poller.exchange(t, "A5", "UID SORT (ARRIVAL) UTF-8 ALL")
	requireLine(t, lines, "* 1 EXPUNGE")
}

// TestExpungeResponsesFollowNegotiatedExtensions replays UID EXPUNGE in a
// QRESYNC session, which answered with the malformed "* 1 EXPUNGE 1" instead
// of VANISHED, and CLOSE, which must not send EXPUNGE responses. UID
// EXPUNGE also removed messages without \Deleted.
func TestExpungeResponsesFollowNegotiatedExtensions(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	appendTestMessages(t, c, 4)
	c.exchange(t, "A0", "ENABLE QRESYNC")
	c.exchange(t, "A1", "SELECT INBOX")
	c.exchange(t, "A2", `UID STORE 1,3 +FLAGS.SILENT (\Deleted)`)
	lines := c.exchange(t, "A3", "UID EXPUNGE 1:2")
	if len(lines) != 2 || lines[0] != "* VANISHED 1" || !strings.HasPrefix(lines[1], "A3 OK") {
		t.Fatalf("UID EXPUNGE with QRESYNC = %q", lines)
	}
	lines = c.exchange(t, "A4", "CLOSE")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "A4 OK") {
		t.Fatalf("CLOSE = %q", lines)
	}
	lines = c.exchange(t, "A5", "STATUS INBOX (MESSAGES)")
	requireLine(t, lines, `* STATUS "INBOX" (MESSAGES 2)`)
}

// TestIdleEndsUnderCompression replays Thunderbird's default session:
// COMPRESS=DEFLATE followed by IDLE. The poll deadline inside IDLE broke the
// decompressor, so DONE was never read and the session hung.
func TestIdleEndsUnderCompression(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c, other := dial(), dial()
	c.exchange(t, "A1", "SELECT INBOX")
	if line := completion(c.exchange(t, "A2", "COMPRESS DEFLATE")); !strings.HasPrefix(line, "A2 OK") {
		t.Fatalf("COMPRESS = %q", line)
	}
	z := newDeflateClient(c)
	z.write(t, "A3 IDLE\r\n")
	if line := z.readLine(t); !strings.HasPrefix(line, "+") {
		t.Fatalf("IDLE continuation = %q", line)
	}
	time.Sleep(400 * time.Millisecond) // longer than the old poll deadline
	appendTestMessages(t, other, 1)
	if line := z.readLine(t); line != "* 1 EXISTS" {
		t.Fatalf("IDLE notification = %q", line)
	}
	z.write(t, "DONE\r\n")
	for {
		line := z.readLine(t)
		if strings.HasPrefix(line, "A3 ") {
			if !strings.HasPrefix(line, "A3 OK") {
				t.Fatalf("IDLE completion = %q", line)
			}
			break
		}
	}
	z.write(t, "A4 NOOP\r\n")
	if line := z.readLine(t); !strings.HasPrefix(line, "A4 OK") {
		t.Fatalf("NOOP after compressed IDLE = %q", line)
	}
}

// deflateClient speaks a COMPRESS=DEFLATE session over a test connection.
type deflateClient struct {
	c      *tc
	writer *flate.Writer
	reader *bufio.Reader
}

func newDeflateClient(c *tc) *deflateClient {
	writer, _ := flate.NewWriter(c.Conn, flate.DefaultCompression)
	return &deflateClient{c: c, writer: writer, reader: bufio.NewReader(flate.NewReader(c.r))}
}

func (z *deflateClient) write(t *testing.T, text string) {
	t.Helper()
	if _, err := z.writer.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := z.writer.Flush(); err != nil {
		t.Fatal(err)
	}
}

func (z *deflateClient) readLine(t *testing.T) string {
	t.Helper()
	_ = z.c.Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := z.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("compressed read: %v (partial %q)", err, line)
	}
	return strings.TrimRight(line, "\r\n")
}

// TestSearchSentDatesUseDateHeader replays "SEARCH SENTSINCE ...": SENT*
// compared the internal (arrival) date instead of the Date header.
func TestSearchSentDatesUseDateHeader(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	msg := "From: bob@example.test\r\nSubject: old\r\nDate: Thu, 2 Jan 2025 23:30:00 -0500\r\n\r\nbody\r\n"
	if _, code, text := c.appendMsg("P1", "INBOX", nil, "", []byte(msg)); code != "OK" {
		t.Fatalf("APPEND: %s %s", code, text)
	}
	c.exchange(t, "A1", "SELECT INBOX")
	for _, step := range []struct{ command, want string }{
		{"SEARCH SENTON 2-Jan-2025", "* SEARCH 1"},
		{"SEARCH SENTBEFORE 3-Jan-2025", "* SEARCH 1"},
		{"SEARCH SENTSINCE 3-Jan-2025", "* SEARCH"},
		{"SEARCH ON 2-Jan-2025", "* SEARCH"},
	} {
		if lines := c.exchange(t, "S1", step.command); lines[0] != step.want {
			t.Fatalf("%s = %q, want %q", step.command, lines, step.want)
		}
	}
}

// TestSearchAcceptsSequenceSetKeys replays Apple Mail and Outlook searches
// such as "UID SEARCH 1:* NOT DELETED": a bare sequence set is a search key,
// but it was refused as an unknown criterion. UID sets with "*" and ranges
// past the last UID must resolve against the mailbox too.
func TestSearchAcceptsSequenceSetKeys(t *testing.T) {
	t.Parallel()
	_, dial := interopServer(t)
	c := dial()
	appendTestMessages(t, c, 4)
	c.exchange(t, "A1", "SELECT INBOX")
	c.exchange(t, "A2", `STORE 2 +FLAGS (\Deleted)`)
	for _, step := range []struct{ command, want string }{
		{"SEARCH 1:3", "* SEARCH 1 2 3"},
		{"SEARCH 2:* NOT DELETED", "* SEARCH 3 4"},
		{"UID SEARCH 1:* NOT DELETED", "* SEARCH 1 3 4"},
		{"SEARCH 4,1", "* SEARCH 1 4"},
		{"UID SEARCH UID 3:*", "* SEARCH 3 4"},
		{"UID SEARCH UID 2:4294967295 UNDELETED", "* SEARCH 3 4"},
		{"SEARCH OR 1 4", "* SEARCH 1 4"},
	} {
		lines := c.exchange(t, "S1", step.command)
		if !strings.HasPrefix(completion(lines), "S1 OK") || lines[0] != step.want {
			t.Fatalf("%s = %q, want %q", step.command, lines, step.want)
		}
	}
}
