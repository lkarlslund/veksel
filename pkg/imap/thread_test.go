package imap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// --- Unit tests for threading logic ---

// TestBuildReferenceThreads tests the THREAD REFERENCES algorithm.
func TestBuildReferenceThreads(t *testing.T) {
	t.Parallel()
	// Create a simple thread: msg1 → msg2 (reply) → msg3 (reply to msg2)
	items := []model.Item{
		{
			UID: 1,
			Headers: map[string]string{
				"Message-Id": "<msg1@example.com>",
				"Subject":    "Hello",
			},
		},
		{
			UID: 2,
			Headers: map[string]string{
				"Message-Id":  "<msg2@example.com>",
				"In-Reply-To": "<msg1@example.com>",
				"References":  "<msg1@example.com>",
				"Subject":     "Re: Hello",
			},
		},
		{
			UID: 3,
			Headers: map[string]string{
				"Message-Id":  "<msg3@example.com>",
				"In-Reply-To": "<msg2@example.com>",
				"References":  "<msg1@example.com> <msg2@example.com>",
				"Subject":     "Re: Hello",
			},
		},
	}

	threads := buildReferenceThreads(items)

	// Should produce one thread with all three messages
	if len(threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(threads))
	}

	// Thread should be in receipt order: msg1, msg2, msg3
	thread := threads[0]
	if len(thread) != 3 {
		t.Fatalf("expected 3 messages in thread, got %d", len(thread))
	}
	if thread[0] != 1 || thread[1] != 2 || thread[2] != 3 {
		t.Fatalf("expected thread [1 2 3], got %v", thread)
	}
}

// TestBuildReferenceThreadsMultipleThreads tests multiple independent threads.
func TestBuildReferenceThreadsMultipleThreads(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		// Thread A: msg1 → msg2
		{
			UID: 1,
			Headers: map[string]string{
				"Message-Id": "<a1@example.com>",
				"Subject":    "Topic A",
			},
		},
		{
			UID: 2,
			Headers: map[string]string{
				"Message-Id":  "<a2@example.com>",
				"In-Reply-To": "<a1@example.com>",
				"Subject":     "Re: Topic A",
			},
		},
		// Thread B: msg3 → msg4
		{
			UID: 3,
			Headers: map[string]string{
				"Message-Id": "<b1@example.com>",
				"Subject":    "Topic B",
			},
		},
		{
			UID: 4,
			Headers: map[string]string{
				"Message-Id":  "<b2@example.com>",
				"In-Reply-To": "<b1@example.com>",
				"Subject":     "Re: Topic B",
			},
		},
	}

	threads := buildReferenceThreads(items)

	// Should produce two threads
	if len(threads) != 2 {
		t.Fatalf("expected 2 threads, got %d", len(threads))
	}

	// Each thread should have 2 messages
	for i, thread := range threads {
		if len(thread) != 2 {
			t.Fatalf("thread %d: expected 2 messages, got %d", i, len(thread))
		}
	}
}

// TestBuildReferenceThreadsEmpty tests empty input.
func TestBuildReferenceThreadsEmpty(t *testing.T) {
	t.Parallel()
	threads := buildReferenceThreads(nil)
	if threads != nil {
		t.Fatalf("expected nil for empty input, got %v", threads)
	}

	threads = buildReferenceThreads([]model.Item{})
	if threads != nil {
		t.Fatalf("expected nil for empty slice, got %v", threads)
	}
}

// TestBuildReferenceThreadsNoMessageID tests messages without Message-ID.
func TestBuildReferenceThreadsNoMessageID(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"Subject": "No ID"}},
		{UID: 2, Headers: map[string]string{"Subject": "Also No ID"}},
	}

	threads := buildReferenceThreads(items)

	// Each message without Message-ID should be its own thread
	if len(threads) != 2 {
		t.Fatalf("expected 2 threads, got %d", len(threads))
	}
}

// TestBuildReferenceThreadsCaseInsensitive tests that Message-ID comparison
// is case-insensitive (RFC 5256 §2).
func TestBuildReferenceThreadsCaseInsensitive(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{
			UID: 1,
			Headers: map[string]string{
				"Message-Id": "<MSG1@Example.COM>",
				"Subject":    "Case Test",
			},
		},
		{
			UID: 2,
			Headers: map[string]string{
				"Message-Id":  "<msg2@example.com>",
				"In-Reply-To": "<msg1@example.com>", // lowercase
				"Subject":     "Re: Case Test",
			},
		},
	}

	threads := buildReferenceThreads(items)

	// Should produce one thread
	if len(threads) != 1 {
		t.Fatalf("expected 1 thread (case-insensitive), got %d", len(threads))
	}
	if len(threads[0]) != 2 {
		t.Fatalf("expected 2 messages in thread, got %d", len(threads[0]))
	}
}

// TestBuildReferenceThreadsBranching tests a branching thread (multiple replies to the same message).
func TestBuildReferenceThreadsBranching(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		// Root message
		{
			UID: 1,
			Headers: map[string]string{
				"Message-Id": "<root@example.com>",
				"Subject":    "Branch Test",
			},
		},
		// Reply 1
		{
			UID: 2,
			Headers: map[string]string{
				"Message-Id":  "<reply1@example.com>",
				"In-Reply-To": "<root@example.com>",
				"Subject":     "Re: Branch Test",
			},
		},
		// Reply 2 (also to root)
		{
			UID: 3,
			Headers: map[string]string{
				"Message-Id":  "<reply2@example.com>",
				"In-Reply-To": "<root@example.com>",
				"Subject":     "Re: Branch Test",
			},
		},
	}

	threads := buildReferenceThreads(items)

	// Should produce one thread with all three messages
	if len(threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(threads))
	}
	if len(threads[0]) != 3 {
		t.Fatalf("expected 3 messages in thread, got %d", len(threads[0]))
	}
	// Root should be first
	if threads[0][0] != 1 {
		t.Fatalf("expected root message (UID 1) first, got UID %d", threads[0][0])
	}
}

// TestBuildOrderedSubjectThreads tests the THREAD ORDEREDSUBJECT algorithm.
func TestBuildOrderedSubjectThreads(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{
			UID:     1,
			Headers: map[string]string{"Subject": "Vacation Plans"},
		},
		{
			UID:     2,
			Headers: map[string]string{"Subject": "Re: Vacation Plans"},
		},
		{
			UID:     3,
			Headers: map[string]string{"Subject": "Re: Re: Vacation Plans"},
		},
		{
			UID:     4,
			Headers: map[string]string{"Subject": "Weather Report"},
		},
		{
			UID:     5,
			Headers: map[string]string{"Subject": "Fw: Weather Report"},
		},
	}

	threads := buildOrderedSubjectThreads(items, "INBOX")

	// Should produce two threads: "Vacation Plans" and "Weather Report"
	if len(threads) != 2 {
		t.Fatalf("expected 2 threads, got %d", len(threads))
	}

	// Find the vacation thread
	var vacationThread, weatherThread []uint32
	for _, thread := range threads {
		if len(thread) == 3 {
			vacationThread = thread
		} else if len(thread) == 2 {
			weatherThread = thread
		}
	}

	if len(vacationThread) != 3 {
		t.Fatalf("expected vacation thread with 3 messages, got %d", len(vacationThread))
	}
	if len(weatherThread) != 2 {
		t.Fatalf("expected weather thread with 2 messages, got %d", len(weatherThread))
	}
}

// TestBuildOrderedSubjectThreadsEmpty tests empty input.
func TestBuildOrderedSubjectThreadsEmpty(t *testing.T) {
	t.Parallel()
	threads := buildOrderedSubjectThreads(nil, "INBOX")
	if threads != nil {
		t.Fatalf("expected nil for empty input, got %v", threads)
	}
}

// TestBuildFlatThread tests the THREAD FLAT algorithm.
func TestBuildFlatThread(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 3, Headers: map[string]string{"Subject": "C"}},
		{UID: 1, Headers: map[string]string{"Subject": "A"}},
		{UID: 2, Headers: map[string]string{"Subject": "B"}},
	}

	threads := buildFlatThread(items)

	// Should produce one flat thread
	if len(threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(threads))
	}
	if len(threads[0]) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(threads[0]))
	}
}

// TestBuildFlatThreadEmpty tests empty input.
func TestBuildFlatThreadEmpty(t *testing.T) {
	t.Parallel()
	threads := buildFlatThread(nil)
	if threads != nil {
		t.Fatalf("expected nil for empty input, got %v", threads)
	}
}

// --- Helper function tests ---

// TestGetMessageID tests Message-ID extraction from headers.
func TestGetMessageID(t *testing.T) {
	t.Parallel()
	item := model.Item{
		Headers: map[string]string{
			"Message-Id": "<test@example.com>",
		},
	}
	result := getMessageID(item)
	if result != "<test@example.com>" {
		t.Errorf("getMessageID() = %q, want %q", result, "<test@example.com>")
	}
}

// TestGetInReplyTo tests In-Reply-To extraction.
func TestGetInReplyTo(t *testing.T) {
	t.Parallel()
	item := model.Item{
		Headers: map[string]string{
			"In-Reply-To": "<parent@example.com>",
		},
	}
	result := getInReplyTo(item)
	if result != "<parent@example.com>" {
		t.Errorf("getInReplyTo() = %q, want %q", result, "<parent@example.com>")
	}
}

// TestParseReferences tests References header parsing.
func TestParseReferences(t *testing.T) {
	t.Parallel()
	item := model.Item{
		Headers: map[string]string{
			"References": "<msg1@example.com> <msg2@example.com>",
		},
	}
	result := parseReferences(item)
	if len(result) != 2 {
		t.Fatalf("parseReferences() = %v, want 2 IDs", result)
	}
}

// --- Integration test for THREAD command ---

// setupThreadTest creates a TypedStore with threaded messages for integration tests.
func setupThreadTest(t *testing.T) (*model.TypedStore, *tc) {
	t.Helper()
	tmpDir := t.TempDir()
	s, err := jsonstore.New(tmpDir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()

	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL, model.NSMetadata} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %s: %v", ns, err)
		}
	}

	if err := ts.UserStore().Create(ctx, "alice", "Alice Test", "secret"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatalf("create folders: %v", err)
	}

	// Create an IMAP server
	cfg := &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	}

	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, srv, nil, nil)
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
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("expected * OK greeting, got: %s", greeting)
	}

	// Login
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	return ts, c
}

// TestThreadReferencesIntegration tests the THREAD REFERENCES command end-to-end.
func TestThreadReferencesIntegration(t *testing.T) {
	t.Parallel()
	ts, c := setupThreadTest(t)
	ctx := context.Background()

	// Get the INBOX folder
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	// Append messages that form a thread
	msg1 := "From: alice@example.com\r\nTo: bob@example.com\r\nMessage-Id: <msg1@example.com>\r\nSubject: Hello\r\n\r\nHi!\r\n"
	if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg1), nil); err != nil {
		t.Fatalf("append msg1: %v", err)
	}

	msg2 := "From: bob@example.com\r\nTo: alice@example.com\r\nMessage-Id: <msg2@example.com>\r\nIn-Reply-To: <msg1@example.com>\r\nReferences: <msg1@example.com>\r\nSubject: Re: Hello\r\n\r\nHey!\r\n"
	if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg2), nil); err != nil {
		t.Fatalf("append msg2: %v", err)
	}

	msg3 := "From: alice@example.com\r\nTo: bob@example.com\r\nMessage-Id: <msg3@example.com>\r\nIn-Reply-To: <msg2@example.com>\r\nReferences: <msg1@example.com> <msg2@example.com>\r\nSubject: Re: Hello\r\n\r\nHow are you?\r\n"
	if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg3), nil); err != nil {
		t.Fatalf("append msg3: %v", err)
	}

	// Re-select to pick up the messages
	c.send("A003", "SELECT INBOX")

	// THREAD REFERENCES ALL
	_, code, _ := c.send("A004", "THREAD REFERENCES ALL")
	if code != "OK" {
		t.Fatalf("THREAD REFERENCES: code=%s, want OK", code)
	}
}

// TestThreadOrderedSubjectIntegration tests the THREAD ORDEREDSUBJECT command.
func TestThreadOrderedSubjectIntegration(t *testing.T) {
	t.Parallel()
	ts, c := setupThreadTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	// Append messages with different subjects
	msg1 := "From: a@b.com\r\nTo: c@d.com\r\nMessage-Id: <os1@example.com>\r\nSubject: Project Alpha\r\n\r\nAlpha\r\n"
	if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg1), nil); err != nil {
		t.Fatalf("append msg1: %v", err)
	}

	msg2 := "From: c@d.com\r\nTo: a@b.com\r\nMessage-Id: <os2@example.com>\r\nSubject: Re: Project Alpha\r\n\r\nRe Alpha\r\n"
	if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg2), nil); err != nil {
		t.Fatalf("append msg2: %v", err)
	}

	msg3 := "From: x@y.com\r\nTo: z@w.com\r\nMessage-Id: <os3@example.com>\r\nSubject: Project Beta\r\n\r\nBeta\r\n"
	if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg3), nil); err != nil {
		t.Fatalf("append msg3: %v", err)
	}

	// Re-select
	c.send("A003", "SELECT INBOX")

	// THREAD ORDEREDSUBJECT INBOX ALL
	_, code, _ := c.send("A004", "THREAD ORDEREDSUBJECT INBOX ALL")
	if code != "OK" {
		t.Fatalf("THREAD ORDEREDSUBJECT: code=%s, want OK", code)
	}
}

// TestThreadFlatIntegration tests the THREAD FLAT command.
func TestThreadFlatIntegration(t *testing.T) {
	t.Parallel()
	ts, c := setupThreadTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	// Append a couple of messages
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nMessage-Id: <flat%d@example.com>\r\nSubject: Msg %d\r\n\r\nBody %d\r\n", i, i, i)
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append msg%d: %v", i, err)
		}
	}

	// Re-select
	c.send("A003", "SELECT INBOX")

	// THREAD FLAT ALL
	_, code, _ := c.send("A004", "THREAD FLAT ALL")
	if code != "OK" {
		t.Fatalf("THREAD FLAT: code=%s, want OK", code)
	}
}

// TestThreadBadAlgorithm tests that an unknown algorithm returns BAD.
func TestThreadBadAlgorithm(t *testing.T) {
	t.Parallel()
	_, c := setupThreadTest(t)

	_, code, _ := c.send("A003", "THREAD UNKNOWN ALL")
	if code != "BAD" {
		t.Fatalf("THREAD UNKNOWN: code=%s, want BAD", code)
	}
}

// TestThreadNoMailbox tests that THREAD without a selected mailbox returns BAD.
func TestThreadNoMailbox(t *testing.T) {
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

	// THREAD without SELECT should fail
	_, code, _ := c.send("A002", "THREAD REFERENCES ALL")
	if code != "BAD" {
		t.Fatalf("THREAD without SELECT: code=%s, want BAD", code)
	}
}

// TestThreadCapability tests that THREAD appears in CAPABILITY response.
func TestThreadCapability(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Send CAPABILITY and read all responses
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 CAPABILITY\r\n")

	// Read all lines until tagged response
	var capLine string
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
		}
		if !strings.HasPrefix(line, "*") {
			break
		}
	}

	if !strings.Contains(capLine, "THREAD") {
		t.Fatalf("CAPABILITY response does not contain THREAD: %s", capLine)
	}
}

// TestBuildReferenceThreadsReferencesOnly tests threading via References header
// without In-Reply-To.
func TestBuildReferenceThreadsReferencesOnly(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{
			UID: 1,
			Headers: map[string]string{
				"Message-Id": "<msg1@example.com>",
				"Subject":    "Original",
			},
		},
		{
			UID: 2,
			Headers: map[string]string{
				"Message-Id": "<msg2@example.com>",
				"References": "<msg1@example.com>",
				"Subject":    "Re: Original",
			},
		},
	}

	threads := buildReferenceThreads(items)

	// Should produce one thread
	if len(threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(threads))
	}
	if len(threads[0]) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(threads[0]))
	}
}

// TestBuildReferenceThreadsDeepNesting tests a deeply nested thread.
func TestBuildReferenceThreadsDeepNesting(t *testing.T) {
	t.Parallel()
	var items []model.Item
	var refs []string
	for i := 1; i <= 10; i++ {
		msgID := fmt.Sprintf("<msg%d@example.com>", i)
		headers := map[string]string{
			"Message-Id": msgID,
			"Subject":    fmt.Sprintf("Re: Topic (msg%d)", i),
		}
		if i > 1 {
			headers["In-Reply-To"] = fmt.Sprintf("<msg%d@example.com>", i-1)
			refs = append(refs, fmt.Sprintf("<msg%d@example.com>", i-1))
			headers["References"] = strings.Join(refs, " ")
		}
		items = append(items, model.Item{UID: uint32(i), Headers: headers})
	}

	threads := buildReferenceThreads(items)

	// Should produce one thread with all 10 messages
	if len(threads) != 1 {
		t.Fatalf("expected 1 thread, got %d", len(threads))
	}
	if len(threads[0]) != 10 {
		t.Fatalf("expected 10 messages, got %d", len(threads[0]))
	}
	// First message should be the root
	if threads[0][0] != 1 {
		t.Fatalf("expected root (UID 1) first, got UID %d", threads[0][0])
	}
}
