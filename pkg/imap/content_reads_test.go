package imap

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// contentCountingSpace counts reads of individual message content.
type contentCountingSpace struct {
	service.FolderSpace
	reads atomic.Int64
}

func (s *contentCountingSpace) GetItem(ctx context.Context, access service.AccessContext, id string) (model.Item, error) {
	s.reads.Add(1)
	return s.FolderSpace.GetItem(ctx, access, id)
}

func (s *contentCountingSpace) GetItemByUID(ctx context.Context, access service.AccessContext, folderID string, uid uint32) (model.Item, error) {
	s.reads.Add(1)
	return s.FolderSpace.GetItemByUID(ctx, access, folderID, uid)
}

// TestMailboxCommandsReadContentOnlyWhenNeeded guards the large-mailbox
// path: flag, size, UID, threading and sorting commands are answered from
// the metadata listing, and only content data items read a message.
func TestMailboxCommandsReadContentOnlyWhenNeeded(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	space := &contentCountingSpace{FolderSpace: service.NewFolderSpace(ts, authz.New(ts))}
	alice := service.UserAccess("alice", "imap")
	messages := []string{
		"Message-ID: <root@example.test>\r\nFrom: Ann <ann@example.test>\r\nDate: Mon, 02 Jan 2026 10:00:00 +0000\r\nSubject: Plan\r\n\r\nfirst body\r\n",
		"Message-ID: <other@example.test>\r\nFrom: Bob <bob@example.test>\r\nDate: Tue, 03 Jan 2026 10:00:00 +0000\r\nSubject: Lunch\r\n\r\nsecond body\r\n",
		"Message-ID: <reply@example.test>\r\nIn-Reply-To: <root@example.test>\r\nReferences: <root@example.test>\r\nFrom: Cat <cat@example.test>\r\nDate: Wed, 04 Jan 2026 10:00:00 +0000\r\nSubject: Re: Plan\r\n\r\nthird body\r\n",
	}
	for index, raw := range messages {
		headers, _ := model.ParseMessageHeaders([]byte(raw))
		input := service.ItemInput{Data: []byte(raw), Headers: headers}
		if index == 1 {
			input.Flags = []string{model.FlagSeen}
		}
		if _, err := space.CreateItem(t.Context(), alice, model.InboxFolderID("alice"), input); err != nil {
			t.Fatal(err)
		}
	}
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    ts,
		FolderSpace:   space,
	})
	c.send("A001", "LOGIN alice secret")
	space.reads.Store(0)

	commands := []struct{ command, want string }{
		{"SELECT INBOX", "* 3 EXISTS"},
		{"FETCH 1:* (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ)", "* 3 FETCH (UID 3"},
		{"UID SEARCH UNSEEN", "* SEARCH 1 3"},
		{"SEARCH SEEN", "* SEARCH 2"},
		{`UID SEARCH FROM "bob" SINCE 1-Jan-2000`, "* SEARCH 2"},
		{"THREAD REFERENCES UTF-8 ALL", "(1 3)"},
		{"UID SORT (REVERSE DATE) UTF-8 ALL", "* SORT 3 2 1"},
		{`UID STORE 1 +FLAGS (\Flagged)`, `* 1 FETCH (UID 1 FLAGS (\Flagged) MODSEQ (`},
		{"FETCH 3 THREADID", "* 3 FETCH (THREADID"},
	}
	for index, step := range commands {
		lines, code := sendQResyncTestCommand(t, c, fmt.Sprintf("B%03d", index), step.command)
		if code != "OK" || !containsQResyncLine(lines, step.want) {
			t.Fatalf("%s: code=%s, want line containing %q, got %q", step.command, code, step.want, lines)
		}
	}
	if reads := space.reads.Load(); reads != 0 {
		t.Fatalf("metadata commands read message content %d times", reads)
	}

	lines, code := sendQResyncTestCommand(t, c, "C001", "FETCH 2 (FLAGS BODY.PEEK[TEXT])")
	if code != "OK" || !strings.Contains(strings.Join(lines, "\n"), "second body") {
		t.Fatalf("content FETCH: code=%s lines=%q", code, lines)
	}
	if reads := space.reads.Load(); reads != 1 {
		t.Fatalf("content FETCH of one message read %d messages, want 1", reads)
	}
	if lines, code := sendQResyncTestCommand(t, c, "C002", `UID SEARCH BODY "third"`); code != "OK" || !containsQResyncLine(lines, "* SEARCH 3") {
		t.Fatalf("content SEARCH: code=%s lines=%q", code, lines)
	}
}
