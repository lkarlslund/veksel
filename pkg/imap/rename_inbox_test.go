package imap

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// TestRenameInboxMovesMessages covers RFC 3501 6.3.5 / RFC 9051 6.3.6:
// RENAME INBOX moves every INBOX message to a new mailbox, keeps INBOX in
// place and empty, and leaves mailboxes below INBOX alone.
func TestRenameInboxMovesMessages(t *testing.T) {
	f := newWakeFixture(t)
	child, err := f.space.CreateFolder(t.Context(), f.access, "Child", model.FolderTypeMail, f.inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.create(t, child.ID)
	const count = 3
	internal := map[string]time.Time{}
	for i := range count {
		item := f.create(t, f.inbox.ID)
		flags := []string{model.FlagSeen}
		if i == 1 {
			flags = append(flags, model.FlagFlagged, "$Label1")
		}
		item, err := f.space.SetFlags(t.Context(), f.access, item.ID, flags)
		if err != nil {
			t.Fatal(err)
		}
		internal[item.ID] = item.InternalDate
	}
	before := mustFolder(t, f, "INBOX")

	c := f.client()
	c.mustOK(t, "R1", "RENAME INBOX Archive/2026")

	after := mustFolder(t, f, "INBOX")
	if after.ID != before.ID || after.UIDValidity != before.UIDValidity {
		t.Fatalf("INBOX changed identity: %+v -> %+v", before, after)
	}
	if left := items(t, f, f.inbox.ID); len(left) != 0 {
		t.Fatalf("INBOX still holds %d messages", len(left))
	}
	if kids := items(t, f, child.ID); len(kids) != 1 {
		t.Fatalf("INBOX/Child holds %d messages, want 1", len(kids))
	}
	if _, err := f.space.GetFolderByPath(t.Context(), f.access, "INBOX/Child"); err != nil {
		t.Fatalf("INBOX/Child moved: %v", err)
	}
	target := mustFolder(t, f, "Archive/2026")
	moved := items(t, f, target.ID)
	if len(moved) != count {
		t.Fatalf("Archive/2026 holds %d messages, want %d", len(moved), count)
	}
	flagged := 0
	for _, item := range moved {
		if !slices.Contains(item.Flags, model.FlagSeen) {
			t.Fatalf("flags lost: %v", item.Flags)
		}
		if slices.Contains(item.Flags, model.FlagFlagged) && slices.Contains(item.Flags, "$Label1") {
			flagged++
		}
		if want, ok := internal[item.ID]; ok && !item.InternalDate.Equal(want) {
			t.Fatalf("internal date %v, want %v", item.InternalDate, want)
		}
	}
	if flagged != 1 {
		t.Fatalf("%d messages kept \\Flagged $Label1, want 1", flagged)
	}

	out := c.mustOK(t, "S1", "SELECT Archive/2026")
	if !strings.Contains(out, fmt.Sprintf("* %d EXISTS", count)) {
		t.Fatalf("SELECT target:\n%s", out)
	}
	out = c.mustOK(t, "F1", "UID FETCH 1:* (FLAGS)")
	for uid := 1; uid <= count; uid++ {
		if !strings.Contains(out, fmt.Sprintf("UID %d ", uid)) {
			t.Fatalf("target UIDs not assigned from 1:\n%s", out)
		}
	}
	out = c.mustOK(t, "S2", "SELECT INBOX")
	if !strings.Contains(out, "* 0 EXISTS") || !strings.Contains(out, fmt.Sprintf("UIDVALIDITY %d", before.UIDValidity)) {
		t.Fatalf("SELECT INBOX after rename:\n%s", out)
	}
}

func TestRenameInboxTargetExists(t *testing.T) {
	f := newWakeFixture(t)
	f.create(t, f.inbox.ID)
	c := f.client()
	out := c.run(t, "R1", "RENAME INBOX Other")
	if !strings.Contains(out, "R1 NO [ALREADYEXISTS]") {
		t.Fatalf("RENAME INBOX onto an existing mailbox:\n%s", out)
	}
	if left := items(t, f, f.inbox.ID); len(left) != 1 {
		t.Fatalf("INBOX holds %d messages after the refused rename, want 1", len(left))
	}
}

func TestRenameInboxExpungesReachIdleSession(t *testing.T) {
	f := newWakeFixture(t)
	f.create(t, f.inbox.ID)
	f.create(t, f.inbox.ID)
	watcher := f.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	idle(t, watcher)

	f.client().mustOK(t, "R1", "RENAME INBOX Old")
	watcher.expectLine(t, "* 2 EXPUNGE")
	watcher.expectLine(t, "* 1 EXPUNGE")
	if out := endIdle(t, watcher); strings.Contains(out, "EXPUNGE") {
		t.Fatalf("expunges repeated at IDLE completion:\n%s", out)
	}
}

func mustFolder(t *testing.T, f wakeFixture, path string) model.Folder {
	t.Helper()
	folder, err := f.space.GetFolderByPath(t.Context(), f.access, path)
	if err != nil {
		t.Fatalf("folder %s: %v", path, err)
	}
	return folder
}

func items(t *testing.T, f wakeFixture, folderID string) []model.Item {
	t.Helper()
	list, err := f.space.ListItems(t.Context(), f.access, folderID, service.ItemQuery{MetadataOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	return list
}
