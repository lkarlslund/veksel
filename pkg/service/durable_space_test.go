package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestDurableFolderSpacePersistsBeforeMutation(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	durable, err := NewDurableFolderSpace(t.Context(), ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "test")
	inbox, err := durable.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	item, err := durable.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: durable\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if item.Headers[commandIDHeader] == "" {
		t.Fatal("durable command identity missing from item")
	}
	commandID := item.Headers[commandIDHeader]
	indexed, err := durable.GetItemByExternalID(t.Context(), access, inbox.ID, commandExternalNamespace, commandID)
	if err != nil || indexed.ID != item.ID {
		t.Fatalf("indexed command item = %q, err = %v, want %q", indexed.ID, err, item.ID)
	}
	keys, err := ts.Store().Scan(t.Context(), model.NSQueue, folderCommandPrefix)
	if err != nil || len(keys) != 0 {
		t.Fatalf("completed commands=%v err=%v", keys, err)
	}
}

func TestItemHistoryCapabilitySurvivesDurableCacheAndReplay(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	durable, err := NewDurableFolderSpace(t.Context(), ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	cached := NewCachedFolderSpace(durable, FolderCacheConfig{})
	history, ok := any(cached).(ItemHistoryFolderSpace)
	if !ok {
		t.Fatal("cached durable space lost item-history capability")
	}
	access := UserAccess("alice", "test")
	inbox, err := cached.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := history.ConfigureItemHistory(t.Context(), access, inbox.ID, model.ItemHistoryPolicy{Enabled: true, MaxVersions: 5}); err != nil {
		t.Fatal(err)
	}
	item, err := cached.CreateItem(t.Context(), access, inbox.ID, ItemInput{Name: "durable-history", Data: []byte("old")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cached.UpdateItem(t.Context(), access, item.ID, []byte("new"), nil); err != nil {
		t.Fatal(err)
	}
	versions, err := history.ListItemVersions(t.Context(), access, inbox.ID, item.ID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions=%+v err=%v", versions, err)
	}

	command := folderCommand{
		ID: "restore-replay", Operation: "restore-item-version", Access: access,
		FolderID: inbox.ID, ItemID: item.ID, VersionID: versions[0].ID,
	}
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Store().Set(t.Context(), model.NSQueue, folderCommandPrefix+command.ID, data); err != nil {
		t.Fatal(err)
	}
	if _, err := durable.apply(t.Context(), command, false); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatal(err)
	}
	got, err := base.GetItem(t.Context(), access, item.ID)
	if err != nil || string(got.Data) != "old" {
		t.Fatalf("restored item=%+v err=%v", got, err)
	}
	versions, err = base.ListItemVersions(t.Context(), access, inbox.ID, item.ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("replayed versions=%+v err=%v", versions, err)
	}
}

func TestDurableFolderSpaceReplaysCreateIdempotently(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "test")
	inbox, err := base.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	command := folderCommand{ID: "replay-1", Operation: "create-item", Access: access, FolderID: inbox.ID, Item: ItemInput{Data: []byte("Subject: replay\r\n\r\nbody")}}
	data, _ := json.Marshal(command)
	if err := ts.Store().Set(t.Context(), model.NSQueue, folderCommandPrefix+command.ID, data); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatal(err)
	}
	items, err := base.ListItems(t.Context(), access, inbox.ID, ItemQuery{})
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%v err=%v", items, err)
	}
}

func TestFolderCommandCompressionRoundTripAndLegacyCompatibility(t *testing.T) {
	large := folderCommand{
		ID: "compressed", Operation: "create-items", FolderID: "folder",
		Items: []ItemInput{{Data: bytes.Repeat([]byte("Subject: compressible\r\n\r\nbody\r\n"), 1024)}},
	}
	raw, err := json.Marshal(large)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeFolderCommand(large)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encoded, folderCommandCompressedMagic) {
		t.Fatal("large folder command was not compressed")
	}
	if len(encoded) >= len(raw)/2 {
		t.Fatalf("compressed command size = %d, raw = %d", len(encoded), len(raw))
	}
	decoded, err := decodeFolderCommand(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ID != large.ID || decoded.Operation != large.Operation || len(decoded.Items) != 1 || !bytes.Equal(decoded.Items[0].Data, large.Items[0].Data) {
		t.Fatalf("decoded command = %#v", decoded)
	}
	legacy, err := decodeFolderCommand(raw)
	if err != nil || legacy.ID != large.ID || !bytes.Equal(legacy.Items[0].Data, large.Items[0].Data) {
		t.Fatalf("legacy command = %#v, %v", legacy, err)
	}
	if _, err := decodeFolderCommand(append(append([]byte(nil), folderCommandCompressedMagic...), []byte("invalid")...)); err == nil {
		t.Fatal("corrupt compressed command was accepted")
	}
}

func TestDurableFolderSpaceReplaysMultiCreateIdempotently(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "test")
	inbox, err := base.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	command := folderCommand{ID: "replay-many", Operation: "create-items", Access: access, FolderID: inbox.ID, Items: []ItemInput{
		{Data: append([]byte("Subject: first\r\n\r\n"), bytes.Repeat([]byte("body "), 1024)...)},
		{Data: append([]byte("Subject: second\r\n\r\n"), bytes.Repeat([]byte("body "), 1024)...)},
	}}
	data, err := encodeFolderCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, folderCommandCompressedMagic) {
		t.Fatal("multi-create replay fixture was not compressed")
	}
	if err := ts.Store().Set(t.Context(), model.NSQueue, folderCommandPrefix+command.ID, data); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
			t.Fatal(err)
		}
	}
	items, err := base.ListItems(t.Context(), access, inbox.ID, ItemQuery{})
	if err != nil || len(items) != 2 {
		t.Fatalf("items=%v err=%v", items, err)
	}
}

func TestDurableFolderSpaceRejectsPermanentReplayFailure(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "test")
	inbox, err := base.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	command := folderCommand{
		ID: "invalid-parent", Operation: "create-folder", Access: access,
		Name: "JYPA", FolderType: model.FolderTypeCalendar, ParentID: inbox.ID,
	}
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	pendingKey := folderCommandPrefix + command.ID
	if err := ts.Store().Set(t.Context(), model.NSQueue, pendingKey, data); err != nil {
		t.Fatal(err)
	}

	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatalf("startup should retain and skip a permanently rejected command: %v", err)
	}
	if _, err := ts.Store().Get(t.Context(), model.NSQueue, pendingKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pending command error = %v, want not found", err)
	}
	rejectedData, err := ts.Store().Get(t.Context(), model.NSQueue, rejectedFolderCommandPrefix+command.ID)
	if err != nil {
		t.Fatal(err)
	}
	var rejected rejectedFolderCommand
	if err := json.Unmarshal(rejectedData, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Command.ID != command.ID || rejected.Error == "" || rejected.FailedAt.IsZero() {
		t.Fatalf("rejected command = %#v", rejected)
	}
}

func TestDurableFolderSpaceDoesNotLeaveRejectedMutationPending(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	durable, err := NewDurableFolderSpace(t.Context(), ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "test")
	inbox, err := durable.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := durable.CreateFolder(t.Context(), access, "JYPA", model.FolderTypeCalendar, inbox.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("create folder error = %v, want forbidden", err)
	}
	pending, err := ts.Store().Scan(t.Context(), model.NSQueue, folderCommandPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending commands = %v, want none", pending)
	}
	rejected, err := ts.Store().Scan(t.Context(), model.NSQueue, rejectedFolderCommandPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 1 {
		t.Fatalf("rejected commands = %v, want one", rejected)
	}
}

// A CalDAV PROPPATCH with an invalid calendar color (caldav-server-tester
// sends a named color) left its update-folder command pending, and the next
// start failed replaying it.
func TestDurableFolderSpaceRejectsInvalidFolderUpdate(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	durable, err := NewDurableFolderSpace(t.Context(), ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "test")
	calendar, err := durable.CreateFolder(t.Context(), access, "Work", model.FolderTypeCalendar, "")
	if err != nil {
		t.Fatal(err)
	}
	color := "red"
	if _, err := durable.UpdateFolder(t.Context(), access, calendar.ID, FolderUpdate{Color: &color}); !errors.Is(err, ErrInvalidFolderUpdate) {
		t.Fatalf("update error = %v, want invalid folder update", err)
	}
	pending, err := ts.Store().Scan(t.Context(), model.NSQueue, folderCommandPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending commands = %v, want none", pending)
	}
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatalf("replay after a rejected update: %v", err)
	}
	name, order := "Work stuff", 4
	updated, err := durable.UpdateFolder(t.Context(), access, calendar.ID, FolderUpdate{Name: &name, Order: &order})
	if err != nil || updated.Name != name || updated.Order != order || updated.Path != calendar.Path {
		t.Fatalf("presentation update = %+v, %v; the path must stay %q", updated, err, calendar.Path)
	}
}

func TestDurableFolderSpaceDoesNotRejectCorruptJournalData(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatal(err)
	}
	key := folderCommandPrefix + "corrupt"
	if err := ts.Store().Set(t.Context(), model.NSQueue, key, []byte("not-json")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err == nil {
		t.Fatal("startup succeeded with corrupt journal data")
	}
	if _, err := ts.Store().Get(t.Context(), model.NSQueue, key); err != nil {
		t.Fatalf("corrupt journal data should remain pending: %v", err)
	}
}

// compactingStore records journal compactions requested of a store.
type compactingStore struct {
	store.Store
	compactions chan string
}

func (s compactingStore) CompactPrefix(_ context.Context, namespace, prefix string) error {
	s.compactions <- namespace + "/" + prefix
	return nil
}

func TestDurableFolderSpaceCompactsJournalAfterLargeCommands(t *testing.T) {
	_, ts, _ := testMailService(t)
	backend := compactingStore{Store: ts.Store(), compactions: make(chan string, 4)}
	durable, err := NewDurableFolderSpace(t.Context(), backend, NewFolderSpace(ts, authz.New(ts)))
	if err != nil {
		t.Fatal(err)
	}
	awaitCompaction := func(reason string) {
		t.Helper()
		select {
		case got := <-backend.compactions:
			if got != model.NSQueue+"/"+folderCommandPrefix {
				t.Fatalf("%s compacted %q", reason, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: journal was not compacted", reason)
		}
		for durable.compacting.Load() {
			time.Sleep(time.Millisecond)
		}
	}
	awaitCompaction("startup")

	access := UserAccess("alice", "test")
	inbox, err := durable.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := durable.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: small\r\n\r\nbody")}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-backend.compactions:
		t.Fatalf("small command compacted %q", got)
	default:
	}
	large := make([]byte, largeFolderCommandSize+1024)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}
	if _, err := durable.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: append([]byte("Subject: large\r\n\r\n"), large...)}); err != nil {
		t.Fatal(err)
	}
	awaitCompaction("large command")
}

// TestDurableFolderSpaceRejectsInvalidRequests replays the interop failure
// where an IMAP CREATE with a trailing delimiter reached the workspace as an
// empty folder name. The validation error was not permanent, so the command
// stayed in the journal and every later start failed while replaying it.
func TestDurableFolderSpaceRejectsInvalidRequests(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	durable, err := NewDurableFolderSpace(t.Context(), ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "test")
	for _, name := range []string{"", "/", "a/b"} {
		if _, err := durable.CreateFolder(t.Context(), access, name, model.FolderTypeMail, ""); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("create folder %q error = %v, want invalid request", name, err)
		}
	}
	pending, err := ts.Store().Scan(t.Context(), model.NSQueue, folderCommandPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending commands = %v, want none", pending)
	}
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatalf("restart after rejected commands: %v", err)
	}
	// IMAP RENAME INBOX failed with a plain validation error and poisoned the
	// journal the same way.
	inbox, err := durable.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := durable.MoveFolder(t.Context(), access, inbox.ID, "", "Old Inbox"); err == nil {
		t.Fatal("moving INBOX succeeded")
	}
	if pending, _ := ts.Store().Scan(t.Context(), model.NSQueue, folderCommandPrefix); len(pending) != 0 {
		t.Fatalf("pending commands after refused move = %v, want none", pending)
	}
	if _, err := NewDurableFolderSpace(t.Context(), ts.Store(), base); err != nil {
		t.Fatalf("restart after refused move: %v", err)
	}
	for _, permanent := range []error{ErrInvalidRequest, model.ErrQuotaExceeded, ErrLegalHold, errors.New("system or trashed folders cannot be moved")} {
		if !isPermanentCommandError(fmt.Errorf("wrapped: %w", permanent)) {
			t.Fatalf("%v is not a permanent command error", permanent)
		}
	}
	for _, transient := range []error{context.Canceled, context.DeadlineExceeded} {
		if isPermanentCommandError(fmt.Errorf("wrapped: %w", transient)) {
			t.Fatalf("%v is a permanent command error", transient)
		}
	}
}
