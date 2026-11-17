package imap

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// readCountingSpace is the account-routed folder space, which announces its
// commits, with the reads sessions make counted.
type readCountingSpace struct {
	*service.AccountFolderSpace
	reads atomic.Int64
}

func (s *readCountingSpace) ListItems(ctx context.Context, access service.AccessContext, folderID string, query service.ItemQuery) ([]model.Item, error) {
	s.reads.Add(1)
	return s.AccountFolderSpace.ListItems(ctx, access, folderID, query)
}

func (s *readCountingSpace) ListFolders(ctx context.Context, access service.AccessContext, query service.FolderQuery) ([]model.Folder, error) {
	s.reads.Add(1)
	return s.AccountFolderSpace.ListFolders(ctx, access, query)
}

func (s *readCountingSpace) GetFolder(ctx context.Context, access service.AccessContext, folderID string) (model.Folder, error) {
	s.reads.Add(1)
	return s.AccountFolderSpace.GetFolder(ctx, access, folderID)
}

func (s *readCountingSpace) GetItem(ctx context.Context, access service.AccessContext, itemID string) (model.Item, error) {
	s.reads.Add(1)
	return s.AccountFolderSpace.GetItem(ctx, access, itemID)
}

// wakeFixture serves IMAP over the account-routed folder space, so changes
// made through the folder space directly (as the web UI, JMAP, ActiveSync,
// EWS, DAV, rules, and retention make them) reach sessions only through its
// commit notifications.
type wakeFixture struct {
	*sharedServer
	space  *readCountingSpace
	access service.AccessContext
	inbox  model.Folder
	other  model.Folder
}

func newWakeFixture(t *testing.T) wakeFixture {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	manager, err := account.NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	user, err := ts.UserStore().Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Ensure(t.Context(), user, "", nil); err != nil {
		t.Fatal(err)
	}
	routed, err := service.NewAccountFolderSpace(t.Context(), ts, manager, authz.New(ts))
	if err != nil {
		t.Fatal(err)
	}
	space := &readCountingSpace{AccountFolderSpace: routed}
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	other, err := space.CreateFolder(t.Context(), access, "Other", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		TypedStore:  ts,
		FolderSpace: space,
		Authorizer:  authz.New(ts),
	}
	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Accept(t.Context(), ln)
	t.Cleanup(func() { srv.Close() })
	return wakeFixture{
		sharedServer: &sharedServer{t: t, cfg: cfg, server: srv, addr: ln.Addr().String()},
		space:        space, access: access, inbox: inbox, other: other,
	}
}

// create adds a message the way another protocol does, returning it.
func (f wakeFixture) create(t *testing.T, folderID string) model.Item {
	t.Helper()
	item, err := f.space.CreateItem(context.Background(), f.access, folderID, service.ItemInput{Data: []byte("From: a@b.test\r\nSubject: elsewhere\r\n\r\nbody\r\n")})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

// idle starts IDLE and waits for its continuation.
func idle(t *testing.T, c *tc) {
	t.Helper()
	c.sendNoTag("I1 IDLE")
	if line, err := c.readIdleContinuation(); err != nil || !strings.HasPrefix(line, "+") {
		t.Fatalf("IDLE continuation = %q %v", line, err)
	}
}

// quiet reads what arrives within a while and returns it.
func quiet(c *tc, wait time.Duration) []string {
	var lines []string
	_ = c.Conn.SetReadDeadline(time.Now().Add(wait))
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return lines
		}
		lines = append(lines, strings.TrimRight(line, "\r\n"))
	}
}

// endIdle ends IDLE and returns everything up to its completion.
func endIdle(t *testing.T, c *tc) string {
	t.Helper()
	c.sendNoTag("DONE")
	var lines []string
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("IDLE completion: %v (got %q)", err, lines)
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, "I1 ") {
			return strings.Join(lines, "\n")
		}
	}
}

func TestIdleSeesFolderSpaceCommitPromptly(t *testing.T) {
	f := newWakeFixture(t)
	watcher := f.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	idle(t, watcher)

	var worst time.Duration
	for round := 1; round <= 5; round++ {
		started := time.Now()
		f.create(t, f.inbox.ID)
		watcher.expectLine(t, fmt.Sprintf("* %d EXISTS", round))
		worst = max(worst, time.Since(started))
	}
	t.Logf("commit to EXISTS: worst of 5 = %v", worst)
	if worst > 100*time.Millisecond {
		t.Fatalf("EXISTS took %v after the commit, want within 100ms", worst)
	}
	if out := endIdle(t, watcher); strings.Contains(out, "EXISTS") {
		t.Fatalf("EXISTS repeated at IDLE completion:\n%s", out)
	}
}

func TestIdleReportsFlagChangeFromAnotherProtocolOnce(t *testing.T) {
	f := newWakeFixture(t)
	item := f.create(t, f.inbox.ID)
	watcher := f.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	idle(t, watcher)

	if _, err := f.space.SetFlags(t.Context(), f.access, item.ID, []string{model.FlagSeen, model.FlagFlagged}); err != nil {
		t.Fatal(err)
	}
	if line := watcher.expectLine(t, "FETCH"); !strings.Contains(line, `\Seen`) || !strings.Contains(line, `\Flagged`) {
		t.Fatalf("flag change = %q", line)
	}
	if extra := quiet(watcher, 10*wakeSettle); len(extra) > 0 {
		t.Fatalf("flag change reported again: %q", extra)
	}
	if out := endIdle(t, watcher); strings.Contains(out, "FETCH") {
		t.Fatalf("flag change repeated at IDLE completion:\n%s", out)
	}
	if out := watcher.mustOK(t, "N1", "NOOP"); strings.Contains(out, "FETCH") {
		t.Fatalf("flag change repeated by NOOP:\n%s", out)
	}
}

func TestNotifyReportsCommitsToOtherMailboxes(t *testing.T) {
	f := newWakeFixture(t)
	watcher := f.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	watcher.mustOK(t, "N1", `NOTIFY SET (selected (MessageNew MessageExpunge)) (personal (MessageNew MessageExpunge FlagChange MailboxName))`)

	// Between commands, without the watcher asking for anything.
	item := f.create(t, f.other.ID)
	if line := watcher.expectLine(t, `* STATUS "Other"`); !strings.Contains(line, "MESSAGES 1") || !strings.Contains(line, "UIDNEXT 2") {
		t.Fatalf("MessageNew STATUS = %q", line)
	}
	if _, err := f.space.SetFlags(t.Context(), f.access, item.ID, []string{model.FlagSeen}); err != nil {
		t.Fatal(err)
	}
	if line := watcher.expectLine(t, `* STATUS "Other"`); !strings.Contains(line, "UNSEEN 0") {
		t.Fatalf("FlagChange STATUS = %q", line)
	}
	if _, err := f.space.CreateFolder(t.Context(), f.access, "Projects", model.FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	if line := watcher.expectLine(t, "LIST"); !strings.Contains(line, `"Projects"`) {
		t.Fatalf("MailboxName create = %q", line)
	}
	// The selected mailbox is reported from the view, once.
	f.create(t, f.inbox.ID)
	watcher.expectLine(t, "* 1 EXISTS")
	watcher.expectLine(t, "* 0 RECENT")
	if extra := quiet(watcher, 10*wakeSettle); len(extra) > 0 {
		t.Fatalf("unexpected repeat: %q", extra)
	}
	if out := watcher.mustOK(t, "W1", "NOOP"); strings.Contains(out, "EXISTS") || strings.Contains(out, "STATUS") {
		t.Fatalf("events repeated:\n%s", out)
	}
}

func TestWakeFromIMAPAndCommitPathsReportsOnce(t *testing.T) {
	f := newWakeFixture(t)
	watcher, actor := f.client(), f.client()
	watcher.mustOK(t, "S1", "SELECT INBOX")
	idle(t, watcher)

	// An IMAP APPEND is announced by the commit and by the session itself,
	// and a direct writer may announce a commit again.
	actor.mustAppend(t, "INBOX", threadRoot)
	f.server.NotifyExists(f.inbox.ID)
	watcher.expectLine(t, "* 1 EXISTS")
	actor.mustOK(t, "S2", "SELECT INBOX")
	actor.mustOK(t, "A1", `STORE 1 +FLAGS (\Seen)`)
	watcher.expectLine(t, "FETCH")
	if extra := quiet(watcher, 10*wakeSettle); len(extra) > 0 {
		t.Fatalf("change reported twice: %q", extra)
	}
	if out := endIdle(t, watcher); strings.Contains(out, "EXISTS") || strings.Contains(out, "FETCH") {
		t.Fatalf("change repeated at IDLE completion:\n%s", out)
	}
}

func TestSessionsOnUntouchedFoldersReadNothing(t *testing.T) {
	f := newWakeFixture(t)
	idler, notifier := f.client(), f.client()
	idler.mustOK(t, "S1", "SELECT Other")
	idle(t, idler)
	notifier.mustOK(t, "N1", `NOTIFY SET (mailboxes Other (MessageNew MessageExpunge))`)
	time.Sleep(10 * wakeSettle)

	before := f.space.reads.Load()
	for range 20 {
		f.create(t, f.inbox.ID)
	}
	time.Sleep(10 * wakeSettle)
	// CreateItem itself reads nothing through the counted methods, so any
	// read is a session's.
	if reads := f.space.reads.Load() - before; reads != 0 {
		t.Fatalf("sessions on untouched folders made %d reads for 20 commits elsewhere", reads)
	}

	// A commit to their folder is still reported, with one burst check.
	before = f.space.reads.Load()
	f.create(t, f.other.ID)
	idler.expectLine(t, "* 1 EXISTS")
	notifier.expectLine(t, `* STATUS "Other"`)
	t.Logf("reads for one watched commit: %d", f.space.reads.Load()-before)
}

func TestWakeRegistrationFollowsSessionsAndSharedOwners(t *testing.T) {
	f := newWakeFixture(t)
	c := f.client()
	c.mustOK(t, "S1", "SELECT INBOX")
	idle(t, c)
	waitFor(t, func() bool { return f.server.wakes.registered() == 1 })
	f.server.followMu.Lock()
	following := f.server.unfollow != nil
	f.server.followMu.Unlock()
	if !following {
		t.Fatal("an idling session does not follow commits")
	}
	endIdle(t, c)
	c.mustOK(t, "L1", "LOGOUT")
	waitFor(t, func() bool {
		f.server.followMu.Lock()
		defer f.server.followMu.Unlock()
		return f.server.wakes.registered() == 0 && f.server.unfollow == nil
	})

	// A shared mailbox is watched by folder and woken under its owner.
	var index wakeIndex
	w := newSessionWake()
	index.set(w, []string{"bob-shared"}, map[string]bool{"bob": false, "alice": true})
	index.changed("bob", []string{"bob-other"})
	if touched, all := w.take(); all || len(touched) != 0 {
		t.Fatalf("an unrelated folder of the owner woke the session: %v %v", touched, all)
	}
	index.changed("bob", []string{"bob-shared"})
	if touched, _ := w.take(); len(touched) != 1 {
		t.Fatalf("the shared folder's commit did not wake the session: %v", touched)
	}
	index.changed("bob", nil)
	if _, all := w.take(); !all {
		t.Fatal("an unspecified commit of the owner did not wake the session")
	}
	index.changed("alice", []string{"alice-folder"})
	if touched, _ := w.take(); len(touched) != 1 {
		t.Fatalf("NOTIFY's own account did not wake the session: %v", touched)
	}
	index.set(w, nil, nil)
	if index.registered() != 0 || len(index.byFolder) != 0 || len(index.byAccount) != 0 {
		t.Fatalf("registration left behind: %v %v", index.byFolder, index.byAccount)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}
