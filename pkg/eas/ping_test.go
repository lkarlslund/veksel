package eas

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// countingSpace is the routed account space, which notifies commits, with
// its journal reads counted.
type countingSpace struct {
	*service.AccountFolderSpace
	journalReads atomic.Int64
	// unlocated reproduces the window after an account commit, and its
	// notification, before the system-wide item location exists: GetItem
	// reports every item as missing.
	unlocated atomic.Bool
}

func (s *countingSpace) GetItem(ctx context.Context, access service.AccessContext, itemID string) (model.Item, error) {
	if s.unlocated.Load() {
		return model.Item{}, store.ErrNotFound
	}
	return s.AccountFolderSpace.GetItem(ctx, access, itemID)
}

func (s *countingSpace) ListChanges(ctx context.Context, access service.AccessContext, scope service.ChangeScope, state string, limit int) (service.ChangePage, error) {
	s.journalReads.Add(1)
	return s.AccountFolderSpace.ListChanges(ctx, access, scope, state, limit)
}

func (s *countingSpace) CurrentChangeState(ctx context.Context, access service.AccessContext, scope service.ChangeScope) (string, error) {
	s.journalReads.Add(1)
	return s.AccountFolderSpace.CurrentChangeState(ctx, access, scope)
}

type pingFixture struct {
	handler *Handler
	space   *countingSpace
	access  service.AccessContext
	inbox   model.Folder
	other   model.Folder
	stop    context.CancelFunc
}

// newPingFixture serves EAS over the account-sharded folder space, whose
// commits notify the handler, with the handler's lifetime under stop.
func newPingFixture(tb testing.TB) pingFixture {
	tb.Helper()
	backend, err := jsonstore.New(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(context.Background(), namespace); err != nil {
			tb.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(context.Background(), "alice", "Alice", "secret"); err != nil {
		tb.Fatal(err)
	}
	manager, err := account.NewManager(tb.TempDir(), store.BackendPebble)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = manager.Close() })
	user, err := ts.UserStore().Get(context.Background(), "alice")
	if err != nil {
		tb.Fatal(err)
	}
	if _, _, err := manager.Ensure(context.Background(), user, "", nil); err != nil {
		tb.Fatal(err)
	}
	routed, err := service.NewAccountFolderSpace(context.Background(), ts, manager, authz.New(ts))
	if err != nil {
		tb.Fatal(err)
	}
	space := &countingSpace{AccountFolderSpace: routed}
	ctx, stop := context.WithCancel(context.Background())
	tb.Cleanup(stop)
	handler, err := New(ctx, Config{Space: space, Store: backend, Authenticate: func(_ context.Context, username, password string) (string, error) {
		if username == "alice" && password == "secret" {
			return "alice", nil
		}
		return "", context.Canceled
	}})
	if err != nil {
		tb.Fatal(err)
	}
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(context.Background(), access, "INBOX")
	if err != nil {
		tb.Fatal(err)
	}
	other, err := space.CreateFolder(context.Background(), access, "Other", model.FolderTypeMail, "")
	if err != nil {
		tb.Fatal(err)
	}
	return pingFixture{handler: handler, space: space, access: access, inbox: inbox, other: other, stop: stop}
}

func pingBody(folderID string) *Node {
	return E(13, "Ping", T(13, "HeartbeatInterval", "300"),
		E(13, "Folders", E(13, "Folder", T(13, "Id", encodeServerID("f:", folderID)), T(13, "Class", "Email"))))
}

// ping sends a Ping from device and returns its status. It needs no
// testing.T, so it runs on its own goroutine.
func (f pingFixture) ping(device string, body *Node) string {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = Encode(body); err != nil {
			return err.Error()
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/Microsoft-Server-ActiveSync?Cmd=Ping&User=alice&DeviceId="+device+"&DeviceType=Test", bytes.NewReader(payload))
	request.SetBasicAuth("alice", "secret")
	request.Header.Set("MS-ASProtocolVersion", "16.1")
	request.Header.Set("Content-Type", "application/vnd.ms-sync.wbxml")
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	root, err := Decode(response.Body.Bytes())
	if err != nil || response.Code != http.StatusOK {
		return fmt.Sprintf("HTTP %d: %v", response.Code, err)
	}
	return nodeText(root, "Status")
}

// goPing sends a Ping from device on its own goroutine.
func (f pingFixture) goPing(device string, body *Node) <-chan string {
	done := make(chan string, 1)
	go func() { done <- f.ping(device, body) }()
	return done
}

// startPing sends a Ping for folderID from device and returns once it is
// registered as waiting; the channel receives its status.
func (f pingFixture) startPing(tb testing.TB, device, folderID string) <-chan string {
	tb.Helper()
	waiting := f.handler.waits.waiting()
	done := f.goPing(device, pingBody(folderID))
	deadline := time.Now().Add(5 * time.Second)
	for f.handler.waits.waiting() <= waiting {
		select {
		case status := <-done:
			tb.Fatalf("Ping answered %s instead of waiting", status)
		default:
		}
		if time.Now().After(deadline) {
			tb.Fatal("Ping never started waiting")
		}
		time.Sleep(time.Millisecond)
	}
	return done
}

func (f pingFixture) deliver(tb testing.TB, folderID string) {
	tb.Helper()
	if _, err := f.space.CreateItem(context.Background(), f.access, folderID, service.ItemInput{Data: []byte("Subject: new\r\n\r\nbody")}); err != nil {
		tb.Fatal(err)
	}
}

func awaitStatus(tb testing.TB, done <-chan string, within time.Duration) (string, time.Duration) {
	tb.Helper()
	started := time.Now()
	select {
	case status := <-done:
		return status, time.Since(started)
	case <-time.After(within):
		tb.Fatalf("Ping did not answer within %v", within)
		return "", 0
	}
}

// TestPingWakesOnCommitToMonitoredFolder: a commit to a watched folder
// answers the Ping at once instead of on the next poll.
func TestPingWakesOnCommitToMonitoredFolder(t *testing.T) {
	f := newPingFixture(t)
	done := f.startPing(t, "D1", f.inbox.ID)
	started := time.Now()
	f.deliver(t, f.inbox.ID)
	status, _ := awaitStatus(t, done, 2*time.Second)
	if elapsed := time.Since(started); status != pingChanges || elapsed > 100*time.Millisecond {
		t.Fatalf("Ping = status %s after %v, want %s within 100ms", status, elapsed, pingChanges)
	}
}

// TestPingIgnoresCommitsToOtherFolders: a commit elsewhere in the account
// neither answers the Ping nor makes it read the journal.
func TestPingIgnoresCommitsToOtherFolders(t *testing.T) {
	f := newPingFixture(t)
	done := f.startPing(t, "D1", f.inbox.ID)
	reads := f.space.journalReads.Load()
	f.deliver(t, f.other.ID)
	select {
	case status := <-done:
		t.Fatalf("Ping answered %s for a commit to an unwatched folder", status)
	case <-time.After(200 * time.Millisecond):
	}
	if delta := f.space.journalReads.Load() - reads; delta != 0 {
		t.Fatalf("an unwatched commit caused %d journal reads", delta)
	}
	f.deliver(t, f.inbox.ID)
	if status, _ := awaitStatus(t, done, 2*time.Second); status != pingChanges {
		t.Fatalf("Ping = %s after a watched commit", status)
	}
}

// TestPingEndsOnShutdown: when the handler's context ends, a waiting Ping
// answers promptly with status 1 so the device simply pings again, and a
// Ping arriving afterwards does not wait.
func TestPingEndsOnShutdown(t *testing.T) {
	f := newPingFixture(t)
	done := f.startPing(t, "D1", f.inbox.ID)
	f.stop()
	if status, elapsed := awaitStatus(t, done, 2*time.Second); status != pingExpired || elapsed > 100*time.Millisecond {
		t.Fatalf("Ping on shutdown = status %s after %v", status, elapsed)
	}
	if status, _ := awaitStatus(t, f.goPing("D1", nil), 2*time.Second); status != pingExpired {
		t.Fatalf("Ping after shutdown = %s", status)
	}
	if waiting := f.handler.waits.waiting(); waiting != 0 {
		t.Fatalf("%d waits remain registered", waiting)
	}
}

// TestNewerPingSupersedesWaitingPing: a device's new Ping ends its previous
// one at once.
func TestNewerPingSupersedesWaitingPing(t *testing.T) {
	f := newPingFixture(t)
	first := f.startPing(t, "D1", f.inbox.ID)
	second := f.goPing("D1", pingBody(f.inbox.ID))
	if status, elapsed := awaitStatus(t, first, 2*time.Second); status != pingExpired || elapsed > 500*time.Millisecond {
		t.Fatalf("superseded Ping = status %s after %v", status, elapsed)
	}
	f.deliver(t, f.inbox.ID)
	if status, _ := awaitStatus(t, second, 2*time.Second); status != pingChanges {
		t.Fatalf("newer Ping = %s", status)
	}
}

// TestIdlePingsReadNothing: many devices waiting on an idle account cause no
// journal reads; the previous design polled every waiting device every 5 s.
func TestIdlePingsReadNothing(t *testing.T) {
	f := newPingFixture(t)
	const devices = 50
	done := make([]<-chan string, devices)
	for i := range devices {
		done[i] = f.startPing(t, fmt.Sprintf("D%d", i), f.inbox.ID)
	}
	reads := f.space.journalReads.Load()
	time.Sleep(500 * time.Millisecond)
	if delta := f.space.journalReads.Load() - reads; delta != 0 {
		t.Fatalf("%d idle Pings made %d journal reads in 500ms", devices, delta)
	}
	f.deliver(t, f.inbox.ID)
	for i := range devices {
		if status, _ := awaitStatus(t, done[i], 2*time.Second); status != pingChanges {
			t.Fatalf("device %d Ping = %s", i, status)
		}
	}
	t.Logf("one commit woke %d Pings with %d journal reads", devices, f.space.journalReads.Load()-reads)
}

// TestSyncAfterWakeSendsItemBeforeItsLocationIsVisible: a Sync woken by a
// commit can run before the new item's location is written; it must still
// send the item rather than advance the sync key past its creation.
func TestSyncAfterWakeSendsItemBeforeItsLocationIsVisible(t *testing.T) {
	f := newPingFixture(t)
	collectionID := encodeServerID("f:", f.inbox.ID)
	key := initialSync(t, f.handler, collectionID)
	f.space.unlocated.Store(true)
	f.deliver(t, f.inbox.ID)
	root := decodeResponse(t, easRequest(t, f.handler, "Sync", easSyncRequest(collectionID, key, 100)))
	f.space.unlocated.Store(false)
	if adds := root.Descendant("Commands").ChildrenNamed("Add"); len(adds) != 1 {
		t.Fatalf("Sync in the location window sent %d Adds: %#v", len(adds), root)
	}
}

// BenchmarkPingWake reports the time from a commit to a watched folder to
// the waiting Ping's answer.
func BenchmarkPingWake(b *testing.B) {
	f := newPingFixture(b)
	var total time.Duration
	for i := 0; b.Loop(); i++ {
		done := f.startPing(b, fmt.Sprintf("B%d", i), f.inbox.ID)
		started := time.Now()
		f.deliver(b, f.inbox.ID)
		if status := <-done; status != pingChanges {
			b.Fatalf("Ping = %s", status)
		}
		total += time.Since(started)
	}
	b.ReportMetric(float64(total.Microseconds())/float64(b.N), "µs/wake")
}
