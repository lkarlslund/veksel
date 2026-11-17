package jmap

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/keyring"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// countingSubmitter accepts every message under a new queue ID.
type countingSubmitter struct {
	mu sync.Mutex
	n  int
}

func (c *countingSubmitter) SubmitRawWithOptions(context.Context, model.PrincipalRef, []byte, service.RawSubmissionOptions) (service.SubmissionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return service.SubmissionResult{ID: fmt.Sprintf("q%03d", c.n), AcceptedAt: time.Now()}, nil
}

func (f *fixture) submit(t *testing.T) string {
	t.Helper()
	emailID := f.storeMail(t, "Drafts", "From: alice@example.test\r\nTo: bob@example.test\r\nSubject: s\r\n\r\nbody", time.Now())
	r := args(t, f.one(t, "EmailSubmission/set", map[string]any{"accountId": "alice", "create": map[string]any{"s": map[string]any{"identityId": "alice@example.test", "emailId": emailID}}}), "EmailSubmission/set")
	created, ok := r["created"].(map[string]any)["s"].(map[string]any)
	if !ok {
		t.Fatalf("EmailSubmission/set = %#v", r)
	}
	return created["id"].(string)
}

func (f *fixture) submissionChanges(t *testing.T, since string, maxChanges int) []any {
	t.Helper()
	request := map[string]any{"accountId": "alice", "sinceState": since}
	if maxChanges > 0 {
		request["maxChanges"] = maxChanges
	}
	return f.one(t, "EmailSubmission/changes", request)
}

func stringList(value any) []string {
	out := []string{}
	for _, item := range value.([]any) {
		out = append(out, item.(string))
	}
	return out
}

func sameStrings(a, b []string) bool {
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func TestEmailSubmissionPersistsAcrossRestartWithChanges(t *testing.T) {
	f := newFixture(t)
	f.cfg.Submitter = &countingSubmitter{}
	f.handler.cfg.Submitter = f.cfg.Submitter
	first, second, third := f.submit(t), f.submit(t), f.submit(t)
	destroy := args(t, f.one(t, "EmailSubmission/set", map[string]any{"accountId": "alice", "destroy": []string{second}}), "EmailSubmission/set")
	if !sameStrings(stringList(destroy["destroyed"]), []string{second}) || destroy["newState"] != "s4" {
		t.Fatalf("destroy = %#v", destroy)
	}
	beforeGet := args(t, f.one(t, "EmailSubmission/get", map[string]any{"accountId": "alice", "ids": nil}), "EmailSubmission/get")

	f.restart(t)

	got := args(t, f.one(t, "EmailSubmission/get", map[string]any{"accountId": "alice", "ids": nil}), "EmailSubmission/get")
	if got["state"] != "s4" || got["state"] != beforeGet["state"] {
		t.Fatalf("state after restart = %v, before %v", got["state"], beforeGet["state"])
	}
	before, _ := json.Marshal(beforeGet["list"])
	after, _ := json.Marshal(got["list"])
	if !bytes.Equal(before, after) || len(got["list"].([]any)) != 2 {
		t.Fatalf("list after restart = %s, before %s", after, before)
	}
	query := args(t, f.one(t, "EmailSubmission/query", map[string]any{"accountId": "alice"}), "EmailSubmission/query")
	if !sameStrings(stringList(query["ids"]), []string{first, third}) || query["queryState"] != "s4" {
		t.Fatalf("query after restart = %#v", query)
	}
	// From the empty state: the one made and destroyed in the window is
	// omitted.
	all := args(t, f.submissionChanges(t, "s0", 0), "EmailSubmission/changes")
	if !sameStrings(stringList(all["created"]), []string{first, third}) || len(all["destroyed"].([]any)) != 0 || all["newState"] != "s4" || all["hasMoreChanges"] != false {
		t.Fatalf("changes from s0 = %#v", all)
	}
	// From after the second submission it is a plain destroy.
	partial := args(t, f.submissionChanges(t, "s2", 0), "EmailSubmission/changes")
	if !sameStrings(stringList(partial["created"]), []string{third}) || !sameStrings(stringList(partial["destroyed"]), []string{second}) {
		t.Fatalf("changes from s2 = %#v", partial)
	}
	paged := args(t, f.submissionChanges(t, "s0", 1), "EmailSubmission/changes")
	if paged["newState"] != "s1" || paged["hasMoreChanges"] != true || !sameStrings(stringList(paged["created"]), []string{first}) {
		t.Fatalf("paged changes = %#v", paged)
	}
	if same := args(t, f.submissionChanges(t, "s4", 0), "EmailSubmission/changes"); same["newState"] != "s4" || len(same["created"].([]any)) != 0 {
		t.Fatalf("changes from current state = %#v", same)
	}
	for _, state := range []string{"s9", "bogus"} {
		if got := errorType(f.submissionChanges(t, state, 0)); got != "cannotCalculateChanges" {
			t.Fatalf("changes from %s = %q", state, got)
		}
	}
	// The counter continues instead of restarting, so old states never
	// come back with new meaning.
	fourth := f.submit(t)
	next := args(t, f.submissionChanges(t, "s4", 0), "EmailSubmission/changes")
	if next["newState"] != "s5" || !sameStrings(stringList(next["created"]), []string{fourth}) {
		t.Fatalf("changes after restart = %#v", next)
	}
}

// rewrite edits stored JMAP records of an account in place.
func (f *fixture) rewrite(t *testing.T, accountID, prefix string, edit func(map[string]any)) {
	t.Helper()
	err := f.accounts.WithIndex(t.Context(), accountID, func(ctx context.Context, index store.Store) error {
		edited := map[string][]byte{}
		err := index.Iterate(ctx, stateNamespace, prefix, func(key string, value []byte) (bool, error) {
			var record map[string]any
			if err := json.Unmarshal(value, &record); err != nil {
				return false, err
			}
			edit(record)
			edited[key], _ = json.Marshal(record)
			return true, nil
		})
		for key, data := range edited {
			if err == nil {
				err = index.Set(ctx, stateNamespace, key, data)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) indexed(t *testing.T) []string {
	t.Helper()
	keys, err := f.cfg.State.List(t.Context(), stateIndexNamespace)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestSweepPrunesSubmissionHistoryPastRetention(t *testing.T) {
	f := newFixture(t)
	f.handler.cfg.Submitter = &countingSubmitter{}
	old, recent := f.submit(t), f.submit(t)
	longAgo := time.Now().Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	f.rewrite(t, "alice", submissionPrefix+old, func(record map[string]any) { record["recorded_at"] = longAgo })
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := args(t, f.one(t, "EmailSubmission/get", map[string]any{"accountId": "alice", "ids": []string{old, recent}}), "EmailSubmission/get")
	if !sameStrings(stringList(got["notFound"]), []string{old}) || got["state"] != "s3" {
		t.Fatalf("after sweep = %#v", got)
	}
	changes := args(t, f.submissionChanges(t, "s2", 0), "EmailSubmission/changes")
	if !sameStrings(stringList(changes["destroyed"]), []string{old}) {
		t.Fatalf("pruned submission must read as destroyed: %#v", changes)
	}
	// Old change entries go too, and the floor follows them.
	f.rewrite(t, "alice", submissionChangePrefix, func(record map[string]any) { record["at"] = longAgo })
	f.handler.SetSubmissionRetention(24 * time.Hour)
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := errorType(f.submissionChanges(t, "s2", 0)); got != "cannotCalculateChanges" {
		t.Fatalf("changes from a pruned state = %q", got)
	}
	if same := args(t, f.submissionChanges(t, "s3", 0), "EmailSubmission/changes"); same["newState"] != "s3" {
		t.Fatalf("changes from the current state = %#v", same)
	}
	f.rewrite(t, "alice", submissionPrefix, func(record map[string]any) { record["recorded_at"] = longAgo })
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.rewrite(t, "alice", submissionChangePrefix, func(record map[string]any) { record["at"] = longAgo })
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if keys := f.indexed(t); len(keys) != 0 {
		t.Fatalf("an account with nothing left stays indexed: %v", keys)
	}
	if state := args(t, f.one(t, "EmailSubmission/get", map[string]any{"accountId": "alice"}), "EmailSubmission/get")["state"]; state != "s4" {
		t.Fatalf("state after full prune = %v", state)
	}
}

type pushReceiver struct {
	server   *httptest.Server
	received chan []byte
	private  *ecdh.PrivateKey
	auth     []byte
}

func newPushReceiver(t *testing.T) *pushReceiver {
	t.Helper()
	r := &pushReceiver{received: make(chan []byte, 16)}
	r.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.received <- body
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(r.server.Close)
	var err error
	if r.private, err = ecdh.P256().GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	r.auth = make([]byte, 16)
	_, _ = rand.Read(r.auth)
	return r
}

func (r *pushReceiver) keys() map[string]string {
	return map[string]string{"p256dh": base64.RawURLEncoding.EncodeToString(r.private.PublicKey().Bytes()), "auth": base64.RawURLEncoding.EncodeToString(r.auth)}
}

func (r *pushReceiver) next(t *testing.T, wantType string) map[string]any {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case body := <-r.received:
			var message map[string]any
			if err := json.Unmarshal(decryptPush(t, r.private, r.auth, body), &message); err != nil {
				t.Fatal(err)
			}
			if message["@type"] == wantType {
				return message
			}
		case <-deadline:
			t.Fatalf("no %s delivered", wantType)
			return nil
		}
	}
}

func (f *fixture) createPush(t *testing.T, receiver *pushReceiver, device string) (string, string) {
	t.Helper()
	set := args(t, f.one(t, "PushSubscription/set", map[string]any{"create": map[string]any{"p": map[string]any{"deviceClientId": device, "url": receiver.server.URL, "keys": receiver.keys()}}}), "PushSubscription/set")
	id := set["created"].(map[string]any)["p"].(map[string]any)["id"].(string)
	verification := receiver.next(t, "PushVerification")
	if verification["pushSubscriptionId"] != id {
		t.Fatalf("verification = %#v", verification)
	}
	return id, verification["verificationCode"].(string)
}

func (f *fixture) pushList(t *testing.T) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, item := range args(t, f.one(t, "PushSubscription/get", map[string]any{}), "PushSubscription/get")["list"].([]any) {
		object := item.(map[string]any)
		out[object["id"].(string)] = object
	}
	return out
}

func TestPushSubscriptionSurvivesRestartAndStillDelivers(t *testing.T) {
	f := newFixture(t)
	receiver := newPushReceiver(t)
	f.cfg.PushClient = receiver.server.Client()
	f.handler.pushClient = f.cfg.PushClient
	verified, code := f.createPush(t, receiver, "phone")
	f.one(t, "PushSubscription/set", map[string]any{"update": map[string]any{verified: map[string]any{"verificationCode": code}}})
	pending, pendingCode := f.createPush(t, receiver, "tablet")

	f.restart(t)

	list := f.pushList(t)
	if len(list) != 2 || list[verified]["verificationCode"] != code || list[pending]["verificationCode"] != nil {
		t.Fatalf("subscriptions after restart = %#v", list)
	}
	// The sweep resumes delivery for verified subscriptions.
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	f.storeMail(t, "INBOX", "Subject: after restart\r\n\r\nbody", time.Now())
	change := receiver.next(t, "StateChange")
	if change["changed"].(map[string]any)["alice"] == nil {
		t.Fatalf("state change = %#v", change)
	}
	// A verification pending across the restart still completes.
	r := args(t, f.one(t, "PushSubscription/set", map[string]any{"update": map[string]any{pending: map[string]any{"verificationCode": pendingCode}}}), "PushSubscription/set")
	if _, ok := r["updated"].(map[string]any)[pending]; !ok {
		t.Fatalf("verify after restart = %#v", r)
	}
	f.handler.mu.Lock()
	running := len(f.handler.pushLoops["alice"])
	f.handler.mu.Unlock()
	if running != 2 {
		t.Fatalf("running push loops = %d", running)
	}
	f.one(t, "PushSubscription/set", map[string]any{"destroy": []string{verified, pending}})
	if keys := f.indexed(t); len(keys) != 0 {
		t.Fatalf("index after destroying every subscription = %v", keys)
	}
}

func TestSweepDeletesExpiredPushSubscriptions(t *testing.T) {
	f := newFixture(t)
	receiver := newPushReceiver(t)
	f.handler.pushClient = receiver.server.Client()
	expiring, code := f.createPush(t, receiver, "old")
	f.one(t, "PushSubscription/set", map[string]any{"update": map[string]any{expiring: map[string]any{"verificationCode": code}}})
	kept, _ := f.createPush(t, receiver, "new")
	f.rewrite(t, "alice", pushPrefix+expiring, func(record map[string]any) {
		record["expires"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	})
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.handler.mu.Lock()
	running := len(f.handler.pushLoops["alice"])
	f.handler.mu.Unlock()
	if running != 0 {
		t.Fatalf("an expired subscription still delivers: %d loops", running)
	}
	var keys []string
	if err := f.accounts.WithIndex(t.Context(), "alice", func(ctx context.Context, index store.Store) error {
		var err error
		keys, err = index.Scan(ctx, stateNamespace, pushPrefix)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !sameStrings(keys, []string{pushPrefix + kept}) {
		t.Fatalf("stored subscriptions after sweep = %v", keys)
	}
	f.rewrite(t, "alice", pushPrefix, func(record map[string]any) {
		record["expires"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	})
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if keys := f.indexed(t); len(keys) != 0 {
		t.Fatalf("index after every subscription expired = %v", keys)
	}
}

func TestSweepForgetsPurgedAccountState(t *testing.T) {
	f := newFixture(t)
	f.handler.cfg.Submitter = &countingSubmitter{}
	receiver := newPushReceiver(t)
	f.handler.pushClient = receiver.server.Client()
	f.submit(t)
	id, code := f.createPush(t, receiver, "phone")
	f.one(t, "PushSubscription/set", map[string]any{"update": map[string]any{id: map[string]any{"verificationCode": code}}})
	if keys := f.indexed(t); len(keys) != 2 {
		t.Fatalf("index = %v", keys)
	}
	f.accounts.purge(t, "alice")
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if keys := f.indexed(t); len(keys) != 0 {
		t.Fatalf("index after purge = %v", keys)
	}
	f.handler.mu.Lock()
	running := len(f.handler.pushLoops)
	f.handler.mu.Unlock()
	if running != 0 {
		t.Fatalf("push loops after purge = %d", running)
	}
}

// managerAccounts opens account indexes through a real account manager.
type managerAccounts struct{ manager *account.Manager }

func (m managerAccounts) WithIndex(ctx context.Context, accountID string, fn func(context.Context, store.Store) error) error {
	generation, release, err := m.manager.Acquire(accountID)
	if err != nil {
		return err
	}
	defer release()
	return fn(ctx, generation.Index)
}

func treeContains(t *testing.T, root, needle string) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || found {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		found = bytes.Contains(data, []byte(needle))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestJMAPStateIsEncryptedAtRestAndPurgedWithTheAccount(t *testing.T) {
	f := newFixture(t)
	ringStore, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ringStore.Close() })
	ring, err := keyring.Load(t.Context(), ringStore)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	open := func() *account.Manager {
		manager, err := account.NewManager(root, store.BackendPebble, account.WithKeyRing(ring))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = manager.Close() })
		return manager
	}
	manager := open()
	if err := manager.SetEncryptionDefault(true); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	entry, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"})
	if err != nil || !entry.Manifest.Encrypted {
		t.Fatalf("encrypted account = %+v, %v", entry.Manifest, err)
	}
	f.cfg.Accounts = managerAccounts{manager}
	f.cfg.Submitter = &countingSubmitter{}
	f.restart(t)

	const canary = "push-canary-4b9e.example"
	set := args(t, f.one(t, "PushSubscription/set", map[string]any{"create": map[string]any{"p": map[string]any{"deviceClientId": "device-canary", "url": "https://" + canary + "/push"}}}), "PushSubscription/set")
	id := set["created"].(map[string]any)["p"].(map[string]any)["id"].(string)
	submission := f.submit(t)
	f.group.Stop()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if treeContains(t, entry.Path, canary) || treeContains(t, entry.Path, "device-canary") {
		t.Fatal("JMAP state is stored in plaintext in an encrypted account")
	}

	manager = open()
	f.cfg.Accounts = managerAccounts{manager}
	f.restart(t)
	if list := f.pushList(t); list[id] == nil {
		t.Fatalf("subscription after reopening the encrypted account = %#v", list)
	}
	if got := args(t, f.one(t, "EmailSubmission/get", map[string]any{"accountId": "alice", "ids": []string{submission}}), "EmailSubmission/get")["list"].([]any); len(got) != 1 {
		t.Fatalf("submission after reopening = %#v", got)
	}
	if err := manager.Purge("alice", "purge:"+entry.Manifest.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if keys := f.indexed(t); len(keys) != 0 {
		t.Fatalf("index after purge = %v", keys)
	}
	if _, err := os.Stat(entry.Path); !os.IsNotExist(err) {
		t.Fatalf("account storage after purge: %v", err)
	}
}
