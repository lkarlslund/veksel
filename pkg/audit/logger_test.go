package audit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func testLogger(t *testing.T) *Logger {
	t.Helper()
	dir := t.TempDir()
	s, err := jsonstore.New(dir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()
	if err := ts.EnsureNamespace(ctx, Namespace); err != nil {
		t.Fatalf("ensure namespace: %v", err)
	}
	return New(ts)
}

func TestLogAndQuery(t *testing.T) {
	l := testLogger(t)

	// Log some entries
	l.Log("admin", "user.create", "alice", nil)
	l.Log("admin", "domain.create", "example.com", nil)
	l.Log("admin", "user.delete", "bob", map[string]string{"reason": "test"})

	// Query all entries
	entries, err := l.Query(context.Background(), time.Time{}, "", "", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify chronological order
	if entries[0].Action != "user.create" {
		t.Errorf("first entry action = %q, want %q", entries[0].Action, "user.create")
	}
	if entries[2].Action != "user.delete" {
		t.Errorf("last entry action = %q, want %q", entries[2].Action, "user.delete")
	}
}

func TestQueryReverse(t *testing.T) {
	l := testLogger(t)

	l.Log("admin", "user.create", "alice", nil)
	l.Log("admin", "domain.create", "example.com", nil)
	l.Log("admin", "user.delete", "bob", nil)

	entries, err := l.QueryReverse(context.Background(), time.Time{}, "", "", 10)
	if err != nil {
		t.Fatalf("query reverse: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify reverse chronological order
	if entries[0].Action != "user.delete" {
		t.Errorf("first entry action = %q, want %q", entries[0].Action, "user.delete")
	}
	if entries[2].Action != "user.create" {
		t.Errorf("last entry action = %q, want %q", entries[2].Action, "user.create")
	}
}

func TestQueryReversePageUsesExclusiveStableCursor(t *testing.T) {
	l := testLogger(t)
	for i := 1; i <= 7; i++ {
		l.Log("admin", "event", fmt.Sprintf("target-%d", i), nil)
	}

	first, err := l.QueryReversePage(context.Background(), 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 7 || first.NextBefore != 5 || sequences(first.Entries) != "7,6,5" {
		t.Fatalf("first page = %+v", first)
	}

	// A later append must not shift or duplicate the continuation page.
	l.Log("admin", "event", "target-8", nil)
	second, err := l.QueryReversePage(context.Background(), first.NextBefore, 3)
	if err != nil {
		t.Fatal(err)
	}
	if second.Total != 8 || second.NextBefore != 2 || sequences(second.Entries) != "4,3,2" {
		t.Fatalf("second page = %+v", second)
	}
	last, err := l.QueryReversePage(context.Background(), second.NextBefore, 3)
	if err != nil {
		t.Fatal(err)
	}
	if last.NextBefore != 0 || sequences(last.Entries) != "1" {
		t.Fatalf("last page = %+v", last)
	}
}

func sequences(entries []Entry) string {
	values := make([]string, len(entries))
	for i, entry := range entries {
		values[i] = strconv.FormatInt(entry.Sequence, 10)
	}
	return strings.Join(values, ",")
}

func TestQueryFilterByAction(t *testing.T) {
	l := testLogger(t)

	l.Log("admin", "user.create", "alice", nil)
	l.Log("admin", "domain.create", "example.com", nil)
	l.Log("admin", "user.create", "bob", nil)

	entries, err := l.Query(context.Background(), time.Time{}, "user.create", "", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Action != "user.create" {
			t.Errorf("entry action = %q, want %q", e.Action, "user.create")
		}
	}
}

func TestQueryFilterByActor(t *testing.T) {
	l := testLogger(t)

	l.Log("admin", "user.create", "alice", nil)
	l.Log("api_user", "user.delete", "bob", nil)
	l.Log("admin", "domain.create", "example.com", nil)

	entries, err := l.Query(context.Background(), time.Time{}, "", "admin", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Actor != "admin" {
			t.Errorf("entry actor = %q, want %q", e.Actor, "admin")
		}
	}
}

func TestQueryFilterBySince(t *testing.T) {
	l := testLogger(t)

	l.Log("admin", "user.create", "alice", nil)
	time.Sleep(10 * time.Millisecond)
	mid := time.Now().UTC()
	time.Sleep(10 * time.Millisecond)
	l.Log("admin", "domain.create", "example.com", nil)

	entries, err := l.Query(context.Background(), mid, "", "", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "domain.create" {
		t.Errorf("entry action = %q, want %q", entries[0].Action, "domain.create")
	}
}

func TestQueryLimit(t *testing.T) {
	l := testLogger(t)

	for i := 0; i < 10; i++ {
		l.Log("admin", "user.create", "user", nil)
	}

	entries, err := l.Query(context.Background(), time.Time{}, "", "", 3)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func TestCount(t *testing.T) {
	l := testLogger(t)

	count, err := l.Count(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries, got %d", count)
	}

	l.Log("admin", "user.create", "alice", nil)
	l.Log("admin", "domain.create", "example.com", nil)

	count, err = l.Count(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 entries, got %d", count)
	}
}

func TestGetActionList(t *testing.T) {
	l := testLogger(t)

	l.Log("admin", "user.create", "alice", nil)
	l.Log("admin", "domain.create", "example.com", nil)
	l.Log("admin", "user.create", "bob", nil)

	actions, err := l.GetActionList(context.Background())
	if err != nil {
		t.Fatalf("get action list: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}
	actionSet := make(map[string]struct{})
	for _, a := range actions {
		actionSet[a] = struct{}{}
	}
	if _, ok := actionSet["user.create"]; !ok {
		t.Error("missing user.create in action list")
	}
	if _, ok := actionSet["domain.create"]; !ok {
		t.Error("missing domain.create in action list")
	}
}

func TestGetActorList(t *testing.T) {
	l := testLogger(t)

	l.Log("admin", "user.create", "alice", nil)
	l.Log("api_user", "user.delete", "bob", nil)

	actors, err := l.GetActorList(context.Background())
	if err != nil {
		t.Fatalf("get actor list: %v", err)
	}
	if len(actors) != 2 {
		t.Fatalf("expected 2 actors, got %d", len(actors))
	}
	actorSet := make(map[string]struct{})
	for _, a := range actors {
		actorSet[a] = struct{}{}
	}
	if _, ok := actorSet["admin"]; !ok {
		t.Error("missing admin in actor list")
	}
	if _, ok := actorSet["api_user"]; !ok {
		t.Error("missing api_user in actor list")
	}
}

// batchRecordingStore counts batches and Sets issued outside one.
type batchRecordingStore struct {
	store.Store
	batches       int
	unbatchedSets int
}

func (s *batchRecordingStore) Set(ctx context.Context, namespace, key string, value []byte) error {
	if !store.InBatch(ctx, s) {
		s.unbatchedSets++
	}
	return s.Store.Set(ctx, namespace, key, value)
}

func (s *batchRecordingStore) Batch(ctx context.Context, fn func(context.Context) error) error {
	s.batches++
	return s.Store.(store.Batcher).Batch(ctx, fn)
}

func TestLogCommitsEntryAndSequenceTogether(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	recorder := &batchRecordingStore{Store: backend}
	l := New(model.NewTypedStore(recorder, store.BackendJSON))

	l.Log("admin", "user.create", "alice", nil)

	if recorder.batches != 1 || recorder.unbatchedSets != 0 {
		t.Fatalf("batches = %d, unbatched sets = %d; want 1 and 0", recorder.batches, recorder.unbatchedSets)
	}
	var seq int64
	if err := l.ts.Get(context.Background(), Namespace, "_seq", &seq); err != nil || seq != 1 {
		t.Fatalf("sequence = %d, %v; want 1", seq, err)
	}
	if count, err := l.Count(context.Background()); err != nil || count != 1 {
		t.Fatalf("count = %d, %v; want 1", count, err)
	}
}

func TestSequenceMonotonic(t *testing.T) {
	l := testLogger(t)

	for i := 0; i < 5; i++ {
		l.Log("admin", "test", "target", nil)
	}

	entries, err := l.Query(context.Background(), time.Time{}, "", "", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].Sequence <= entries[i-1].Sequence {
			t.Errorf("sequence not monotonic: %d <= %d", entries[i].Sequence, entries[i-1].Sequence)
		}
	}
}

func TestDetailsPreserved(t *testing.T) {
	l := testLogger(t)

	details := map[string]string{
		"ip":     "192.168.1.1",
		"reason": "test",
		"method": "POST",
	}
	l.Log("admin", "admin.login", "admin_ui", details)

	entries, err := l.Query(context.Background(), time.Time{}, "", "", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	for k, v := range details {
		if e.Details[k] != v {
			t.Errorf("details[%q] = %q, want %q", k, e.Details[k], v)
		}
	}
}

func TestLoadSequence(t *testing.T) {
	l := testLogger(t)

	// Log some entries
	for i := 0; i < 5; i++ {
		l.Log("admin", "test", "target", nil)
	}

	// Create a new logger (simulates restart) — should pick up sequence
	l2 := New(l.ts)
	l2.Log("admin", "after_restart", "target", nil)

	entries, err := l2.Query(context.Background(), time.Time{}, "", "", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 6 {
		t.Fatalf("expected 6 entries, got %d", len(entries))
	}
	// The last entry should have sequence 6
	if entries[5].Sequence != 6 {
		t.Errorf("last entry sequence = %d, want 6", entries[5].Sequence)
	}
}

func TestQueryCombinedFilters(t *testing.T) {
	l := testLogger(t)

	l.Log("admin", "user.create", "alice", nil)
	l.Log("api_user", "user.create", "bob", nil)
	l.Log("admin", "domain.create", "example.com", nil)
	l.Log("admin", "user.delete", "charlie", nil)

	// Filter by both action and actor
	entries, err := l.Query(context.Background(), time.Time{}, "user.create", "admin", 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Target != "alice" {
		t.Errorf("target = %q, want %q", entries[0].Target, "alice")
	}
}
