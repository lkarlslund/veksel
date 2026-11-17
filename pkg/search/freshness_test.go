package search

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// freshnessFixture is a ready Pebble-backed account behind the production
// durable folder stack, with search enabled and its first build complete.
type freshnessFixture struct {
	manager  *Manager
	accounts *account.Manager
	space    *service.DurableFolderSpace
	access   service.AccessContext
}

func newFreshnessFixture(tb testing.TB, config Config) freshnessFixture {
	tb.Helper()
	return newFreshnessFixtureWith(tb, config, func(space *service.DurableFolderSpace) service.FolderSpace { return space })
}

// newFreshnessFixtureWith lets a test wrap the folder space the search
// manager reads through.
func newFreshnessFixtureWith(tb testing.TB, config Config, wrap func(*service.DurableFolderSpace) service.FolderSpace) freshnessFixture {
	tb.Helper()
	accounts, err := account.NewManager(tb.TempDir(), store.BackendPebble)
	if err != nil {
		tb.Fatal(err)
	}
	return newSearchFixture(tb, config, accounts, wrap)
}

// newSearchFixture builds the fixture on accounts, which it closes.
func newSearchFixture(tb testing.TB, config Config, accounts *account.Manager, wrap func(*service.DurableFolderSpace) service.FolderSpace) freshnessFixture {
	tb.Helper()
	ctx := context.Background()
	backend, err := pebblestore.New(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = backend.Close() })
	system := model.NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range model.Namespaces() {
		if err := system.EnsureNamespace(ctx, namespace); err != nil {
			tb.Fatal(err)
		}
	}
	if err := system.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
		tb.Fatal(err)
	}
	if err := system.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = accounts.Close() })
	user, _ := system.UserStore().Get(ctx, "alice")
	if _, _, err := accounts.Ensure(ctx, user, "alice@example.test", nil); err != nil {
		tb.Fatal(err)
	}
	engine := authz.New(system)
	routed, err := service.NewAccountFolderSpace(ctx, system, accounts, engine)
	if err != nil {
		tb.Fatal(err)
	}
	durable, err := service.NewDurableFolderSpace(ctx, backend, routed)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(durable.Close)
	manager, err := New(ctx, accounts, wrap(durable), engine, config)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = manager.Close() })
	access := service.UserAccess("alice", "test")
	waitReady(tb, manager, access, "alice")
	return freshnessFixture{manager: manager, accounts: accounts, space: durable, access: access}
}

func freshnessMessage(marker string) service.ItemInput {
	return service.ItemInput{Data: []byte("From: sender@example.test\r\nTo: alice@example.test\r\nSubject: Status " + marker + "\r\n\r\nBody text with " + marker + " inside.\r\n")}
}

// searchableAfter appends one message and returns how long it took until a
// full-text query for its unique body term returned it.
func (f freshnessFixture) searchableAfter(tb testing.TB, marker string) time.Duration {
	tb.Helper()
	started := time.Now()
	if _, err := f.space.CreateItem(context.Background(), f.access, model.InboxFolderID("alice"), freshnessMessage(marker)); err != nil {
		tb.Fatal(err)
	}
	deadline := started.Add(15 * time.Second)
	for time.Now().Before(deadline) {
		page, err := f.manager.Search(context.Background(), f.access, service.SearchQuery{Text: marker, OmitSnippets: true})
		if err != nil {
			tb.Fatal(err)
		}
		if len(page.Hits) == 1 {
			return time.Since(started)
		}
		time.Sleep(2 * time.Millisecond)
	}
	tb.Fatalf("%s was not searchable within 15s", marker)
	return 0
}

// TestNewMailIsSearchableWithinASecond pins the freshness target: a message
// appended to an idle, ready index is returned by full-text search well
// under a second later.
func TestNewMailIsSearchableWithinASecond(t *testing.T) {
	f := newFreshnessFixture(t, Config{Enabled: true, Workers: 2, BatchSize: 256, IdleClose: time.Minute})
	for n := range 3 {
		if elapsed := f.searchableAfter(t, fmt.Sprintf("freshmarker%d", n)); elapsed > time.Second {
			t.Fatalf("message %d searchable after %s, want < 1s", n, elapsed)
		}
	}
}

// TestSearchReadsItsOwnWrites covers a folder space without commit
// notifications: the first query after an append wakes the indexer and waits
// for it, so it already returns the new message. A folder-only change must
// still advance the serving checkpoint, or every later query would wait.
func TestSearchReadsItsOwnWrites(t *testing.T) {
	f := newFreshnessFixture(t, Config{Enabled: true, Workers: 1, BatchSize: 256, IdleClose: time.Minute})
	if f.manager.stopNotify != nil {
		f.manager.stopNotify()
	}
	ctx := context.Background()
	if _, err := f.space.CreateItem(ctx, f.access, model.InboxFolderID("alice"), freshnessMessage("ownwrite")); err != nil {
		t.Fatal(err)
	}
	page, err := f.manager.Search(ctx, f.access, service.SearchQuery{Text: "ownwrite", OmitSnippets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Hits) != 1 {
		t.Fatalf("first query after append returned %d hits, want 1", len(page.Hits))
	}
	if _, err := f.space.CreateFolder(ctx, f.access, "Projects", model.FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := f.manager.Search(ctx, f.access, service.SearchQuery{Text: "ownwrite", OmitSnippets: true}); err != nil {
		t.Fatal(err)
	}
	current, err := f.space.CurrentChangeState(ctx, f.access, service.ChangeScope{Object: service.ChangeObjectItem})
	if err != nil {
		t.Fatal(err)
	}
	rt := f.manager.runtime("alice")
	rt.mu.Lock()
	checkpoint := rt.state.Checkpoint
	rt.mu.Unlock()
	if checkpoint != current {
		t.Fatalf("checkpoint after folder-only change = %q, want %q", checkpoint, current)
	}
	if elapsed := time.Since(started); elapsed >= readYourWritesWait {
		t.Fatalf("query after folder-only change took %s", elapsed)
	}
}

// unlocatedItemSpace reproduces the window in which the routed account space
// has committed a new item and its journal record, and has notified commit
// listeners, but has not yet written the system-wide item location that
// GetItem resolves IDs through: while unlocated is set, GetItem reports every
// item as missing.
type unlocatedItemSpace struct {
	*service.DurableFolderSpace
	unlocated atomic.Bool
}

func (s *unlocatedItemSpace) GetItem(ctx context.Context, access service.AccessContext, itemID string) (model.Item, error) {
	if s.unlocated.Load() {
		return model.Item{}, store.ErrNotFound
	}
	return s.DurableFolderSpace.GetItem(ctx, access, itemID)
}

// TestCatchUpIndexesItemBeforeItsLocationIsVisible is the regression test for
// a message that never became searchable: catch-up woken by the commit read
// the journal record before the item location existed, took the missing item
// for a deleted one, and advanced the checkpoint past its creation, so no
// later catch-up or fallback poll revisited it.
func TestCatchUpIndexesItemBeforeItsLocationIsVisible(t *testing.T) {
	var space *unlocatedItemSpace
	f := newFreshnessFixtureWith(t, Config{Enabled: true, Workers: 1, BatchSize: 256, IdleClose: time.Minute}, func(durable *service.DurableFolderSpace) service.FolderSpace {
		space = &unlocatedItemSpace{DurableFolderSpace: durable}
		return space
	})
	ctx := context.Background()
	space.unlocated.Store(true)
	if _, err := f.space.CreateItem(ctx, f.access, model.InboxFolderID("alice"), freshnessMessage("unlocated")); err != nil {
		t.Fatal(err)
	}
	target, err := f.space.CurrentChangeState(ctx, f.access, service.ChangeScope{Object: service.ChangeObjectItem})
	if err != nil {
		t.Fatal(err)
	}
	rt := f.manager.runtime("alice")
	deadline := time.Now().Add(15 * time.Second)
	for {
		rt.mu.Lock()
		checkpoint := rt.state.Checkpoint
		rt.mu.Unlock()
		if checkpoint == target {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("checkpoint %q never reached %q", checkpoint, target)
		}
		time.Sleep(time.Millisecond)
	}
	space.unlocated.Store(false)
	page, err := f.manager.Search(ctx, f.access, service.SearchQuery{Text: "unlocated", OmitSnippets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Hits) != 1 {
		t.Fatalf("item applied before its location was visible: %d hits, want 1", len(page.Hits))
	}
}

// BenchmarkAppendToSearchable reports the time from one append to the
// message being returned by a body-term search.
func BenchmarkAppendToSearchable(b *testing.B) {
	f := newFreshnessFixture(b, Config{Enabled: true, Workers: 2, BatchSize: 256, IdleClose: time.Hour})
	var total time.Duration
	b.ResetTimer()
	for n := range b.N {
		total += f.searchableAfter(b, fmt.Sprintf("benchmarker%d", n))
	}
	b.ReportMetric(float64(total.Milliseconds())/float64(b.N), "ms/searchable")
}

// BenchmarkAppendToIndexed reports the time from one append to the
// background indexer committing it, without any query waiting for it.
func BenchmarkAppendToIndexed(b *testing.B) {
	f := newFreshnessFixture(b, Config{Enabled: true, Workers: 2, BatchSize: 256, IdleClose: time.Hour})
	rt := f.manager.runtime("alice")
	var total time.Duration
	b.ResetTimer()
	for n := range b.N {
		started := time.Now()
		item, err := f.space.CreateItem(context.Background(), f.access, model.InboxFolderID("alice"), freshnessMessage(fmt.Sprintf("indexmarker%d", n)))
		if err != nil {
			b.Fatal(err)
		}
		_ = item
		target, err := f.space.CurrentChangeState(context.Background(), f.access, service.ChangeScope{Object: service.ChangeObjectItem})
		if err != nil {
			b.Fatal(err)
		}
		for {
			rt.mu.Lock()
			done := rt.state.Checkpoint == target
			rt.mu.Unlock()
			if done {
				break
			}
			if time.Since(started) > 15*time.Second {
				b.Fatal("append was not indexed within 15s")
			}
			time.Sleep(time.Millisecond)
		}
		total += time.Since(started)
	}
	b.ReportMetric(float64(total.Microseconds())/1000/float64(b.N), "ms/indexed")
}

// BenchmarkBacklogCatchUp measures pure catch-up throughput: 5000 messages
// are appended while indexing is paused, and the benchmark times how long
// the resumed indexer takes to apply the backlog.
func BenchmarkBacklogCatchUp(b *testing.B) {
	const total, chunk = 5000, 250
	for range b.N {
		b.StopTimer()
		config := Config{Enabled: true, Workers: 2, BatchSize: 256, IdleClose: time.Hour}
		f := newFreshnessFixture(b, config)
		paused := config
		paused.Enabled = false
		if err := f.manager.Reconfigure(paused); err != nil {
			b.Fatal(err)
		}
		for first := 0; first < total; first += chunk {
			inputs := make([]service.ItemInput, 0, chunk)
			for n := first; n < first+chunk; n++ {
				inputs = append(inputs, freshnessMessage(fmt.Sprintf("backlogmarker%d", n)))
			}
			if _, err := f.space.CreateItems(context.Background(), f.access, model.InboxFolderID("alice"), inputs); err != nil {
				b.Fatal(err)
			}
		}
		target, err := f.space.CurrentChangeState(context.Background(), f.access, service.ChangeScope{Object: service.ChangeObjectItem})
		if err != nil {
			b.Fatal(err)
		}
		rt := f.manager.runtime("alice")
		b.StartTimer()
		started := time.Now()
		if err := f.manager.Reconfigure(config); err != nil {
			b.Fatal(err)
		}
		for {
			rt.mu.Lock()
			done := rt.state.Checkpoint == target
			rt.mu.Unlock()
			if done {
				break
			}
			if time.Since(started) > 2*time.Minute {
				b.Fatal("backlog was not indexed within 2 minutes")
			}
			time.Sleep(time.Millisecond)
		}
		elapsed := time.Since(started)
		b.ReportMetric(elapsed.Seconds(), "s/indexed")
		b.ReportMetric(total/elapsed.Seconds(), "msgs/s")
	}
}

// BenchmarkBulkCatchUp appends 5000 messages to a ready index, 50 per
// atomic batch, and reports the time until the last one is searchable.
func BenchmarkBulkCatchUp(b *testing.B) {
	const total, chunk = 5000, 50
	for range b.N {
		b.StopTimer()
		f := newFreshnessFixture(b, Config{Enabled: true, Workers: 2, BatchSize: 256, IdleClose: time.Hour})
		b.StartTimer()
		started := time.Now()
		for first := 0; first < total; first += chunk {
			inputs := make([]service.ItemInput, 0, chunk)
			for n := first; n < first+chunk; n++ {
				inputs = append(inputs, freshnessMessage(fmt.Sprintf("bulkmarker%d", n)))
			}
			if _, err := f.space.CreateItems(context.Background(), f.access, model.InboxFolderID("alice"), inputs); err != nil {
				b.Fatal(err)
			}
		}
		appended := time.Since(started)
		last := service.SearchQuery{Text: fmt.Sprintf("bulkmarker%d", total-1), OmitSnippets: true}
		for {
			page, err := f.manager.Search(context.Background(), f.access, last)
			if err != nil {
				b.Fatal(err)
			}
			if len(page.Hits) == 1 {
				break
			}
			if time.Since(started) > 2*time.Minute {
				b.Fatal("bulk append was not searchable within 2 minutes")
			}
			time.Sleep(5 * time.Millisecond)
		}
		elapsed := time.Since(started)
		b.ReportMetric(appended.Seconds(), "s/append")
		b.ReportMetric(elapsed.Seconds(), "s/searchable")
		b.ReportMetric(total/elapsed.Seconds(), "msgs/s")
	}
}
