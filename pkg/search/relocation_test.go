package search

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// TestWriteIndexFaultsOnVanishedDirectoryInsteadOfPanicking pins the Scorch
// behaviour behind the disaster-recovery crash: once a batch cannot be
// persisted, Scorch closes that batch's in-memory segment although the index
// root still serves it, and the next batch on the handle panics with
// "assignment to entry in nil map" in zapx. writeIndex must report both as
// faults instead of letting the panic escape.
func TestWriteIndexFaultsOnVanishedDirectoryInsteadOfPanicking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account", "idx")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	idx, err := bleve.New(path, indexMapping())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guardIndex("close", idx.Close) }()
	batch := idx.NewBatch()
	for n := range 10 {
		if err := batch.Index(fmt.Sprint("doc", n), map[string]any{"subject": "hello world"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeIndex(idx, batch); err != nil {
		t.Fatal(err)
	}
	// An account move renames the account directory under the open index.
	if err := os.Rename(filepath.Join(dir, "account"), filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	for round := range 3 {
		batch = idx.NewBatch()
		if err := batch.Index(fmt.Sprint("late", round), map[string]any{"subject": "hello again"}); err != nil {
			t.Fatal(err)
		}
		if err := writeIndex(idx, batch); !errors.Is(err, errIndexFault) {
			t.Fatalf("round %d: write to vanished index = %v, want an index fault", round, err)
		}
	}
}

// TestServingIndexWriteFaultIsQuarantinedAndRebuilt covers a serving index
// whose storage disappears while it is open: catch-up must neither crash nor
// keep using the handle, and search must recover through a rebuild.
func TestServingIndexWriteFaultIsQuarantinedAndRebuilt(t *testing.T) {
	f := newFreshnessFixture(t, Config{Enabled: true, Workers: 2, BatchSize: 64, IdleClose: time.Minute})
	f.searchableAfter(t, "beforefault")
	status, err := f.manager.SearchStatus(t.Context(), f.access, "alice")
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := f.accounts.ByLogin("alice")
	indexPath := filepath.Join(entry.Path, "search", "indexes", status.ServingIndexID)
	if err := os.Rename(indexPath, filepath.Join(t.TempDir(), "gone")); err != nil {
		t.Fatal(err)
	}
	for n := range 3 {
		if _, err := f.space.CreateItem(t.Context(), f.access, model.InboxFolderID("alice"), freshnessMessage(fmt.Sprintf("afterfault%d", n))); err != nil {
			t.Fatal(err)
		}
	}
	recovered := waitRecovered(t, f.manager, f.access, "alice", status.ServingIndexID)
	if recovered.ServingIndexID == status.ServingIndexID {
		t.Fatalf("faulted index %s is still serving", status.ServingIndexID)
	}
	for _, marker := range []string{"beforefault", "afterfault0", "afterfault2"} {
		waitHits(t, f.manager, f.access, service.SearchQuery{Text: marker, OmitSnippets: true}, 1)
	}
}

// TestAccountMoveDuringDeliveryKeepsSearchServing reproduces the drill: the
// account moves to another storage root while mail is delivered and searched
// concurrently. Search must release the index before the directory is renamed,
// carry it to the new root, and keep indexing there.
func TestAccountMoveDuringDeliveryKeepsSearchServing(t *testing.T) {
	base := t.TempDir()
	accounts, err := account.NewManagerWithRoots([]account.Root{
		{ID: "fast", Path: filepath.Join(base, "fast")}, {ID: "bulk", Path: filepath.Join(base, "bulk")},
	}, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	f := newSearchFixture(t, Config{Enabled: true, Workers: 2, BatchSize: 16, IdleClose: time.Minute}, accounts, func(space *service.DurableFolderSpace) service.FolderSpace { return space })
	f.searchableAfter(t, "beforemove")
	before, err := f.manager.SearchStatus(t.Context(), f.access, "alice")
	if err != nil {
		t.Fatal(err)
	}
	source, _ := accounts.ByLogin("alice")

	ctx, stop := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	var delivered atomic.Int64
	for worker := range 3 {
		wg.Go(func() {
			for n := 0; ctx.Err() == nil; n++ {
				// Deliveries fail while the account is fenced for the move.
				if _, err := f.space.CreateItem(ctx, f.access, model.InboxFolderID("alice"), freshnessMessage(fmt.Sprintf("during%dx%d", worker, n))); err == nil {
					delivered.Add(1)
				}
			}
		})
	}
	wg.Go(func() {
		for ctx.Err() == nil {
			_, _ = f.manager.Search(ctx, f.access, service.SearchQuery{Text: "body", OmitSnippets: true})
		}
	})
	time.Sleep(50 * time.Millisecond)
	moved, _, moveErr := accounts.Move(t.Context(), "alice", "bulk")
	time.Sleep(50 * time.Millisecond)
	stop()
	wg.Wait()
	if moveErr != nil {
		t.Fatalf("move: %v", moveErr)
	}
	if moved.Path == source.Path {
		t.Fatalf("account did not move from %s", source.Path)
	}
	if delivered.Load() == 0 {
		t.Fatal("no message was delivered during the test")
	}

	waitReady(t, f.manager, f.access, "alice")
	f.searchableAfter(t, "aftermove")
	waitHits(t, f.manager, f.access, service.SearchQuery{Text: "beforemove", OmitSnippets: true}, 1)
	after, err := f.manager.SearchStatus(t.Context(), f.access, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if after.ServingIndexID != before.ServingIndexID {
		t.Fatalf("index was rebuilt instead of carried over the move: %s -> %s", before.ServingIndexID, after.ServingIndexID)
	}
	if _, err := os.Stat(filepath.Join(moved.Path, "search", "indexes", after.ServingIndexID)); err != nil {
		t.Fatalf("serving index is not under the moved account: %v", err)
	}
	if _, err := os.Stat(source.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("search recreated the account directory the move left: %v", err)
	}
}

// TestRelocationClosesIndexAndBlocksUseUntilFinished checks the observer
// contract directly: while an account is relocating its index is closed and
// neither queries nor catch-up reopen it.
func TestRelocationClosesIndexAndBlocksUseUntilFinished(t *testing.T) {
	f := newFreshnessFixture(t, Config{Enabled: true, Workers: 2, BatchSize: 64, IdleClose: time.Minute})
	f.searchableAfter(t, "relocating")
	entry, _ := f.accounts.ByLogin("alice")
	f.manager.AccountRelocating("alice", entry.Path)
	rt := f.manager.runtime("alice")
	rt.mu.Lock()
	open, building := rt.index != nil, rt.building
	rt.mu.Unlock()
	if open || building {
		t.Fatalf("relocating account keeps index open=%v building=%v", open, building)
	}
	if _, err := f.manager.Search(t.Context(), f.access, service.SearchQuery{Text: "relocating", OmitSnippets: true}); !errors.Is(err, service.ErrSearchUnavailable) {
		t.Fatalf("search while relocating = %v, want unavailable", err)
	}
	if _, err := f.space.CreateItem(t.Context(), f.access, model.InboxFolderID("alice"), freshnessMessage("whilemoving")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	rt.mu.Lock()
	open = rt.index != nil
	rt.mu.Unlock()
	if open {
		t.Fatal("catch-up reopened the index of a relocating account")
	}
	f.manager.AccountRelocated("alice", entry.Path, "")
	waitHits(t, f.manager, f.access, service.SearchQuery{Text: "whilemoving", OmitSnippets: true}, 1)
}
