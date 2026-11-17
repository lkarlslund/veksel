package service

import (
	"errors"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestConditionalItemUpdateIsAtomicThroughDurableAndCacheWrappers(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	durable, err := NewDurableFolderSpace(t.Context(), ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	cached := NewCachedFolderSpace(durable, FolderCacheConfig{})
	access := UserAccess("alice", "conditional-test")
	created, err := cached.CreateItem(t.Context(), access, model.FolderKey("alice", "Files"), ItemInput{Name: "document.txt", Data: []byte("one")})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := cached.UpdateItemIfModSeq(t.Context(), access, created.ID, created.ModSeq, []byte("two"), map[string]string{"Content-Type": "text/plain"})
	if err != nil || updated.ModSeq <= created.ModSeq || string(updated.Data) != "two" {
		t.Fatalf("conditional update = %+v, %v", updated, err)
	}
	if _, err := cached.UpdateItemIfModSeq(t.Context(), access, created.ID, created.ModSeq, []byte("stale"), nil); !errors.Is(err, ErrItemUpdateConflict) {
		t.Fatalf("stale update error = %v", err)
	}
	stored, err := cached.GetItem(t.Context(), access, created.ID)
	if err != nil || string(stored.Data) != "two" || stored.ModSeq != updated.ModSeq {
		t.Fatalf("stale update changed item = %+v, %v", stored, err)
	}
}

func TestExclusiveItemCreationAllowsOneConcurrentWinner(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	durable, err := NewDurableFolderSpace(t.Context(), ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "exclusive-test")
	folderID := model.FolderKey("alice", "Files")
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, data := range []string{"one", "two"} {
		data := data
		go func() {
			ready.Done()
			<-start
			_, err := durable.CreateItemIfAbsent(t.Context(), access, folderID, ItemInput{Name: "same.txt", Data: []byte(data)})
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	succeeded, conflicted := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, store.ErrExists):
			conflicted++
		default:
			t.Fatalf("unexpected create result: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("create outcomes: succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func TestConditionalDurableCommandReplayIsIdempotent(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	durable, err := NewDurableFolderSpace(t.Context(), ts.Store(), base)
	if err != nil {
		t.Fatal(err)
	}
	access := UserAccess("alice", "replay-test")
	created, err := base.CreateItem(t.Context(), access, model.FolderKey("alice", "Files"), ItemInput{Name: "replay.txt", Data: []byte("one")})
	if err != nil {
		t.Fatal(err)
	}
	command := folderCommand{ID: "conditional-replay", Operation: "update-item-if-modseq", Access: access, ItemID: created.ID, ExpectedModSeq: created.ModSeq, Data: []byte("two"), Headers: map[string]string{"Content-Type": "text/plain"}}
	first, err := durable.apply(t.Context(), command, false)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := durable.apply(t.Context(), command, true)
	if err != nil || replayed.Item.ID != first.Item.ID || replayed.Item.ModSeq != first.Item.ModSeq || string(replayed.Item.Data) != "two" {
		t.Fatalf("replayed conditional update = %+v, %v; first=%+v", replayed.Item, err, first.Item)
	}
}
