package folderindex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type testDefinition struct{}

func (testDefinition) Name() string { return "test-name" }
func (testDefinition) Version() int { return 3 }
func (testDefinition) Project(item model.Item) (Document, error) {
	raw, _ := json.Marshal(item.Name)
	return Document{ItemID: item.ID, Keys: []string{"all"}, Value: raw}, nil
}

type testSpace struct {
	service.FolderSpace
	folder model.Folder
	items  []model.Item
	pages  int
}

type checkpointSpace struct {
	*testSpace
	current string
}

func (s *checkpointSpace) CurrentChangeState(context.Context, service.AccessContext, service.ChangeScope) (string, error) {
	return s.current, nil
}

func (s *checkpointSpace) ListChanges(context.Context, service.AccessContext, service.ChangeScope, string, int) (service.ChangePage, error) {
	return service.ChangePage{NewState: s.current, CurrentState: s.current}, nil
}

func (s *testSpace) GetFolder(context.Context, service.AccessContext, string) (model.Folder, error) {
	return s.folder, nil
}
func (s *testSpace) ListItemPage(context.Context, service.AccessContext, string, service.ItemPageQuery) (service.ItemPage, error) {
	s.pages++
	return service.ItemPage{Items: s.items}, nil
}

func TestIndexRequiresAttachedFolderCapabilityAndReusesProjection(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	space := &testSpace{folder: model.Folder{ID: "folder", HighestModSeq: 1, ItemCount: 1}, items: []model.Item{{ID: "item", Name: "value"}}}
	index := New(backend)
	access := service.UserAccess("alice", "test")
	err = index.WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(*Snapshot) error { return nil })
	if !errors.Is(err, ErrIndexNotAttached) {
		t.Fatalf("without attachment error=%v", err)
	}
	space.folder.Indexes = []model.FolderIndex{{Name: "test-name", Version: 3}}
	err = index.WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(snapshot *Snapshot) error {
		if len(snapshot.Buckets["all"]) != 1 {
			t.Fatalf("documents=%d", len(snapshot.Buckets["all"]))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	space.pages = 0
	if err := New(backend).WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(*Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if space.pages != 0 {
		t.Fatalf("warm index rebuilt with %d pages", space.pages)
	}
	// A new value revision rebuilds under the same attachment version.
	if err := New(backend).WithSnapshot(t.Context(), space, access, space.folder, revisedDefinition{}, func(*Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if space.pages != 1 {
		t.Fatalf("revised definition reused a stale projection (%d pages)", space.pages)
	}
}

type revisedDefinition struct{ testDefinition }

func (revisedDefinition) Revision() int { return 2 }

func TestWarmIndexAdvancesCheckpointPastUnrelatedAccountChanges(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	base := &testSpace{
		folder: model.Folder{ID: "calendar", HighestModSeq: 1, ItemCount: 1, Indexes: []model.FolderIndex{{Name: "test-name", Version: 3}}},
		items:  []model.Item{{ID: "event", Name: "value"}},
	}
	space := &checkpointSpace{testSpace: base, current: "c1.1"}
	index := New(backend)
	access := service.UserAccess("alice", "test")
	if err := index.WithSnapshot(t.Context(), space, access, base.folder, testDefinition{}, func(*Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	space.current = "c1.zz"
	if err := index.WithSnapshot(t.Context(), space, access, base.folder, testDefinition{}, func(snapshot *Snapshot) error {
		if snapshot.Checkpoint != space.current {
			t.Fatalf("checkpoint=%q, want journal head %q", snapshot.Checkpoint, space.current)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if base.pages != 1 {
		t.Fatalf("unchanged folder enumerated %d times, want initial build only", base.pages)
	}
}

func TestSnapshotCacheDiscardsFailedChangesAndStaysBounded(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	indexes := []model.FolderIndex{{Name: "test-name", Version: 3}}
	space := &testSpace{folder: model.Folder{ID: "folder", HighestModSeq: 1, ItemCount: 1, Indexes: indexes}, items: []model.Item{{ID: "item", Name: "value"}}}
	index := New(backend)
	access := service.UserAccess("alice", "test")
	if err := index.WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(*Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("callback failed")
	err = index.WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(snapshot *Snapshot) error {
		decoded, err := DecodeValue[string](&snapshot.Buckets["all"][0])
		if err != nil || decoded != "value" {
			t.Fatalf("decoded=%q err=%v", decoded, err)
		}
		snapshot.Buckets["all"] = nil
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatalf("err=%v, want callback failure", err)
	}
	if err := index.WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(snapshot *Snapshot) error {
		if len(snapshot.Buckets["all"]) != 1 {
			t.Fatalf("failed callback leaked into the cached snapshot: %d documents", len(snapshot.Buckets["all"]))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if space.pages != 1 {
		t.Fatalf("pages=%d, want the stored projection reused", space.pages)
	}

	for n := range maxCachedSnapshots + 5 {
		folder := model.Folder{ID: fmt.Sprintf("folder-%d", n), HighestModSeq: 1, ItemCount: 1, Indexes: indexes}
		if err := index.WithSnapshot(t.Context(), space, access, folder, testDefinition{}, func(*Snapshot) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	cached := 0
	for _, entry := range index.entries {
		if entry.cached.Load() != nil {
			cached++
		}
	}
	if cached != maxCachedSnapshots {
		t.Fatalf("cached snapshots=%d, want %d", cached, maxCachedSnapshots)
	}
	if index.entries["test-name\x00folder"].cached.Load() != nil {
		t.Fatal("least recently used snapshot was not evicted")
	}
}
