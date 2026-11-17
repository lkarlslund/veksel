package folderindex

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// gatedSpace serves one item per folder and records every enumeration; an
// enumeration of a gated folder blocks until its gate closes.
type gatedSpace struct {
	service.FolderSpace
	mu      sync.Mutex
	folders map[string]model.Folder
	gates   map[string]chan struct{}
	built   []string
}

func newGatedSpace(owners map[string]string) *gatedSpace {
	space := &gatedSpace{folders: make(map[string]model.Folder), gates: make(map[string]chan struct{})}
	for id, owner := range owners {
		space.folders[id] = model.Folder{ID: id, UserID: owner, HighestModSeq: 1, ItemCount: 1, Indexes: []model.FolderIndex{{Name: "test-name", Version: 3}}}
	}
	return space
}

func (s *gatedSpace) GetFolder(_ context.Context, _ service.AccessContext, id string) (model.Folder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.folders[id], nil
}

func (s *gatedSpace) ListItemPage(_ context.Context, _ service.AccessContext, folderID string, _ service.ItemPageQuery) (service.ItemPage, error) {
	s.mu.Lock()
	s.built = append(s.built, folderID)
	gate := s.gates[folderID]
	s.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return service.ItemPage{Items: []model.Item{{ID: folderID + "-item", Name: folderID}}}, nil
}

func (s *gatedSpace) gate(folderID string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	gate := make(chan struct{})
	s.gates[folderID] = gate
	return gate
}

func (s *gatedSpace) builds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.built)
}

func newBuilderIndex(t *testing.T, workers int) (*Index, *Builder) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	index := New(backend)
	builder := NewBuilder(t.Context(), workers)
	index.SetBuilder(builder)
	return index, builder
}

func TestInteractiveSnapshotDefersRebuildAndAnnouncesReadiness(t *testing.T) {
	index, builder := newBuilderIndex(t, 2)
	space := newGatedSpace(map[string]string{"inbox": "alice"})
	gate := space.gate("inbox")
	folder := space.folders["inbox"]
	type readiness struct {
		documents int
		waiters   []service.AccessContext
	}
	ready := make(chan readiness, 4)
	build := Build{Priority: PriorityViewed, Ready: func(_ model.Folder, snapshot *Snapshot, waiters []service.AccessContext) {
		ready <- readiness{documents: len(snapshot.Buckets["all"]), waiters: waiters}
	}}
	alice, delegate := service.UserAccess("alice", "test"), service.UserAccess("bob", "test")
	used := false
	use := func(*Snapshot) error { used = true; return nil }

	started := time.Now()
	if err := index.WithBuiltSnapshot(t.Context(), space, alice, folder, testDefinition{}, build, use); !errors.Is(err, ErrBuilding) {
		t.Fatalf("missing projection err=%v, want ErrBuilding", err)
	}
	// The build now holds the entry lock inside the gated enumeration; a
	// second interactive query must not wait for it.
	for len(space.builds()) == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := index.WithBuiltSnapshot(t.Context(), space, delegate, folder, testDefinition{}, build, use); !errors.Is(err, ErrBuilding) {
		t.Fatalf("query during build err=%v, want ErrBuilding", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second || used {
		t.Fatalf("interactive queries waited %v for the build (used=%v)", elapsed, used)
	}
	close(gate)
	builder.Wait()
	select {
	case got := <-ready:
		if got.documents != 1 || len(got.waiters) != 2 || got.waiters[0] != alice || got.waiters[1] != delegate {
			t.Fatalf("readiness=%+v, want one document and both waiters", got)
		}
	default:
		t.Fatal("background build did not announce readiness")
	}
	if err := index.WithBuiltSnapshot(t.Context(), space, alice, folder, testDefinition{}, build, use); err != nil || !used {
		t.Fatalf("built projection err=%v used=%v", err, used)
	}
	if builds := space.builds(); len(builds) != 1 {
		t.Fatalf("builds=%v, want one merged build", builds)
	}
	if len(ready) != 0 {
		t.Fatal("a current projection must not announce readiness again")
	}
}

func TestBuilderMergesRequestsAndRunsMostUrgentFirst(t *testing.T) {
	index, builder := newBuilderIndex(t, 1)
	space := newGatedSpace(map[string]string{"busy": "zed", "archive": "alice", "notes": "alice", "inbox": "alice"})
	gate := space.gate("busy")
	access := service.UserAccess("alice", "test")
	schedule := func(id string, priority Priority) {
		t.Helper()
		if err := index.Schedule(space, access, space.folders[id], testDefinition{}, Build{Priority: priority}); err != nil {
			t.Fatal(err)
		}
	}
	schedule("busy", PriorityWarm)
	for len(space.builds()) == 0 {
		time.Sleep(time.Millisecond)
	}
	schedule("archive", PriorityWarm)
	schedule("notes", PriorityFolder)
	schedule("inbox", PriorityViewed)
	schedule("archive", PriorityInbox)
	close(gate)
	builder.Wait()
	if got, want := space.builds(), []string{"busy", "inbox", "archive", "notes"}; !slices.Equal(got, want) {
		t.Fatalf("build order=%v, want %v", got, want)
	}
}

func TestBuilderRunsOneBuildPerAccount(t *testing.T) {
	index, builder := newBuilderIndex(t, 2)
	space := newGatedSpace(map[string]string{"zed-inbox": "zed", "zed-sent": "zed", "alice-inbox": "alice"})
	gate := space.gate("zed-inbox")
	built := make(chan string, 4)
	build := func(priority Priority) Build {
		return Build{Priority: priority, Ready: func(folder model.Folder, _ *Snapshot, _ []service.AccessContext) { built <- folder.ID }}
	}
	access := service.UserAccess("zed", "test")
	if err := index.Schedule(space, access, space.folders["zed-inbox"], testDefinition{}, build(PriorityWarm)); err != nil {
		t.Fatal(err)
	}
	for len(space.builds()) == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := index.Schedule(space, access, space.folders["zed-sent"], testDefinition{}, build(PriorityViewed)); err != nil {
		t.Fatal(err)
	}
	if err := index.Schedule(space, access, space.folders["alice-inbox"], testDefinition{}, build(PriorityWarm)); err != nil {
		t.Fatal(err)
	}
	// The second worker serves alice while zed's mailbox is busy, even
	// though zed's queued folder is more urgent.
	select {
	case id := <-built:
		if id != "alice-inbox" {
			t.Fatalf("first finished build %q, want alice-inbox", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("another account's build waited behind a busy mailbox")
	}
	close(gate)
	builder.Wait()
	if got, want := space.builds(), []string{"zed-inbox", "alice-inbox", "zed-sent"}; !slices.Equal(got, want) {
		t.Fatalf("build order=%v, want %v", got, want)
	}
}
