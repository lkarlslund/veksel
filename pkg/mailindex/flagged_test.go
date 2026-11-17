package mailindex

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func flaggedIDs(t testing.TB, index *Index, space service.FolderSpace, access service.AccessContext, folderID string) []string {
	t.Helper()
	folder, err := space.GetFolder(t.Context(), access, folderID)
	if err != nil {
		t.Fatal(err)
	}
	summaries, err := index.Flagged(t.Context(), space, access, folder)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(summaries))
	for _, summary := range summaries {
		ids = append(ids, summary.ID)
	}
	return ids
}

func TestFlaggedFollowsFlagMoveAndDelete(t *testing.T) {
	space, backend, access, inbox := testSpace(t)
	archive, err := space.CreateFolder(t.Context(), access, "Projects", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	older := deliver(t, space, access, inbox.ID, "From: a@example.test\nSubject: one\n\nfirst body\n", base, model.FlagFlagged)
	newer := deliver(t, space, access, inbox.ID, "From: b@example.test\nSubject: two\n\nsecond body\n", base.Add(time.Hour), model.FlagFlagged, model.FlagSeen)
	plain := deliver(t, space, access, inbox.ID, "From: c@example.test\nSubject: three\n\nthird body\n", base.Add(2*time.Hour))
	index := New(backend)

	if got := flaggedIDs(t, index, space, access, inbox.ID); !slices.Equal(got, []string{newer.ID, older.ID}) {
		t.Fatalf("flagged = %v, want newest first %v", got, []string{newer.ID, older.ID})
	}
	folder, _ := space.GetFolder(t.Context(), access, inbox.ID)
	summaries, err := index.Flagged(t.Context(), space, access, folder)
	if err != nil || summaries[1].Preview != "first body" || summaries[1].FolderID != inbox.ID || summaries[1].Headers["Subject"] != "one" {
		t.Fatalf("flagged summaries = %+v, %v", summaries, err)
	}
	if got := flaggedIDs(t, index, space, access, archive.ID); len(got) != 0 {
		t.Fatalf("empty archive flagged = %v", got)
	}

	// Flag and unflag.
	if _, err := space.SetFlags(t.Context(), access, plain.ID, []string{model.FlagFlagged}); err != nil {
		t.Fatal(err)
	}
	if _, err := space.SetFlags(t.Context(), access, older.ID, []string{model.FlagSeen}); err != nil {
		t.Fatal(err)
	}
	if got := flaggedIDs(t, index, space, access, inbox.ID); !slices.Equal(got, []string{plain.ID, newer.ID}) {
		t.Fatalf("after flag/unflag = %v", got)
	}
	// The unread count still comes from the same projection.
	folder, _ = space.GetFolder(t.Context(), access, inbox.ID)
	if unseen, err := index.Unseen(t.Context(), space, access, folder, folderindex.PriorityFolder); err != nil || unseen != 1 {
		t.Fatalf("unseen = %d, %v", unseen, err)
	}

	// Move to another folder.
	if _, err := space.MoveItem(t.Context(), access, newer.ID, archive.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got := flaggedIDs(t, index, space, access, inbox.ID); !slices.Equal(got, []string{plain.ID}) {
		t.Fatalf("inbox after move = %v", got)
	}
	if got := flaggedIDs(t, index, space, access, archive.ID); !slices.Equal(got, []string{newer.ID}) {
		t.Fatalf("archive after move = %v", got)
	}

	// Delete: trash and permanent removal.
	if _, err := space.TrashItem(t.Context(), access, plain.ID); err != nil {
		t.Fatal(err)
	}
	if got := flaggedIDs(t, index, space, access, inbox.ID); len(got) != 0 {
		t.Fatalf("inbox after trash = %v", got)
	}
	if err := space.DeleteItem(t.Context(), access, newer.ID); err != nil {
		t.Fatal(err)
	}
	if got := flaggedIDs(t, index, space, access, archive.ID); len(got) != 0 {
		t.Fatalf("archive after delete = %v", got)
	}
}

func TestFlaggedSkipsListProjectionOfUnflaggedFolders(t *testing.T) {
	space, backend, access, inbox := testSpace(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	for n := range 5 {
		deliver(t, space, access, inbox.ID, fmt.Sprintf("From: a@example.test\nSubject: %d\n\nbody\n", n), base.Add(time.Duration(n)*time.Minute))
	}
	index := New(backend)
	if got := flaggedIDs(t, index, space, access, inbox.ID); len(got) != 0 {
		t.Fatalf("flagged = %v", got)
	}
	if space.fullPages != 0 {
		t.Fatalf("a folder without flagged mail read %d payload pages; it must answer from metadata", space.fullPages)
	}
}

// staleUnseenDefinition is the revision 0 unread projection, which keyed
// only unseen messages.
type staleUnseenDefinition struct{ unseenDefinition }

func (staleUnseenDefinition) Revision() int { return 0 }
func (staleUnseenDefinition) Project(item model.Item) (folderindex.Document, error) {
	if slices.Contains(item.Flags, model.FlagSeen) {
		return folderindex.Document{ItemID: item.ID}, nil
	}
	return folderindex.Document{ItemID: item.ID, Keys: []string{unseenBucket}}, nil
}

func TestFlaggedRebuildsAnUnseenProjectionOfTheOldRevision(t *testing.T) {
	space, backend, access, inbox := testSpace(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	flagged := deliver(t, space, access, inbox.ID, "From: a@example.test\nSubject: one\n\nbody\n", base, model.FlagFlagged, model.FlagSeen)
	deliver(t, space, access, inbox.ID, "From: b@example.test\nSubject: two\n\nbody\n", base.Add(time.Minute))
	folder, _ := space.GetFolder(t.Context(), access, inbox.ID)
	old := folderindex.New(backend)
	if err := old.WithSnapshot(t.Context(), space, access, folder, staleUnseenDefinition{}, func(snapshot *folderindex.Snapshot) error {
		if snapshot.Revision != 0 || len(snapshot.Buckets[flaggedBucket]) != 0 {
			t.Fatalf("old revision snapshot = %+v", snapshot)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	index := New(backend)
	if got := flaggedIDs(t, index, space, access, inbox.ID); !slices.Equal(got, []string{flagged.ID}) {
		t.Fatalf("flagged after revision rebuild = %v", got)
	}
	if unseen, err := index.Unseen(t.Context(), space, access, folder, folderindex.PriorityFolder); err != nil || unseen != 1 {
		t.Fatalf("unseen after revision rebuild = %d, %v", unseen, err)
	}
}

func TestFlaggedFallsBackToTheListWhileTheFlaggedBucketBuilds(t *testing.T) {
	counting, backend, access, inbox := testSpace(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	flagged := deliver(t, counting, access, inbox.ID, "From: a@example.test\nSubject: one\n\nbody\n", base, model.FlagFlagged)
	index := New(backend)
	folder, _ := counting.GetFolder(t.Context(), access, inbox.ID)
	// Build the list projection inline, then hold every further build.
	if _, err := index.List(t.Context(), counting, access, folder, Query{Limit: 10}); err != nil {
		t.Fatal(err)
	}
	space := &slowBuildSpace{countingSpace: counting, release: make(chan struct{})}
	defer close(space.release)
	builder := folderindex.NewBuilder(t.Context(), 1)
	index.SetBuilder(builder, nil)
	summaries, err := index.Flagged(t.Context(), space, access, folder)
	if err != nil || len(summaries) != 1 || summaries[0].ID != flagged.ID {
		t.Fatalf("flagged while building = %+v, %v", summaries, err)
	}
}

// BenchmarkFollowUps measures the Follow up smart view's per-folder work over
// a synthetic mailbox of 100 folders of 1000 messages with 10 flagged in all,
// warm: ListFiltered is the former list-projection scan of every folder,
// Flagged the flagged-bucket lookup.
func BenchmarkFollowUps(b *testing.B) {
	const folders, perFolder, flaggedEvery = 100, 1000, 10000
	backend, err := pebblestore.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = backend.Close() })
	space, access := benchmarkSpace(b, backend)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var all []model.Folder
	n := 0
	for f := range folders {
		folder, err := space.CreateFolder(b.Context(), access, fmt.Sprintf("F%03d", f), model.FolderTypeMail, "")
		if err != nil {
			b.Fatal(err)
		}
		for m := range perFolder {
			flags := []string{model.FlagSeen}
			if n%flaggedEvery == 0 {
				flags = append(flags, model.FlagFlagged)
			}
			n++
			message := fmt.Sprintf("From: Sender %d <s%d@example.test>\r\nTo: alice@example.test\r\nSubject: Message %d in %d\r\n\r\n%s\r\n", m, m, m, f, strings.Repeat("body text ", 20))
			if _, err := space.CreateItem(b.Context(), access, folder.ID, service.ItemInput{Data: []byte(message), InternalDate: base.Add(time.Duration(n) * time.Minute), Flags: flags}); err != nil {
				b.Fatal(err)
			}
		}
		if folder, err = space.GetFolder(b.Context(), access, folder.ID); err != nil {
			b.Fatal(err)
		}
		all = append(all, folder)
	}
	index := New(backend)
	run := func(b *testing.B, collect func(model.Folder) (int, error)) {
		total := 0
		for _, folder := range all { // warm: build every projection once
			if _, err := collect(folder); err != nil {
				b.Fatal(err)
			}
		}
		b.ResetTimer()
		for b.Loop() {
			total = 0
			for _, folder := range all {
				count, err := collect(folder)
				if err != nil {
					b.Fatal(err)
				}
				total += count
			}
		}
		if want := folders * perFolder / flaggedEvery; total != want {
			b.Fatalf("found %d flagged, want %d", total, want)
		}
	}
	b.Run("ListFiltered", func(b *testing.B) {
		run(b, func(folder model.Folder) (int, error) {
			page, err := index.List(b.Context(), space, access, folder, Query{Filter: FilterFlagged, Sort: SortDate, Limit: maxPageLimit})
			return len(page.Items), err
		})
	})
	b.Run("Flagged", func(b *testing.B) {
		run(b, func(folder model.Folder) (int, error) {
			summaries, err := index.Flagged(b.Context(), space, access, folder)
			return len(summaries), err
		})
	})
}

func benchmarkSpace(b *testing.B, backend store.Store) (*service.FolderSpaceService, service.AccessContext) {
	b.Helper()
	ts := model.NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(b.Context(), namespace); err != nil {
			b.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(b.Context(), "alice", "Alice", "password123"); err != nil {
		b.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(b.Context(), "alice"); err != nil {
		b.Fatal(err)
	}
	return service.NewFolderSpace(ts, authz.New(ts)), service.UserAccess("alice", "test")
}
