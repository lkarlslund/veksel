package calendarindex

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

type testSpace struct {
	service.FolderSpace
	folder model.Folder
	items  []model.Item
	pages  int
	gets   int
}

func (s *testSpace) GetFolder(context.Context, service.AccessContext, string) (model.Folder, error) {
	return s.folder, nil
}

func (s *testSpace) ListItemPage(_ context.Context, _ service.AccessContext, _ string, query service.ItemPageQuery) (service.ItemPage, error) {
	s.pages++
	if query.BeforeUID != 0 {
		return service.ItemPage{}, nil
	}
	return service.ItemPage{Items: append([]model.Item(nil), s.items...)}, nil
}

func (s *testSpace) GetItem(_ context.Context, _ service.AccessContext, id string) (model.Item, error) {
	s.gets++
	for _, item := range s.items {
		if item.ID == id {
			return item, nil
		}
	}
	return model.Item{}, nil
}

func TestQueryPersistsRangeProjectionAndInvalidatesOnFolderGeneration(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	space := &testSpace{
		folder: model.Folder{ID: "calendar", Type: model.FolderTypeCalendar, Indexes: model.DefaultFolderIndexes(model.FolderTypeCalendar), HighestModSeq: 2, ItemCount: 2},
		items: []model.Item{
			{ID: "single", FolderID: "calendar", UID: 1, Data: []byte("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:single\r\nSUMMARY:Single\r\nDTSTART:20260817T090000Z\r\nDTEND:20260817T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")},
			{ID: "repeat", FolderID: "calendar", UID: 2, Data: []byte("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:repeat\r\nSUMMARY:Repeat\r\nDTSTART:20260818T090000Z\r\nDTEND:20260818T100000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")},
		},
	}
	index := New(backend)
	access := service.UserAccess("alice", "test")
	start := mustTime(t, "2026-08-18T00:00:00Z")
	end := mustTime(t, "2026-08-20T00:00:00Z")
	results, err := index.Query(t.Context(), space, access, space.folder, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || space.pages != 1 || space.gets != 1 {
		t.Fatalf("first query results=%d pages=%d recurring gets=%d", len(results), space.pages, space.gets)
	}
	space.pages, space.gets = 0, 0
	results, err = New(backend).Query(t.Context(), space, access, space.folder, start, end)
	if err != nil {
		t.Fatal(err)
	}
	// A new process loads the stored projection without enumerating the
	// folder; recurrence expansions live in memory only, so the recurring
	// master is read once to expand the window again.
	if len(results) != 2 || space.pages != 0 || space.gets != 1 {
		t.Fatalf("warm query results=%d pages=%d recurring gets=%d", len(results), space.pages, space.gets)
	}
	space.folder.HighestModSeq++
	space.pages = 0
	if _, err = index.Query(t.Context(), space, access, space.folder, start, end); err != nil {
		t.Fatal(err)
	}
	if space.pages != 1 {
		t.Fatalf("stale generation pages=%d, want rebuild", space.pages)
	}
}

func TestCachedQueryMatchesStoredProjection(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	space := &testSpace{
		folder: model.Folder{ID: "calendar", Type: model.FolderTypeCalendar, Indexes: model.DefaultFolderIndexes(model.FolderTypeCalendar), HighestModSeq: 2, ItemCount: 2},
		items: []model.Item{
			{ID: "single", FolderID: "calendar", UID: 1, Data: []byte("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:single\r\nSUMMARY:Single\r\nATTENDEE:mailto:bob@example.test\r\nDTSTART:20260817T090000Z\r\nDTEND:20260817T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")},
			{ID: "repeat", FolderID: "calendar", UID: 2, Data: []byte("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:repeat\r\nSUMMARY:Repeat\r\nDTSTART:20260818T090000Z\r\nDTEND:20260818T100000Z\r\nRRULE:FREQ=WEEKLY;COUNT=10\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")},
		},
	}
	cached := New(backend)
	access := service.UserAccess("alice", "test")
	for _, window := range [][2]string{{"2026-08-01T00:00:00Z", "2026-09-12T00:00:00Z"}, {"2026-09-01T00:00:00Z", "2026-10-13T00:00:00Z"}, {"2026-08-01T00:00:00Z", "2026-09-12T00:00:00Z"}} {
		start, end := mustTime(t, window[0]), mustTime(t, window[1])
		warm, err := cached.Query(t.Context(), space, access, space.folder, start, end)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := New(backend).Query(t.Context(), space, access, space.folder, start, end)
		if err != nil {
			t.Fatal(err)
		}
		if len(warm) == 0 || !reflect.DeepEqual(warm, stored) {
			t.Fatalf("window %v: cached results differ from stored projection:\ncached=%+v\nstored=%+v", window, warm, stored)
		}
	}
}

func TestWarmBuildsProjectionBeforeTheFirstQuery(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	space := benchCalendar(300)
	index := New(backend)
	access := service.UserAccess("alice", "test")
	if err := index.Warm(space, access, space.folder, folderindex.PriorityWarm); err == nil {
		t.Fatal("warm without a builder succeeded")
	}
	builder := folderindex.NewBuilder(t.Context(), 1)
	index.SetBuilder(builder)
	if err := index.Warm(space, access, space.folder, folderindex.PriorityWarm); err != nil {
		t.Fatal(err)
	}
	builder.Wait()
	if space.pages != 1 {
		t.Fatalf("warm build enumerated %d pages", space.pages)
	}
	results, err := index.Query(t.Context(), space, access, space.folder, benchWindowStart, benchWindowEnd)
	if err != nil || len(results) == 0 || space.pages != 1 {
		t.Fatalf("query after warm-up results=%d pages=%d err=%v", len(results), space.pages, err)
	}
	// The projection built in parallel answers exactly as the stored copy
	// a fresh process loads.
	stored, err := New(backend).Query(t.Context(), space, access, space.folder, benchWindowStart, benchWindowEnd)
	if err != nil || !reflect.DeepEqual(results, stored) {
		t.Fatalf("stored projection differs: err=%v %d vs %d results", err, len(results), len(stored))
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
