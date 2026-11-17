package mailindex

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// slowBuildSpace holds every projection build (UID-ordered enumeration)
// until release closes, standing in for a very large folder. Date-ordered
// pages, which serve the fallback list, pass straight through.
type slowBuildSpace struct {
	*countingSpace
	release chan struct{}
}

func (s *slowBuildSpace) ListItemPage(ctx context.Context, access service.AccessContext, folderID string, query service.ItemPageQuery) (service.ItemPage, error) {
	if query.Order == service.ItemPageOrderUIDDescending {
		select {
		case <-s.release:
		case <-ctx.Done():
			return service.ItemPage{}, ctx.Err()
		}
	}
	return s.countingSpace.ListItemPage(ctx, access, folderID, query)
}

func TestQueriesDoNotWaitForBackgroundProjectionBuilds(t *testing.T) {
	counting, backend, access, inbox := testSpace(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	older := deliver(t, counting, access, inbox.ID, "From: Zed <zed@example.test>\nSubject: Older\n\nfirst body\n", base)
	middle := deliver(t, counting, access, inbox.ID, "From: Amy <amy@example.test>\nSubject: Middle\n\nsecond body\n", base.Add(time.Hour), model.FlagSeen)
	newest := deliver(t, counting, access, inbox.ID, "From: Bob <bob@example.test>\nSubject: Newest\n\nthird body\n", base.Add(2*time.Hour))
	inbox, err := counting.GetFolder(t.Context(), access, inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	space := &slowBuildSpace{countingSpace: counting, release: make(chan struct{})}
	index := New(backend)
	builder := folderindex.NewBuilder(t.Context(), 2)
	ready := make(chan Ready, 8)
	index.SetBuilder(builder, func(r Ready) { ready <- r })

	started := time.Now()
	if _, err := index.Unseen(t.Context(), space, access, inbox, folderindex.PriorityInbox); !errors.Is(err, folderindex.ErrBuilding) {
		t.Fatalf("unread count err=%v, want ErrBuilding", err)
	}
	page, err := index.List(t.Context(), space, access, inbox, Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	// The fallback page comes newest first from the folder's date index,
	// with previews projected on the fly, and pages on with its own cursor.
	if !page.Building || page.Total != 3 || len(page.Items) != 2 || page.Items[0].ID != newest.ID || page.Items[1].ID != middle.ID || page.Items[0].Preview != "third body" || !strings.HasPrefix(page.NextCursor, fallbackCursorPrefix) {
		t.Fatalf("fallback page=%+v", page)
	}
	rest, err := index.List(t.Context(), space, access, inbox, Query{Limit: 2, Cursor: page.NextCursor})
	if err != nil || !rest.Building || len(rest.Items) != 1 || rest.Items[0].ID != older.ID || rest.NextCursor != "" {
		t.Fatalf("fallback second page=%+v err=%v", rest, err)
	}
	filtered, err := index.List(t.Context(), space, access, inbox, Query{Limit: 2, Filter: FilterUnread})
	if err != nil || !filtered.Building || len(filtered.Items) != 0 {
		t.Fatalf("filtered page while building=%+v err=%v", filtered, err)
	}
	if _, err := index.Previews(t.Context(), space, access, inbox); !errors.Is(err, folderindex.ErrBuilding) {
		t.Fatalf("previews err=%v, want ErrBuilding", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("queries waited %v for projection builds", elapsed)
	}

	close(space.release)
	builder.Wait()
	announced := map[string]int64{}
	for len(ready) > 0 {
		r := <-ready
		if r.Folder.ID != inbox.ID || len(r.Waiters) == 0 {
			t.Fatalf("readiness=%+v", r)
		}
		announced[r.Index] = r.Unread
	}
	if announced[model.MailUnseenIndex] != 2 || announced[model.MailListIndex] != 2 || len(announced) != 2 {
		t.Fatalf("announced=%v, want both projections with two unread", announced)
	}
	if unread, err := index.Unseen(t.Context(), space, access, inbox, folderindex.PriorityInbox); err != nil || unread != 2 {
		t.Fatalf("unread=%d err=%v", unread, err)
	}
	built, err := index.List(t.Context(), space, access, inbox, Query{Limit: 2, Filter: FilterUnread})
	if err != nil || built.Building || built.Unread != 2 || len(built.Items) != 2 || built.Items[0].ID != newest.ID || built.Items[1].ID != older.ID {
		t.Fatalf("projected page=%+v err=%v", built, err)
	}
	if len(ready) != 0 {
		t.Fatal("current projections announced readiness again")
	}
}

func TestWarmBuildsProjectionsAheadOfQueries(t *testing.T) {
	counting, backend, access, inbox := testSpace(t)
	deliver(t, counting, access, inbox.ID, "From: amy@example.test\nSubject: Hi\n\nbody\n", time.Now())
	inbox, err := counting.GetFolder(t.Context(), access, inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	index := New(backend)
	builder := folderindex.NewBuilder(t.Context(), 1)
	var announced []string
	index.SetBuilder(builder, func(r Ready) { announced = append(announced, r.Index) })
	if err := index.Warm(counting, access, inbox, folderindex.PriorityWarm); err != nil {
		t.Fatal(err)
	}
	builder.Wait()
	if !slices.Equal(announced, []string{model.MailUnseenIndex, model.MailListIndex}) {
		t.Fatalf("warm-up order=%v, want unread count first", announced)
	}
	pages := counting.fullPages
	page, err := index.List(t.Context(), counting, access, inbox, Query{Limit: 10})
	if err != nil || page.Building || len(page.Items) != 1 || counting.fullPages != pages {
		t.Fatalf("warmed list page=%+v err=%v (full pages %d -> %d)", page, err, pages, counting.fullPages)
	}
}
