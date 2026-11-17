package app

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// gatedBuildSpace holds projection builds (UID-ordered enumerations) until
// release closes, standing in for a very large mailbox.
type gatedBuildSpace struct {
	service.FolderSpace
	release chan struct{}
}

func (s *gatedBuildSpace) ListItemPage(ctx context.Context, access service.AccessContext, folderID string, query service.ItemPageQuery) (service.ItemPage, error) {
	if query.Order == service.ItemPageOrderUIDDescending {
		select {
		case <-s.release:
		case <-ctx.Done():
			return service.ItemPage{}, ctx.Err()
		}
	}
	return s.FolderSpace.(service.FolderItemPager).ListItemPage(ctx, access, folderID, query)
}

func (s *gatedBuildSpace) CurrentChangeState(ctx context.Context, access service.AccessContext, scope service.ChangeScope) (string, error) {
	return s.FolderSpace.(service.FolderChangeReader).CurrentChangeState(ctx, access, scope)
}

func (s *gatedBuildSpace) ListChanges(ctx context.Context, access service.AccessContext, scope service.ChangeScope, since string, limit int) (service.ChangePage, error) {
	return s.FolderSpace.(service.FolderChangeReader).ListChanges(ctx, access, scope, since, limit)
}

func TestMailWorkspaceAnswersWhileProjectionsBuildInBackground(t *testing.T) {
	handler, _ := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	inbox := model.InboxFolderID("alice")
	base := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	older := seedMail(t, handler, inbox, "From: zed@example.net\nSubject: Older\n\nfirst\n", base)
	newer := seedMail(t, handler, inbox, "From: amy@example.net\nSubject: Newer\n\nsecond\n", base.Add(time.Hour), model.FlagSeen)

	space := &gatedBuildSpace{FolderSpace: handler.folderSpace, release: make(chan struct{})}
	handler.folderSpace = space
	handler.StartMailIndexing()
	stream, unsubscribe := handler.events.Subscribe("alice")
	t.Cleanup(unsubscribe)

	folders := func() map[string]workspaceFolder {
		response, err := client.Get(server.URL + "/api/v1/workspace/folders?include=unread&first=" + url.QueryEscape(inbox))
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]workspaceFolder{}
		for _, folder := range decodeTestJSON[[]workspaceFolder](t, response) {
			byID[folder.ID] = folder
		}
		return byID
	}
	list := func() mailindex.Page {
		response, err := client.Get(server.URL + "/api/v1/workspace/mail/list?folder_id=" + url.QueryEscape(inbox))
		if err != nil {
			t.Fatal(err)
		}
		return decodeTestJSON[mailindex.Page](t, response)
	}

	started := time.Now()
	if folder := folders()[inbox]; folder.UnreadCount != nil || folder.UnreadState != unreadCounting {
		t.Fatalf("inbox while building: count=%v state=%q", folder.UnreadCount, folder.UnreadState)
	}
	if page := list(); !page.Building || len(page.Items) != 2 || page.Items[0].ID != newer.ID || page.Items[1].ID != older.ID || page.Items[1].Preview != "first" {
		t.Fatalf("list while building=%+v", page)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("requests waited %v for projection builds", elapsed)
	}

	close(space.release)
	announced := map[string]any{}
	timeout := time.After(10 * time.Second)
	for announced["folders.counts"] == nil || announced["mail.list.ready"] == nil {
		select {
		case event := <-stream:
			if event.Resource == inbox {
				announced[event.Type] = event.Data["unread_count"]
			}
		case <-timeout:
			t.Fatalf("readiness events not published: %v", announced)
		}
	}
	if announced["folders.counts"] != int64(1) || announced["mail.list.ready"] != int64(1) {
		t.Fatalf("announced unread counts=%v", announced)
	}
	if folder := folders()[inbox]; folder.UnreadCount == nil || *folder.UnreadCount != 1 || folder.UnreadState != "" {
		t.Fatalf("inbox after build: count=%v state=%q", folder.UnreadCount, folder.UnreadState)
	}
	if page := list(); page.Building || page.Unread != 1 || len(page.Items) != 2 {
		t.Fatalf("list after build=%+v", page)
	}
}

// countingBuildSpace counts full enumerations of one folder.
type countingBuildSpace struct {
	service.FolderSpace
	folderID string
	builds   atomic.Int64
}

func (s *countingBuildSpace) ListItemPage(ctx context.Context, access service.AccessContext, folderID string, query service.ItemPageQuery) (service.ItemPage, error) {
	if folderID == s.folderID && query.BeforeUID == 0 {
		s.builds.Add(1)
	}
	return s.FolderSpace.(service.FolderItemPager).ListItemPage(ctx, access, folderID, query)
}

func (s *countingBuildSpace) CurrentChangeState(ctx context.Context, access service.AccessContext, scope service.ChangeScope) (string, error) {
	return s.FolderSpace.(service.FolderChangeReader).CurrentChangeState(ctx, access, scope)
}

func (s *countingBuildSpace) ListChanges(ctx context.Context, access service.AccessContext, scope service.ChangeScope, since string, limit int) (service.ChangePage, error) {
	return s.FolderSpace.(service.FolderChangeReader).ListChanges(ctx, access, scope, since, limit)
}

func TestAccountWarmUpBuildsCalendarProjectionBeforeTheFirstRequest(t *testing.T) {
	handler, _ := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	calendarID := model.FolderKey("alice", "Calendar")
	event := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Veksel Test//EN\r\nBEGIN:VEVENT\r\nUID:warm-1\r\nDTSTAMP:20260801T000000Z\r\nSUMMARY:Warmed\r\nDTSTART:20260817T090000Z\r\nDTEND:20260817T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	if _, err := handler.folderSpace.CreateItem(t.Context(), service.UserAccess("alice", "test"), calendarID, service.ItemInput{Data: []byte(event)}); err != nil {
		t.Fatal(err)
	}
	space := &countingBuildSpace{FolderSpace: handler.folderSpace, folderID: calendarID}
	handler.folderSpace = space
	handler.StartMailIndexing()
	handler.warmAccount(t.Context(), "alice")
	deadline := time.Now().Add(10 * time.Second)
	for space.builds.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("calendar projection was not warmed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The request reuses the warm-up's projection, waiting for the build if
	// it is still running, instead of enumerating the calendar again.
	response, err := client.Get(server.URL + "/api/v1/workspace/calendar/events?folder_id=" + url.QueryEscape(calendarID) + "&start=2026-08-01T00%3A00%3A00Z&end=2026-09-01T00%3A00%3A00Z")
	if err != nil {
		t.Fatal(err)
	}
	events := decodeTestJSON[[]workspaceCalendarEvent](t, response)
	if len(events) != 1 || events[0].Summary != "Warmed" || space.builds.Load() != 1 {
		t.Fatalf("events=%+v calendar builds=%d", events, space.builds.Load())
	}
}

func TestRecentSubjectsSelectsActiveMailboxesNewestFirst(t *testing.T) {
	handler, ts := testHandler(t)
	for _, user := range []string{"alice", "bob", "carol"} {
		if err := ts.UserStore().Create(t.Context(), user, user, "password123"); err != nil {
			t.Fatal(err)
		}
	}
	for _, user := range []string{"carol", "alice", "bob"} {
		if _, err := handler.sessions.Create(t.Context(), user, "csrf", "127.0.0.1", "test"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := handler.sessions.CreatePending(t.Context(), "dave", "csrf", "127.0.0.1", "test", secondFactorVerify); err != nil {
		t.Fatal(err)
	}
	subjects, err := handler.sessions.RecentSubjects(t.Context(), time.Now().Add(-time.Hour), 2)
	if err != nil || len(subjects) != 2 || subjects[0] != "bob" || subjects[1] != "alice" {
		t.Fatalf("recent subjects=%v err=%v", subjects, err)
	}
	if subjects, err = handler.sessions.RecentSubjects(t.Context(), time.Now().Add(time.Hour), 2); err != nil || len(subjects) != 0 {
		t.Fatalf("future window subjects=%v err=%v", subjects, err)
	}
}
