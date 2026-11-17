package app

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const (
	// mailIndexWorkers bounds concurrent background projection builds when
	// no search worker count is configured.
	mailIndexWorkers = 2
	// startupWarmDelay keeps startup warm-up out of the way of startup.
	startupWarmDelay = 15 * time.Second
	// startupWarmWindow and startupWarmAccounts select the mailboxes warmed
	// after startup: those with browser activity in the window, newest first.
	startupWarmWindow   = 72 * time.Hour
	startupWarmAccounts = 16
)

// ConfigureMailIndex shares the mail list index other protocols use, so
// background builds, their queue, and the snapshot cache are shared too.
func (h *Handler) ConfigureMailIndex(index *mailindex.Index) {
	if index != nil {
		h.mailIndex = index
	}
}

// StartMailIndexing moves full mail projection builds off request paths onto
// a bounded worker pool, announces finished builds on the event stream, and
// warms the mailboxes and calendars of recently active browser sessions. The
// calendar range projections share the pool. The pool follows
// search_index_workers, the operator's budget for background indexing.
// Projections of accounts encrypted at rest stay sealed.
func (h *Handler) StartMailIndexing() {
	workers := mailIndexWorkers
	if h.cfg != nil && h.cfg.SearchIndexWorkers > 0 {
		workers = min(h.cfg.SearchIndexWorkers, 8)
	}
	// Builds run on the server's background group: shutdown cancels them and
	// waits for running builds before the stores close.
	builder := folderindex.NewBuilder(h.background.Context(), workers)
	h.mailIndex.SetBuilder(builder, h.publishMailIndexReady)
	h.calendarIndex.SetBuilder(builder)
	h.mailIndexWarm.Store(true)
	h.background.Go(func(ctx context.Context) {
		<-ctx.Done()
		builder.Wait()
	})
	h.background.Go(func(ctx context.Context) {
		select {
		case <-time.After(startupWarmDelay):
		case <-ctx.Done():
			return
		}
		subjects, err := h.sessions.RecentSubjects(ctx, time.Now().Add(-startupWarmWindow), startupWarmAccounts)
		if err != nil {
			log.Warn("mail index warm-up skipped", "error", err)
			return
		}
		for _, subject := range subjects {
			h.warmAccount(ctx, subject)
		}
	})
}

// warmAccount queues low-priority builds of userID's own mail and calendar
// projections: Inbox first, then calendars, then the other mail folders.
// Builds of one account run one at a time in queue order. Interactive mail
// requests raise a queued folder's priority; a calendar query arriving while
// its build runs waits for that build instead of starting another.
func (h *Handler) warmAccount(ctx context.Context, userID string) {
	access := service.UserAccess(userID, "web")
	folders, err := h.folderSpace.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		log.Warn("index warm-up skipped", "user", userID, "error", err)
		return
	}
	folders = slices.DeleteFunc(folders, func(folder model.Folder) bool {
		return !strings.EqualFold(folder.UserID, userID) || folder.Type != model.FolderTypeMail && folder.Type != model.FolderTypeCalendar
	})
	order := func(folder model.Folder) int {
		switch {
		case folder.SpecialUse == model.SpecialUseInbox:
			return 0
		case folder.Type == model.FolderTypeCalendar:
			return 1
		}
		return 2
	}
	slices.SortStableFunc(folders, func(left, right model.Folder) int { return order(left) - order(right) })
	for _, folder := range folders {
		var err error
		if folder.Type == model.FolderTypeCalendar {
			err = h.calendarIndex.Warm(h.folderSpace, access, folder, folderindex.PriorityWarm)
		} else {
			err = h.mailIndex.Warm(h.folderSpace, access, folder, folderindex.PriorityWarm)
		}
		if err != nil {
			log.Debug("index warm-up skipped folder", "folder_id", folder.ID, "error", err)
		}
	}
}

// mailFolderPriority orders the background build of a folder's unread count:
// Inbox, then the folders the client lists first (its current folder and
// favorites), then the rest.
func mailFolderPriority(folder model.Folder, preferred []string) folderindex.Priority {
	switch {
	case folder.SpecialUse == model.SpecialUseInbox:
		return folderindex.PriorityInbox
	case slices.Contains(preferred, folder.ID):
		return folderindex.PriorityFavorite
	}
	return folderindex.PriorityFolder
}

// publishMailIndexReady tells the folder's owner and every deferred
// requester that a background build finished: folders.counts carries a new
// unread count, mail.list.ready invites a reload of a building list page.
func (h *Handler) publishMailIndexReady(ready mailindex.Ready) {
	recipients := []string{strings.ToLower(ready.Folder.UserID)}
	for _, waiter := range ready.Waiters {
		for _, id := range []string{waiter.Actor.ID, waiter.Subject.ID} {
			if id = strings.ToLower(id); id != "" && !slices.Contains(recipients, id) {
				recipients = append(recipients, id)
			}
		}
	}
	eventType := "folders.counts"
	if ready.Index == model.MailListIndex {
		eventType = "mail.list.ready"
	}
	h.events.Publish(events.Event{Type: eventType, Resource: ready.Folder.ID, Data: map[string]any{"folder_id": ready.Folder.ID, "unread_count": ready.Unread}, Recipients: recipients})
}
