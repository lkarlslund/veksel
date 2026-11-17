package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/mailstate"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// maxFollowUpRows bounds the Follow up smart view.
const maxFollowUpRows = 500

// ConfigureMailState installs snooze and follow-up metadata over the same
// FolderSpace used by the web workspace; callers start its wake job.
func (h *Handler) ConfigureMailState(ctx context.Context, cfg mailstate.Config) (*mailstate.Service, error) {
	states, err := mailstate.New(ctx, h.ts, h.folderSpace, cfg)
	if err != nil {
		return nil, err
	}
	h.mailState = states
	return states, nil
}

// applyMailStateAction runs the snooze, pin, and follow-up item actions.
func (h *Handler) applyMailStateAction(r *http.Request, itemID string, request workspaceItemActionRequest) (model.Item, error) {
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	switch request.Action {
	case "pin", "unpin":
		return h.workspace.SetItemKeyword(r.Context(), actor, subject, mode, itemID, model.KeywordPinned, request.Action == "pin")
	}
	if h.mailState == nil {
		return model.Item{}, errors.New("snooze and follow-up dates are unavailable")
	}
	access := webAccess(actor, subject, mode)
	switch request.Action {
	case "snooze":
		return h.mailState.Snooze(r.Context(), access, itemID, request.Until)
	case "unsnooze":
		return h.mailState.Unsnooze(r.Context(), access, itemID)
	case "follow_up":
		var due, reminder time.Time
		if request.DueAt != nil {
			due = *request.DueAt
		}
		if request.ReminderAt != nil {
			reminder = *request.ReminderAt
		}
		item, _, err := h.mailState.SetFollowUp(r.Context(), access, itemID, due, reminder)
		return item, err
	case "complete":
		item, err := h.workspace.SetItemFlagged(r.Context(), actor, subject, mode, itemID, false)
		if err != nil {
			return model.Item{}, err
		}
		return item, h.mailState.ForgetFollowUp(r.Context(), subject.ID, itemID)
	case "dismiss_reminder":
		if err := h.mailState.DismissReminder(r.Context(), subject.ID, itemID); err != nil {
			return model.Item{}, err
		}
		return h.workspace.GetItem(r.Context(), actor, subject, mode, itemID)
	}
	return model.Item{}, errors.New("unsupported mail state action")
}

// annotateMailPage adds the subject's snooze wake times and follow-up dates
// to a list page. A snooze shows only while its message is still in the
// folder it was snoozed into.
func (h *Handler) annotateMailPage(ctx context.Context, ownerID string, page *mailindex.Page) error {
	if h.mailState == nil || len(page.Items) == 0 {
		return nil
	}
	snoozes, err := h.mailState.Snoozes(ctx, ownerID)
	if err != nil {
		return err
	}
	followUps, err := h.mailState.FollowUps(ctx, ownerID)
	if err != nil {
		return err
	}
	if len(snoozes) == 0 && len(followUps) == 0 {
		return nil
	}
	page.Annotate(func(summary *mailindex.Summary) {
		if snooze, ok := snoozes[summary.ID]; ok && snooze.FolderID == summary.FolderID {
			wake := snooze.WakeAt
			summary.SnoozedUntil = &wake
		}
		if followUp, ok := followUps[summary.ID]; ok && slices.Contains(summary.Flags, model.FlagFlagged) {
			summary.FollowUp = followUpMark(followUp)
		}
	})
	return nil
}

func followUpMark(record mailstate.FollowUp) *mailindex.FollowUp {
	mark := &mailindex.FollowUp{}
	if !record.DueAt.IsZero() {
		due := record.DueAt
		mark.DueAt = &due
	}
	if !record.ReminderAt.IsZero() {
		reminder := record.ReminderAt
		mark.ReminderAt = &reminder
	}
	return mark
}

// followUpRow is one Follow up smart view row.
type followUpRow struct {
	mailindex.Summary
	FolderName string `json:"folder_name"`
}

// apiWorkspaceMailFollowUps serves the Follow up smart view: flagged
// messages across the signed-in mailbox (Trash and Junk excluded), earliest
// due date first and undated flags last.
func (h *Handler) apiWorkspaceMailFollowUps(w http.ResponseWriter, r *http.Request) {
	folders, err := h.workspace.ListFolders(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		apiError(w, err)
		return
	}
	subject := currentSubject(r)
	access := webAccess(currentActor(r), subject, currentActingMode(r))
	rows := []followUpRow{}
	for _, folder := range folders {
		if folder.Type != model.FolderTypeMail || !strings.EqualFold(folder.UserID, subject.ID) || folder.SpecialUse == model.SpecialUseTrash || folder.SpecialUse == model.SpecialUseJunk {
			continue
		}
		readable, err := h.folderItemsReadable(r.Context(), r, folder)
		if err != nil {
			apiError(w, err)
			return
		}
		if !readable {
			continue
		}
		flagged, err := h.mailIndex.Flagged(r.Context(), h.folderSpace, access, folder)
		if err != nil {
			apiError(w, err)
			return
		}
		for _, item := range flagged {
			rows = append(rows, followUpRow{Summary: item, FolderName: folder.Name})
		}
	}
	page := mailindex.Page{Items: make([]mailindex.Summary, len(rows))}
	for i := range rows {
		page.Items[i] = rows[i].Summary
	}
	if err := h.annotateMailPage(r.Context(), subject.ID, &page); err != nil {
		apiError(w, err)
		return
	}
	h.annotateMailCategories(r.Context(), currentActor(r).ID, &page)
	for i := range rows {
		rows[i].Summary = page.Items[i]
	}
	due := func(row followUpRow) *time.Time {
		if row.FollowUp == nil {
			return nil
		}
		return row.FollowUp.DueAt
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := due(rows[i]), due(rows[j])
		if (a == nil) != (b == nil) {
			return a != nil
		}
		if a != nil && !a.Equal(*b) {
			return a.Before(*b)
		}
		return rows[i].InternalDate > rows[j].InternalDate
	})
	if len(rows) > maxFollowUpRows {
		rows = rows[:maxFollowUpRows]
	}
	jsonResponse(w, http.StatusOK, map[string]any{"items": rows, "total": len(rows)})
}

// folderItemsReadable reports whether the request may read folder's items:
// the signed-in user's own folders without a policy lookup, others by the
// single read check the Follow up view needs rather than every capability.
func (h *Handler) folderItemsReadable(ctx context.Context, r *http.Request, folder model.Folder) (bool, error) {
	subject := currentSubject(r)
	if subject.Kind == model.PrincipalUser && strings.EqualFold(folder.UserID, subject.ID) {
		return true, nil
	}
	decision, err := h.authorizer.Check(ctx, authz.Request{
		Actor: currentActor(r), Subject: subject, Mode: currentActingMode(r), Action: authz.FolderItemsRead,
		Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID},
	})
	if err != nil {
		return false, fmt.Errorf("check read capability for folder %q: %w", folder.ID, err)
	}
	return decision.Allowed, nil
}

// mailReminder is one due follow-up reminder for the in-app notifier.
type mailReminder struct {
	ItemID     string     `json:"item_id"`
	FolderID   string     `json:"folder_id"`
	Subject    string     `json:"subject"`
	From       string     `json:"from"`
	DueAt      *time.Time `json:"due_at,omitzero"`
	ReminderAt time.Time  `json:"reminder_at"`
}

// apiWorkspaceMailReminders lists the subject's undismissed follow-up
// reminders that are due. Reminders for messages that no longer exist, are
// no longer flagged, or sit in Trash are dropped.
func (h *Handler) apiWorkspaceMailReminders(w http.ResponseWriter, r *http.Request) {
	reminders := []mailReminder{}
	if h.mailState == nil {
		jsonResponse(w, http.StatusOK, reminders)
		return
	}
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	due, err := h.mailState.DueReminders(r.Context(), subject.ID, 20)
	if err != nil {
		apiError(w, err)
		return
	}
	for _, record := range due {
		item, err := h.workspace.GetItem(r.Context(), actor, subject, mode, record.ItemID)
		if errors.Is(err, store.ErrNotFound) || err == nil && !slices.Contains(item.Flags, model.FlagFlagged) {
			_ = h.mailState.ForgetFollowUp(r.Context(), subject.ID, record.ItemID)
			continue
		}
		if err != nil {
			continue
		}
		if folder, err := h.folderSpace.GetFolder(r.Context(), webAccess(actor, subject, mode), item.FolderID); err != nil || folder.SpecialUse == model.SpecialUseTrash {
			continue
		}
		reminder := mailReminder{ItemID: item.ID, FolderID: item.FolderID, Subject: headerOf(item, "Subject"), From: messageSender(item), ReminderAt: record.ReminderAt}
		reminder.DueAt = followUpMark(record).DueAt
		reminders = append(reminders, reminder)
	}
	jsonResponse(w, http.StatusOK, reminders)
}

func headerOf(item model.Item, name string) string {
	for key, value := range item.Headers {
		if strings.EqualFold(key, name) {
			return model.DecodeHeaderValue(value)
		}
	}
	if message, err := mail.ReadMessage(bytes.NewReader(item.Data)); err == nil {
		return model.DecodeHeaderValue(message.Header.Get(name))
	}
	return ""
}
