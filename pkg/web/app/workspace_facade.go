package app

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// workspaceFacade adapts the protocol-neutral FolderSpace to the web UI's
// richer trash, flag, and summary helpers.
type workspaceFacade struct {
	space service.FolderSpace
}

func newWorkspaceFacade(space service.FolderSpace) *workspaceFacade {
	return &workspaceFacade{space: space}
}

func (w *workspaceFacade) SetFolderSpace(space service.FolderSpace) { w.space = space }

func (w *workspaceFacade) SetTrashRetentionDays(days int) {
	if configurable, ok := w.space.(service.TrashRetentionConfigurer); ok {
		configurable.SetTrashRetentionDays(days)
	}
}

func (w *workspaceFacade) SetChangeRetention(days, maxEntries int) {
	if configurable, ok := w.space.(service.ChangeRetentionConfigurer); ok {
		configurable.SetChangeRetention(days, maxEntries)
	}
}

func webAccess(actor, subject model.PrincipalRef, mode authz.ActingMode) service.AccessContext {
	return service.AccessContext{Actor: actor, Subject: subject, Mode: mode, Protocol: "web"}
}

// ListFolders lists the subject's workspace. While acting for another
// account (impersonation or delegation) the list is what the subject
// would see, not everything the acting administrator can reach: an
// administrator's own mailbox must not appear as a folder "shared" into the
// mailbox being supported.
func (w *workspaceFacade) ListFolders(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode) ([]model.Folder, error) {
	folders, err := w.space.ListFolders(ctx, webAccess(actor, subject, mode), service.FolderQuery{})
	if err != nil || actor.ID == "" || actor.ID == subject.ID {
		return folders, err
	}
	visible, err := w.space.ListFolders(ctx, webAccess(subject, subject, ""), service.FolderQuery{})
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(visible))
	for _, folder := range visible {
		allowed[folder.ID] = true
	}
	result := folders[:0]
	for _, folder := range folders {
		if allowed[folder.ID] {
			result = append(result, folder)
		}
	}
	return result, nil
}

func (w *workspaceFacade) CreateFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, name string, folderType model.FolderType, parentID string) (model.Folder, error) {
	return w.space.CreateFolder(ctx, webAccess(actor, subject, mode), name, folderType, parentID)
}

func (w *workspaceFacade) MoveFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID, parentID, name string) (model.Folder, error) {
	return w.space.MoveFolder(ctx, webAccess(actor, subject, mode), folderID, parentID, name)
}

func (w *workspaceFacade) UpdateFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, update service.FolderUpdate) (model.Folder, error) {
	return w.space.UpdateFolder(ctx, webAccess(actor, subject, mode), folderID, update)
}

func (w *workspaceFacade) TrashFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string) error {
	return w.space.DeleteFolder(ctx, webAccess(actor, subject, mode), folderID)
}

func (w *workspaceFacade) RestoreFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string) (model.Folder, error) {
	recovery, ok := w.space.(service.RecoverableFolderSpace)
	if !ok {
		return model.Folder{}, errors.New("folder recovery is unavailable")
	}
	return recovery.RestoreFolder(ctx, webAccess(actor, subject, mode), folderID)
}

func (w *workspaceFacade) PurgeFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string) error {
	recovery, ok := w.space.(service.RecoverableFolderSpace)
	if !ok {
		return errors.New("folder recovery is unavailable")
	}
	return recovery.PurgeFolder(ctx, webAccess(actor, subject, mode), folderID)
}

func (w *workspaceFacade) ListItems(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string) ([]service.ItemSummary, error) {
	items, err := w.space.ListItems(ctx, webAccess(actor, subject, mode), folderID, service.ItemQuery{MetadataOnly: true})
	if err != nil {
		return nil, err
	}
	summaries := make([]service.ItemSummary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, summarizeItem(item))
	}
	return summaries, nil
}

func (w *workspaceFacade) ListItemPage(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, query service.ItemPageQuery) (service.ItemSummaryPage, error) {
	pager, ok := w.space.(service.FolderItemPager)
	if !ok {
		return service.ItemSummaryPage{}, errors.New("bounded item paging is unavailable")
	}
	page, err := pager.ListItemPage(ctx, webAccess(actor, subject, mode), folderID, query)
	if err != nil {
		return service.ItemSummaryPage{}, err
	}
	result := service.ItemSummaryPage{Items: make([]service.ItemSummary, 0, len(page.Items)), Total: page.Total, NextBeforeUID: page.NextBeforeUID, NextCursor: page.NextCursor}
	for _, item := range page.Items {
		result.Items = append(result.Items, summarizeItem(item))
	}
	return result, nil
}

func (w *workspaceFacade) ListFullItemPage(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, beforeUID uint32, limit int) (service.ItemPage, error) {
	pager, ok := w.space.(service.FolderItemPager)
	if !ok {
		return service.ItemPage{}, errors.New("bounded item paging is unavailable")
	}
	return pager.ListItemPage(ctx, webAccess(actor, subject, mode), folderID, service.ItemPageQuery{BeforeUID: beforeUID, Limit: limit, IncludeData: true})
}

func summarizeItem(item model.Item) service.ItemSummary {
	summary := service.ItemSummary{
		ID: item.ID, Name: item.Name, FolderID: item.FolderID, Headers: displayHeaders(item.Headers), Size: item.Size,
		UID: item.UID, ModSeq: item.ModSeq, Flags: slices.Clone(item.Flags), InternalDate: item.InternalDate.UTC().Format(time.RFC3339Nano),
		OriginalFolderID: item.OriginalFolderID, OriginalName: item.OriginalName, Previewable: service.ContentPreviewable(item.Headers["Content-Type"], item.Size),
	}
	if !item.TrashedAt.IsZero() {
		summary.TrashedAt = item.TrashedAt.UTC().Format(time.RFC3339)
	}
	if !item.PurgeAfter.IsZero() {
		summary.PurgeAfter = item.PurgeAfter.UTC().Format(time.RFC3339)
	}
	return summary
}

func (w *workspaceFacade) GetItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) (model.Item, error) {
	return w.space.GetItem(ctx, webAccess(actor, subject, mode), itemID)
}

func (w *workspaceFacade) CreateItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, data []byte, headers map[string]string) (string, error) {
	item, err := w.space.CreateItem(ctx, webAccess(actor, subject, mode), folderID, service.ItemInput{Data: data, Headers: headers})
	return item.ID, err
}

func (w *workspaceFacade) PutNamedItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID, name string, data []byte, headers map[string]string) (model.Item, error) {
	access := webAccess(actor, subject, mode)
	if existing, err := w.space.GetItemByName(ctx, access, folderID, name); err == nil {
		return w.space.UpdateItem(ctx, access, existing.ID, data, headers)
	}
	return w.space.CreateItem(ctx, access, folderID, service.ItemInput{Name: name, Data: data, Headers: headers})
}

func (w *workspaceFacade) UpdateItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, data []byte, headers map[string]string) (model.Item, error) {
	return w.space.UpdateItem(ctx, webAccess(actor, subject, mode), itemID, data, headers)
}

func (w *workspaceFacade) UpdateItemIfModSeq(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, expected uint64, data []byte, headers map[string]string) (model.Item, error) {
	updater, ok := w.space.(service.ConditionalItemUpdater)
	if !ok {
		return model.Item{}, errors.New("conditional item update is unavailable")
	}
	return updater.UpdateItemIfModSeq(ctx, webAccess(actor, subject, mode), itemID, expected, data, headers)
}

func (w *workspaceFacade) MoveItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID, folderID string) (model.Item, error) {
	return w.MoveItemNamed(ctx, actor, subject, mode, itemID, folderID, "")
}

func (w *workspaceFacade) MoveItemNamed(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID, folderID, name string) (model.Item, error) {
	return w.space.MoveItem(ctx, webAccess(actor, subject, mode), itemID, folderID, name)
}

func (w *workspaceFacade) DeleteItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) error {
	return w.space.DeleteItem(ctx, webAccess(actor, subject, mode), itemID)
}

func (w *workspaceFacade) SetItemRead(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, enabled bool) (model.Item, error) {
	return w.setFlag(ctx, actor, subject, mode, itemID, model.FlagSeen, enabled)
}

func (w *workspaceFacade) SetItemFlagged(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, enabled bool) (model.Item, error) {
	return w.setFlag(ctx, actor, subject, mode, itemID, model.FlagFlagged, enabled)
}

func (w *workspaceFacade) SetItemDraft(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, enabled bool) (model.Item, error) {
	return w.setFlag(ctx, actor, subject, mode, itemID, model.FlagDraft, enabled)
}

// SetItemFlags replaces an item's flags and keywords.
func (w *workspaceFacade) SetItemFlags(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, flags []string) (model.Item, error) {
	return w.space.SetFlags(ctx, webAccess(actor, subject, mode), itemID, flags)
}

// SetItemKeyword adds or removes one IMAP keyword such as $Pinned.
func (w *workspaceFacade) SetItemKeyword(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID, keyword string, enabled bool) (model.Item, error) {
	return w.setFlag(ctx, actor, subject, mode, itemID, keyword, enabled)
}

func (w *workspaceFacade) setFlag(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID, flag string, enabled bool) (model.Item, error) {
	access := webAccess(actor, subject, mode)
	item, err := w.space.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	flags := slices.DeleteFunc(slices.Clone(item.Flags), func(candidate string) bool { return candidate == flag })
	if enabled {
		flags = append(flags, flag)
	}
	return w.space.SetFlags(ctx, access, itemID, flags)
}

func (w *workspaceFacade) ListTrash(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode) ([]service.ItemSummary, error) {
	recovery, ok := w.space.(service.RecoverableFolderSpace)
	if !ok {
		return nil, errors.New("item recovery is unavailable")
	}
	return recovery.ListTrash(ctx, webAccess(actor, subject, mode))
}

func (w *workspaceFacade) ListTrashedFolders(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode) ([]model.Folder, error) {
	recovery, ok := w.space.(service.RecoverableFolderSpace)
	if !ok {
		return nil, errors.New("folder recovery is unavailable")
	}
	return recovery.ListTrashedFolders(ctx, webAccess(actor, subject, mode))
}

func (w *workspaceFacade) TrashItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) (model.Item, error) {
	recovery, ok := w.space.(service.RecoverableFolderSpace)
	if !ok {
		return model.Item{}, errors.New("item recovery is unavailable")
	}
	return recovery.TrashItem(ctx, webAccess(actor, subject, mode), itemID)
}

func (w *workspaceFacade) RestoreItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) (model.Item, error) {
	recovery, ok := w.space.(service.RecoverableFolderSpace)
	if !ok {
		return model.Item{}, errors.New("item recovery is unavailable")
	}
	return recovery.RestoreItem(ctx, webAccess(actor, subject, mode), itemID)
}

// displayHeaders returns headers with RFC 2047 encoded-words decoded in the
// fields a person reads (sender, recipients, subject). Stored headers keep
// their wire form; the web client shows them as text.
func displayHeaders(headers map[string]string) map[string]string {
	decoded, cloned := headers, false
	for _, name := range []string{"From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Subject"} {
		value, ok := headers[name]
		if !ok || !strings.Contains(value, "=?") {
			continue
		}
		if text := model.DecodeHeaderValue(value); text != value {
			if !cloned {
				decoded, cloned = maps.Clone(headers), true
			}
			decoded[name] = text
		}
	}
	return decoded
}
