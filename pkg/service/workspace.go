package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

// ItemSummary is the safe list representation of an item. Message bodies are
// returned only by GetItem after a separate read authorization check.
type ItemSummary struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	FolderID         string            `json:"folder_id"`
	Headers          map[string]string `json:"headers"`
	Size             int64             `json:"size"`
	UID              uint32            `json:"uid"`
	ModSeq           uint64            `json:"mod_seq"`
	Flags            []string          `json:"flags,omitempty"`
	InternalDate     string            `json:"internal_date"`
	Previewable      bool              `json:"previewable,omitempty"`
	TrashedAt        string            `json:"trashed_at,omitempty"`
	PurgeAfter       string            `json:"purge_after,omitempty"`
	OriginalFolderID string            `json:"original_folder_id,omitempty"`
	OriginalName     string            `json:"original_name,omitempty"`
}

// ItemSummaryPage is a cursor page for large folder views. UID-ordered callers
// pass NextBeforeUID back as before_uid; explicitly ordered callers use the
// opaque NextCursor instead.
type ItemSummaryPage struct {
	Items         []ItemSummary `json:"items"`
	Total         int64         `json:"total"`
	NextBeforeUID uint32        `json:"next_before_uid,omitempty"`
	NextCursor    string        `json:"next_cursor,omitempty"`
}

// Workspace exposes authorization-filtered folders and their items.
type Workspace struct {
	folders            *model.FolderStore
	items              *model.ItemStore
	authorizer         *authz.Engine
	trashRetentionDays atomic.Int64
}

const DefaultTrashRetentionDays = 30

// MaxItemPageLimit is the largest page the item pagers return.
const MaxItemPageLimit = 200

var errMaxItemPageLimit = fmt.Errorf("page limit must be between 1 and %d", MaxItemPageLimit)

func NewWorkspace(ts *model.TypedStore, authorizer *authz.Engine) *Workspace {
	workspace := &Workspace{folders: ts.FolderStore(), items: ts.ItemStore(), authorizer: authorizer}
	workspace.trashRetentionDays.Store(DefaultTrashRetentionDays)
	return workspace
}

func (s *Workspace) SetTrashRetentionDays(days int) {
	if days < 1 {
		days = 1
	}
	s.trashRetentionDays.Store(int64(days))
}

func (s *Workspace) trashRetention() time.Duration {
	return time.Duration(s.trashRetentionDays.Load()) * 24 * time.Hour
}

func (s *Workspace) ListFolders(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode) ([]model.Folder, error) {
	folders, err := s.folders.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	visible := make([]model.Folder, 0, len(folders))
	for _, folder := range folders {
		if !folder.TrashedAt.IsZero() {
			continue
		}
		decision, err := s.authorizer.Check(ctx, authz.Request{
			Actor: actor, Subject: subject, Mode: mode, Action: authz.FolderDiscover,
			Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID},
		})
		if err != nil {
			return nil, err
		}
		if decision.Allowed {
			visible = append(visible, folder)
		}
	}
	sort.Slice(visible, func(i, j int) bool {
		if visible[i].UserID == visible[j].UserID {
			return visible[i].Path < visible[j].Path
		}
		return visible[i].UserID < visible[j].UserID
	})
	return visible, nil
}

// CreateFolder creates a typed folder below parentID, or at the account root
// when parentID is empty.
func (s *Workspace) CreateFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, name string, folderType model.FolderType, parentID string) (model.Folder, error) {
	name = strings.TrimSpace(strings.Trim(name, "/"))
	if subject.Kind != model.PrincipalUser || name == "" || strings.Contains(name, "/") {
		return model.Folder{}, fmt.Errorf("%w: a user and single-segment folder name are required", ErrInvalidRequest)
	}
	if !validFolderType(folderType) {
		return model.Folder{}, fmt.Errorf("%w: unsupported folder type %q", ErrInvalidRequest, folderType)
	}
	path := name
	if parentID != "" {
		parent, err := s.folders.Get(ctx, parentID)
		if err != nil {
			return model.Folder{}, err
		}
		if parent.UserID != subject.ID || parent.Type != folderType {
			return model.Folder{}, fmt.Errorf("%w: invalid parent folder", ErrForbidden)
		}
		if err := s.require(ctx, actor, subject, mode, authz.FolderChildrenCreate, parent.ID); err != nil {
			return model.Folder{}, err
		}
		path = parent.Path + "/" + name
	} else if err := s.requireAccountContext(ctx, actor, subject, mode); err != nil {
		return model.Folder{}, err
	}
	if err := s.folders.Create(ctx, subject.ID, path, folderType, parentID); err != nil {
		return model.Folder{}, err
	}
	return s.folders.GetByPath(ctx, subject.ID, path)
}

func (s *Workspace) MoveFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID, parentID, name string) (model.Folder, error) {
	folder, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	if err := s.requireFolderTree(ctx, actor, subject, mode, folder, authz.FolderMetadataWrite, false); err != nil {
		return model.Folder{}, err
	}
	if parentID != "" {
		if err := s.require(ctx, actor, subject, mode, authz.FolderChildrenCreate, parentID); err != nil {
			return model.Folder{}, err
		}
	} else if folder.UserID != subject.ID {
		return model.Folder{}, ErrForbidden
	}
	if err := s.folders.Move(ctx, folder.ID, parentID, name); err != nil {
		return model.Folder{}, err
	}
	return s.folders.Get(ctx, folder.ID)
}

func (s *Workspace) TrashFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string) error {
	folder, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return err
	}
	if err := s.requireFolderTree(ctx, actor, subject, mode, folder, authz.FolderChildrenDelete, false); err != nil {
		return err
	}
	return s.folders.Trash(ctx, folderID, s.trashRetention())
}

func (s *Workspace) RestoreFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string) (model.Folder, error) {
	folder, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	if err := s.requireFolderTree(ctx, actor, subject, mode, folder, authz.FolderMetadataWrite, true); err != nil {
		return model.Folder{}, err
	}
	if err := s.folders.Restore(ctx, folderID); err != nil {
		return model.Folder{}, err
	}
	return s.folders.Get(ctx, folderID)
}

func (s *Workspace) ListItems(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string) ([]ItemSummary, error) {
	storedItems, err := s.ListItemMetadata(ctx, actor, subject, mode, folderID, authz.FolderItemsList)
	if err != nil {
		return nil, err
	}
	items := make([]ItemSummary, 0, len(storedItems))
	for _, item := range storedItems {
		items = append(items, ItemSummary{
			ID: item.ID, Name: item.Name, FolderID: item.FolderID, Headers: item.Headers, Size: item.Size,
			UID: item.UID, ModSeq: item.ModSeq, Flags: item.Flags, InternalDate: item.InternalDate.UTC().Format(time.RFC3339Nano),
			Previewable: ContentPreviewable(item.Headers["Content-Type"], item.Size),
		})
	}
	return items, nil
}

// ListItemMetadata returns the folder's items without payloads, keeping every
// stored metadata field, in descending UID order. action is the folder
// permission the caller needs: FolderItemsList for a listing, or
// FolderItemsRead when the metadata stands in for a content read.
func (s *Workspace) ListItemMetadata(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, action authz.Action) ([]model.Item, error) {
	if err := s.require(ctx, actor, subject, mode, action, folderID); err != nil {
		return nil, err
	}
	storedItems, err := s.items.ListMetadata(ctx, folderID)
	if err != nil {
		return nil, err
	}
	items := storedItems[:0]
	for _, item := range storedItems {
		if item.FolderID == folderID {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UID > items[j].UID })
	return items, nil
}

func (s *Workspace) ListItemPage(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, beforeUID uint32, limit int) (ItemSummaryPage, error) {
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsList, folderID); err != nil {
		return ItemSummaryPage{}, err
	}
	if limit < 1 || limit > MaxItemPageLimit {
		return ItemSummaryPage{}, errMaxItemPageLimit
	}
	storedItems, total, nextBeforeUID, err := s.items.ListMetadataPage(ctx, folderID, beforeUID, limit)
	if err != nil {
		return ItemSummaryPage{}, err
	}
	page := ItemSummaryPage{Items: make([]ItemSummary, 0, len(storedItems)), Total: total, NextBeforeUID: nextBeforeUID}
	for _, item := range storedItems {
		page.Items = append(page.Items, ItemSummary{
			ID: item.ID, Name: item.Name, FolderID: item.FolderID, Headers: item.Headers, Size: item.Size,
			UID: item.UID, ModSeq: item.ModSeq, Flags: item.Flags, InternalDate: item.InternalDate.UTC().Format(time.RFC3339Nano),
			Previewable: ContentPreviewable(item.Headers["Content-Type"], item.Size),
		})
	}
	return page, nil
}

// ListDateItemPage exposes the model's durable chronological index only after
// the same folder-list authorization as every other FolderSpace enumeration.
func (s *Workspace) ListDateItemPage(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID, cursor string, limit int, includeData bool) (ItemPage, error) {
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsList, folderID); err != nil {
		return ItemPage{}, err
	}
	if includeData {
		if err := s.require(ctx, actor, subject, mode, authz.FolderItemsRead, folderID); err != nil {
			return ItemPage{}, err
		}
	}
	if limit < 1 || limit > MaxItemPageLimit {
		return ItemPage{}, errMaxItemPageLimit
	}
	items, total, nextCursor, err := s.items.ListDatePage(ctx, folderID, cursor, limit, includeData)
	if err != nil {
		return ItemPage{}, err
	}
	return ItemPage{Items: items, Total: total, NextCursor: nextCursor}, nil
}

// ListDateItemWindow returns the anchor and at most one chronological neighbor
// on either side. The folder authorization and metadata-only default match
// ListDateItemPage, while the model's durable date index bounds the result.
func (s *Workspace) ListDateItemWindow(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID, anchorItemID string, includeData bool) (ItemPage, error) {
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsList, folderID); err != nil {
		return ItemPage{}, err
	}
	if includeData {
		if err := s.require(ctx, actor, subject, mode, authz.FolderItemsRead, folderID); err != nil {
			return ItemPage{}, err
		}
	}
	items, total, err := s.items.ListDateWindow(ctx, folderID, anchorItemID, includeData)
	if err != nil {
		return ItemPage{}, err
	}
	return ItemPage{Items: items, Total: total}, nil
}

func (s *Workspace) ListFullItemPage(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, beforeUID uint32, limit int) (ItemPage, error) {
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsList, folderID); err != nil {
		return ItemPage{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsRead, folderID); err != nil {
		return ItemPage{}, err
	}
	if limit < 1 || limit > MaxItemPageLimit {
		return ItemPage{}, errMaxItemPageLimit
	}
	items, total, nextBeforeUID, err := s.items.ListPage(ctx, folderID, beforeUID, limit)
	if err != nil {
		return ItemPage{}, err
	}
	return ItemPage{Items: items, Total: total, NextBeforeUID: nextBeforeUID}, nil
}

func (s *Workspace) GetItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) (model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsRead, item.FolderID); err != nil {
		return model.Item{}, err
	}
	return item, nil
}

func (s *Workspace) ListTrash(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode) ([]ItemSummary, error) {
	if err := s.requireAccountContext(ctx, actor, subject, mode); err != nil {
		return nil, err
	}
	items, err := s.items.ListTrashedForUser(ctx, subject.ID)
	if err != nil {
		return nil, err
	}
	summaries := make([]ItemSummary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, ItemSummary{
			ID: item.ID, Name: item.Name, FolderID: item.FolderID, Headers: item.Headers, Size: item.Size,
			UID: item.UID, Flags: item.Flags, InternalDate: item.InternalDate.UTC().Format(time.RFC3339),
			Previewable: ContentPreviewable(item.Headers["Content-Type"], item.Size),
			TrashedAt:   item.TrashedAt.UTC().Format(time.RFC3339), PurgeAfter: item.PurgeAfter.UTC().Format(time.RFC3339), OriginalFolderID: item.OriginalFolderID, OriginalName: item.OriginalName,
		})
	}
	return summaries, nil
}

func (s *Workspace) ListTrashedFolders(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode) ([]model.Folder, error) {
	if err := s.requireAccountContext(ctx, actor, subject, mode); err != nil {
		return nil, err
	}
	folders, err := s.folders.ListTrashedForUser(ctx, subject.ID)
	if err != nil {
		return nil, err
	}
	trashed := make(map[string]struct{}, len(folders))
	for _, folder := range folders {
		trashed[folder.ID] = struct{}{}
	}
	roots := make([]model.Folder, 0, len(folders))
	for _, folder := range folders {
		if _, parentIsTrashed := trashed[folder.OriginalParentID]; !parentIsTrashed {
			roots = append(roots, folder)
		}
	}
	return roots, nil
}

func (s *Workspace) PurgeFolder(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string) error {
	folder, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return err
	}
	if folder.TrashedAt.IsZero() {
		return fmt.Errorf("%w: folder is not in trash", ErrInvalidRequest)
	}
	if err := s.requireFolderTree(ctx, actor, subject, mode, folder, authz.FolderItemsExpunge, true); err != nil {
		return err
	}
	all, err := s.folders.ListTrashedForUser(ctx, folder.UserID)
	if err != nil {
		return err
	}
	tree := make([]model.Folder, 0)
	for _, candidate := range all {
		if candidate.ID == folder.ID || strings.HasPrefix(candidate.OriginalPath, folder.OriginalPath+"/") {
			tree = append(tree, candidate)
		}
	}
	sort.Slice(tree, func(i, j int) bool { return len(tree[i].OriginalPath) > len(tree[j].OriginalPath) })
	for _, candidate := range tree {
		ids, listErr := s.items.List(ctx, candidate.ID)
		if listErr != nil {
			return listErr
		}
		for _, id := range ids {
			if err := s.items.Delete(ctx, id); err != nil {
				return err
			}
		}
		if err := s.folders.Delete(ctx, candidate.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Workspace) requireFolderTree(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, root model.Folder, action authz.Action, trashed bool) error {
	if actor == subject && subject.Kind == model.PrincipalUser && subject.ID == root.UserID {
		return s.require(ctx, actor, subject, mode, action, root.ID)
	}
	var folders []model.Folder
	var err error
	rootPath := root.Path
	if trashed {
		folders, err = s.folders.ListTrashedForUser(ctx, root.UserID)
		rootPath = root.OriginalPath
	} else {
		folders, err = s.folders.ListForUser(ctx, root.UserID)
	}
	if err != nil {
		return err
	}
	for _, folder := range folders {
		path := folder.Path
		if trashed {
			path = folder.OriginalPath
		}
		if folder.ID != root.ID && !strings.HasPrefix(path, rootPath+"/") {
			continue
		}
		if err := s.require(ctx, actor, subject, mode, action, folder.ID); err != nil {
			return err
		}
	}
	return nil
}

// CreateItem appends data to a folder after checking the caller's create right.
func (s *Workspace) CreateItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, data []byte, headers map[string]string) (string, error) {
	item, err := s.CreateItemRecord(ctx, actor, subject, mode, folderID, model.Item{Data: data, Headers: headers})
	return item.ID, err
}

// CreateItemRecord appends a complete item after checking the caller's create
// right. ItemStore remains responsible for identity, UID, quota, and indexes.
func (s *Workspace) CreateItemRecord(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID string, item model.Item) (model.Item, error) {
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsCreate, folderID); err != nil {
		return model.Item{}, err
	}
	return s.items.AppendItem(ctx, folderID, item)
}

// PutNamedItem creates or replaces a protocol-named item while keeping REST
// identity separate from its mutable filename/resource name.
func (s *Workspace) PutNamedItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, folderID, name string, data []byte, headers map[string]string) (model.Item, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/\\") {
		return model.Item{}, fmt.Errorf("%w: a single-segment item name is required", ErrInvalidRequest)
	}
	if existing, err := s.items.Get(ctx, model.ItemKey(folderID, name)); err == nil && existing.TrashedAt.IsZero() {
		return s.UpdateItem(ctx, actor, subject, mode, existing.ID, data, headers)
	}
	id, err := s.CreateItem(ctx, actor, subject, mode, folderID, data, headers)
	if err != nil {
		return model.Item{}, err
	}
	item, err := s.items.Get(ctx, id)
	if err != nil {
		return model.Item{}, err
	}
	item.Name = name
	if err := s.items.SetItem(ctx, item); err != nil {
		_ = s.items.Delete(ctx, item.ID)
		return model.Item{}, err
	}
	return item, nil
}

// UpdateItem replaces an item's payload while preserving its storage identity
// and IMAP bookkeeping fields.
func (s *Workspace) UpdateItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, data []byte, headers map[string]string) (model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsUpdate, item.FolderID); err != nil {
		return model.Item{}, err
	}
	return s.items.UpdateContent(ctx, itemID, data, headers)
}

// DeleteItem removes an item after checking the caller's delete right.
func (s *Workspace) DeleteItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) error {
	_, err := s.DeleteItemWithTombstone(ctx, actor, subject, mode, itemID)
	return err
}

// DeleteItemWithTombstone removes an item and returns the final metadata needed
// by incremental protocols. The deletion receives its own mailbox mod-sequence
// before the live record is removed.
func (s *Workspace) DeleteItemWithTombstone(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) (model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsDelete, item.FolderID); err != nil {
		return model.Item{}, err
	}
	if err := s.items.UpdateModSeq(ctx, itemID); err != nil {
		return model.Item{}, err
	}
	item, err = s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.items.Delete(ctx, itemID); err != nil {
		return model.Item{}, err
	}
	return item, nil
}

func (s *Workspace) SetItemRead(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, read bool) (model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsUpdate, item.FolderID); err != nil {
		return model.Item{}, err
	}
	if read {
		err = s.items.AddFlags(ctx, item.ID, model.FlagSeen)
	} else {
		err = s.items.RemoveFlags(ctx, item.ID, model.FlagSeen)
	}
	if err != nil {
		return model.Item{}, err
	}
	return s.items.Get(ctx, item.ID)
}

func (s *Workspace) SetItemFlagged(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, flagged bool) (model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsUpdate, item.FolderID); err != nil {
		return model.Item{}, err
	}
	if flagged {
		err = s.items.AddFlags(ctx, item.ID, model.FlagFlagged)
	} else {
		err = s.items.RemoveFlags(ctx, item.ID, model.FlagFlagged)
	}
	if err != nil {
		return model.Item{}, err
	}
	return s.items.Get(ctx, item.ID)
}

func (s *Workspace) SetItemDraft(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string, draft bool) (model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsUpdate, item.FolderID); err != nil {
		return model.Item{}, err
	}
	if draft {
		err = s.items.AddFlags(ctx, item.ID, model.FlagDraft)
	} else {
		err = s.items.RemoveFlags(ctx, item.ID, model.FlagDraft)
	}
	if err != nil {
		return model.Item{}, err
	}
	return s.items.Get(ctx, item.ID)
}

func (s *Workspace) MoveItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID, destinationFolderID string) (model.Item, error) {
	return s.MoveItemNamed(ctx, actor, subject, mode, itemID, destinationFolderID, "")
}

func (s *Workspace) MoveItemNamed(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID, destinationFolderID, destinationName string) (model.Item, error) {
	item, _, err := s.MoveItemNamedWithTombstone(ctx, actor, subject, mode, itemID, destinationFolderID, destinationName)
	return item, err
}

func (s *Workspace) MoveItemNamedWithTombstone(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID, destinationFolderID, destinationName string) (model.Item, model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, model.Item{}, err
	}
	source, err := s.folders.Get(ctx, item.FolderID)
	if err != nil {
		return model.Item{}, model.Item{}, err
	}
	destination, err := s.folders.Get(ctx, destinationFolderID)
	if err != nil {
		return model.Item{}, model.Item{}, err
	}
	if source.Type != destination.Type {
		return model.Item{}, model.Item{}, fmt.Errorf("%w: items cannot move between workspace types", ErrForbidden)
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsDelete, item.FolderID); err != nil {
		return model.Item{}, model.Item{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsCreate, destinationFolderID); err != nil {
		return model.Item{}, model.Item{}, err
	}
	if destinationName == "" {
		destinationName = item.Name
	}
	return s.items.MoveWithTombstone(ctx, item.ID, destinationFolderID, destinationName)
}

func (s *Workspace) TrashItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) (model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsDelete, item.FolderID); err != nil {
		return model.Item{}, err
	}
	folder, err := s.folders.Get(ctx, item.FolderID)
	if err != nil {
		return model.Item{}, err
	}
	trashFolderID := ""
	if folder.Type == model.FolderTypeMail {
		if trash, trashErr := s.folders.SpecialFolder(ctx, folder.UserID, model.SpecialUseTrash); trashErr == nil {
			if permissionErr := s.require(ctx, actor, subject, mode, authz.FolderItemsCreate, trash.ID); permissionErr == nil {
				trashFolderID = trash.ID
			}
		}
	}
	return s.items.Trash(ctx, item.ID, trashFolderID, s.trashRetention())
}

func (s *Workspace) RestoreItem(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, itemID string) (model.Item, error) {
	item, err := s.items.Get(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if item.OriginalFolderID == "" {
		return model.Item{}, fmt.Errorf("%w: item has no restore destination", ErrInvalidRequest)
	}
	if err := s.require(ctx, actor, subject, mode, authz.FolderItemsCreate, item.OriginalFolderID); err != nil {
		return model.Item{}, err
	}
	return s.items.Restore(ctx, item.ID)
}

func validFolderType(folderType model.FolderType) bool {
	switch folderType {
	case model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeTasks, model.FolderTypeContacts, model.FolderTypeFiles,
		model.FolderTypeNotes, model.FolderTypeSieve, model.FolderTypeScheduleInbox, model.FolderTypeScheduleOutbox,
		model.FolderTypeSavedSearch, model.FolderTypeMailTemplate:
		return true
	default:
		return false
	}
}

func (s *Workspace) requireAccountContext(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode) error {
	if actor == subject && mode == authz.ActingNone {
		return nil
	}
	action := authz.AccountDelegate
	if mode == authz.ActingImpersonation {
		action = authz.AccountImpersonate
	}
	decision, err := s.authorizer.Check(ctx, authz.Request{
		Actor: actor, Subject: actor, Action: action,
		Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: subject.ID},
	})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fmt.Errorf("%w: %s", ErrForbidden, decision.Reason)
	}
	return nil
}

func (s *Workspace) require(ctx context.Context, actor, subject model.PrincipalRef, mode authz.ActingMode, action authz.Action, folderID string) error {
	decision, err := s.authorizer.Check(ctx, authz.Request{
		Actor: actor, Subject: subject, Mode: mode, Action: action,
		Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folderID},
	})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fmt.Errorf("%w: %s", ErrForbidden, decision.Reason)
	}
	return nil
}
