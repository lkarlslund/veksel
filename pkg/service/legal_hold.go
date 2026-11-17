package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// legalHoldBox lets an interface value live in an atomic pointer.
type legalHoldBox struct{ checker LegalHoldChecker }

// SetLegalHolds installs the hold registry consulted by every destructive
// operation. FolderSpaceService is the single layer every protocol, the web
// workspace, retention, and trash purge reach to destroy an item.
func (s *FolderSpaceService) SetLegalHolds(checker LegalHoldChecker) {
	if checker == nil {
		s.legalHolds.Store(nil)
		return
	}
	s.legalHolds.Store(&legalHoldBox{checker: checker})
}

func (s *FolderSpaceService) accountHeld(ctx context.Context, accountID string) bool {
	box := s.legalHolds.Load()
	return box != nil && accountID != "" && box.checker.AccountHeld(ctx, accountID)
}

// requireVisibleFolder hides held-deleted folders from everyone but
// compliance access.
func (s *FolderSpaceService) requireVisibleFolder(ctx context.Context, access AccessContext, folderID string) error {
	if heldVisible(access) {
		return nil
	}
	return s.requireUserFolder(ctx, folderID)
}

// requireUserFolder refuses writing into a held-deleted folder. Only a
// deletion under hold places items there.
func (s *FolderSpaceService) requireUserFolder(ctx context.Context, folderID string) error {
	folder, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return err
	}
	if model.IsHeldDeletedFolder(folder) {
		return store.ErrNotFound
	}
	return nil
}

func legalHoldError(accountID string) error {
	return fmt.Errorf("%w: account %s is under legal hold", ErrLegalHold, accountID)
}

// preserveDeletedItem replaces a user's deletion of item, owned by a held
// account, with a move into the hidden held-deleted folder. Users and their
// clients observe a normal destroy; compliance access finds the item intact.
// Policy deletions and deletions of already preserved items are refused.
func (s *FolderSpaceService) preserveDeletedItem(ctx context.Context, access AccessContext, item model.Item, folder model.Folder) error {
	if systemDeletion(access) || !item.HeldDeletedAt.IsZero() {
		return legalHoldError(folder.UserID)
	}
	held, err := s.folders.EnsureHeldDeletedFolder(ctx, folder.UserID, folder.Type)
	if err != nil {
		return err
	}
	fromPath := folder.Path
	if !folder.TrashedAt.IsZero() {
		fromPath = folder.OriginalPath
	}
	var preserved, tombstone model.Item
	return s.commitChange(ctx, func(batchCtx context.Context) error {
		var err error
		preserved, tombstone, err = s.items.HoldDeleted(batchCtx, item.ID, held.ID, fromPath, time.Now())
		return err
	}, func() []Change {
		return []Change{itemChange(ChangeDestroy, tombstone, ""), itemChange(ChangeCreate, preserved, "")}
	})
}

// preservePurgedFolder purges a trashed folder tree of a held account by
// preserving every item it contains before removing the empty folders.
func (s *FolderSpaceService) preservePurgedFolder(ctx context.Context, access AccessContext, root model.Folder) error {
	if systemDeletion(access) {
		return legalHoldError(root.UserID)
	}
	if root.TrashedAt.IsZero() {
		return fmt.Errorf("folder is not in trash")
	}
	if err := s.workspace.requireFolderTree(ctx, access.Actor, access.Subject, access.Mode, root, authz.FolderItemsExpunge, true); err != nil {
		return err
	}
	tree, err := s.trashedFolderTree(ctx, root)
	if err != nil {
		return err
	}
	sort.Slice(tree, func(i, j int) bool { return len(tree[i].OriginalPath) > len(tree[j].OriginalPath) })
	held, err := s.folders.EnsureHeldDeletedFolder(ctx, root.UserID, root.Type)
	if err != nil {
		return err
	}
	var effects []Change
	return s.commitChange(ctx, func(batchCtx context.Context) error {
		now := time.Now()
		for _, folder := range tree {
			ids, err := s.items.List(batchCtx, folder.ID)
			if err != nil {
				return err
			}
			for _, id := range ids {
				preserved, tombstone, err := s.items.HoldDeleted(batchCtx, id, held.ID, folder.OriginalPath, now)
				if err != nil {
					return err
				}
				effects = append(effects, itemChange(ChangeDestroy, tombstone, ""), itemChange(ChangeCreate, preserved, ""))
			}
			if err := s.folders.Delete(batchCtx, folder.ID); err != nil {
				return err
			}
			effects = append(effects, folderChange(ChangeDestroy, folder, folder.OriginalParentID))
		}
		return nil
	}, func() []Change { return effects })
}

// filterHeldChanges removes changes inside held-deleted folders so a user's
// incremental clients see a preserved item only as destroyed.
func (s *FolderSpaceService) filterHeldChanges(ctx context.Context, page ChangePage) ChangePage {
	hidden := make(map[string]bool)
	isHidden := func(folderID string) bool {
		if folderID == "" {
			return false
		}
		value, known := hidden[folderID]
		if !known {
			folder, err := s.folders.Get(ctx, folderID)
			value = err == nil && model.IsHeldDeletedFolder(folder)
			hidden[folderID] = value
		}
		return value
	}
	filtered := page.Records[:0]
	for _, record := range page.Records {
		changes := record.Changes[:0]
		for _, change := range record.Changes {
			if !isHidden(change.FolderID) {
				changes = append(changes, change)
			}
		}
		if len(changes) > 0 {
			record.Changes = changes
			filtered = append(filtered, record)
		}
	}
	page.Records = filtered
	return page
}

// preservedLocations reports which of ids survived a deletion because legal
// hold preserved them, with their held-deleted folders.
func (s *FolderSpaceService) preservedLocations(ctx context.Context, ids []string) (map[string]string, []model.Folder, error) {
	preserved := make(map[string]string)
	var held []model.Folder
	for _, id := range ids {
		item, err := s.items.GetMetadata(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if item.HeldDeletedAt.IsZero() {
			continue
		}
		preserved[id] = item.FolderID
		if !slices.ContainsFunc(held, func(folder model.Folder) bool { return folder.ID == item.FolderID }) {
			folder, err := s.folders.Get(ctx, item.FolderID)
			if err != nil {
				return nil, nil, err
			}
			held = append(held, folder)
		}
	}
	return preserved, held, nil
}
