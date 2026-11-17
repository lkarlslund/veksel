package model

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// SpecialUseHeldDeletedPrefix marks the hidden per-type folders that preserve
// items a user deleted while their account was under legal hold.
const SpecialUseHeldDeletedPrefix = "held-deleted-"

// HeldDeletedSpecialUse is the special use of the held-deleted folder for ft.
func HeldDeletedSpecialUse(ft FolderType) string { return SpecialUseHeldDeletedPrefix + string(ft) }

// HeldDeletedFolderID returns the immutable ID of userID's held-deleted
// folder for ft.
func HeldDeletedFolderID(userID string, ft FolderType) string {
	return specialFolderID(userID, HeldDeletedSpecialUse(ft))
}

// IsHeldDeletedFolder reports whether folder preserves held-deleted items.
func IsHeldDeletedFolder(folder Folder) bool {
	return strings.HasPrefix(folder.SpecialUse, SpecialUseHeldDeletedPrefix)
}

// EnsureHeldDeletedFolder returns userID's hidden held-deleted folder for ft,
// creating it on first use. The folder is a system folder that is never
// subscribed and that FolderSpace hides from everyone but compliance access.
func (fs *FolderStore) EnsureHeldDeletedFolder(ctx context.Context, userID string, ft FolderType) (Folder, error) {
	id := HeldDeletedFolderID(userID, ft)
	if folder, err := fs.Get(ctx, id); err == nil {
		return folder, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return Folder{}, err
	}
	err := fs.create(ctx, userID, ".held-deleted-"+string(ft), ft, "", true, HeldDeletedSpecialUse(ft), false)
	if err != nil && !errors.Is(err, store.ErrExists) {
		return Folder{}, err
	}
	return fs.Get(ctx, id)
}

// HoldDeleted moves an item into heldFolderID instead of destroying it and
// stamps the preservation metadata. It returns the preserved item and the
// tombstone of its previous location for incremental protocols. A trashed
// item leaves the owner's trash listing.
func (is *ItemStore) HoldDeleted(ctx context.Context, id, heldFolderID, fromPath string, now time.Time) (Item, Item, error) {
	var preserved, tombstone Item
	err := store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		before, err := is.GetMetadata(batchCtx, id)
		if err != nil {
			return err
		}
		heldFolder, err := is.getFolder(batchCtx, heldFolderID)
		if err != nil {
			return err
		}
		preserved, tombstone, err = is.MoveWithTombstone(batchCtx, id, heldFolderID, id+".held")
		if err != nil {
			return err
		}
		preserved.HeldDeletedAt = now.UTC()
		preserved.HeldDeletedFrom = fromPath
		preserved.TrashedAt, preserved.PurgeAfter = time.Time{}, time.Time{}
		if err := is.SetItem(batchCtx, preserved); err != nil {
			return err
		}
		if !before.TrashedAt.IsZero() {
			if err := is.ts.Delete(batchCtx, NSItems, TrashedItemKey(heldFolder.UserID, id)); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return nil
	})
	return preserved, tombstone, err
}
