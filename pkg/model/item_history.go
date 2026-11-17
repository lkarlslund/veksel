package model

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/objectstore"
	"github.com/lkarlslund/veksel/pkg/store"
)

const itemHistoryUsageVersion = 1

var ErrItemHistoryConflict = errors.New("item history restore conflict")

type storedItemVersion struct {
	ItemVersion
	Payload *objectstore.Ref `json:"payload_ref,omitempty"`
}

// ItemHistoryStore persists immutable snapshots separately from the protocol
// change journal. It is backend-neutral and uses the same account-local store
// and immutable object log as current items.
type ItemHistoryStore struct {
	ts *TypedStore
}

func NewItemHistoryStore(ts *TypedStore) *ItemHistoryStore {
	return &ItemHistoryStore{ts: ts}
}

func (s *ItemHistoryStore) Ensure(ctx context.Context) error {
	if store.InBatch(ctx, s.ts.Store()) {
		return nil
	}
	return s.ts.EnsureNamespace(ctx, NSItemHistory)
}

func (s *ItemHistoryStore) ensure(ctx context.Context) error {
	return s.Ensure(ctx)
}

// Capture stores the current item when its folder has history enabled. The
// returned boolean is false when the capability is disabled for the folder.
func (s *ItemHistoryStore) Capture(ctx context.Context, item Item, operation ItemHistoryOperation) (version ItemVersion, captured bool, err error) {
	if err := s.ensure(ctx); err != nil {
		return ItemVersion{}, false, err
	}
	folder, err := s.ts.FolderStore().Get(ctx, item.FolderID)
	if err != nil {
		return ItemVersion{}, false, err
	}
	if !folder.History.Enabled {
		return ItemVersion{}, false, nil
	}
	if item.ID == "" || item.FolderID == "" {
		return ItemVersion{}, false, errors.New("history snapshot requires item and folder IDs")
	}

	err = store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		folder, err = s.ts.FolderStore().Get(batchCtx, item.FolderID)
		if err != nil {
			return err
		}
		if !folder.History.Enabled {
			return nil
		}
		if folder.HistoryUsageVersion != itemHistoryUsageVersion {
			if err := s.rebuildFolderAccounting(batchCtx, &folder); err != nil {
				return err
			}
		}
		now := time.Now().UTC()
		if _, err := s.pruneItem(batchCtx, &folder, item.ID, now, 1); err != nil {
			return err
		}
		id, err := newResourceID("ver")
		if err != nil {
			return err
		}
		version = ItemVersion{
			ID: id, UserID: folder.UserID, FolderID: folder.ID, ItemID: item.ID,
			Operation: operation, Item: cloneHistoryItem(item), CapturedAt: now,
		}
		stored := storedItemVersion{ItemVersion: version}
		if s.ts.objects != nil {
			current, currentErr := s.ts.ItemStore().getStored(batchCtx, item.ID)
			if currentErr == nil && current.Payload != nil && payloadMatches(*current.Payload, item.Data) {
				stored.Payload = current.Payload
				stored.Item.Data = nil
			} else {
				ref, putErr := s.ts.objects.Put(batchCtx, objectstore.Header{
					ItemID: id, FolderID: folder.ID, ContentType: folderContentType(folder.Type),
				}, int64(len(item.Data)), bytes.NewReader(item.Data))
				if putErr != nil {
					return fmt.Errorf("store history payload: %w", putErr)
				}
				stored.Payload = &ref
				stored.Item.Data = nil
			}
		}
		if err := s.ts.UserStore().AdjustUsage(batchCtx, folder.UserID, item.Size, 0); err != nil {
			return err
		}
		if err := s.ts.Set(batchCtx, NSItemHistory, historyVersionKey(id), stored); err != nil {
			return err
		}
		if err := s.ts.Set(batchCtx, NSItemHistory, historyIndexKey(folder.ID, item.ID, now, id), id); err != nil {
			return err
		}
		adjustHistoryUsage(&folder, 1, item.Size)
		if err := s.ts.Set(batchCtx, NSFolders, folder.ID, folder); err != nil {
			return err
		}
		captured = true
		return nil
	})
	return version, captured, err
}

// List returns newest-first metadata without materializing version payloads.
func (s *ItemHistoryStore) List(ctx context.Context, folderID, itemID string) ([]ItemVersion, error) {
	if err := s.ensure(ctx); err != nil {
		return nil, err
	}
	stored, err := s.listStored(ctx, historyItemPrefix(folderID, itemID))
	if err != nil {
		return nil, err
	}
	versions := make([]ItemVersion, 0, len(stored))
	for _, candidate := range stored {
		version := candidate.ItemVersion
		version.Item.Data = nil
		versions = append(versions, version)
	}
	sortVersions(versions)
	return versions, nil
}

// Get returns one complete version and verifies its folder and item scope.
func (s *ItemHistoryStore) Get(ctx context.Context, folderID, itemID, versionID string) (ItemVersion, error) {
	if err := s.ensure(ctx); err != nil {
		return ItemVersion{}, err
	}
	version, err := s.GetByID(ctx, versionID)
	if err != nil {
		return ItemVersion{}, err
	}
	if version.FolderID != folderID || version.ItemID != itemID {
		return ItemVersion{}, store.ErrNotFound
	}
	return version, nil
}

// GetByID returns one complete version without imposing a caller-visible
// folder scope. It is intended for account integrity and logical transfer.
func (s *ItemHistoryStore) GetByID(ctx context.Context, versionID string) (ItemVersion, error) {
	if err := s.ensure(ctx); err != nil {
		return ItemVersion{}, err
	}
	var stored storedItemVersion
	if err := s.ts.Get(ctx, NSItemHistory, historyVersionKey(versionID), &stored); err != nil {
		return ItemVersion{}, err
	}
	version := stored.ItemVersion
	if stored.Payload != nil {
		if s.ts.objects == nil {
			return ItemVersion{}, errors.New("history version references object storage but no object store is open")
		}
		var payload bytes.Buffer
		if err := s.ts.objects.Read(ctx, *stored.Payload, &payload); err != nil {
			return ItemVersion{}, fmt.Errorf("read history payload %s: %w", version.ID, err)
		}
		version.Item.Data = payload.Bytes()
	}
	return version, nil
}

// ListAll returns complete logical snapshots in deterministic order. Physical
// object references are deliberately materialized so account conversion and
// portable bundles cannot retain references into the source object log.
func (s *ItemHistoryStore) ListAll(ctx context.Context) ([]ItemVersion, error) {
	if err := s.ensure(ctx); err != nil {
		return nil, err
	}
	keys, err := s.ts.Scan(ctx, NSItemHistory, "version:")
	if err != nil {
		return nil, err
	}
	slices.Sort(keys)
	versions := make([]ItemVersion, 0, len(keys))
	for _, key := range keys {
		version, err := s.GetByID(ctx, strings.TrimPrefix(key, "version:"))
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, nil
}

// RestoreSnapshot writes an already-accounted logical snapshot during account
// conversion or bundle restore. Folder and user counters are copied as part of
// the same account image, so this method intentionally does not adjust them.
func (s *ItemHistoryStore) RestoreSnapshot(ctx context.Context, version ItemVersion) error {
	if version.ID == "" || version.UserID == "" || version.FolderID == "" || version.ItemID == "" || version.CapturedAt.IsZero() {
		return errors.New("invalid item history snapshot")
	}
	if err := s.Ensure(ctx); err != nil {
		return err
	}
	return store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		var existing storedItemVersion
		existingErr := s.ts.Get(batchCtx, NSItemHistory, historyVersionKey(version.ID), &existing)
		if existingErr == nil {
			logical, err := s.GetByID(batchCtx, version.ID)
			if err != nil {
				return err
			}
			if !itemVersionsEqual(logical, version) {
				return fmt.Errorf("restore history version %s: %w", version.ID, store.ErrExists)
			}
			return nil
		}
		if !errors.Is(existingErr, store.ErrNotFound) {
			return existingErr
		}
		stored := storedItemVersion{ItemVersion: version}
		stored.Item = cloneHistoryItem(version.Item)
		if s.ts.objects != nil {
			folder, err := s.ts.FolderStore().Get(batchCtx, version.FolderID)
			if err != nil {
				return fmt.Errorf("read history folder: %w", err)
			}
			ref, err := s.ts.objects.Put(batchCtx, objectstore.Header{
				ItemID: version.ID, FolderID: version.FolderID, ContentType: folderContentType(folder.Type),
			}, int64(len(version.Item.Data)), bytes.NewReader(version.Item.Data))
			if err != nil {
				return fmt.Errorf("restore history payload: %w", err)
			}
			stored.Payload = &ref
			stored.Item.Data = nil
		}
		if err := s.ts.Set(batchCtx, NSItemHistory, historyVersionKey(version.ID), stored); err != nil {
			return err
		}
		return s.ts.Set(batchCtx, NSItemHistory, historyIndexKey(version.FolderID, version.ItemID, version.CapturedAt, version.ID), version.ID)
	})
}

// PruneFolder applies age and per-item bounds and returns removed versions.
func (s *ItemHistoryStore) PruneFolder(ctx context.Context, folderID string, now time.Time) (removed int, err error) {
	if err := s.ensure(ctx); err != nil {
		return 0, err
	}
	err = store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		folder, err := s.ts.FolderStore().Get(batchCtx, folderID)
		if err != nil {
			return err
		}
		if folder.HistoryUsageVersion != itemHistoryUsageVersion {
			if err := s.rebuildFolderAccounting(batchCtx, &folder); err != nil {
				return err
			}
		}
		stored, err := s.listStored(batchCtx, historyFolderPrefix(folderID))
		if err != nil {
			return err
		}
		items := make(map[string]struct{}, len(stored))
		for _, candidate := range stored {
			items[candidate.ItemID] = struct{}{}
		}
		for itemID := range items {
			count, pruneErr := s.pruneItem(batchCtx, &folder, itemID, now, 0)
			if pruneErr != nil {
				return pruneErr
			}
			removed += count
		}
		return s.ts.Set(batchCtx, NSFolders, folder.ID, folder)
	})
	return removed, err
}

// DeleteFolder removes every retained version before a folder is purged.
func (s *ItemHistoryStore) DeleteFolder(ctx context.Context, folderID string) (removed int, err error) {
	if err := s.ensure(ctx); err != nil {
		return 0, err
	}
	err = store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		folder, err := s.ts.FolderStore().Get(batchCtx, folderID)
		if err != nil {
			return err
		}
		stored, err := s.listStored(batchCtx, historyFolderPrefix(folderID))
		if err != nil {
			return err
		}
		for _, candidate := range stored {
			if err := s.deleteVersion(batchCtx, &folder, candidate); err != nil {
				return err
			}
			removed++
		}
		return s.ts.Set(batchCtx, NSFolders, folder.ID, folder)
	})
	return removed, err
}

func (s *ItemHistoryStore) pruneItem(ctx context.Context, folder *Folder, itemID string, now time.Time, reserve int) (int, error) {
	stored, err := s.listStored(ctx, historyItemPrefix(folder.ID, itemID))
	if err != nil {
		return 0, err
	}
	sort.Slice(stored, func(i, j int) bool {
		if stored[i].CapturedAt.Equal(stored[j].CapturedAt) {
			return stored[i].ID > stored[j].ID
		}
		return stored[i].CapturedAt.After(stored[j].CapturedAt)
	})
	keep := folder.History.MaxVersions - reserve
	if folder.History.MaxVersions == 0 {
		keep = len(stored)
	}
	if keep < 0 {
		keep = 0
	}
	cutoff := time.Time{}
	if folder.History.RetentionDays > 0 {
		cutoff = now.Add(-time.Duration(folder.History.RetentionDays) * 24 * time.Hour)
	}
	removed := 0
	retained := 0
	for _, candidate := range stored {
		expired := !cutoff.IsZero() && candidate.CapturedAt.Before(cutoff)
		overLimit := !expired && retained >= keep
		if expired || overLimit {
			if err := s.deleteVersion(ctx, folder, candidate); err != nil {
				return removed, err
			}
			removed++
			continue
		}
		retained++
	}
	return removed, nil
}

func (s *ItemHistoryStore) deleteVersion(ctx context.Context, folder *Folder, stored storedItemVersion) error {
	if err := s.ts.Delete(ctx, NSItemHistory, historyVersionKey(stored.ID)); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := s.ts.Delete(ctx, NSItemHistory, historyIndexKey(stored.FolderID, stored.ItemID, stored.CapturedAt, stored.ID)); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := s.ts.UserStore().AdjustUsage(ctx, stored.UserID, -stored.Item.Size, 0); err != nil {
		return err
	}
	adjustHistoryUsage(folder, -1, -stored.Item.Size)
	return nil
}

func (s *ItemHistoryStore) listStored(ctx context.Context, prefix string) ([]storedItemVersion, error) {
	keys, err := s.ts.Scan(ctx, NSItemHistory, prefix)
	if err != nil {
		return nil, err
	}
	result := make([]storedItemVersion, 0, len(keys))
	for _, key := range keys {
		var id string
		if err := s.ts.Get(ctx, NSItemHistory, key, &id); err != nil {
			return nil, err
		}
		var version storedItemVersion
		if err := s.ts.Get(ctx, NSItemHistory, historyVersionKey(id), &version); err != nil {
			return nil, err
		}
		result = append(result, version)
	}
	return result, nil
}

func (s *ItemHistoryStore) rebuildFolderAccounting(ctx context.Context, folder *Folder) error {
	stored, err := s.listStored(ctx, historyFolderPrefix(folder.ID))
	if err != nil {
		return err
	}
	folder.HistoryVersionCount = int64(len(stored))
	folder.HistoryLogicalBytes = 0
	for _, candidate := range stored {
		folder.HistoryLogicalBytes += candidate.Item.Size
	}
	folder.HistoryUsageVersion = itemHistoryUsageVersion
	return s.ts.Set(ctx, NSFolders, folder.ID, *folder)
}

func adjustHistoryUsage(folder *Folder, versionDelta, byteDelta int64) {
	if folder.HistoryUsageVersion != itemHistoryUsageVersion {
		return
	}
	folder.HistoryVersionCount = max(int64(0), folder.HistoryVersionCount+versionDelta)
	folder.HistoryLogicalBytes = max(int64(0), folder.HistoryLogicalBytes+byteDelta)
	folder.UpdatedAt = time.Now().UTC()
}

func cloneHistoryItem(item Item) Item {
	item.Data = bytes.Clone(item.Data)
	item.Flags = append([]string(nil), item.Flags...)
	item.Headers = cloneHistoryMap(item.Headers)
	item.ExternalIDs = cloneHistoryMap(item.ExternalIDs)
	return item
}

func cloneHistoryMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func sortVersions(versions []ItemVersion) {
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].CapturedAt.Equal(versions[j].CapturedAt) {
			return versions[i].ID > versions[j].ID
		}
		return versions[i].CapturedAt.After(versions[j].CapturedAt)
	})
}

// ItemHistoryEqual reports whether restoring snapshot would change the
// user-visible item fields retained by history. Identity, folder lifecycle,
// UID, mod-sequence, and timestamps are intentionally excluded.
func ItemHistoryEqual(current, snapshot Item) bool {
	return current.Name == snapshot.Name && bytes.Equal(current.Data, snapshot.Data) &&
		maps.Equal(current.Headers, snapshot.Headers) && maps.Equal(current.ExternalIDs, snapshot.ExternalIDs) &&
		slices.Equal(current.Flags, snapshot.Flags) && current.InternalDate.Equal(snapshot.InternalDate)
}

func itemVersionsEqual(left, right ItemVersion) bool {
	return reflect.DeepEqual(left, right)
}

func historyVersionKey(versionID string) string { return "version:" + versionID }

func historyFolderPrefix(folderID string) string { return "folder:" + folderID + ":" }

func historyItemPrefix(folderID, itemID string) string {
	return historyFolderPrefix(folderID) + "item:" + itemID + ":"
}

func historyIndexKey(folderID, itemID string, capturedAt time.Time, versionID string) string {
	return historyItemPrefix(folderID, itemID) + fmt.Sprintf("%020d:%s", capturedAt.UnixNano(), versionID)
}
