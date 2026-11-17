package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/objectstore"
	"github.com/lkarlslund/veksel/pkg/store"
)

// IMAP system-defined flags (RFC 3501).
const (
	FlagSeen     = "\\Seen"
	FlagAnswered = "\\Answered"
	FlagFlagged  = "\\Flagged"
	FlagDeleted  = "\\Deleted"
	FlagDraft    = "\\Draft"
	FlagRecent   = "\\Recent"
)

// KeywordPinned is the IMAP keyword that pins a message to the top of its
// folder's date-sorted list in the web UI.
const KeywordPinned = "$Pinned"

// KeywordMDNSent records that the user answered a read receipt request, by
// sending or declining it (RFC 3503), so the reader stops asking.
const KeywordMDNSent = "$MDNSent"

// ItemStore provides storage for items inside folders.
type ItemStore struct {
	ts *TypedStore
	us *UserStore // optional: used for quota enforcement
	// Per-folder mutexes for atomic UID allocation
	mu       sync.Mutex
	folderMu map[string]*sync.Mutex
}

type storedItem struct {
	Item
	Payload *objectstore.Ref `json:"payload_ref,omitempty"`
}

// NewItemStore returns an ItemStore backed by ts.
func NewItemStore(ts *TypedStore) *ItemStore {
	return &ItemStore{
		ts:       ts,
		folderMu: make(map[string]*sync.Mutex),
	}
}

// SetUserStore sets the UserStore for quota enforcement.
// This can be called after creation to avoid circular dependencies.
func (is *ItemStore) SetUserStore(us *UserStore) {
	is.us = us
}

// extractUserID extracts the user ID from a folder ID.
// Folder IDs are "userID:path", so we split on the first colon.
func extractUserID(folderID string) string {
	if idx := strings.Index(folderID, ":"); idx > 0 {
		return folderID[:idx]
	}
	return ""
}

// folderLock returns a per-folder mutex, creating one if needed.
func (is *ItemStore) folderLock(folderID string) *sync.Mutex {
	is.mu.Lock()
	defer is.mu.Unlock()
	if m, ok := is.folderMu[folderID]; ok {
		return m
	}
	m := &sync.Mutex{}
	is.folderMu[folderID] = m
	return m
}

// AllocateUID atomically increments the folder's NextUID and returns the new UID.
func (is *ItemStore) AllocateUID(ctx context.Context, folderID string) (uint32, error) {
	if !store.InBatch(ctx, is.ts.Store()) {
		lock := is.folderLock(folderID)
		lock.Lock()
		defer lock.Unlock()
	}

	folder, err := is.getFolder(ctx, folderID)
	if err != nil {
		return 0, fmt.Errorf("read folder for UID allocation: %w", err)
	}

	uid := folder.NextUID + 1
	folder.NextUID = uid
	folder.UpdatedAt = time.Now().UTC()

	if err := is.ts.Set(ctx, NSFolders, folder.ID, folder); err != nil {
		return 0, fmt.Errorf("update folder NextUID: %w", err)
	}

	return uid, nil
}

func (is *ItemStore) allocateModSeqLocked(ctx context.Context, folderID string) (uint64, error) {
	folder, err := is.getFolder(ctx, folderID)
	if err != nil {
		return 0, fmt.Errorf("read folder for modification sequence: %w", err)
	}
	folder.HighestModSeq++
	if folder.HighestModSeq == 0 {
		folder.HighestModSeq = 1
	}
	folder.UpdatedAt = time.Now().UTC()
	if err := is.ts.Set(ctx, NSFolders, folder.ID, folder); err != nil {
		return 0, fmt.Errorf("update folder modification sequence: %w", err)
	}
	return folder.HighestModSeq, nil
}

func (is *ItemStore) allocateModSeq(ctx context.Context, folderID string) (uint64, error) {
	if !store.InBatch(ctx, is.ts.Store()) {
		lock := is.folderLock(folderID)
		lock.Lock()
		defer lock.Unlock()
	}
	return is.allocateModSeqLocked(ctx, folderID)
}

// getFolder reads a folder from the store.
func (is *ItemStore) getFolder(ctx context.Context, folderID string) (Folder, error) {
	return is.ts.FolderStore().Get(ctx, folderID)
}

// Append adds an item to a folder. Returns the generated item ID.
// UID is automatically allocated from the folder's NextUID.
// If quota enforcement is enabled (via SetUserStore), returns ErrQuotaExceeded
// when the user's storage or item limit would be exceeded.
func (is *ItemStore) Append(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
	item, err := is.AppendItem(ctx, folderID, Item{Data: data, Headers: headers})
	return item.ID, err
}

// AppendItem creates a complete item and all of its secondary indexes as one
// logical operation. Batching stores commit it atomically. Protocol metadata
// is included in the initial record, avoiding a create-read-rewrite cycle.
func (is *ItemStore) AppendItem(ctx context.Context, folderID string, input Item) (Item, error) {
	var item Item
	err := store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		var err error
		item, err = is.appendItem(batchCtx, folderID, input)
		return err
	})
	return item, err
}

func (is *ItemStore) appendItem(ctx context.Context, folderID string, input Item) (created Item, err error) {
	folder, err := is.getFolder(ctx, folderID)
	if err != nil {
		return Item{}, fmt.Errorf("read destination folder: %w", err)
	}
	folderID = folder.ID
	for namespace, externalID := range input.ExternalIDs {
		if strings.TrimSpace(namespace) == "" || strings.TrimSpace(externalID) == "" {
			return Item{}, errors.New("external item namespace and ID are required")
		}
		var existingID string
		err := is.ts.Get(ctx, NSItems, ExternalItemIndexKey(folderID, namespace, externalID), &existingID)
		if err == nil {
			return Item{}, fmt.Errorf("%w: external item identity is already assigned", store.ErrExists)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return Item{}, err
		}
	}
	quotaIncremented := false
	defer func() {
		if err == nil || !quotaIncremented || is.us == nil || folder.UserID == "" {
			return
		}
		is.us.DecrementUsage(ctx, folder.UserID, int64(len(input.Data)))
	}()
	// Check quota before doing any work.
	if is.us != nil {
		userID := folder.UserID
		if userID != "" {
			if err := is.us.CheckAndIncrementUsage(ctx, userID, int64(len(input.Data))); err != nil {
				return Item{}, err
			}
			quotaIncremented = true
		}
	}

	now := time.Now().UTC()
	itemName := now.Format("20060102T150405Z")

	// Ensure uniqueness by appending a counter on collision.
	for i := 1; i <= 999; i++ {
		name := fmt.Sprintf("%s-%03d", itemName, i)
		if _, err := is.resolveName(ctx, folderID, name); err == nil {
			continue
		} else if err != store.ErrNotFound {
			return Item{}, err
		}
		resourceID, err := newResourceID("itm")
		if err != nil {
			return Item{}, err
		}
		if err := is.ts.Put(ctx, NSItems, resourceID, struct{}{}); err == nil {
			// Key reserved, now allocate UID (outside the loop, inside folder lock)
			uid, err := is.AllocateUID(ctx, folderID)
			if err != nil {
				// Clean up the reserved key
				is.ts.Delete(ctx, NSItems, resourceID)
				return Item{}, err
			}
			modSeq, err := is.allocateModSeq(ctx, folderID)
			if err != nil {
				is.ts.Delete(ctx, NSItems, resourceID)
				return Item{}, err
			}

			internalDate := input.InternalDate.UTC()
			if input.InternalDate.IsZero() {
				internalDate = now
			}
			item := Item{
				ID:           resourceID,
				Name:         name,
				FolderID:     folderID,
				Data:         input.Data,
				Headers:      input.Headers,
				Size:         int64(len(input.Data)),
				UID:          uid,
				Flags:        append([]string(nil), input.Flags...),
				InternalDate: internalDate,
				ExternalIDs:  cloneExternalIDs(input.ExternalIDs),
				ModSeq:       modSeq,
				SavedAt:      now,
				CreatedAt:    now,
				UpdatedAt:    now,
			}
			if err := is.persistItem(ctx, item); err != nil {
				return Item{}, fmt.Errorf("store item: %w", err)
			}
			if err := is.ts.Set(ctx, NSItems, ItemMemberKey(folderID, resourceID), resourceID); err != nil {
				return Item{}, fmt.Errorf("store folder membership: %w", err)
			}
			if err := is.ts.Set(ctx, NSItems, ItemNameKey(folderID, name), resourceID); err != nil {
				return Item{}, fmt.Errorf("store item name: %w", err)
			}

			// Create UID reverse index
			uidKey := UIDIndexKey(folderID, uid)
			if err := is.ts.Set(ctx, NSItems, uidKey, resourceID); err != nil {
				return Item{}, fmt.Errorf("store UID index: %w", err)
			}

			// Create date secondary index
			dateKey := DateIndexKey(folderID, internalDate.Format("20060102"), resourceID)
			if err := is.ts.Set(ctx, NSItems, dateKey, resourceID); err != nil {
				return Item{}, fmt.Errorf("store date index: %w", err)
			}
			for namespace, externalID := range item.ExternalIDs {
				if err := is.ts.Set(ctx, NSItems, ExternalItemIndexKey(folderID, namespace, externalID), resourceID); err != nil {
					return Item{}, fmt.Errorf("store external item index: %w", err)
				}
			}
			accountedFolder, folderErr := is.getFolder(ctx, folderID)
			if folderErr != nil {
				return Item{}, folderErr
			}
			adjustFolderUsage(&accountedFolder, 1, item.Size)
			if err := is.ts.Set(ctx, NSFolders, accountedFolder.ID, accountedFolder); err != nil {
				return Item{}, fmt.Errorf("update folder accounting: %w", err)
			}

			return item, nil
		} else if !errors.Is(err, store.ErrExists) {
			return Item{}, fmt.Errorf("reserve item ID: %w", err)
		}
	}
	return Item{}, fmt.Errorf("failed to generate unique item ID")
}

func cloneExternalIDs(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	clone := make(map[string]string, len(input))
	for namespace, externalID := range input {
		clone[namespace] = externalID
	}
	return clone
}

func (is *ItemStore) getStored(ctx context.Context, id string) (storedItem, error) {
	var stored storedItem
	if err := is.ts.Get(ctx, NSItems, id, &stored); err != nil {
		if folderID, name, ok := splitItemKey(id); ok {
			resolved, resolveErr := is.resolveName(ctx, folderID, name)
			if resolveErr != nil {
				return storedItem{}, resolveErr
			}
			return is.getStored(ctx, resolved)
		}
		return storedItem{}, err
	}
	return stored, nil
}

// GetMetadata returns an item without reading its payload or reassembling
// attachments. Callers that render indexes and summaries should prefer it.
func (is *ItemStore) GetMetadata(ctx context.Context, id string) (Item, error) {
	stored, err := is.getStored(ctx, id)
	if err != nil {
		return Item{}, err
	}
	item := stored.Item
	item.Data = nil
	return item, nil
}

// Get returns an item by its store key.
// If attachment reassembly is configured, large attachments are reassembled
// from the file store before returning.
func (is *ItemStore) Get(ctx context.Context, id string) (Item, error) {
	stored, err := is.getStored(ctx, id)
	if err != nil {
		return Item{}, err
	}
	item := stored.Item
	if stored.Payload != nil {
		if is.ts.objects == nil {
			return Item{}, errors.New("item references object storage but no object store is open")
		}
		var payload bytes.Buffer
		payload.Grow(int(stored.Payload.PayloadLength))
		if err := is.ts.objects.Read(ctx, *stored.Payload, &payload); err != nil {
			return Item{}, fmt.Errorf("read item payload %s: %w", item.ID, err)
		}
		item.Data = payload.Bytes()
	}

	return item, nil
}

// GetByUID returns an item by its IMAP UID within a folder.
func (is *ItemStore) GetByUID(ctx context.Context, folderID string, uid uint32) (Item, error) {
	uidKey := UIDIndexKey(folderID, uid)
	var itemID string
	if err := is.ts.Get(ctx, NSItems, uidKey, &itemID); err != nil {
		return Item{}, err
	}
	return is.Get(ctx, itemID)
}

// GetByExternalID resolves a protocol-neutral source identity in a folder.
func (is *ItemStore) GetByExternalID(ctx context.Context, folderID, namespace, externalID string) (Item, error) {
	if folder, err := is.getFolder(ctx, folderID); err == nil {
		folderID = folder.ID
	}
	var itemID string
	if err := is.ts.Get(ctx, NSItems, ExternalItemIndexKey(folderID, namespace, externalID), &itemID); err != nil {
		return Item{}, err
	}
	return is.Get(ctx, itemID)
}

// GetMetadataByExternalID resolves a protocol-neutral source identity without
// opening the item's payload. Synchronizers and index views should use this
// when only identity, version headers, flags, or sizes are required.
func (is *ItemStore) GetMetadataByExternalID(ctx context.Context, folderID, namespace, externalID string) (Item, error) {
	if folder, err := is.getFolder(ctx, folderID); err == nil {
		folderID = folder.ID
	}
	var itemID string
	if err := is.ts.Get(ctx, NSItems, ExternalItemIndexKey(folderID, namespace, externalID), &itemID); err != nil {
		return Item{}, err
	}
	return is.GetMetadata(ctx, itemID)
}

// ListMetadata returns folder items ordered by UID without loading payloads.
func (is *ItemStore) ListMetadata(ctx context.Context, folderID string) ([]Item, error) {
	var items []Item
	err := store.View(ctx, is.ts.Store(), func(viewCtx context.Context) error {
		var err error
		items, err = is.listMetadata(viewCtx, folderID)
		return err
	})
	return items, err
}

// ListMetadataPage returns live folder items in descending UID order without
// loading payloads. beforeUID is an exclusive cursor; zero starts at the
// newest assigned UID. The total comes from durable folder accounting rather
// than an item scan.
func (is *ItemStore) ListMetadataPage(ctx context.Context, folderID string, beforeUID uint32, limit int) (items []Item, total int64, nextBeforeUID uint32, err error) {
	return is.listPage(ctx, folderID, beforeUID, limit, false)
}

// ListPage returns a bounded page including item payloads. It shares one store
// view for the UID index and item records so projections such as contacts do
// not incur one independent transaction per item.
func (is *ItemStore) ListPage(ctx context.Context, folderID string, beforeUID uint32, limit int) (items []Item, total int64, nextBeforeUID uint32, err error) {
	return is.listPage(ctx, folderID, beforeUID, limit, true)
}

type itemDateCursor struct {
	Version  int    `json:"v"`
	FolderID string `json:"f"`
	Date     string `json:"d"`
	UID      uint32 `json:"u"`
	ItemID   string `json:"i"`
	parsed   time.Time
}

// ListDatePage returns a stable newest-first page using the durable per-folder
// date index. The opaque cursor is exclusive and remains valid when newer
// items arrive because it identifies the complete last-item sort tuple.
func (is *ItemStore) ListDatePage(ctx context.Context, folderID, cursor string, limit int, includeData bool) (items []Item, total int64, nextCursor string, err error) {
	if limit < 1 {
		return nil, 0, "", errors.New("page limit must be positive")
	}
	var boundary itemDateCursor
	if cursor != "" {
		boundary, err = decodeItemDateCursor(cursor)
		if err != nil {
			return nil, 0, "", err
		}
	}
	err = store.View(ctx, is.ts.Store(), func(viewCtx context.Context) error {
		folder, getErr := is.getFolder(viewCtx, folderID)
		if getErr != nil {
			return getErr
		}
		folderID = folder.ID
		if cursor != "" && boundary.FolderID != folderID {
			return errors.New("item page cursor belongs to another folder")
		}
		total = folder.ItemCount
		prefix := DateIndexPrefix(folderID)
		keys, scanErr := is.ts.Scan(viewCtx, NSItems, prefix)
		if scanErr != nil {
			return fmt.Errorf("scan item date index: %w", scanErr)
		}
		includeTrashed := folder.SpecialUse == SpecialUseTrash
		items = make([]Item, 0, limit+1)
		cursorDay := ""
		if cursor != "" {
			cursorDay = boundary.parsed.UTC().Format("20060102")
		}
		for end := len(keys); end > 0 && len(items) <= limit; {
			day, ok := itemDateIndexDay(keys[end-1], prefix)
			if !ok {
				end--
				continue
			}
			start := end - 1
			for start > 0 {
				previousDay, valid := itemDateIndexDay(keys[start-1], prefix)
				if !valid || previousDay != day {
					break
				}
				start--
			}
			if cursorDay != "" && day > cursorDay {
				end = start
				continue
			}
			group := make([]Item, 0, end-start)
			for _, key := range keys[start:end] {
				if contextErr := viewCtx.Err(); contextErr != nil {
					return contextErr
				}
				var itemID string
				if getErr := is.ts.Get(viewCtx, NSItems, key, &itemID); getErr != nil || itemID == "" {
					continue
				}
				item, getErr := is.GetMetadata(viewCtx, itemID)
				if getErr != nil || item.FolderID != folderID || (!includeTrashed && !item.TrashedAt.IsZero()) {
					continue
				}
				group = append(group, item)
			}
			sort.Slice(group, func(left, right int) bool { return itemDateBefore(group[left], group[right]) })
			for _, item := range group {
				if cursor != "" && !itemFallsAfterDateCursor(item, boundary) {
					continue
				}
				items = append(items, item)
				if len(items) > limit {
					break
				}
			}
			end = start
		}
		if len(items) > limit {
			items = items[:limit]
			last := items[len(items)-1]
			nextCursor, getErr = encodeItemDateCursor(itemDateCursor{Version: 1, FolderID: folderID, Date: last.InternalDate.UTC().Format(time.RFC3339Nano), UID: last.UID, ItemID: last.ID})
			if getErr != nil {
				return getErr
			}
		}
		if includeData {
			for index := range items {
				items[index], getErr = is.Get(viewCtx, items[index].ID)
				if getErr != nil {
					return getErr
				}
			}
		}
		return nil
	})
	return items, total, nextCursor, err
}

// ListDateWindow returns an anchor item with at most one immediately newer and
// one immediately older neighbor. It reads only metadata unless includeData is
// requested and uses the durable per-folder date index rather than enumerating
// item payloads.
func (is *ItemStore) ListDateWindow(ctx context.Context, folderID, anchorItemID string, includeData bool) (items []Item, total int64, err error) {
	if strings.TrimSpace(anchorItemID) == "" {
		return nil, 0, errors.New("anchor item ID is required")
	}
	err = store.View(ctx, is.ts.Store(), func(viewCtx context.Context) error {
		folder, getErr := is.getFolder(viewCtx, folderID)
		if getErr != nil {
			return getErr
		}
		folderID = folder.ID
		total = folder.ItemCount
		anchor, getErr := is.GetMetadata(viewCtx, anchorItemID)
		if getErr != nil {
			return getErr
		}
		includeTrashed := folder.SpecialUse == SpecialUseTrash
		if anchor.FolderID != folderID || (!includeTrashed && !anchor.TrashedAt.IsZero()) {
			return store.ErrNotFound
		}
		prefix := DateIndexPrefix(folderID)
		keys, scanErr := is.ts.Scan(viewCtx, NSItems, prefix)
		if scanErr != nil {
			return fmt.Errorf("scan item date index: %w", scanErr)
		}
		anchorDay := anchor.InternalDate.Format("20060102")
		groupStart, groupEnd := -1, -1
		for index, key := range keys {
			day, ok := itemDateIndexDay(key, prefix)
			if !ok {
				continue
			}
			if day == anchorDay {
				if groupStart < 0 {
					groupStart = index
				}
				groupEnd = index + 1
			} else if groupStart >= 0 && day > anchorDay {
				break
			}
		}
		if groupStart < 0 {
			return errors.New("anchor item is missing from the date index")
		}
		group, loadErr := is.loadDateIndexGroup(viewCtx, folderID, prefix, keys[groupStart:groupEnd], includeTrashed)
		if loadErr != nil {
			return loadErr
		}
		anchorIndex := -1
		for index := range group {
			if group[index].ID == anchorItemID {
				anchorIndex = index
				break
			}
		}
		if anchorIndex < 0 {
			return errors.New("anchor item is missing from the date index")
		}
		var newer, older *Item
		if anchorIndex > 0 {
			candidate := group[anchorIndex-1]
			newer = &candidate
		} else {
			candidate, found, findErr := is.nearestDateIndexItem(viewCtx, folderID, prefix, keys, groupEnd, 1, includeTrashed)
			if findErr != nil {
				return findErr
			}
			if found {
				newer = &candidate
			}
		}
		if anchorIndex+1 < len(group) {
			candidate := group[anchorIndex+1]
			older = &candidate
		} else {
			candidate, found, findErr := is.nearestDateIndexItem(viewCtx, folderID, prefix, keys, groupStart, -1, includeTrashed)
			if findErr != nil {
				return findErr
			}
			if found {
				older = &candidate
			}
		}
		items = make([]Item, 0, 3)
		if newer != nil {
			items = append(items, *newer)
		}
		items = append(items, anchor)
		if older != nil {
			items = append(items, *older)
		}
		if includeData {
			for index := range items {
				items[index], getErr = is.Get(viewCtx, items[index].ID)
				if getErr != nil {
					return getErr
				}
			}
		}
		return nil
	})
	return items, total, err
}

func (is *ItemStore) loadDateIndexGroup(ctx context.Context, folderID, prefix string, keys []string, includeTrashed bool) ([]Item, error) {
	group := make([]Item, 0, len(keys))
	for _, key := range keys {
		if _, ok := itemDateIndexDay(key, prefix); !ok {
			continue
		}
		var itemID string
		if err := is.ts.Get(ctx, NSItems, key, &itemID); err != nil || itemID == "" {
			continue
		}
		item, err := is.GetMetadata(ctx, itemID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if item.FolderID != folderID || (!includeTrashed && !item.TrashedAt.IsZero()) {
			continue
		}
		group = append(group, item)
	}
	sort.Slice(group, func(left, right int) bool { return itemDateBefore(group[left], group[right]) })
	return group, nil
}

func (is *ItemStore) nearestDateIndexItem(ctx context.Context, folderID, prefix string, keys []string, boundary, direction int, includeTrashed bool) (Item, bool, error) {
	for boundary >= 0 && boundary <= len(keys) {
		var start, end int
		if direction > 0 {
			if boundary == len(keys) {
				break
			}
			day, ok := itemDateIndexDay(keys[boundary], prefix)
			if !ok {
				boundary++
				continue
			}
			start, end = boundary, boundary+1
			for end < len(keys) {
				nextDay, valid := itemDateIndexDay(keys[end], prefix)
				if !valid || nextDay != day {
					break
				}
				end++
			}
			boundary = end
		} else {
			if boundary == 0 {
				break
			}
			day, ok := itemDateIndexDay(keys[boundary-1], prefix)
			if !ok {
				boundary--
				continue
			}
			start, end = boundary-1, boundary
			for start > 0 {
				previousDay, valid := itemDateIndexDay(keys[start-1], prefix)
				if !valid || previousDay != day {
					break
				}
				start--
			}
			boundary = start
		}
		group, err := is.loadDateIndexGroup(ctx, folderID, prefix, keys[start:end], includeTrashed)
		if err != nil {
			return Item{}, false, err
		}
		if len(group) == 0 {
			continue
		}
		if direction > 0 {
			return group[len(group)-1], true, nil
		}
		return group[0], true, nil
	}
	return Item{}, false, nil
}

func itemDateIndexDay(key, prefix string) (string, bool) {
	if !strings.HasPrefix(key, prefix) || len(key) < len(prefix)+9 || key[len(prefix)+8] != ':' {
		return "", false
	}
	return key[len(prefix) : len(prefix)+8], true
}

func itemDateBefore(left, right Item) bool {
	if !left.InternalDate.Equal(right.InternalDate) {
		return left.InternalDate.After(right.InternalDate)
	}
	if left.UID != right.UID {
		return left.UID > right.UID
	}
	return left.ID < right.ID
}

func itemFallsAfterDateCursor(item Item, cursor itemDateCursor) bool {
	if !item.InternalDate.Equal(cursor.parsed) {
		return item.InternalDate.Before(cursor.parsed)
	}
	if item.UID != cursor.UID {
		return item.UID < cursor.UID
	}
	return item.ID > cursor.ItemID
}

func encodeItemDateCursor(cursor itemDateCursor) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeItemDateCursor(value string) (itemDateCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return itemDateCursor{}, errors.New("invalid item page cursor")
	}
	var cursor itemDateCursor
	if err := json.Unmarshal(raw, &cursor); err != nil || cursor.Version != 1 || cursor.FolderID == "" || cursor.ItemID == "" {
		return itemDateCursor{}, errors.New("invalid item page cursor")
	}
	cursor.parsed, err = time.Parse(time.RFC3339Nano, cursor.Date)
	if err != nil {
		return itemDateCursor{}, errors.New("invalid item page cursor")
	}
	return cursor, nil
}

func (is *ItemStore) listPage(ctx context.Context, folderID string, beforeUID uint32, limit int, includeData bool) (items []Item, total int64, nextBeforeUID uint32, err error) {
	if limit < 1 {
		return nil, 0, 0, errors.New("page limit must be positive")
	}
	err = store.View(ctx, is.ts.Store(), func(viewCtx context.Context) error {
		folder, getErr := is.getFolder(viewCtx, folderID)
		if getErr != nil {
			return getErr
		}
		folderID = folder.ID
		total = folder.ItemCount
		start := folder.NextUID
		if beforeUID > 0 && beforeUID <= start {
			start = beforeUID - 1
		}
		includeTrashed := folder.SpecialUse == SpecialUseTrash
		items = make([]Item, 0, limit)
		for uid := start; uid > 0 && len(items) < limit; uid-- {
			var itemID string
			if getErr := is.ts.Get(viewCtx, NSItems, UIDIndexKey(folderID, uid), &itemID); getErr != nil {
				if errors.Is(getErr, store.ErrNotFound) {
					continue
				}
				return getErr
			}
			var item Item
			if includeData {
				item, getErr = is.Get(viewCtx, itemID)
			} else {
				item, getErr = is.GetMetadata(viewCtx, itemID)
			}
			if getErr != nil {
				if errors.Is(getErr, store.ErrNotFound) {
					continue
				}
				return getErr
			}
			if includeTrashed || item.TrashedAt.IsZero() {
				items = append(items, item)
			}
		}
		if len(items) == limit && items[len(items)-1].UID > 1 {
			nextBeforeUID = items[len(items)-1].UID
		}
		return nil
	})
	return items, total, nextBeforeUID, err
}

func (is *ItemStore) listMetadata(ctx context.Context, folderID string) ([]Item, error) {
	includeTrashed := false
	if folder, err := is.getFolder(ctx, folderID); err == nil {
		folderID = folder.ID
		includeTrashed = folder.SpecialUse == SpecialUseTrash
	}
	// The membership index stores each item ID as its value, so one prefix
	// iteration yields the IDs without a point read per member.
	var ids []string
	err := is.ts.Store().Iterate(ctx, NSItems, ItemMemberPrefix(folderID), func(_ string, value []byte) (bool, error) {
		var id string
		if json.Unmarshal(value, &id) == nil && id != "" {
			ids = append(ids, id)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(ids))
	for _, id := range ids {
		item, itemErr := is.GetMetadata(ctx, id)
		if itemErr == nil && (includeTrashed || item.TrashedAt.IsZero()) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UID == items[j].UID {
			return items[i].ID < items[j].ID
		}
		return items[i].UID < items[j].UID
	})
	return items, nil
}

// List returns all item keys in a folder without loading payloads.
func (is *ItemStore) List(ctx context.Context, folderID string) ([]string, error) {
	items, err := is.ListMetadata(ctx, folderID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	return ids, nil
}

// CountAll returns the number of current folder memberships without loading
// item payloads. Each live item has exactly one membership index entry.
func (is *ItemStore) CountAll(ctx context.Context) (int, error) {
	keys, err := is.ts.Scan(ctx, NSItems, "member:")
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}

// Delete removes an item and its UID and date index entries.
// If quota enforcement is enabled, decrements the user's usage counters.
// If attachment storage is configured, cleans up attachment files and metadata.
func (is *ItemStore) Delete(ctx context.Context, id string) error {
	return store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		return is.delete(batchCtx, id)
	})
}

func (is *ItemStore) delete(ctx context.Context, id string) error {
	item, err := is.GetMetadata(ctx, id)
	if err != nil {
		return err
	}
	folder, err := is.getFolder(ctx, item.FolderID)
	if err != nil {
		return fmt.Errorf("read item folder for accounting: %w", err)
	}

	is.removeIndexes(ctx, item)
	if !item.TrashedAt.IsZero() {
		if folder, folderErr := is.getFolder(ctx, item.FolderID); folderErr == nil {
			_ = is.ts.Delete(ctx, NSItems, TrashedItemKey(folder.UserID, item.ID))
		}
	}
	if err := is.ts.Delete(ctx, NSItems, item.ID); err != nil {
		return err
	}
	adjustFolderUsage(&folder, -1, -item.Size)
	if err := is.ts.Set(ctx, NSFolders, folder.ID, folder); err != nil {
		return fmt.Errorf("update folder accounting: %w", err)
	}
	// Decrement quota counters
	if is.us != nil && folder.UserID != "" {
		if err := is.us.DecrementUsage(ctx, folder.UserID, item.Size); err != nil {
			return fmt.Errorf("release item quota: %w", err)
		}
	}
	return nil
}

// Trash marks an item for recoverable deletion. Mail items may be moved into
// the user's system Trash folder; other item types remain in place but are
// hidden from their normal folder and exposed through ListTrashedForUser.
func (is *ItemStore) Trash(ctx context.Context, id, trashFolderID string, retention time.Duration) (Item, error) {
	item, err := is.Get(ctx, id)
	if err != nil {
		return Item{}, err
	}
	sourceFolder, err := is.getFolder(ctx, item.FolderID)
	if err != nil {
		return Item{}, err
	}
	if !item.TrashedAt.IsZero() {
		return item, nil
	}
	originalFolderID, originalName := item.FolderID, item.Name
	// Trashed items always take an ID-derived name so their live name is free
	// for a new item; Restore moves them back and reports name conflicts.
	trashTargetID := item.FolderID
	if trashFolderID != "" && trashFolderID != item.FolderID {
		trashFolder, folderErr := is.getFolder(ctx, trashFolderID)
		if folderErr != nil {
			return Item{}, folderErr
		}
		if trashFolder.UserID == sourceFolder.UserID && trashFolder.Type == sourceFolder.Type {
			trashTargetID = trashFolder.ID
		}
	}
	item, err = is.Move(ctx, item.ID, trashTargetID, item.ID+".trashed")
	if err != nil {
		return Item{}, err
	}
	now := time.Now().UTC()
	item.TrashedAt = now
	if retention > 0 {
		item.PurgeAfter = now.Add(retention)
	}
	item.OriginalFolderID = originalFolderID
	item.OriginalName = originalName
	item.ModSeq, err = is.allocateModSeq(ctx, item.FolderID)
	if err != nil {
		return Item{}, err
	}
	item.UpdatedAt = now
	if err := is.SetItem(ctx, item); err != nil {
		return Item{}, err
	}
	if err := is.ts.Set(ctx, NSItems, TrashedItemKey(sourceFolder.UserID, item.ID), item.ID); err != nil {
		return Item{}, err
	}
	return item, nil
}

// Restore returns a recoverably deleted item to its original folder.
func (is *ItemStore) Restore(ctx context.Context, id string) (Item, error) {
	item, err := is.Get(ctx, id)
	if err != nil {
		return Item{}, err
	}
	if item.TrashedAt.IsZero() || item.OriginalFolderID == "" {
		return Item{}, fmt.Errorf("item is not recoverably deleted")
	}
	currentFolder, err := is.getFolder(ctx, item.FolderID)
	if err != nil {
		return Item{}, err
	}
	originalFolderID, originalName := item.OriginalFolderID, item.OriginalName
	if originalName == "" {
		originalName = item.Name
	}
	if item.FolderID != originalFolderID || item.Name != originalName {
		item, err = is.Move(ctx, item.ID, originalFolderID, originalName)
		if err != nil {
			return Item{}, err
		}
	}
	item.TrashedAt = time.Time{}
	item.PurgeAfter = time.Time{}
	item.OriginalFolderID = ""
	item.OriginalName = ""
	item.ModSeq, err = is.allocateModSeq(ctx, item.FolderID)
	if err != nil {
		return Item{}, err
	}
	item.UpdatedAt = time.Now().UTC()
	if err := is.SetItem(ctx, item); err != nil {
		return Item{}, err
	}
	_ = is.ts.Delete(ctx, NSItems, TrashedItemKey(currentFolder.UserID, item.ID))
	return item, nil
}

// ListTrashedForUser returns recoverably deleted items across all folder types.
func (is *ItemStore) ListTrashedForUser(ctx context.Context, userID string) ([]Item, error) {
	var items []Item
	err := store.View(ctx, is.ts.Store(), func(viewCtx context.Context) error {
		var err error
		items, err = is.listTrashedForUser(viewCtx, userID)
		return err
	})
	return items, err
}

func (is *ItemStore) listTrashedForUser(ctx context.Context, userID string) ([]Item, error) {
	keys, err := is.ts.Scan(ctx, NSItems, TrashedItemPrefix(normalizeID(userID)))
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(keys))
	for _, key := range keys {
		var id string
		if err := is.ts.Get(ctx, NSItems, key, &id); err != nil {
			continue
		}
		item, err := is.GetMetadata(ctx, id)
		if err == nil && !item.TrashedAt.IsZero() {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].TrashedAt.After(items[j].TrashedAt) })
	return items, nil
}

// Move changes an item's folder and protocol-facing name while preserving its
// immutable resource ID. A move receives a new UID in the destination folder,
// as required by IMAP, but remains the same resource to REST and WebDAV clients.
func (is *ItemStore) Move(ctx context.Context, id, destinationFolderID, destinationName string) (Item, error) {
	item, _, err := is.MoveWithTombstone(ctx, id, destinationFolderID, destinationName)
	return item, err
}

// MoveWithTombstone returns both the destination item and the final source
// identity so incremental protocols can report the source UID as removed.
func (is *ItemStore) MoveWithTombstone(ctx context.Context, id, destinationFolderID, destinationName string) (Item, Item, error) {
	item, err := is.Get(ctx, id)
	if err != nil {
		return Item{}, Item{}, err
	}
	sourceFolder, err := is.getFolder(ctx, item.FolderID)
	if err != nil {
		return Item{}, Item{}, fmt.Errorf("read source folder: %w", err)
	}
	destinationFolder, err := is.getFolder(ctx, destinationFolderID)
	if err != nil {
		return Item{}, Item{}, fmt.Errorf("read destination folder: %w", err)
	}
	if sourceFolder.UserID != destinationFolder.UserID {
		return Item{}, Item{}, fmt.Errorf("cannot move an item between users")
	}
	if sourceFolder.Type != destinationFolder.Type {
		return Item{}, Item{}, fmt.Errorf("cannot move an item between different folder types")
	}
	if destinationName == "" {
		destinationName = item.Name
	}
	if destinationFolder.ID == item.FolderID && destinationName == item.Name {
		return item, item, nil
	}
	if existingID, resolveErr := is.resolveName(ctx, destinationFolder.ID, destinationName); resolveErr == nil && existingID != item.ID {
		return Item{}, Item{}, fmt.Errorf("%w: destination item %q already exists", store.ErrExists, destinationName)
	} else if resolveErr != nil && resolveErr != store.ErrNotFound {
		return Item{}, Item{}, resolveErr
	}

	oldItem := item
	oldItem.ModSeq, err = is.allocateModSeq(ctx, sourceFolder.ID)
	if err != nil {
		return Item{}, Item{}, err
	}
	uid, err := is.AllocateUID(ctx, destinationFolder.ID)
	if err != nil {
		return Item{}, Item{}, err
	}
	destinationModSeq, err := is.allocateModSeq(ctx, destinationFolder.ID)
	if err != nil {
		return Item{}, Item{}, err
	}
	is.removeIndexes(ctx, item)
	item.FolderID = destinationFolder.ID
	item.Name = destinationName
	item.UID = uid
	item.ModSeq = destinationModSeq
	item.SavedAt = time.Now().UTC()
	item.UpdatedAt = item.SavedAt
	if err := is.SetItem(ctx, item); err != nil {
		_ = is.SetItem(ctx, oldItem)
		return Item{}, Item{}, fmt.Errorf("store moved item: %w", err)
	}
	return item, oldItem, nil
}

func (is *ItemStore) removeIndexes(ctx context.Context, item Item) {
	is.removeExternalIndexes(ctx, item)
	if item.UID != 0 {
		_ = is.ts.Delete(ctx, NSItems, UIDIndexKey(item.FolderID, item.UID))
	}
	_ = is.ts.Delete(ctx, NSItems, ItemMemberKey(item.FolderID, item.ID))
	if item.Name != "" {
		_ = is.ts.Delete(ctx, NSItems, ItemNameKey(item.FolderID, item.Name))
	}
	if !item.InternalDate.IsZero() {
		_ = is.ts.Delete(ctx, NSItems, DateIndexKey(item.FolderID, item.InternalDate.Format("20060102"), item.ID))
	}
}

func (is *ItemStore) removeExternalIndexes(ctx context.Context, item Item) {
	for namespace, externalID := range item.ExternalIDs {
		_ = is.ts.Delete(ctx, NSItems, ExternalItemIndexKey(item.FolderID, namespace, externalID))
	}
}

// SetFlags replaces all flags on an item and bumps ModSeq.
func (is *ItemStore) SetFlags(ctx context.Context, id string, flags []string) error {
	return store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		item, err := is.Get(batchCtx, id)
		if err != nil {
			return err
		}
		item.Flags = flags
		item.ModSeq, err = is.allocateModSeq(batchCtx, item.FolderID)
		if err != nil {
			return err
		}
		item.UpdatedAt = time.Now().UTC()
		return is.SetItem(batchCtx, item)
	})
}

// AddFlags adds the given flags to an item and bumps ModSeq.
func (is *ItemStore) AddFlags(ctx context.Context, id string, flags ...string) error {
	return store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		item, err := is.Get(batchCtx, id)
		if err != nil {
			return err
		}
		existing := make(map[string]bool)
		for _, f := range item.Flags {
			existing[f] = true
		}
		for _, f := range flags {
			if !existing[f] {
				item.Flags = append(item.Flags, f)
				existing[f] = true
			}
		}
		item.ModSeq, err = is.allocateModSeq(batchCtx, item.FolderID)
		if err != nil {
			return err
		}
		item.UpdatedAt = time.Now().UTC()
		return is.SetItem(batchCtx, item)
	})
}

// RemoveFlags removes the given flags from an item and bumps ModSeq.
func (is *ItemStore) RemoveFlags(ctx context.Context, id string, flags ...string) error {
	return store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		item, err := is.Get(batchCtx, id)
		if err != nil {
			return err
		}
		remove := make(map[string]bool)
		for _, f := range flags {
			remove[f] = true
		}
		kept := make([]string, 0, len(item.Flags))
		for _, f := range item.Flags {
			if !remove[f] {
				kept = append(kept, f)
			}
		}
		item.Flags = kept
		item.ModSeq, err = is.allocateModSeq(batchCtx, item.FolderID)
		if err != nil {
			return err
		}
		item.UpdatedAt = time.Now().UTC()
		return is.SetItem(batchCtx, item)
	})
}

// UpdateModSeq bumps the ModSeq on an item for any mutation.
func (is *ItemStore) UpdateModSeq(ctx context.Context, id string) error {
	return store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		item, err := is.Get(batchCtx, id)
		if err != nil {
			return err
		}
		item.ModSeq, err = is.allocateModSeq(batchCtx, item.FolderID)
		if err != nil {
			return err
		}
		item.UpdatedAt = time.Now().UTC()
		return is.SetItem(batchCtx, item)
	})
}

// UpdateContent atomically replaces an item's payload and headers while
// allocating the next folder-wide modification sequence. Callers must not
// increment an item's existing ModSeq directly: an older item can be far behind
// the folder high-water mark, which would leave derived indexes unaware of the
// update.
func (is *ItemStore) UpdateContent(ctx context.Context, id string, data []byte, headers map[string]string) (Item, error) {
	var updated Item
	err := store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		item, err := is.Get(batchCtx, id)
		if err != nil {
			return err
		}
		item.ModSeq, err = is.allocateModSeq(batchCtx, item.FolderID)
		if err != nil {
			return err
		}
		item.Data = data
		item.Headers = headers
		item.Size = int64(len(data))
		item.UpdatedAt = time.Now().UTC()
		if err := is.setItem(batchCtx, item, true); err != nil {
			return err
		}
		updated = item
		return nil
	})
	return updated, err
}

// SetItem transactionally creates or replaces an item and accounts for the
// resulting item and byte delta. It is used by protocol PUT/update paths.
func (is *ItemStore) SetItem(ctx context.Context, item Item) error {
	return store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		return is.setItem(batchCtx, item, true)
	})
}

// RestoreItem writes an item without changing quota counters. It is reserved
// for verified account bundle restore/conversion, where user counters are part
// of the same logical image and are checked before activation.
func (is *ItemStore) RestoreItem(ctx context.Context, item Item) error {
	return store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		return is.setItem(batchCtx, item, false)
	})
}

// RestoreVersion applies a historical snapshot without changing a live item's
// identity, folder, UID, or recoverable-deletion state. If the original item
// no longer exists, a new item is created in the version's folder. A live item
// that moved elsewhere is rejected so restoring history cannot silently move
// data across an authorization boundary.
func (is *ItemStore) RestoreVersion(ctx context.Context, snapshot Item) (restored Item, created bool, err error) {
	err = store.Batch(ctx, is.ts.Store(), func(batchCtx context.Context) error {
		current, getErr := is.Get(batchCtx, snapshot.ID)
		if errors.Is(getErr, store.ErrNotFound) {
			snapshot.TrashedAt = time.Time{}
			snapshot.PurgeAfter = time.Time{}
			snapshot.OriginalFolderID = ""
			snapshot.OriginalName = ""
			restored, getErr = is.appendItem(batchCtx, snapshot.FolderID, snapshot)
			created = getErr == nil
			return getErr
		}
		if getErr != nil {
			return getErr
		}
		if current.FolderID != snapshot.FolderID {
			return fmt.Errorf("%w: item is now in another folder", ErrItemHistoryConflict)
		}
		if ItemHistoryEqual(current, snapshot) {
			restored = current
			return nil
		}
		if current.Name != snapshot.Name {
			if existingID, resolveErr := is.resolveName(batchCtx, current.FolderID, snapshot.Name); resolveErr == nil && existingID != current.ID {
				return fmt.Errorf("%w: restored item name already exists", ErrItemHistoryConflict)
			} else if resolveErr != nil && !errors.Is(resolveErr, store.ErrNotFound) {
				return resolveErr
			}
		}
		restored = current
		restored.Name = snapshot.Name
		restored.Data = bytes.Clone(snapshot.Data)
		restored.Headers = cloneHistoryMap(snapshot.Headers)
		restored.ExternalIDs = cloneHistoryMap(snapshot.ExternalIDs)
		restored.Flags = append([]string(nil), snapshot.Flags...)
		restored.InternalDate = snapshot.InternalDate
		restored.Size = snapshot.Size
		restored.ModSeq, getErr = is.allocateModSeq(batchCtx, current.FolderID)
		if getErr != nil {
			return getErr
		}
		restored.UpdatedAt = time.Now().UTC()
		return is.setItem(batchCtx, restored, true)
	})
	return restored, created, err
}

func (is *ItemStore) setItem(ctx context.Context, item Item, accountQuota bool) error {
	if item.FolderID == "" {
		return fmt.Errorf("item folder is required")
	}
	folder, err := is.getFolder(ctx, item.FolderID)
	if err != nil {
		return err
	}
	item.FolderID = folder.ID
	if !store.InBatch(ctx, is.ts.Store()) {
		lock := is.folderLock(item.FolderID)
		lock.Lock()
		defer lock.Unlock()
	}
	if !strings.HasPrefix(item.ID, "itm_") {
		folderID, name, ok := splitItemKey(item.ID)
		if ok {
			item.FolderID = folderID
			item.Name = name
			if existingID, err := is.resolveName(ctx, folderID, name); err == nil {
				item.ID = existingID
			}
		}
	}
	if item.ID == "" || !strings.HasPrefix(item.ID, "itm_") {
		id, err := newResourceID("itm")
		if err != nil {
			return err
		}
		item.ID = id
	}
	if item.Name == "" {
		item.Name = item.ID
	}
	for namespace, externalID := range item.ExternalIDs {
		var existingID string
		err := is.ts.Get(ctx, NSItems, ExternalItemIndexKey(item.FolderID, namespace, externalID), &existingID)
		if err == nil && existingID != "" && existingID != item.ID {
			return fmt.Errorf("%w: external item identity is already assigned", store.ErrExists)
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	if item.Size == 0 && len(item.Data) > 0 {
		item.Size = int64(len(item.Data))
	}
	var previous Item
	var previousFolder Folder
	var folderErr error
	previousFound := false
	if err := is.ts.Get(ctx, NSItems, item.ID, &previous); err == nil && previous.ID != "" {
		previousFound = true
		if previous.FolderID != item.FolderID {
			previousFolder, folderErr = is.getFolder(ctx, previous.FolderID)
			if folderErr != nil {
				return folderErr
			}
			if previousFolder.UserID != folder.UserID {
				return errors.New("cannot replace an item across user quota roots")
			}
		}
		if previous.FolderID != item.FolderID || previous.Name != item.Name || previous.UID != item.UID {
			is.removeIndexes(ctx, previous)
		} else {
			if !previous.InternalDate.Equal(item.InternalDate) && !previous.InternalDate.IsZero() {
				_ = is.ts.Delete(ctx, NSItems, DateIndexKey(previous.FolderID, previous.InternalDate.Format("20060102"), previous.ID))
			}
			is.removeExternalIndexes(ctx, previous)
		}
	}
	if accountQuota && is.us != nil && folder.UserID != "" {
		itemDelta := 1
		storageDelta := item.Size
		if previousFound {
			itemDelta = 0
			storageDelta -= previous.Size
		}
		if err := is.us.AdjustUsage(ctx, folder.UserID, storageDelta, itemDelta); err != nil {
			return err
		}
	}
	if accountQuota {
		switch {
		case !previousFound:
			adjustFolderUsage(&folder, 1, item.Size)
		case previous.FolderID == item.FolderID:
			adjustFolderUsage(&folder, 0, item.Size-previous.Size)
		default:
			adjustFolderUsage(&previousFolder, -1, -previous.Size)
			adjustFolderUsage(&folder, 1, item.Size)
			if err := is.ts.Set(ctx, NSFolders, previousFolder.ID, previousFolder); err != nil {
				return err
			}
		}
	}
	folderChanged := accountQuota
	if item.ModSeq > folder.HighestModSeq {
		folder.HighestModSeq = item.ModSeq
		folder.UpdatedAt = time.Now().UTC()
		folderChanged = true
	}
	if folderChanged {
		if err := is.ts.Set(ctx, NSFolders, folder.ID, folder); err != nil {
			return err
		}
	}
	if err := is.persistItem(ctx, item); err != nil {
		return err
	}
	if err := is.ts.Set(ctx, NSItems, ItemMemberKey(item.FolderID, item.ID), item.ID); err != nil {
		return err
	}
	if err := is.ts.Set(ctx, NSItems, ItemNameKey(item.FolderID, item.Name), item.ID); err != nil {
		return err
	}
	if item.UID != 0 {
		if err := is.ts.Set(ctx, NSItems, UIDIndexKey(item.FolderID, item.UID), item.ID); err != nil {
			return err
		}
	}
	if !item.InternalDate.IsZero() {
		if err := is.ts.Set(ctx, NSItems, DateIndexKey(item.FolderID, item.InternalDate.Format("20060102"), item.ID), item.ID); err != nil {
			return err
		}
	}
	for namespace, externalID := range item.ExternalIDs {
		if namespace == "" || externalID == "" {
			continue
		}
		if err := is.ts.Set(ctx, NSItems, ExternalItemIndexKey(item.FolderID, namespace, externalID), item.ID); err != nil {
			return err
		}
	}
	return nil
}

func adjustFolderUsage(folder *Folder, itemDelta, byteDelta int64) {
	if folder.UsageVersion != 1 {
		return
	}
	folder.ItemCount = max(int64(0), folder.ItemCount+itemDelta)
	folder.LogicalBytes = max(int64(0), folder.LogicalBytes+byteDelta)
	folder.UpdatedAt = time.Now().UTC()
}

func (is *ItemStore) persistItem(ctx context.Context, item Item) error {
	if is.ts.objects == nil {
		return is.ts.Set(ctx, NSItems, item.ID, item)
	}

	var previous storedItem
	previousErr := is.ts.Get(ctx, NSItems, item.ID, &previous)
	if previousErr != nil && !errors.Is(previousErr, store.ErrNotFound) {
		return previousErr
	}
	payloadRef := previous.Payload
	if payloadRef == nil || !payloadMatches(*payloadRef, item.Data) {
		folder, err := is.getFolder(ctx, item.FolderID)
		if err != nil {
			return fmt.Errorf("read item folder for object storage: %w", err)
		}
		ref, err := is.ts.objects.Put(ctx, objectstore.Header{
			ItemID:      item.ID,
			FolderID:    item.FolderID,
			ContentType: folderContentType(folder.Type),
		}, int64(len(item.Data)), bytes.NewReader(item.Data))
		if err != nil {
			return fmt.Errorf("store item payload: %w", err)
		}
		payloadRef = &ref
	}
	metadata := item
	metadata.Data = nil
	return is.ts.Set(ctx, NSItems, item.ID, storedItem{Item: metadata, Payload: payloadRef})
}

func payloadMatches(ref objectstore.Ref, payload []byte) bool {
	if ref.PayloadLength != int64(len(payload)) {
		return false
	}
	digest := sha256.Sum256(payload)
	return ref.Digest == hex.EncodeToString(digest[:])
}

func folderContentType(folderType FolderType) string {
	switch folderType {
	case FolderTypeMail:
		return "message/rfc822"
	case FolderTypeCalendar, FolderTypeTasks, FolderTypeScheduleInbox, FolderTypeScheduleOutbox:
		return "text/calendar"
	case FolderTypeContacts:
		return "text/vcard"
	case FolderTypeNotes:
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}

func (is *ItemStore) resolveName(ctx context.Context, folderID, name string) (string, error) {
	if folder, err := is.getFolder(ctx, folderID); err == nil {
		folderID = folder.ID
	}
	var id string
	if err := is.ts.Get(ctx, NSItems, ItemNameKey(folderID, name), &id); err != nil {
		return "", err
	}
	return id, nil
}

func splitItemKey(id string) (folderID, name string, ok bool) {
	if !strings.HasPrefix(id, "fld_") {
		return "", "", false
	}
	idx := strings.Index(id, ":")
	if idx < 1 || idx == len(id)-1 {
		return "", "", false
	}
	return id[:idx], id[idx+1:], true
}

// SearchByDate returns items whose InternalDate falls within [since, before).
// It uses the date secondary index for efficient lookup.
func (is *ItemStore) SearchByDate(ctx context.Context, folderID string, since, before time.Time) ([]Item, error) {
	// Scan date index entries for this folder using the prefix.
	prefix := DateIndexPrefix(folderID)
	keys, err := is.ts.Scan(ctx, NSItems, prefix)
	if err != nil {
		return nil, fmt.Errorf("scan date index: %w", err)
	}

	// Collect item IDs from matching date index entries.
	sinceStr := since.Format("20060102")
	beforeStr := before.Format("20060102")
	seen := make(map[string]bool)
	var itemIDs []string
	for _, k := range keys {
		// k is "date:{folderID}:{YYYYMMDD}:{itemID}" — extract the date portion.
		dateStart := len("date:") + len(folderID) + 1 // +1 for the colon after folderID
		if dateStart >= len(k) || dateStart+8 > len(k) {
			continue
		}
		dateStr := k[dateStart : dateStart+8]
		if dateStr < sinceStr || dateStr >= beforeStr {
			continue
		}
		// The item ID follows the date string and another colon.
		itemIDStart := dateStart + 8 + 1 // +1 for the colon after date
		if itemIDStart >= len(k) {
			continue
		}
		itemID := k[itemIDStart:]
		if !seen[itemID] {
			seen[itemID] = true
			itemIDs = append(itemIDs, itemID)
		}
	}

	// Fetch the items.
	items := make([]Item, 0, len(itemIDs))
	for _, itemID := range itemIDs {
		item, err := is.Get(ctx, itemID)
		if err != nil {
			// Skip deleted items (they may have been removed between index scan and fetch).
			continue
		}
		items = append(items, item)
	}

	return items, nil
}
