package service

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

type FolderCacheConfig struct {
	// Disabled turns the cache into a pass-through; its contents are dropped.
	Disabled   bool
	TTL        time.Duration
	MaxEntries int
	MaxBytes   int64
}

type FolderCacheStats struct {
	Entries   int    `json:"entries"`
	Bytes     int64  `json:"bytes"`
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	Evictions uint64 `json:"evictions"`
}

// cacheClass separates the reads that interactive sessions repeat from the
// item content that bulk readers pass over once.
type cacheClass int

const (
	// classListing holds folders and folder listings.
	classListing cacheClass = iota
	// classItem holds single item reads.
	classItem
	cacheClasses
)

type folderCacheEntry struct {
	key       string
	value     any
	stored    time.Time
	size      int64
	scopes    map[string]struct{}
	class     cacheClass
	protected bool
}

// cacheSegment is one least recently used list and the bytes it holds.
type cacheSegment struct {
	lru   *list.List
	bytes int64
}

// cacheClassSegments is one class's segmented LRU.
type cacheClassSegments struct {
	probation cacheSegment
	protected cacheSegment
}

func (c *cacheClassSegments) entries() int { return c.probation.lru.Len() + c.protected.lru.Len() }
func (c *cacheClassSegments) bytes() int64 { return c.probation.bytes + c.protected.bytes }

// CachedFolderSpace is a transparent bounded read-through decorator. Its
// authority remains the wrapped FolderSpace; every successful mutation clears
// cached reads before returning to the caller.
//
// The cache resists scans so a one-pass read of many items cannot flush the
// folders and listings that interactive clients reread:
//
//   - Listings and single items are separate classes. Each is guaranteed half
//     of the entry and byte limits and may borrow what the other leaves
//     unused; when the cache is full, the class over its half yields.
//   - Within a class the cache is a segmented LRU. A new entry starts on
//     probation and a later hit moves it to the protected segment, which may
//     hold up to four fifths of the class's half. Eviction takes the least
//     recently used probationary entry first; protected entries pushed out of
//     their segment return to probation rather than leaving the cache.
//   - As in 2Q, the keys of evicted entries, and of protected entries that
//     expired or were invalidated, are remembered without their values. A
//     read that stores a remembered key again is reuse and enters the
//     protected segment directly.
//   - Reads marked with WithBulkRead use cached entries but never store or
//     promote item content.
type CachedFolderSpace struct {
	next       FolderSpace
	mu         sync.Mutex
	entries    map[string]*list.Element
	classes    [cacheClasses]cacheClassSegments
	ghosts     map[string]*list.Element
	ghostOrder *list.List
	disabled   bool
	ttl        time.Duration
	maxEntries int
	maxBytes   int64
	bytes      int64
	hits       atomic.Uint64
	misses     atomic.Uint64
	evictions  atomic.Uint64
}

type bulkReadKey struct{}

// WithBulkRead marks ctx as a one-pass read of many items, such as an export
// or a FETCH over a message range. Such reads still use cached entries but do
// not populate the cache with item content or count as reuse, so they cannot
// evict the hot entries of interactive sessions.
func WithBulkRead(ctx context.Context) context.Context {
	return context.WithValue(ctx, bulkReadKey{}, true)
}

// IsBulkRead reports whether ctx was marked with WithBulkRead.
func IsBulkRead(ctx context.Context) bool {
	bulk, _ := ctx.Value(bulkReadKey{}).(bool)
	return bulk
}

func NewCachedFolderSpace(next FolderSpace, cfg FolderCacheConfig) *CachedFolderSpace {
	s := &CachedFolderSpace{next: next, ghostOrder: list.New()}
	for class := range s.classes {
		s.classes[class] = cacheClassSegments{probation: cacheSegment{lru: list.New()}, protected: cacheSegment{lru: list.New()}}
	}
	s.clearLocked()
	s.SetConfig(cfg)
	return s
}

// SetConfig applies new limits to a running cache. Disabling drops every
// cached read, a shorter lifetime also applies to entries already cached, and
// lower limits evict the least recently used entries immediately.
func (s *CachedFolderSpace) SetConfig(cfg FolderCacheConfig) {
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Second
	}
	if cfg.MaxEntries < 1 {
		cfg.MaxEntries = 4096
	}
	if cfg.MaxBytes < 1 {
		cfg.MaxBytes = 64 << 20
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disabled, s.ttl, s.maxEntries, s.maxBytes = cfg.Disabled, cfg.TTL, cfg.MaxEntries, cfg.MaxBytes
	if s.disabled {
		s.clearLocked()
		return
	}
	s.evictLocked()
}

// Enabled reports whether reads are currently cached.
func (s *CachedFolderSpace) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.disabled
}

func (s *CachedFolderSpace) Stats() FolderCacheStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return FolderCacheStats{Entries: len(s.entries), Bytes: s.bytes, Hits: s.hits.Load(), Misses: s.misses.Load(), Evictions: s.evictions.Load()}
}

func (s *CachedFolderSpace) Clear() {
	s.mu.Lock()
	s.clearLocked()
	s.mu.Unlock()
}

func (s *CachedFolderSpace) clearLocked() {
	s.entries = make(map[string]*list.Element)
	for class := range s.classes {
		segments := &s.classes[class]
		segments.probation.lru.Init()
		segments.protected.lru.Init()
		segments.probation.bytes, segments.protected.bytes = 0, 0
	}
	s.bytes = 0
	s.ghosts = make(map[string]*list.Element)
	s.ghostOrder.Init()
}

func (s *CachedFolderSpace) segmentLocked(entry *folderCacheEntry) *cacheSegment {
	if entry.protected {
		return &s.classes[entry.class].protected
	}
	return &s.classes[entry.class].probation
}

// pushLocked adds entry as the most recent of its segment.
func (s *CachedFolderSpace) pushLocked(entry *folderCacheEntry) {
	segment := s.segmentLocked(entry)
	segment.bytes += entry.size
	s.entries[entry.key] = segment.lru.PushFront(entry)
}

// unlinkLocked takes an entry out of its segment, keeping it in the map.
func (s *CachedFolderSpace) unlinkLocked(element *list.Element) *folderCacheEntry {
	entry := element.Value.(*folderCacheEntry)
	segment := s.segmentLocked(entry)
	segment.bytes -= entry.size
	segment.lru.Remove(element)
	return entry
}

func (s *CachedFolderSpace) removeLocked(element *list.Element) {
	if element == nil {
		return
	}
	entry := s.unlinkLocked(element)
	delete(s.entries, entry.key)
	s.bytes -= entry.size
}

// rememberLocked records the key of an entry that left the cache, keeping at
// most maxEntries such keys.
func (s *CachedFolderSpace) rememberLocked(key string) {
	if element := s.ghosts[key]; element != nil {
		s.ghostOrder.MoveToFront(element)
	} else {
		s.ghosts[key] = s.ghostOrder.PushFront(key)
	}
	s.trimGhostsLocked()
}

func (s *CachedFolderSpace) trimGhostsLocked() {
	for s.ghostOrder.Len() > s.maxEntries {
		oldest := s.ghostOrder.Back()
		delete(s.ghosts, oldest.Value.(string))
		s.ghostOrder.Remove(oldest)
	}
}

// forgetLocked reports whether key was remembered, and forgets it.
func (s *CachedFolderSpace) forgetLocked(key string) bool {
	element := s.ghosts[key]
	if element == nil {
		return false
	}
	delete(s.ghosts, key)
	s.ghostOrder.Remove(element)
	return true
}

// balanceLocked returns a class's protected entries over four fifths of the
// class's half of the limits to probation.
func (s *CachedFolderSpace) balanceLocked(class cacheClass) {
	protected := &s.classes[class].protected
	for protected.lru.Len()*5 > s.maxEntries*2 || protected.bytes*5 > s.maxBytes*2 {
		entry := s.unlinkLocked(protected.lru.Back())
		entry.protected = false
		s.pushLocked(entry)
	}
}

// victimClassLocked picks the class that yields when the cache is over a
// limit: the one holding more than its half of that limit.
func (s *CachedFolderSpace) victimClassLocked() cacheClass {
	items := &s.classes[classItem]
	if len(s.entries) > s.maxEntries {
		if items.entries()*2 > s.maxEntries {
			return classItem
		}
		return classListing
	}
	if items.bytes()*2 > s.maxBytes {
		return classItem
	}
	return classListing
}

// evictLocked rebalances the segments, then drops least recently used
// entries, probationary first, until the limits hold.
func (s *CachedFolderSpace) evictLocked() {
	s.trimGhostsLocked()
	for class := range cacheClasses {
		s.balanceLocked(class)
	}
	for len(s.entries) > s.maxEntries || s.bytes > s.maxBytes {
		segments := &s.classes[s.victimClassLocked()]
		victim := segments.probation.lru.Back()
		if victim == nil {
			victim = segments.protected.lru.Back()
		}
		s.rememberLocked(victim.Value.(*folderCacheEntry).key)
		s.removeLocked(victim)
		s.evictions.Add(1)
	}
}

func cacheAccess(access AccessContext) string {
	return string(access.Actor.Kind) + ":" + access.Actor.ID + ":" + string(access.Subject.Kind) + ":" + access.Subject.ID + ":" + string(access.Mode)
}

// selfCacheAccess admits a user reading their own account. Compliance and
// indexer access, which also see held-deleted items, always read through.
func selfCacheAccess(access AccessContext) bool {
	return !heldVisible(access) && access.Actor.Kind == model.PrincipalUser && access.Subject.Kind == model.PrincipalUser && access.Actor.ID == access.Subject.ID && access.Mode == ""
}

// load returns a cached value. A read that is not reuse, such as a bulk
// read, neither promotes the entry nor refreshes its recency.
func (s *CachedFolderSpace) load(key string, reuse bool) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	element := s.entries[key]
	if s.disabled || element == nil {
		s.misses.Add(1)
		return nil, false
	}
	entry := element.Value.(*folderCacheEntry)
	if time.Now().After(entry.stored.Add(s.ttl)) {
		if entry.protected {
			s.rememberLocked(key)
		}
		s.removeLocked(element)
		s.misses.Add(1)
		return nil, false
	}
	switch {
	case !reuse:
	case entry.protected:
		s.classes[entry.class].protected.lru.MoveToFront(element)
	default:
		s.unlinkLocked(element)
		entry.protected = true
		s.pushLocked(entry)
		s.balanceLocked(entry.class)
	}
	s.hits.Add(1)
	return cloneCached(entry.value), true
}

func (s *CachedFolderSpace) store(class cacheClass, key string, value any, scopes ...string) {
	size := cacheValueSize(value)
	s.mu.Lock()
	tooLarge := s.disabled || size > s.maxBytes
	s.mu.Unlock()
	if tooLarge {
		return
	}
	value = cloneCached(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disabled || size > s.maxBytes {
		return
	}
	reused := s.forgetLocked(key)
	if existing := s.entries[key]; existing != nil {
		reused = reused || existing.Value.(*folderCacheEntry).protected
		s.removeLocked(existing)
	}
	entryScopes := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope != "" {
			entryScopes[scope] = struct{}{}
		}
	}
	s.pushLocked(&folderCacheEntry{key: key, value: value, stored: time.Now(), size: size, scopes: entryScopes, class: class, protected: reused})
	s.bytes += size
	s.evictLocked()
}

func (s *CachedFolderSpace) invalidate(scopes ...string) {
	wanted := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope != "" {
			wanted[scope] = struct{}{}
		}
	}
	s.mu.Lock()
	for _, element := range s.entries {
		entry := element.Value.(*folderCacheEntry)
		remove := false
		for scope := range wanted {
			if _, ok := entry.scopes[scope]; ok {
				remove = true
				break
			}
		}
		if remove {
			if entry.protected {
				s.rememberLocked(entry.key)
			}
			s.removeLocked(element)
		}
	}
	s.mu.Unlock()
}

func cacheValueSize(value any) int64 {
	switch typed := value.(type) {
	case model.Item:
		size := int64(len(typed.Data) + len(typed.Name) + 512)
		for name, value := range typed.Headers {
			size += int64(len(name) + len(value))
		}
		return size
	case []model.Item:
		var size int64
		for _, item := range typed {
			size += cacheValueSize(item)
		}
		return size
	case model.Folder:
		return int64(len(typed.Name) + len(typed.Path) + 512)
	case []model.Folder:
		return int64(len(typed) * 512)
	default:
		return 256
	}
}

func cloneCached(value any) any {
	switch typed := value.(type) {
	case model.Item:
		return cloneItem(typed)
	case []model.Item:
		result := make([]model.Item, len(typed))
		for index := range typed {
			result[index] = cloneItem(typed[index])
		}
		return result
	case []model.Folder:
		return append([]model.Folder(nil), typed...)
	default:
		return value
	}
}

func cloneItem(item model.Item) model.Item {
	item.Data = append([]byte(nil), item.Data...)
	item.Flags = append([]string(nil), item.Flags...)
	item.Headers = cloneStringMap(item.Headers)
	item.ExternalIDs = cloneStringMap(item.ExternalIDs)
	return item
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func (s *CachedFolderSpace) AccountUsage(ctx context.Context, access AccessContext) (AccountUsage, error) {
	return s.next.AccountUsage(ctx, access)
}

func (s *CachedFolderSpace) ListFolders(ctx context.Context, access AccessContext, query FolderQuery) ([]model.Folder, error) {
	if !selfCacheAccess(access) {
		return s.next.ListFolders(ctx, access, query)
	}
	key := fmt.Sprintf("folders:%s:%s:%t", cacheAccess(access), query.Type, query.IncludeTrashed)
	if value, ok := s.load(key, true); ok {
		return value.([]model.Folder), nil
	}
	value, err := s.next.ListFolders(ctx, access, query)
	if err == nil {
		scopes := make([]string, len(value))
		for index := range value {
			if value[index].UserID != access.Subject.ID {
				return value, nil
			}
			scopes[index] = value[index].ID
		}
		s.store(classListing, key, value, scopes...)
	}
	return value, err
}

func (s *CachedFolderSpace) GetFolder(ctx context.Context, access AccessContext, id string) (model.Folder, error) {
	return cacheFolderRead(s, access, "folder:"+cacheAccess(access)+":"+id, func() (model.Folder, error) { return s.next.GetFolder(ctx, access, id) })
}
func (s *CachedFolderSpace) GetFolderByPath(ctx context.Context, access AccessContext, path string) (model.Folder, error) {
	return cacheFolderRead(s, access, "folder-path:"+cacheAccess(access)+":"+path, func() (model.Folder, error) { return s.next.GetFolderByPath(ctx, access, path) })
}
func (s *CachedFolderSpace) GetFolderByOwnerPath(ctx context.Context, access AccessContext, owner, path string) (model.Folder, error) {
	return cacheFolderRead(s, access, "folder-owner-path:"+cacheAccess(access)+":"+owner+":"+path, func() (model.Folder, error) { return s.next.GetFolderByOwnerPath(ctx, access, owner, path) })
}

// cacheFolderRead caches one folder. Folders are small and every cached item
// read consults its folder, so bulk reads cache them too.
func cacheFolderRead(s *CachedFolderSpace, access AccessContext, key string, load func() (model.Folder, error)) (model.Folder, error) {
	if !selfCacheAccess(access) {
		return load()
	}
	if value, ok := s.load(key, true); ok {
		return value.(model.Folder), nil
	}
	value, err := load()
	if err == nil && value.UserID == access.Subject.ID {
		s.store(classListing, key, value, value.ID)
	}
	return value, err
}

func (s *CachedFolderSpace) ListItems(ctx context.Context, access AccessContext, folderID string, query ItemQuery) ([]model.Item, error) {
	folder, folderErr := s.GetFolder(ctx, access, folderID)
	if folderErr != nil {
		return nil, folderErr
	}
	if folder.UserID != access.Subject.ID || !selfCacheAccess(access) {
		return s.next.ListItems(ctx, access, folderID, query)
	}
	key := fmt.Sprintf("items:%s:%s:%d:%t:%t:%d:%d", cacheAccess(access), folderID, query.Limit, query.MetadataOnly, query.RequireRead, query.Since.UnixNano(), query.Before.UnixNano())
	bulk := IsBulkRead(ctx)
	if value, ok := s.load(key, !bulk); ok {
		return value.([]model.Item), nil
	}
	value, err := s.next.ListItems(ctx, access, folderID, query)
	if err == nil && !bulk {
		s.store(classListing, key, value, folderID)
	}
	return value, err
}

func (s *CachedFolderSpace) ListItemPage(ctx context.Context, access AccessContext, folderID string, query ItemPageQuery) (ItemPage, error) {
	pager, ok := s.next.(FolderItemPager)
	if !ok {
		return ItemPage{}, errors.New("bounded item paging is unavailable")
	}
	return pager.ListItemPage(ctx, access, folderID, query)
}

func (s *CachedFolderSpace) GetItem(ctx context.Context, access AccessContext, id string) (model.Item, error) {
	return cacheItemRead(ctx, s, access, "item:"+cacheAccess(access)+":"+id, func() (model.Item, error) { return s.next.GetItem(ctx, access, id) })
}
func (s *CachedFolderSpace) GetItemByUID(ctx context.Context, access AccessContext, folderID string, uid uint32) (model.Item, error) {
	return cacheItemRead(ctx, s, access, fmt.Sprintf("item-uid:%s:%s:%d", cacheAccess(access), folderID, uid), func() (model.Item, error) { return s.next.GetItemByUID(ctx, access, folderID, uid) })
}
func (s *CachedFolderSpace) GetItemByName(ctx context.Context, access AccessContext, folderID, name string) (model.Item, error) {
	return cacheItemRead(ctx, s, access, "item-name:"+cacheAccess(access)+":"+folderID+":"+name, func() (model.Item, error) { return s.next.GetItemByName(ctx, access, folderID, name) })
}
func (s *CachedFolderSpace) GetItemByExternalID(ctx context.Context, access AccessContext, folderID, namespace, externalID string) (model.Item, error) {
	return cacheItemRead(ctx, s, access, "item-external:"+cacheAccess(access)+":"+folderID+":"+namespace+":"+externalID, func() (model.Item, error) {
		return s.next.GetItemByExternalID(ctx, access, folderID, namespace, externalID)
	})
}
func (s *CachedFolderSpace) GetItemMetadataByExternalID(ctx context.Context, access AccessContext, folderID, namespace, externalID string) (model.Item, error) {
	return cacheItemRead(ctx, s, access, "item-external-metadata:"+cacheAccess(access)+":"+folderID+":"+namespace+":"+externalID, func() (model.Item, error) {
		return s.next.GetItemMetadataByExternalID(ctx, access, folderID, namespace, externalID)
	})
}

// itemLimit is the largest single item the cache stores.
func (s *CachedFolderSpace) itemLimit() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxBytes / 64
}

func cacheItemRead(ctx context.Context, s *CachedFolderSpace, access AccessContext, key string, load func() (model.Item, error)) (model.Item, error) {
	if !selfCacheAccess(access) {
		return load()
	}
	bulk := IsBulkRead(ctx)
	if value, ok := s.load(key, !bulk); ok {
		return value.(model.Item), nil
	}
	value, err := load()
	// A message with large attachments would evict many folder listings for
	// one rarely repeated read, so single items are cached only up to a
	// small share of the cache. A bulk read is one pass and is not stored.
	if err == nil && !bulk && cacheValueSize(value) <= s.itemLimit() {
		folder, folderErr := s.GetFolder(ctx, access, value.FolderID)
		if folderErr == nil && folder.UserID == access.Subject.ID {
			s.store(classItem, key, value, value.FolderID)
		}
	}
	return value, err
}

func (s *CachedFolderSpace) CreateFolder(ctx context.Context, access AccessContext, name string, kind model.FolderType, parent string) (model.Folder, error) {
	value, err := s.next.CreateFolder(ctx, access, name, kind, parent)
	s.clearOnSuccess(err)
	return value, err
}
func (s *CachedFolderSpace) UpdateFolder(ctx context.Context, access AccessContext, id string, update FolderUpdate) (model.Folder, error) {
	value, err := s.next.UpdateFolder(ctx, access, id, update)
	s.clearOnSuccess(err)
	return value, err
}
func (s *CachedFolderSpace) MoveFolder(ctx context.Context, access AccessContext, id, parent, name string) (model.Folder, error) {
	value, err := s.next.MoveFolder(ctx, access, id, parent, name)
	s.clearOnSuccess(err)
	return value, err
}
func (s *CachedFolderSpace) DeleteFolder(ctx context.Context, access AccessContext, id string) error {
	err := s.next.DeleteFolder(ctx, access, id)
	s.clearOnSuccess(err)
	return err
}
func (s *CachedFolderSpace) CreateItem(ctx context.Context, access AccessContext, folderID string, input ItemInput) (model.Item, error) {
	value, err := s.next.CreateItem(ctx, access, folderID, input)
	if err == nil {
		s.invalidate(folderID)
	}
	return value, err
}
func (s *CachedFolderSpace) CreateItems(ctx context.Context, access AccessContext, folderID string, inputs []ItemInput) ([]model.Item, error) {
	creator, ok := s.next.(FolderItemBatchCreator)
	if !ok {
		return nil, errors.New("atomic multi-item creation is unavailable")
	}
	values, err := creator.CreateItems(ctx, access, folderID, inputs)
	if err == nil {
		s.invalidate(folderID)
	}
	return values, err
}
func (s *CachedFolderSpace) CreateItemIfAbsent(ctx context.Context, access AccessContext, folderID string, input ItemInput) (model.Item, error) {
	creator, ok := s.next.(ExclusiveItemCreator)
	if !ok {
		return model.Item{}, errors.New("exclusive item creation is unavailable")
	}
	value, err := creator.CreateItemIfAbsent(ctx, access, folderID, input)
	if err == nil {
		s.invalidate(folderID)
	}
	return value, err
}
func (s *CachedFolderSpace) BindItemExternalID(ctx context.Context, access AccessContext, id, namespace, externalID string) (model.Item, error) {
	value, err := s.next.BindItemExternalID(ctx, access, id, namespace, externalID)
	if err == nil {
		s.invalidate(value.FolderID)
	}
	return value, err
}
func (s *CachedFolderSpace) UpdateItem(ctx context.Context, access AccessContext, id string, data []byte, headers map[string]string) (model.Item, error) {
	value, err := s.next.UpdateItem(ctx, access, id, data, headers)
	if err == nil {
		s.invalidate(value.FolderID)
	}
	return value, err
}
func (s *CachedFolderSpace) UpdateItemIfModSeq(ctx context.Context, access AccessContext, id string, expected uint64, data []byte, headers map[string]string) (model.Item, error) {
	updater, ok := s.next.(ConditionalItemUpdater)
	if !ok {
		return model.Item{}, errors.New("conditional item update is unavailable")
	}
	value, err := updater.UpdateItemIfModSeq(ctx, access, id, expected, data, headers)
	if err == nil {
		s.invalidate(value.FolderID)
	}
	return value, err
}
func (s *CachedFolderSpace) SetFlags(ctx context.Context, access AccessContext, id string, flags []string) (model.Item, error) {
	value, err := s.next.SetFlags(ctx, access, id, flags)
	if err == nil {
		s.invalidate(value.FolderID)
	}
	return value, err
}
func (s *CachedFolderSpace) MoveItem(ctx context.Context, access AccessContext, id, folderID, name string) (model.Item, error) {
	before, _ := s.next.GetItem(ctx, access, id)
	value, err := s.next.MoveItem(ctx, access, id, folderID, name)
	if err == nil {
		s.invalidate(before.FolderID, value.FolderID)
	}
	return value, err
}
func (s *CachedFolderSpace) CopyItem(ctx context.Context, access AccessContext, id, folderID, name string) (model.Item, error) {
	value, err := s.next.CopyItem(ctx, access, id, folderID, name)
	if err == nil {
		s.invalidate(value.FolderID)
	}
	return value, err
}
func (s *CachedFolderSpace) DeleteItem(ctx context.Context, access AccessContext, id string) error {
	before, _ := s.next.GetItem(ctx, access, id)
	err := s.next.DeleteItem(ctx, access, id)
	if err == nil {
		s.invalidate(before.FolderID)
	}
	return err
}
func (s *CachedFolderSpace) clearOnSuccess(err error) {
	if err == nil {
		s.Clear()
	}
}

func (s *CachedFolderSpace) Batch(ctx context.Context, fn func(context.Context) error) error {
	err := Batch(ctx, s.next, fn)
	s.clearOnSuccess(err)
	return err
}
func (s *CachedFolderSpace) CurrentChangeState(ctx context.Context, access AccessContext, scope ChangeScope) (string, error) {
	reader, ok := s.next.(FolderChangeReader)
	if !ok {
		return "", errors.New("folder change history is unavailable")
	}
	return reader.CurrentChangeState(ctx, access, scope)
}
func (s *CachedFolderSpace) ListChanges(ctx context.Context, access AccessContext, scope ChangeScope, state string, limit int) (ChangePage, error) {
	reader, ok := s.next.(FolderChangeReader)
	if !ok {
		return ChangePage{}, errors.New("folder change history is unavailable")
	}
	return reader.ListChanges(ctx, access, scope, state, limit)
}

// OnChangesCommitted forwards FolderChangeNotifier to the wrapped space.
func (s *CachedFolderSpace) OnChangesCommitted(listener func(accountID string, folderIDs []string)) func() {
	notifier, ok := s.next.(FolderChangeNotifier)
	if !ok {
		return func() {}
	}
	return notifier.OnChangesCommitted(listener)
}

func (s *CachedFolderSpace) itemHistory() (ItemHistoryFolderSpace, error) {
	value, ok := s.next.(ItemHistoryFolderSpace)
	if !ok {
		return nil, ErrItemHistoryUnavailable
	}
	return value, nil
}
func (s *CachedFolderSpace) GetItemHistoryPolicy(ctx context.Context, access AccessContext, folderID string) (model.ItemHistoryPolicy, error) {
	value, err := s.itemHistory()
	if err != nil {
		return model.ItemHistoryPolicy{}, err
	}
	return value.GetItemHistoryPolicy(ctx, access, folderID)
}
func (s *CachedFolderSpace) ConfigureItemHistory(ctx context.Context, access AccessContext, folderID string, policy model.ItemHistoryPolicy) (model.Folder, error) {
	value, err := s.itemHistory()
	if err != nil {
		return model.Folder{}, err
	}
	folder, err := value.ConfigureItemHistory(ctx, access, folderID, policy)
	s.clearOnSuccess(err)
	return folder, err
}
func (s *CachedFolderSpace) ListItemVersions(ctx context.Context, access AccessContext, folderID, itemID string) ([]model.ItemVersion, error) {
	value, err := s.itemHistory()
	if err != nil {
		return nil, err
	}
	return value.ListItemVersions(ctx, access, folderID, itemID)
}
func (s *CachedFolderSpace) GetItemVersion(ctx context.Context, access AccessContext, folderID, itemID, versionID string) (model.ItemVersion, error) {
	value, err := s.itemHistory()
	if err != nil {
		return model.ItemVersion{}, err
	}
	return value.GetItemVersion(ctx, access, folderID, itemID, versionID)
}
func (s *CachedFolderSpace) RestoreItemVersion(ctx context.Context, access AccessContext, folderID, itemID, versionID string) (model.Item, error) {
	value, err := s.itemHistory()
	if err != nil {
		return model.Item{}, err
	}
	item, err := value.RestoreItemVersion(ctx, access, folderID, itemID, versionID)
	if err == nil {
		s.invalidate(folderID)
	}
	return item, err
}
func (s *CachedFolderSpace) recoverable() (RecoverableFolderSpace, error) {
	value, ok := s.next.(RecoverableFolderSpace)
	if !ok {
		return nil, errors.New("recoverable folder operations are unavailable")
	}
	return value, nil
}
func (s *CachedFolderSpace) ListTrash(ctx context.Context, access AccessContext) ([]ItemSummary, error) {
	value, err := s.recoverable()
	if err != nil {
		return nil, err
	}
	return value.ListTrash(ctx, access)
}
func (s *CachedFolderSpace) ListTrashedFolders(ctx context.Context, access AccessContext) ([]model.Folder, error) {
	value, err := s.recoverable()
	if err != nil {
		return nil, err
	}
	return value.ListTrashedFolders(ctx, access)
}
func (s *CachedFolderSpace) RestoreFolder(ctx context.Context, access AccessContext, id string) (model.Folder, error) {
	next, err := s.recoverable()
	if err != nil {
		return model.Folder{}, err
	}
	value, err := next.RestoreFolder(ctx, access, id)
	s.clearOnSuccess(err)
	return value, err
}
func (s *CachedFolderSpace) PurgeFolder(ctx context.Context, access AccessContext, id string) error {
	next, err := s.recoverable()
	if err != nil {
		return err
	}
	err = next.PurgeFolder(ctx, access, id)
	s.clearOnSuccess(err)
	return err
}
func (s *CachedFolderSpace) TrashItem(ctx context.Context, access AccessContext, id string) (model.Item, error) {
	next, err := s.recoverable()
	if err != nil {
		return model.Item{}, err
	}
	before, _ := s.next.GetItem(ctx, access, id)
	value, err := next.TrashItem(ctx, access, id)
	if err == nil {
		s.invalidate(before.FolderID, value.FolderID)
	}
	return value, err
}
func (s *CachedFolderSpace) RestoreItem(ctx context.Context, access AccessContext, id string) (model.Item, error) {
	next, err := s.recoverable()
	if err != nil {
		return model.Item{}, err
	}
	before, _ := s.next.GetItem(ctx, access, id)
	value, err := next.RestoreItem(ctx, access, id)
	if err == nil {
		s.invalidate(before.FolderID, value.FolderID)
	}
	return value, err
}
func (s *CachedFolderSpace) SetLegalHolds(checker LegalHoldChecker) {
	if value, ok := s.next.(LegalHoldConfigurer); ok {
		value.SetLegalHolds(checker)
	}
}
func (s *CachedFolderSpace) SetTrashRetentionDays(days int) {
	if value, ok := s.next.(TrashRetentionConfigurer); ok {
		value.SetTrashRetentionDays(days)
	}
}
func (s *CachedFolderSpace) SetChangeRetention(days, entries int) {
	if value, ok := s.next.(ChangeRetentionConfigurer); ok {
		value.SetChangeRetention(days, entries)
	}
}
