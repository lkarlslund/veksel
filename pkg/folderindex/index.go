// Package folderindex provides durable, rebuildable derived indexes over the
// generic FolderSpace boundary. Item-type packages supply only projection
// semantics; storage lifecycle, generation checks, and bounded rebuilds stay
// shared.
package folderindex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	namespace = "folder_derived_indexes"
	pageSize  = 200
	// maxCachedSnapshots bounds the decoded snapshots kept in memory. Without
	// the cache every query re-reads and re-decodes the whole projection.
	maxCachedSnapshots = 32
	// maxProjectWorkers bounds the goroutines one rebuild of a
	// ParallelDefinition projects items on.
	maxProjectWorkers = 4
)

var ErrIndexNotAttached = errors.New("derived index is not attached to folder")

// Definition translates one opaque folder item into index keys and a compact
// type-specific value. A deferred document is retained by identity for lazy
// materialization, such as unbounded recurring calendar events.
type Definition interface {
	Name() string
	Version() int
	Project(model.Item) (Document, error)
}

// MetadataDefinition is implemented by definitions that project item
// metadata (flags, dates, sizes) alone, letting rebuilds skip payloads.
type MetadataDefinition interface {
	MetadataOnly() bool
}

// RevisionDefinition is implemented by definitions whose stored value format
// changes while the folder attachment Version stays: a snapshot projected by
// another revision is rebuilt instead of decoded.
type RevisionDefinition interface {
	Revision() int
}

func revision(definition Definition) int {
	if revised, ok := definition.(RevisionDefinition); ok {
		return revised.Revision()
	}
	return 0
}

// ParallelDefinition is implemented by definitions whose Project is safe
// for concurrent use and costly enough, such as parsing a full iCalendar
// payload, that a rebuild should spread it over several cores.
type ParallelDefinition interface {
	ParallelProject() bool
}

func metadataOnly(definition Definition) bool {
	metadata, ok := definition.(MetadataDefinition)
	return ok && metadata.MetadataOnly()
}

type Document struct {
	ItemID   string          `json:"item_id"`
	Keys     []string        `json:"keys,omitempty"`
	Deferred bool            `json:"deferred,omitempty"`
	Value    json.RawMessage `json:"value,omitempty"`
	// decoded memoizes Value for DecodeValue. A cached snapshot keeps it
	// across queries; a projected document's Value never changes.
	decoded any
}

// DecodeValue returns document's Value decoded as T, memoized on the
// document. Pass a pointer into the snapshot's slices so the memo survives
// with the cached snapshot. Callers must treat the result as read-only.
func DecodeValue[T any](document *Document) (T, error) {
	if decoded, ok := document.decoded.(T); ok {
		return decoded, nil
	}
	var decoded T
	if err := json.Unmarshal(document.Value, &decoded); err != nil {
		return decoded, err
	}
	document.decoded = decoded
	return decoded, nil
}

// DecodedDocument returns a document holding an already decoded value for
// DecodeValue. Its Value is empty, so it suits only Snapshot.Materialized,
// which is never stored.
func DecodedDocument[T any](itemID string, value T) Document {
	return Document{ItemID: itemID, decoded: value}
}

type Snapshot struct {
	Definition    string                `json:"definition"`
	Version       int                   `json:"version"`
	Revision      int                   `json:"revision,omitempty"`
	FolderID      string                `json:"folder_id"`
	HighestModSeq uint64                `json:"highest_mod_seq"`
	ItemCount     int64                 `json:"item_count"`
	Checkpoint    string                `json:"checkpoint,omitempty"`
	Buckets       map[string][]Document `json:"buckets"`
	Deferred      []Document            `json:"deferred,omitempty"`
	// Materialized holds lazily expanded documents, such as the occurrences
	// of deferred recurring events per month. It lives with the cached
	// snapshot only: expanding a month again is cheap, while storing every
	// expansion grew the stored projection and rewrote all of it whenever a
	// new month was viewed.
	Materialized map[string][]Document `json:"-"`
	BuiltAt      time.Time             `json:"built_at"`
	dirty        bool
}

// binaryPrefix marks a snapshot stored in the gob encoding. A gob snapshot
// copies each document's Value instead of scanning it as JSON text, which
// made loading a large projection the dominant cost of the first query after
// a restart. Snapshots stored as JSON by earlier releases still load and are
// rewritten in the binary encoding by their next save.
const binaryPrefix = "veksel-folderindex-gob-v1\x00"

func encodeSnapshot(snapshot Snapshot) ([]byte, error) {
	// gob ignores the json:"-" tag, so drop the in-memory expansions here;
	// snapshot is a copy and the cached map is untouched.
	snapshot.Materialized = nil
	var buffer bytes.Buffer
	buffer.WriteString(binaryPrefix)
	if err := gob.NewEncoder(&buffer).Encode(&snapshot); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func decodeSnapshot(raw []byte) (Snapshot, error) {
	var snapshot Snapshot
	var err error
	if encoded, ok := bytes.CutPrefix(raw, []byte(binaryPrefix)); ok {
		err = gob.NewDecoder(bytes.NewReader(encoded)).Decode(&snapshot)
	} else {
		err = json.Unmarshal(raw, &snapshot)
		// Rewrite a snapshot stored as JSON in the binary encoding.
		snapshot.dirty = true
	}
	if err != nil {
		return Snapshot{}, err
	}
	// Snapshots stored before encodeSnapshot dropped them may carry
	// expansions whose documents lost their decoded values.
	snapshot.Materialized = nil
	// gob leaves an empty map nil; catch-up adds documents to it.
	if snapshot.Buckets == nil {
		snapshot.Buckets = make(map[string][]Document)
	}
	return snapshot, nil
}

func (s *Snapshot) MarkDirty() { s.dirty = true }

type Index struct {
	store   store.Store
	sealer  atomic.Pointer[Sealer]
	builder atomic.Pointer[Builder]
	mu      sync.Mutex
	entries map[string]*entry
	clock   uint64
}

// entry serializes one folder/definition view and caches its last loaded or
// saved snapshot. The snapshot's maps are only touched under the entry lock;
// eviction merely drops the pointer.
type entry struct {
	sync.Mutex
	cached atomic.Pointer[Snapshot]
	// pending is set while a full rebuild of this view runs or is queued
	// for a query that found it stale, so interactive queries need not wait
	// on the entry lock.
	pending atomic.Bool
	used    uint64 // guarded by Index.mu
}

func New(s store.Store) *Index { return &Index{store: s, entries: make(map[string]*entry)} }

// WithSnapshot serializes one folder/definition view, rebuilding stale data
// through FolderSpace and persisting callback materializations atomically at
// the snapshot level.
func (i *Index) WithSnapshot(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, definition Definition, use func(*Snapshot) error) error {
	return i.withSnapshot(ctx, space, access, folder, definition, nil, use)
}

// WithBuiltSnapshot is WithSnapshot for interactive callers: a projection
// that needs a full rebuild (never built, built by another revision, or
// beyond the change journal's retention) is queued on the attached Builder
// and the call returns ErrBuilding at once. A current projection, or one the
// journal can catch up, is served as WithSnapshot serves it. Without a
// Builder the rebuild runs inline.
func (i *Index) WithBuiltSnapshot(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, definition Definition, build Build, use func(*Snapshot) error) error {
	return i.withSnapshot(ctx, space, access, folder, definition, &build, use)
}

func (i *Index) withSnapshot(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, definition Definition, background *Build, use func(*Snapshot) error) (err error) {
	if i == nil || i.store == nil || definition == nil {
		return errors.New("folder derived index is unavailable")
	}
	if !folder.HasIndex(definition.Name(), definition.Version()) {
		return fmt.Errorf("%w: %s", ErrIndexNotAttached, definition.Name())
	}
	entry := i.entry(definition.Name(), folder.ID)
	var builder *Builder
	if background != nil {
		builder = i.builder.Load()
	}
	// rebuild replaces a missing or stale snapshot: inline, or for an
	// interactive caller with a builder, by queueing it.
	rebuild := func() (Snapshot, error) {
		if builder != nil {
			builder.enqueue(i, entry, space, access, folder, definition, *background, true)
			return Snapshot{}, ErrBuilding
		}
		// Interactive callers skip the entry lock while it is held for a
		// full rebuild rather than wait for it.
		entry.pending.Store(true)
		defer entry.pending.Store(false)
		return i.rebuild(ctx, space, access, folder, definition)
	}
	if builder != nil && entry.pending.Load() {
		_, err := rebuild()
		return err
	}
	entry.Lock()
	defer entry.Unlock()
	defer func() {
		// Catch-up and callbacks change the snapshot in place; after a
		// failure only the stored copy is known to be consistent.
		if err != nil {
			entry.cached.Store(nil)
		}
	}()
	snapshot, err := i.load(ctx, entry, folder, definition)
	if err != nil {
		snapshot, err = rebuild()
		if err != nil {
			return err
		}
	} else if snapshot.HighestModSeq != folder.HighestModSeq || snapshot.ItemCount != folder.ItemCount {
		snapshot, err = i.catchUp(ctx, space, access, folder, definition, snapshot)
		if errors.Is(err, service.ErrChangeStateExpired) {
			snapshot, err = rebuild()
		}
		if err != nil {
			return err
		}
	} else if reader, ok := space.(service.FolderChangeReader); ok && snapshot.Checkpoint != "" {
		// The journal is account-wide. Keep a queried folder's safe checkpoint
		// at the journal head even when unrelated folders are busy, otherwise
		// its next single-item mutation must scan every intervening account
		// change before the index can catch up.
		checkpoint, checkpointErr := reader.CurrentChangeState(ctx, access, service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem})
		if checkpointErr != nil {
			return checkpointErr
		}
		if checkpoint != snapshot.Checkpoint {
			snapshot.Checkpoint = checkpoint
			snapshot.dirty = true
		}
	}
	if err := use(&snapshot); err != nil {
		return err
	}
	if snapshot.dirty {
		if err := i.save(ctx, folder.UserID, snapshot); err != nil {
			return err
		}
		snapshot.dirty = false
	}
	i.remember(entry, snapshot)
	return nil
}

func (i *Index) entry(name, folderID string) *entry {
	key := name + "\x00" + folderID
	i.mu.Lock()
	defer i.mu.Unlock()
	e := i.entries[key]
	if e == nil {
		e = &entry{}
		i.entries[key] = e
	}
	i.clock++
	e.used = i.clock
	return e
}

// remember caches snapshot for e and evicts the least recently used cached
// snapshot beyond maxCachedSnapshots.
func (i *Index) remember(e *entry, snapshot Snapshot) {
	e.cached.Store(&snapshot)
	i.mu.Lock()
	defer i.mu.Unlock()
	cached := 0
	var oldest *entry
	for _, candidate := range i.entries {
		if candidate.cached.Load() == nil {
			continue
		}
		cached++
		if candidate != e && (oldest == nil || candidate.used < oldest.used) {
			oldest = candidate
		}
	}
	if cached > maxCachedSnapshots {
		oldest.cached.Store(nil)
	}
}

func indexKey(name, folderID string) string {
	value := name + "\x00" + folderID
	return "projection/" + base64.RawURLEncoding.EncodeToString([]byte(value))
}

func (i *Index) load(ctx context.Context, e *entry, folder model.Folder, definition Definition) (Snapshot, error) {
	if cached := e.cached.Load(); cached != nil {
		return *cached, nil
	}
	key := indexKey(definition.Name(), folder.ID)
	raw, err := i.store.Get(ctx, namespace, key)
	if err != nil {
		return Snapshot{}, err
	}
	if raw, err = i.unseal(folder.UserID, key, raw); err != nil {
		return Snapshot{}, err
	}
	snapshot, err := decodeSnapshot(raw)
	if err != nil {
		return Snapshot{}, fmt.Errorf("decode %s folder index: %w", definition.Name(), err)
	}
	if snapshot.Definition != definition.Name() || snapshot.Version != definition.Version() || snapshot.Revision != revision(definition) || snapshot.FolderID != folder.ID {
		return Snapshot{}, errors.New("folder derived index is stale")
	}
	return snapshot, nil
}

func (i *Index) rebuild(ctx context.Context, space service.FolderSpace, access service.AccessContext, initial model.Folder, definition Definition) (Snapshot, error) {
	for attempt := 0; attempt < 3; attempt++ {
		folder, err := space.GetFolder(ctx, access, initial.ID)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot := Snapshot{Definition: definition.Name(), Version: definition.Version(), Revision: revision(definition), FolderID: folder.ID, HighestModSeq: folder.HighestModSeq, ItemCount: folder.ItemCount, Buckets: make(map[string][]Document), Materialized: make(map[string][]Document), BuiltAt: time.Now().UTC()}
		if reader, ok := space.(service.FolderChangeReader); ok {
			snapshot.Checkpoint, err = reader.CurrentChangeState(ctx, access, service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem})
			if err != nil {
				return Snapshot{}, err
			}
		}
		workers := projectWorkers(definition)
		if err := enumerate(ctx, space, access, folder.ID, !metadataOnly(definition), func(items []model.Item) {
			for _, document := range project(definition, items, workers) {
				addDocument(&snapshot, document)
			}
		}); err != nil {
			return Snapshot{}, err
		}
		current, err := space.GetFolder(ctx, access, folder.ID)
		if err != nil {
			return Snapshot{}, err
		}
		if current.HighestModSeq != folder.HighestModSeq || current.ItemCount != folder.ItemCount {
			if snapshot.Checkpoint == "" {
				continue
			}
			snapshot, err = i.catchUp(ctx, space, access, current, definition, snapshot)
			if err != nil {
				if errors.Is(err, service.ErrChangeStateExpired) {
					continue
				}
				return Snapshot{}, err
			}
		}
		if err := i.save(ctx, folder.UserID, snapshot); err != nil {
			return Snapshot{}, err
		}
		snapshot.dirty = false
		return snapshot, nil
	}
	return Snapshot{}, errors.New("folder changed repeatedly while its derived index was being built")
}

func (i *Index) catchUp(ctx context.Context, space service.FolderSpace, access service.AccessContext, folder model.Folder, definition Definition, snapshot Snapshot) (Snapshot, error) {
	reader, ok := space.(service.FolderChangeReader)
	if !ok || snapshot.Checkpoint == "" {
		return Snapshot{}, service.ErrChangeStateExpired
	}
	for {
		page, err := reader.ListChanges(ctx, access, service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem}, snapshot.Checkpoint, pageSize)
		if err != nil {
			return Snapshot{}, err
		}
		for _, record := range page.Records {
			for _, change := range record.Changes {
				removeDocument(&snapshot, change.ID)
				if change.FolderID != folder.ID || !indexesCurrentItem(change.Operation, folder) {
					continue
				}
				item, getErr := space.GetItem(ctx, access, change.ID)
				if getErr != nil {
					if errors.Is(getErr, store.ErrNotFound) {
						continue
					}
					return Snapshot{}, getErr
				}
				if item.FolderID != folder.ID || (!item.TrashedAt.IsZero() && folder.SpecialUse != model.SpecialUseTrash) {
					continue
				}
				document, projectErr := definition.Project(item)
				if projectErr != nil {
					continue
				}
				if document.ItemID == "" {
					document.ItemID = item.ID
				}
				addDocument(&snapshot, document)
			}
		}
		snapshot.Checkpoint = page.NewState
		if !page.HasMoreChanges && page.NewState == page.CurrentState {
			break
		}
	}
	current, err := space.GetFolder(ctx, access, folder.ID)
	if err != nil {
		return Snapshot{}, err
	}
	latest, err := reader.CurrentChangeState(ctx, access, service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem})
	if err != nil {
		return Snapshot{}, err
	}
	if latest != snapshot.Checkpoint {
		// Return the consistent checkpoint already projected. Keep the older
		// folder generation so the next query continues catch-up without an
		// unbounded retry while a busy import is mutating the folder.
		snapshot.Materialized = make(map[string][]Document)
		snapshot.dirty = true
		return snapshot, nil
	}
	snapshot.HighestModSeq, snapshot.ItemCount = current.HighestModSeq, current.ItemCount
	snapshot.Materialized = make(map[string][]Document)
	snapshot.dirty = true
	return snapshot, nil
}

// indexesCurrentItem reports whether a change leaves a listable item in
// folder. Recoverably deleted mail moves into the Trash folder, which lists it.
func indexesCurrentItem(operation service.ChangeOperation, folder model.Folder) bool {
	switch operation {
	case service.ChangeCreate, service.ChangeUpdate, service.ChangeMove, service.ChangeRestore:
		return true
	case service.ChangeTrash:
		return folder.SpecialUse == model.SpecialUseTrash
	}
	return false
}

func addDocument(snapshot *Snapshot, document Document) {
	if document.Deferred {
		snapshot.Deferred = append(snapshot.Deferred, document)
		return
	}
	for _, key := range document.Keys {
		snapshot.Buckets[key] = append(snapshot.Buckets[key], document)
	}
}

func removeDocument(snapshot *Snapshot, itemID string) {
	for key, documents := range snapshot.Buckets {
		filtered := documents[:0]
		for _, document := range documents {
			if document.ItemID != itemID {
				filtered = append(filtered, document)
			}
		}
		snapshot.Buckets[key] = filtered
	}
	filtered := snapshot.Deferred[:0]
	for _, document := range snapshot.Deferred {
		if document.ItemID != itemID {
			filtered = append(filtered, document)
		}
	}
	snapshot.Deferred = filtered
}

func (i *Index) save(ctx context.Context, owner string, snapshot Snapshot) error {
	if err := ensureNamespace(ctx, i.store); err != nil {
		return err
	}
	raw, err := encodeSnapshot(snapshot)
	if err != nil {
		return err
	}
	key := indexKey(snapshot.Definition, snapshot.FolderID)
	if sealer := i.loadSealer(); sealer != nil && sealer.DerivedEncrypted(owner) {
		sealed, err := sealer.SealDerived(owner, []byte(key), raw)
		if err != nil {
			return fmt.Errorf("seal %s folder index: %w", snapshot.Definition, err)
		}
		raw = append([]byte(sealedPrefix), sealed...)
	}
	return i.store.Set(ctx, namespace, key, raw)
}

// Sealer protects the snapshots of folders whose owner account is encrypted
// at rest: projections carry subjects, senders, previews, and event titles,
// and live in the system store outside the encrypted account directory.
// *account.Manager implements it.
type Sealer interface {
	DerivedEncrypted(owner string) bool
	SealDerived(owner string, aad, plaintext []byte) ([]byte, error)
	OpenDerived(owner string, aad, sealed []byte) ([]byte, error)
}

const sealedPrefix = "veksel-sealed-v1\x00"

// SetSealer installs the sealer used for encrypted accounts.
func (i *Index) SetSealer(sealer Sealer) {
	if i != nil {
		i.sealer.Store(&sealer)
	}
}

func (i *Index) loadSealer() Sealer {
	if sealer := i.sealer.Load(); sealer != nil {
		return *sealer
	}
	return nil
}

// unseal returns the stored snapshot bytes in plaintext. A plaintext snapshot
// of an encrypted account is reported stale, so the rebuild overwrites it.
func (i *Index) unseal(owner, key string, raw []byte) ([]byte, error) {
	sealer := i.loadSealer()
	if sealed, ok := bytes.CutPrefix(raw, []byte(sealedPrefix)); ok {
		if sealer == nil {
			return nil, errors.New("folder derived index is sealed and no sealer is configured")
		}
		return sealer.OpenDerived(owner, []byte(key), sealed)
	}
	if sealer != nil && sealer.DerivedEncrypted(owner) {
		return nil, errors.New("folder derived index of an encrypted account is not sealed")
	}
	return raw, nil
}

// project projects one page of items in order, spreading the work over
// workers goroutines. Items that do not project are left out.
func project(definition Definition, items []model.Item, workers int) []Document {
	documents := make([]Document, len(items))
	projected := make([]bool, len(items))
	projectOne := func(n int) {
		document, err := definition.Project(items[n])
		if err != nil {
			return
		}
		if document.ItemID == "" {
			document.ItemID = items[n].ID
		}
		documents[n], projected[n] = document, true
	}
	if workers <= 1 || len(items) < 2*workers {
		for n := range items {
			projectOne(n)
		}
	} else {
		var next atomic.Int64
		var wg sync.WaitGroup
		for range workers {
			wg.Go(func() {
				for n := int(next.Add(1)) - 1; n < len(items); n = int(next.Add(1)) - 1 {
					projectOne(n)
				}
			})
		}
		wg.Wait()
	}
	result := documents[:0]
	for n, document := range documents {
		if projected[n] {
			result = append(result, document)
		}
	}
	return result
}

// projectWorkers is how many goroutines one rebuild projects items on.
func projectWorkers(definition Definition) int {
	if parallel, ok := definition.(ParallelDefinition); ok && parallel.ParallelProject() {
		return min(runtime.GOMAXPROCS(0), maxProjectWorkers)
	}
	return 1
}

// enumerate visits the folder's items a page at a time.
func enumerate(ctx context.Context, space service.FolderSpace, access service.AccessContext, folderID string, includeData bool, visit func([]model.Item)) error {
	if pager, ok := space.(service.FolderItemPager); ok {
		var before uint32
		for {
			page, err := pager.ListItemPage(ctx, access, folderID, service.ItemPageQuery{BeforeUID: before, Limit: pageSize, IncludeData: includeData})
			if err != nil {
				return err
			}
			visit(page.Items)
			if page.NextBeforeUID == 0 {
				return nil
			}
			if page.NextBeforeUID == before {
				return errors.New("folder item page did not advance")
			}
			before = page.NextBeforeUID
		}
	}
	items, err := space.ListItems(ctx, access, folderID, service.ItemQuery{MetadataOnly: !includeData})
	if err != nil {
		return err
	}
	for len(items) > 0 {
		page := items[:min(pageSize, len(items))]
		visit(page)
		items = items[len(page):]
	}
	return nil
}

func ensureNamespace(ctx context.Context, s store.Store) error {
	exists, err := s.NamespaceExists(ctx, namespace)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	err = s.CreateNamespace(ctx, namespace)
	if errors.Is(err, store.ErrExists) {
		return nil
	}
	return err
}
