package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	DefaultChangeRetentionDays = 90
	DefaultChangeMaxEntries    = 1_000_000
	changeMetaKey              = model.ChangeJournalMetaKey
	changeRecordPrefix         = model.ChangeJournalRecordPrefix
)

var ErrChangeStateExpired = errors.New("change state is no longer retained")

type ChangeObject string

const (
	ChangeObjectFolder ChangeObject = "folder"
	ChangeObjectItem   ChangeObject = "item"
)

type ChangeOperation string

const (
	ChangeCreate  ChangeOperation = "create"
	ChangeUpdate  ChangeOperation = "update"
	ChangeMove    ChangeOperation = "move"
	ChangeDestroy ChangeOperation = "destroy"
	ChangeTrash   ChangeOperation = "trash"
	ChangeRestore ChangeOperation = "restore"
)

// Change describes one metadata-only committed folder-space effect.
type Change struct {
	Object           ChangeObject     `json:"object"`
	Operation        ChangeOperation  `json:"operation"`
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	FolderID         string           `json:"folder_id,omitempty"`
	PreviousFolderID string           `json:"previous_folder_id,omitempty"`
	PreviousName     string           `json:"previous_name,omitempty"`
	UID              uint32           `json:"uid,omitempty"`
	ModSeq           uint64           `json:"mod_seq,omitempty"`
	PreviousUID      uint32           `json:"previous_uid,omitempty"`
	PreviousModSeq   uint64           `json:"previous_mod_seq,omitempty"`
	FolderType       model.FolderType `json:"folder_type,omitempty"`
}

// ChangeRecord is the atomic set of effects produced by one mutation.
type ChangeRecord struct {
	Sequence    uint64    `json:"sequence"`
	MutationID  string    `json:"mutation_id"`
	CommittedAt time.Time `json:"committed_at"`
	Changes     []Change  `json:"changes"`
}

type ChangeScope struct {
	FolderID string
	Object   ChangeObject
}

type ChangePage struct {
	OldState       string         `json:"old_state"`
	NewState       string         `json:"new_state"`
	CurrentState   string         `json:"current_state"`
	HasMoreChanges bool           `json:"has_more_changes"`
	Records        []ChangeRecord `json:"records"`
}

// FolderChangeReader is the optional incremental-change capability exposed by
// a FolderSpace implementation.
type FolderChangeReader interface {
	CurrentChangeState(context.Context, AccessContext, ChangeScope) (string, error)
	ListChanges(context.Context, AccessContext, ChangeScope, string, int) (ChangePage, error)
}

// FolderChangeNotifier is the optional capability of a FolderSpace to report
// that an account's change journal advanced. A listener runs synchronously on
// the committing goroutine after the commit, so it must return promptly; it
// is a wake-up hint, and consumers still read the journal to learn what
// changed. folderIDs names every folder a committed record touched (an
// item's current and previous folder, a folder and its previous parent); it
// is nil when the notifier cannot tell, and then any folder of the account
// may have changed. The returned function removes the listener.
type FolderChangeNotifier interface {
	OnChangesCommitted(listener func(accountID string, folderIDs []string)) (remove func())
}

// ChangeStateSequence returns the journal position encoded in a change state,
// so consumers can tell how far one state is behind another. The empty state
// is position zero.
func ChangeStateSequence(state string) (uint64, error) {
	return decodeChangeState(state)
}

// changeListeners is a registry of FolderChangeNotifier listeners.
type changeListeners struct {
	mu        sync.RWMutex
	next      uint64
	listeners map[uint64]func(string, []string)
}

func (l *changeListeners) add(listener func(string, []string)) func() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listeners == nil {
		l.listeners = make(map[uint64]func(string, []string))
	}
	l.next++
	id := l.next
	l.listeners[id] = listener
	return func() {
		l.mu.Lock()
		delete(l.listeners, id)
		l.mu.Unlock()
	}
}

func (l *changeListeners) notify(accountID string, folderIDs []string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, listener := range l.listeners {
		listener(accountID, folderIDs)
	}
}

// touchedFolders collects the folders the change records of one outermost
// commit touch, including records written by nested commits.
type touchedFolders struct {
	ids map[string]struct{}
}

type touchedFoldersKey struct{}

func withTouchedFolders(ctx context.Context) (context.Context, *touchedFolders) {
	touched := &touchedFolders{ids: map[string]struct{}{}}
	return context.WithValue(ctx, touchedFoldersKey{}, touched), touched
}

func touchedFoldersFrom(ctx context.Context) *touchedFolders {
	touched, _ := ctx.Value(touchedFoldersKey{}).(*touchedFolders)
	return touched
}

func (t *touchedFolders) add(changes []Change) {
	if t == nil {
		return
	}
	for _, change := range changes {
		for _, folderID := range []string{change.FolderID, change.PreviousFolderID} {
			if folderID != "" {
				t.ids[folderID] = struct{}{}
			}
		}
	}
}

// list returns the collected folders, or nil when nothing was collected so
// listeners treat the whole account as changed.
func (t *touchedFolders) list() []string {
	if t == nil || len(t.ids) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(t.ids))
}

type changeMeta = model.ChangeJournalMeta

type ChangeStore struct {
	ts         *model.TypedStore
	mu         sync.RWMutex
	retention  time.Duration
	maxEntries int64
}

func NewChangeStore(ts *model.TypedStore) *ChangeStore {
	return &ChangeStore{ts: ts, retention: DefaultChangeRetentionDays * 24 * time.Hour, maxEntries: DefaultChangeMaxEntries}
}

func (s *ChangeStore) SetRetention(days, maxEntries int) {
	if days < 1 {
		days = 1
	}
	if maxEntries < 1 {
		maxEntries = 1
	}
	s.mu.Lock()
	s.retention = time.Duration(days) * 24 * time.Hour
	s.maxEntries = int64(maxEntries)
	s.mu.Unlock()
}

func (s *ChangeStore) Ensure(ctx context.Context) error {
	if _, ok := s.ts.Store().(store.Batcher); !ok {
		return errors.New("account store must support atomic batches for change history")
	}
	// Namespace discovery takes the store's outer lock on some backends. A
	// caller entering a batch must have ensured it before acquiring that lock.
	if store.InBatch(ctx, s.ts.Store()) {
		return nil
	}
	return s.ts.EnsureNamespace(ctx, model.NSChanges)
}

// Record adds a change record. The caller must use the same store batch as the
// domain mutation being described.
func (s *ChangeStore) Record(ctx context.Context, changes []Change) (ChangeRecord, error) {
	if len(changes) == 0 {
		return ChangeRecord{}, errors.New("change record requires at least one effect")
	}
	var meta changeMeta
	err := s.ts.Get(ctx, model.NSChanges, changeMetaKey, &meta)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return ChangeRecord{}, err
	}
	meta.Current++
	mutationID, err := newMutationID()
	if err != nil {
		return ChangeRecord{}, err
	}
	record := ChangeRecord{Sequence: meta.Current, MutationID: mutationID, CommittedAt: time.Now().UTC(), Changes: append([]Change(nil), changes...)}
	if err := s.ts.Put(ctx, model.NSChanges, changeRecordKey(record.Sequence), record); err != nil {
		return ChangeRecord{}, err
	}
	meta.EntryCount += int64(len(changes))
	if err := s.ts.Set(ctx, model.NSChanges, changeMetaKey, meta); err != nil {
		return ChangeRecord{}, err
	}
	return record, nil
}

func (s *ChangeStore) CurrentState(ctx context.Context) (string, error) {
	if err := s.Ensure(ctx); err != nil {
		return "", err
	}
	var meta changeMeta
	if err := s.ts.Get(ctx, model.NSChanges, changeMetaKey, &meta); err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	return encodeChangeState(meta.Current), nil
}

func (s *ChangeStore) List(ctx context.Context, scope ChangeScope, state string, limit int) (ChangePage, error) {
	if err := s.Ensure(ctx); err != nil {
		return ChangePage{}, err
	}
	since, err := decodeChangeState(state)
	if err != nil {
		return ChangePage{}, err
	}
	if limit < 1 {
		limit = 100
	}
	if limit > 10_000 {
		limit = 10_000
	}
	var page ChangePage
	// One stable view keeps the head, the retention floor, and the records
	// consistent with each other while writers append or prune.
	err = store.View(ctx, s.ts.Store(), func(viewCtx context.Context) error {
		var meta changeMeta
		if err := s.ts.Get(viewCtx, model.NSChanges, changeMetaKey, &meta); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if since > meta.Current {
			return errors.New("change state is ahead of current state")
		}
		if since < meta.Floor {
			return ErrChangeStateExpired
		}
		page = ChangePage{OldState: encodeChangeState(since), NewState: encodeChangeState(since), CurrentState: encodeChangeState(meta.Current), Records: []ChangeRecord{}}
		// Polling consumers normally sit at the journal head. Avoid turning
		// that idle check into a journal read on every poll.
		if since == meta.Current {
			return nil
		}
		// Record keys sort by sequence, so the read seeks straight past the
		// caller's state: its cost follows the records returned, not the
		// journal's length.
		changeCount, full := 0, false
		err := store.IterateFrom(viewCtx, s.ts.Store(), model.NSChanges, changeRecordPrefix, changeRecordKey(since+1), func(key string, value []byte) (bool, error) {
			sequence, ok := parseChangeRecordKey(key)
			if !ok || sequence <= since {
				return true, nil
			}
			if sequence > meta.Current {
				return false, nil
			}
			var record ChangeRecord
			if err := json.Unmarshal(value, &record); err != nil {
				return false, fmt.Errorf("decode change record %s: %w", key, err)
			}
			filtered := filterChanges(record.Changes, scope)
			page.NewState = encodeChangeState(sequence)
			if len(filtered) > 0 {
				record.Changes = filtered
				page.Records = append(page.Records, record)
				changeCount += len(filtered)
			}
			if changeCount >= limit {
				page.HasMoreChanges = sequence < meta.Current
				full = true
				return false, nil
			}
			return true, nil
		})
		if err != nil {
			return err
		}
		if !full {
			page.NewState = page.CurrentState
		}
		return nil
	})
	if err != nil {
		return ChangePage{}, err
	}
	return page, nil
}

func (s *ChangeStore) Prune(ctx context.Context, now time.Time) (int, error) {
	if err := s.Ensure(ctx); err != nil {
		return 0, err
	}
	s.mu.RLock()
	retention, maxEntries := s.retention, s.maxEntries
	s.mu.RUnlock()
	removed := 0
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		var meta changeMeta
		if err := s.ts.Get(batchCtx, model.NSChanges, changeMetaKey, &meta); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		// Retained records start just above the floor. Seeking there skips
		// the deleted keys of earlier passes, and the read stops at the first
		// record that must be kept. Deletion waits until the iteration ends.
		type expired struct {
			key      string
			sequence uint64
			changes  int
		}
		var doomed []expired
		entries := meta.EntryCount
		err := store.IterateFrom(batchCtx, s.ts.Store(), model.NSChanges, changeRecordPrefix, changeRecordKey(meta.Floor+1), func(key string, value []byte) (bool, error) {
			var record ChangeRecord
			if err := json.Unmarshal(value, &record); err != nil {
				return false, fmt.Errorf("decode change record %s: %w", key, err)
			}
			if !record.CommittedAt.Before(now.Add(-retention)) && entries <= maxEntries {
				return false, nil
			}
			doomed = append(doomed, expired{key: key, sequence: record.Sequence, changes: len(record.Changes)})
			entries -= int64(len(record.Changes))
			return true, nil
		})
		if err != nil {
			return err
		}
		for _, record := range doomed {
			if err := s.ts.Delete(batchCtx, model.NSChanges, record.key); err != nil {
				return err
			}
			meta.EntryCount -= int64(record.changes)
			meta.Floor = record.sequence
			removed += record.changes
		}
		return s.ts.Set(batchCtx, model.NSChanges, changeMetaKey, meta)
	})
	return removed, err
}

func changeRecordKey(sequence uint64) string {
	return fmt.Sprintf("%s%020d", changeRecordPrefix, sequence)
}

func parseChangeRecordKey(key string) (uint64, bool) {
	if !strings.HasPrefix(key, changeRecordPrefix) {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimPrefix(key, changeRecordPrefix), 10, 64)
	return value, err == nil
}

func encodeChangeState(sequence uint64) string {
	return "c1." + strconv.FormatUint(sequence, 36)
}

func decodeChangeState(state string) (uint64, error) {
	if state == "" {
		return 0, nil
	}
	if !strings.HasPrefix(state, "c1.") {
		return 0, errors.New("invalid change state")
	}
	value, err := strconv.ParseUint(strings.TrimPrefix(state, "c1."), 36, 64)
	if err != nil {
		return 0, errors.New("invalid change state")
	}
	return value, nil
}

func filterChanges(changes []Change, scope ChangeScope) []Change {
	result := make([]Change, 0, len(changes))
	for _, change := range changes {
		if scope.Object != "" && change.Object != scope.Object {
			continue
		}
		if scope.FolderID != "" && change.FolderID != scope.FolderID && change.PreviousFolderID != scope.FolderID {
			continue
		}
		result = append(result, change)
	}
	return result
}

func newMutationID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "chg_" + hex.EncodeToString(value[:]), nil
}
