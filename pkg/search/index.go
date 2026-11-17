package search

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	mappingVersion     = 10
	stateFilename      = "state.json"
	buildStateFilename = "build.json"
	// readYourWritesWait bounds how long a query waits for the indexer to
	// reach the journal position current when the query started, and
	// readYourWritesMaxLag (in catch-up batches) skips the wait during a
	// backlog the indexer cannot clear within that bound anyway.
	readYourWritesWait   = 500 * time.Millisecond
	readYourWritesMaxLag = 4
)

// Config controls derived search work. Zero values receive safe defaults.
type Config struct {
	Enabled           bool
	Workers           int
	BatchSize         int
	IdleClose         time.Duration
	MaxExtractedBytes int64
	QueryMaxResults   int
	// IndexEncryptedAccounts builds the on-disk index, which holds plaintext
	// terms, for accounts encrypted at rest too. Off by default.
	IndexEncryptedAccounts bool
}

func (c Config) normalized() Config {
	if c.Workers < 1 {
		c.Workers = 2
	}
	if c.BatchSize < 1 {
		c.BatchSize = 256
	}
	if c.IdleClose <= 0 {
		c.IdleClose = 5 * time.Minute
	}
	if c.QueryMaxResults < 1 {
		c.QueryMaxResults = 100
	}
	if c.MaxExtractedBytes <= 0 {
		c.MaxExtractedBytes = 1 << 20
	}
	return c
}

type persistedState struct {
	Version          int       `json:"version"`
	IndexID          string    `json:"index_id"`
	Checkpoint       string    `json:"checkpoint"`
	ActiveGeneration string    `json:"active_generation"`
	State            string    `json:"state"`
	Documents        uint64    `json:"documents"`
	FoldersDone      int       `json:"folders_done"`
	FoldersTotal     int       `json:"folders_total"`
	ItemsDone        int64     `json:"items_done"`
	LastFolderID     string    `json:"last_folder_id,omitempty"`
	TrashComplete    bool      `json:"trash_complete,omitempty"`
	BuildStartedAt   time.Time `json:"build_started_at,omitzero"`
	LastResumedAt    time.Time `json:"last_resumed_at,omitzero"`
	ResumeCount      int       `json:"resume_count,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	LastRecoveryID   string    `json:"last_recovery_index_id,omitempty"`
	LastRecovery     string    `json:"last_recovery_reason,omitempty"`
	LastRecoveryAt   time.Time `json:"last_recovery_at,omitzero"`
	UpdatedAt        time.Time `json:"updated_at"`
}

var logger = log.For(log.ModuleSearch)

type runtime struct {
	mu sync.Mutex
	// indexUse is held for reading by every catch-up write to index and for
	// writing while a detached index is closed, so a handle is never closed
	// under an in-flight batch. Lock order: indexUse before mu; mu is held
	// while waiting for indexUse for writing only when no pass is running.
	indexUse sync.RWMutex
	index    bleve.Index
	// path is the account directory the persisted state and index were
	// loaded from. An account move changes it; the runtime then reloads
	// rather than keep writing to the directory the move renamed away.
	path string
	// relocating fences the account during Move: no pass starts and the
	// index stays closed. cancelPass and passDone stop and await the
	// running pass.
	relocating   bool
	cancelPass   context.CancelFunc
	passDone     chan struct{}
	state        persistedState
	buildState   *persistedState
	initialized  bool
	building     bool
	forceRebuild bool
	freshBuild   bool
	nextAttempt  time.Time
	lastUsed     time.Time
	validated    bool
	// rerun asks the running build or catch-up to run catch-up once more
	// when it finishes: changes were committed or a full page remained.
	rerun bool
	// advanced is closed and replaced whenever the serving checkpoint moves,
	// waking queries waiting to read their own writes.
	advanced chan struct{}
}

// checkpointAdvancedLocked wakes queries waiting for the serving checkpoint.
// rt.mu must be held.
func (rt *runtime) checkpointAdvancedLocked() {
	if rt.advanced != nil {
		close(rt.advanced)
		rt.advanced = nil
	}
}

// Manager owns all account search indexes and implements service.SearchReader.
type Manager struct {
	ctx        context.Context
	cancel     context.CancelFunc
	accounts   *account.Manager
	space      service.FolderSpace
	changes    service.FolderChangeReader
	authorizer *authz.Engine
	config     atomic.Pointer[Config]
	eventsMu   sync.RWMutex
	events     events.Publisher
	workers    *workerPool

	// Committed-change notifications mark accounts dirty and wake the
	// poller, which starts their catch-up without waiting for its tick.
	stopNotify     func()
	stopRelocation func()
	wake           chan struct{}
	dirtyMu        sync.Mutex
	dirty          map[string]struct{}

	// reconfigureMu serializes Reconfigure. lifecycleMu guards the indexing
	// context: it is non-nil exactly while background indexing is enabled,
	// and indexWG counts the poller and build goroutines started under it.
	reconfigureMu sync.Mutex
	lifecycleMu   sync.RWMutex
	indexCtx      context.Context
	indexCancel   context.CancelFunc
	indexWG       sync.WaitGroup

	mu       sync.Mutex
	runtimes map[string]*runtime
	wg       sync.WaitGroup
}

func New(ctx context.Context, accounts *account.Manager, space service.FolderSpace, authorizer *authz.Engine, config Config) (*Manager, error) {
	if accounts == nil || space == nil || authorizer == nil {
		return nil, errors.New("search requires accounts, folder space, and authorizer")
	}
	changes, ok := space.(service.FolderChangeReader)
	if !ok {
		return nil, errors.New("search requires durable folder change history")
	}
	config = config.normalized()
	managerCtx, cancel := context.WithCancel(ctx)
	m := &Manager{
		ctx: managerCtx, cancel: cancel, accounts: accounts, space: space, changes: changes,
		authorizer: authorizer, workers: newWorkerPool(config.Workers), runtimes: make(map[string]*runtime),
		wake: make(chan struct{}, 1), dirty: make(map[string]struct{}),
	}
	m.config.Store(&config)
	if notifier, ok := space.(service.FolderChangeNotifier); ok {
		m.stopNotify = notifier.OnChangesCommitted(m.changesCommitted)
	}
	m.stopRelocation = accounts.OnRelocation(m)
	if config.Enabled {
		m.lifecycleMu.Lock()
		m.startIndexingLocked()
		m.lifecycleMu.Unlock()
		m.ensureAllBuilds()
	}
	return m, nil
}

func (m *Manager) SetEventPublisher(publisher events.Publisher) {
	m.eventsMu.Lock()
	m.events = publisher
	m.eventsMu.Unlock()
}

func (m *Manager) Close() error {
	if m.stopNotify != nil {
		m.stopNotify()
	}
	if m.stopRelocation != nil {
		m.stopRelocation()
	}
	m.cancel()
	m.wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	var result error
	for _, rt := range m.runtimes {
		rt.mu.Lock()
		if rt.index != nil {
			rt.indexUse.Lock()
			result = errors.Join(result, rt.index.Close())
			rt.index = nil
			rt.indexUse.Unlock()
		}
		rt.mu.Unlock()
	}
	return result
}

func (m *Manager) runtime(login string) *runtime {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rt := m.runtimes[login]; rt != nil {
		return rt
	}
	rt := &runtime{state: persistedState{Version: mappingVersion, State: "missing"}}
	m.runtimes[login] = rt
	return rt
}

func (m *Manager) poll(ctx context.Context) {
	defer m.wg.Done()
	defer m.indexWG.Done()
	ticker := time.NewTicker(time.Second)
	reaper := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer reaper.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
			m.dirtyMu.Lock()
			logins := make([]string, 0, len(m.dirty))
			for login := range m.dirty {
				logins = append(logins, login)
			}
			clear(m.dirty)
			m.dirtyMu.Unlock()
			for _, login := range logins {
				m.ensureBuild(login)
			}
		case <-ticker.C:
			m.ensureAllBuilds()
		case <-reaper.C:
			m.closeIdle(time.Now().Add(-m.settings().IdleClose))
		}
	}
}

// changesCommitted is the FolderChangeNotifier listener. It runs on the
// committing goroutine, so it only records the account and wakes the poller.
func (m *Manager) changesCommitted(accountID string, _ []string) {
	m.dirtyMu.Lock()
	m.dirty[accountID] = struct{}{}
	m.dirtyMu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// closeIdle closes serving indexes that are not building and were last used
// before cutoff; queries reopen them on demand.
func (m *Manager) closeIdle(cutoff time.Time) {
	m.mu.Lock()
	runtimes := make([]*runtime, 0, len(m.runtimes))
	for _, rt := range m.runtimes {
		runtimes = append(runtimes, rt)
	}
	m.mu.Unlock()
	for _, rt := range runtimes {
		rt.mu.Lock()
		if !rt.building && rt.index != nil && rt.lastUsed.Before(cutoff) {
			rt.indexUse.Lock()
			_ = guardIndex("close", rt.index.Close)
			rt.index = nil
			rt.indexUse.Unlock()
		}
		rt.mu.Unlock()
	}
}

func (m *Manager) ensureBuild(login string) {
	ctx, done, enabled := m.beginIndexing()
	if !enabled {
		return
	}
	spawned := false
	defer func() {
		if !spawned {
			done()
		}
	}()
	rt := m.runtime(login)
	rt.mu.Lock()
	if rt.building {
		// The running pass may have read the journal before the change that
		// triggered this call; catch up again as soon as it finishes.
		rt.rerun = true
		rt.mu.Unlock()
		return
	}
	if rt.relocating {
		// AccountRelocated starts the next pass at the final path.
		rt.mu.Unlock()
		return
	}
	entry, found := m.accounts.ByLogin(login)
	if !found {
		rt.mu.Unlock()
		return
	}
	if rt.initialized && rt.path != entry.Path {
		// The account directory changed without a relocation notice; never
		// keep writing to the directory it left. Reload at the new path.
		m.resetRuntimeLocked(rt)
	}
	if entry.Manifest.Encrypted && !m.settings().IndexEncryptedAccounts {
		m.dropIndexLocked(entry, rt)
		rt.mu.Unlock()
		return
	}
	if !rt.nextAttempt.IsZero() && time.Now().Before(rt.nextAttempt) {
		rt.mu.Unlock()
		return
	}
	cleanup := false
	if !rt.initialized {
		if state, err := loadState(entry.Path); err == nil {
			rt.state = state
		}
		if build, err := loadBuildState(entry.Path); err == nil {
			if build.IndexID == rt.state.IndexID && rt.state.State == "ready" {
				_ = removeBuildState(entry.Path)
			} else if build.IndexID != "" {
				rt.buildState = &build
			} else {
				_ = removeBuildState(entry.Path)
			}
		}
		rt.initialized = true
		rt.path = entry.Path
		cleanup = true
	}
	needsBuild := needsSearchRebuild(rt.state, rt.buildState, rt.forceRebuild, entry.Manifest.ActiveGeneration)
	rt.forceRebuild = false
	freshBuild := rt.freshBuild
	rt.freshBuild = false
	activeIndexID := rt.state.IndexID
	buildIndexID := ""
	if rt.buildState != nil {
		buildIndexID = rt.buildState.IndexID
	}
	rt.building = true
	ctx, cancelPass := context.WithCancel(ctx)
	rt.cancelPass = cancelPass
	rt.passDone = make(chan struct{})
	rt.mu.Unlock()
	spawned = true
	go func() {
		defer done()
		if err := m.workers.acquire(ctx); err != nil {
			rt.mu.Lock()
			rt.endPassLocked()
			rt.mu.Unlock()
			return
		}
		defer m.workers.release()
		if cleanup {
			m.removeStaleIndexes(entry.Path, activeIndexID, buildIndexID)
		}
		var err error
		more := false
		if needsBuild {
			err = m.guardPass(login, rt, func() error { return m.rebuild(ctx, login, rt, freshBuild) })
		} else {
			err = m.guardPass(login, rt, func() (passErr error) {
				more, passErr = m.catchUp(ctx, login, rt)
				return passErr
			})
		}
		recovered := false
		if errors.Is(err, errIndexFault) && !needsBuild {
			// The serving index panicked or failed a write: Scorch may have
			// closed segments it still serves, so the handle must never be
			// used again. Quarantine it and rebuild from the account at once;
			// a rebuild that faults too backs off as a failed build.
			rt.mu.Lock()
			indexID := rt.state.IndexID
			rt.mu.Unlock()
			logger.Warn("search: serving index faulted; rebuilding", "account", login, "index", indexID, "error", err)
			_ = m.recoverServingIndex(login, rt, indexID, err)
			recovered = true
		}
		rt.mu.Lock()
		rt.endPassLocked()
		// Continue at once while a backlog remains or changes arrived during
		// this pass: catch-up batches whatever accumulated meanwhile, so a
		// busy account indexes in full batches and an idle one immediately.
		rerun := (err == nil && (more || rt.rerun)) || errors.Is(err, errAccountMoved) || recovered
		rt.rerun = false
		defer func() {
			if rerun {
				m.ensureBuild(login)
			}
		}()
		if err != nil && !recovered && !errors.Is(err, context.Canceled) && !errors.Is(err, errAccountMoved) {
			failed := persistedState{Version: mappingVersion, State: "failed", LastError: err.Error(), UpdatedAt: time.Now().UTC()}
			if rt.buildState != nil {
				failed = *rt.buildState
				failed.State = "failed"
				failed.LastError = err.Error()
				failed.UpdatedAt = time.Now().UTC()
			}
			if needsBuild && failed.IndexID != "" && rt.path == entry.Path && !rt.relocating {
				_ = saveBuildState(entry.Path, failed)
			}
			rt.buildState = &failed
			rt.forceRebuild = needsBuild || rt.forceRebuild
			if needsBuild && errors.Is(err, errIndexFault) {
				rt.freshBuild = true
			}
			rt.nextAttempt = time.Now().Add(time.Minute)
			m.publish(login, "search.index.failed", failed)
		} else if err == nil {
			rt.buildState = nil
			rt.nextAttempt = time.Time{}
		}
		rt.mu.Unlock()
	}()
}

// endPassLocked marks the running build or catch-up pass finished and wakes
// a relocation waiting for it. rt.mu must be held.
func (rt *runtime) endPassLocked() {
	rt.building = false
	if rt.cancelPass != nil {
		rt.cancelPass()
		rt.cancelPass = nil
	}
	if rt.passDone != nil {
		close(rt.passDone)
		rt.passDone = nil
	}
}

// errIndexFault marks a Bleve write that failed or a Bleve call that
// panicked. Scorch closes the in-memory segment of a batch whose persistence
// failed even though that segment is already part of the index root, so the
// next batch or query on the same handle panics with a nil map in zapx. An
// index handle that reported a fault is therefore never used again.
var errIndexFault = errors.New("search index fault")

// errAccountMoved reports that the account directory is moving or moved
// since the runtime loaded its index; the next pass reloads at the new path.
var errAccountMoved = errors.New("search: account directory moved")

// guardIndex runs one Bleve call, converting a panic inside Bleve into an
// errIndexFault so a single broken index cannot take the server down.
func guardIndex(operation string, call func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.Error("search: index operation panicked", "operation", operation, "panic", recovered, "stack", string(debug.Stack()))
			err = fmt.Errorf("%w: %s panicked: %v", errIndexFault, operation, recovered)
		}
	}()
	return call()
}

// writeIndex applies batch to idx. Any failure is an errIndexFault: see
// errIndexFault for why the handle cannot be trusted afterwards.
func writeIndex(idx bleve.Index, batch *bleve.Batch) error {
	if err := guardIndex("batch", func() error { return idx.Batch(batch) }); err != nil {
		if errors.Is(err, errIndexFault) {
			return err
		}
		return fmt.Errorf("%w: write batch: %w", errIndexFault, err)
	}
	return nil
}

// guardPass runs one build or catch-up pass and recovers a panic anywhere in
// it, so a defect in one account's indexing is reported as a failed pass
// rather than terminating the process. It is defence in depth: Bleve calls
// are guarded individually by guardIndex.
func (m *Manager) guardPass(login string, rt *runtime, pass func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.Error("search: indexing pass panicked", "account", login, "panic", recovered, "stack", string(debug.Stack()))
			err = fmt.Errorf("%w: indexing pass panicked: %v", errIndexFault, recovered)
		}
	}()
	return pass()
}

// detachIndex removes idx from serving, if it is still the serving handle,
// and closes it once in-flight catch-up writes have finished. Queries read
// the serving handle under rt.mu, so none can reach it after the detach.
// rt.mu must not be held.
func (m *Manager) detachIndex(rt *runtime, idx bleve.Index) {
	if idx == nil {
		return
	}
	rt.mu.Lock()
	if rt.index == idx {
		rt.index = nil
		rt.validated = false
	}
	rt.mu.Unlock()
	rt.indexUse.Lock()
	_ = guardIndex("close", idx.Close)
	rt.indexUse.Unlock()
}

// resetRuntimeLocked forgets the loaded state of an account whose directory
// changed and closes its serving index, so the next pass reloads the state
// at the account's current path. No pass may be running. rt.mu must be held.
func (m *Manager) resetRuntimeLocked(rt *runtime) {
	if rt.index != nil {
		rt.indexUse.Lock()
		_ = guardIndex("close", rt.index.Close)
		rt.index = nil
		rt.indexUse.Unlock()
	}
	rt.state = persistedState{Version: mappingVersion, State: "missing"}
	rt.buildState, rt.initialized, rt.validated, rt.path = nil, false, false, ""
	rt.forceRebuild, rt.freshBuild, rt.nextAttempt = false, false, time.Time{}
	rt.checkpointAdvancedLocked()
}

// AccountRelocating implements account.RelocationObserver. It stops the
// account's running pass, keeps new ones from starting, and closes the
// serving index, so nothing under path is open when Move renames it.
func (m *Manager) AccountRelocating(login, _ string) {
	rt := m.runtime(login)
	rt.mu.Lock()
	rt.relocating = true
	if rt.cancelPass != nil {
		rt.cancelPass()
	}
	passDone := rt.passDone
	rt.mu.Unlock()
	if passDone != nil {
		// The pass reads the fenced account, which fails fast, and checks its
		// context between Bleve calls, so it ends promptly.
		<-passDone
	}
	rt.mu.Lock()
	idx := rt.index
	rt.mu.Unlock()
	m.detachIndex(rt, idx)
}

// AccountRelocated implements account.RelocationObserver. After a committed
// move it carries the derived search directory over from the retained copy
// when it can, falling back to a rebuild, and resumes indexing at path.
func (m *Manager) AccountRelocated(login, path, retained string) {
	rt := m.runtime(login)
	rt.mu.Lock()
	if retained != "" && path != rt.path {
		source := filepath.Join(retained, "search")
		destination := filepath.Join(path, "search")
		if _, err := os.Stat(source); err == nil {
			if _, err := os.Lstat(destination); errors.Is(err, os.ErrNotExist) {
				// A rename across file systems fails; the next pass then
				// finds no index at path and rebuilds it.
				if err := os.Rename(source, destination); err != nil {
					logger.Warn("search: index not carried over account move; rebuilding", "account", login, "error", err)
				}
			}
		}
	}
	if rt.path != path {
		m.resetRuntimeLocked(rt)
	}
	rt.relocating = false
	rt.mu.Unlock()
	m.ensureBuild(login)
}

// dropIndexLocked removes every on-disk index of an account encrypted at
// rest: a full-text index would store its plaintext terms and stored fields
// next to the encrypted generation. rt.mu must be held.
func (m *Manager) dropIndexLocked(entry account.Entry, rt *runtime) {
	if rt.index != nil {
		rt.indexUse.Lock()
		_ = guardIndex("close", rt.index.Close)
		rt.index = nil
		rt.indexUse.Unlock()
	}
	rt.state = persistedState{Version: mappingVersion, State: notIndexedState, ActiveGeneration: entry.Manifest.ActiveGeneration, UpdatedAt: time.Now().UTC()}
	rt.buildState, rt.initialized, rt.forceRebuild, rt.nextAttempt = nil, true, false, time.Time{}
	if err := os.RemoveAll(filepath.Join(entry.Path, "search")); err != nil {
		rt.state.LastError = err.Error()
	}
}

// notIndexedState is the search state of accounts encrypted at rest.
const notIndexedState = "not_indexed"

func needsSearchRebuild(serving persistedState, build *persistedState, forced bool, generation string) bool {
	return forced || (build != nil && build.IndexID != "") || serving.Version != mappingVersion || serving.IndexID == "" || serving.ActiveGeneration != generation || serving.State != "ready"
}

func (m *Manager) rebuild(ctx context.Context, login string, rt *runtime, fresh bool) error {
	err := m.rebuildOnce(ctx, login, rt, fresh)
	if !errors.Is(err, service.ErrChangeStateExpired) || ctx.Err() != nil {
		return err
	}
	entry, found := m.accounts.ByLogin(login)
	if !found {
		return store.ErrNotFound
	}
	m.discardPartialBuild(entry.Path, rt)
	return m.rebuildOnce(ctx, login, rt, true)
}

func (m *Manager) rebuildOnce(ctx context.Context, login string, rt *runtime, fresh bool) error {
	entry, found := m.accounts.ByLogin(login)
	if !found {
		return store.ErrNotFound
	}
	access := service.UserAccess(login, service.ProtocolSearchIndexer)
	searchRoot := filepath.Join(entry.Path, "search")
	if fresh {
		m.discardPartialBuild(entry.Path, rt)
	}
	state, loadErr := loadBuildState(entry.Path)
	resumed := loadErr == nil && validBuildState(state, entry.Manifest.ActiveGeneration) == nil
	var idx bleve.Index
	var err error
	if resumed {
		idx, err = bleve.Open(filepath.Join(searchRoot, "indexes", state.IndexID))
		opened := err == nil
		if err == nil {
			var documents uint64
			documents, err = idx.DocCount()
			if err == nil && documents < state.Documents {
				err = fmt.Errorf("partial index document count %d is below checkpoint %d", documents, state.Documents)
			}
			if err == nil {
				// A crash can occur after a bounded Bleve batch is durable but
				// before the containing folder checkpoint advances. Replaying
				// that folder overwrites the same stable item IDs; later journal
				// catch-up removes anything deleted in the meantime.
				state.Documents = documents
			}
		}
		if err != nil {
			if opened {
				_ = idx.Close()
			}
			m.discardPartialBuild(entry.Path, rt)
			resumed = false
		}
	} else if loadErr == nil || !errors.Is(loadErr, os.ErrNotExist) {
		m.discardPartialBuild(entry.Path, rt)
	}
	if !resumed {
		checkpoint, checkpointErr := m.changes.CurrentChangeState(ctx, access, service.ChangeScope{Object: service.ChangeObjectItem})
		if checkpointErr != nil {
			return fmt.Errorf("capture search checkpoint: %w", checkpointErr)
		}
		indexID, idErr := newIndexID()
		if idErr != nil {
			return idErr
		}
		indexPath := filepath.Join(searchRoot, "indexes", indexID)
		if err := os.MkdirAll(filepath.Dir(indexPath), 0o700); err != nil {
			return err
		}
		idx, err = bleve.New(indexPath, indexMapping())
		if err != nil {
			return fmt.Errorf("create Bleve index: %w", err)
		}
		now := time.Now().UTC()
		state = persistedState{
			Version: mappingVersion, IndexID: indexID, Checkpoint: checkpoint,
			ActiveGeneration: entry.Manifest.ActiveGeneration, State: "building",
			BuildStartedAt: now, UpdatedAt: now,
		}
	} else {
		state.State = "building"
		state.LastError = ""
		state.ResumeCount++
		state.LastResumedAt = time.Now().UTC()
		state.UpdatedAt = state.LastResumedAt
	}
	committed := false
	durablePartial := false
	defer func() {
		if !committed {
			_ = idx.Close()
			if !durablePartial {
				_ = os.RemoveAll(filepath.Join(searchRoot, "indexes", state.IndexID))
			}
		}
	}()
	folders, err := m.space.ListFolders(ctx, access, service.FolderQuery{IncludeTrashed: true})
	if err != nil {
		return err
	}
	folders, trashedItems, err := m.indexableTrash(ctx, access, folders)
	if err != nil {
		return err
	}
	folders = slices.DeleteFunc(folders, func(folder model.Folder) bool {
		return !searchableFolderType(folder.Type) || !ownedBy(folder, login)
	})
	sort.Slice(folders, func(i, j int) bool { return folders[i].ID < folders[j].ID })
	rt.mu.Lock()
	previousState := rt.state
	rt.mu.Unlock()
	state.FoldersTotal = len(folders)
	state.LastRecoveryID = previousState.LastRecoveryID
	state.LastRecovery = previousState.LastRecovery
	state.LastRecoveryAt = previousState.LastRecoveryAt
	state.FoldersDone = completedFolderCount(folders, state.LastFolderID)
	state.UpdatedAt = time.Now().UTC()
	if err := saveBuildState(entry.Path, state); err != nil {
		return fmt.Errorf("save search build checkpoint: %w", err)
	}
	durablePartial = true
	m.setBuildState(rt, state)
	if resumed {
		m.publish(login, "search.index.resumed", state)
	}
	batch := idx.NewBatch()
	pending := 0
	flush := func() error {
		if pending == 0 {
			return nil
		}
		if err := writeIndex(idx, batch); err != nil {
			return err
		}
		batch, pending = idx.NewBatch(), 0
		return nil
	}
	indexItems := func(folder model.Folder, items []model.Item) error {
		for _, item := range items {
			if err := ctx.Err(); err != nil {
				return err
			}
			doc := extract(folder, item, m.settings().MaxExtractedBytes)
			if err := validateDocument(doc); err != nil {
				continue
			}
			if err := batch.Index(item.ID, doc); err != nil {
				return err
			}
			pending++
			state.ItemsDone++
			if pending >= m.settings().BatchSize {
				if err := writeIndex(idx, batch); err != nil {
					return err
				}
				batch, pending = idx.NewBatch(), 0
			}
		}
		return nil
	}
	for _, folder := range folders {
		if state.LastFolderID != "" && folder.ID <= state.LastFolderID {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := forEachFolderItem(ctx, m.space, access, folder.ID, m.settings().BatchSize, func(items []model.Item) error {
			return indexItems(folder, items)
		}); err != nil {
			return fmt.Errorf("list %s for indexing: %w", folder.ID, err)
		}
		if err := flush(); err != nil {
			return err
		}
		state.FoldersDone++
		state.LastFolderID = folder.ID
		state.Documents, err = idx.DocCount()
		if err != nil {
			return err
		}
		state.UpdatedAt = time.Now().UTC()
		if err := saveBuildState(entry.Path, state); err != nil {
			return fmt.Errorf("save search folder checkpoint: %w", err)
		}
		m.setBuildState(rt, state)
		m.publish(login, "search.index.progress", state)
	}
	if !state.TrashComplete {
		for _, item := range trashedItems {
			if err := ctx.Err(); err != nil {
				return err
			}
			folder, found := findFolder(folders, item.FolderID)
			if !found {
				continue
			}
			doc := extract(folder, item, m.settings().MaxExtractedBytes)
			if err := validateDocument(doc); err != nil {
				continue
			}
			if err := batch.Index(item.ID, doc); err != nil {
				return err
			}
			pending++
			state.ItemsDone++
			if pending >= m.settings().BatchSize {
				if err := writeIndex(idx, batch); err != nil {
					return err
				}
				batch, pending = idx.NewBatch(), 0
			}
		}
		if err := flush(); err != nil {
			return err
		}
		state.TrashComplete = true
		state.Documents, err = idx.DocCount()
		if err != nil {
			return err
		}
		state.UpdatedAt = time.Now().UTC()
		if err := saveBuildState(entry.Path, state); err != nil {
			return fmt.Errorf("save search trash checkpoint: %w", err)
		}
		m.setBuildState(rt, state)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, listErr := m.changes.ListChanges(ctx, access, service.ChangeScope{Object: service.ChangeObjectItem}, state.Checkpoint, m.settings().BatchSize)
		if listErr != nil {
			return listErr
		}
		if err := m.applyChanges(ctx, idx, access, folders, page); err != nil {
			return err
		}
		state.Checkpoint = page.NewState
		state.Documents, err = idx.DocCount()
		if err != nil {
			return err
		}
		state.UpdatedAt = time.Now().UTC()
		if err := saveBuildState(entry.Path, state); err != nil {
			return fmt.Errorf("save search catch-up checkpoint: %w", err)
		}
		m.setBuildState(rt, state)
		if !page.HasMoreChanges && page.NewState == page.CurrentState {
			break
		}
	}
	count, err := idx.DocCount()
	if err != nil {
		return err
	}
	state.Documents = count
	state.State = "ready"
	state.LastError = ""
	state.UpdatedAt = time.Now().UTC()
	if err := saveState(entry.Path, state); err != nil {
		return err
	}
	if err := removeBuildState(entry.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rt.mu.Lock()
	old := rt.index
	rt.index = idx
	rt.state = state
	rt.lastUsed = time.Now()
	rt.validated = true
	rt.mu.Unlock()
	if old != nil {
		rt.indexUse.Lock()
		_ = guardIndex("close", old.Close)
		rt.indexUse.Unlock()
	}
	committed = true
	m.removeStaleIndexes(entry.Path, state.IndexID)
	m.publish(login, "search.index.ready", state)
	return nil
}

// forEachFolderItem bounds payload residency and the duration of account-store
// read views during a derived-index rebuild. Older FolderSpace implementations
// retain the unbounded compatibility path, while Veksel' routed, durable,
// cached, and automation-decorated spaces all provide the pager.
func forEachFolderItem(ctx context.Context, space service.FolderSpace, access service.AccessContext, folderID string, limit int, visit func([]model.Item) error) error {
	if pager, ok := space.(service.FolderItemPager); ok {
		limit = min(limit, service.MaxItemPageLimit)
		beforeUID := uint32(0)
		for {
			page, err := pager.ListItemPage(ctx, access, folderID, service.ItemPageQuery{BeforeUID: beforeUID, Limit: limit, IncludeData: true})
			if err != nil {
				return err
			}
			if len(page.Items) > 0 {
				if err := visit(page.Items); err != nil {
					return err
				}
			}
			if page.NextBeforeUID == 0 {
				return nil
			}
			if page.NextBeforeUID == beforeUID {
				return errors.New("folder item page did not advance")
			}
			beforeUID = page.NextBeforeUID
		}
	}
	items, err := space.ListItems(ctx, access, folderID, service.ItemQuery{})
	if err != nil {
		return err
	}
	return visit(items)
}

// ownedBy reports whether folder belongs to account login. An account's
// index holds only its own folders: an account that can read other
// accounts' folders, such as the system owner, searches them through their
// owners' indexes (SearchQuery.AccountID), so they are neither indexed
// twice nor copied out of an account sealed at rest.
func ownedBy(folder model.Folder, login string) bool {
	return strings.EqualFold(folder.UserID, login)
}

func (m *Manager) indexableTrash(ctx context.Context, access service.AccessContext, folders []model.Folder) ([]model.Folder, []model.Item, error) {
	recovery, ok := m.space.(service.RecoverableFolderSpace)
	if !ok {
		return folders, nil, nil
	}
	summaries, err := recovery.ListTrash(ctx, access)
	if err != nil {
		return nil, nil, err
	}
	seenFolders := make(map[string]struct{}, len(folders))
	for _, folder := range folders {
		seenFolders[folder.ID] = struct{}{}
	}
	items := make([]model.Item, 0, len(summaries))
	for _, summary := range summaries {
		item, itemErr := m.space.GetItem(ctx, access, summary.ID)
		if itemErr != nil {
			return nil, nil, itemErr
		}
		items = append(items, item)
		if _, exists := seenFolders[item.FolderID]; exists {
			continue
		}
		folder, folderErr := m.space.GetFolder(ctx, access, item.FolderID)
		if folderErr != nil {
			return nil, nil, folderErr
		}
		folders = append(folders, folder)
		seenFolders[folder.ID] = struct{}{}
	}
	return folders, items, nil
}

func findFolder(folders []model.Folder, id string) (model.Folder, bool) {
	for _, folder := range folders {
		if folder.ID == id {
			return folder, true
		}
	}
	return model.Folder{}, false
}

func (m *Manager) removeStaleIndexes(accountPath string, retainedIDs ...string) {
	root := filepath.Join(accountPath, "search", "indexes")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	retained := make(map[string]struct{}, len(retainedIDs))
	for _, id := range retainedIDs {
		if id != "" {
			retained[id] = struct{}{}
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		_, keep := retained[name]
		if !entry.IsDir() || keep || !strings.HasPrefix(name, "idx_") {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, name))
	}
	m.trimIndexQuarantine(accountPath, 3)
}

func (m *Manager) quarantineIndex(accountPath, indexID string, cause error) error {
	if indexID == "" || filepath.Base(indexID) != indexID || !strings.HasPrefix(indexID, "idx_") {
		return fmt.Errorf("invalid search index identity %q", indexID)
	}
	source := filepath.Join(accountPath, "search", "indexes", indexID)
	if _, err := os.Stat(source); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	root := filepath.Join(accountPath, "search", "quarantine")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	destination := filepath.Join(root, time.Now().UTC().Format("20060102T150405.000000000Z")+"-"+indexID)
	if err := os.Rename(source, destination); err != nil {
		return fmt.Errorf("quarantine index: %w", err)
	}
	record := map[string]any{"index_id": indexID, "quarantined_at": time.Now().UTC(), "reason": cause.Error()}
	data, _ := json.MarshalIndent(record, "", "  ")
	if err := os.WriteFile(filepath.Join(destination, "veksel-recovery.json"), data, 0o600); err != nil {
		return fmt.Errorf("write quarantine record: %w", err)
	}
	m.trimIndexQuarantine(accountPath, 3)
	return nil
}

func (m *Manager) trimIndexQuarantine(accountPath string, retain int) {
	root := filepath.Join(accountPath, "search", "quarantine")
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) <= retain {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		left, leftErr := entries[i].Info()
		right, rightErr := entries[j].Info()
		if leftErr != nil || rightErr != nil {
			return entries[i].Name() < entries[j].Name()
		}
		return left.ModTime().Before(right.ModTime())
	})
	for _, entry := range entries[:len(entries)-retain] {
		_ = os.RemoveAll(filepath.Join(root, entry.Name()))
	}
}

func (m *Manager) indexDiskBytes(login, indexID string) int64 {
	if indexID == "" {
		return 0
	}
	entry, found := m.accounts.ByLogin(login)
	if !found {
		return 0
	}
	var total int64
	root := filepath.Join(entry.Path, "search", "indexes", indexID)
	_ = filepath.WalkDir(root, func(_ string, item os.DirEntry, err error) error {
		if err != nil || item.IsDir() {
			return nil
		}
		info, infoErr := item.Info()
		if infoErr == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// catchUp applies one page of journal changes to the serving index. more
// reports that the journal holds further changes beyond the page.
func (m *Manager) catchUp(ctx context.Context, login string, rt *runtime) (more bool, err error) {
	entry, found := m.accounts.ByLogin(login)
	if !found {
		return false, store.ErrNotFound
	}
	access := service.UserAccess(login, service.ProtocolSearchIndexer)
	rt.mu.Lock()
	state := rt.state
	validated := rt.validated
	rt.mu.Unlock()
	page, err := m.changes.ListChanges(ctx, access, service.ChangeScope{Object: service.ChangeObjectItem}, state.Checkpoint, m.settings().BatchSize)
	if errors.Is(err, service.ErrChangeStateExpired) {
		return false, m.rebuild(ctx, login, rt, true)
	}
	if err != nil {
		return false, err
	}
	if len(page.Records) == 0 {
		if !validated {
			if err := m.validateColdIndex(login, state); err != nil {
				_ = m.recoverServingIndex(login, rt, state.IndexID, fmt.Errorf("open ready index: %w", err))
				return false, m.rebuild(ctx, login, rt, true)
			}
			rt.mu.Lock()
			rt.validated = true
			rt.mu.Unlock()
		}
		// Only non-item changes (folders) followed the checkpoint. Advance
		// past them so a query reading its own writes does not wait for a
		// change the index never has to apply.
		if page.NewState == state.Checkpoint {
			return false, nil
		}
		state.Checkpoint = page.NewState
		return page.HasMoreChanges, m.commitCatchUp(entry.Path, rt, state)
	}
	// Opening a large Scorch index may resume costly background segment merges.
	// Keep an unchanged ready index cold after startup; searches validate it on
	// demand, and catch-up opens it only when there is actual work to apply.
	idx, err := m.openIndex(login, rt)
	if errors.Is(err, errAccountMoved) {
		return false, err
	}
	if err != nil {
		_ = m.recoverServingIndex(login, rt, state.IndexID, fmt.Errorf("open ready index: %w", err))
		return false, m.rebuild(ctx, login, rt, true)
	}
	folders, err := m.space.ListFolders(ctx, access, service.FolderQuery{IncludeTrashed: true})
	if err != nil {
		return false, err
	}
	folders = slices.DeleteFunc(folders, func(folder model.Folder) bool { return !ownedBy(folder, login) })
	if err := m.writeServing(rt, idx, state.IndexID, func() error {
		if err := m.applyChanges(ctx, idx, access, folders, page); err != nil {
			return err
		}
		state.Checkpoint = page.NewState
		if err := guardIndex("count", func() (countErr error) {
			state.Documents, countErr = idx.DocCount()
			return countErr
		}); err != nil {
			return fmt.Errorf("%w: count search documents after catch-up: %w", errIndexFault, err)
		}
		return nil
	}); err != nil {
		return false, err
	}
	return page.HasMoreChanges, m.commitCatchUp(entry.Path, rt, state)
}

// writeServing runs write while holding the write lease on idx, provided idx
// is still the serving index of generation indexID. The lease keeps detach
// and close waiting until write returns, panics included.
func (m *Manager) writeServing(rt *runtime, idx bleve.Index, indexID string, write func() error) error {
	rt.indexUse.RLock()
	defer rt.indexUse.RUnlock()
	rt.mu.Lock()
	serving := rt.index == idx && rt.state.IndexID == indexID && !rt.relocating
	rt.mu.Unlock()
	if !serving {
		return fmt.Errorf("search serving generation changed during catch-up")
	}
	return write()
}

// commitCatchUp persists an advanced serving checkpoint and wakes queries
// waiting for it, unless the serving generation changed meanwhile.
func (m *Manager) commitCatchUp(accountPath string, rt *runtime, state persistedState) error {
	state.UpdatedAt = time.Now().UTC()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.state.IndexID != state.IndexID || rt.state.State != "ready" {
		return nil
	}
	if err := saveState(accountPath, state); err != nil {
		return err
	}
	rt.state = state
	rt.checkpointAdvancedLocked()
	return nil
}

// validateColdIndex verifies the durable serving generation without retaining
// an open Scorch instance. Opening Scorch starts its background merger; closing
// it immediately after validation prevents an unchanged account from spending
// CPU and disk bandwidth compacting the derived index merely because Veksel
// restarted.
func (m *Manager) validateColdIndex(login string, state persistedState) error {
	entry, found := m.accounts.ByLogin(login)
	if !found {
		return store.ErrNotFound
	}
	idx, err := bleve.Open(filepath.Join(entry.Path, "search", "indexes", state.IndexID))
	if err != nil {
		return err
	}
	documents, countErr := idx.DocCount()
	closeErr := idx.Close()
	if countErr != nil {
		return fmt.Errorf("validate index: %w", countErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close validated index: %w", closeErr)
	}
	if documents != state.Documents {
		return fmt.Errorf("validate index: stored document count %d differs from index count %d", state.Documents, documents)
	}
	return nil
}

func (m *Manager) openIndex(login string, rt *runtime) (bleve.Index, error) {
	entry, found := m.accounts.ByLogin(login)
	if !found {
		return nil, store.ErrNotFound
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.relocating || (rt.path != "" && rt.path != entry.Path) {
		// Never serve or reopen an index from the directory a move left.
		return nil, errAccountMoved
	}
	if rt.index != nil {
		rt.lastUsed = time.Now()
		return rt.index, nil
	}
	idx, err := bleve.Open(filepath.Join(entry.Path, "search", "indexes", rt.state.IndexID))
	if err != nil {
		return nil, err
	}
	documents, err := idx.DocCount()
	if err != nil {
		_ = idx.Close()
		return nil, fmt.Errorf("validate index: %w", err)
	}
	if documents != rt.state.Documents {
		_ = idx.Close()
		return nil, fmt.Errorf("validate index: stored document count %d differs from index count %d", rt.state.Documents, documents)
	}
	rt.index = idx
	rt.lastUsed = time.Now()
	rt.validated = true
	return idx, nil
}

func (m *Manager) recoverServingIndex(login string, rt *runtime, indexID string, cause error) error {
	entry, found := m.accounts.ByLogin(login)
	if !found {
		return store.ErrNotFound
	}
	now := time.Now().UTC()
	rt.mu.Lock()
	if rt.state.IndexID != indexID {
		rt.mu.Unlock()
		return nil
	}
	failedIndex := rt.index
	rt.index = nil
	rt.validated = false
	state := rt.state
	state.IndexID = ""
	state.Documents = 0
	state.State = "rebuild_requested"
	state.LastError = "serving search index failed validation: " + cause.Error()
	state.LastRecoveryID = indexID
	state.LastRecovery = cause.Error()
	state.LastRecoveryAt = now
	state.UpdatedAt = now
	rt.state = state
	if rt.buildState == nil {
		requested := state
		rt.buildState = &requested
	}
	rt.forceRebuild = true
	rt.nextAttempt = time.Time{}
	rt.mu.Unlock()
	if failedIndex != nil {
		rt.indexUse.Lock()
		_ = guardIndex("close", failedIndex.Close)
		rt.indexUse.Unlock()
	}

	quarantineErr := m.quarantineIndex(entry.Path, indexID, cause)
	saveErr := saveState(entry.Path, state)
	m.publish(login, "search.index.recovery_requested", state)
	return errors.Join(quarantineErr, saveErr)
}

func (m *Manager) applyChanges(ctx context.Context, idx bleve.Index, access service.AccessContext, folders []model.Folder, page service.ChangePage) error {
	folderByID := make(map[string]model.Folder, len(folders))
	for _, folder := range folders {
		folderByID[folder.ID] = folder
	}
	batch := idx.NewBatch()
	for _, record := range page.Records {
		for _, change := range record.Changes {
			if change.Object != service.ChangeObjectItem {
				continue
			}
			if change.Operation == service.ChangeDestroy {
				batch.Delete(change.ID)
				continue
			}
			item, err := m.changedItem(ctx, access, change)
			if errors.Is(err, store.ErrNotFound) {
				batch.Delete(change.ID)
				continue
			}
			if err != nil {
				return err
			}
			folder, found := folderByID[item.FolderID]
			if !found {
				folder, err = m.space.GetFolder(ctx, access, item.FolderID)
				if errors.Is(err, store.ErrNotFound) {
					batch.Delete(item.ID)
					continue
				}
				if err != nil {
					return err
				}
				folderByID[folder.ID] = folder
			}
			if !searchableFolderType(folder.Type) {
				batch.Delete(item.ID)
				continue
			}
			if err := batch.Index(item.ID, extract(folder, item, m.settings().MaxExtractedBytes)); err != nil {
				return err
			}
		}
	}
	return writeIndex(idx, batch)
}

// changedItem reads the current item of a journaled item change. Not found
// means the item no longer exists where the change put it, so the index
// drops it; a later journal record covers wherever it went.
//
// GetItem alone cannot establish that. The routed account space resolves an
// item ID through a system-wide location index written only after the
// account commit, and that commit already made the journal record visible
// and woke the indexer. A brand-new item read in that window is reported as
// missing, and treating it as deleted would advance the checkpoint past its
// creation and leave it unsearchable until the next rebuild. The change's
// folder and UID address the item in the account store that holds the
// journal itself, so that lookup is never behind the record being applied.
func (m *Manager) changedItem(ctx context.Context, access service.AccessContext, change service.Change) (model.Item, error) {
	item, err := m.space.GetItem(ctx, access, change.ID)
	if !errors.Is(err, store.ErrNotFound) || change.FolderID == "" || change.UID == 0 {
		return item, err
	}
	item, err = m.space.GetItemByUID(ctx, access, change.FolderID, change.UID)
	if err == nil && item.ID != change.ID {
		return model.Item{}, store.ErrNotFound
	}
	return item, err
}

func searchableFolderType(folderType model.FolderType) bool {
	return slices.Contains([]model.FolderType{
		model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeTasks, model.FolderTypeContacts,
		model.FolderTypeFiles, model.FolderTypeNotes,
	}, folderType)
}

func (m *Manager) setBuildState(rt *runtime, state persistedState) {
	rt.mu.Lock()
	rt.buildState = &state
	rt.mu.Unlock()
}

func (m *Manager) publish(login, eventType string, state persistedState) {
	m.eventsMu.RLock()
	publisher := m.events
	m.eventsMu.RUnlock()
	if publisher == nil {
		return
	}
	publisher.Publish(events.Event{Type: eventType, Resource: "account:" + login, Recipients: []string{login}, Data: map[string]any{
		"state": state.State, "folders_done": state.FoldersDone, "folders_total": state.FoldersTotal,
		"items_done": state.ItemsDone, "documents": state.Documents, "error": state.LastError,
		"last_folder_id": state.LastFolderID, "resume_count": state.ResumeCount,
	}})
}

// indexMapping lays out the account index for size. Every field opts out of
// the composite _all field and of term vectors: queries always name their
// fields, phrase queries are not offered, and snippets are cut from the
// re-extracted item rather than highlighted from the index. Only folder_id
// and summary are stored, because they are all a hit is served from;
// doc values are kept just for the facet and sort fields. Fields that are
// neither queried, sorted, nor faceted (item_id, folder_name, truncated,
// contact_emails) are left unmapped and dynamic mapping is off, so they
// never reach the index; the summary carries what hits present of them.
func indexMapping() mapping.IndexMapping {
	result := bleve.NewIndexMapping()
	result.IndexDynamic = false
	result.StoreDynamic = false
	result.DocValuesDynamic = false
	doc := bleve.NewDocumentMapping()
	doc.Dynamic = false
	lean := func(field *mapping.FieldMapping, docValues bool) *mapping.FieldMapping {
		field.Store = false
		field.IncludeInAll = false
		field.IncludeTermVectors = false
		field.DocValues = docValues
		return field
	}
	// keyword is an exact-match term without relevance statistics; sort
	// and facet fields keep doc values.
	keyword := func(docValues bool) *mapping.FieldMapping {
		field := lean(bleve.NewKeywordFieldMapping(), docValues)
		field.SkipFreqNorm = true
		return field
	}
	text := func(docValues bool) *mapping.FieldMapping { return lean(bleve.NewTextFieldMapping(), docValues) }
	folderID := keyword(true)
	folderID.Store = true // read back to authorize summary hits
	doc.AddFieldMappingsAt("folder_id", folderID)
	doc.AddFieldMappingsAt("type", keyword(true))
	// Sortable text fields keep doc values; the rest are search-only.
	for _, field := range []string{"name", "title", "sender", "recipients"} {
		doc.AddFieldMappingsAt(field, text(true))
	}
	for _, field := range []string{"subject", "headers", "content", "attachment", "attachment_content", "contact_suggest"} {
		doc.AddFieldMappingsAt(field, text(false))
	}
	for _, field := range []string{"contact_name", "contact_org", "contact_email", "contact_phone"} {
		doc.AddFieldMappingsAt(field, keyword(true))
	}
	doc.AddFieldMappingsAt("flags", keyword(false))
	doc.AddFieldMappingsAt("categories", keyword(false))
	date := lean(bleve.NewDateTimeFieldMapping(), true)
	doc.AddFieldMappingsAt("date", date)
	doc.AddFieldMappingsAt("updated", lean(bleve.NewDateTimeFieldMapping(), false))
	doc.AddFieldMappingsAt("size", lean(bleve.NewNumericFieldMapping(), true))
	doc.AddFieldMappingsAt("trashed", lean(bleve.NewBooleanFieldMapping(), false))
	doc.AddFieldMappingsAt("has_attachment", lean(bleve.NewBooleanFieldMapping(), false))
	summary := bleve.NewKeywordFieldMapping()
	summary.Store = true
	summary.Index = false
	summary.IncludeInAll = false
	summary.IncludeTermVectors = false
	summary.DocValues = false
	doc.AddFieldMappingsAt("summary", summary)
	result.DefaultMapping = doc
	result.DefaultAnalyzer = "standard"
	return result
}

func statePath(accountPath string) string { return filepath.Join(accountPath, "search", stateFilename) }

func buildStatePath(accountPath string) string {
	return filepath.Join(accountPath, "search", buildStateFilename)
}

func loadState(accountPath string) (persistedState, error) {
	data, err := os.ReadFile(statePath(accountPath))
	if err != nil {
		return persistedState{}, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, err
	}
	return state, nil
}

func saveState(accountPath string, state persistedState) error {
	return savePersistedState(accountPath, statePath(accountPath), ".state.tmp", state)
}

func loadBuildState(accountPath string) (persistedState, error) {
	data, err := os.ReadFile(buildStatePath(accountPath))
	if err != nil {
		return persistedState{}, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, err
	}
	return state, nil
}

func saveBuildState(accountPath string, state persistedState) error {
	return savePersistedState(accountPath, buildStatePath(accountPath), ".build.tmp", state)
}

func savePersistedState(accountPath, destination, temporaryName string, state persistedState) error {
	root := filepath.Join(accountPath, "search")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temporary := filepath.Join(root, temporaryName)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func removeBuildState(accountPath string) error {
	return os.Remove(buildStatePath(accountPath))
}

func validBuildState(state persistedState, generation string) error {
	if state.Version != mappingVersion || state.ActiveGeneration != generation {
		return errors.New("search build version or account generation changed")
	}
	if state.IndexID == "" || filepath.Base(state.IndexID) != state.IndexID || !strings.HasPrefix(state.IndexID, "idx_") {
		return errors.New("invalid partial search index identity")
	}
	if state.Checkpoint == "" || state.BuildStartedAt.IsZero() || state.ResumeCount < 0 || state.FoldersDone < 0 || state.FoldersTotal < 0 || state.ItemsDone < 0 {
		return errors.New("incomplete partial search checkpoint")
	}
	if state.State != "building" && state.State != "failed" && state.State != "rebuild_requested" {
		return errors.New("partial search checkpoint has an invalid state")
	}
	if len(state.LastFolderID) > 1024 || (state.FoldersDone > 0 && state.LastFolderID == "") {
		return errors.New("partial search folder checkpoint is inconsistent")
	}
	return nil
}

func completedFolderCount(folders []model.Folder, lastFolderID string) int {
	if lastFolderID == "" {
		return 0
	}
	return sort.Search(len(folders), func(index int) bool { return folders[index].ID > lastFolderID })
}

func (m *Manager) discardPartialBuild(accountPath string, rt *runtime) {
	state, err := loadBuildState(accountPath)
	rt.mu.Lock()
	servingID := rt.state.IndexID
	rt.buildState = nil
	rt.mu.Unlock()
	if err == nil && state.IndexID != servingID && filepath.Base(state.IndexID) == state.IndexID && strings.HasPrefix(state.IndexID, "idx_") {
		_ = os.RemoveAll(filepath.Join(accountPath, "search", "indexes", state.IndexID))
	}
	_ = removeBuildState(accountPath)
}

func newIndexID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "idx_" + hex.EncodeToString(raw[:]), nil
}

func (m *Manager) visibleFolders(ctx context.Context, access service.AccessContext, accountID string, query service.SearchQuery) ([]model.Folder, service.AccessContext, error) {
	readAccess := access
	if !strings.EqualFold(accountID, access.Subject.ID) {
		readAccess.Subject = access.Actor
		readAccess.Mode = authz.ActingNone
	}
	folders, err := m.space.ListFolders(ctx, readAccess, service.FolderQuery{IncludeTrashed: query.IncludeTrash})
	if err != nil {
		return nil, readAccess, err
	}
	// Trashed collections are intentionally absent from normal discovery. Add
	// only folders represented by authorized trash items when explicitly asked.
	if query.IncludeTrash {
		if recovery, ok := m.space.(service.RecoverableFolderSpace); ok {
			if trash, trashErr := recovery.ListTrash(ctx, readAccess); trashErr == nil {
				seen := make(map[string]struct{}, len(folders))
				for _, folder := range folders {
					seen[folder.ID] = struct{}{}
				}
				for _, item := range trash {
					if _, exists := seen[item.FolderID]; exists {
						continue
					}
					folder, folderErr := m.space.GetFolder(ctx, readAccess, item.FolderID)
					if folderErr == nil {
						folders = append(folders, folder)
						seen[folder.ID] = struct{}{}
					}
				}
			}
		}
	}
	wantedFolders := make(map[string]struct{}, len(query.FolderIDs))
	for _, id := range query.FolderIDs {
		wantedFolders[id] = struct{}{}
	}
	wantedTypes := make(map[model.FolderType]struct{}, len(query.Types))
	for _, folderType := range query.Types {
		wantedTypes[folderType] = struct{}{}
	}
	visible := folders[:0]
	for _, folder := range folders {
		if !strings.EqualFold(folder.UserID, accountID) {
			continue
		}
		if len(wantedFolders) > 0 {
			if _, ok := wantedFolders[folder.ID]; !ok {
				continue
			}
		}
		if len(wantedTypes) > 0 {
			if _, ok := wantedTypes[folder.Type]; !ok {
				continue
			}
		}
		visible = append(visible, folder)
	}
	return visible, readAccess, nil
}
