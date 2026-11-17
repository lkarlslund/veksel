package account

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Manager is the process boundary for account discovery and storage lifecycle.
// It caches active generations and leases them per operation so conversion can
// fence one account without disturbing any other account.
type Manager struct {
	mu                   sync.RWMutex
	root                 atomic.Pointer[string]
	roots                map[string]string
	primaryRoot          string
	defaultEngine        store.Backend
	catalog              *Catalog
	converting           map[string]struct{}
	conversionCancel     map[string]context.CancelFunc
	runtimes             map[string]*accountRuntime
	idleTimeout          atomic.Int64
	retainedCleanupDays  atomic.Int64
	stopReaper           chan struct{}
	closeReaper          sync.Once
	operations           sync.WaitGroup
	closing              atomic.Bool
	availabilityNotifier func(string)
	relocationObservers  map[uint64]RelocationObserver
	relocationSeq        uint64
	keys                 KeyWrapper
	encryptByDefault     atomic.Bool
}

// Export writes the active account as a backend-independent logical bundle.
func (m *Manager) Export(ctx context.Context, login string, destination io.Writer) error {
	entry, found := m.ByLogin(login)
	if !found {
		return store.ErrNotFound
	}
	generation, release, err := m.Acquire(login)
	if err != nil {
		return err
	}
	defer release()
	return ExportBundle(ctx, entry, generation, destination)
}

// Restore replaces an account's active logical image after identity and digest
// verification. Client synchronization state is rebased, as for an
// installation restore, so clients resynchronize. The prior generation
// remains available for operator cleanup.
func (m *Manager) Restore(ctx context.Context, login string, source io.Reader, engine store.Backend) (IntegrityReport, error) {
	if !SupportedEngine(engine) {
		return IntegrityReport{}, fmt.Errorf("unsupported account engine %q", engine)
	}
	entry, found := m.ByLogin(login)
	if !found {
		return IntegrityReport{}, store.ErrNotFound
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return IntegrityReport{}, err
	}
	defer runtime.lifecycle.Store(false)
	if !m.beginOperation() {
		return IntegrityReport{}, ErrTemporarilyUnavailable
	}
	defer m.operations.Done()
	if !runtime.maintenance.CompareAndSwap(false, true) {
		return IntegrityReport{}, ErrTemporarilyUnavailable
	}
	defer m.releaseMaintenance(runtime, entry.Manifest.Login)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.generation != nil {
		_ = runtime.generation.Close()
		runtime.generation = nil
	}
	generationID, err := NewGenerationID()
	if err != nil {
		return IntegrityReport{}, err
	}
	job, err := m.newLifecycleJob(entry, LifecycleRestore, entry.RootID)
	if err != nil {
		return IntegrityReport{}, err
	}
	job.SourceGeneration = entry.Manifest.ActiveGeneration
	job.TargetGeneration = generationID
	job.TargetEngine = engine
	job.Phase = LifecycleRunning
	job.UpdatedAt = time.Now().UTC()
	if err := m.writeLifecycleJob(job); err != nil {
		return IntegrityReport{}, err
	}
	var report IntegrityReport
	var restoreErr error
	activated := false
	defer func() {
		if activated {
			job.RetainedSource = filepath.Join(entry.Path, "generations", job.SourceGeneration)
		}
		m.finishLifecycleJob(&job, report.ID, restoreErr, &runtime.lifecycle)
	}()
	target, err := createGeneration(entry.Path, generationID, engine, m.keys, entry.Manifest.Encrypted)
	if err != nil {
		restoreErr = err
		return IntegrityReport{}, err
	}
	defer func() {
		_ = target.Close()
		if !activated {
			_ = os.RemoveAll(filepath.Join(entry.Path, "generations", generationID))
		}
	}()
	bundleManifest, err := ImportBundle(ctx, source, target)
	if err != nil {
		restoreErr = err
		return IntegrityReport{}, err
	}
	if bundleManifest.ID != entry.Manifest.ID || bundleManifest.Login != entry.Manifest.Login {
		restoreErr = errors.New("account bundle identity does not match restore target")
		return IntegrityReport{}, restoreErr
	}
	if err := rebaseRestoredSyncState(ctx, target, time.Now()); err != nil {
		restoreErr = err
		return IntegrityReport{}, err
	}
	restored := entry
	restored.Manifest.Engine = engine
	restored.Manifest.ActiveGeneration = generationID
	report, err = CheckGeneration(ctx, restored, target, false)
	if err != nil || !report.Healthy {
		if err == nil {
			err = errors.New("restored account failed integrity verification")
		}
		restoreErr = err
		return report, err
	}
	if err := target.Close(); err != nil {
		restoreErr = err
		return report, err
	}
	target = &Generation{Objects: nil}
	manifest := entry.Manifest
	manifest.Engine = engine
	manifest.ActiveGeneration = generationID
	manifest.UpdatedAt = time.Now().UTC()
	if err := WriteManifest(filepath.Join(entry.Path, ManifestFilename), manifest); err != nil {
		restoreErr = err
		return report, err
	}
	activated = true
	m.mu.Lock()
	err = m.refreshLocked()
	m.mu.Unlock()
	restoreErr = err
	return report, err
}

// Move relocates one account to another configured root through a verified
// logical copy. The prior directory is retained under a hidden name.
func (m *Manager) Move(ctx context.Context, login, targetRootID string) (Entry, IntegrityReport, error) {
	return m.move(ctx, login, targetRootID, false)
}

func (m *Manager) move(ctx context.Context, login, targetRootID string, lifecycleReserved bool) (Entry, IntegrityReport, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return Entry{}, IntegrityReport{}, store.ErrNotFound
	}
	m.mu.RLock()
	targetRoot, configured := m.roots[targetRootID]
	m.mu.RUnlock()
	if !configured {
		return Entry{}, IntegrityReport{}, fmt.Errorf("account root %q is not configured", targetRootID)
	}
	if entry.RootID == targetRootID {
		return Entry{}, IntegrityReport{}, errors.New("account already uses target root")
	}
	m.mu.RLock()
	runtime := m.runtimes[entry.Manifest.ID]
	m.mu.RUnlock()
	if !lifecycleReserved {
		var err error
		runtime, err = m.reserveLifecycle(entry.Manifest.ID)
		if err != nil {
			return Entry{}, IntegrityReport{}, err
		}
		defer runtime.lifecycle.Store(false)
	}
	if !runtime.maintenance.CompareAndSwap(false, true) {
		return Entry{}, IntegrityReport{}, ErrTemporarilyUnavailable
	}
	// Derived state such as the search index keeps files open inside the
	// account directory. Observers release them before the directory is
	// renamed and reopen at the final path once the account is available
	// again (deferred first, so it runs after maintenance is released).
	retained := ""
	finishRelocation := m.beginRelocation(entry)
	defer func() { finishRelocation(retained) }()
	defer m.releaseMaintenance(runtime, entry.Manifest.Login)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.generation != nil {
		_ = runtime.generation.Close()
		runtime.generation = nil
	}
	if err := os.MkdirAll(targetRoot, 0o700); err != nil {
		return Entry{}, IntegrityReport{}, err
	}
	moveID, err := randomID("mov")
	if err != nil {
		return Entry{}, IntegrityReport{}, err
	}
	staging := filepath.Join(targetRoot, "."+moveID)
	if err := os.Mkdir(staging, 0o700); err != nil {
		return Entry{}, IntegrityReport{}, err
	}
	committed := false
	preserveStaging := false
	defer func() {
		if !committed && !preserveStaging {
			_ = os.RemoveAll(staging)
		}
	}()
	sourceGeneration, err := openActive(entry, m.keys)
	if err != nil {
		return Entry{}, IntegrityReport{}, err
	}
	bundle, err := os.CreateTemp(targetRoot, ".move-bundle-*.tmp")
	if err != nil {
		_ = sourceGeneration.Close()
		return Entry{}, IntegrityReport{}, err
	}
	bundlePath := bundle.Name()
	defer func() { _ = os.Remove(bundlePath) }()
	if err := ExportBundle(ctx, entry, sourceGeneration, bundle); err != nil {
		_ = bundle.Close()
		_ = sourceGeneration.Close()
		return Entry{}, IntegrityReport{}, err
	}
	if err := errors.Join(bundle.Sync(), sourceGeneration.Close()); err != nil {
		_ = bundle.Close()
		return Entry{}, IntegrityReport{}, err
	}
	if _, err := bundle.Seek(0, io.SeekStart); err != nil {
		_ = bundle.Close()
		return Entry{}, IntegrityReport{}, err
	}
	targetGeneration, err := createGeneration(staging, entry.Manifest.ActiveGeneration, entry.Manifest.Engine, m.keys, entry.Manifest.Encrypted)
	if err != nil {
		_ = bundle.Close()
		return Entry{}, IntegrityReport{}, err
	}
	if _, err := ImportBundle(ctx, bundle, targetGeneration); err != nil {
		_ = bundle.Close()
		_ = targetGeneration.Close()
		return Entry{}, IntegrityReport{}, err
	}
	_ = bundle.Close()
	targetEntry := Entry{Manifest: entry.Manifest, Path: filepath.Join(targetRoot, entry.Manifest.ID), RootID: targetRootID}
	report, err := CheckGeneration(ctx, targetEntry, targetGeneration, false)
	if closeErr := targetGeneration.Close(); err == nil {
		err = closeErr
	}
	if err != nil || !report.Healthy {
		if err == nil {
			err = errors.New("moved account failed verification")
		}
		return Entry{}, report, err
	}
	if err := WriteManifest(filepath.Join(staging, ManifestFilename), entry.Manifest); err != nil {
		return Entry{}, report, err
	}
	finalPath := filepath.Join(targetRoot, entry.Manifest.ID)
	if _, err := os.Lstat(finalPath); !errors.Is(err, os.ErrNotExist) {
		return Entry{}, report, errors.New("target account path already exists")
	}
	hiddenSource := filepath.Join(filepath.Dir(entry.Path), ".moved-"+entry.Manifest.ID+"-"+moveID)
	journal := moveJournal{Version: moveJournalVersion, MoveID: moveID, AccountID: entry.Manifest.ID, Source: entry.Path, HiddenSource: hiddenSource, Staging: staging, Final: finalPath}
	journalPath := journal.filename(targetRoot)
	if err := writeMoveJournal(journalPath, journal); err != nil {
		return Entry{}, report, err
	}
	if err := os.Rename(entry.Path, hiddenSource); err != nil {
		_ = os.Remove(journalPath)
		return Entry{}, report, err
	}
	preserveStaging = true
	if err := syncDirectory(filepath.Dir(entry.Path)); err != nil {
		return Entry{}, report, err
	}
	if err := os.Rename(staging, finalPath); err != nil {
		if rollbackErr := os.Rename(hiddenSource, entry.Path); rollbackErr == nil {
			preserveStaging = false
			_ = os.Remove(journalPath)
		}
		return Entry{}, report, err
	}
	if err := syncDirectory(targetRoot); err != nil {
		return Entry{}, report, err
	}
	committed = true
	retained = hiddenSource
	m.mu.Lock()
	err = m.refreshLocked()
	m.mu.Unlock()
	if err != nil {
		return Entry{}, report, err
	}
	moved, found := m.ByLogin(login)
	if !found {
		return Entry{}, report, errors.New("moved account is not discoverable")
	}
	if err := os.Remove(journalPath); err != nil {
		return moved, report, err
	}
	if err := syncDirectory(targetRoot); err != nil {
		return moved, report, err
	}
	return moved, report, nil
}

// Purge irreversibly removes account storage after an exact confirmation.
func (m *Manager) Purge(login, confirmation string) error {
	return m.purge(login, confirmation, false)
}

func (m *Manager) purge(login, confirmation string, lifecycleReserved bool) error {
	entry, found := m.ByLogin(login)
	if !found {
		return store.ErrNotFound
	}
	if confirmation != "purge:"+entry.Manifest.ID {
		return errors.New("account purge confirmation does not match")
	}
	m.mu.RLock()
	runtime := m.runtimes[entry.Manifest.ID]
	m.mu.RUnlock()
	if !lifecycleReserved {
		var err error
		runtime, err = m.reserveLifecycle(entry.Manifest.ID)
		if err != nil {
			return err
		}
		defer runtime.lifecycle.Store(false)
	}
	if runtime == nil || !runtime.maintenance.CompareAndSwap(false, true) {
		return ErrTemporarilyUnavailable
	}
	runtime.mu.Lock()
	if runtime.generation != nil {
		_ = runtime.generation.Close()
		runtime.generation = nil
	}
	hidden := filepath.Join(filepath.Dir(entry.Path), ".purged-"+entry.Manifest.ID+fmt.Sprintf("-%d", time.Now().UnixNano()))
	if err := os.Rename(entry.Path, hidden); err != nil {
		runtime.mu.Unlock()
		m.releaseMaintenance(runtime, entry.Manifest.Login)
		return err
	}
	runtime.mu.Unlock()
	m.mu.Lock()
	refreshErr := m.refreshLocked()
	m.mu.Unlock()
	if refreshErr != nil {
		_ = os.Rename(hidden, entry.Path)
		m.releaseMaintenance(runtime, entry.Manifest.Login)
		return refreshErr
	}
	m.mu.Lock()
	delete(m.runtimes, entry.Manifest.ID)
	m.mu.Unlock()
	return os.RemoveAll(hidden)
}

type accountRuntime struct {
	mu          sync.RWMutex
	generation  *Generation
	maintenance atomic.Bool
	lifecycle   atomic.Bool
	lastUsed    atomic.Int64
}

func (m *Manager) reserveLifecycle(accountID string) (*accountRuntime, error) {
	m.mu.RLock()
	runtime := m.runtimes[accountID]
	m.mu.RUnlock()
	if runtime == nil {
		return nil, store.ErrNotFound
	}
	if !runtime.lifecycle.CompareAndSwap(false, true) {
		return nil, ErrLifecycleConflict
	}
	return runtime, nil
}

func NewManager(root string, defaultEngine store.Backend, options ...ManagerOption) (*Manager, error) {
	return NewManagerWithRoots([]Root{{ID: "default", Path: root}}, "default", defaultEngine, options...)
}

// normalizeRoots validates a root set and returns it with absolute paths, the
// ID-to-path map, and the primary root's path.
func normalizeRoots(roots []Root, primaryRoot string) ([]Root, map[string]string, string, error) {
	if len(roots) == 0 {
		return nil, nil, "", errors.New("at least one account storage root is required")
	}
	roots = slices.Clone(roots)
	rootMap := make(map[string]string, len(roots))
	for index := range roots {
		if strings.TrimSpace(roots[index].ID) == "" || strings.ContainsAny(roots[index].ID, "/\\\x00") {
			return nil, nil, "", fmt.Errorf("invalid account root ID %q", roots[index].ID)
		}
		absolute, err := filepath.Abs(roots[index].Path)
		if err != nil {
			return nil, nil, "", err
		}
		if _, duplicate := rootMap[roots[index].ID]; duplicate {
			return nil, nil, "", fmt.Errorf("duplicate account root ID %q", roots[index].ID)
		}
		if info, statErr := os.Lstat(absolute); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, "", fmt.Errorf("account storage root %q cannot be a symlink", roots[index].ID)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, nil, "", fmt.Errorf("inspect account storage root %q: %w", roots[index].ID, statErr)
		}
		for _, existing := range rootMap {
			if absolute == existing || strings.HasPrefix(absolute+string(os.PathSeparator), existing+string(os.PathSeparator)) || strings.HasPrefix(existing+string(os.PathSeparator), absolute+string(os.PathSeparator)) {
				return nil, nil, "", errors.New("account storage roots cannot overlap")
			}
		}
		roots[index].Path = absolute
		rootMap[roots[index].ID] = absolute
	}
	primaryPath, found := rootMap[primaryRoot]
	if !found {
		return nil, nil, "", fmt.Errorf("primary account root %q is not configured", primaryRoot)
	}
	return roots, rootMap, primaryPath, nil
}

// NewManagerWithRoots discovers accounts across named placement roots.
func NewManagerWithRoots(roots []Root, primaryRoot string, defaultEngine store.Backend, options ...ManagerOption) (*Manager, error) {
	var settings managerSettings
	for _, option := range options {
		option(&settings)
	}
	if !SupportedEngine(defaultEngine) {
		return nil, fmt.Errorf("unsupported default account engine %q", defaultEngine)
	}
	roots, rootMap, primaryPath, err := normalizeRoots(roots, primaryRoot)
	if err != nil {
		return nil, err
	}
	if err := recoverMoves(roots); err != nil {
		return nil, err
	}
	catalog, err := DiscoverRoots(roots)
	if err != nil {
		return nil, err
	}
	recoveredPreparing := false
	for _, entry := range catalog.Entries() {
		recovered, recoverErr := recoverPreparingConversion(entry, settings.keys)
		if recoverErr != nil {
			return nil, fmt.Errorf("recover preparing conversion for %s: %w", entry.Manifest.Login, recoverErr)
		}
		recoveredPreparing = recoveredPreparing || recovered
	}
	if recoveredPreparing {
		catalog, err = DiscoverRoots(roots)
		if err != nil {
			return nil, err
		}
	}
	manager := &Manager{roots: rootMap, primaryRoot: primaryRoot, defaultEngine: defaultEngine, catalog: catalog, converting: make(map[string]struct{}), conversionCancel: make(map[string]context.CancelFunc), runtimes: make(map[string]*accountRuntime), stopReaper: make(chan struct{}), keys: settings.keys}
	manager.root.Store(&primaryPath)
	manager.idleTimeout.Store(int64(5 * time.Minute))
	manager.retainedCleanupDays.Store(30)
	for _, entry := range catalog.Entries() {
		if err := reconcileActivatedConversions(entry); err != nil {
			_ = manager.Close()
			return nil, fmt.Errorf("reconcile conversion for %s: %w", entry.Manifest.Login, err)
		}
		manager.runtimeLocked(entry.Manifest.ID)
		if entry.Manifest.State == StateConverting && entry.Manifest.ConversionID != "" {
			manager.converting[entry.Manifest.ID] = struct{}{}
			manager.runtimes[entry.Manifest.ID].maintenance.Store(true)
			manager.runtimes[entry.Manifest.ID].lifecycle.Store(true)
			manager.operations.Add(1)
			go func() {
				defer manager.operations.Done()
				manager.resume(entry, context.Background())
			}()
		}
	}
	if err := manager.reconcileLifecycleJobs(); err != nil {
		_ = manager.Close()
		return nil, err
	}
	go manager.reapLoop()
	return manager, nil
}

// Acquire returns the active account generation and a mandatory release
// callback. The shared generation stays open across requests, while the read
// lease lets conversion wait for in-flight operations and fence new ones.
func (m *Manager) Acquire(login string) (*Generation, func(), error) {
	m.mu.RLock()
	entry, found := m.catalog.ByLogin(login)
	var runtime *accountRuntime
	if found {
		runtime = m.runtimes[entry.Manifest.ID]
	}
	m.mu.RUnlock()
	if !found || runtime == nil {
		return nil, nil, store.ErrNotFound
	}
	if runtime.maintenance.Load() || entry.Manifest.State == StateConverting || entry.Manifest.State == StateUnavailable {
		return nil, nil, ErrTemporarilyUnavailable
	}
	runtime.mu.RLock()
	if runtime.maintenance.Load() {
		runtime.mu.RUnlock()
		return nil, nil, ErrTemporarilyUnavailable
	}
	if runtime.generation != nil && runtime.generation.ID == entry.Manifest.ActiveGeneration {
		runtime.lastUsed.Store(time.Now().UnixNano())
		return runtime.generation, func() {
			runtime.lastUsed.Store(time.Now().UnixNano())
			runtime.mu.RUnlock()
		}, nil
	}
	runtime.mu.RUnlock()

	runtime.mu.Lock()
	if runtime.maintenance.Load() {
		runtime.mu.Unlock()
		return nil, nil, ErrTemporarilyUnavailable
	}
	if runtime.generation == nil || runtime.generation.ID != entry.Manifest.ActiveGeneration {
		if runtime.generation != nil {
			_ = runtime.generation.Close()
		}
		generation, err := openActive(entry, m.keys)
		if err != nil {
			runtime.mu.Unlock()
			return nil, nil, err
		}
		runtime.generation = generation
	}
	runtime.mu.Unlock()
	return m.Acquire(login)
}

// Close releases every cached account provider. It must run after protocol
// listeners stop accepting work.
func (m *Manager) Close() error {
	m.mu.Lock()
	m.closing.Store(true)
	m.mu.Unlock()
	m.closeReaper.Do(func() { close(m.stopReaper) })
	m.operations.Wait()
	m.mu.RLock()
	runtimes := make([]*accountRuntime, 0, len(m.runtimes))
	for _, runtime := range m.runtimes {
		runtimes = append(runtimes, runtime)
	}
	m.mu.RUnlock()
	var result error
	for _, runtime := range runtimes {
		runtime.maintenance.Store(true)
		runtime.mu.Lock()
		if runtime.generation != nil {
			result = errors.Join(result, runtime.generation.Close())
			runtime.generation = nil
		}
		runtime.mu.Unlock()
	}
	return result
}

// SetIdleTimeout controls how long an unused account generation remains open.
// Zero disables idle closing; a later Acquire transparently reopens it.
func (m *Manager) SetIdleTimeout(timeout time.Duration) {
	if timeout < 0 {
		timeout = 0
	}
	m.idleTimeout.Store(int64(timeout))
}

func (m *Manager) reapLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			m.ReapIdle(now)
			_, _ = m.ReapRetained(now)
		case <-m.stopReaper:
			return
		}
	}
}

// SetRetainedCleanupDays controls when verified rollback copies become
// eligible for automatic cleanup. Values below one day are clamped to one.
func (m *Manager) SetRetainedCleanupDays(days int) {
	if days < 1 {
		days = 1
	}
	m.retainedCleanupDays.Store(int64(days))
}

// ReapIdle closes inactive providers without interrupting leased operations.
// It is exported for deterministic maintenance and tests.
func (m *Manager) ReapIdle(now time.Time) int {
	timeout := time.Duration(m.idleTimeout.Load())
	if timeout <= 0 {
		return 0
	}
	m.mu.RLock()
	runtimes := make([]*accountRuntime, 0, len(m.runtimes))
	for _, runtime := range m.runtimes {
		runtimes = append(runtimes, runtime)
	}
	m.mu.RUnlock()
	cutoff := now.Add(-timeout).UnixNano()
	closed := 0
	for _, runtime := range runtimes {
		if runtime.lastUsed.Load() > cutoff || runtime.maintenance.Load() || !runtime.mu.TryLock() {
			continue
		}
		if runtime.lastUsed.Load() <= cutoff && runtime.generation != nil {
			_ = runtime.generation.Close()
			runtime.generation = nil
			closed++
		}
		runtime.mu.Unlock()
	}
	return closed
}

func (m *Manager) Root() string { return *m.root.Load() }

func (m *Manager) Roots() []Root {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rootsLocked()
}

func (m *Manager) rootsLocked() []Root {
	result := make([]Root, 0, len(m.roots))
	for id, path := range m.roots {
		result = append(result, Root{ID: id, Path: path})
	}
	slices.SortFunc(result, func(a, b Root) int { return strings.Compare(a.ID, b.ID) })
	return result
}

func (m *Manager) DefaultEngine() store.Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultEngine
}

func (m *Manager) SetDefaultEngine(engine store.Backend) error {
	if !SupportedEngine(engine) {
		return fmt.Errorf("unsupported default account engine %q", engine)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultEngine = engine
	return nil
}

func (m *Manager) Entries() []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.catalog.Entries()
}

func (m *Manager) Issues() []Issue {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.catalog.Issues()
}

func (m *Manager) ByLogin(login string) (Entry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.catalog.ByLogin(login)
}

// Ensure creates the independent account generation for a system user if it
// was not already discovered. Existing manifests remain authoritative.
func (m *Manager) Ensure(ctx context.Context, user model.User, primary string, addresses []string) (Entry, bool, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, found := m.catalog.ByLogin(user.ID); found {
		runtime := m.runtimeLocked(entry.Manifest.ID)
		if runtime.maintenance.Load() {
			return Entry{}, false, ErrTemporarilyUnavailable
		}
		runtime.mu.Lock()
		generation := runtime.generation
		if generation == nil || generation.ID != entry.Manifest.ActiveGeneration {
			if generation != nil {
				_ = generation.Close()
			}
			var err error
			generation, err = openActive(entry, m.keys)
			if err != nil {
				runtime.mu.Unlock()
				return Entry{}, false, err
			}
			runtime.generation = generation
		}
		typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
		if err := applyOwner(ctx, typed, user); err != nil {
			runtime.mu.Unlock()
			return Entry{}, false, fmt.Errorf("update account owner: %w", err)
		}
		if err := typed.FolderStore().EnsureForUser(ctx, user.ID); err != nil {
			runtime.mu.Unlock()
			return Entry{}, false, fmt.Errorf("ensure account folders: %w", err)
		}
		runtime.mu.Unlock()
		normalized := normalizeAddresses(addresses)
		if len(normalized) == 0 {
			normalized = entry.Manifest.Addresses
		}
		primary = normalizeAddress(primary)
		if primary == "" {
			primary = entry.Manifest.PrimaryAddress
		}
		updated := entry.Manifest
		updated.DisplayName = user.DisplayName
		updated.Addresses = normalized
		updated.PrimaryAddress = primary
		if primary != "" && !slices.Contains(updated.Addresses, primary) {
			updated.Addresses = append(updated.Addresses, primary)
			slices.Sort(updated.Addresses)
		}
		updated.UpdatedAt = time.Now().UTC()
		if updated.DisplayName != entry.Manifest.DisplayName || !slices.Equal(updated.Addresses, entry.Manifest.Addresses) || updated.PrimaryAddress != entry.Manifest.PrimaryAddress {
			if err := WriteManifest(filepath.Join(entry.Path, ManifestFilename), updated); err != nil {
				return Entry{}, false, err
			}
			if err := m.refreshLocked(); err != nil {
				return Entry{}, false, err
			}
			entry, _ = m.catalog.ByLogin(user.ID)
		}
		return entry, false, nil
	}
	normalizedAddresses := normalizeAddresses(addresses)
	primary = normalizeAddress(primary)
	if primary == "" && len(normalizedAddresses) > 0 {
		primary = normalizedAddresses[0]
	}
	manifest, err := NewManifest(user.ID, user.DisplayName, primary, normalizedAddresses, m.defaultEngine, time.Now())
	if err != nil {
		return Entry{}, false, err
	}
	manifest.Encrypted = m.encryptByDefault.Load()
	accountPath := filepath.Join(m.Root(), manifest.ID)
	if err := os.Mkdir(accountPath, 0o700); err != nil {
		return Entry{}, false, fmt.Errorf("create account directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(accountPath)
		}
	}()
	generation, err := createGeneration(accountPath, manifest.ActiveGeneration, manifest.Engine, m.keys, manifest.Encrypted)
	if err != nil {
		return Entry{}, false, err
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(ctx, namespace); err != nil {
			_ = generation.Close()
			return Entry{}, false, fmt.Errorf("initialize account namespace %q: %w", namespace, err)
		}
	}
	if err := typed.Put(ctx, model.NSUsers, user.ID, user); err != nil {
		_ = generation.Close()
		return Entry{}, false, fmt.Errorf("initialize account owner: %w", err)
	}
	if err := typed.FolderStore().EnsureForUser(ctx, user.ID); err != nil {
		_ = generation.Close()
		return Entry{}, false, err
	}
	if err := generation.Close(); err != nil {
		return Entry{}, false, err
	}
	if err := WriteManifest(filepath.Join(accountPath, ManifestFilename), manifest); err != nil {
		return Entry{}, false, err
	}
	if err := m.refreshLocked(); err != nil {
		return Entry{}, false, err
	}
	entry, found := m.catalog.ByID(manifest.ID)
	if !found {
		return Entry{}, false, errors.New("new account was not discoverable")
	}
	m.runtimeLocked(manifest.ID)
	committed = true
	return entry, true, nil
}

// applyOwner refreshes the account-local owner record from the system user.
// Usage counters are account-authoritative: item writes adjust them in the
// same account transaction, so the system copy's stale values never replace
// them. Every other field, including quota limits, follows the system record.
func applyOwner(ctx context.Context, typed *model.TypedStore, user model.User) error {
	return store.Batch(ctx, typed.Store(), func(batchCtx context.Context) error {
		current, err := typed.UserStore().Get(batchCtx, user.ID)
		if err == nil {
			user.CurrentStorageBytes = current.CurrentStorageBytes
			user.CurrentItems = current.CurrentItems
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		return typed.Set(batchCtx, model.NSUsers, user.ID, user)
	})
}

// Convert changes an account's engine using verified generation cutover.
func (m *Manager) Convert(ctx context.Context, login string, target store.Backend) (ConversionJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return ConversionJob{}, store.ErrNotFound
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return ConversionJob{}, err
	}
	defer runtime.lifecycle.Store(false)
	m.mu.Lock()
	if _, busy := m.converting[entry.Manifest.ID]; busy {
		m.mu.Unlock()
		return ConversionJob{}, ErrConversionConflict
	}
	m.converting[entry.Manifest.ID] = struct{}{}
	m.mu.Unlock()
	if !runtime.maintenance.CompareAndSwap(false, true) {
		m.mu.Lock()
		delete(m.converting, entry.Manifest.ID)
		m.mu.Unlock()
		return ConversionJob{}, ErrTemporarilyUnavailable
	}
	runtime.mu.Lock()
	if runtime.generation != nil {
		_ = runtime.generation.Close()
		runtime.generation = nil
	}
	runtime.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.converting, entry.Manifest.ID)
		_ = m.refreshLocked()
		m.mu.Unlock()
		m.releaseMaintenance(runtime, entry.Manifest.Login)
	}()
	return convert(ctx, entry.Path, ConversionTarget{Engine: target, Encrypted: entry.Manifest.Encrypted}, m.keys)
}

// StartConversion prepares a durable job and returns before the data copy. A
// process interruption leaves both the source generation and job checkpoint in
// place; NewManager resumes it on the next start.
func (m *Manager) StartConversion(login string, target store.Backend) (ConversionJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return ConversionJob{}, store.ErrNotFound
	}
	return m.startConversion(login, ConversionTarget{Engine: target, Encrypted: entry.Manifest.Encrypted}, "")
}

// StartConversionTo is StartConversion for an explicit target, which may
// also encrypt, decrypt, or rotate the data-encryption key of the account.
func (m *Manager) StartConversionTo(login string, target ConversionTarget) (ConversionJob, error) {
	return m.startConversion(login, target, "")
}

func (m *Manager) startConversion(login string, target ConversionTarget, parentJobID string) (ConversionJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return ConversionJob{}, store.ErrNotFound
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return ConversionJob{}, err
	}
	if !m.beginOperation() {
		runtime.lifecycle.Store(false)
		return ConversionJob{}, ErrTemporarilyUnavailable
	}
	handedOff := false
	defer func() {
		if !handedOff {
			m.operations.Done()
			runtime.lifecycle.Store(false)
		}
	}()
	m.mu.Lock()
	if _, busy := m.converting[entry.Manifest.ID]; busy {
		m.mu.Unlock()
		return ConversionJob{}, ErrConversionConflict
	}
	m.converting[entry.Manifest.ID] = struct{}{}
	m.mu.Unlock()
	if !runtime.maintenance.CompareAndSwap(false, true) {
		m.mu.Lock()
		delete(m.converting, entry.Manifest.ID)
		m.mu.Unlock()
		return ConversionJob{}, ErrTemporarilyUnavailable
	}
	runtime.mu.Lock()
	if runtime.generation != nil {
		_ = runtime.generation.Close()
		runtime.generation = nil
	}
	runtime.mu.Unlock()
	job, err := prepareConversion(entry.Path, target, m.keys, nil)
	if err != nil {
		m.mu.Lock()
		delete(m.converting, entry.Manifest.ID)
		m.mu.Unlock()
		m.releaseMaintenance(runtime, entry.Manifest.Login)
		return job, err
	}
	job.ParentJobID = parentJobID
	if err := writeConversionJob(entry.Path, job); err != nil {
		if converting, readErr := ReadManifest(filepath.Join(entry.Path, ManifestFilename)); readErr == nil {
			_, _ = rollbackConversion(entry.Path, converting, job, err)
		}
		m.mu.Lock()
		delete(m.converting, entry.Manifest.ID)
		m.mu.Unlock()
		m.releaseMaintenance(runtime, entry.Manifest.Login)
		return job, err
	}
	m.mu.Lock()
	_ = m.refreshLocked()
	m.mu.Unlock()
	entry.Manifest.State = StateConverting
	entry.Manifest.ConversionID = job.ID
	conversionContext, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.conversionCancel[entry.Manifest.ID] = cancel
	m.mu.Unlock()
	handedOff = true
	go func() {
		defer m.operations.Done()
		m.resume(entry, conversionContext)
	}()
	return job, nil
}

func (m *Manager) resume(entry Entry, ctx context.Context) {
	defer func() {
		m.mu.RLock()
		runtime := m.runtimes[entry.Manifest.ID]
		m.mu.RUnlock()
		if runtime != nil {
			runtime.lifecycle.Store(false)
		}
	}()
	_, _ = resumeConversion(ctx, entry.Path, entry.Manifest.ConversionID, m.keys, nil)
	m.mu.Lock()
	delete(m.converting, entry.Manifest.ID)
	if cancel := m.conversionCancel[entry.Manifest.ID]; cancel != nil {
		cancel()
		delete(m.conversionCancel, entry.Manifest.ID)
	}
	_ = m.refreshLocked()
	runtime := m.runtimeLocked(entry.Manifest.ID)
	m.mu.Unlock()
	m.releaseMaintenance(runtime, entry.Manifest.Login)
}

// SetAvailabilityNotifier installs the queue wake hook used after account
// maintenance. The callback must return quickly and must not call Close.
func (m *Manager) SetAvailabilityNotifier(notifier func(string)) {
	m.mu.Lock()
	m.availabilityNotifier = notifier
	m.mu.Unlock()
}

func (m *Manager) releaseMaintenance(runtime *accountRuntime, login string) {
	runtime.maintenance.Store(false)
	m.mu.RLock()
	notifier := m.availabilityNotifier
	m.mu.RUnlock()
	if notifier != nil {
		notifier(login)
	}
}

func (m *Manager) Jobs(login string) ([]ConversionJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return nil, store.ErrNotFound
	}
	dir := filepath.Join(entry.Path, "conversions")
	files, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []ConversionJob{}, nil
	}
	if err != nil {
		return nil, err
	}
	jobs := make([]ConversionJob, 0, len(files))
	for _, file := range files {
		id := strings.TrimSuffix(file.Name(), ".json")
		if file.IsDir() || id == file.Name() || !validConversionID(id) {
			continue
		}
		job, err := ReadConversionJob(entry.Path, id)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	slices.SortFunc(jobs, func(a, b ConversionJob) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return jobs, nil
}

// CancelConversion durably requests cancellation before manifest activation.
// The runner observes both the durable flag and its in-process context.
func (m *Manager) CancelConversion(login, jobID string) (ConversionJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return ConversionJob{}, store.ErrNotFound
	}
	job, err := ReadConversionJob(entry.Path, jobID)
	if err != nil {
		return ConversionJob{}, err
	}
	if job.AccountID != entry.Manifest.ID || job.Phase == ConversionActivating || job.Phase == ConversionCompleted || job.Phase == ConversionCanceled || job.Phase == ConversionFailed {
		return job, fmt.Errorf("%w: conversion cannot be canceled in phase %s", ErrConversionConflict, job.Phase)
	}
	if entry.Manifest.State != StateConverting || entry.Manifest.ConversionID != job.ID {
		return job, fmt.Errorf("%w: conversion is not active", ErrConversionConflict)
	}
	job.CancelRequested = true
	job.UpdatedAt = time.Now().UTC()
	if err := writeConversionJob(entry.Path, job); err != nil {
		return job, err
	}
	m.mu.RLock()
	cancel := m.conversionCancel[entry.Manifest.ID]
	m.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
	return job, nil
}

// StartConversionRollback converts the current logical account image back to
// the source engine of a completed conversion. It never activates the stale
// retained generation over writes made after the original cutover.
func (m *Manager) StartConversionRollback(login, jobID string) (ConversionJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return ConversionJob{}, store.ErrNotFound
	}
	original, err := ReadConversionJob(entry.Path, jobID)
	if err != nil {
		return ConversionJob{}, err
	}
	if original.AccountID != entry.Manifest.ID || original.Phase != ConversionCompleted || original.SourcePurgedAt != nil || entry.Manifest.Engine != original.TargetEngine || entry.Manifest.ActiveGeneration != original.TargetGeneration {
		return ConversionJob{}, fmt.Errorf("%w: completed conversion is not the active cutover", ErrConversionConflict)
	}
	retained := filepath.Join(entry.Path, "generations", original.SourceGeneration)
	if exists, err := safeDirectoryExists(retained); err != nil {
		return ConversionJob{}, err
	} else if !exists {
		return ConversionJob{}, errors.New("retained source generation is unavailable")
	}
	return m.startConversion(login, ConversionTarget{Engine: original.SourceEngine, Encrypted: original.SourceEncrypted, RotateKey: original.SourceEncrypted && original.TargetEncrypted && original.SourceEngine == original.TargetEngine}, original.ID)
}

// CleanupConversionSource permanently removes a retained source generation
// after exact confirmation. The active generation is never accepted.
func (m *Manager) CleanupConversionSource(login, jobID, confirmation string) (ConversionJob, error) {
	entry, job, err := m.conversionCleanupCandidate(login, jobID)
	if err != nil {
		return job, err
	}
	if confirmation != "cleanup:"+job.ID {
		return job, errors.New("conversion cleanup confirmation or job state does not match")
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return job, err
	}
	defer runtime.lifecycle.Store(false)
	if !m.beginOperation() {
		return job, ErrTemporarilyUnavailable
	}
	defer m.operations.Done()
	return m.cleanupConversionSource(entry, job)
}

func (m *Manager) conversionCleanupCandidate(login, jobID string) (Entry, ConversionJob, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return Entry{}, ConversionJob{}, store.ErrNotFound
	}
	job, err := ReadConversionJob(entry.Path, jobID)
	if err != nil {
		return entry, ConversionJob{}, err
	}
	if job.AccountID != entry.Manifest.ID || job.Phase != ConversionCompleted || job.SourcePurgedAt != nil {
		return entry, job, errors.New("conversion cleanup confirmation or job state does not match")
	}
	if entry.Manifest.ActiveGeneration == job.SourceGeneration {
		return entry, job, errors.New("refusing to remove the active generation")
	}
	return entry, job, nil
}

func (m *Manager) cleanupConversionSource(entry Entry, job ConversionJob) (ConversionJob, error) {
	path := filepath.Join(entry.Path, "generations", job.SourceGeneration)
	if filepath.Dir(path) != filepath.Join(entry.Path, "generations") || !generationPattern.MatchString(filepath.Base(path)) {
		return job, errors.New("invalid retained generation path")
	}
	if exists, err := safeDirectoryExists(path); err != nil {
		return job, err
	} else if !exists {
		return job, errors.New("retained source generation is unavailable")
	}
	if err := os.RemoveAll(path); err != nil {
		return job, err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return job, err
	}
	purgedAt := time.Now().UTC()
	job.SourcePurgedAt = &purgedAt
	job.UpdatedAt = purgedAt
	return job, writeConversionJob(entry.Path, job)
}

// Check verifies account-local truth. Repair fences the account and may rebuild
// only derived counters; ordinary checks hold a read lease and remain online.
func (m *Manager) Check(ctx context.Context, login string, repair bool) (IntegrityReport, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return IntegrityReport{}, store.ErrNotFound
	}
	if !repair {
		return m.runIntegrityCheck(ctx, entry, false, nil, nil)
	}
	runtime, err := m.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		return IntegrityReport{}, err
	}
	defer runtime.lifecycle.Store(false)
	return m.runIntegrityCheck(ctx, entry, true, runtime, nil)
}

func (m *Manager) runIntegrityCheck(ctx context.Context, entry Entry, repair bool, runtime *accountRuntime, progress func(IntegrityProgress) error) (IntegrityReport, error) {
	if !repair {
		generation, release, err := m.Acquire(entry.Manifest.Login)
		if err != nil {
			return IntegrityReport{}, err
		}
		defer release()
		report, err := checkGeneration(ctx, entry, generation, false, progress)
		if err == nil {
			err = writeIntegrityReport(entry.Path, report)
		}
		return report, err
	}
	if runtime == nil {
		return IntegrityReport{}, errors.New("repair requires a reserved lifecycle lease")
	}
	if !runtime.maintenance.CompareAndSwap(false, true) {
		return IntegrityReport{}, ErrTemporarilyUnavailable
	}
	defer m.releaseMaintenance(runtime, entry.Manifest.Login)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.generation != nil {
		_ = runtime.generation.Close()
		runtime.generation = nil
	}
	generation, err := openActive(entry, m.keys)
	if err != nil {
		return IntegrityReport{}, err
	}
	report, checkErr := checkGeneration(ctx, entry, generation, true, progress)
	closeErr := generation.Close()
	if checkErr == nil {
		checkErr = writeIntegrityReport(entry.Path, report)
	}
	return report, errors.Join(checkErr, closeErr)
}

func (m *Manager) refreshLocked() error {
	catalog, err := DiscoverRoots(m.rootsLocked())
	if err != nil {
		return err
	}
	m.catalog = catalog
	for _, entry := range catalog.Entries() {
		m.runtimeLocked(entry.Manifest.ID)
	}
	return nil
}

func (m *Manager) runtimeLocked(accountID string) *accountRuntime {
	runtime := m.runtimes[accountID]
	if runtime == nil {
		runtime = &accountRuntime{}
		m.runtimes[accountID] = runtime
	}
	return runtime
}
