package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const accountItemLocationsNamespace = "account_item_locations"

type accountItemLocation struct {
	Login    string `json:"login"`
	FolderID string `json:"folder_id"`
}

type cachedAccountSpace struct {
	generation *account.Generation
	space      *FolderSpaceService
}

// AccountFolderSpace routes logical folder operations to the owning account's
// selected generation. The system store retains only the folder resource
// catalog needed by global RBAC and the rebuildable item-location index.
type AccountFolderSpace struct {
	system     *model.TypedStore
	accounts   *account.Manager
	authorizer *authz.Engine

	mu                  sync.Mutex
	cache               map[string]cachedAccountSpace
	trashRetentionDays  atomic.Int64
	changeRetentionDays atomic.Int64
	changeMaxEntries    atomic.Int64
	legalHolds          atomic.Pointer[legalHoldBox]
	commitListeners     changeListeners
}

// ChangePruneResult reports one bounded pass over per-account change journals.
type ChangePruneResult struct {
	AccountsScanned int `json:"accounts_scanned"`
	AccountsSkipped int `json:"accounts_skipped"`
	ChangesRemoved  int `json:"changes_removed"`
}

type ItemHistoryPruneResult struct {
	AccountsScanned int `json:"accounts_scanned"`
	AccountsSkipped int `json:"accounts_skipped"`
	VersionsRemoved int `json:"versions_removed"`
}

func NewAccountFolderSpace(ctx context.Context, system *model.TypedStore, accounts *account.Manager, authorizer *authz.Engine) (*AccountFolderSpace, error) {
	if system == nil || accounts == nil || authorizer == nil {
		return nil, errors.New("system store, account manager, and authorizer are required")
	}
	if err := system.EnsureNamespace(ctx, accountItemLocationsNamespace); err != nil {
		return nil, fmt.Errorf("initialize account item locations: %w", err)
	}
	result := &AccountFolderSpace{system: system, accounts: accounts, authorizer: authorizer, cache: make(map[string]cachedAccountSpace)}
	result.trashRetentionDays.Store(DefaultTrashRetentionDays)
	result.changeRetentionDays.Store(DefaultChangeRetentionDays)
	result.changeMaxEntries.Store(DefaultChangeMaxEntries)
	if err := result.reconcileFolderCatalog(ctx); err != nil {
		return nil, fmt.Errorf("reconcile account folder catalog: %w", err)
	}
	return result, nil
}

// reconcileFolderCatalog repairs the rebuildable system-side resource catalog
// from canonical account stores. It covers folders created by older builds or
// interrupted migrations, and keeps RBAC checks independent of item storage.
// Each account's folders mirror in one system-store batch, so startup syncs
// once per account instead of once per folder.
func (s *AccountFolderSpace) reconcileFolderCatalog(ctx context.Context) error {
	for _, entry := range s.accounts.Entries() {
		generation, release, err := s.accounts.Acquire(entry.Manifest.Login)
		if err != nil {
			return fmt.Errorf("open %s: %w", entry.Manifest.Login, err)
		}
		typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
		folders, listErr := typed.FolderStore().ListAll(ctx)
		release()
		if listErr == nil {
			listErr = store.Batch(ctx, s.system.Store(), func(batchCtx context.Context) error {
				for _, folder := range folders {
					if err := s.mirrorFolder(batchCtx, folder); err != nil {
						return err
					}
				}
				return nil
			})
		}
		if listErr != nil {
			return fmt.Errorf("mirror %s: %w", entry.Manifest.Login, listErr)
		}
	}
	return nil
}

func (s *AccountFolderSpace) accountSpace(login string, generation *account.Generation) *FolderSpaceService {
	s.mu.Lock()
	defer s.mu.Unlock()
	cached := s.cache[login]
	if cached.generation != generation {
		typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
		cached = cachedAccountSpace{generation: generation, space: NewFolderSpace(typed, s.authorizer)}
		cached.space.committed = func(folderIDs []string) { s.commitListeners.notify(login, folderIDs) }
		cached.space.SetTrashRetentionDays(int(s.trashRetentionDays.Load()))
		cached.space.changes.SetRetention(int(s.changeRetentionDays.Load()), int(s.changeMaxEntries.Load()))
		if box := s.legalHolds.Load(); box != nil {
			cached.space.SetLegalHolds(box.checker)
		}
		s.cache[login] = cached
	}
	return cached.space
}

// OnChangesCommitted implements FolderChangeNotifier for every account.
func (s *AccountFolderSpace) OnChangesCommitted(listener func(accountID string, folderIDs []string)) func() {
	return s.commitListeners.add(listener)
}

// SetLegalHolds installs the hold registry on every account's FolderSpace.
func (s *AccountFolderSpace) SetLegalHolds(checker LegalHoldChecker) {
	if checker == nil {
		s.legalHolds.Store(nil)
	} else {
		s.legalHolds.Store(&legalHoldBox{checker: checker})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cached := range s.cache {
		cached.space.SetLegalHolds(checker)
	}
}

func (s *AccountFolderSpace) SetChangeRetention(days, maxEntries int) {
	if days < 1 {
		days = 1
	}
	if maxEntries < 1 {
		maxEntries = 1
	}
	s.changeRetentionDays.Store(int64(days))
	s.changeMaxEntries.Store(int64(maxEntries))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cached := range s.cache {
		cached.space.changes.SetRetention(days, maxEntries)
	}
}

// PruneChanges applies the configured retention policy independently to every
// available account. Accounts fenced by lifecycle maintenance are skipped and
// will be considered by the next pass.
func (s *AccountFolderSpace) PruneChanges(ctx context.Context, now time.Time) (ChangePruneResult, error) {
	var result ChangePruneResult
	var resultErr error
	for _, entry := range s.accounts.Entries() {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(resultErr, err)
		}
		generation, release, err := s.accounts.Acquire(entry.Manifest.Login)
		if err != nil {
			if serviceUnavailable := IsTemporarilyUnavailable(err); serviceUnavailable {
				result.AccountsSkipped++
				continue
			}
			resultErr = errors.Join(resultErr, fmt.Errorf("prune changes for %s: %w", entry.Manifest.Login, err))
			continue
		}
		removed, pruneErr := s.accountSpace(entry.Manifest.Login, generation).changes.Prune(ctx, now)
		release()
		if pruneErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("prune changes for %s: %w", entry.Manifest.Login, pruneErr))
			continue
		}
		result.AccountsScanned++
		result.ChangesRemoved += removed
	}
	return result, resultErr
}

// PruneItemHistory applies each folder's own bounded version policy without
// opening item payloads. Accounts fenced for conversion are retried later.
func (s *AccountFolderSpace) PruneItemHistory(ctx context.Context, now time.Time) (ItemHistoryPruneResult, error) {
	var result ItemHistoryPruneResult
	var resultErr error
	for _, entry := range s.accounts.Entries() {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(resultErr, err)
		}
		generation, release, err := s.accounts.Acquire(entry.Manifest.Login)
		if err != nil {
			if IsTemporarilyUnavailable(err) {
				result.AccountsSkipped++
				continue
			}
			resultErr = errors.Join(resultErr, fmt.Errorf("prune item history for %s: %w", entry.Manifest.Login, err))
			continue
		}
		removed, pruneErr := s.accountSpace(entry.Manifest.Login, generation).PruneItemHistory(ctx, now)
		release()
		if pruneErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("prune item history for %s: %w", entry.Manifest.Login, pruneErr))
			continue
		}
		result.AccountsScanned++
		result.VersionsRemoved += removed
	}
	return result, resultErr
}

func (s *AccountFolderSpace) GetItemHistoryPolicy(ctx context.Context, access AccessContext, folderID string) (model.ItemHistoryPolicy, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.ItemHistoryPolicy{}, err
	}
	return withAccount(ctx, s, login, func(space *FolderSpaceService) (model.ItemHistoryPolicy, error) {
		return space.GetItemHistoryPolicy(ctx, access, folderID)
	})
}

func (s *AccountFolderSpace) ConfigureItemHistory(ctx context.Context, access AccessContext, folderID string, policy model.ItemHistoryPolicy) (model.Folder, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	folder, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Folder, error) {
		return space.ConfigureItemHistory(ctx, access, folderID, policy)
	})
	if err != nil {
		return model.Folder{}, err
	}
	return folder, s.mirrorFolder(ctx, folder)
}

func (s *AccountFolderSpace) ListItemVersions(ctx context.Context, access AccessContext, folderID, itemID string) ([]model.ItemVersion, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return nil, err
	}
	return withAccount(ctx, s, login, func(space *FolderSpaceService) ([]model.ItemVersion, error) {
		return space.ListItemVersions(ctx, access, folderID, itemID)
	})
}

func (s *AccountFolderSpace) GetItemVersion(ctx context.Context, access AccessContext, folderID, itemID, versionID string) (model.ItemVersion, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.ItemVersion{}, err
	}
	return withAccount(ctx, s, login, func(space *FolderSpaceService) (model.ItemVersion, error) {
		return space.GetItemVersion(ctx, access, folderID, itemID, versionID)
	})
}

func (s *AccountFolderSpace) RestoreItemVersion(ctx context.Context, access AccessContext, folderID, itemID, versionID string) (model.Item, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Item{}, err
	}
	item, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Item, error) {
		return space.RestoreItemVersion(ctx, access, folderID, itemID, versionID)
	})
	if err != nil {
		return model.Item{}, err
	}
	return item, s.setItemLocation(ctx, item.ID, login, item.FolderID)
}

func (s *AccountFolderSpace) SetTrashRetentionDays(days int) {
	if days < 1 {
		days = 1
	}
	s.trashRetentionDays.Store(int64(days))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cached := range s.cache {
		cached.space.SetTrashRetentionDays(days)
	}
}

func (s *AccountFolderSpace) CurrentChangeState(ctx context.Context, access AccessContext, scope ChangeScope) (string, error) {
	login := access.Subject.ID
	if scope.FolderID != "" {
		var err error
		login, err = s.folderOwner(ctx, scope.FolderID)
		if err != nil {
			return "", err
		}
	}
	return withAccount(ctx, s, login, func(space *FolderSpaceService) (string, error) {
		return space.CurrentChangeState(ctx, access, scope)
	})
}

func (s *AccountFolderSpace) ListChanges(ctx context.Context, access AccessContext, scope ChangeScope, state string, limit int) (ChangePage, error) {
	login := access.Subject.ID
	if scope.FolderID != "" {
		var err error
		login, err = s.folderOwner(ctx, scope.FolderID)
		if err != nil {
			return ChangePage{}, err
		}
	}
	return withAccount(ctx, s, login, func(space *FolderSpaceService) (ChangePage, error) {
		return space.ListChanges(ctx, access, scope, state, limit)
	})
}

func (s *AccountFolderSpace) ListTrash(ctx context.Context, access AccessContext) ([]ItemSummary, error) {
	return withAccount(ctx, s, access.Subject.ID, func(space *FolderSpaceService) ([]ItemSummary, error) {
		return space.ListTrash(ctx, access)
	})
}

func (s *AccountFolderSpace) ListTrashedFolders(ctx context.Context, access AccessContext) ([]model.Folder, error) {
	return withAccount(ctx, s, access.Subject.ID, func(space *FolderSpaceService) ([]model.Folder, error) {
		return space.ListTrashedFolders(ctx, access)
	})
}

func (s *AccountFolderSpace) RestoreFolder(ctx context.Context, access AccessContext, folderID string) (model.Folder, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	folder, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Folder, error) {
		return space.RestoreFolder(ctx, access, folderID)
	})
	if err == nil {
		err = s.mirrorFolder(ctx, folder)
	}
	return folder, err
}

func (s *AccountFolderSpace) PurgeFolder(ctx context.Context, access AccessContext, folderID string) error {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return err
	}
	type purgedTree struct {
		folders   []string
		items     []string
		preserved map[string]string
		held      []model.Folder
	}
	purged, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (purgedTree, error) {
		root, err := space.folders.Get(ctx, folderID)
		if err != nil {
			return purgedTree{}, err
		}
		trashed, err := space.folders.ListTrashedForUser(ctx, root.UserID)
		if err != nil {
			return purgedTree{}, err
		}
		result := purgedTree{}
		for _, candidate := range trashed {
			if candidate.ID != root.ID && !strings.HasPrefix(candidate.OriginalPath, root.OriginalPath+"/") {
				continue
			}
			result.folders = append(result.folders, candidate.ID)
			ids, listErr := space.items.List(ctx, candidate.ID)
			if listErr != nil {
				return purgedTree{}, listErr
			}
			result.items = append(result.items, ids...)
		}
		if err := space.PurgeFolder(ctx, access, folderID); err != nil {
			return purgedTree{}, err
		}
		result.preserved, result.held, err = space.preservedLocations(ctx, result.items)
		return result, err
	})
	if err != nil {
		return err
	}
	if err := s.recordPreserved(ctx, login, purged.preserved, purged.held); err != nil {
		return err
	}
	for _, id := range purged.items {
		if _, preserved := purged.preserved[id]; preserved {
			continue
		}
		if deleteErr := s.system.Delete(ctx, accountItemLocationsNamespace, id); deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
			return deleteErr
		}
	}
	for _, id := range purged.folders {
		if deleteErr := s.system.Delete(ctx, model.NSFolders, id); deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
			return deleteErr
		}
	}
	return nil
}

func (s *AccountFolderSpace) TrashItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	location, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	item, err := withAccount(ctx, s, location.Login, func(space *FolderSpaceService) (model.Item, error) {
		return space.TrashItem(ctx, access, itemID)
	})
	if err == nil {
		err = s.setItemLocation(ctx, item.ID, location.Login, item.FolderID)
	}
	return item, err
}

func (s *AccountFolderSpace) RestoreItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	location, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	item, err := withAccount(ctx, s, location.Login, func(space *FolderSpaceService) (model.Item, error) {
		return space.RestoreItem(ctx, access, itemID)
	})
	if err == nil {
		err = s.setItemLocation(ctx, item.ID, location.Login, item.FolderID)
	}
	return item, err
}

func withAccount[T any](ctx context.Context, s *AccountFolderSpace, login string, fn func(*FolderSpaceService) (T, error)) (T, error) {
	var zero T
	generation, release, err := s.acquireAccount(ctx, login)
	if err != nil {
		return zero, err
	}
	defer release()
	return fn(s.accountSpace(login, generation))
}

// acquireAccount recreates account-local storage for a system user on first
// use. An administrator can purge a test account while retaining its identity;
// the next protocol, UI, or sync operation must see the same bootstrap behavior
// as a process restart instead of failing until Veksel is restarted.
func (s *AccountFolderSpace) acquireAccount(ctx context.Context, login string) (*account.Generation, func(), error) {
	generation, release, err := s.accounts.Acquire(login)
	if !errors.Is(err, store.ErrNotFound) {
		return generation, release, err
	}
	user, err := s.system.UserStore().Get(ctx, login)
	if err != nil {
		return nil, nil, err
	}
	identities, err := s.system.UserStore().ListEmailAddressesForUser(ctx, login)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	addresses := make([]string, 0, len(identities))
	primary := ""
	for _, identity := range identities {
		addresses = append(addresses, identity.ID)
		if identity.Primary {
			primary = identity.ID
		}
	}
	if _, _, err := s.accounts.Ensure(ctx, user, primary, addresses); err != nil {
		return nil, nil, fmt.Errorf("initialize account storage for %s: %w", login, err)
	}
	return s.accounts.Acquire(login)
}

func (s *AccountFolderSpace) Batch(ctx context.Context, fn func(context.Context) error) error {
	// A batch is account-local only after the callback resolves its account.
	// DurableFolderSpace still journals the complete logical command first.
	return fn(ctx)
}

func (s *AccountFolderSpace) AccountUsage(ctx context.Context, access AccessContext) (AccountUsage, error) {
	return withAccount(ctx, s, access.Subject.ID, func(space *FolderSpaceService) (AccountUsage, error) {
		return space.AccountUsage(ctx, access)
	})
}

func (s *AccountFolderSpace) ListFolders(ctx context.Context, access AccessContext, query FolderQuery) ([]model.Folder, error) {
	if err := access.Validate(); err != nil {
		return nil, err
	}
	// Ensure the caller's own account is represented before taking the catalog
	// snapshot. This matters immediately after an account-storage purge.
	_, release, err := s.acquireAccount(ctx, access.Subject.ID)
	if err != nil {
		return nil, err
	}
	release()
	entries := s.accounts.Entries()
	result := make([]model.Folder, 0)
	for _, entry := range entries {
		folders, err := withAccount(ctx, s, entry.Manifest.Login, func(space *FolderSpaceService) ([]model.Folder, error) {
			return space.ListFolders(ctx, access, query)
		})
		if errors.Is(err, account.ErrTemporarilyUnavailable) && entry.Manifest.Login != access.Subject.ID {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, folders...)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].UserID == result[j].UserID {
			return result[i].Path < result[j].Path
		}
		return result[i].UserID < result[j].UserID
	})
	return result, nil
}

// ListOwnFolders lists access.Subject's own folders from its account alone.
func (s *AccountFolderSpace) ListOwnFolders(ctx context.Context, access AccessContext, query FolderQuery) ([]model.Folder, error) {
	return withAccount(ctx, s, access.Subject.ID, func(space *FolderSpaceService) ([]model.Folder, error) {
		return space.ListOwnFolders(ctx, access, query)
	})
}

func (s *AccountFolderSpace) GetFolder(ctx context.Context, access AccessContext, folderID string) (model.Folder, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	return withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Folder, error) {
		return space.GetFolder(ctx, access, folderID)
	})
}

func (s *AccountFolderSpace) GetFolderByPath(ctx context.Context, access AccessContext, path string) (model.Folder, error) {
	return s.GetFolderByOwnerPath(ctx, access, access.Subject.ID, path)
}

func (s *AccountFolderSpace) GetFolderByOwnerPath(ctx context.Context, access AccessContext, ownerID, path string) (model.Folder, error) {
	return withAccount(ctx, s, ownerID, func(space *FolderSpaceService) (model.Folder, error) {
		return space.GetFolderByOwnerPath(ctx, access, ownerID, path)
	})
}

func (s *AccountFolderSpace) CreateFolder(ctx context.Context, access AccessContext, name string, folderType model.FolderType, parentID string) (model.Folder, error) {
	login := access.Subject.ID
	if parentID != "" {
		var err error
		login, err = s.folderOwner(ctx, parentID)
		if err != nil {
			return model.Folder{}, err
		}
	}
	folder, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Folder, error) {
		return space.CreateFolder(ctx, access, name, folderType, parentID)
	})
	if err != nil {
		return model.Folder{}, err
	}
	return folder, s.mirrorFolder(ctx, folder)
}

func (s *AccountFolderSpace) UpdateFolder(ctx context.Context, access AccessContext, folderID string, update FolderUpdate) (model.Folder, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	var related []model.Folder
	folder, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Folder, error) {
		folder, err := space.UpdateFolder(ctx, access, folderID, update)
		if err == nil && update.Default != nil {
			related, err = space.folders.ListForUser(ctx, login)
		}
		return folder, err
	})
	if err != nil {
		return model.Folder{}, err
	}
	if err := s.mirrorFolder(ctx, folder); err != nil {
		return model.Folder{}, err
	}
	for _, candidate := range related {
		if candidate.Type == model.FolderTypeCalendar {
			if err := s.mirrorFolder(ctx, candidate); err != nil {
				return model.Folder{}, err
			}
		}
	}
	return folder, nil
}

func (s *AccountFolderSpace) MoveFolder(ctx context.Context, access AccessContext, folderID, parentID, name string) (model.Folder, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	folder, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Folder, error) {
		return space.MoveFolder(ctx, access, folderID, parentID, name)
	})
	if err != nil {
		return model.Folder{}, err
	}
	return folder, s.mirrorFolder(ctx, folder)
}

func (s *AccountFolderSpace) DeleteFolder(ctx context.Context, access AccessContext, folderID string) error {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return err
	}
	_, err = withAccount(ctx, s, login, func(space *FolderSpaceService) (struct{}, error) {
		if err := space.DeleteFolder(ctx, access, folderID); err != nil {
			return struct{}{}, err
		}
		folders, err := space.folders.ListAll(ctx)
		if err != nil {
			return struct{}{}, err
		}
		for _, folder := range folders {
			if folder.UserID != login || (folder.ID != folderID && folder.Type != model.FolderTypeCalendar) {
				continue
			}
			if err := s.mirrorFolder(ctx, folder); err != nil {
				return struct{}{}, err
			}
		}
		return struct{}{}, nil
	})
	return err
}

func (s *AccountFolderSpace) ListItems(ctx context.Context, access AccessContext, folderID string, query ItemQuery) ([]model.Item, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return nil, err
	}
	items, err := withAccount(ctx, s, login, func(space *FolderSpaceService) ([]model.Item, error) {
		return space.ListItems(ctx, access, folderID, query)
	})
	return items, err
}

func (s *AccountFolderSpace) ListItemPage(ctx context.Context, access AccessContext, folderID string, query ItemPageQuery) (ItemPage, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return ItemPage{}, err
	}
	return withAccount(ctx, s, login, func(space *FolderSpaceService) (ItemPage, error) {
		return space.ListItemPage(ctx, access, folderID, query)
	})
}

func (s *AccountFolderSpace) GetItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	location, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	return withAccount(ctx, s, location.Login, func(space *FolderSpaceService) (model.Item, error) {
		return space.GetItem(ctx, access, itemID)
	})
}

func (s *AccountFolderSpace) GetItemByUID(ctx context.Context, access AccessContext, folderID string, uid uint32) (model.Item, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Item{}, err
	}
	item, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Item, error) {
		return space.GetItemByUID(ctx, access, folderID, uid)
	})
	return item, err
}

func (s *AccountFolderSpace) GetItemByName(ctx context.Context, access AccessContext, folderID, name string) (model.Item, error) {
	return s.itemFromFolder(ctx, access, folderID, func(space *FolderSpaceService) (model.Item, error) {
		return space.GetItemByName(ctx, access, folderID, name)
	})
}

func (s *AccountFolderSpace) GetItemByExternalID(ctx context.Context, access AccessContext, folderID, namespace, externalID string) (model.Item, error) {
	item, err := s.itemFromFolder(ctx, access, folderID, func(space *FolderSpaceService) (model.Item, error) {
		return space.GetItemByExternalID(ctx, access, folderID, namespace, externalID)
	})
	if err == nil {
		if login, ownerErr := s.folderOwner(ctx, folderID); ownerErr == nil {
			err = s.setItemLocation(ctx, item.ID, login, folderID)
		}
	}
	return item, err
}

func (s *AccountFolderSpace) GetItemMetadataByExternalID(ctx context.Context, access AccessContext, folderID, namespace, externalID string) (model.Item, error) {
	return s.itemFromFolder(ctx, access, folderID, func(space *FolderSpaceService) (model.Item, error) {
		return space.GetItemMetadataByExternalID(ctx, access, folderID, namespace, externalID)
	})
}

func (s *AccountFolderSpace) itemFromFolder(ctx context.Context, access AccessContext, folderID string, fn func(*FolderSpaceService) (model.Item, error)) (model.Item, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Item{}, err
	}
	item, err := withAccount(ctx, s, login, fn)
	return item, err
}

func (s *AccountFolderSpace) CreateItem(ctx context.Context, access AccessContext, folderID string, input ItemInput) (model.Item, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Item{}, err
	}
	item, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Item, error) {
		return space.CreateItem(ctx, access, folderID, input)
	})
	if err != nil {
		return model.Item{}, err
	}
	return item, s.setItemLocation(ctx, item.ID, login, item.FolderID)
}

func (s *AccountFolderSpace) CreateItems(ctx context.Context, access AccessContext, folderID string, inputs []ItemInput) ([]model.Item, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return nil, err
	}
	items, err := withAccount(ctx, s, login, func(space *FolderSpaceService) ([]model.Item, error) {
		return space.CreateItems(ctx, access, folderID, inputs)
	})
	if err != nil {
		return nil, err
	}
	err = store.Batch(ctx, s.system.Store(), func(batchCtx context.Context) error {
		for _, item := range items {
			if err := s.setItemLocation(batchCtx, item.ID, login, item.FolderID); err != nil {
				return err
			}
		}
		return nil
	})
	return items, err
}

func (s *AccountFolderSpace) CreateItemIfAbsent(ctx context.Context, access AccessContext, folderID string, input ItemInput) (model.Item, error) {
	login, err := s.folderOwner(ctx, folderID)
	if err != nil {
		return model.Item{}, err
	}
	item, err := withAccount(ctx, s, login, func(space *FolderSpaceService) (model.Item, error) {
		return space.CreateItemIfAbsent(ctx, access, folderID, input)
	})
	if err != nil {
		return model.Item{}, err
	}
	return item, s.setItemLocation(ctx, item.ID, login, item.FolderID)
}

func (s *AccountFolderSpace) BindItemExternalID(ctx context.Context, access AccessContext, itemID, namespace, externalID string) (model.Item, error) {
	location, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	return withAccount(ctx, s, location.Login, func(space *FolderSpaceService) (model.Item, error) {
		return space.BindItemExternalID(ctx, access, itemID, namespace, externalID)
	})
}

func (s *AccountFolderSpace) UpdateItem(ctx context.Context, access AccessContext, itemID string, data []byte, headers map[string]string) (model.Item, error) {
	location, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	return withAccount(ctx, s, location.Login, func(space *FolderSpaceService) (model.Item, error) {
		return space.UpdateItem(ctx, access, itemID, data, headers)
	})
}

func (s *AccountFolderSpace) UpdateItemIfModSeq(ctx context.Context, access AccessContext, itemID string, expected uint64, data []byte, headers map[string]string) (model.Item, error) {
	location, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	return withAccount(ctx, s, location.Login, func(space *FolderSpaceService) (model.Item, error) {
		return space.UpdateItemIfModSeq(ctx, access, itemID, expected, data, headers)
	})
}

func (s *AccountFolderSpace) SetFlags(ctx context.Context, access AccessContext, itemID string, flags []string) (model.Item, error) {
	location, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	return withAccount(ctx, s, location.Login, func(space *FolderSpaceService) (model.Item, error) {
		return space.SetFlags(ctx, access, itemID, flags)
	})
}

func (s *AccountFolderSpace) MoveItem(ctx context.Context, access AccessContext, itemID, destinationFolderID, name string) (model.Item, error) {
	return s.copyOrMoveItem(ctx, access, itemID, destinationFolderID, name, true)
}

func (s *AccountFolderSpace) CopyItem(ctx context.Context, access AccessContext, itemID, destinationFolderID, name string) (model.Item, error) {
	return s.copyOrMoveItem(ctx, access, itemID, destinationFolderID, name, false)
}

func (s *AccountFolderSpace) copyOrMoveItem(ctx context.Context, access AccessContext, itemID, destinationFolderID, name string, move bool) (model.Item, error) {
	source, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return model.Item{}, err
	}
	destinationLogin, err := s.folderOwner(ctx, destinationFolderID)
	if err != nil {
		return model.Item{}, err
	}
	if source.Login == destinationLogin {
		item, err := withAccount(ctx, s, source.Login, func(space *FolderSpaceService) (model.Item, error) {
			if move {
				return space.MoveItem(ctx, access, itemID, destinationFolderID, name)
			}
			return space.CopyItem(ctx, access, itemID, destinationFolderID, name)
		})
		if err == nil {
			err = s.setItemLocation(ctx, item.ID, destinationLogin, destinationFolderID)
		}
		return item, err
	}
	item, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	created, err := s.CreateItem(ctx, access, destinationFolderID, ItemInput{
		Name: name, Data: item.Data, Headers: item.Headers, ExternalIDs: item.ExternalIDs,
		Flags: slices.Clone(item.Flags), InternalDate: item.InternalDate,
	})
	if err != nil {
		return model.Item{}, err
	}
	if move {
		if err := s.DeleteItem(ctx, access, itemID); err != nil {
			_ = s.DeleteItem(ctx, access, created.ID)
			return model.Item{}, err
		}
	}
	return created, nil
}

func (s *AccountFolderSpace) DeleteItem(ctx context.Context, access AccessContext, itemID string) error {
	location, err := s.itemLocation(ctx, itemID)
	if err != nil {
		return err
	}
	type deletion struct {
		preserved map[string]string
		held      []model.Folder
	}
	result, err := withAccount(ctx, s, location.Login, func(space *FolderSpaceService) (deletion, error) {
		if err := space.DeleteItem(ctx, access, itemID); err != nil {
			return deletion{}, err
		}
		preserved, held, err := space.preservedLocations(ctx, []string{itemID})
		return deletion{preserved: preserved, held: held}, err
	})
	if err != nil {
		return err
	}
	if len(result.preserved) > 0 {
		return s.recordPreserved(ctx, location.Login, result.preserved, result.held)
	}
	if err := s.system.Delete(ctx, accountItemLocationsNamespace, itemID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// recordPreserved keeps items preserved by legal hold addressable: their
// held-deleted folders join the system catalog and their locations follow
// them, so compliance access resolves them like any other item.
func (s *AccountFolderSpace) recordPreserved(ctx context.Context, login string, preserved map[string]string, held []model.Folder) error {
	for _, folder := range held {
		if err := s.mirrorFolder(ctx, folder); err != nil {
			return err
		}
	}
	for itemID, folderID := range preserved {
		if err := s.setItemLocation(ctx, itemID, login, folderID); err != nil {
			return err
		}
	}
	return nil
}

func (s *AccountFolderSpace) folderOwner(ctx context.Context, folderID string) (string, error) {
	folder, err := s.system.FolderStore().Get(ctx, folderID)
	if err != nil {
		return "", err
	}
	return folder.UserID, nil
}

func (s *AccountFolderSpace) mirrorFolder(ctx context.Context, folder model.Folder) error {
	return s.system.Set(ctx, model.NSFolders, folder.ID, folder)
}

func (s *AccountFolderSpace) setItemLocation(ctx context.Context, itemID, login, folderID string) error {
	return s.system.Set(ctx, accountItemLocationsNamespace, itemID, accountItemLocation{Login: login, FolderID: folderID})
}

func (s *AccountFolderSpace) itemLocation(ctx context.Context, itemID string) (accountItemLocation, error) {
	var location accountItemLocation
	if err := s.system.Get(ctx, accountItemLocationsNamespace, itemID, &location); err != nil {
		return location, err
	}
	if location.Login == "" || location.FolderID == "" {
		return accountItemLocation{}, store.ErrNotFound
	}
	return location, nil
}
