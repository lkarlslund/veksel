package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	SpecialUseInbox            = "inbox"
	SpecialUseDrafts           = "drafts"
	SpecialUseSent             = "sent"
	SpecialUseTrash            = "trash"
	SpecialUseJunk             = "junk"
	SpecialUseArchive          = "archive"
	SpecialUseCalendar         = "calendar"
	SpecialUseContacts         = "contacts"
	SpecialUseRecentRecipients = "recent-recipients"
	SpecialUseFiles            = "files"
	SpecialUseSieve            = "sieve"
	SpecialUseScheduleInbox    = "schedule-inbox"
	SpecialUseScheduleOutbox   = "schedule-outbox"
	SpecialUseSavedSearch      = "saved-search"
	SpecialUseMailTemplate     = "mail-template"
)

// defaultFolders defines the folders created automatically for each new user.
var defaultFolders = []struct {
	Path       string
	Type       FolderType
	Sub        bool
	SpecialUse string
}{
	{"INBOX", FolderTypeMail, true, SpecialUseInbox},
	{"Drafts", FolderTypeMail, true, SpecialUseDrafts},
	{"Sent", FolderTypeMail, true, SpecialUseSent},
	{"Trash", FolderTypeMail, true, SpecialUseTrash},
	{"Junk", FolderTypeMail, true, SpecialUseJunk},
	{"Archive", FolderTypeMail, true, SpecialUseArchive},
	{"Calendar", FolderTypeCalendar, false, SpecialUseCalendar},
	{"Contacts", FolderTypeContacts, false, SpecialUseContacts},
	{"Recent recipients", FolderTypeContacts, false, SpecialUseRecentRecipients},
	{"Files", FolderTypeFiles, false, SpecialUseFiles},
	{"Sieve scripts", FolderTypeSieve, false, SpecialUseSieve},
	{"schedule-inbox", FolderTypeScheduleInbox, false, SpecialUseScheduleInbox},
	{"schedule-outbox", FolderTypeScheduleOutbox, false, SpecialUseScheduleOutbox},
	{FolderPathSavedSearch, FolderTypeSavedSearch, false, SpecialUseSavedSearch},
	{FolderPathMailTemplate, FolderTypeMailTemplate, false, SpecialUseMailTemplate},
}

const (
	FolderPathSavedSearch  = "Saved searches"
	FolderPathMailTemplate = "Message templates"
)

// FolderStore provides typed CRUD for Folder entities.
type FolderStore struct {
	ts      *TypedStore
	mu      sync.Mutex
	indexMu sync.Mutex
	indexNS atomic.Bool
}

// NewFolderStore returns a FolderStore backed by ts.
func NewFolderStore(ts *TypedStore) *FolderStore {
	return &FolderStore{ts: ts}
}

// CreateForUser creates the default folder set for a new user.
func (fs *FolderStore) CreateForUser(ctx context.Context, userID string) error {
	userID = normalizeID(userID)
	if err := fs.prepareNewUserIndexes(ctx, userID); err != nil {
		return err
	}
	for _, df := range defaultFolders {
		if err := fs.create(ctx, userID, df.Path, df.Type, "", true, df.SpecialUse, df.Sub); err != nil {
			return fmt.Errorf("create default folder %q: %w", df.Path, err)
		}
	}
	return nil
}

// prepareNewUserIndexes avoids treating a genuinely new account as a legacy
// migration. INBOX has a deterministic ID and is the first default created,
// so its presence distinguishes an existing or partially initialized account;
// those accounts take the safe backfill path instead.
func (fs *FolderStore) prepareNewUserIndexes(ctx context.Context, userID string) error {
	if err := fs.ensureIndexNamespace(ctx); err != nil {
		return err
	}
	var version int
	err := fs.ts.Get(ctx, NSFolderIndexes, FolderIndexMarkerKey(userID), &version)
	if ready, err := folderIndexReady(version, err); err != nil {
		return err
	} else if ready {
		return nil
	}
	if _, err := fs.Get(ctx, InboxFolderID(userID)); err == nil {
		return fs.ensureUserIndexes(ctx, userID)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return fs.ts.Set(ctx, NSFolderIndexes, FolderIndexMarkerKey(userID), FolderIndexVersion)
}

// EnsureForUser creates any missing default folders for userID. It is used by
// crash-safe account bootstrap and is otherwise equivalent to CreateForUser.
func (fs *FolderStore) EnsureForUser(ctx context.Context, userID string) error {
	userID = normalizeID(userID)
	for _, df := range defaultFolders {
		if _, err := fs.GetByPath(ctx, userID, df.Path); err == nil {
			continue
		}
		if err := fs.create(ctx, userID, df.Path, df.Type, "", true, df.SpecialUse, df.Sub); err != nil {
			return fmt.Errorf("ensure default folder %q: %w", df.Path, err)
		}
	}
	return nil
}

// Create stores a new folder.
func (fs *FolderStore) Create(ctx context.Context, userID, path string, ft FolderType, parentID string) error {
	reservedPath, specialUse := "", ""
	switch ft {
	case FolderTypeSavedSearch:
		reservedPath, specialUse = FolderPathSavedSearch, SpecialUseSavedSearch
	case FolderTypeMailTemplate:
		reservedPath, specialUse = FolderPathMailTemplate, SpecialUseMailTemplate
	}
	if reservedPath != "" {
		if strings.Trim(path, "/") != reservedPath || parentID != "" {
			return fmt.Errorf("%s folders use the reserved top-level path %q", ft, reservedPath)
		}
		return fs.create(ctx, userID, reservedPath, ft, "", true, specialUse, false)
	}
	return fs.create(ctx, userID, path, ft, parentID, false, "", true)
}

func (fs *FolderStore) create(ctx context.Context, userID, path string, ft FolderType, parentID string, system bool, specialUse string, subscribed bool) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	userID = normalizeID(userID)
	path = strings.Trim(path, "/")
	if path == "" {
		return fmt.Errorf("empty folder path")
	}
	if _, err := fs.GetByPath(ctx, userID, path); err == nil {
		return store.ErrExists
	} else if err != store.ErrNotFound {
		return err
	}
	if parentID != "" {
		parent, err := fs.Get(ctx, parentID)
		if err != nil {
			return fmt.Errorf("get parent: %w", err)
		}
		if parent.UserID != userID || parent.Type != ft || !parent.TrashedAt.IsZero() {
			return fmt.Errorf("invalid parent folder")
		}
	}

	name := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		name = path[idx+1:]
	}

	now := time.Now().UTC()
	id := ""
	if system && specialUse != "" {
		id = specialFolderID(userID, specialUse)
	} else {
		var err error
		id, err = newResourceID("fld")
		if err != nil {
			return err
		}
	}
	f := Folder{
		ID:                  id,
		UserID:              userID,
		Name:                name,
		Path:                path,
		ParentID:            parentID,
		Type:                ft,
		Delimiter:           "/",
		Subscribed:          subscribed,
		System:              system,
		SpecialUse:          specialUse,
		Indexes:             DefaultFolderIndexes(ft),
		UIDValidity:         uint32(now.Unix()),
		NextUID:             0,
		UsageVersion:        1,
		HistoryUsageVersion: 1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	return store.Batch(ctx, fs.ts.Store(), func(batchCtx context.Context) error {
		if err := fs.ts.Put(batchCtx, NSFolders, f.ID, f); err != nil {
			return err
		}
		if err := fs.writeIndexes(batchCtx, nil, &f); err != nil {
			_ = fs.ts.Delete(batchCtx, NSFolders, f.ID)
			_ = fs.writeIndexes(batchCtx, &f, nil)
			return err
		}
		return nil
	})
}

// Get returns a folder by its store key.
func (fs *FolderStore) Get(ctx context.Context, id string) (Folder, error) {
	var f Folder
	if err := fs.ts.Get(ctx, NSFolders, id, &f); err != nil {
		// Legacy path-shaped IDs are accepted at call boundaries during the
		// schema-v2 refactor, but are never persisted as resource identities.
		if parts := strings.SplitN(id, ":", 2); len(parts) == 2 {
			return fs.GetByPath(ctx, parts[0], parts[1])
		}
		return f, err
	}
	return f.withLegacyDefaultIndexes(), nil
}

// GetByPath returns a folder by userID and path.
func (fs *FolderStore) GetByPath(ctx context.Context, userID, path string) (Folder, error) {
	userID = normalizeID(userID)
	path = strings.Trim(path, "/")
	if store.InView(ctx, fs.ts.Store()) {
		var version int
		err := fs.ts.Get(ctx, NSFolderIndexes, FolderIndexMarkerKey(userID), &version)
		ready, err := folderIndexReady(version, err)
		if err != nil {
			return Folder{}, err
		}
		if !ready {
			return fs.getByPathScan(ctx, userID, path)
		}
	}
	if err := fs.ensureUserIndexes(ctx, userID); err != nil {
		return Folder{}, err
	}
	var id string
	if err := fs.ts.Get(ctx, NSFolderIndexes, FolderPathIndexKey(userID, path), &id); err != nil {
		return Folder{}, err
	}
	folder, err := fs.Get(ctx, id)
	if err != nil {
		return Folder{}, err
	}
	if folder.UserID != userID || folder.Path != path || !folder.TrashedAt.IsZero() {
		return Folder{}, store.ErrNotFound
	}
	return folder, nil
}

// getByPathScan is the read-only compatibility path for a legacy path-shaped
// ID encountered inside an existing store view. A view cannot be upgraded to
// a write batch without deadlocking stores that use reader/writer locks; the
// next ordinary access performs the durable lazy backfill.
func (fs *FolderStore) getByPathScan(ctx context.Context, userID, path string) (Folder, error) {
	folders, err := fs.ListAll(ctx)
	if err != nil {
		return Folder{}, err
	}
	for _, folder := range folders {
		if folder.UserID == userID && folder.Path == path && folder.TrashedAt.IsZero() {
			return folder, nil
		}
	}
	return Folder{}, store.ErrNotFound
}

// ensureUserIndexes lazily upgrades legacy stores. The marker is written last
// in the same backend batch, so an interrupted rebuild is safely retried.
func (fs *FolderStore) ensureUserIndexes(ctx context.Context, userID string) error {
	userID = normalizeID(userID)
	if err := fs.ensureIndexNamespace(ctx); err != nil {
		return err
	}
	var version int
	err := fs.ts.Get(ctx, NSFolderIndexes, FolderIndexMarkerKey(userID), &version)
	if ready, err := folderIndexReady(version, err); err != nil {
		return err
	} else if ready {
		return nil
	}

	fs.indexMu.Lock()
	defer fs.indexMu.Unlock()
	err = fs.ts.Get(ctx, NSFolderIndexes, FolderIndexMarkerKey(userID), &version)
	if ready, err := folderIndexReady(version, err); err != nil {
		return err
	} else if ready {
		return nil
	}
	all, err := fs.ListAll(ctx)
	if err != nil {
		return err
	}
	return store.Batch(ctx, fs.ts.Store(), func(batchCtx context.Context) error {
		for i := range all {
			if all[i].UserID != userID {
				continue
			}
			if err := fs.writeIndexes(batchCtx, nil, &all[i]); err != nil {
				return err
			}
		}
		return fs.ts.Set(batchCtx, NSFolderIndexes, FolderIndexMarkerKey(userID), FolderIndexVersion)
	})
}

func folderIndexReady(version int, err error) (bool, error) {
	if err == nil {
		if version > FolderIndexVersion {
			return false, fmt.Errorf("folder index version %d is newer than supported version %d", version, FolderIndexVersion)
		}
		return version == FolderIndexVersion, nil
	}
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return false, err
}

func (fs *FolderStore) ensureIndexNamespace(ctx context.Context) error {
	if fs.indexNS.Load() {
		return nil
	}
	fs.indexMu.Lock()
	defer fs.indexMu.Unlock()
	if fs.indexNS.Load() {
		return nil
	}
	if err := fs.ts.EnsureNamespace(ctx, NSFolderIndexes); err != nil {
		return err
	}
	fs.indexNS.Store(true)
	return nil
}

func (fs *FolderStore) writeIndexes(ctx context.Context, before, after *Folder) error {
	if before != nil {
		if after == nil || before.UserID != after.UserID {
			if err := deleteIfPresent(ctx, fs.ts, NSFolderIndexes, FolderUserIndexKey(before.UserID, before.ID)); err != nil {
				return err
			}
		}
		if before.TrashedAt.IsZero() && (after == nil || !after.TrashedAt.IsZero() || before.UserID != after.UserID || before.Path != after.Path) {
			if err := deleteIfPresent(ctx, fs.ts, NSFolderIndexes, FolderPathIndexKey(before.UserID, before.Path)); err != nil {
				return err
			}
		}
	}
	if after == nil {
		return nil
	}
	if err := fs.ts.Set(ctx, NSFolderIndexes, FolderUserIndexKey(after.UserID, after.ID), after.ID); err != nil {
		return err
	}
	if after.TrashedAt.IsZero() {
		if err := fs.ts.Set(ctx, NSFolderIndexes, FolderPathIndexKey(after.UserID, after.Path), after.ID); err != nil {
			return err
		}
	}
	return nil
}

func deleteIfPresent(ctx context.Context, ts *TypedStore, namespace, key string) error {
	err := ts.Delete(ctx, namespace, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

func (fs *FolderStore) setFolder(ctx context.Context, before, after Folder) error {
	if err := fs.ts.Set(ctx, NSFolders, after.ID, after); err != nil {
		return err
	}
	return fs.writeIndexes(ctx, &before, &after)
}

type folderMutation struct {
	before Folder
	after  Folder
}

func (fs *FolderStore) applyFolderMutations(ctx context.Context, mutations []folderMutation) error {
	return store.Batch(ctx, fs.ts.Store(), func(batchCtx context.Context) error {
		written := make([]folderMutation, 0, len(mutations))
		for _, mutation := range mutations {
			if err := fs.setFolder(batchCtx, mutation.before, mutation.after); err != nil {
				_ = fs.setFolder(batchCtx, mutation.after, mutation.before)
				for i := len(written) - 1; i >= 0; i-- {
					_ = fs.setFolder(batchCtx, written[i].after, written[i].before)
				}
				return err
			}
			written = append(written, mutation)
		}
		return nil
	})
}

// ListForUser returns all folders for a user.
func (fs *FolderStore) ListForUser(ctx context.Context, userID string) ([]Folder, error) {
	folders, err := fs.listForUser(ctx, userID, false)
	if err != nil {
		return nil, err
	}
	sort.Slice(folders, func(i, j int) bool { return folders[i].Path < folders[j].Path })
	return folders, nil
}

func (fs *FolderStore) ListTrashedForUser(ctx context.Context, userID string) ([]Folder, error) {
	folders, err := fs.listForUser(ctx, userID, true)
	if err != nil {
		return nil, err
	}
	sort.Slice(folders, func(i, j int) bool { return folders[i].OriginalPath < folders[j].OriginalPath })
	return folders, nil
}

func (fs *FolderStore) listForUser(ctx context.Context, userID string, trashed bool) ([]Folder, error) {
	userID = normalizeID(userID)
	if err := fs.ensureUserIndexes(ctx, userID); err != nil {
		return nil, err
	}
	var folders []Folder
	prefix := FolderUserIndexPrefix(userID)
	err := store.View(ctx, fs.ts.Store(), func(viewCtx context.Context) error {
		keys, err := fs.ts.Scan(viewCtx, NSFolderIndexes, prefix)
		if err != nil {
			return err
		}
		folders = make([]Folder, 0, len(keys))
		for _, key := range keys {
			id := strings.TrimPrefix(key, prefix)
			folder, getErr := fs.Get(viewCtx, id)
			if getErr != nil {
				if errors.Is(getErr, store.ErrNotFound) {
					continue
				}
				return getErr
			}
			if folder.UserID == userID && (!folder.TrashedAt.IsZero()) == trashed {
				folders = append(folders, folder)
			}
		}
		return nil
	})
	return folders, err
}

// Delete removes a folder.
func (fs *FolderStore) Delete(ctx context.Context, id string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err := fs.ensureIndexNamespace(ctx); err != nil {
		return err
	}
	folder, err := fs.Get(ctx, id)
	if err != nil {
		return err
	}
	return store.Batch(ctx, fs.ts.Store(), func(batchCtx context.Context) error {
		if err := fs.ts.Delete(batchCtx, NSFolders, folder.ID); err != nil {
			return err
		}
		if err := fs.writeIndexes(batchCtx, &folder, nil); err != nil {
			_ = fs.ts.Set(batchCtx, NSFolders, folder.ID, folder)
			_ = fs.writeIndexes(batchCtx, nil, &folder)
			return err
		}
		return nil
	})
}

// Trash marks a custom folder and its descendants for recoverable deletion.
// Stable IDs and parent links are retained so restoration is lossless.
func (fs *FolderStore) Trash(ctx context.Context, id string, retention time.Duration) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	folder, err := fs.Get(ctx, id)
	if err != nil {
		return err
	}
	if folder.System {
		return fmt.Errorf("system folders cannot be deleted")
	}
	if !folder.TrashedAt.IsZero() {
		return nil
	}
	all, err := fs.ListForUser(ctx, folder.UserID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	mutations := make([]folderMutation, 0)
	for _, candidate := range all {
		if candidate.ID != folder.ID && !strings.HasPrefix(candidate.Path, folder.Path+"/") {
			continue
		}
		before := candidate
		candidate.OriginalPath = candidate.Path
		candidate.OriginalParentID = candidate.ParentID
		candidate.TrashedAt = now
		if retention > 0 {
			candidate.PurgeAfter = now.Add(retention)
		}
		candidate.UpdatedAt = now
		mutations = append(mutations, folderMutation{before: before, after: candidate})
	}
	return fs.applyFolderMutations(ctx, mutations)
}

// Restore makes a recoverably deleted folder tree active again.
func (fs *FolderStore) Restore(ctx context.Context, id string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	folder, err := fs.Get(ctx, id)
	if err != nil {
		return err
	}
	if folder.TrashedAt.IsZero() || folder.OriginalPath == "" {
		return fmt.Errorf("folder is not recoverably deleted")
	}
	all, err := fs.listForUser(ctx, folder.UserID, true)
	if err != nil {
		return err
	}
	active, err := fs.ListForUser(ctx, folder.UserID)
	if err != nil {
		return err
	}
	for _, candidate := range active {
		if candidate.Path == folder.OriginalPath || strings.HasPrefix(candidate.Path, folder.OriginalPath+"/") {
			return store.ErrExists
		}
	}
	now := time.Now().UTC()
	mutations := make([]folderMutation, 0)
	for _, candidate := range all {
		if candidate.ID != folder.ID && !strings.HasPrefix(candidate.OriginalPath, folder.OriginalPath+"/") {
			continue
		}
		before := candidate
		candidate.Path = candidate.OriginalPath
		candidate.ParentID = candidate.OriginalParentID
		candidate.OriginalPath = ""
		candidate.OriginalParentID = ""
		candidate.TrashedAt = time.Time{}
		candidate.PurgeAfter = time.Time{}
		candidate.UpdatedAt = now
		mutations = append(mutations, folderMutation{before: before, after: candidate})
	}
	return fs.applyFolderMutations(ctx, mutations)
}

// Update applies a mutation function to an existing folder.
func (fs *FolderStore) Update(ctx context.Context, id string, mut func(*Folder)) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err := fs.ensureIndexNamespace(ctx); err != nil {
		return err
	}
	f, err := fs.Get(ctx, id)
	if err != nil {
		return err
	}
	before := f
	mut(&f)
	f.UpdatedAt = time.Now().UTC()
	return fs.applyFolderMutations(ctx, []folderMutation{{before: before, after: f}})
}

// SetDefault assigns the protocol-visible default role for a typed folder.
// The role is unique per account and changed atomically with rollback on
// stores whose Batch implementation cannot provide native transactions.
func (fs *FolderStore) SetDefault(ctx context.Context, userID string, folderType FolderType, folderID string) ([]Folder, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	specialUse := ""
	switch folderType {
	case FolderTypeCalendar:
		specialUse = SpecialUseCalendar
	default:
		return nil, fmt.Errorf("folder type %q has no default role", folderType)
	}
	target, err := fs.Get(ctx, folderID)
	if err != nil {
		return nil, err
	}
	userID = normalizeID(userID)
	if target.UserID != userID || target.Type != folderType || !target.TrashedAt.IsZero() {
		return nil, fmt.Errorf("invalid default folder")
	}
	all, err := fs.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	before := make(map[string]Folder)
	changed := make([]Folder, 0, 2)
	for _, folder := range all {
		if folder.UserID != userID || folder.Type != folderType || !folder.TrashedAt.IsZero() {
			continue
		}
		newRole := folder.SpecialUse
		if folder.SpecialUse == specialUse {
			newRole = ""
		}
		if folder.ID == target.ID {
			newRole = specialUse
		}
		if folder.SpecialUse == newRole {
			continue
		}
		before[folder.ID] = folder
		folder.SpecialUse = newRole
		folder.UpdatedAt = now
		changed = append(changed, folder)
	}
	if len(changed) == 0 {
		return []Folder{target}, nil
	}
	written := make([]string, 0, len(changed))
	for _, folder := range changed {
		if err := fs.ts.Set(ctx, NSFolders, folder.ID, folder); err != nil {
			for _, id := range written {
				_ = fs.ts.Set(ctx, NSFolders, id, before[id])
			}
			return nil, fmt.Errorf("set default folder: %w", err)
		}
		written = append(written, folder.ID)
	}
	return changed, nil
}

// Move renames and/or reparents a folder without changing its identity. Every
// descendant retains its identity and parent link; only protocol-facing paths
// are rewritten.
func (fs *FolderStore) Move(ctx context.Context, id, parentID, name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	folder, err := fs.Get(ctx, id)
	if err != nil {
		return err
	}
	if folder.System || !folder.TrashedAt.IsZero() {
		return fmt.Errorf("system or trashed folders cannot be moved")
	}
	name = strings.TrimSpace(strings.Trim(name, "/"))
	if name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("folder name must be a single non-empty path segment")
	}
	parentPath := ""
	if parentID != "" {
		parent, getErr := fs.Get(ctx, parentID)
		if getErr != nil {
			return fmt.Errorf("get destination parent: %w", getErr)
		}
		if parent.UserID != folder.UserID || parent.Type != folder.Type || !parent.TrashedAt.IsZero() {
			return fmt.Errorf("invalid destination parent")
		}
		if parent.ID == folder.ID || strings.HasPrefix(parent.Path+"/", folder.Path+"/") {
			return fmt.Errorf("cannot move a folder into itself or a descendant")
		}
		parentPath = parent.Path
	}
	newPath := name
	if parentPath != "" {
		newPath = parentPath + "/" + name
	}
	if existing, lookupErr := fs.GetByPath(ctx, folder.UserID, newPath); lookupErr == nil && existing.ID != id {
		return store.ErrExists
	} else if lookupErr != nil && lookupErr != store.ErrNotFound {
		return lookupErr
	}
	if newPath == folder.Path && parentID == folder.ParentID {
		return nil
	}

	all, err := fs.ListForUser(ctx, folder.UserID)
	if err != nil {
		return err
	}
	oldPath := folder.Path
	mutations := make([]folderMutation, 0)
	for _, candidate := range all {
		if candidate.ID != id && !strings.HasPrefix(candidate.Path, oldPath+"/") {
			continue
		}
		before := candidate
		if candidate.ID == id {
			candidate.Name = name
			candidate.ParentID = parentID
			candidate.Path = newPath
		} else {
			candidate.Path = newPath + strings.TrimPrefix(candidate.Path, oldPath)
		}
		candidate.UpdatedAt = time.Now().UTC()
		mutations = append(mutations, folderMutation{before: before, after: candidate})
	}
	sort.Slice(mutations, func(i, j int) bool { return len(mutations[i].after.Path) < len(mutations[j].after.Path) })
	if err := fs.applyFolderMutations(ctx, mutations); err != nil {
		return fmt.Errorf("move folder: %w", err)
	}
	return nil
}

// SpecialFolder returns the active folder assigned to specialUse for userID.
func (fs *FolderStore) SpecialFolder(ctx context.Context, userID, specialUse string) (Folder, error) {
	folders, err := fs.ListForUser(ctx, userID)
	if err != nil {
		return Folder{}, err
	}
	for _, folder := range folders {
		if folder.SpecialUse == specialUse {
			return folder, nil
		}
	}
	return Folder{}, store.ErrNotFound
}

// InboxFolderID returns the immutable ID of a user's system Inbox.
func InboxFolderID(userID string) string { return specialFolderID(userID, SpecialUseInbox) }

// SentFolderID returns the immutable ID of a user's system Sent folder.
func SentFolderID(userID string) string { return specialFolderID(userID, SpecialUseSent) }

// JunkFolderID returns the immutable ID of a user's system Junk folder.
func JunkFolderID(userID string) string { return specialFolderID(userID, SpecialUseJunk) }

// RecentRecipientsFolderID returns the immutable ID of a user's recipient
// history address book.
func RecentRecipientsFolderID(userID string) string {
	return specialFolderID(userID, SpecialUseRecentRecipients)
}

// ListAll returns all folders across all users.
func (fs *FolderStore) ListAll(ctx context.Context) ([]Folder, error) {
	var folders []Folder
	err := fs.ts.Store().Iterate(ctx, NSFolders, "", func(_ string, value []byte) (bool, error) {
		var folder Folder
		if err := json.Unmarshal(value, &folder); err != nil || folder.ID == "" {
			return true, nil
		}
		folders = append(folders, folder.withLegacyDefaultIndexes())
		return true, nil
	})
	return folders, err
}

// SetACL stores an ACL entry for a folder.
func (fs *FolderStore) SetACL(ctx context.Context, folderID, username, rights string) error {
	if err := ValidateACLRights(rights); err != nil {
		return err
	}
	e := ACLEntry{
		Username: normalizeID(username),
		Rights:   NormalizeACLRights(rights),
	}
	return fs.ts.Set(ctx, NSACL, ACLKey(folderID, e.Username), e)
}

// GetACL returns a single ACL entry for a folder and username.
func (fs *FolderStore) GetACL(ctx context.Context, folderID, username string) (ACLEntry, error) {
	var e ACLEntry
	if err := fs.ts.Get(ctx, NSACL, ACLKey(folderID, normalizeID(username)), &e); err != nil {
		return e, err
	}
	return e, nil
}

// ListACL returns all ACL entries for a folder.
func (fs *FolderStore) ListACL(ctx context.Context, folderID string) ([]ACLEntry, error) {
	keys, err := fs.ts.Scan(ctx, NSACL, ACLPrefix(folderID))
	if err != nil {
		return nil, err
	}
	var entries []ACLEntry
	for _, k := range keys {
		var e ACLEntry
		if err := fs.ts.Get(ctx, NSACL, k, &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// DeleteACL removes an ACL entry for a folder and username.
func (fs *FolderStore) DeleteACL(ctx context.Context, folderID, username string) error {
	return fs.ts.Delete(ctx, NSACL, ACLKey(folderID, normalizeID(username)))
}

// HasRight checks if the given username has the specified right on the folder.
func (fs *FolderStore) HasRight(ctx context.Context, folderID, username, right string) (bool, error) {
	e, err := fs.GetACL(ctx, folderID, username)
	if err != nil {
		return false, err
	}
	return HasACLRights(e.Rights, right), nil
}

// GetUserRights returns the rights string for a user on a folder.
func (fs *FolderStore) GetUserRights(ctx context.Context, folderID, username string) (string, error) {
	e, err := fs.GetACL(ctx, folderID, username)
	if err != nil {
		return "", err
	}
	return e.Rights, nil
}

// ListACLForUser returns all ACL entries where the given username is the grantee.
// Returns a map of folderID -> ACLEntry.
func (fs *FolderStore) ListACLForUser(ctx context.Context, username string) (map[string]ACLEntry, error) {
	keys, err := fs.ts.Scan(ctx, NSACL, "")
	if err != nil {
		return nil, err
	}
	result := make(map[string]ACLEntry)
	username = normalizeID(username)
	for _, k := range keys {
		var e ACLEntry
		if err := fs.ts.Get(ctx, NSACL, k, &e); err != nil {
			continue
		}
		if e.Username == username {
			// Extract folderID from key (format: "folderID:username")
			// folderID itself contains a colon (e.g. "alice:INBOX"), so split from the right
			idx := strings.LastIndex(k, ":")
			if idx > 0 {
				folderID := k[:idx]
				result[folderID] = e
			}
		}
	}
	return result, nil
}

// SetCalendarSharing grants a CalDAV sharing role to a user on a calendar folder.
// role should be ShareOwner, ShareWriter, or ShareReader.
func (fs *FolderStore) SetCalendarSharing(ctx context.Context, folderID, username, role string) error {
	rights := ShareRoleToRights(role)
	return fs.SetACL(ctx, folderID, username, rights)
}

// GetCalendarSharing returns the sharing role for a user on a calendar folder.
// Returns "", ErrNotFound if no sharing entry exists.
func (fs *FolderStore) GetCalendarSharing(ctx context.Context, folderID, username string) (string, error) {
	e, err := fs.GetACL(ctx, folderID, username)
	if err != nil {
		return "", err
	}
	return ShareRightsToRole(e.Rights), nil
}

// ListCalendarSharing returns all sharees for a calendar folder.
func (fs *FolderStore) ListCalendarSharing(ctx context.Context, folderID string) ([]Sharee, error) {
	entries, err := fs.ListACL(ctx, folderID)
	if err != nil {
		return nil, err
	}
	sharees := make([]Sharee, 0, len(entries))
	for _, e := range entries {
		sharees = append(sharees, Sharee{
			UserID: e.Username,
			Role:   ShareRightsToRole(e.Rights),
		})
	}
	return sharees, nil
}

// DeleteCalendarSharing removes a sharing grant for a user on a calendar folder.
func (fs *FolderStore) DeleteCalendarSharing(ctx context.Context, folderID, username string) error {
	return fs.DeleteACL(ctx, folderID, username)
}

// GetShareInfo returns full sharing information for a calendar folder.
func (fs *FolderStore) GetShareInfo(ctx context.Context, folderID string) (ShareInfo, error) {
	folder, err := fs.Get(ctx, folderID)
	if err != nil {
		return ShareInfo{}, err
	}

	sharees, err := fs.ListCalendarSharing(ctx, folderID)
	if err != nil {
		return ShareInfo{}, err
	}

	return ShareInfo{
		OwnerID:  folder.UserID,
		FolderID: folderID,
		Sharees:  sharees,
	}, nil
}

// IsSharedCalendar checks if a calendar folder has any sharing grants.
func (fs *FolderStore) IsSharedCalendar(ctx context.Context, folderID string) (bool, error) {
	entries, err := fs.ListACL(ctx, folderID)
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}

// CanAccessCalendar checks if a user can access a calendar folder.
// The owner always has access. Shared users are checked via ACL.
func (fs *FolderStore) CanAccessCalendar(ctx context.Context, folderID, username string) (bool, error) {
	folder, err := fs.Get(ctx, folderID)
	if err != nil {
		return false, err
	}
	// Owner always has access
	if folder.UserID == normalizeID(username) {
		return true, nil
	}
	// Check ACL
	_, err = fs.GetACL(ctx, folderID, username)
	return err == nil, nil
}
