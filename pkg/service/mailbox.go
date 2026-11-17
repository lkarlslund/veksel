package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// AccessContext identifies the principal performing a folder-space operation
// and the account on whose behalf it is performed. Protocol adapters construct an
// AccessContext after authentication and never make authorization decisions
// themselves.
type AccessContext struct {
	Actor       model.PrincipalRef
	Subject     model.PrincipalRef
	Mode        authz.ActingMode
	Protocol    string
	Correlation string
}

// UserAccess constructs the normal access context for an authenticated user.
func UserAccess(userID, protocol string) AccessContext {
	principal := model.PrincipalRef{Kind: model.PrincipalUser, ID: userID}
	return AccessContext{Actor: principal, Subject: principal, Protocol: protocol}
}

// Validate rejects incomplete contexts before they reach authorization.
func (a AccessContext) Validate() error {
	if a.Actor.Kind == "" || a.Actor.ID == "" || a.Subject.Kind == "" || a.Subject.ID == "" {
		return errors.New("folder access requires actor and subject principals")
	}
	return nil
}

// FolderQuery controls protocol-neutral folder enumeration. IncludeTrashed
// includes every recoverable folder, including descendants hidden beneath a
// trashed root, so metadata accounting can cover the complete account.
type FolderQuery struct {
	Type           model.FolderType
	IncludeTrashed bool
}

// ItemQuery controls protocol-neutral item enumeration. Zero values request
// all current items in the folder.
type ItemQuery struct {
	Since        time.Time
	Before       time.Time
	Limit        int
	MetadataOnly bool
	// RequireRead authorizes a MetadataOnly listing as a content read
	// (FolderItemsRead), for callers that serve message data from it, such
	// as an IMAP session that reads payloads on demand.
	RequireRead bool
}

type ItemPageQuery struct {
	BeforeUID    uint32
	Cursor       string
	AnchorItemID string
	Order        ItemPageOrder
	Limit        int
	IncludeData  bool
}

type ItemPageOrder string

const (
	ItemPageOrderUIDDescending          ItemPageOrder = ""
	ItemPageOrderInternalDateDescending ItemPageOrder = "internal_date_desc"
)

type ItemPage struct {
	Items         []model.Item
	Total         int64
	NextBeforeUID uint32
	NextCursor    string
}

// UsageByType is one account-usage subtotal derived from folder metadata.
type UsageByType struct {
	Type                model.FolderType `json:"type"`
	Folders             int64            `json:"folders"`
	Items               int64            `json:"items"`
	LogicalBytes        int64            `json:"logical_bytes"`
	HistoryVersions     int64            `json:"history_versions"`
	HistoryLogicalBytes int64            `json:"history_logical_bytes"`
}

// AccountUsage is the complete metadata-only usage projection for one account.
// Recoverably deleted folders and items remain included until they are purged.
type AccountUsage struct {
	AccountID           string          `json:"account_id"`
	Quota               model.QuotaInfo `json:"quota"`
	Folders             int64           `json:"folders"`
	Items               int64           `json:"items"`
	LogicalBytes        int64           `json:"logical_bytes"`
	HistoryVersions     int64           `json:"history_versions"`
	HistoryLogicalBytes int64           `json:"history_logical_bytes"`
	AccountingReady     bool            `json:"accounting_ready"`
	ByType              []UsageByType   `json:"by_type"`
}

// ItemInput contains the storage-independent fields shared by mail,
// calendar, contact, file, EWS, EAS, DAV, and migration writers.
type ItemInput struct {
	Name         string
	Data         []byte
	Headers      map[string]string
	ExternalIDs  map[string]string
	Flags        []string
	InternalDate time.Time
}

// FolderUpdate contains protocol-neutral mutable collection properties.
type FolderUpdate struct {
	Subscribed *bool `json:"subscribed,omitempty"`
	Default    *bool `json:"default,omitempty"`
	// Collection presentation set by CalDAV/CardDAV PROPPATCH and
	// MKCALENDAR. Name changes the display name only; the path, and with
	// it every protocol URL, stays the same.
	Name        *string `json:"name,omitempty"`
	Color       *string `json:"color,omitempty"`
	Description *string `json:"description,omitempty"`
	Order       *int    `json:"order,omitempty"`
}

// collectionPresentation reports whether the update changes a collection's
// display name, color, description, or order.
func (u FolderUpdate) collectionPresentation() bool {
	return u.Name != nil || u.Color != nil || u.Description != nil || u.Order != nil
}

// validateCollectionPresentation checks presentation changes, which only
// calendars, task lists, and address books carry.
func validateCollectionPresentation(folder model.Folder, update FolderUpdate) error {
	if !update.collectionPresentation() {
		return nil
	}
	switch folder.Type {
	case model.FolderTypeCalendar, model.FolderTypeTasks, model.FolderTypeContacts:
	default:
		return fmt.Errorf("%w: only calendars, task lists, and address books have a display name, color, or order", ErrInvalidFolderUpdate)
	}
	if update.Name != nil {
		name := strings.TrimSpace(*update.Name)
		if name == "" || len(name) > 255 || strings.ContainsFunc(name, unicode.IsControl) {
			return fmt.Errorf("%w: display name must be 1 to 255 printable characters", ErrInvalidFolderUpdate)
		}
	}
	if update.Color != nil && *update.Color != "" && !collectionColor.MatchString(*update.Color) {
		return fmt.Errorf("%w: color must be #RRGGBB or #RRGGBBAA", ErrInvalidFolderUpdate)
	}
	if update.Description != nil && len(*update.Description) > 4096 {
		return fmt.Errorf("%w: description is limited to 4096 bytes", ErrInvalidFolderUpdate)
	}
	return nil
}

// ErrInvalidFolderUpdate reports a folder update with an invalid value.
var ErrInvalidFolderUpdate = errors.New("invalid folder update")

var collectionColor = regexp.MustCompile(`^#[0-9A-Fa-f]{6}([0-9A-Fa-f]{2})?$`)

// FolderSpace is the single data boundary used by wire protocols. Folders are
// typed containers, but item payloads are deliberately opaque: MIME, iCalendar,
// vCard, files, and protocol metadata are interpreted only by adapters.
type FolderSpace interface {
	AccountUsage(context.Context, AccessContext) (AccountUsage, error)
	ListFolders(context.Context, AccessContext, FolderQuery) ([]model.Folder, error)
	GetFolder(context.Context, AccessContext, string) (model.Folder, error)
	GetFolderByPath(context.Context, AccessContext, string) (model.Folder, error)
	GetFolderByOwnerPath(context.Context, AccessContext, string, string) (model.Folder, error)
	CreateFolder(context.Context, AccessContext, string, model.FolderType, string) (model.Folder, error)
	UpdateFolder(context.Context, AccessContext, string, FolderUpdate) (model.Folder, error)
	MoveFolder(context.Context, AccessContext, string, string, string) (model.Folder, error)
	DeleteFolder(context.Context, AccessContext, string) error

	ListItems(context.Context, AccessContext, string, ItemQuery) ([]model.Item, error)
	GetItem(context.Context, AccessContext, string) (model.Item, error)
	GetItemByUID(context.Context, AccessContext, string, uint32) (model.Item, error)
	GetItemByName(context.Context, AccessContext, string, string) (model.Item, error)
	GetItemByExternalID(context.Context, AccessContext, string, string, string) (model.Item, error)
	GetItemMetadataByExternalID(context.Context, AccessContext, string, string, string) (model.Item, error)
	CreateItem(context.Context, AccessContext, string, ItemInput) (model.Item, error)
	BindItemExternalID(context.Context, AccessContext, string, string, string) (model.Item, error)
	UpdateItem(context.Context, AccessContext, string, []byte, map[string]string) (model.Item, error)
	SetFlags(context.Context, AccessContext, string, []string) (model.Item, error)
	MoveItem(context.Context, AccessContext, string, string, string) (model.Item, error)
	CopyItem(context.Context, AccessContext, string, string, string) (model.Item, error)
	DeleteItem(context.Context, AccessContext, string) error
}

// ConditionalItemUpdater atomically replaces content only when the caller's
// observed mailbox mod-sequence is still current.
type ConditionalItemUpdater interface {
	UpdateItemIfModSeq(context.Context, AccessContext, string, uint64, []byte, map[string]string) (model.Item, error)
}

// ExclusiveItemCreator atomically creates a named item without inheriting the
// sync-oriented CreateItem upsert behavior.
type ExclusiveItemCreator interface {
	CreateItemIfAbsent(context.Context, AccessContext, string, ItemInput) (model.Item, error)
}

var ErrItemUpdateConflict = errors.New("item changed since it was read")

// FolderItemPager is the optional bounded enumeration capability used by
// interactive and API consumers. Protocol implementations can keep their
// existing sequence semantics through ListItems.
type FolderItemPager interface {
	ListItemPage(context.Context, AccessContext, string, ItemPageQuery) (ItemPage, error)
}

// FolderItemBatchCreator atomically appends multiple items to one folder. It
// is optional because not every embedded FolderSpace can promise rollback.
type FolderItemBatchCreator interface {
	CreateItems(context.Context, AccessContext, string, []ItemInput) ([]model.Item, error)
}

// FolderSpaceBatcher is an optional capability for committing a related set of
// folder mutations atomically. Callers must use the callback context for every
// operation in the batch.
type FolderSpaceBatcher interface {
	Batch(context.Context, func(context.Context) error) error
}

// RecoverableFolderSpace is the optional trash lifecycle capability shared by
// the web workspace and protocols that expose recoverable deletion.
type RecoverableFolderSpace interface {
	ListTrash(context.Context, AccessContext) ([]ItemSummary, error)
	ListTrashedFolders(context.Context, AccessContext) ([]model.Folder, error)
	RestoreFolder(context.Context, AccessContext, string) (model.Folder, error)
	PurgeFolder(context.Context, AccessContext, string) error
	TrashItem(context.Context, AccessContext, string) (model.Item, error)
	RestoreItem(context.Context, AccessContext, string) (model.Item, error)
}

type TrashRetentionConfigurer interface {
	SetTrashRetentionDays(int)
}

type ChangeRetentionConfigurer interface {
	SetChangeRetention(int, int)
}

const (
	DefaultItemHistoryRetentionDays = 30
	DefaultItemHistoryMaxVersions   = 50
	MaxItemHistoryRetentionDays     = 3650
	MaxItemHistoryVersions          = 1000
)

var ErrItemHistoryUnavailable = errors.New("item history is unavailable")

// ItemHistoryFolderSpace is the optional generic version capability. FolderID
// remains explicit for deleted items and lets account-routed implementations
// resolve the correct backend without a live item-location index.
type ItemHistoryFolderSpace interface {
	GetItemHistoryPolicy(context.Context, AccessContext, string) (model.ItemHistoryPolicy, error)
	ConfigureItemHistory(context.Context, AccessContext, string, model.ItemHistoryPolicy) (model.Folder, error)
	ListItemVersions(context.Context, AccessContext, string, string) ([]model.ItemVersion, error)
	GetItemVersion(context.Context, AccessContext, string, string, string) (model.ItemVersion, error)
	RestoreItemVersion(context.Context, AccessContext, string, string, string) (model.Item, error)
}

// Batch runs fn atomically when the FolderSpace supports batching. Other
// implementations retain their normal operation-by-operation behavior.
func Batch(ctx context.Context, space FolderSpace, fn func(context.Context) error) error {
	if batcher, ok := space.(FolderSpaceBatcher); ok {
		return batcher.Batch(ctx, fn)
	}
	return fn(ctx)
}

// FolderSpaceService adapts the authorization-aware Workspace to the complete
// protocol-facing folder contract. It is the only production implementation.
type FolderSpaceService struct {
	ts         *model.TypedStore
	workspace  *Workspace
	folders    *model.FolderStore
	items      *model.ItemStore
	history    *model.ItemHistoryStore
	changes    *ChangeStore
	legalHolds atomic.Pointer[legalHoldBox]
	// committed, when set, runs after a change record is durably committed
	// with the folders the committed records touched. It is installed before
	// the space is shared and never changes.
	committed func(folderIDs []string)
}

func NewFolderSpace(ts *model.TypedStore, authorizer *authz.Engine) *FolderSpaceService {
	return &FolderSpaceService{
		ts:        ts,
		workspace: NewWorkspace(ts, authorizer),
		folders:   ts.FolderStore(),
		items:     ts.ItemStore(),
		history:   ts.ItemHistoryStore(),
		changes:   NewChangeStore(ts),
	}
}

// AccountUsage returns quota limits and folder-derived usage without listing
// item identities or reading item payloads.
func (s *FolderSpaceService) AccountUsage(ctx context.Context, access AccessContext) (AccountUsage, error) {
	if err := access.Validate(); err != nil {
		return AccountUsage{}, err
	}
	if err := s.workspace.requireAccountContext(ctx, access.Actor, access.Subject, access.Mode); err != nil {
		return AccountUsage{}, err
	}
	quota, err := s.ts.UserStore().GetQuota(ctx, access.Subject.ID)
	if err != nil {
		return AccountUsage{}, err
	}
	all, err := s.folders.ListAll(ctx)
	if err != nil {
		return AccountUsage{}, err
	}
	usage := AccountUsage{AccountID: access.Subject.ID, Quota: quota, AccountingReady: true}
	byType := make(map[model.FolderType]*UsageByType)
	for _, folder := range all {
		if folder.UserID != access.Subject.ID {
			continue
		}
		usage.Folders++
		usage.Items += folder.ItemCount
		usage.LogicalBytes += folder.LogicalBytes + folder.HistoryLogicalBytes
		usage.HistoryVersions += folder.HistoryVersionCount
		usage.HistoryLogicalBytes += folder.HistoryLogicalBytes
		historyAccountingReady := folder.HistoryUsageVersion == 1 ||
			(folder.HistoryUsageVersion == 0 && folder.HistoryVersionCount == 0 && folder.HistoryLogicalBytes == 0)
		if folder.UsageVersion != 1 || !historyAccountingReady {
			usage.AccountingReady = false
		}
		entry := byType[folder.Type]
		if entry == nil {
			entry = &UsageByType{Type: folder.Type}
			byType[folder.Type] = entry
		}
		entry.Folders++
		entry.Items += folder.ItemCount
		entry.LogicalBytes += folder.LogicalBytes + folder.HistoryLogicalBytes
		entry.HistoryVersions += folder.HistoryVersionCount
		entry.HistoryLogicalBytes += folder.HistoryLogicalBytes
	}
	types := make([]model.FolderType, 0, len(byType))
	for folderType := range byType {
		types = append(types, folderType)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	usage.ByType = make([]UsageByType, 0, len(types))
	for _, folderType := range types {
		usage.ByType = append(usage.ByType, *byType[folderType])
	}
	return usage, nil
}

func (s *FolderSpaceService) SetTrashRetentionDays(days int) {
	s.workspace.SetTrashRetentionDays(days)
}

func normalizeItemHistoryPolicy(policy, current model.ItemHistoryPolicy) (model.ItemHistoryPolicy, error) {
	if policy.RetentionDays < 0 || policy.RetentionDays > MaxItemHistoryRetentionDays {
		return model.ItemHistoryPolicy{}, fmt.Errorf("history retention_days must be between 0 and %d", MaxItemHistoryRetentionDays)
	}
	if policy.MaxVersions < 0 || policy.MaxVersions > MaxItemHistoryVersions {
		return model.ItemHistoryPolicy{}, fmt.Errorf("history max_versions must be between 0 and %d", MaxItemHistoryVersions)
	}
	if policy.Enabled && policy.RetentionDays == 0 && policy.MaxVersions == 0 {
		policy.RetentionDays = DefaultItemHistoryRetentionDays
		policy.MaxVersions = DefaultItemHistoryMaxVersions
	}
	if !policy.Enabled && policy.RetentionDays == 0 && policy.MaxVersions == 0 {
		policy.RetentionDays = current.RetentionDays
		policy.MaxVersions = current.MaxVersions
		if policy.RetentionDays == 0 && policy.MaxVersions == 0 {
			policy.RetentionDays = DefaultItemHistoryRetentionDays
			policy.MaxVersions = DefaultItemHistoryMaxVersions
		}
	}
	return policy, nil
}

func (s *FolderSpaceService) GetItemHistoryPolicy(ctx context.Context, access AccessContext, folderID string) (model.ItemHistoryPolicy, error) {
	folder, err := s.GetFolder(ctx, access, folderID)
	if err != nil {
		return model.ItemHistoryPolicy{}, err
	}
	return folder.History, nil
}

func (s *FolderSpaceService) ConfigureItemHistory(ctx context.Context, access AccessContext, folderID string, policy model.ItemHistoryPolicy) (model.Folder, error) {
	if err := access.Validate(); err != nil {
		return model.Folder{}, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderMetadataWrite, folderID); err != nil {
		return model.Folder{}, err
	}
	folder, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	if model.IsHeldDeletedFolder(folder) {
		return model.Folder{}, store.ErrNotFound
	}
	policy, err = normalizeItemHistoryPolicy(policy, folder.History)
	if err != nil {
		return model.Folder{}, err
	}
	var result model.Folder
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		if err := s.folders.Update(batchCtx, folderID, func(candidate *model.Folder) {
			candidate.History = policy
		}); err != nil {
			return err
		}
		if !s.accountHeld(batchCtx, folder.UserID) {
			if _, err := s.history.PruneFolder(batchCtx, folderID, time.Now().UTC()); err != nil {
				return err
			}
		}
		result, err = s.folders.Get(batchCtx, folderID)
		return err
	}, func() []Change { return []Change{folderChange(ChangeUpdate, result, result.ParentID)} })
	return result, err
}

func (s *FolderSpaceService) ListItemVersions(ctx context.Context, access AccessContext, folderID, itemID string) ([]model.ItemVersion, error) {
	if err := access.Validate(); err != nil {
		return nil, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsList, folderID); err != nil {
		return nil, err
	}
	return s.history.List(ctx, folderID, itemID)
}

func (s *FolderSpaceService) GetItemVersion(ctx context.Context, access AccessContext, folderID, itemID, versionID string) (model.ItemVersion, error) {
	if err := access.Validate(); err != nil {
		return model.ItemVersion{}, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsRead, folderID); err != nil {
		return model.ItemVersion{}, err
	}
	return s.history.Get(ctx, folderID, itemID, versionID)
}

func (s *FolderSpaceService) RestoreItemVersion(ctx context.Context, access AccessContext, folderID, itemID, versionID string) (model.Item, error) {
	version, err := s.GetItemVersion(ctx, access, folderID, itemID, versionID)
	if err != nil {
		return model.Item{}, err
	}
	current, currentErr := s.items.Get(ctx, itemID)
	created := false
	switch {
	case currentErr == nil:
		if current.FolderID != folderID {
			return model.Item{}, fmt.Errorf("%w: item is now in another folder", model.ErrItemHistoryConflict)
		}
		if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsUpdate, folderID); err != nil {
			return model.Item{}, err
		}
		if model.ItemHistoryEqual(current, version.Item) {
			return current, nil
		}
	case errors.Is(currentErr, store.ErrNotFound):
		if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsCreate, folderID); err != nil {
			return model.Item{}, err
		}
	case currentErr != nil:
		return model.Item{}, currentErr
	}

	var result model.Item
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		if currentErr == nil {
			if _, _, err := s.history.Capture(batchCtx, current, model.ItemHistoryRestore); err != nil {
				return err
			}
		}
		var err error
		result, created, err = s.items.RestoreVersion(batchCtx, version.Item)
		return err
	}, func() []Change {
		operation := ChangeUpdate
		if created {
			operation = ChangeCreate
		}
		return []Change{itemChange(operation, result, "")}
	})
	return result, err
}

func (s *FolderSpaceService) captureHistory(ctx context.Context, item model.Item, operation model.ItemHistoryOperation) error {
	_, _, err := s.history.Capture(ctx, item, operation)
	return err
}

// PruneItemHistory applies every folder's retained policy. It is used by the
// account router's bounded maintenance pass; unavailable or trashed folders
// remain independently recoverable.
func (s *FolderSpaceService) PruneItemHistory(ctx context.Context, now time.Time) (int, error) {
	folders, err := s.folders.ListAll(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, folder := range folders {
		if s.accountHeld(ctx, folder.UserID) {
			continue
		}
		count, pruneErr := s.history.PruneFolder(ctx, folder.ID, now)
		if pruneErr != nil {
			return removed, pruneErr
		}
		removed += count
	}
	return removed, nil
}

func (s *FolderSpaceService) ListTrash(ctx context.Context, access AccessContext) ([]ItemSummary, error) {
	return s.workspace.ListTrash(ctx, access.Actor, access.Subject, access.Mode)
}

func (s *FolderSpaceService) ListTrashedFolders(ctx context.Context, access AccessContext) ([]model.Folder, error) {
	return s.workspace.ListTrashedFolders(ctx, access.Actor, access.Subject, access.Mode)
}

func (s *FolderSpaceService) RestoreFolder(ctx context.Context, access AccessContext, folderID string) (model.Folder, error) {
	if err := access.Validate(); err != nil {
		return model.Folder{}, err
	}
	before, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	tree, err := s.trashedFolderTree(ctx, before)
	if err != nil {
		return model.Folder{}, err
	}
	var result model.Folder
	var restored []model.Folder
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		var err error
		result, err = s.workspace.RestoreFolder(batchCtx, access.Actor, access.Subject, access.Mode, folderID)
		if err != nil {
			return err
		}
		restored, err = s.foldersByID(batchCtx, tree)
		return err
	}, func() []Change {
		changes := make([]Change, 0, len(restored))
		for index, folder := range restored {
			changes = append(changes, folderChange(ChangeRestore, folder, tree[index].OriginalParentID))
		}
		return changes
	})
	return result, err
}

func (s *FolderSpaceService) PurgeFolder(ctx context.Context, access AccessContext, folderID string) error {
	root, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return err
	}
	if s.accountHeld(ctx, root.UserID) {
		return s.preservePurgedFolder(ctx, access, root)
	}
	trashed, err := s.folders.ListTrashedForUser(ctx, root.UserID)
	if err != nil {
		return err
	}
	effects := make([]Change, 0)
	for _, folder := range trashed {
		if folder.ID != root.ID && !strings.HasPrefix(folder.OriginalPath, root.OriginalPath+"/") {
			continue
		}
		items, listErr := s.items.ListMetadata(ctx, folder.ID)
		if listErr != nil {
			return listErr
		}
		for _, item := range items {
			effects = append(effects, itemChange(ChangeDestroy, item, ""))
		}
		effects = append(effects, folderChange(ChangeDestroy, folder, folder.OriginalParentID))
	}
	return s.commitChange(ctx, func(batchCtx context.Context) error {
		for _, folder := range trashed {
			if folder.ID != root.ID && !strings.HasPrefix(folder.OriginalPath, root.OriginalPath+"/") {
				continue
			}
			if _, err := s.history.DeleteFolder(batchCtx, folder.ID); err != nil {
				return err
			}
		}
		return s.workspace.PurgeFolder(batchCtx, access.Actor, access.Subject, access.Mode, folderID)
	}, func() []Change { return effects })
}

func (s *FolderSpaceService) TrashItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	before, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	var result model.Item
	var previousModSeq uint64
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		if err := s.captureHistory(batchCtx, before, model.ItemHistoryTrash); err != nil {
			return err
		}
		var err error
		result, err = s.workspace.TrashItem(batchCtx, access.Actor, access.Subject, access.Mode, itemID)
		if err != nil {
			return err
		}
		if result.FolderID == before.FolderID {
			previousModSeq = result.ModSeq
			return nil
		}
		source, err := s.folders.Get(batchCtx, before.FolderID)
		if err == nil {
			previousModSeq = source.HighestModSeq
		}
		return err
	}, func() []Change {
		change := itemChange(ChangeTrash, result, result.OriginalFolderID)
		change.PreviousUID, change.PreviousModSeq = before.UID, previousModSeq
		return []Change{change}
	})
	return result, err
}

func (s *FolderSpaceService) RestoreItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	before, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	var result model.Item
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		if err := s.captureHistory(batchCtx, before, model.ItemHistoryRestore); err != nil {
			return err
		}
		var err error
		result, err = s.workspace.RestoreItem(batchCtx, access.Actor, access.Subject, access.Mode, itemID)
		return err
	}, func() []Change { return []Change{itemChange(ChangeRestore, result, before.FolderID)} })
	return result, err
}

func (s *FolderSpaceService) ListFolders(ctx context.Context, access AccessContext, query FolderQuery) ([]model.Folder, error) {
	if err := access.Validate(); err != nil {
		return nil, err
	}
	folders, err := s.workspace.ListFolders(ctx, access.Actor, access.Subject, access.Mode)
	if err != nil {
		return nil, err
	}
	if query.IncludeTrashed {
		if err := s.workspace.requireAccountContext(ctx, access.Actor, access.Subject, access.Mode); err != nil {
			return nil, err
		}
		trashed, err := s.folders.ListTrashedForUser(ctx, access.Subject.ID)
		if err != nil {
			return nil, err
		}
		folders = append(folders, trashed...)
	}
	visible := heldVisible(access)
	result := folders[:0]
	for _, folder := range folders {
		if !visible && model.IsHeldDeletedFolder(folder) {
			continue
		}
		if query.Type == "" || folder.Type == query.Type {
			result = append(result, folder)
		}
	}
	return result, nil
}

// ListOwnFolders lists the folders access.Subject owns, omitting shared ones.
func (s *FolderSpaceService) ListOwnFolders(ctx context.Context, access AccessContext, query FolderQuery) ([]model.Folder, error) {
	folders, err := s.ListFolders(ctx, access, query)
	if err != nil {
		return nil, err
	}
	own := folders[:0]
	for _, folder := range folders {
		if strings.EqualFold(folder.UserID, access.Subject.ID) {
			own = append(own, folder)
		}
	}
	return own, nil
}

func (s *FolderSpaceService) GetFolder(ctx context.Context, access AccessContext, folderID string) (model.Folder, error) {
	if err := access.Validate(); err != nil {
		return model.Folder{}, err
	}
	folder, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	if !folder.TrashedAt.IsZero() || model.IsHeldDeletedFolder(folder) && !heldVisible(access) {
		return model.Folder{}, store.ErrNotFound
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderDiscover, folder.ID); err != nil {
		return model.Folder{}, err
	}
	return folder, nil
}

func (s *FolderSpaceService) GetFolderByPath(ctx context.Context, access AccessContext, path string) (model.Folder, error) {
	return s.GetFolderByOwnerPath(ctx, access, access.Subject.ID, path)
}

func (s *FolderSpaceService) GetFolderByOwnerPath(ctx context.Context, access AccessContext, ownerID, path string) (model.Folder, error) {
	if err := access.Validate(); err != nil {
		return model.Folder{}, err
	}
	path = strings.Trim(strings.TrimSpace(path), "/")
	folder, err := s.folders.GetByPath(ctx, ownerID, path)
	if err != nil {
		return model.Folder{}, err
	}
	if model.IsHeldDeletedFolder(folder) && !heldVisible(access) {
		return model.Folder{}, store.ErrNotFound
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderDiscover, folder.ID); err != nil {
		return model.Folder{}, err
	}
	return folder, nil
}

func (s *FolderSpaceService) CreateFolder(ctx context.Context, access AccessContext, name string, folderType model.FolderType, parentID string) (model.Folder, error) {
	if err := access.Validate(); err != nil {
		return model.Folder{}, err
	}
	var result model.Folder
	err := s.commitChange(ctx, func(batchCtx context.Context) error {
		var err error
		result, err = s.workspace.CreateFolder(batchCtx, access.Actor, access.Subject, access.Mode, name, folderType, parentID)
		return err
	}, func() []Change { return []Change{folderChange(ChangeCreate, result, "")} })
	return result, err
}

func (s *FolderSpaceService) UpdateFolder(ctx context.Context, access AccessContext, folderID string, update FolderUpdate) (model.Folder, error) {
	if err := access.Validate(); err != nil {
		return model.Folder{}, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderMetadataWrite, folderID); err != nil {
		return model.Folder{}, err
	}
	folder, err := s.folders.Get(ctx, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	if model.IsHeldDeletedFolder(folder) {
		return model.Folder{}, store.ErrNotFound
	}
	if update.Default != nil && (!*update.Default || folder.UserID != access.Subject.ID || folder.Type != model.FolderTypeCalendar || !folder.TrashedAt.IsZero()) {
		return model.Folder{}, fmt.Errorf("%w: default calendar must be an active calendar owned by the acting account", ErrForbidden)
	}
	if err := validateCollectionPresentation(folder, update); err != nil {
		return model.Folder{}, err
	}
	var result model.Folder
	var changed []model.Folder
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		if err := s.folders.Update(batchCtx, folderID, func(folder *model.Folder) {
			if update.Subscribed != nil {
				folder.Subscribed = *update.Subscribed
			}
			if update.Name != nil {
				folder.Name = strings.TrimSpace(*update.Name)
			}
			if update.Color != nil {
				folder.Color = *update.Color
			}
			if update.Description != nil {
				folder.Description = *update.Description
			}
			if update.Order != nil {
				folder.Order = *update.Order
			}
		}); err != nil {
			return err
		}
		if update.Default != nil {
			var err error
			changed, err = s.folders.SetDefault(batchCtx, folder.UserID, folder.Type, folderID)
			if err != nil {
				return err
			}
		}
		var err error
		result, err = s.folders.Get(batchCtx, folderID)
		return err
	}, func() []Change {
		if len(changed) == 0 {
			return []Change{folderChange(ChangeUpdate, result, "")}
		}
		changes := make([]Change, 0, len(changed))
		for _, folder := range changed {
			changes = append(changes, folderChange(ChangeUpdate, folder, ""))
		}
		return changes
	})
	return result, err
}

func (s *FolderSpaceService) MoveFolder(ctx context.Context, access AccessContext, folderID, parentID, name string) (model.Folder, error) {
	if err := access.Validate(); err != nil {
		return model.Folder{}, err
	}
	before, err := s.GetFolder(ctx, access, folderID)
	if err != nil {
		return model.Folder{}, err
	}
	tree, err := s.activeFolderTree(ctx, before)
	if err != nil {
		return model.Folder{}, err
	}
	var result model.Folder
	var moved []model.Folder
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		var err error
		result, err = s.workspace.MoveFolder(batchCtx, access.Actor, access.Subject, access.Mode, folderID, parentID, name)
		if err != nil {
			return err
		}
		moved, err = s.foldersByID(batchCtx, tree)
		return err
	}, func() []Change {
		changes := make([]Change, 0, len(moved))
		for index, folder := range moved {
			changes = append(changes, folderChange(ChangeMove, folder, tree[index].ParentID))
		}
		return changes
	})
	return result, err
}

func (s *FolderSpaceService) DeleteFolder(ctx context.Context, access AccessContext, folderID string) error {
	if err := access.Validate(); err != nil {
		return err
	}
	before, err := s.GetFolder(ctx, access, folderID)
	if err != nil {
		return err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderChildrenDelete, folderID); err != nil {
		return err
	}
	tree, err := s.activeFolderTree(ctx, before)
	if err != nil {
		return err
	}
	var replacement model.Folder
	if before.SpecialUse == model.SpecialUseCalendar {
		folders, listErr := s.folders.ListForUser(ctx, before.UserID)
		if listErr != nil {
			return listErr
		}
		for _, candidate := range folders {
			if candidate.ID == before.ID || candidate.Type != model.FolderTypeCalendar || strings.HasPrefix(candidate.Path, before.Path+"/") {
				continue
			}
			replacement = candidate
			break
		}
		if replacement.ID == "" {
			return errors.New("create another calendar before deleting the default calendar")
		}
	}
	var changedDefaults []model.Folder
	return s.commitChange(ctx, func(batchCtx context.Context) error {
		if replacement.ID != "" {
			var err error
			changedDefaults, err = s.folders.SetDefault(batchCtx, before.UserID, model.FolderTypeCalendar, replacement.ID)
			if err != nil {
				return err
			}
		}
		return s.folders.Trash(batchCtx, folderID, s.workspace.trashRetention())
	}, func() []Change {
		changes := make([]Change, 0, len(changedDefaults)+1)
		for _, folder := range changedDefaults {
			changes = append(changes, folderChange(ChangeUpdate, folder, ""))
		}
		for _, folder := range tree {
			changes = append(changes, folderChange(ChangeTrash, folder, folder.ParentID))
		}
		return changes
	})
}

func (s *FolderSpaceService) activeFolderTree(ctx context.Context, root model.Folder) ([]model.Folder, error) {
	folders, err := s.folders.ListForUser(ctx, root.UserID)
	if err != nil {
		return nil, err
	}
	return folderTree(folders, root.ID, root.Path, false), nil
}

func (s *FolderSpaceService) trashedFolderTree(ctx context.Context, root model.Folder) ([]model.Folder, error) {
	folders, err := s.folders.ListTrashedForUser(ctx, root.UserID)
	if err != nil {
		return nil, err
	}
	return folderTree(folders, root.ID, root.OriginalPath, true), nil
}

func folderTree(folders []model.Folder, rootID, rootPath string, original bool) []model.Folder {
	tree := make([]model.Folder, 0)
	for _, folder := range folders {
		path := folder.Path
		if original {
			path = folder.OriginalPath
		}
		if folder.ID == rootID || strings.HasPrefix(path, rootPath+"/") {
			tree = append(tree, folder)
		}
	}
	sort.Slice(tree, func(i, j int) bool {
		left, right := tree[i].Path, tree[j].Path
		if original {
			left, right = tree[i].OriginalPath, tree[j].OriginalPath
		}
		return left < right
	})
	return tree
}

func (s *FolderSpaceService) foldersByID(ctx context.Context, before []model.Folder) ([]model.Folder, error) {
	after := make([]model.Folder, 0, len(before))
	for _, folder := range before {
		current, err := s.folders.Get(ctx, folder.ID)
		if err != nil {
			return nil, err
		}
		after = append(after, current)
	}
	return after, nil
}

func (s *FolderSpaceService) ListItems(ctx context.Context, access AccessContext, folderID string, query ItemQuery) ([]model.Item, error) {
	if err := access.Validate(); err != nil {
		return nil, err
	}
	if err := s.requireVisibleFolder(ctx, access, folderID); err != nil {
		return nil, err
	}
	action := authz.FolderItemsList
	if query.RequireRead {
		action = authz.FolderItemsRead
	}
	stored, err := s.workspace.ListItemMetadata(ctx, access.Actor, access.Subject, access.Mode, folderID, action)
	if err != nil {
		return nil, err
	}
	items := make([]model.Item, 0, len(stored))
	for _, item := range stored {
		if !query.Since.IsZero() && item.InternalDate.Before(query.Since) {
			continue
		}
		if !query.Before.IsZero() && !item.InternalDate.Before(query.Before) {
			continue
		}
		if !query.MetadataOnly {
			var err error
			item, err = s.workspace.GetItem(ctx, access.Actor, access.Subject, access.Mode, item.ID)
			if err != nil {
				return nil, err
			}
		}
		items = append(items, item)
		if query.Limit > 0 && len(items) >= query.Limit {
			break
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].UID < items[j].UID })
	return items, nil
}

func (s *FolderSpaceService) ListItemPage(ctx context.Context, access AccessContext, folderID string, query ItemPageQuery) (ItemPage, error) {
	if err := access.Validate(); err != nil {
		return ItemPage{}, err
	}
	if err := s.requireVisibleFolder(ctx, access, folderID); err != nil {
		return ItemPage{}, err
	}
	if query.Order == ItemPageOrderInternalDateDescending {
		if query.AnchorItemID != "" {
			if query.Cursor != "" {
				return ItemPage{}, errors.New("anchor item cannot be combined with a cursor")
			}
			page, err := s.workspace.ListDateItemWindow(ctx, access.Actor, access.Subject, access.Mode, folderID, query.AnchorItemID, query.IncludeData)
			if err != nil {
				return ItemPage{}, err
			}
			return ItemPage{Items: page.Items, Total: page.Total}, nil
		}
		page, err := s.workspace.ListDateItemPage(ctx, access.Actor, access.Subject, access.Mode, folderID, query.Cursor, query.Limit, query.IncludeData)
		if err != nil {
			return ItemPage{}, err
		}
		return ItemPage{Items: page.Items, Total: page.Total, NextCursor: page.NextCursor}, nil
	}
	if query.Order != ItemPageOrderUIDDescending {
		return ItemPage{}, errors.New("unsupported item page order")
	}
	if query.Cursor != "" {
		return ItemPage{}, errors.New("item page cursor requires an ordered page")
	}
	if query.IncludeData {
		return s.workspace.ListFullItemPage(ctx, access.Actor, access.Subject, access.Mode, folderID, query.BeforeUID, query.Limit)
	}
	page, err := s.workspace.ListItemPage(ctx, access.Actor, access.Subject, access.Mode, folderID, query.BeforeUID, query.Limit)
	if err != nil {
		return ItemPage{}, err
	}
	result := ItemPage{Items: make([]model.Item, 0, len(page.Items)), Total: page.Total, NextBeforeUID: page.NextBeforeUID}
	for _, summary := range page.Items {
		result.Items = append(result.Items, itemFromSummary(summary))
	}
	return result, nil
}

func itemFromSummary(summary ItemSummary) model.Item {
	internalDate, _ := time.Parse(time.RFC3339, summary.InternalDate)
	trashedAt, _ := time.Parse(time.RFC3339, summary.TrashedAt)
	purgeAfter, _ := time.Parse(time.RFC3339, summary.PurgeAfter)
	return model.Item{
		ID: summary.ID, Name: summary.Name, FolderID: summary.FolderID,
		Headers: summary.Headers, Size: summary.Size, UID: summary.UID, ModSeq: summary.ModSeq,
		Flags: append([]string(nil), summary.Flags...), InternalDate: internalDate,
		TrashedAt: trashedAt, PurgeAfter: purgeAfter, OriginalFolderID: summary.OriginalFolderID,
	}
}

func (s *FolderSpaceService) GetItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	if err := access.Validate(); err != nil {
		return model.Item{}, err
	}
	item, err := s.workspace.GetItem(ctx, access.Actor, access.Subject, access.Mode, itemID)
	if err == nil && !item.HeldDeletedAt.IsZero() && !heldVisible(access) {
		return model.Item{}, store.ErrNotFound
	}
	return item, err
}

func (s *FolderSpaceService) GetItemByUID(ctx context.Context, access AccessContext, folderID string, uid uint32) (model.Item, error) {
	folder, err := s.GetFolder(ctx, access, folderID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsList, folder.ID); err != nil {
		return model.Item{}, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsRead, folder.ID); err != nil {
		return model.Item{}, err
	}
	item, err := s.items.GetByUID(ctx, folder.ID, uid)
	if err != nil {
		return model.Item{}, err
	}
	if item.FolderID != folder.ID || (!item.TrashedAt.IsZero() && folder.SpecialUse != model.SpecialUseTrash) {
		return model.Item{}, store.ErrNotFound
	}
	return item, nil
}

func (s *FolderSpaceService) GetItemByName(ctx context.Context, access AccessContext, folderID, name string) (model.Item, error) {
	if _, err := s.GetFolder(ctx, access, folderID); err != nil {
		return model.Item{}, err
	}
	item, err := s.items.Get(ctx, model.ItemKey(folderID, name))
	if err != nil {
		return model.Item{}, err
	}
	return s.GetItem(ctx, access, item.ID)
}

func (s *FolderSpaceService) GetItemByExternalID(ctx context.Context, access AccessContext, folderID, namespace, externalID string) (model.Item, error) {
	if _, err := s.GetFolder(ctx, access, folderID); err != nil {
		return model.Item{}, err
	}
	item, err := s.items.GetByExternalID(ctx, folderID, namespace, externalID)
	if err != nil {
		return model.Item{}, err
	}
	return s.GetItem(ctx, access, item.ID)
}

func (s *FolderSpaceService) GetItemMetadataByExternalID(ctx context.Context, access AccessContext, folderID, namespace, externalID string) (model.Item, error) {
	if _, err := s.GetFolder(ctx, access, folderID); err != nil {
		return model.Item{}, err
	}
	return s.items.GetMetadataByExternalID(ctx, folderID, namespace, externalID)
}

func (s *FolderSpaceService) CreateItem(ctx context.Context, access AccessContext, folderID string, request ItemInput) (model.Item, error) {
	if err := access.Validate(); err != nil {
		return model.Item{}, err
	}
	if err := s.requireUserFolder(ctx, folderID); err != nil {
		return model.Item{}, err
	}
	if err := s.changes.Ensure(ctx); err != nil {
		return model.Item{}, err
	}
	operation := ChangeCreate
	var previous model.Item
	var err error
	if request.Name != "" {
		if previous, err = s.GetItemByName(ctx, access, folderID, request.Name); err == nil {
			operation = ChangeUpdate
		} else if !errors.Is(err, store.ErrNotFound) {
			return model.Item{}, err
		}
	}
	for namespace, externalID := range request.ExternalIDs {
		if strings.TrimSpace(namespace) == "" || strings.TrimSpace(externalID) == "" {
			return model.Item{}, errors.New("external item namespace and ID are required")
		}
		if _, err := s.GetItemByExternalID(ctx, access, folderID, namespace, externalID); err == nil {
			return model.Item{}, fmt.Errorf("%w: external item identity is already assigned", store.ErrExists)
		} else if !errors.Is(err, store.ErrNotFound) {
			return model.Item{}, err
		}
	}
	var item model.Item
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		var err error
		if operation == ChangeUpdate {
			if bytes.Equal(previous.Data, request.Data) && maps.Equal(previous.Headers, request.Headers) &&
				(len(request.Flags) == 0 || slices.Equal(previous.Flags, request.Flags)) &&
				(request.InternalDate.IsZero() || previous.InternalDate.Equal(request.InternalDate)) &&
				(len(request.ExternalIDs) == 0 || maps.Equal(previous.ExternalIDs, request.ExternalIDs)) {
				item = previous
				return nil
			}
			if err := s.captureHistory(batchCtx, previous, model.ItemHistoryUpdate); err != nil {
				return err
			}
		}
		if request.Name == "" {
			item, err = s.workspace.CreateItemRecord(batchCtx, access.Actor, access.Subject, access.Mode, folderID, model.Item{
				Data: request.Data, Headers: request.Headers, Flags: request.Flags,
				InternalDate: request.InternalDate, ExternalIDs: request.ExternalIDs,
			})
			return err
		}
		item, err = s.workspace.PutNamedItem(batchCtx, access.Actor, access.Subject, access.Mode, folderID, request.Name, request.Data, request.Headers)
		if err != nil {
			return err
		}
		if len(request.Flags) > 0 || !request.InternalDate.IsZero() || len(request.ExternalIDs) > 0 {
			if len(request.Flags) > 0 {
				item.Flags = append([]string(nil), request.Flags...)
			}
			if !request.InternalDate.IsZero() {
				item.InternalDate = request.InternalDate.UTC()
			}
			item.ExternalIDs = copyStringMap(request.ExternalIDs)
			if err := s.items.SetItem(batchCtx, item); err != nil {
				return fmt.Errorf("set protocol item metadata: %w", err)
			}
		}
		return nil
	}, func() []Change { return []Change{itemChange(operation, item, "")} })
	return item, err
}

func (s *FolderSpaceService) CreateItems(ctx context.Context, access AccessContext, folderID string, requests []ItemInput) ([]model.Item, error) {
	if len(requests) == 0 {
		return nil, errors.New("at least one item is required")
	}
	if _, ok := s.ts.Store().(store.Batcher); !ok {
		return nil, errors.New("atomic multi-item creation is unavailable")
	}
	if err := s.changes.Ensure(ctx); err != nil {
		return nil, err
	}
	items := make([]model.Item, 0, len(requests))
	outermost := !store.InBatch(ctx, s.ts.Store())
	var touched *touchedFolders
	if outermost {
		ctx, touched = withTouchedFolders(ctx)
	}
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		for _, request := range requests {
			item, err := s.CreateItem(batchCtx, access, folderID, request)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return nil
	})
	if err == nil && outermost {
		s.notifyCommitted(touched)
	}
	return items, err
}

func (s *FolderSpaceService) CreateItemIfAbsent(ctx context.Context, access AccessContext, folderID string, request ItemInput) (model.Item, error) {
	if err := access.Validate(); err != nil {
		return model.Item{}, err
	}
	if strings.TrimSpace(request.Name) == "" {
		return model.Item{}, errors.New("exclusive item creation requires a name")
	}
	if err := s.requireUserFolder(ctx, folderID); err != nil {
		return model.Item{}, err
	}
	for namespace, externalID := range request.ExternalIDs {
		if strings.TrimSpace(namespace) == "" || strings.TrimSpace(externalID) == "" {
			return model.Item{}, errors.New("external item namespace and ID are required")
		}
	}
	if err := s.changes.Ensure(ctx); err != nil {
		return model.Item{}, err
	}
	var item model.Item
	err := s.commitChange(ctx, func(batchCtx context.Context) error {
		if _, err := s.GetItemByName(batchCtx, access, folderID, request.Name); err == nil {
			return store.ErrExists
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		for namespace, externalID := range request.ExternalIDs {
			if _, err := s.GetItemByExternalID(batchCtx, access, folderID, namespace, externalID); err == nil {
				return fmt.Errorf("%w: external item identity is already assigned", store.ErrExists)
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		var err error
		item, err = s.workspace.PutNamedItem(batchCtx, access.Actor, access.Subject, access.Mode, folderID, request.Name, request.Data, request.Headers)
		if err != nil {
			return err
		}
		if len(request.Flags) > 0 || !request.InternalDate.IsZero() || len(request.ExternalIDs) > 0 {
			item.Flags = slices.Clone(request.Flags)
			if !request.InternalDate.IsZero() {
				item.InternalDate = request.InternalDate.UTC()
			}
			item.ExternalIDs = copyStringMap(request.ExternalIDs)
			if err := s.items.SetItem(batchCtx, item); err != nil {
				return err
			}
		}
		return nil
	}, func() []Change { return []Change{itemChange(ChangeCreate, item, "")} })
	return item, err
}

func (s *FolderSpaceService) BindItemExternalID(ctx context.Context, access AccessContext, itemID, namespace, externalID string) (model.Item, error) {
	if strings.TrimSpace(namespace) == "" || strings.TrimSpace(externalID) == "" {
		return model.Item{}, errors.New("external item namespace and ID are required")
	}
	item, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsUpdate, item.FolderID); err != nil {
		return model.Item{}, err
	}
	if item.ExternalIDs[namespace] == externalID {
		return item, nil
	}
	item.ExternalIDs = copyStringMap(item.ExternalIDs)
	item.ExternalIDs[namespace] = externalID
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		before, err := s.items.Get(batchCtx, itemID)
		if err != nil {
			return err
		}
		if namespace != commandExternalNamespace {
			if err := s.captureHistory(batchCtx, before, model.ItemHistoryMetadata); err != nil {
				return err
			}
		}
		return s.items.SetItem(batchCtx, item)
	}, func() []Change { return []Change{itemChange(ChangeUpdate, item, "")} })
	return item, err
}

func (s *FolderSpaceService) UpdateItem(ctx context.Context, access AccessContext, itemID string, data []byte, headers map[string]string) (model.Item, error) {
	if err := access.Validate(); err != nil {
		return model.Item{}, err
	}
	before, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsUpdate, before.FolderID); err != nil {
		return model.Item{}, err
	}
	if bytes.Equal(before.Data, data) && maps.Equal(before.Headers, headers) {
		return before, nil
	}
	var result model.Item
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		if err := s.captureHistory(batchCtx, before, model.ItemHistoryUpdate); err != nil {
			return err
		}
		var err error
		result, err = s.workspace.UpdateItem(batchCtx, access.Actor, access.Subject, access.Mode, itemID, data, headers)
		return err
	}, func() []Change { return []Change{itemChange(ChangeUpdate, result, "")} })
	return result, err
}

func (s *FolderSpaceService) UpdateItemIfModSeq(ctx context.Context, access AccessContext, itemID string, expectedModSeq uint64, data []byte, headers map[string]string) (model.Item, error) {
	if err := access.Validate(); err != nil {
		return model.Item{}, err
	}
	if expectedModSeq == 0 {
		return model.Item{}, errors.New("expected mod-sequence is required")
	}
	if err := s.changes.Ensure(ctx); err != nil {
		return model.Item{}, err
	}
	var result model.Item
	err := s.commitChange(ctx, func(batchCtx context.Context) error {
		before, err := s.items.Get(batchCtx, itemID)
		if err != nil {
			return err
		}
		if !before.HeldDeletedAt.IsZero() {
			return store.ErrNotFound
		}
		if err := s.workspace.require(batchCtx, access.Actor, access.Subject, access.Mode, authz.FolderItemsUpdate, before.FolderID); err != nil {
			return err
		}
		if before.ModSeq != expectedModSeq {
			return fmt.Errorf("%w: expected %d, current %d", ErrItemUpdateConflict, expectedModSeq, before.ModSeq)
		}
		if bytes.Equal(before.Data, data) && maps.Equal(before.Headers, headers) {
			result = before
			return nil
		}
		if err := s.captureHistory(batchCtx, before, model.ItemHistoryUpdate); err != nil {
			return err
		}
		result, err = s.workspace.UpdateItem(batchCtx, access.Actor, access.Subject, access.Mode, itemID, data, headers)
		return err
	}, func() []Change { return []Change{itemChange(ChangeUpdate, result, "")} })
	return result, err
}

func (s *FolderSpaceService) SetFlags(ctx context.Context, access AccessContext, itemID string, flags []string) (model.Item, error) {
	item, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsUpdate, item.FolderID); err != nil {
		return model.Item{}, err
	}
	if slices.Equal(item.Flags, flags) {
		return item, nil
	}
	var result model.Item
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		if err := s.captureHistory(batchCtx, item, model.ItemHistoryMetadata); err != nil {
			return err
		}
		if err := s.items.SetFlags(batchCtx, item.ID, flags); err != nil {
			return err
		}
		var err error
		result, err = s.GetItem(batchCtx, access, itemID)
		return err
	}, func() []Change { return []Change{itemChange(ChangeUpdate, result, "")} })
	return result, err
}

func (s *FolderSpaceService) MoveItem(ctx context.Context, access AccessContext, itemID, destinationFolderID, destinationName string) (model.Item, error) {
	if err := access.Validate(); err != nil {
		return model.Item{}, err
	}
	before, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	if err := s.requireUserFolder(ctx, destinationFolderID); err != nil {
		return model.Item{}, err
	}
	resolvedName := destinationName
	if resolvedName == "" {
		resolvedName = before.Name
	}
	if before.FolderID == destinationFolderID && before.Name == resolvedName {
		return before, nil
	}
	var result model.Item
	var tombstone model.Item
	err = s.commitChange(ctx, func(batchCtx context.Context) error {
		if err := s.captureHistory(batchCtx, before, model.ItemHistoryMove); err != nil {
			return err
		}
		var err error
		result, tombstone, err = s.workspace.MoveItemNamedWithTombstone(batchCtx, access.Actor, access.Subject, access.Mode, itemID, destinationFolderID, destinationName)
		return err
	}, func() []Change {
		change := itemChange(ChangeMove, result, before.FolderID)
		change.PreviousUID, change.PreviousModSeq = tombstone.UID, tombstone.ModSeq
		change.PreviousName = tombstone.Name
		return []Change{change}
	})
	return result, err
}

func (s *FolderSpaceService) CopyItem(ctx context.Context, access AccessContext, itemID, destinationFolderID, destinationName string) (model.Item, error) {
	item, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	return s.CreateItem(ctx, access, destinationFolderID, ItemInput{
		Name: destinationName, Data: item.Data, Headers: item.Headers, Flags: item.Flags, InternalDate: item.InternalDate,
	})
}

func (s *FolderSpaceService) DeleteItem(ctx context.Context, access AccessContext, itemID string) error {
	if err := access.Validate(); err != nil {
		return err
	}
	before, err := s.GetItem(ctx, access, itemID)
	if err != nil {
		return err
	}
	if err := s.workspace.require(ctx, access.Actor, access.Subject, access.Mode, authz.FolderItemsDelete, before.FolderID); err != nil {
		return err
	}
	folder, err := s.folders.Get(ctx, before.FolderID)
	if err != nil {
		return err
	}
	if s.accountHeld(ctx, folder.UserID) {
		return s.preserveDeletedItem(ctx, access, before, folder)
	}
	var tombstone model.Item
	return s.commitChange(ctx, func(batchCtx context.Context) error {
		if err := s.captureHistory(batchCtx, before, model.ItemHistoryDelete); err != nil {
			return err
		}
		var err error
		tombstone, err = s.workspace.DeleteItemWithTombstone(batchCtx, access.Actor, access.Subject, access.Mode, itemID)
		return err
	}, func() []Change { return []Change{itemChange(ChangeDestroy, tombstone, "")} })
}

func (s *FolderSpaceService) commitChange(ctx context.Context, mutate func(context.Context) error, effects func() []Change) error {
	if err := s.changes.Ensure(ctx); err != nil {
		return err
	}
	if err := s.history.Ensure(ctx); err != nil {
		return err
	}
	outermost := !store.InBatch(ctx, s.ts.Store())
	var touched *touchedFolders
	if outermost {
		ctx, touched = withTouchedFolders(ctx)
	}
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		if err := mutate(batchCtx); err != nil {
			return err
		}
		changes := effects()
		touchedFoldersFrom(batchCtx).add(changes)
		_, err := s.changes.Record(batchCtx, changes)
		return err
	})
	// A nested change commits with its enclosing batch, whose owner notifies
	// with the folders every nested record touched.
	if err == nil && outermost {
		s.notifyCommitted(touched)
	}
	return err
}

func (s *FolderSpaceService) notifyCommitted(touched *touchedFolders) {
	if s.committed != nil {
		s.committed(touched.list())
	}
}

func folderChange(operation ChangeOperation, folder model.Folder, previousParentID string) Change {
	return Change{Object: ChangeObjectFolder, Operation: operation, ID: folder.ID, FolderID: folder.ID, PreviousFolderID: previousParentID, FolderType: folder.Type}
}

func itemChange(operation ChangeOperation, item model.Item, previousFolderID string) Change {
	return Change{Object: ChangeObjectItem, Operation: operation, ID: item.ID, Name: item.Name, FolderID: item.FolderID, PreviousFolderID: previousFolderID, UID: item.UID, ModSeq: item.ModSeq}
}

func (s *FolderSpaceService) CurrentChangeState(ctx context.Context, access AccessContext, scope ChangeScope) (string, error) {
	if err := s.authorizeChangeScope(ctx, access, scope); err != nil {
		return "", err
	}
	return s.changes.CurrentState(ctx)
}

func (s *FolderSpaceService) ListChanges(ctx context.Context, access AccessContext, scope ChangeScope, state string, limit int) (ChangePage, error) {
	allowed, err := s.authorizedChangeFolders(ctx, access, scope)
	if err != nil {
		return ChangePage{}, err
	}
	page, err := s.changes.List(ctx, scope, state, limit)
	if err != nil {
		return ChangePage{}, err
	}
	if !heldVisible(access) {
		page = s.filterHeldChanges(ctx, page)
	}
	if allowed == nil {
		return page, nil
	}
	filtered := page.Records[:0]
	for _, record := range page.Records {
		changes := record.Changes[:0]
		for _, change := range record.Changes {
			if allowed[change.FolderID] || allowed[change.PreviousFolderID] {
				changes = append(changes, change)
			}
		}
		if len(changes) > 0 {
			record.Changes = changes
			filtered = append(filtered, record)
		}
	}
	page.Records = filtered
	return page, nil
}

func (s *FolderSpaceService) authorizeChangeScope(ctx context.Context, access AccessContext, scope ChangeScope) error {
	_, err := s.authorizedChangeFolders(ctx, access, scope)
	return err
}

func (s *FolderSpaceService) authorizedChangeFolders(ctx context.Context, access AccessContext, scope ChangeScope) (map[string]bool, error) {
	if err := access.Validate(); err != nil {
		return nil, err
	}
	if scope.FolderID != "" {
		if _, err := s.GetFolder(ctx, access, scope.FolderID); err != nil {
			return nil, err
		}
		return map[string]bool{scope.FolderID: true}, nil
	}
	if access.Actor == access.Subject {
		return nil, nil
	}
	folders, err := s.ListFolders(ctx, access, FolderQuery{})
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(folders))
	for _, folder := range folders {
		allowed[folder.ID] = true
	}
	return allowed, nil
}
