package rules

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// FolderSpace is the outer protocol-neutral ingestion decorator. It retains
// every optional capability offered by its delegate and applies automation
// only after a create has committed successfully.
type FolderSpace struct {
	service.FolderSpace
	engine    *Engine
	observers atomic.Pointer[[]ItemObserver]
}

// ItemObserver follows committed item writes and removals made by every
// protocol through the automated FolderSpace. It runs synchronously after the
// commit, so it must stay cheap for items it does not care about, and it can
// never fail or undo the write.
type ItemObserver interface {
	ItemWritten(ctx context.Context, access service.AccessContext, item model.Item)
	ItemRemoved(ctx context.Context, access service.AccessContext, itemID string)
}

// ItemMoveObserver is an ItemObserver that also follows moves and copies
// between folders. ItemMoving runs before the move or copy, while the source
// item is still in place, and returns the callback to run with the resulting
// item once it has committed, or nil when the observer does not care.
type ItemMoveObserver interface {
	ItemObserver
	ItemMoving(ctx context.Context, access service.AccessContext, itemID, destinationFolderID string, copied bool) func(context.Context, model.Item)
}

// SetItemObserver installs observer as the only item observer; nil removes
// every observer.
func (s *FolderSpace) SetItemObserver(observer ItemObserver) {
	if observer == nil {
		s.observers.Store(nil)
		return
	}
	s.observers.Store(&[]ItemObserver{observer})
}

// AddItemObserver adds observer after the installed observers.
func (s *FolderSpace) AddItemObserver(observer ItemObserver) {
	for {
		current := s.observers.Load()
		var next []ItemObserver
		if current != nil {
			next = slices.Clone(*current)
		}
		next = append(next, observer)
		if s.observers.CompareAndSwap(current, &next) {
			return
		}
	}
}

func (s *FolderSpace) itemObservers() []ItemObserver {
	if current := s.observers.Load(); current != nil {
		return *current
	}
	return nil
}

func (s *FolderSpace) written(ctx context.Context, access service.AccessContext, item model.Item, err error) (model.Item, error) {
	if err == nil {
		for _, observer := range s.itemObservers() {
			observer.ItemWritten(ctx, access, item)
		}
	}
	return item, err
}

func (s *FolderSpace) removed(ctx context.Context, access service.AccessContext, itemID string, err error) {
	if err == nil {
		for _, observer := range s.itemObservers() {
			observer.ItemRemoved(ctx, access, itemID)
		}
	}
}

// relocated runs a move or copy between the move observers' before and
// after callbacks.
func (s *FolderSpace) relocated(ctx context.Context, access service.AccessContext, itemID, destinationFolderID string, copied bool, relocate func() (model.Item, error)) (model.Item, error) {
	var after []func(context.Context, model.Item)
	for _, observer := range s.itemObservers() {
		if mover, ok := observer.(ItemMoveObserver); ok {
			if callback := mover.ItemMoving(ctx, access, itemID, destinationFolderID, copied); callback != nil {
				after = append(after, callback)
			}
		}
	}
	item, err := relocate()
	if err == nil {
		for _, callback := range after {
			callback(ctx, item)
		}
	}
	return item, err
}

func (s *FolderSpace) MoveItem(ctx context.Context, access service.AccessContext, itemID, destinationFolderID, name string) (model.Item, error) {
	return s.relocated(ctx, access, itemID, destinationFolderID, false, func() (model.Item, error) {
		return s.FolderSpace.MoveItem(ctx, access, itemID, destinationFolderID, name)
	})
}

func (s *FolderSpace) CopyItem(ctx context.Context, access service.AccessContext, itemID, destinationFolderID, name string) (model.Item, error) {
	return s.relocated(ctx, access, itemID, destinationFolderID, true, func() (model.Item, error) {
		return s.FolderSpace.CopyItem(ctx, access, itemID, destinationFolderID, name)
	})
}

func NewFolderSpace(next service.FolderSpace, engine *Engine) (*FolderSpace, error) {
	if next == nil || engine == nil {
		return nil, errors.New("automation FolderSpace requires delegate and engine")
	}
	return &FolderSpace{FolderSpace: next, engine: engine}, nil
}

func (s *FolderSpace) CreateItem(ctx context.Context, access service.AccessContext, folderID string, input service.ItemInput) (model.Item, error) {
	item, err := s.FolderSpace.CreateItem(ctx, access, folderID, input)
	if err != nil {
		return model.Item{}, err
	}
	return s.written(ctx, access, s.engine.Apply(ctx, access, item), nil)
}

func (s *FolderSpace) UpdateItem(ctx context.Context, access service.AccessContext, itemID string, data []byte, headers map[string]string) (model.Item, error) {
	item, err := s.FolderSpace.UpdateItem(ctx, access, itemID, data, headers)
	return s.written(ctx, access, item, err)
}

func (s *FolderSpace) DeleteItem(ctx context.Context, access service.AccessContext, itemID string) error {
	err := s.FolderSpace.DeleteItem(ctx, access, itemID)
	s.removed(ctx, access, itemID, err)
	return err
}

func (s *FolderSpace) CreateItems(ctx context.Context, access service.AccessContext, folderID string, inputs []service.ItemInput) ([]model.Item, error) {
	creator, ok := s.FolderSpace.(service.FolderItemBatchCreator)
	if !ok {
		return nil, errors.New("atomic multi-item creation is unavailable")
	}
	items, err := creator.CreateItems(ctx, access, folderID, inputs)
	if err != nil {
		return nil, err
	}
	for index := range items {
		items[index], _ = s.written(ctx, access, s.engine.Apply(ctx, access, items[index]), nil)
	}
	return items, nil
}

func (s *FolderSpace) UpdateItemIfModSeq(ctx context.Context, access service.AccessContext, itemID string, expected uint64, data []byte, headers map[string]string) (model.Item, error) {
	updater, ok := s.FolderSpace.(service.ConditionalItemUpdater)
	if !ok {
		return model.Item{}, errors.New("conditional item update is unavailable")
	}
	item, err := updater.UpdateItemIfModSeq(ctx, access, itemID, expected, data, headers)
	return s.written(ctx, access, item, err)
}

func (s *FolderSpace) ListItemPage(ctx context.Context, access service.AccessContext, folderID string, query service.ItemPageQuery) (service.ItemPage, error) {
	pager, ok := s.FolderSpace.(service.FolderItemPager)
	if !ok {
		return service.ItemPage{}, errors.New("bounded item paging is unavailable")
	}
	return pager.ListItemPage(ctx, access, folderID, query)
}

func (s *FolderSpace) Batch(ctx context.Context, fn func(context.Context) error) error {
	return service.Batch(ctx, s.FolderSpace, fn)
}

func (s *FolderSpace) ListTrash(ctx context.Context, access service.AccessContext) ([]service.ItemSummary, error) {
	recovery, ok := s.FolderSpace.(service.RecoverableFolderSpace)
	if !ok {
		return nil, errors.New("item recovery is unavailable")
	}
	return recovery.ListTrash(ctx, access)
}

func (s *FolderSpace) ListTrashedFolders(ctx context.Context, access service.AccessContext) ([]model.Folder, error) {
	recovery, ok := s.FolderSpace.(service.RecoverableFolderSpace)
	if !ok {
		return nil, errors.New("folder recovery is unavailable")
	}
	return recovery.ListTrashedFolders(ctx, access)
}

func (s *FolderSpace) RestoreFolder(ctx context.Context, access service.AccessContext, id string) (model.Folder, error) {
	recovery, ok := s.FolderSpace.(service.RecoverableFolderSpace)
	if !ok {
		return model.Folder{}, errors.New("folder recovery is unavailable")
	}
	return recovery.RestoreFolder(ctx, access, id)
}

func (s *FolderSpace) PurgeFolder(ctx context.Context, access service.AccessContext, id string) error {
	recovery, ok := s.FolderSpace.(service.RecoverableFolderSpace)
	if !ok {
		return errors.New("folder recovery is unavailable")
	}
	return recovery.PurgeFolder(ctx, access, id)
}

func (s *FolderSpace) TrashItem(ctx context.Context, access service.AccessContext, id string) (model.Item, error) {
	recovery, ok := s.FolderSpace.(service.RecoverableFolderSpace)
	if !ok {
		return model.Item{}, errors.New("item recovery is unavailable")
	}
	item, err := recovery.TrashItem(ctx, access, id)
	s.removed(ctx, access, id, err)
	return item, err
}

func (s *FolderSpace) RestoreItem(ctx context.Context, access service.AccessContext, id string) (model.Item, error) {
	recovery, ok := s.FolderSpace.(service.RecoverableFolderSpace)
	if !ok {
		return model.Item{}, errors.New("item recovery is unavailable")
	}
	item, err := recovery.RestoreItem(ctx, access, id)
	return s.written(ctx, access, item, err)
}

func (s *FolderSpace) CurrentChangeState(ctx context.Context, access service.AccessContext, scope service.ChangeScope) (string, error) {
	reader, ok := s.FolderSpace.(service.FolderChangeReader)
	if !ok {
		return "", errors.New("incremental changes are unavailable")
	}
	return reader.CurrentChangeState(ctx, access, scope)
}

func (s *FolderSpace) ListChanges(ctx context.Context, access service.AccessContext, scope service.ChangeScope, state string, limit int) (service.ChangePage, error) {
	reader, ok := s.FolderSpace.(service.FolderChangeReader)
	if !ok {
		return service.ChangePage{}, errors.New("incremental changes are unavailable")
	}
	return reader.ListChanges(ctx, access, scope, state, limit)
}

// OnChangesCommitted forwards service.FolderChangeNotifier to the wrapped
// space.
func (s *FolderSpace) OnChangesCommitted(listener func(accountID string, folderIDs []string)) func() {
	notifier, ok := s.FolderSpace.(service.FolderChangeNotifier)
	if !ok {
		return func() {}
	}
	return notifier.OnChangesCommitted(listener)
}

func (s *FolderSpace) GetItemHistoryPolicy(ctx context.Context, access service.AccessContext, folderID string) (model.ItemHistoryPolicy, error) {
	history, ok := s.FolderSpace.(service.ItemHistoryFolderSpace)
	if !ok {
		return model.ItemHistoryPolicy{}, service.ErrItemHistoryUnavailable
	}
	return history.GetItemHistoryPolicy(ctx, access, folderID)
}

func (s *FolderSpace) ConfigureItemHistory(ctx context.Context, access service.AccessContext, folderID string, policy model.ItemHistoryPolicy) (model.Folder, error) {
	history, ok := s.FolderSpace.(service.ItemHistoryFolderSpace)
	if !ok {
		return model.Folder{}, service.ErrItemHistoryUnavailable
	}
	return history.ConfigureItemHistory(ctx, access, folderID, policy)
}

func (s *FolderSpace) ListItemVersions(ctx context.Context, access service.AccessContext, folderID, itemID string) ([]model.ItemVersion, error) {
	history, ok := s.FolderSpace.(service.ItemHistoryFolderSpace)
	if !ok {
		return nil, service.ErrItemHistoryUnavailable
	}
	return history.ListItemVersions(ctx, access, folderID, itemID)
}

func (s *FolderSpace) GetItemVersion(ctx context.Context, access service.AccessContext, folderID, itemID, versionID string) (model.ItemVersion, error) {
	history, ok := s.FolderSpace.(service.ItemHistoryFolderSpace)
	if !ok {
		return model.ItemVersion{}, service.ErrItemHistoryUnavailable
	}
	return history.GetItemVersion(ctx, access, folderID, itemID, versionID)
}

func (s *FolderSpace) RestoreItemVersion(ctx context.Context, access service.AccessContext, folderID, itemID, versionID string) (model.Item, error) {
	history, ok := s.FolderSpace.(service.ItemHistoryFolderSpace)
	if !ok {
		return model.Item{}, service.ErrItemHistoryUnavailable
	}
	item, err := history.RestoreItemVersion(ctx, access, folderID, itemID, versionID)
	return s.written(ctx, access, item, err)
}

func (s *FolderSpace) SetLegalHolds(checker service.LegalHoldChecker) {
	service.ConfigureLegalHolds(s.FolderSpace, checker)
}

func (s *FolderSpace) SetTrashRetentionDays(days int) {
	if configurable, ok := s.FolderSpace.(service.TrashRetentionConfigurer); ok {
		configurable.SetTrashRetentionDays(days)
	}
}

func (s *FolderSpace) SetChangeRetention(days, maxEntries int) {
	if configurable, ok := s.FolderSpace.(service.ChangeRetentionConfigurer); ok {
		configurable.SetChangeRetention(days, maxEntries)
	}
}
