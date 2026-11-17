package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

var journalLogger = log.For(log.ModuleQueue)

const folderCommandPrefix = "folder-command/"
const rejectedFolderCommandPrefix = "folder-command-rejected/"
const commandIDHeader = "X-Veksel-Command-ID"
const commandExternalNamespace = "veksel.folder-command"
const folderCommandCompressionThreshold = 4 << 10

// largeFolderCommandSize is the encoded command size above which deleting the
// journal entry also compacts the journal range: a deleted multi-megabyte
// value otherwise stays readable to the LSM engine and slows neighbouring scans.
const largeFolderCommandSize = 1 << 20

var folderCommandCompressedMagic = []byte("VEKSEL-FOLDER-COMMAND-ZSTD-1\x00")

// CommandIDHeader identifies internal replay metadata so presentation adapters
// can exclude it without duplicating the literal.
func CommandIDHeader() string { return commandIDHeader }

var folderCommandEncoder = sync.OnceValues(func() (*zstd.Encoder, error) {
	return zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1))
})

var folderCommandDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
	return zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
})

type folderCommand struct {
	ID                  string                  `json:"id"`
	Operation           string                  `json:"operation"`
	Access              AccessContext           `json:"access"`
	FolderID            string                  `json:"folder_id,omitempty"`
	ParentID            string                  `json:"parent_id,omitempty"`
	DestinationFolderID string                  `json:"destination_folder_id,omitempty"`
	ItemID              string                  `json:"item_id,omitempty"`
	Name                string                  `json:"name,omitempty"`
	FolderType          model.FolderType        `json:"folder_type,omitempty"`
	Item                ItemInput               `json:"item,omitempty"`
	Items               []ItemInput             `json:"items,omitempty"`
	Data                []byte                  `json:"data,omitempty"`
	Headers             map[string]string       `json:"headers,omitempty"`
	Flags               []string                `json:"flags,omitempty"`
	ExternalNamespace   string                  `json:"external_namespace,omitempty"`
	ExternalID          string                  `json:"external_id,omitempty"`
	FolderUpdate        FolderUpdate            `json:"folder_update,omitempty"`
	HistoryPolicy       model.ItemHistoryPolicy `json:"history_policy,omitempty"`
	VersionID           string                  `json:"version_id,omitempty"`
	ExpectedModSeq      uint64                  `json:"expected_mod_seq,omitempty"`
	CreatedAt           time.Time               `json:"created_at"`
}

type rejectedFolderCommand struct {
	Command  folderCommand `json:"command"`
	Error    string        `json:"error"`
	FailedAt time.Time     `json:"failed_at"`
}

// DurableFolderSpace journals every mutation in the same generic disk store
// used by the system queue, then applies it through the authorized FolderSpace.
// Reads are delegated unchanged.
type DurableFolderSpace struct {
	backend store.Store
	next    FolderSpace
	mu      sync.Mutex
	// compacting coalesces journal compactions requested while one runs, and
	// compactions tracks the running one so Close can wait for it.
	compacting  atomic.Bool
	compactions sync.WaitGroup
}

// Close waits for a background journal compaction to finish. Call it before
// closing the backend store.
func (s *DurableFolderSpace) Close() {
	s.compactions.Wait()
}

func (s *DurableFolderSpace) SetLegalHolds(checker LegalHoldChecker) {
	if configurable, ok := s.next.(LegalHoldConfigurer); ok {
		configurable.SetLegalHolds(checker)
	}
}

func (s *DurableFolderSpace) SetTrashRetentionDays(days int) {
	if configurable, ok := s.next.(TrashRetentionConfigurer); ok {
		configurable.SetTrashRetentionDays(days)
	}
}

func (s *DurableFolderSpace) SetChangeRetention(days, maxEntries int) {
	if configurable, ok := s.next.(ChangeRetentionConfigurer); ok {
		configurable.SetChangeRetention(days, maxEntries)
	}
}

func (s *DurableFolderSpace) ListTrash(ctx context.Context, access AccessContext) ([]ItemSummary, error) {
	recovery, ok := s.next.(RecoverableFolderSpace)
	if !ok {
		return nil, errors.New("item recovery is unavailable")
	}
	return recovery.ListTrash(ctx, access)
}

func (s *DurableFolderSpace) ListTrashedFolders(ctx context.Context, access AccessContext) ([]model.Folder, error) {
	recovery, ok := s.next.(RecoverableFolderSpace)
	if !ok {
		return nil, errors.New("folder recovery is unavailable")
	}
	return recovery.ListTrashedFolders(ctx, access)
}

func (s *DurableFolderSpace) RestoreFolder(ctx context.Context, access AccessContext, folderID string) (model.Folder, error) {
	recovery, ok := s.next.(RecoverableFolderSpace)
	if !ok {
		return model.Folder{}, errors.New("folder recovery is unavailable")
	}
	return recovery.RestoreFolder(ctx, access, folderID)
}

func (s *DurableFolderSpace) PurgeFolder(ctx context.Context, access AccessContext, folderID string) error {
	recovery, ok := s.next.(RecoverableFolderSpace)
	if !ok {
		return errors.New("folder recovery is unavailable")
	}
	return recovery.PurgeFolder(ctx, access, folderID)
}

func (s *DurableFolderSpace) TrashItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	recovery, ok := s.next.(RecoverableFolderSpace)
	if !ok {
		return model.Item{}, errors.New("item recovery is unavailable")
	}
	return recovery.TrashItem(ctx, access, itemID)
}

func (s *DurableFolderSpace) RestoreItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	recovery, ok := s.next.(RecoverableFolderSpace)
	if !ok {
		return model.Item{}, errors.New("item recovery is unavailable")
	}
	return recovery.RestoreItem(ctx, access, itemID)
}

type durableBatchContextKey struct{}

func NewDurableFolderSpace(ctx context.Context, backend store.Store, next FolderSpace) (*DurableFolderSpace, error) {
	if backend == nil || next == nil {
		return nil, errors.New("durable folder space requires store and delegate")
	}
	exists, err := backend.NamespaceExists(ctx, model.NSQueue)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, model.NSQueue); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
	}
	space := &DurableFolderSpace{backend: backend, next: next}
	if err := space.replay(ctx); err != nil {
		return nil, fmt.Errorf("replay folder commands: %w", err)
	}
	// Reclaim journal entries deleted before this process started.
	space.compactJournal()
	return space, nil
}

func (s *DurableFolderSpace) AccountUsage(ctx context.Context, access AccessContext) (AccountUsage, error) {
	return s.next.AccountUsage(ctx, access)
}

func (s *DurableFolderSpace) ListFolders(ctx context.Context, access AccessContext, query FolderQuery) ([]model.Folder, error) {
	return s.next.ListFolders(ctx, access, query)
}
func (s *DurableFolderSpace) GetFolder(ctx context.Context, access AccessContext, id string) (model.Folder, error) {
	return s.next.GetFolder(ctx, access, id)
}
func (s *DurableFolderSpace) GetFolderByPath(ctx context.Context, access AccessContext, path string) (model.Folder, error) {
	return s.next.GetFolderByPath(ctx, access, path)
}
func (s *DurableFolderSpace) GetFolderByOwnerPath(ctx context.Context, access AccessContext, ownerID, path string) (model.Folder, error) {
	return s.next.GetFolderByOwnerPath(ctx, access, ownerID, path)
}
func (s *DurableFolderSpace) ListItems(ctx context.Context, access AccessContext, folderID string, query ItemQuery) ([]model.Item, error) {
	return s.next.ListItems(ctx, access, folderID, query)
}

func (s *DurableFolderSpace) ListItemPage(ctx context.Context, access AccessContext, folderID string, query ItemPageQuery) (ItemPage, error) {
	pager, ok := s.next.(FolderItemPager)
	if !ok {
		return ItemPage{}, errors.New("bounded item paging is unavailable")
	}
	return pager.ListItemPage(ctx, access, folderID, query)
}
func (s *DurableFolderSpace) GetItem(ctx context.Context, access AccessContext, id string) (model.Item, error) {
	return s.next.GetItem(ctx, access, id)
}
func (s *DurableFolderSpace) GetItemByUID(ctx context.Context, access AccessContext, folderID string, uid uint32) (model.Item, error) {
	return s.next.GetItemByUID(ctx, access, folderID, uid)
}
func (s *DurableFolderSpace) GetItemByName(ctx context.Context, access AccessContext, folderID, name string) (model.Item, error) {
	return s.next.GetItemByName(ctx, access, folderID, name)
}
func (s *DurableFolderSpace) GetItemByExternalID(ctx context.Context, access AccessContext, folderID, namespace, externalID string) (model.Item, error) {
	return s.next.GetItemByExternalID(ctx, access, folderID, namespace, externalID)
}
func (s *DurableFolderSpace) GetItemMetadataByExternalID(ctx context.Context, access AccessContext, folderID, namespace, externalID string) (model.Item, error) {
	return s.next.GetItemMetadataByExternalID(ctx, access, folderID, namespace, externalID)
}

func (s *DurableFolderSpace) itemHistory() (ItemHistoryFolderSpace, error) {
	history, ok := s.next.(ItemHistoryFolderSpace)
	if !ok {
		return nil, ErrItemHistoryUnavailable
	}
	return history, nil
}

func (s *DurableFolderSpace) GetItemHistoryPolicy(ctx context.Context, access AccessContext, folderID string) (model.ItemHistoryPolicy, error) {
	history, err := s.itemHistory()
	if err != nil {
		return model.ItemHistoryPolicy{}, err
	}
	return history.GetItemHistoryPolicy(ctx, access, folderID)
}

func (s *DurableFolderSpace) ListItemVersions(ctx context.Context, access AccessContext, folderID, itemID string) ([]model.ItemVersion, error) {
	history, err := s.itemHistory()
	if err != nil {
		return nil, err
	}
	return history.ListItemVersions(ctx, access, folderID, itemID)
}

func (s *DurableFolderSpace) GetItemVersion(ctx context.Context, access AccessContext, folderID, itemID, versionID string) (model.ItemVersion, error) {
	history, err := s.itemHistory()
	if err != nil {
		return model.ItemVersion{}, err
	}
	return history.GetItemVersion(ctx, access, folderID, itemID, versionID)
}

func (s *DurableFolderSpace) CurrentChangeState(ctx context.Context, access AccessContext, scope ChangeScope) (string, error) {
	reader, ok := s.next.(FolderChangeReader)
	if !ok {
		return "", errors.New("folder change history is unavailable")
	}
	return reader.CurrentChangeState(ctx, access, scope)
}

func (s *DurableFolderSpace) ListChanges(ctx context.Context, access AccessContext, scope ChangeScope, state string, limit int) (ChangePage, error) {
	reader, ok := s.next.(FolderChangeReader)
	if !ok {
		return ChangePage{}, errors.New("folder change history is unavailable")
	}
	return reader.ListChanges(ctx, access, scope, state, limit)
}

// OnChangesCommitted forwards FolderChangeNotifier to the wrapped space.
func (s *DurableFolderSpace) OnChangesCommitted(listener func(accountID string, folderIDs []string)) func() {
	notifier, ok := s.next.(FolderChangeNotifier)
	if !ok {
		return func() {}
	}
	return notifier.OnChangesCommitted(listener)
}

// Batch commits a related set of folder operations as one durable store
// transaction when the configured backend supports it.
func (s *DurableFolderSpace) Batch(ctx context.Context, fn func(context.Context) error) error {
	if activeBatch(ctx, s) {
		return fn(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	batchCtx := context.WithValue(ctx, durableBatchContextKey{}, s)
	return store.Batch(batchCtx, s.backend, fn)
}

func (s *DurableFolderSpace) CreateFolder(ctx context.Context, access AccessContext, name string, folderType model.FolderType, parentID string) (model.Folder, error) {
	command := folderCommand{Operation: "create-folder", Access: access, Name: name, FolderType: folderType, ParentID: parentID}
	result, err := s.execute(ctx, &command)
	return result.Folder, err
}

func (s *DurableFolderSpace) MoveFolder(ctx context.Context, access AccessContext, folderID, parentID, name string) (model.Folder, error) {
	command := folderCommand{Operation: "move-folder", Access: access, FolderID: folderID, ParentID: parentID, Name: name}
	result, err := s.execute(ctx, &command)
	return result.Folder, err
}

func (s *DurableFolderSpace) UpdateFolder(ctx context.Context, access AccessContext, folderID string, update FolderUpdate) (model.Folder, error) {
	command := folderCommand{Operation: "update-folder", Access: access, FolderID: folderID, FolderUpdate: update}
	result, err := s.execute(ctx, &command)
	return result.Folder, err
}

func (s *DurableFolderSpace) ConfigureItemHistory(ctx context.Context, access AccessContext, folderID string, policy model.ItemHistoryPolicy) (model.Folder, error) {
	command := folderCommand{Operation: "configure-item-history", Access: access, FolderID: folderID, HistoryPolicy: policy}
	result, err := s.execute(ctx, &command)
	return result.Folder, err
}

func (s *DurableFolderSpace) DeleteFolder(ctx context.Context, access AccessContext, folderID string) error {
	_, err := s.execute(ctx, &folderCommand{Operation: "delete-folder", Access: access, FolderID: folderID})
	return err
}

func (s *DurableFolderSpace) CreateItem(ctx context.Context, access AccessContext, folderID string, input ItemInput) (model.Item, error) {
	command := folderCommand{Operation: "create-item", Access: access, FolderID: folderID, Item: input}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

func (s *DurableFolderSpace) CreateItems(ctx context.Context, access AccessContext, folderID string, inputs []ItemInput) ([]model.Item, error) {
	command := folderCommand{Operation: "create-items", Access: access, FolderID: folderID, Items: inputs}
	result, err := s.execute(ctx, &command)
	return result.Items, err
}

func (s *DurableFolderSpace) CreateItemIfAbsent(ctx context.Context, access AccessContext, folderID string, input ItemInput) (model.Item, error) {
	command := folderCommand{Operation: "create-item-if-absent", Access: access, FolderID: folderID, Item: input}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

func (s *DurableFolderSpace) BindItemExternalID(ctx context.Context, access AccessContext, itemID, namespace, externalID string) (model.Item, error) {
	command := folderCommand{Operation: "bind-item-external-id", Access: access, ItemID: itemID, ExternalNamespace: namespace, ExternalID: externalID}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

func (s *DurableFolderSpace) UpdateItem(ctx context.Context, access AccessContext, itemID string, data []byte, headers map[string]string) (model.Item, error) {
	command := folderCommand{Operation: "update-item", Access: access, ItemID: itemID, Data: data, Headers: headers}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

func (s *DurableFolderSpace) UpdateItemIfModSeq(ctx context.Context, access AccessContext, itemID string, expected uint64, data []byte, headers map[string]string) (model.Item, error) {
	command := folderCommand{Operation: "update-item-if-modseq", Access: access, ItemID: itemID, ExpectedModSeq: expected, Data: data, Headers: headers}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

func (s *DurableFolderSpace) SetFlags(ctx context.Context, access AccessContext, itemID string, flags []string) (model.Item, error) {
	command := folderCommand{Operation: "set-flags", Access: access, ItemID: itemID, Flags: flags}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

func (s *DurableFolderSpace) MoveItem(ctx context.Context, access AccessContext, itemID, destinationFolderID, name string) (model.Item, error) {
	command := folderCommand{Operation: "move-item", Access: access, ItemID: itemID, DestinationFolderID: destinationFolderID, Name: name}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

func (s *DurableFolderSpace) CopyItem(ctx context.Context, access AccessContext, itemID, destinationFolderID, name string) (model.Item, error) {
	command := folderCommand{Operation: "copy-item", Access: access, ItemID: itemID, DestinationFolderID: destinationFolderID, Name: name}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

func (s *DurableFolderSpace) DeleteItem(ctx context.Context, access AccessContext, itemID string) error {
	_, err := s.execute(ctx, &folderCommand{Operation: "delete-item", Access: access, ItemID: itemID})
	return err
}

func (s *DurableFolderSpace) RestoreItemVersion(ctx context.Context, access AccessContext, folderID, itemID, versionID string) (model.Item, error) {
	command := folderCommand{Operation: "restore-item-version", Access: access, FolderID: folderID, ItemID: itemID, VersionID: versionID}
	result, err := s.execute(ctx, &command)
	return result.Item, err
}

type commandResult struct {
	Folder model.Folder
	Item   model.Item
	Items  []model.Item
}

func (s *DurableFolderSpace) execute(ctx context.Context, command *folderCommand) (commandResult, error) {
	if !activeBatch(ctx, s) {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if command.ID == "" {
		id, err := folderCommandID()
		if err != nil {
			return commandResult{}, err
		}
		command.ID = id
		command.CreatedAt = time.Now().UTC()
	}
	data, err := encodeFolderCommand(*command)
	if err != nil {
		return commandResult{}, err
	}
	key := folderCommandPrefix + command.ID
	if err := s.backend.Put(ctx, model.NSQueue, key, data); err != nil && !errors.Is(err, store.ErrExists) {
		return commandResult{}, fmt.Errorf("persist folder command: %w", err)
	}
	result, err := s.apply(ctx, *command, false)
	if err != nil {
		if isPermanentCommandError(err) {
			if rejectErr := s.reject(ctx, key, *command, err); rejectErr != nil {
				return commandResult{}, errors.Join(err, rejectErr)
			}
		}
		return commandResult{}, err
	}
	if err := s.backend.Delete(ctx, model.NSQueue, key); err != nil && !errors.Is(err, store.ErrNotFound) {
		return commandResult{}, fmt.Errorf("complete folder command: %w", err)
	}
	if len(data) >= largeFolderCommandSize {
		s.compactJournal()
	}
	return result, nil
}

// compactJournal compacts the folder command journal in the background when
// the store supports it, coalescing requests made while one is running.
func (s *DurableFolderSpace) compactJournal() {
	compactor, ok := s.backend.(store.Compactor)
	if !ok || !s.compacting.CompareAndSwap(false, true) {
		return
	}
	s.compactions.Add(1)
	go func() {
		defer s.compactions.Done()
		defer s.compacting.Store(false)
		if err := compactor.CompactPrefix(context.Background(), model.NSQueue, folderCommandPrefix); err != nil {
			journalLogger.Warn("compact folder command journal", "error", err)
		}
	}()
}

func activeBatch(ctx context.Context, space *DurableFolderSpace) bool {
	if ctx == nil {
		return false
	}
	active, _ := ctx.Value(durableBatchContextKey{}).(*DurableFolderSpace)
	return active == space
}

func (s *DurableFolderSpace) replay(ctx context.Context) error {
	keys, err := s.backend.Scan(ctx, model.NSQueue, folderCommandPrefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		data, err := s.backend.Get(ctx, model.NSQueue, key)
		if err != nil {
			return err
		}
		command, err := decodeFolderCommand(data)
		if err != nil {
			return fmt.Errorf("decode command %q: %w", key, err)
		}
		if _, err := s.apply(ctx, command, true); err != nil {
			if !isPermanentCommandError(err) {
				return fmt.Errorf("apply command %q: %w", key, err)
			}
			if rejectErr := s.reject(ctx, key, command, err); rejectErr != nil {
				return fmt.Errorf("reject command %q: %w", key, errors.Join(err, rejectErr))
			}
			continue
		}
		if err := s.backend.Delete(ctx, model.NSQueue, key); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

func encodeFolderCommand(command folderCommand) ([]byte, error) {
	raw, err := json.Marshal(command)
	if err != nil || len(raw) < folderCommandCompressionThreshold {
		return raw, err
	}
	encoder, err := folderCommandEncoder()
	if err != nil {
		return nil, fmt.Errorf("initialize folder command compressor: %w", err)
	}
	compressed := encoder.EncodeAll(raw, make([]byte, 0, len(raw)/2))
	if len(folderCommandCompressedMagic)+len(compressed) >= len(raw) {
		return raw, nil
	}
	framed := make([]byte, 0, len(folderCommandCompressedMagic)+len(compressed))
	framed = append(framed, folderCommandCompressedMagic...)
	return append(framed, compressed...), nil
}

func decodeFolderCommand(data []byte) (folderCommand, error) {
	var command folderCommand
	if !bytes.HasPrefix(data, folderCommandCompressedMagic) {
		return command, json.Unmarshal(data, &command)
	}
	decoder, err := folderCommandDecoder()
	if err != nil {
		return command, fmt.Errorf("initialize folder command decompressor: %w", err)
	}
	raw, err := decoder.DecodeAll(data[len(folderCommandCompressedMagic):], nil)
	if err != nil {
		return command, fmt.Errorf("decompress folder command: %w", err)
	}
	return command, json.Unmarshal(raw, &command)
}

func (s *DurableFolderSpace) reject(ctx context.Context, key string, command folderCommand, commandErr error) error {
	rejected := rejectedFolderCommand{
		Command:  command,
		Error:    commandErr.Error(),
		FailedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(rejected)
	if err != nil {
		return fmt.Errorf("encode rejected folder command: %w", err)
	}
	rejectedKey := rejectedFolderCommandPrefix + command.ID
	if err := s.backend.Set(ctx, model.NSQueue, rejectedKey, data); err != nil {
		return fmt.Errorf("persist rejected folder command: %w", err)
	}
	if err := s.backend.Delete(ctx, model.NSQueue, key); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("remove pending folder command: %w", err)
	}
	return nil
}

// isPermanentCommandError reports whether a failed folder command must be
// rejected rather than kept for replay. The caller was already told the
// command failed, so only infrastructure failures that a later attempt can
// overcome (an account lease or store briefly unavailable, a canceled
// request) stay journaled. Validation, authorization, quota, legal-hold and
// conflict errors fail identically on every replay; keeping them pending
// blocked every later start and could apply a mutation the client was told
// was refused.
func isPermanentCommandError(err error) bool {
	return !errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) &&
		!IsTemporarilyUnavailable(err)
}

func (s *DurableFolderSpace) apply(ctx context.Context, command folderCommand, replay bool) (commandResult, error) {
	switch command.Operation {
	case "create-folder":
		if existing, err := s.findFolder(ctx, command); err == nil {
			return commandResult{Folder: existing}, nil
		}
		folder, err := s.next.CreateFolder(ctx, command.Access, command.Name, command.FolderType, command.ParentID)
		return commandResult{Folder: folder}, err
	case "move-folder":
		folder, err := s.next.MoveFolder(ctx, command.Access, command.FolderID, command.ParentID, command.Name)
		return commandResult{Folder: folder}, err
	case "update-folder":
		folder, err := s.next.UpdateFolder(ctx, command.Access, command.FolderID, command.FolderUpdate)
		return commandResult{Folder: folder}, err
	case "configure-item-history":
		history, err := s.itemHistory()
		if err != nil {
			return commandResult{}, err
		}
		folder, err := history.ConfigureItemHistory(ctx, command.Access, command.FolderID, command.HistoryPolicy)
		return commandResult{Folder: folder}, err
	case "delete-folder":
		err := s.next.DeleteFolder(ctx, command.Access, command.FolderID)
		if errors.Is(err, store.ErrNotFound) {
			err = nil
		}
		return commandResult{}, err
	case "create-item":
		if existing, err := s.findCreatedItem(ctx, command, replay); err == nil {
			return commandResult{Item: existing}, nil
		}
		command.Item.Headers = copyStringMap(command.Item.Headers)
		command.Item.Headers[commandIDHeader] = command.ID
		command.Item.ExternalIDs = copyStringMap(command.Item.ExternalIDs)
		command.Item.ExternalIDs[commandExternalNamespace] = command.ID
		item, err := s.next.CreateItem(ctx, command.Access, command.FolderID, command.Item)
		return commandResult{Item: item}, err
	case "create-items":
		creator, ok := s.next.(FolderItemBatchCreator)
		if !ok {
			return commandResult{}, errors.New("atomic multi-item creation is unavailable")
		}
		items := make([]model.Item, len(command.Items))
		missingInputs := make([]ItemInput, 0, len(command.Items))
		missingIndexes := make([]int, 0, len(command.Items))
		for index, input := range command.Items {
			identity := fmt.Sprintf("%s/%d", command.ID, index)
			if replay {
				existing, findErr := s.next.GetItemByExternalID(ctx, command.Access, command.FolderID, commandExternalNamespace, identity)
				if findErr == nil {
					items[index] = existing
					continue
				}
				if !errors.Is(findErr, store.ErrNotFound) {
					return commandResult{}, findErr
				}
			}
			input.Headers = copyStringMap(input.Headers)
			input.Headers[commandIDHeader] = identity
			input.ExternalIDs = copyStringMap(input.ExternalIDs)
			input.ExternalIDs[commandExternalNamespace] = identity
			missingInputs = append(missingInputs, input)
			missingIndexes = append(missingIndexes, index)
		}
		if len(missingInputs) == 0 {
			return commandResult{Items: items}, nil
		}
		created, err := creator.CreateItems(ctx, command.Access, command.FolderID, missingInputs)
		if err != nil {
			return commandResult{}, err
		}
		for index, item := range created {
			items[missingIndexes[index]] = item
		}
		return commandResult{Items: items}, nil
	case "create-item-if-absent":
		if existing, err := s.findCreatedItem(ctx, command, replay); err == nil {
			return commandResult{Item: existing}, nil
		}
		creator, ok := s.next.(ExclusiveItemCreator)
		if !ok {
			return commandResult{}, errors.New("exclusive item creation is unavailable")
		}
		command.Item.Headers = copyStringMap(command.Item.Headers)
		command.Item.Headers[commandIDHeader] = command.ID
		command.Item.ExternalIDs = copyStringMap(command.Item.ExternalIDs)
		command.Item.ExternalIDs[commandExternalNamespace] = command.ID
		item, err := creator.CreateItemIfAbsent(ctx, command.Access, command.FolderID, command.Item)
		return commandResult{Item: item}, err
	case "update-item":
		item, err := s.next.UpdateItem(ctx, command.Access, command.ItemID, command.Data, command.Headers)
		return commandResult{Item: item}, err
	case "update-item-if-modseq":
		updater, ok := s.next.(ConditionalItemUpdater)
		if !ok {
			return commandResult{}, errors.New("conditional item update is unavailable")
		}
		if replay {
			current, err := s.next.GetItem(ctx, command.Access, command.ItemID)
			if err != nil {
				return commandResult{}, err
			}
			if current.Headers[commandIDHeader] == command.ID {
				return commandResult{Item: current}, nil
			}
		}
		command.Headers = copyStringMap(command.Headers)
		command.Headers[commandIDHeader] = command.ID
		item, err := updater.UpdateItemIfModSeq(ctx, command.Access, command.ItemID, command.ExpectedModSeq, command.Data, command.Headers)
		return commandResult{Item: item}, err
	case "bind-item-external-id":
		item, err := s.next.BindItemExternalID(ctx, command.Access, command.ItemID, command.ExternalNamespace, command.ExternalID)
		return commandResult{Item: item}, err
	case "set-flags":
		item, err := s.next.SetFlags(ctx, command.Access, command.ItemID, command.Flags)
		return commandResult{Item: item}, err
	case "move-item":
		item, err := s.next.MoveItem(ctx, command.Access, command.ItemID, command.DestinationFolderID, command.Name)
		return commandResult{Item: item}, err
	case "copy-item":
		if existing, err := s.findCreatedItem(ctx, command, replay); err == nil {
			return commandResult{Item: existing}, nil
		}
		source, err := s.next.GetItem(ctx, command.Access, command.ItemID)
		if err != nil {
			return commandResult{}, err
		}
		headers := copyStringMap(source.Headers)
		headers[commandIDHeader] = command.ID
		item, err := s.next.CreateItem(ctx, command.Access, command.DestinationFolderID, ItemInput{
			Name: command.Name, Data: source.Data, Headers: headers, Flags: source.Flags, InternalDate: source.InternalDate,
			ExternalIDs: map[string]string{commandExternalNamespace: command.ID},
		})
		return commandResult{Item: item}, err
	case "delete-item":
		err := s.next.DeleteItem(ctx, command.Access, command.ItemID)
		if errors.Is(err, store.ErrNotFound) {
			err = nil
		}
		return commandResult{}, err
	case "restore-item-version":
		if replay {
			if existing, findErr := s.next.GetItemByExternalID(ctx, command.Access, command.FolderID, commandExternalNamespace, command.ID); findErr == nil {
				return commandResult{Item: existing}, nil
			} else if !errors.Is(findErr, store.ErrNotFound) {
				return commandResult{}, findErr
			}
		}
		history, err := s.itemHistory()
		if err != nil {
			return commandResult{}, err
		}
		item, err := history.RestoreItemVersion(ctx, command.Access, command.FolderID, command.ItemID, command.VersionID)
		if err != nil {
			return commandResult{}, err
		}
		item, err = s.next.BindItemExternalID(ctx, command.Access, item.ID, commandExternalNamespace, command.ID)
		return commandResult{Item: item}, err
	default:
		return commandResult{}, fmt.Errorf("unknown folder command %q", command.Operation)
	}
}

func (s *DurableFolderSpace) findFolder(ctx context.Context, command folderCommand) (model.Folder, error) {
	folders, err := s.next.ListFolders(ctx, command.Access, FolderQuery{Type: command.FolderType})
	if err != nil {
		return model.Folder{}, err
	}
	for _, folder := range folders {
		if folder.ParentID == command.ParentID && strings.EqualFold(folder.Name, command.Name) {
			return folder, nil
		}
	}
	return model.Folder{}, store.ErrNotFound
}

func (s *DurableFolderSpace) findCreatedItem(ctx context.Context, command folderCommand, replay bool) (model.Item, error) {
	folderID := command.FolderID
	if command.Operation == "copy-item" {
		folderID = command.DestinationFolderID
	}
	item, err := s.next.GetItemByExternalID(ctx, command.Access, folderID, commandExternalNamespace, command.ID)
	if err == nil || !replay || !errors.Is(err, store.ErrNotFound) {
		return item, err
	}
	// Commands written by older versions, and commands interrupted between
	// storing their item and its identity index, can only be found by header.
	items, err := s.next.ListItems(ctx, command.Access, folderID, ItemQuery{})
	if err != nil {
		return model.Item{}, err
	}
	for _, item := range items {
		if item.Headers[commandIDHeader] == command.ID {
			return item, nil
		}
	}
	return model.Item{}, store.ErrNotFound
}

func copyStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input)+1)
	for key, value := range input {
		output[key] = value
	}
	return output
}

func folderCommandID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
