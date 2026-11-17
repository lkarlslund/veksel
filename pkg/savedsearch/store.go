// Package savedsearch persists reusable backend-neutral search definitions as
// typed account-folder items. Executing one still re-enters the ordinary search
// service so current RBAC and folder visibility remain final.
package savedsearch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	searchengine "github.com/lkarlslund/veksel/pkg/search"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	MaxPerOwner = 100
	FolderPath  = model.FolderPathSavedSearch
)

var (
	ErrInvalid = errors.New("invalid saved search")
	ErrLimit   = errors.New("saved search limit reached")
)

// Definition is a durable named query. Cursor and page size are deliberately
// absent from retained execution state.
type Definition struct {
	ID        string              `json:"id"`
	OwnerID   string              `json:"owner_id"`
	Name      string              `json:"name"`
	Query     service.SearchQuery `json:"query"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}

// Store owns saved-search invariants on the shared FolderSpace boundary.
type Store struct {
	mu    sync.Mutex
	space service.FolderSpace
}

func New(space service.FolderSpace) *Store { return &Store{space: space} }

// SetFolderSpace follows the application's account-aware FolderSpace when the
// process finishes wiring account discovery.
func (s *Store) SetFolderSpace(space service.FolderSpace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.space = space
}

func (s *Store) Create(ctx context.Context, ownerID, name string, query service.SearchQuery) (Definition, error) {
	ownerID = normalizeOwner(ownerID)
	name, query, err := normalizeDefinition(ownerID, name, query)
	if err != nil {
		return Definition{}, err
	}
	id, err := newID()
	if err != nil {
		return Definition{}, fmt.Errorf("generate saved search ID: %w", err)
	}
	now := time.Now().UTC()
	definition := Definition{ID: id, OwnerID: ownerID, Name: name, Query: query, CreatedAt: now, UpdatedAt: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	space, err := s.folderSpace()
	if err != nil {
		return Definition{}, err
	}
	access := service.UserAccess(ownerID, "saved-search")
	folder, err := ensureFolder(ctx, space, access, ownerID)
	if err != nil {
		return Definition{}, err
	}
	if folder.ItemCount >= MaxPerOwner {
		return Definition{}, ErrLimit
	}
	data, err := json.Marshal(definition)
	if err != nil {
		return Definition{}, err
	}
	creator, ok := space.(service.ExclusiveItemCreator)
	if !ok {
		return Definition{}, errors.New("saved searches require exclusive FolderSpace item creation")
	}
	if _, err := creator.CreateItemIfAbsent(ctx, access, folder.ID, service.ItemInput{Name: itemName(id), Data: data, Headers: itemHeaders(definition)}); err != nil {
		return Definition{}, err
	}
	return definition, nil
}

func (s *Store) List(ctx context.Context, ownerID string) ([]Definition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	space, err := s.folderSpace()
	if err != nil {
		return nil, err
	}
	ownerID = normalizeOwner(ownerID)
	access := service.UserAccess(ownerID, "saved-search")
	folder, err := ensureFolder(ctx, space, access, ownerID)
	if err != nil {
		return nil, err
	}
	items, err := space.ListItems(ctx, access, folder.ID, service.ItemQuery{Limit: MaxPerOwner + 1})
	if err != nil {
		return nil, err
	}
	result := make([]Definition, 0, len(items))
	for _, item := range items {
		definition, err := decodeItem(ownerID, item)
		if err != nil {
			return nil, err
		}
		result = append(result, definition)
	}
	slices.SortFunc(result, compareDefinitions)
	return result, nil
}

func (s *Store) Get(ctx context.Context, ownerID, id string) (Definition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(ctx, normalizeOwner(ownerID), id)
}

func (s *Store) Update(ctx context.Context, ownerID, id, name string, query service.SearchQuery) (Definition, error) {
	ownerID = normalizeOwner(ownerID)
	name, query, err := normalizeDefinition(ownerID, name, query)
	if err != nil {
		return Definition{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space, err := s.folderSpace()
	if err != nil {
		return Definition{}, err
	}
	definition, item, err := s.getItemLocked(ctx, space, ownerID, id)
	if err != nil {
		return Definition{}, err
	}
	definition.Name, definition.Query, definition.UpdatedAt = name, query, time.Now().UTC()
	data, err := json.Marshal(definition)
	if err != nil {
		return Definition{}, err
	}
	if _, err := space.UpdateItem(ctx, service.UserAccess(ownerID, "saved-search"), item.ID, data, itemHeaders(definition)); err != nil {
		return Definition{}, err
	}
	return definition, nil
}

func (s *Store) Delete(ctx context.Context, ownerID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	space, err := s.folderSpace()
	if err != nil {
		return err
	}
	ownerID = normalizeOwner(ownerID)
	_, item, err := s.getItemLocked(ctx, space, ownerID, id)
	if err != nil {
		return err
	}
	return space.DeleteItem(ctx, service.UserAccess(ownerID, "saved-search"), item.ID)
}

func (s *Store) getLocked(ctx context.Context, ownerID, id string) (Definition, error) {
	space, err := s.folderSpace()
	if err != nil {
		return Definition{}, err
	}
	definition, _, err := s.getItemLocked(ctx, space, ownerID, id)
	return definition, err
}

func (s *Store) getItemLocked(ctx context.Context, space service.FolderSpace, ownerID, id string) (Definition, model.Item, error) {
	if !validID(id) {
		return Definition{}, model.Item{}, store.ErrNotFound
	}
	access := service.UserAccess(ownerID, "saved-search")
	folder, err := ensureFolder(ctx, space, access, ownerID)
	if err != nil {
		return Definition{}, model.Item{}, err
	}
	item, err := space.GetItemByName(ctx, access, folder.ID, itemName(id))
	if err != nil {
		return Definition{}, model.Item{}, err
	}
	definition, err := decodeItem(ownerID, item)
	return definition, item, err
}

func (s *Store) folderSpace() (service.FolderSpace, error) {
	if s.space == nil {
		return nil, errors.New("saved-search FolderSpace is unavailable")
	}
	return s.space, nil
}

func ensureFolder(ctx context.Context, space service.FolderSpace, access service.AccessContext, ownerID string) (model.Folder, error) {
	folder, err := space.GetFolderByOwnerPath(ctx, access, ownerID, FolderPath)
	if err == nil {
		if folder.Type != model.FolderTypeSavedSearch {
			return model.Folder{}, fmt.Errorf("%w: reserved folder has type %q", ErrInvalid, folder.Type)
		}
		return folder, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return model.Folder{}, err
	}
	folder, err = space.CreateFolder(ctx, access, FolderPath, model.FolderTypeSavedSearch, "")
	if errors.Is(err, store.ErrExists) {
		return space.GetFolderByOwnerPath(ctx, access, ownerID, FolderPath)
	}
	return folder, err
}

func decodeItem(ownerID string, item model.Item) (Definition, error) {
	var definition Definition
	if err := json.Unmarshal(item.Data, &definition); err != nil {
		return Definition{}, fmt.Errorf("%w: decode item %s: %v", ErrInvalid, item.ID, err)
	}
	wantedID := strings.TrimSuffix(item.Name, ".json")
	if definition.OwnerID != ownerID || definition.ID != wantedID || !validID(definition.ID) {
		return Definition{}, fmt.Errorf("%w: item identity mismatch", ErrInvalid)
	}
	return definition, nil
}

func itemHeaders(definition Definition) map[string]string {
	return map[string]string{"Content-Type": "application/vnd.veksel.saved-search+json", "Title": definition.Name}
}

func itemName(id string) string { return id + ".json" }

func compareDefinitions(left, right Definition) int {
	if compared := strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name)); compared != 0 {
		return compared
	}
	return strings.Compare(left.ID, right.ID)
}

func normalizeDefinition(ownerID, name string, query service.SearchQuery) (string, service.SearchQuery, error) {
	name = strings.TrimSpace(name)
	if ownerID == "" || name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 120 || len(name) > 512 {
		return "", service.SearchQuery{}, fmt.Errorf("%w: name is required and must be at most 120 characters", ErrInvalid)
	}
	query.AccountID = strings.ToLower(strings.TrimSpace(query.AccountID))
	query.Text = strings.TrimSpace(query.Text)
	query.Expression = strings.TrimSpace(query.Expression)
	query.Cursor = ""
	query.Limit = 0
	query.FolderIDs = cleanStrings(query.FolderIDs)
	types, err := cleanTypes(query.Types)
	if err != nil {
		return "", service.SearchQuery{}, err
	}
	query.Types = types
	if query.Sort == "" {
		query.Sort = "relevance"
	}
	if !slices.Contains([]string{"relevance", "date_desc", "date_asc", "name"}, query.Sort) {
		return "", service.SearchQuery{}, fmt.Errorf("%w: unsupported sort order", ErrInvalid)
	}
	if query.Text == "" && query.Expression == "" && query.Filter == nil && len(query.FolderIDs) == 0 && len(query.Types) == 0 && !query.IncludeTrash {
		return "", service.SearchQuery{}, fmt.Errorf("%w: query has no criteria", ErrInvalid)
	}
	if err := searchengine.ValidateQuery(query); err != nil {
		return "", service.SearchQuery{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return name, query, nil
}

func cleanStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func cleanTypes(values []model.FolderType) ([]model.FolderType, error) {
	seen := make(map[model.FolderType]struct{}, len(values))
	result := make([]model.FolderType, 0, len(values))
	for _, value := range values {
		value = model.FolderType(strings.TrimSpace(string(value)))
		if value == "" {
			continue
		}
		if !slices.Contains([]model.FolderType{model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts, model.FolderTypeFiles, model.FolderTypeNotes}, value) {
			return nil, fmt.Errorf("%w: unsupported item type %q", ErrInvalid, value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func normalizeOwner(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func validID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
