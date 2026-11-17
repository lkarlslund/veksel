// Package messagetemplate persists personal reusable mail content as typed
// account-folder items. It owns no backend and reaches data only through the
// shared FolderSpace boundary.
package messagetemplate

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
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	MaxPerOwner     = 100
	MaxNameRunes    = 120
	MaxSubjectRunes = 300
	MaxBodyBytes    = 256 << 10
	FolderPath      = model.FolderPathMailTemplate
)

var (
	ErrInvalid = errors.New("invalid message template")
	ErrLimit   = errors.New("message template limit reached")
)

// Definition is the safe user-authored content inserted into a composer.
// Addressing, identity, attachments, and delivery options are intentionally
// absent so applying a template cannot redirect or silently alter a message.
type Definition struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	mu    sync.Mutex
	space service.FolderSpace
}

func New(space service.FolderSpace) *Store { return &Store{space: space} }

func (s *Store) SetFolderSpace(space service.FolderSpace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.space = space
}

func (s *Store) Create(ctx context.Context, ownerID, name, subject, body string) (Definition, error) {
	ownerID = normalizeOwner(ownerID)
	name, subject, body, err := normalize(ownerID, name, subject, body)
	if err != nil {
		return Definition{}, err
	}
	id, err := newID()
	if err != nil {
		return Definition{}, fmt.Errorf("generate message template ID: %w", err)
	}
	now := time.Now().UTC()
	definition := Definition{ID: id, OwnerID: ownerID, Name: name, Subject: subject, Body: body, CreatedAt: now, UpdatedAt: now}

	s.mu.Lock()
	defer s.mu.Unlock()
	space, err := s.folderSpace()
	if err != nil {
		return Definition{}, err
	}
	access := service.UserAccess(ownerID, "message-template")
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
		return Definition{}, errors.New("message templates require exclusive FolderSpace item creation")
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
	access := service.UserAccess(ownerID, "message-template")
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
	space, err := s.folderSpace()
	if err != nil {
		return Definition{}, err
	}
	definition, _, err := getItem(ctx, space, normalizeOwner(ownerID), id)
	return definition, err
}

func (s *Store) Update(ctx context.Context, ownerID, id, name, subject, body string) (Definition, error) {
	ownerID = normalizeOwner(ownerID)
	name, subject, body, err := normalize(ownerID, name, subject, body)
	if err != nil {
		return Definition{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	space, err := s.folderSpace()
	if err != nil {
		return Definition{}, err
	}
	definition, item, err := getItem(ctx, space, ownerID, id)
	if err != nil {
		return Definition{}, err
	}
	definition.Name, definition.Subject, definition.Body, definition.UpdatedAt = name, subject, body, time.Now().UTC()
	data, err := json.Marshal(definition)
	if err != nil {
		return Definition{}, err
	}
	if _, err := space.UpdateItem(ctx, service.UserAccess(ownerID, "message-template"), item.ID, data, itemHeaders(definition)); err != nil {
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
	_, item, err := getItem(ctx, space, ownerID, id)
	if err != nil {
		return err
	}
	return space.DeleteItem(ctx, service.UserAccess(ownerID, "message-template"), item.ID)
}

func (s *Store) folderSpace() (service.FolderSpace, error) {
	if s.space == nil {
		return nil, errors.New("message-template FolderSpace is unavailable")
	}
	return s.space, nil
}

func ensureFolder(ctx context.Context, space service.FolderSpace, access service.AccessContext, ownerID string) (model.Folder, error) {
	folder, err := space.GetFolderByOwnerPath(ctx, access, ownerID, FolderPath)
	if err == nil {
		if folder.Type != model.FolderTypeMailTemplate {
			return model.Folder{}, fmt.Errorf("%w: reserved folder has type %q", ErrInvalid, folder.Type)
		}
		return folder, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return model.Folder{}, err
	}
	folder, err = space.CreateFolder(ctx, access, FolderPath, model.FolderTypeMailTemplate, "")
	if errors.Is(err, store.ErrExists) {
		return space.GetFolderByOwnerPath(ctx, access, ownerID, FolderPath)
	}
	return folder, err
}

func getItem(ctx context.Context, space service.FolderSpace, ownerID, id string) (Definition, model.Item, error) {
	if !validID(id) {
		return Definition{}, model.Item{}, store.ErrNotFound
	}
	access := service.UserAccess(ownerID, "message-template")
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

func normalize(ownerID, name, subject, body string) (string, string, string, error) {
	name, subject = strings.TrimSpace(name), strings.TrimSpace(subject)
	body = strings.ReplaceAll(body, "\r\n", "\n")
	if ownerID == "" || name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxNameRunes || len(name) > 512 {
		return "", "", "", fmt.Errorf("%w: name is required and must be at most %d characters", ErrInvalid, MaxNameRunes)
	}
	if !utf8.ValidString(subject) || utf8.RuneCountInString(subject) > MaxSubjectRunes || len(subject) > 998 || strings.ContainsAny(subject, "\r\n\x00") {
		return "", "", "", fmt.Errorf("%w: subject must be one line and at most %d characters", ErrInvalid, MaxSubjectRunes)
	}
	if !utf8.ValidString(body) || len(body) > MaxBodyBytes || strings.ContainsRune(body, 0) {
		return "", "", "", fmt.Errorf("%w: body must be valid text no larger than %d bytes", ErrInvalid, MaxBodyBytes)
	}
	if subject == "" && strings.TrimSpace(body) == "" {
		return "", "", "", fmt.Errorf("%w: subject or body is required", ErrInvalid)
	}
	return name, subject, body, nil
}

func normalizeOwner(ownerID string) string { return strings.ToLower(strings.TrimSpace(ownerID)) }

func itemHeaders(definition Definition) map[string]string {
	return map[string]string{"Content-Type": "application/vnd.veksel.message-template+json", "Title": definition.Name}
}

func itemName(id string) string { return id + ".json" }

func compareDefinitions(left, right Definition) int {
	if compared := strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name)); compared != 0 {
		return compared
	}
	return strings.Compare(left.ID, right.ID)
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
