package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/sieve"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	ScriptsFolderPath = "Sieve scripts"
	ActiveFlag        = "$veksel-sieve-active"
	MaxScriptBytes    = 1 << 20
	MaxScripts        = 128
)

var (
	ErrActive = errors.New("active script")
	ErrExists = errors.New("script already exists")
)

type ScriptInfo struct {
	Name   string
	Size   int64
	Active bool
}

// Repository persists named scripts exclusively through the authorized folder
// abstraction. Its mutex makes the single-active-script invariant atomic from
// the point of view of concurrent protocol sessions in this process.
type SieveRepository struct {
	space FolderSpace
	mu    sync.Mutex
}

func NewSieveRepository(space FolderSpace) *SieveRepository { return &SieveRepository{space: space} }

func (r *SieveRepository) Check(script string) error {
	if len(script) > MaxScriptBytes {
		return fmt.Errorf("script exceeds %d bytes", MaxScriptBytes)
	}
	p, err := sieve.NewParser(script)
	if err != nil {
		return err
	}
	_, err = p.Parse()
	return err
}

func (r *SieveRepository) List(ctx context.Context, userID string) ([]ScriptInfo, error) {
	access := UserAccess(userID, "managesieve")
	folder, err := r.folder(ctx, access)
	if err != nil {
		return nil, err
	}
	items, err := r.space.ListItems(ctx, access, folder.ID, ItemQuery{MetadataOnly: true})
	if err != nil {
		return nil, err
	}
	result := make([]ScriptInfo, 0, len(items))
	for _, item := range items {
		result = append(result, ScriptInfo{Name: item.Name, Size: item.Size, Active: slices.Contains(item.Flags, ActiveFlag)})
	}
	slices.SortFunc(result, func(a, b ScriptInfo) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}

func (r *SieveRepository) Get(ctx context.Context, userID, name string) (string, error) {
	if err := validateScriptName(name); err != nil {
		return "", err
	}
	access := UserAccess(userID, "managesieve")
	folder, err := r.folder(ctx, access)
	if err != nil {
		return "", err
	}
	item, err := r.space.GetItemByName(ctx, access, folder.ID, name)
	if err != nil {
		return "", err
	}
	return string(item.Data), nil
}

func (r *SieveRepository) Put(ctx context.Context, userID, name, script string) error {
	if err := validateScriptName(name); err != nil {
		return err
	}
	if err := r.Check(script); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	access := UserAccess(userID, "managesieve")
	folder, err := r.folder(ctx, access)
	if err != nil {
		return err
	}
	if _, err := r.space.GetItemByName(ctx, access, folder.ID, name); errors.Is(err, store.ErrNotFound) {
		items, listErr := r.space.ListItems(ctx, access, folder.ID, ItemQuery{MetadataOnly: true})
		if listErr != nil {
			return listErr
		}
		if len(items) >= MaxScripts {
			return fmt.Errorf("script limit %d reached", MaxScripts)
		}
	} else if err != nil {
		return err
	}
	_, err = r.space.CreateItem(ctx, access, folder.ID, ItemInput{Name: name, Data: []byte(script)})
	return err
}

func (r *SieveRepository) SetActive(ctx context.Context, userID, name string) error {
	if name != "" {
		if err := validateScriptName(name); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	access := UserAccess(userID, "managesieve")
	folder, err := r.folder(ctx, access)
	if err != nil {
		return err
	}
	items, err := r.space.ListItems(ctx, access, folder.ID, ItemQuery{MetadataOnly: true})
	if err != nil {
		return err
	}
	if name != "" && !slices.ContainsFunc(items, func(item model.Item) bool { return item.Name == name }) {
		return store.ErrNotFound
	}
	apply := func(batchCtx context.Context) error {
		for _, item := range items {
			flags := slices.DeleteFunc(slices.Clone(item.Flags), func(flag string) bool { return flag == ActiveFlag })
			if item.Name == name {
				flags = append(flags, ActiveFlag)
			}
			if !slices.Equal(flags, item.Flags) {
				if _, err := r.space.SetFlags(batchCtx, access, item.ID, flags); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if batcher, ok := r.space.(FolderSpaceBatcher); ok {
		return batcher.Batch(ctx, apply)
	}
	return apply(ctx)
}

func (r *SieveRepository) Active(ctx context.Context, userID string) (string, bool, error) {
	access := UserAccess(userID, "smtp")
	folder, err := r.folder(ctx, access)
	if err != nil {
		return "", false, err
	}
	items, err := r.space.ListItems(ctx, access, folder.ID, ItemQuery{})
	if err != nil {
		return "", false, err
	}
	for _, item := range items {
		if slices.Contains(item.Flags, ActiveFlag) {
			return string(item.Data), true, nil
		}
	}
	return "", false, nil
}

func (r *SieveRepository) Delete(ctx context.Context, userID, name string) error {
	if err := validateScriptName(name); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	access := UserAccess(userID, "managesieve")
	folder, err := r.folder(ctx, access)
	if err != nil {
		return err
	}
	item, err := r.space.GetItemByName(ctx, access, folder.ID, name)
	if err != nil {
		return err
	}
	if slices.Contains(item.Flags, ActiveFlag) {
		return ErrActive
	}
	return r.space.DeleteItem(ctx, access, item.ID)
}

func (r *SieveRepository) Rename(ctx context.Context, userID, oldName, newName string) error {
	if err := validateScriptName(oldName); err != nil {
		return err
	}
	if err := validateScriptName(newName); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	access := UserAccess(userID, "managesieve")
	folder, err := r.folder(ctx, access)
	if err != nil {
		return err
	}
	if _, err := r.space.GetItemByName(ctx, access, folder.ID, newName); err == nil {
		return ErrExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	item, err := r.space.GetItemByName(ctx, access, folder.ID, oldName)
	if err != nil {
		return err
	}
	_, err = r.space.MoveItem(ctx, access, item.ID, folder.ID, newName)
	return err
}

func (r *SieveRepository) folder(ctx context.Context, access AccessContext) (model.Folder, error) {
	folder, err := r.space.GetFolderByPath(ctx, access, ScriptsFolderPath)
	if err == nil {
		if folder.Type != model.FolderTypeSieve {
			return model.Folder{}, errors.New("Sieve scripts path has incompatible folder type")
		}
		return folder, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return model.Folder{}, err
	}
	return r.space.CreateFolder(ctx, access, ScriptsFolderPath, model.FolderTypeSieve, "")
}

func validateScriptName(name string) error {
	if name == "" || !utf8.ValidString(name) || len(name) > 512 || utf8.RuneCountInString(name) > 128 {
		return errors.New("invalid script name")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("script name contains a control character")
		}
	}
	return nil
}
