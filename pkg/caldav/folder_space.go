package caldav

import (
	"context"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// folderSpaceStore keeps DAV's wire-format code independent of persistence.
// Its FolderStore/ItemStore-shaped views are intentionally package-private:
// every collection and object operation delegates to the shared FolderSpace.
type folderSpaceStore struct {
	users   *model.UserStore
	sharing *model.FolderStore
	space   service.FolderSpace
}

func (s *folderSpaceStore) UserStore() *model.UserStore { return s.users }
func (s *folderSpaceStore) FolderStore() *davFolders {
	return &davFolders{space: s.space, sharing: s.sharing}
}
func (s *folderSpaceStore) ItemStore() *davItems { return &davItems{space: s.space} }

type davFolders struct {
	space   service.FolderSpace
	sharing *model.FolderStore
}

func davAccess(ctx context.Context, subject string) service.AccessContext {
	actor, _ := ctx.Value(authenticatedUserKey{}).(string)
	if actor == "" {
		actor = subject
	}
	access := service.UserAccess(actor, "dav")
	if subject != "" && !strings.EqualFold(actor, subject) {
		access.Subject = model.PrincipalRef{Kind: model.PrincipalUser, ID: subject}
	}
	return access
}

func (s *davFolders) GetByPath(ctx context.Context, userID, path string) (model.Folder, error) {
	folder, err := s.space.GetFolderByOwnerPath(ctx, davAccess(ctx, ""), userID, path)
	return folder, noteDAVError(ctx, err)
}

func (s *davFolders) Get(ctx context.Context, id string) (model.Folder, error) {
	folder, err := s.space.GetFolder(ctx, davAccess(ctx, ""), id)
	return folder, noteDAVError(ctx, err)
}

func (s *davFolders) ListForUser(ctx context.Context, userID string) ([]model.Folder, error) {
	folders, err := s.space.ListFolders(ctx, davAccess(ctx, userID), service.FolderQuery{})
	if err != nil {
		return nil, noteDAVError(ctx, err)
	}
	result := make([]model.Folder, 0, len(folders))
	for _, folder := range folders {
		if strings.EqualFold(folder.UserID, userID) {
			result = append(result, folder)
		}
	}
	return result, nil
}

func (s *davFolders) Create(ctx context.Context, userID, path string, folderType model.FolderType, parentID string) error {
	name := path
	if slash := strings.LastIndex(path, "/"); slash >= 0 {
		name = path[slash+1:]
	}
	_, err := s.space.CreateFolder(ctx, davAccess(ctx, userID), name, folderType, parentID)
	return noteDAVError(ctx, err)
}

// Update changes a collection's display name, color, description, or order.
func (s *davFolders) Update(ctx context.Context, id string, update service.FolderUpdate) (model.Folder, error) {
	folder, err := s.space.UpdateFolder(ctx, davAccess(ctx, ""), id, update)
	return folder, noteDAVError(ctx, err)
}

func (s *davFolders) Delete(ctx context.Context, id string) error {
	return noteDAVError(ctx, s.space.DeleteFolder(ctx, davAccess(ctx, ""), id))
}

// DAV sharing properties are an authorization concern, not object storage.
// They remain on the canonical ACL compatibility layer while payload access
// goes exclusively through FolderSpace.
func (s *davFolders) ListACLForUser(ctx context.Context, userID string) (map[string]model.ACLEntry, error) {
	return s.sharing.ListACLForUser(ctx, userID)
}

func (s *davFolders) ListCalendarSharing(ctx context.Context, folderID string) ([]model.Sharee, error) {
	return s.sharing.ListCalendarSharing(ctx, folderID)
}

type davItems struct{ space service.FolderSpace }

func (s *davItems) List(ctx context.Context, folderID string) ([]string, error) {
	items, err := s.space.ListItems(ctx, davAccess(ctx, ""), folderID, service.ItemQuery{})
	if err != nil {
		return nil, noteDAVError(ctx, err)
	}
	ids := make([]string, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	return ids, nil
}

func (s *davItems) Get(ctx context.Context, id string) (model.Item, error) {
	if item, err := s.space.GetItem(ctx, davAccess(ctx, ""), id); err == nil {
		return item, nil
	} else {
		_ = noteDAVError(ctx, err)
	}
	folders, err := s.space.ListFolders(ctx, davAccess(ctx, ""), service.FolderQuery{})
	if err != nil {
		return model.Item{}, noteDAVError(ctx, err)
	}
	for _, folder := range folders {
		prefix := folder.ID + ":"
		if strings.HasPrefix(id, prefix) {
			item, err := s.space.GetItemByName(ctx, davAccess(ctx, ""), folder.ID, strings.TrimPrefix(id, prefix))
			return item, noteDAVError(ctx, err)
		}
	}
	item, err := s.space.GetItem(ctx, davAccess(ctx, ""), id)
	return item, noteDAVError(ctx, err)
}

func (s *davItems) SetItem(ctx context.Context, item model.Item) error {
	existing, err := s.Get(ctx, item.ID)
	if err == nil {
		_, err = s.space.UpdateItem(ctx, davAccess(ctx, ""), existing.ID, item.Data, item.Headers)
		if err == nil && len(item.Flags) > 0 {
			_, err = s.space.SetFlags(ctx, davAccess(ctx, ""), existing.ID, item.Flags)
		}
		return noteDAVError(ctx, err)
	}
	name := item.Name
	if name == "" {
		name = strings.TrimPrefix(item.ID, item.FolderID+":")
	}
	_, err = s.space.CreateItem(ctx, davAccess(ctx, ""), item.FolderID, service.ItemInput{
		Name: name, Data: item.Data, Headers: item.Headers, Flags: item.Flags, InternalDate: item.InternalDate,
	})
	return noteDAVError(ctx, err)
}

func (s *davItems) Delete(ctx context.Context, id string) error {
	item, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	return noteDAVError(ctx, s.space.DeleteItem(ctx, davAccess(ctx, ""), item.ID))
}

func (s *davItems) Move(ctx context.Context, id, destinationFolderID, destinationName string) (model.Item, error) {
	item, err := s.Get(ctx, id)
	if err != nil {
		return model.Item{}, err
	}
	moved, err := s.space.MoveItem(ctx, davAccess(ctx, ""), item.ID, destinationFolderID, destinationName)
	return moved, noteDAVError(ctx, err)
}
