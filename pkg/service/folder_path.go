package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// EnsureFolderPath resolves a folder path through FolderSpace, creating any
// missing path components. It is safe to retry after a partial completion or a
// concurrent creator: existing components are reused and never duplicated.
func EnsureFolderPath(ctx context.Context, space FolderSpace, access AccessContext, path string, folderType model.FolderType) (model.Folder, error) {
	cleanPath := strings.Trim(strings.TrimSpace(path), "/")
	if cleanPath == "" {
		return model.Folder{}, errors.New("folder path is required")
	}

	parts := strings.Split(cleanPath, "/")
	for _, part := range parts {
		if strings.TrimSpace(part) == "" || part == "." || part == ".." {
			return model.Folder{}, fmt.Errorf("invalid folder path %q", path)
		}
	}

	parentID := ""
	var current model.Folder
	for index, name := range parts {
		currentPath := strings.Join(parts[:index+1], "/")
		folder, err := space.GetFolderByPath(ctx, access, currentPath)
		if err == nil {
			if folder.Type != folderType {
				return model.Folder{}, fmt.Errorf("folder %q has type %q, want %q", currentPath, folder.Type, folderType)
			}
			current, parentID = folder, folder.ID
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return model.Folder{}, fmt.Errorf("resolve folder %q: %w", currentPath, err)
		}

		folder, err = space.CreateFolder(ctx, access, name, folderType, parentID)
		if err != nil {
			// A concurrent worker may have created the same component after
			// our lookup. Resolve it once before returning the create error.
			existing, getErr := space.GetFolderByPath(ctx, access, currentPath)
			if getErr != nil {
				return model.Folder{}, fmt.Errorf("create folder %q: %w", currentPath, err)
			}
			if existing.Type != folderType {
				return model.Folder{}, fmt.Errorf("folder %q has type %q, want %q", currentPath, existing.Type, folderType)
			}
			folder = existing
		}
		current, parentID = folder, folder.ID
	}
	return current, nil
}
