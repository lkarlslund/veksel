package service

import (
	"context"
	"errors"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// CreateItemIdempotent creates an item once for a stable producer identity.
// A retry after an acknowledgement loss resolves and returns the prior commit.
func CreateItemIdempotent(ctx context.Context, space FolderSpace, access AccessContext, folderID, namespace, externalID string, input ItemInput) (model.Item, error) {
	if input.ExternalIDs == nil {
		input.ExternalIDs = make(map[string]string, 1)
	}
	input.ExternalIDs[namespace] = externalID
	item, err := space.CreateItem(ctx, access, folderID, input)
	if !errors.Is(err, store.ErrExists) {
		return item, err
	}
	return space.GetItemByExternalID(ctx, access, folderID, namespace, externalID)
}
