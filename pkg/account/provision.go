package account

import (
	"context"
	"errors"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Provisioner creates system users together with their default folder
// catalog and account storage, and keeps account manifests in step with
// their identities. A nil Manager limits it to the system store.
type Provisioner struct {
	TS      *model.TypedStore
	Manager *Manager
}

// Create stores user as a new account. A partially created account is
// rolled back so a retry starts clean.
func (p Provisioner) Create(ctx context.Context, user model.User) error {
	users := p.TS.UserStore()
	if err := users.CreateUser(ctx, user); err != nil {
		return err
	}
	if err := p.TS.FolderStore().CreateForUser(ctx, user.ID); err != nil {
		return errors.Join(err, users.Delete(ctx, user.ID))
	}
	if _, err := p.Sync(ctx, user.ID); err != nil {
		return errors.Join(err, p.rollback(ctx, user.ID))
	}
	return nil
}

// Sync records the user's current primary and addresses in its account
// manifest and reports whether account storage had to be created.
func (p Provisioner) Sync(ctx context.Context, userID string) (bool, error) {
	if p.Manager == nil {
		return false, nil
	}
	users := p.TS.UserStore()
	user, err := users.Get(ctx, userID)
	if err != nil {
		return false, err
	}
	identities, err := users.ListEmailAddressesForUser(ctx, userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	addresses := make([]string, 0, len(identities))
	primary := ""
	for _, identity := range identities {
		addresses = append(addresses, identity.ID)
		if identity.Primary {
			primary = identity.ID
		}
	}
	_, created, err := p.Manager.Ensure(ctx, user, primary, addresses)
	return created, err
}

// rollback removes a user created by Create together with its folders.
func (p Provisioner) rollback(ctx context.Context, userID string) error {
	var rollback error
	folders, err := p.TS.FolderStore().ListForUser(ctx, userID)
	if err == nil {
		for _, folder := range folders {
			rollback = errors.Join(rollback, p.TS.FolderStore().Delete(ctx, folder.ID))
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		rollback = errors.Join(rollback, err)
	}
	return errors.Join(rollback, p.TS.UserStore().Delete(ctx, userID))
}
