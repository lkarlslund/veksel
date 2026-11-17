package jmap

import (
	"context"
	"errors"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// ModelDirectory exposes non-payload account metadata to JMAP. Mailbox and
// blob payloads intentionally remain behind service.FolderSpace.
type ModelDirectory struct{ users *model.UserStore }

func NewModelDirectory(ts *model.TypedStore) *ModelDirectory {
	return &ModelDirectory{users: ts.UserStore()}
}
func (d *ModelDirectory) ListAccounts(ctx context.Context) ([]model.User, error) {
	return d.users.List(ctx)
}
func (d *ModelDirectory) GetAccount(ctx context.Context, id string) (model.User, error) {
	return d.users.Get(ctx, id)
}

// ListIdentities lists the account's addresses; an account without any
// has no identities rather than being missing.
func (d *ModelDirectory) ListIdentities(ctx context.Context, id string) ([]model.EmailAddress, error) {
	addresses, err := d.users.ListEmailAddressesForUser(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return addresses, err
}
func (d *ModelDirectory) SetVacation(ctx context.Context, id string, enabled bool, start, end time.Time, subject, message string) error {
	return d.users.UpdateVacation(ctx, id, enabled, start, end, subject, message)
}
