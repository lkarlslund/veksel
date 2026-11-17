package backup

import (
	"context"
	"errors"
	"sync"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/keyring"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// AccountKeys returns the installation key ring of system as an account key
// wrapper, or nil when the store has none. A nil ring must not become a
// non-nil interface.
func AccountKeys(ctx context.Context, system store.Store) (account.KeyWrapper, error) {
	ring, err := keyring.LoadExisting(ctx, system)
	if err != nil || ring == nil {
		return nil, err
	}
	return ring, nil
}

// archiveKeys loads the key ring of an archived system store on first use,
// by restoring that store into a scratch directory. Verifying an archive of
// plaintext accounts therefore never pays for it.
type archiveKeys struct {
	once    sync.Once
	ring    account.KeyWrapper
	err     error
	restore func() (account.KeyWrapper, error)
}

func newArchiveKeys(ctx context.Context, staged *stagedInstallation, scratchDir string) *archiveKeys {
	return &archiveKeys{restore: func() (account.KeyWrapper, error) {
		scratch, err := jsonstore.New(scratchDir)
		if err != nil {
			return nil, err
		}
		defer func() { _ = scratch.Close() }()
		system, err := staged.open(installationSystemName)
		if err != nil {
			return nil, err
		}
		defer func() { _ = system.Close() }()
		if _, err := RestoreContext(ctx, scratch, system, Replace); err != nil {
			return nil, err
		}
		return AccountKeys(ctx, scratch)
	}}
}

func (k *archiveKeys) load() (account.KeyWrapper, error) {
	k.once.Do(func() {
		k.ring, k.err = k.restore()
		if k.err == nil && k.ring == nil {
			k.err = errors.New("archive holds encrypted accounts but its system store has no installation key ring")
		}
	})
	return k.ring, k.err
}

func (k *archiveKeys) SealSecret(purpose, id string, plaintext []byte) ([]byte, error) {
	ring, err := k.load()
	if err != nil {
		return nil, err
	}
	return ring.SealSecret(purpose, id, plaintext)
}

func (k *archiveKeys) OpenSecret(purpose, id string, sealed []byte) ([]byte, error) {
	ring, err := k.load()
	if err != nil {
		return nil, err
	}
	return ring.OpenSecret(purpose, id, sealed)
}
