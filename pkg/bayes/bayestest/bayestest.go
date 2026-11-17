// Package bayestest provides fixtures for tests of the statistical spam
// classifier.
package bayestest

import (
	"context"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// Accounts gives every account its own temporary index store, as account
// generations do. It implements bayes.Accounts.
type Accounts struct {
	t      testing.TB
	mu     sync.Mutex
	stores map[string]store.Store
}

// NewAccounts returns account stores that close when the test ends, after
// any classifier created later in the test has closed.
func NewAccounts(t testing.TB) *Accounts {
	accounts := &Accounts{t: t, stores: make(map[string]store.Store)}
	t.Cleanup(accounts.close)
	return accounts
}

// WithIndex runs fn with userID's index store, creating it on first use.
func (a *Accounts) WithIndex(ctx context.Context, userID string, fn func(context.Context, store.Store) error) error {
	a.mu.Lock()
	index, ok := a.stores[userID]
	if !ok {
		var err error
		if index, err = pebblestore.New(a.t.TempDir()); err != nil {
			a.mu.Unlock()
			return err
		}
		a.stores[userID] = index
	}
	a.mu.Unlock()
	return fn(ctx, index)
}

func (a *Accounts) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, index := range a.stores {
		_ = index.Close()
	}
}
