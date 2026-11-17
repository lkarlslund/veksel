package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Durable JMAP state. EmailSubmission and PushSubscription records live in
// the owning account's own index store, so they follow the account through
// moves, conversion, export and encryption at rest, and vanish with it on
// purge. A small system-store index names the accounts holding such
// records, so the background sweep and push resumption after a restart do
// not have to open every account.

var logger = log.For(log.ModuleJMAP)

const (
	// stateNamespace holds the records in each account's index store.
	stateNamespace = "jmap"
	// stateIndexNamespace lists, in the system store, the accounts that
	// hold records: "push/<user>" and "submission/<account>".
	stateIndexNamespace = "jmap_state_index"

	submissionPrefix       = "submission/"
	submissionChangePrefix = "submission-change/"
	submissionStateKey     = "submission-state"
	pushPrefix             = "push/"

	indexPushPrefix       = "push/"
	indexSubmissionPrefix = "submission/"

	// maxSubmissionChanges bounds the EmailSubmission change log kept for
	// /changes; older entries are pruned and the floor raised.
	maxSubmissionChanges = 10_000
	// DefaultSubmissionRetention is how long EmailSubmission history and
	// its change log are kept; it follows change_history_retention_days.
	DefaultSubmissionRetention = 90 * 24 * time.Hour
)

// AccountStores opens an account's own index store (encrypted at rest when
// the account is) for the duration of fn. It returns store.ErrNotFound when
// the account has no storage.
type AccountStores interface {
	WithIndex(ctx context.Context, accountID string, fn func(context.Context, store.Store) error) error
}

// errNoState reports that an account has never stored JMAP records.
var errNoState = errors.New("no jmap state")

// withState runs fn against the account's JMAP namespace. A read of an
// account without records, or without storage, runs nothing and succeeds;
// a write creates the namespace first.
func (h *Handler) withState(ctx context.Context, accountID string, write bool, fn func(context.Context, store.Store) error) error {
	err := h.cfg.Accounts.WithIndex(ctx, accountID, func(ctx context.Context, index store.Store) error {
		exists, err := index.NamespaceExists(ctx, stateNamespace)
		if err != nil {
			return err
		}
		if !exists {
			if !write {
				return errNoState
			}
			if err := index.CreateNamespace(ctx, stateNamespace); err != nil && !errors.Is(err, store.ErrExists) {
				return err
			}
		}
		return fn(ctx, index)
	})
	if errors.Is(err, errNoState) || (!write && errors.Is(err, store.ErrNotFound)) {
		return nil
	}
	return err
}

func getJSON(ctx context.Context, s store.Store, key string, value any) (bool, error) {
	data, err := s.Get(ctx, stateNamespace, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return false, fmt.Errorf("decode jmap state %s: %w", key, err)
	}
	return true, nil
}

func setJSON(ctx context.Context, s store.Store, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.Set(ctx, stateNamespace, key, data)
}

func deleteKey(ctx context.Context, s store.Store, namespace, key string) error {
	if err := s.Delete(ctx, namespace, key); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// markIndexed records that an account holds JMAP records of a kind.
func (h *Handler) markIndexed(ctx context.Context, prefix, accountID string) error {
	return h.cfg.State.Set(ctx, stateIndexNamespace, prefix+accountID, []byte("{}"))
}

func (h *Handler) unmarkIndexed(ctx context.Context, prefix, accountID string) error {
	return deleteKey(ctx, h.cfg.State, stateIndexNamespace, prefix+accountID)
}

// SetSubmissionRetention sets how long EmailSubmission history is kept.
func (h *Handler) SetSubmissionRetention(retention time.Duration) {
	if retention < time.Hour {
		retention = time.Hour
	}
	h.retention.Store(int64(retention))
}

func (h *Handler) submissionRetention() time.Duration {
	return time.Duration(h.retention.Load())
}

// Sweep deletes expired push subscriptions, prunes EmailSubmission history
// past retention, drops the records of deleted or purged accounts, and
// (re)starts delivery for verified push subscriptions, which is how push
// resumes after a restart. The server runs it on its background group.
func (h *Handler) Sweep(ctx context.Context) error {
	keys, err := h.cfg.State.List(ctx, stateIndexNamespace)
	if err != nil {
		if errors.Is(err, store.ErrClosed) {
			return nil
		}
		return err
	}
	var errs []error
	for _, key := range keys {
		if ctx.Err() != nil {
			return nil
		}
		var sweepErr error
		switch {
		case strings.HasPrefix(key, indexPushPrefix):
			sweepErr = h.sweepPush(ctx, strings.TrimPrefix(key, indexPushPrefix))
		case strings.HasPrefix(key, indexSubmissionPrefix):
			sweepErr = h.sweepSubmissions(ctx, strings.TrimPrefix(key, indexSubmissionPrefix))
		}
		if errors.Is(sweepErr, store.ErrClosed) {
			return nil
		}
		if sweepErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, sweepErr))
		}
	}
	return errors.Join(errs...)
}

// goBackground runs fn on the server background group, or on a plain
// goroutine when the handler has none. After shutdown it runs nothing and
// reports false.
func (h *Handler) goBackground(fn func(context.Context)) bool {
	if h.cfg.Go != nil {
		return h.cfg.Go(fn)
	}
	go fn(context.Background())
	return true
}
