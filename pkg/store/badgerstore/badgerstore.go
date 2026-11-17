// Package badgerstore implements store.Store using Badger.
package badgerstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/dgraph-io/badger/v4"

	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	separator       = "\x00"
	namespacePrefix = "__ns__\x00"
)

// Store implements store.Store using one Badger database.
type Store struct {
	db *badger.DB

	// Badger detects transaction conflicts, but serializing explicit batches
	// gives store.Batch the same stable read-modify-write semantics as the
	// other Veksel engines. Close takes it exclusively, so closed is stable
	// while it is held.
	batchMu sync.RWMutex
	closed  bool
}

// shared admits an operation that may run alongside others and returns the
// function that releases it, or store.ErrClosed once the store is closed.
func (s *Store) shared() (unlock func(), err error) {
	s.batchMu.RLock()
	if s.closed {
		s.batchMu.RUnlock()
		return nil, store.ErrClosed
	}
	return s.batchMu.RUnlock, nil
}

// exclusive admits an operation that must run alone, like shared.
func (s *Store) exclusive() (unlock func(), err error) {
	s.batchMu.Lock()
	if s.closed {
		s.batchMu.Unlock()
		return nil, store.ErrClosed
	}
	return s.batchMu.Unlock, nil
}

type batchContextKey struct{}

type batchContext struct {
	store *Store
	txn   *badger.Txn
}

// New opens or creates a Badger database at dir. Badger's default options
// leave SyncWrites off, so store.WithoutSync needs no handling here.
func New(dir string) (*Store, error) {
	options := badger.DefaultOptions(dir).WithLogger(nil)
	db, err := badger.Open(options)
	if err != nil {
		return nil, fmt.Errorf("open badger: %w", err)
	}
	return &Store{db: db}, nil
}

func dataKey(namespace, key string) []byte {
	return []byte(namespace + separator + key)
}

func dataPrefix(namespace, prefix string) []byte {
	return dataKey(namespace, prefix)
}

func namespaceKey(namespace string) []byte {
	return []byte(namespacePrefix + namespace)
}

func (s *Store) transaction(ctx context.Context) *badger.Txn {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(batchContextKey{}).(batchContext)
	if state.store != s {
		return nil
	}
	return state.txn
}

func value(txn *badger.Txn, key []byte) ([]byte, error) {
	item, err := txn.Get(key)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("badger get: %w", err)
	}
	result, err := item.ValueCopy(nil)
	if err != nil {
		return nil, fmt.Errorf("badger copy value: %w", err)
	}
	return result, nil
}

// Get implements store.Store.
func (s *Store) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	if txn := s.transaction(ctx); txn != nil {
		return value(txn, dataKey(namespace, key))
	}
	unlock, err := s.shared()
	if err != nil {
		return nil, err
	}
	defer unlock()

	var result []byte
	err = s.db.View(func(txn *badger.Txn) error {
		var err error
		result, err = value(txn, dataKey(namespace, key))
		return err
	})
	return result, err
}

// Set implements store.Store.
func (s *Store) Set(ctx context.Context, namespace, key string, value []byte) error {
	if txn := s.transaction(ctx); txn != nil {
		return txn.Set(dataKey(namespace, key), value)
	}
	unlock, err := s.shared()
	if err != nil {
		return err
	}
	defer unlock()
	return wrapUpdate(s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(dataKey(namespace, key), value)
	}))
}

// Put implements store.Store.
func (s *Store) Put(ctx context.Context, namespace, key string, value []byte) error {
	apply := func(txn *badger.Txn) error {
		_, err := txn.Get(dataKey(namespace, key))
		if err == nil {
			return store.ErrExists
		}
		if !errors.Is(err, badger.ErrKeyNotFound) {
			return fmt.Errorf("badger get: %w", err)
		}
		return txn.Set(dataKey(namespace, key), value)
	}
	if txn := s.transaction(ctx); txn != nil {
		return apply(txn)
	}
	unlock, err := s.shared()
	if err != nil {
		return err
	}
	defer unlock()
	return wrapUpdate(s.db.Update(apply))
}

// Delete implements store.Store.
func (s *Store) Delete(ctx context.Context, namespace, key string) error {
	apply := func(txn *badger.Txn) error {
		if _, err := txn.Get(dataKey(namespace, key)); errors.Is(err, badger.ErrKeyNotFound) {
			return store.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("badger get: %w", err)
		}
		return txn.Delete(dataKey(namespace, key))
	}
	if txn := s.transaction(ctx); txn != nil {
		return apply(txn)
	}
	unlock, err := s.shared()
	if err != nil {
		return err
	}
	defer unlock()
	return wrapUpdate(s.db.Update(apply))
}

func keys(ctx context.Context, txn *badger.Txn, namespace, prefix string) ([]string, error) {
	wanted := dataPrefix(namespace, prefix)
	options := badger.DefaultIteratorOptions
	options.Prefix = wanted
	options.PrefetchValues = false
	iterator := txn.NewIterator(options)
	defer iterator.Close()

	base := len(namespace) + len(separator)
	result := make([]string, 0)
	for iterator.Seek(wanted); iterator.ValidForPrefix(wanted); iterator.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := iterator.Item().KeyCopy(nil)
		result = append(result, string(key[base:]))
	}
	slices.Sort(result)
	return result, nil
}

func (s *Store) list(ctx context.Context, namespace, prefix string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if txn := s.transaction(ctx); txn != nil {
		return keys(ctx, txn, namespace, prefix)
	}
	unlock, err := s.shared()
	if err != nil {
		return nil, err
	}
	defer unlock()

	var result []string
	err = s.db.View(func(txn *badger.Txn) error {
		var err error
		result, err = keys(ctx, txn, namespace, prefix)
		return err
	})
	return result, err
}

// List implements store.Store.
func (s *Store) List(ctx context.Context, namespace string) ([]string, error) {
	return s.list(ctx, namespace, "")
}

// Scan implements store.Store.
func (s *Store) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	return s.list(ctx, namespace, prefix)
}

// CompareAndSwap implements store.Store.
func (s *Store) CompareAndSwap(ctx context.Context, namespace, key string, oldValue, newValue []byte) error {
	apply := func(txn *badger.Txn) error {
		current, err := value(txn, dataKey(namespace, key))
		if err != nil {
			return err
		}
		if !bytes.Equal(current, oldValue) {
			return store.ErrPreconditionFailed
		}
		return txn.Set(dataKey(namespace, key), newValue)
	}
	if txn := s.transaction(ctx); txn != nil {
		return apply(txn)
	}
	// Serialize compare-and-swap transactions so Badger conflicts are exposed
	// through the Store contract as a failed precondition, not an engine error.
	unlock, err := s.exclusive()
	if err != nil {
		return err
	}
	defer unlock()
	return wrapUpdate(s.db.Update(apply))
}

// Iterate implements store.Store.
func (s *Store) Iterate(ctx context.Context, namespace, prefix string, fn store.IterCallback) error {
	return s.IterateFrom(ctx, namespace, prefix, "", fn)
}

// IterateFrom implements store.RangeIterator by seeking the iterator to start.
func (s *Store) IterateFrom(ctx context.Context, namespace, prefix, start string, fn store.IterCallback) error {
	if ctx == nil {
		ctx = context.Background()
	}
	iterate := func(txn *badger.Txn) error {
		wanted := dataPrefix(namespace, prefix)
		seek := wanted
		if start > prefix {
			seek = dataPrefix(namespace, start)
		}
		options := badger.DefaultIteratorOptions
		options.Prefix = wanted
		iterator := txn.NewIterator(options)
		defer iterator.Close()

		base := len(namespace) + len(separator)
		for iterator.Seek(seek); iterator.ValidForPrefix(wanted); iterator.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			item := iterator.Item()
			current, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("badger copy value: %w", err)
			}
			key := item.KeyCopy(nil)
			proceed, err := fn(string(key[base:]), current)
			if err != nil || !proceed {
				return err
			}
		}
		return nil
	}
	if txn := s.transaction(ctx); txn != nil {
		return iterate(txn)
	}
	unlock, err := s.shared()
	if err != nil {
		return err
	}
	defer unlock()
	return s.db.View(iterate)
}

// Batch implements store.Batcher with a single serializable Badger transaction.
func (s *Store) Batch(ctx context.Context, fn func(context.Context) error) error {
	if s.transaction(ctx) != nil {
		return fn(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unlock, err := s.exclusive()
	if err != nil {
		return err
	}
	defer unlock()

	txn := s.db.NewTransaction(true)
	defer txn.Discard()
	batchCtx := context.WithValue(ctx, batchContextKey{}, batchContext{store: s, txn: txn})
	if err := fn(batchCtx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return wrapUpdate(txn.Commit())
}

// View implements store.Viewer with one read-only Badger transaction. The
// shared lock keeps explicit write batches from starving a multi-read query.
func (s *Store) View(ctx context.Context, fn func(context.Context) error) error {
	if s.transaction(ctx) != nil {
		return fn(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unlock, err := s.shared()
	if err != nil {
		return err
	}
	defer unlock()
	txn := s.db.NewTransaction(false)
	defer txn.Discard()
	return fn(context.WithValue(ctx, batchContextKey{}, batchContext{store: s, txn: txn}))
}

// NamespaceExists implements store.Store.
func (s *Store) NamespaceExists(ctx context.Context, namespace string) (bool, error) {
	_, err := s.getRaw(ctx, namespaceKey(namespace))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) getRaw(ctx context.Context, key []byte) ([]byte, error) {
	if txn := s.transaction(ctx); txn != nil {
		return value(txn, key)
	}
	unlock, err := s.shared()
	if err != nil {
		return nil, err
	}
	defer unlock()
	var result []byte
	err = s.db.View(func(txn *badger.Txn) error {
		var err error
		result, err = value(txn, key)
		return err
	})
	return result, err
}

// CreateNamespace implements store.Store.
func (s *Store) CreateNamespace(ctx context.Context, namespace string) error {
	apply := func(txn *badger.Txn) error {
		_, err := txn.Get(namespaceKey(namespace))
		if err == nil {
			return store.ErrExists
		}
		if !errors.Is(err, badger.ErrKeyNotFound) {
			return fmt.Errorf("badger get namespace: %w", err)
		}
		return txn.Set(namespaceKey(namespace), []byte{1})
	}
	if txn := s.transaction(ctx); txn != nil {
		return apply(txn)
	}
	unlock, err := s.shared()
	if err != nil {
		return err
	}
	defer unlock()
	return wrapUpdate(s.db.Update(apply))
}

// DeleteNamespace implements store.Store.
func (s *Store) DeleteNamespace(ctx context.Context, namespace string) error {
	apply := func(txn *badger.Txn) error {
		if _, err := txn.Get(namespaceKey(namespace)); errors.Is(err, badger.ErrKeyNotFound) {
			return store.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("badger get namespace: %w", err)
		}

		prefix := dataPrefix(namespace, "")
		options := badger.DefaultIteratorOptions
		options.Prefix = prefix
		options.PrefetchValues = false
		iterator := txn.NewIterator(options)
		defer iterator.Close()
		for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
			if err := txn.Delete(iterator.Item().KeyCopy(nil)); err != nil {
				return fmt.Errorf("badger delete namespace key: %w", err)
			}
		}
		return txn.Delete(namespaceKey(namespace))
	}
	if txn := s.transaction(ctx); txn != nil {
		return apply(txn)
	}
	unlock, err := s.shared()
	if err != nil {
		return err
	}
	defer unlock()
	return wrapUpdate(s.db.Update(apply))
}

// ListNamespaces implements store.Store.
func (s *Store) ListNamespaces(ctx context.Context) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	list := func(txn *badger.Txn) ([]string, error) {
		prefix := []byte(namespacePrefix)
		options := badger.DefaultIteratorOptions
		options.Prefix = prefix
		options.PrefetchValues = false
		iterator := txn.NewIterator(options)
		defer iterator.Close()

		result := make([]string, 0)
		for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			key := iterator.Item().KeyCopy(nil)
			result = append(result, string(key[len(prefix):]))
		}
		slices.Sort(result)
		return result, nil
	}
	if txn := s.transaction(ctx); txn != nil {
		return list(txn)
	}
	unlock, err := s.shared()
	if err != nil {
		return nil, err
	}
	defer unlock()
	var result []string
	err = s.db.View(func(txn *badger.Txn) error {
		var err error
		result, err = list(txn)
		return err
	})
	return result, err
}

// Close flushes and closes the Badger database.
func (s *Store) Close() error {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

func wrapUpdate(err error) error {
	if err == nil || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrPreconditionFailed) {
		return err
	}
	return fmt.Errorf("badger update: %w", err)
}

var (
	_ store.Store         = (*Store)(nil)
	_ store.Batcher       = (*Store)(nil)
	_ store.Viewer        = (*Store)(nil)
	_ store.RangeIterator = (*Store)(nil)
)
