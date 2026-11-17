// Package pebblestore implements store.Store using Pebble, an embedded LSM tree.
//
// Key encoding:
//
//	<namespace>\x00<key>
//
// Namespace sentinel keys are stored under a special prefix:
//
//	__ns__\x00<namespace>
//
// This layout allows efficient namespace-scanned iteration using Pebble's
// iterator prefix seeks.
package pebblestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/cockroachdb/pebble"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/store"
)

var log = logpkg.For(logpkg.ModuleStorage)

const sep = "\x00"

// Store implements store.Store using Pebble.
//
// Reads never wait for writers. Pebble reads are safe concurrently with
// commits and every commit is atomic, so a reader observes the state either
// before or after a write or batch. Serializing reads behind writers instead
// made every read wait for another goroutine's WAL fsync, which takes
// milliseconds on real disks.
type Store struct {
	// writeMu serializes mutations and batches so check-then-write operations
	// and batch read-modify-write sequences observe a stable store state.
	writeMu sync.Mutex
	// closeMu is held shared by every operation and exclusively by Close, so
	// the database is not closed under an in-flight operation. Pebble panics
	// on use after Close; closed turns that into store.ErrClosed.
	closeMu sync.RWMutex
	closed  bool
	db      *pebble.DB
}

// beginRead admits one read and returns the function that releases it, or
// store.ErrClosed once the store is closed.
func (s *Store) beginRead() (end func(), err error) {
	s.closeMu.RLock()
	if s.closed {
		s.closeMu.RUnlock()
		return nil, store.ErrClosed
	}
	return s.closeMu.RUnlock, nil
}

// beginWrite admits one mutation or batch and returns the function that
// releases it, or store.ErrClosed once the store is closed.
func (s *Store) beginWrite() (end func(), err error) {
	endRead, err := s.beginRead()
	if err != nil {
		return nil, err
	}
	s.writeMu.Lock()
	return func() {
		s.writeMu.Unlock()
		endRead()
	}, nil
}

type batchContextKey struct{}

type batchContext struct {
	store *Store
	batch *pebble.Batch
}

type viewContextKey struct{}

type viewContext struct {
	store  *Store
	reader pebble.Reader
}

func (s *Store) activeBatch(ctx context.Context) *pebble.Batch {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(batchContextKey{}).(batchContext)
	if state.store != s {
		return nil
	}
	return state.batch
}

func (s *Store) activeReader(ctx context.Context) pebble.Reader {
	if batch := s.activeBatch(ctx); batch != nil {
		return batch
	}
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(viewContextKey{}).(viewContext)
	if state.store != s {
		return nil
	}
	return state.reader
}

// sharedCacheSize bounds the block cache shared by every Pebble store in the
// process. Pebble's per-database default (8 MiB) let large values evict hot
// index blocks, so small reads re-read and re-checksummed megabyte blocks.
const sharedCacheSize = 128 << 20

// sharedCache is shared, never released, by all stores opened by New.
var sharedCache = sync.OnceValue(func() *pebble.Cache { return pebble.NewCache(sharedCacheSize) })

// New opens or creates a Pebble database at dir.
func New(dir string) (*Store, error) {
	return open(dir, &pebble.Options{Cache: sharedCache()})
}

func open(dir string, opts *pebble.Options) (*Store, error) {
	db, err := pebble.Open(dir, opts)
	if err != nil {
		log.Error("pebblestore: failed to open database", "dir", dir, "error", err)
		return nil, fmt.Errorf("open pebble: %w", err)
	}
	return &Store{db: db}, nil
}

// writeOptions returns the commit durability requested by ctx.
func writeOptions(ctx context.Context) *pebble.WriteOptions {
	if store.SyncDisabled(ctx) {
		return pebble.NoSync
	}
	return pebble.Sync
}

func nsKey(ns, key string) []byte {
	return []byte(ns + sep + key)
}

func nsSentinel(ns string) []byte {
	return []byte("__ns__" + sep + ns)
}

func nsSentinelNext(ns string) []byte {
	return []byte(namespaceNext(ns) + sep)
}

// Get implements store.Store.
func (s *Store) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	if reader := s.activeReader(ctx); reader != nil {
		return get(reader, nsKey(namespace, key))
	}
	end, err := s.beginRead()
	if err != nil {
		return nil, err
	}
	defer end()
	return get(s.db, nsKey(namespace, key))
}

func get(reader pebble.Reader, key []byte) ([]byte, error) {
	val, closer, err := reader.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("pebble get: %w", err)
	}
	data := bytes.Clone(val)
	closer.Close()
	return data, nil
}

// Set implements store.Store.
func (s *Store) Set(ctx context.Context, namespace, key string, value []byte) error {
	if batch := s.activeBatch(ctx); batch != nil {
		return batch.Set(nsKey(namespace, key), value, nil)
	}
	end, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer end()

	return s.db.Set(nsKey(namespace, key), value, writeOptions(ctx))
}

// Put implements store.Store.
func (s *Store) Put(ctx context.Context, namespace, key string, value []byte) error {
	if batch := s.activeBatch(ctx); batch != nil {
		return put(batch, namespace, key, value, nil)
	}
	end, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	return put(s.db, namespace, key, value, writeOptions(ctx))
}

func put(writer interface {
	pebble.Reader
	Set([]byte, []byte, *pebble.WriteOptions) error
}, namespace, key string, value []byte, options *pebble.WriteOptions) error {
	// Check existence first
	_, closer, err := writer.Get(nsKey(namespace, key))
	if err == nil {
		closer.Close()
		return store.ErrExists
	}
	if !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("pebble get: %w", err)
	}
	return writer.Set(nsKey(namespace, key), value, options)
}

// Delete implements store.Store.
func (s *Store) Delete(ctx context.Context, namespace, key string) error {
	if batch := s.activeBatch(ctx); batch != nil {
		return deleteKey(batch, namespace, key, nil)
	}
	end, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	return deleteKey(s.db, namespace, key, writeOptions(ctx))
}

func deleteKey(writer interface {
	pebble.Reader
	Delete([]byte, *pebble.WriteOptions) error
}, namespace, key string, options *pebble.WriteOptions) error {
	// Check existence first
	_, closer, err := writer.Get(nsKey(namespace, key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return store.ErrNotFound
		}
		return fmt.Errorf("pebble get: %w", err)
	}
	closer.Close()
	return writer.Delete(nsKey(namespace, key), options)
}

// List implements store.Store.
func (s *Store) List(ctx context.Context, namespace string) ([]string, error) {
	if reader := s.activeReader(ctx); reader != nil {
		return list(reader, namespace, "")
	}
	end, err := s.beginRead()
	if err != nil {
		return nil, err
	}
	defer end()
	return list(s.db, namespace, "")
}

func list(reader pebble.Reader, namespace, prefix string) ([]string, error) {
	lower, upper := scanBounds(namespace, prefix)
	iter, err := reader.NewIter(&pebble.IterOptions{
		LowerBound: lower,
		UpperBound: upper,
	})
	if err != nil {
		return nil, fmt.Errorf("pebble new iter: %w", err)
	}
	defer iter.Close()

	var keys []string
	for iter.First(); iter.Valid(); iter.Next() {
		k := extractKey(namespace, iter.Key())
		if k != "" && strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("pebble iter: %w", err)
	}
	slices.Sort(keys)
	return keys, nil
}

// Scan implements store.Store.
func (s *Store) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	if reader := s.activeReader(ctx); reader != nil {
		return list(reader, namespace, prefix)
	}
	end, err := s.beginRead()
	if err != nil {
		return nil, err
	}
	defer end()
	return list(s.db, namespace, prefix)
}

// CompareAndSwap implements store.Store.
func (s *Store) CompareAndSwap(ctx context.Context, namespace, key string, oldValue, newValue []byte) error {
	if batch := s.activeBatch(ctx); batch != nil {
		return compareAndSwap(batch, namespace, key, oldValue, newValue, nil)
	}
	end, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	return compareAndSwap(s.db, namespace, key, oldValue, newValue, writeOptions(ctx))
}

func compareAndSwap(writer interface {
	pebble.Reader
	Set([]byte, []byte, *pebble.WriteOptions) error
}, namespace, key string, oldValue, newValue []byte, options *pebble.WriteOptions) error {
	current, closer, err := writer.Get(nsKey(namespace, key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return store.ErrNotFound
		}
		return fmt.Errorf("pebble get: %w", err)
	}
	defer closer.Close()

	if !bytes.Equal(current, oldValue) {
		return store.ErrPreconditionFailed
	}

	return writer.Set(nsKey(namespace, key), newValue, options)
}

// Iterate implements store.Store.
func (s *Store) Iterate(ctx context.Context, namespace, prefix string, fn store.IterCallback) error {
	if reader := s.activeReader(ctx); reader != nil {
		return iterate(reader, namespace, prefix, "", fn)
	}
	end, err := s.beginRead()
	if err != nil {
		return err
	}
	defer end()
	return iterate(s.db, namespace, prefix, "", fn)
}

// IterateFrom implements store.RangeIterator by raising the iterator's lower
// bound to start.
func (s *Store) IterateFrom(ctx context.Context, namespace, prefix, start string, fn store.IterCallback) error {
	if reader := s.activeReader(ctx); reader != nil {
		return iterate(reader, namespace, prefix, start, fn)
	}
	end, err := s.beginRead()
	if err != nil {
		return err
	}
	defer end()
	return iterate(s.db, namespace, prefix, start, fn)
}

func iterate(reader pebble.Reader, namespace, prefix, start string, fn store.IterCallback) error {
	lower, upper := scanBounds(namespace, prefix)
	if start > prefix {
		lower = nsKey(namespace, start)
		if bytes.Compare(lower, upper) >= 0 {
			return nil
		}
	}
	iter, err := reader.NewIter(&pebble.IterOptions{
		LowerBound: lower,
		UpperBound: upper,
	})
	if err != nil {
		return fmt.Errorf("pebble new iter: %w", err)
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		k := extractKey(namespace, iter.Key())
		if k == "" || len(k) < len(prefix) || k[:len(prefix)] != prefix {
			continue
		}
		cont, err := fn(k, bytes.Clone(iter.Value()))
		if err != nil || !cont {
			return err
		}
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("pebble iter: %w", err)
	}
	return nil
}

func scanBounds(namespace, prefix string) ([]byte, []byte) {
	lower := nsKey(namespace, prefix)
	if prefix == "" {
		return lower, nsSentinelNext(namespace)
	}
	upper := bytes.Clone(lower)
	for index := len(upper) - 1; index >= 0; index-- {
		if upper[index] == 0xff {
			continue
		}
		upper[index]++
		return lower, upper[:index+1]
	}
	return lower, nsSentinelNext(namespace)
}

// Batch implements store.Batcher using an indexed Pebble batch so reads see
// earlier writes in the same transaction. The commit performs one WAL sync
// unless ctx was marked by store.WithoutSync.
func (s *Store) Batch(ctx context.Context, fn func(context.Context) error) error {
	if s.activeBatch(ctx) != nil {
		return fn(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	end, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer end()

	batch := s.db.NewIndexedBatch()
	defer batch.Close()
	batchCtx := context.WithValue(ctx, batchContextKey{}, batchContext{store: s, batch: batch})
	if err := fn(batchCtx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := batch.Commit(writeOptions(ctx)); err != nil {
		return fmt.Errorf("pebble commit batch: %w", err)
	}
	return nil
}

// CompactPrefix implements store.Compactor by compacting the key range under
// namespace and prefix, dropping deleted values.
func (s *Store) CompactPrefix(_ context.Context, namespace, prefix string) error {
	end, err := s.beginRead()
	if err != nil {
		return err
	}
	defer end()
	lower, upper := scanBounds(namespace, prefix)
	return s.db.Compact(lower, upper, true)
}

// View implements store.Viewer with one Pebble snapshot, so a multi-read
// query observes one consistent state without blocking or waiting for writers.
func (s *Store) View(ctx context.Context, fn func(context.Context) error) error {
	if s.activeReader(ctx) != nil {
		return fn(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	end, err := s.beginRead()
	if err != nil {
		return err
	}
	defer end()
	snapshot := s.db.NewSnapshot()
	defer snapshot.Close()
	return fn(context.WithValue(ctx, viewContextKey{}, viewContext{store: s, reader: snapshot}))
}

// NamespaceExists implements store.Store.
func (s *Store) NamespaceExists(ctx context.Context, namespace string) (bool, error) {
	if reader := s.activeReader(ctx); reader != nil {
		return namespaceExists(reader, namespace)
	}
	end, err := s.beginRead()
	if err != nil {
		return false, err
	}
	defer end()
	return namespaceExists(s.db, namespace)
}

func namespaceExists(reader pebble.Reader, namespace string) (bool, error) {
	_, closer, err := reader.Get(nsSentinel(namespace))
	if errors.Is(err, pebble.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("pebble get: %w", err)
	}
	closer.Close()
	return true, nil
}

// CreateNamespace implements store.Store.
// In Pebble, namespaces are implicit (no explicit creation needed).
// We store a sentinel key to make namespace enumeration possible.
func (s *Store) CreateNamespace(ctx context.Context, namespace string) error {
	if batch := s.activeBatch(ctx); batch != nil {
		return createNamespace(batch, namespace, nil)
	}
	end, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	return createNamespace(s.db, namespace, writeOptions(ctx))
}

func createNamespace(writer interface {
	pebble.Reader
	Set([]byte, []byte, *pebble.WriteOptions) error
}, namespace string, options *pebble.WriteOptions) error {
	// Check if sentinel already exists
	_, closer, err := writer.Get(nsSentinel(namespace))
	if err == nil {
		closer.Close()
		return store.ErrExists
	}
	if !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("pebble get: %w", err)
	}
	return writer.Set(nsSentinel(namespace), nil, options)
}

// DeleteNamespace implements store.Store.
func (s *Store) DeleteNamespace(ctx context.Context, namespace string) error {
	if batch := s.activeBatch(ctx); batch != nil {
		return deleteNamespace(batch, namespace, nil)
	}
	end, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer end()
	return deleteNamespace(s.db, namespace, writeOptions(ctx))
}

func deleteNamespace(writer interface {
	pebble.Reader
	Delete([]byte, *pebble.WriteOptions) error
}, namespace string, options *pebble.WriteOptions) error {
	// Check sentinel exists
	_, closer, err := writer.Get(nsSentinel(namespace))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return store.ErrNotFound
		}
		return fmt.Errorf("pebble get: %w", err)
	}
	closer.Close()

	// Delete all keys in namespace
	iter, err := writer.NewIter(&pebble.IterOptions{
		LowerBound: nsKey(namespace, ""),
		UpperBound: nsSentinelNext(namespace),
	})
	if err != nil {
		return fmt.Errorf("pebble new iter: %w", err)
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		if err := writer.Delete(iter.Key(), nil); err != nil {
			return fmt.Errorf("pebble delete: %w", err)
		}
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("pebble iter: %w", err)
	}

	// Delete sentinel
	return writer.Delete(nsSentinel(namespace), options)
}

// ListNamespaces implements store.Store.
func (s *Store) ListNamespaces(ctx context.Context) ([]string, error) {
	if reader := s.activeReader(ctx); reader != nil {
		return listNamespaces(reader)
	}
	end, err := s.beginRead()
	if err != nil {
		return nil, err
	}
	defer end()
	return listNamespaces(s.db)
}

func listNamespaces(reader pebble.Reader) ([]string, error) {
	iter, err := reader.NewIter(&pebble.IterOptions{
		LowerBound: []byte("__ns__" + sep),
		UpperBound: []byte("__ns__" + sep + "~"),
	})
	if err != nil {
		return nil, fmt.Errorf("pebble new iter: %w", err)
	}
	defer iter.Close()

	var namespaces []string
	for iter.First(); iter.Valid(); iter.Next() {
		ns := extractNamespace(iter.Key())
		if ns != "" {
			namespaces = append(namespaces, ns)
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("pebble iter: %w", err)
	}
	slices.Sort(namespaces)
	return namespaces, nil
}

// Close implements store.Store.
func (s *Store) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

var (
	_ store.Store         = (*Store)(nil)
	_ store.Batcher       = (*Store)(nil)
	_ store.Viewer        = (*Store)(nil)
	_ store.RangeIterator = (*Store)(nil)
)

// extractKey extracts the key portion from a composite key.
func extractKey(namespace string, key []byte) string {
	prefix := []byte(namespace + sep)
	if bytes.HasPrefix(key, prefix) {
		return string(key[len(prefix):])
	}
	return ""
}

// extractNamespace extracts the namespace from a sentinel key.
func extractNamespace(key []byte) string {
	prefix := []byte("__ns__" + sep)
	if bytes.HasPrefix(key, prefix) {
		return string(key[len(prefix):])
	}
	return ""
}

// namespaceNext returns the lexicographically next namespace prefix
// for use as an upper bound in iterators.
func namespaceNext(ns string) string {
	b := []byte(ns)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return string(b)
		}
	}
	return ns + "\x01"
}
