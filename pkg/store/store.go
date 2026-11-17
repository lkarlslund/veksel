// Package store defines the generic key-value store interface used throughout Veksel.
//
// The store operates on a namespace/key/value model. Namespaces group related
// entities (e.g. "users", "domains", "mailboxes"). Keys are unique within a
// namespace. Values are opaque []byte — the caller is responsible for
// serialization (typically JSON).
//
// Production backends:
//
//   - pebblestore: Pebble LSM tree
//   - badgerstore: Badger LSM tree with a value log
//
// jsonstore remains available for tests and offline diagnostics. It is not a
// production backend and must not be offered by server configuration.
package store

import (
	"context"
	"errors"
	"io"
)

// Backend identifies the storage backend to use.
type Backend string

const (
	// BackendJSON uses flat JSON files on disk. It is retained for tests and
	// offline diagnostics only.
	BackendJSON Backend = "json"
	// BackendPebble uses the Pebble embedded LSM tree.
	BackendPebble Backend = "pebble"
	// BackendBadger uses the Badger embedded LSM tree and value log.
	BackendBadger Backend = "badger"
)

var (
	ErrNotFound           = errors.New("key not found")
	ErrExists             = errors.New("key already exists")
	ErrPreconditionFailed = errors.New("current value does not match expected value")
	// ErrClosed is returned by every operation on a store after Close, so
	// background work that outlives the store fails instead of reaching a
	// released engine.
	ErrClosed = errors.New("store is closed")
)

// Store is the generic key-value store interface.
//
// All methods are safe for concurrent use.
type Store interface {
	// Get returns the value for the given namespace and key.
	// Returns ErrNotFound when the key does not exist.
	Get(ctx context.Context, namespace, key string) ([]byte, error)

	// Set stores the value for the given namespace and key.
	// Overwrites any existing value.
	Set(ctx context.Context, namespace, key string, value []byte) error

	// Put stores the value only when the key does not yet exist.
	// Returns ErrExists when the key is already present.
	Put(ctx context.Context, namespace, key string, value []byte) error

	// Delete removes the key from the namespace.
	// Returns ErrNotFound when the key does not exist.
	Delete(ctx context.Context, namespace, key string) error

	// List returns all keys in the namespace.
	// Keys are returned in lexicographic order.
	List(ctx context.Context, namespace string) ([]string, error)

	// Scan returns all keys in the namespace that have a prefix.
	Scan(ctx context.Context, namespace, prefix string) ([]string, error)

	// CompareAndSwap atomically replaces the value for key only if the current
	// value equals oldValue (byte-for-byte). Returns ErrNotFound when the key
	// does not exist. Returns ErrPreconditionFailed when the current value does
	// not match oldValue.
	CompareAndSwap(ctx context.Context, namespace, key string, oldValue, newValue []byte) error

	// Iterate calls fn for each key in the namespace that has the given prefix.
	// Iteration stops early when fn returns a non-nil error or false. Returns
	// all matching keys when fn always returns true. The callback receives the
	// key and its current value.
	Iterate(ctx context.Context, namespace, prefix string, fn IterCallback) error

	// NamespaceExists reports whether the namespace has been created.
	NamespaceExists(ctx context.Context, namespace string) (bool, error)

	// CreateNamespace creates a new namespace.
	// Returns ErrExists when the namespace already exists.
	CreateNamespace(ctx context.Context, namespace string) error

	// DeleteNamespace removes a namespace and all keys within it.
	// Returns ErrNotFound when the namespace does not exist.
	DeleteNamespace(ctx context.Context, namespace string) error

	// ListNamespaces returns all existing namespaces.
	ListNamespaces(ctx context.Context) ([]string, error)

	// Close flushes and releases resources. Later operations return
	// ErrClosed, and closing again is a no-op.
	Close() error
}

// IterCallback is the callback type used by Store.Iterate.
// Return true to continue iteration, false to stop early.
// Return an error to abort iteration with that error.
type IterCallback func(key string, value []byte) (continueIteration bool, err error)

// RangeIterator is an optional Store capability for resuming an ordered
// prefix iteration at a key. Engines seek directly to start, so the cost is
// independent of how many keys with the prefix sort before it.
type RangeIterator interface {
	// IterateFrom behaves like Iterate restricted to the keys that sort at or
	// after start.
	IterateFrom(ctx context.Context, namespace, prefix, start string, fn IterCallback) error
}

// IterateFrom calls fn, in lexicographic order, for each key in namespace
// that has prefix and sorts at or after start. Stores without RangeIterator
// fall back to a full prefix iteration that skips the earlier keys.
func IterateFrom(ctx context.Context, s Store, namespace, prefix, start string, fn IterCallback) error {
	if ranged, ok := s.(RangeIterator); ok {
		return ranged.IterateFrom(ctx, namespace, prefix, start, fn)
	}
	return s.Iterate(ctx, namespace, prefix, func(key string, value []byte) (bool, error) {
		if key < start {
			return true, nil
		}
		return fn(key, value)
	})
}

// Batcher is an optional Store capability for grouping related operations in
// one atomic, durable commit. The context passed to fn must be used for every
// store operation that belongs to the batch. Returning an error rolls back the
// batch. Implementations serialize the callback with other operations so a
// read-modify-write sequence observes a stable store state.
type Batcher interface {
	Batch(ctx context.Context, fn func(context.Context) error) error
}

// Viewer is an optional Store capability for grouping reads into one stable
// view. Implementations may also use it to amortize synchronization across a
// scan followed by many point reads.
type Viewer interface {
	View(ctx context.Context, fn func(context.Context) error) error
}

// Compactor is an optional Store capability for reclaiming the space and read
// cost of deleted records under a namespace prefix. LSM engines keep deleted
// values until a compaction rewrites their key range, and readers scanning
// neighbouring keys must step over them meanwhile.
type Compactor interface {
	CompactPrefix(ctx context.Context, namespace, prefix string) error
}

type batchContextKey struct{}

type batchContext struct {
	store Store
}

type noSyncContextKey struct{}

// WithoutSync marks ctx so writes and batch commits issued with it may skip
// the durable sync to disk. Such writes stay atomic and are visible to readers
// immediately, and a clean Close persists them, but a crash may lose the most
// recent ones. Use it only for data that may be lost, such as metrics.
// Backends that never sync individual writes ignore the mark.
func WithoutSync(ctx context.Context) context.Context {
	return context.WithValue(ctx, noSyncContextKey{}, true)
}

// SyncDisabled reports whether ctx was marked by WithoutSync.
func SyncDisabled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	disabled, _ := ctx.Value(noSyncContextKey{}).(bool)
	return disabled
}

type viewContextKey struct{}

type viewContext struct {
	store Store
}

// Batch runs fn using the store's atomic batching capability when available.
// Stores without batching retain their normal operation-by-operation behavior.
func Batch(ctx context.Context, s Store, fn func(context.Context) error) error {
	if InBatch(ctx, s) {
		return fn(ctx)
	}
	if batcher, ok := s.(Batcher); ok {
		return batcher.Batch(ctx, func(batchCtx context.Context) error {
			return fn(context.WithValue(batchCtx, batchContextKey{}, batchContext{store: s}))
		})
	}
	return fn(ctx)
}

// InBatch reports whether ctx belongs to an exclusive batch for s.
func InBatch(ctx context.Context, s Store) bool {
	if ctx == nil {
		return false
	}
	batch, _ := ctx.Value(batchContextKey{}).(batchContext)
	return batch.store == s
}

// View runs fn using the store's stable read capability when available.
// Stores without that capability retain their normal operation-by-operation
// behavior. A write batch already provides a stable view of its own writes.
func View(ctx context.Context, s Store, fn func(context.Context) error) error {
	if InBatch(ctx, s) || InView(ctx, s) {
		return fn(ctx)
	}
	if viewer, ok := s.(Viewer); ok {
		return viewer.View(ctx, func(viewCtx context.Context) error {
			return fn(context.WithValue(viewCtx, viewContextKey{}, viewContext{store: s}))
		})
	}
	return fn(ctx)
}

// InView reports whether ctx belongs to a stable read view for s.
func InView(ctx context.Context, s Store) bool {
	if ctx == nil {
		return false
	}
	view, _ := ctx.Value(viewContextKey{}).(viewContext)
	return view.store == s
}

// Closer is the io.Closer interface, re-exported for convenience.
var _ io.Closer = (Store)(nil)
