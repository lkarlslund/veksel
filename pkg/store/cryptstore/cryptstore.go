// Package cryptstore encrypts another store.Store at rest.
//
// Every value is sealed with the account data-encryption key and bound to
// its namespace and logical key, so swapping ciphertexts between records
// fails authentication. Namespace names and most key names stay plaintext
// because engines order and prefix-scan them; key families that embed
// user-chosen text are declared as KeyFamily rules and their confidential
// tails are deterministically encrypted. The decorator restores logical keys
// and lexicographic order on every list, scan, and iteration, so callers
// observe exactly the semantics of the wrapped engine.
package cryptstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/lkarlslund/veksel/pkg/dek"
	"github.com/lkarlslund/veksel/pkg/store"
)

// KeyFamily declares a key-name family whose tail is confidential. Keys in
// Namespace starting with Prefix keep Prefix and the next Segments
// colon-terminated segments in plaintext (the "block", used for ordering and
// prefix scans); the remainder of the key is encrypted. Keys with fewer
// segments are stored unchanged.
type KeyFamily struct {
	Namespace string
	Prefix    string
	Segments  int
}

// Store is the encrypting decorator. It implements store.Batcher,
// store.Viewer, and store.Compactor by delegating to the wrapped engine.
type Store struct {
	inner    store.Store
	key      *dek.Key
	families map[string][]KeyFamily
	// closed lets operations the engine never sees, such as compaction of an
	// engine without a compactor, report store.ErrClosed like the engine.
	closed atomic.Bool
}

var (
	_ store.Store         = (*Store)(nil)
	_ store.Batcher       = (*Store)(nil)
	_ store.Viewer        = (*Store)(nil)
	_ store.Compactor     = (*Store)(nil)
	_ store.RangeIterator = (*Store)(nil)
)

// New wraps inner, which must support atomic batches because account
// mutations rely on them.
func New(inner store.Store, key *dek.Key, families []KeyFamily) (*Store, error) {
	if inner == nil || key == nil {
		return nil, errors.New("encrypted store requires an inner store and a key")
	}
	if _, ok := inner.(store.Batcher); !ok {
		return nil, errors.New("encrypted store requires an engine with atomic batches")
	}
	byNamespace := make(map[string][]KeyFamily)
	for _, family := range families {
		if family.Namespace == "" || family.Segments < 0 {
			return nil, fmt.Errorf("invalid key family %+v", family)
		}
		for _, existing := range byNamespace[family.Namespace] {
			if strings.HasPrefix(existing.Prefix, family.Prefix) || strings.HasPrefix(family.Prefix, existing.Prefix) {
				return nil, fmt.Errorf("overlapping key families %q and %q in %s", existing.Prefix, family.Prefix, family.Namespace)
			}
		}
		byNamespace[family.Namespace] = append(byNamespace[family.Namespace], family)
	}
	return &Store{inner: inner, key: key, families: byNamespace}, nil
}

func valueAAD(namespace, key string) []byte {
	return []byte("veksel-store-v1\x00" + namespace + "\x00" + key)
}

func nameAAD(namespace, block string) []byte {
	return []byte("veksel-key-v1\x00" + namespace + "\x00" + block)
}

// blockEnd returns the length of key's plaintext block under family, or -1
// when key does not contain the complete block.
func blockEnd(key string, family KeyFamily) int {
	if !strings.HasPrefix(key, family.Prefix) {
		return -1
	}
	end := len(family.Prefix)
	for range family.Segments {
		index := strings.IndexByte(key[end:], ':')
		if index < 0 {
			return -1
		}
		end += index + 1
	}
	return end
}

func (s *Store) family(namespace, key string) (KeyFamily, int) {
	for _, family := range s.families[namespace] {
		if end := blockEnd(key, family); end >= 0 {
			return family, end
		}
	}
	return KeyFamily{}, -1
}

func (s *Store) encodeKey(namespace, key string) string {
	_, end := s.family(namespace, key)
	if end < 0 {
		return key
	}
	block := key[:end]
	return block + s.key.SealName(nameAAD(namespace, block), key[end:])
}

// decodeKey returns the logical key and, for a protected key, its block.
func (s *Store) decodeKey(namespace, stored string) (string, string, error) {
	_, end := s.family(namespace, stored)
	if end < 0 {
		return stored, "", nil
	}
	block := stored[:end]
	tail, err := s.key.OpenName(nameAAD(namespace, block), stored[end:])
	if err != nil {
		return "", "", fmt.Errorf("decrypt key name in %s: %w", namespace, err)
	}
	return block + tail, block, nil
}

// plan translates a logical prefix scan into the engine prefix to scan and
// whether results must be filtered and reordered after decoding.
func (s *Store) plan(namespace, prefix string) (string, bool) {
	under, reorder := prefix, false
	for _, family := range s.families[namespace] {
		switch {
		case strings.HasPrefix(prefix, family.Prefix):
			reorder = true
			if end := blockEnd(prefix, family); end >= 0 {
				// The prefix reaches into the encrypted tail: scan the whole
				// block and filter decoded keys.
				under = prefix[:end]
			}
		case strings.HasPrefix(family.Prefix, prefix):
			reorder = true
		}
	}
	return under, reorder
}

func (s *Store) seal(namespace, key string, value []byte) ([]byte, error) {
	return s.key.Seal(valueAAD(namespace, key), value)
}

func (s *Store) open(namespace, key string, sealed []byte) ([]byte, error) {
	plaintext, err := s.key.Open(valueAAD(namespace, key), sealed)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s/%s: %w", namespace, key, err)
	}
	return plaintext, nil
}

// Get implements store.Store.
func (s *Store) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	sealed, err := s.inner.Get(ctx, namespace, s.encodeKey(namespace, key))
	if err != nil {
		return nil, err
	}
	return s.open(namespace, key, sealed)
}

// Set implements store.Store.
func (s *Store) Set(ctx context.Context, namespace, key string, value []byte) error {
	sealed, err := s.seal(namespace, key, value)
	if err != nil {
		return err
	}
	return s.inner.Set(ctx, namespace, s.encodeKey(namespace, key), sealed)
}

// Put implements store.Store.
func (s *Store) Put(ctx context.Context, namespace, key string, value []byte) error {
	sealed, err := s.seal(namespace, key, value)
	if err != nil {
		return err
	}
	return s.inner.Put(ctx, namespace, s.encodeKey(namespace, key), sealed)
}

// Delete implements store.Store.
func (s *Store) Delete(ctx context.Context, namespace, key string) error {
	return s.inner.Delete(ctx, namespace, s.encodeKey(namespace, key))
}

// CompareAndSwap compares plaintext, then swaps on the exact stored
// ciphertext so a concurrent writer still fails the precondition.
func (s *Store) CompareAndSwap(ctx context.Context, namespace, key string, oldValue, newValue []byte) error {
	stored := s.encodeKey(namespace, key)
	current, err := s.inner.Get(ctx, namespace, stored)
	if err != nil {
		return err
	}
	plaintext, err := s.open(namespace, key, current)
	if err != nil {
		return err
	}
	if string(plaintext) != string(oldValue) {
		return store.ErrPreconditionFailed
	}
	sealed, err := s.seal(namespace, key, newValue)
	if err != nil {
		return err
	}
	return s.inner.CompareAndSwap(ctx, namespace, stored, current, sealed)
}

// List implements store.Store.
func (s *Store) List(ctx context.Context, namespace string) ([]string, error) {
	return s.Scan(ctx, namespace, "")
}

// Scan implements store.Store.
func (s *Store) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	under, reorder := s.plan(namespace, prefix)
	var stored []string
	var err error
	if under == "" {
		stored, err = s.inner.List(ctx, namespace)
	} else {
		stored, err = s.inner.Scan(ctx, namespace, under)
	}
	if err != nil || !reorder {
		return stored, err
	}
	keys := stored[:0]
	for _, key := range stored {
		logical, _, err := s.decodeKey(namespace, key)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(logical, prefix) {
			keys = append(keys, logical)
		}
	}
	slices.Sort(keys)
	return keys, nil
}

type pendingEntry struct {
	key   string
	value []byte
}

// Iterate implements store.Store. Protected keys of one block are adjacent in
// engine order, so only one block at a time is buffered to restore logical
// order before it is handed to fn.
func (s *Store) Iterate(ctx context.Context, namespace, prefix string, fn store.IterCallback) error {
	return s.IterateFrom(ctx, namespace, prefix, "", fn)
}

// IterateFrom implements store.RangeIterator. Keys outside protected
// families are stored in logical order, so the engine seeks to start
// directly; a protected family is iterated in full and filtered after its
// keys are decoded.
func (s *Store) IterateFrom(ctx context.Context, namespace, prefix, start string, fn store.IterCallback) error {
	under, reorder := s.plan(namespace, prefix)
	engineStart := start
	if reorder {
		engineStart = ""
	}
	var pending []pendingEntry
	pendingBlock, stopped := "", false
	flush := func() error {
		slices.SortFunc(pending, func(a, b pendingEntry) int { return strings.Compare(a.key, b.key) })
		for _, entry := range pending {
			more, err := fn(entry.key, entry.value)
			if err != nil {
				return err
			}
			if !more {
				stopped = true
				break
			}
		}
		pending, pendingBlock = pending[:0], ""
		return nil
	}
	err := store.IterateFrom(ctx, s.inner, namespace, under, engineStart, func(stored string, sealed []byte) (bool, error) {
		logical, block := stored, ""
		if reorder {
			var err error
			if logical, block, err = s.decodeKey(namespace, stored); err != nil {
				return false, err
			}
			if !strings.HasPrefix(logical, prefix) || logical < start {
				return true, nil
			}
		}
		value, err := s.open(namespace, logical, sealed)
		if err != nil {
			return false, err
		}
		if block != pendingBlock || block == "" {
			if err := flush(); err != nil || stopped {
				return false, err
			}
		}
		if block != "" {
			pending, pendingBlock = append(pending, pendingEntry{key: logical, value: value}), block
			return true, nil
		}
		return fn(logical, value)
	})
	if err != nil || stopped {
		return err
	}
	return flush()
}

// NamespaceExists implements store.Store.
func (s *Store) NamespaceExists(ctx context.Context, namespace string) (bool, error) {
	return s.inner.NamespaceExists(ctx, namespace)
}

// CreateNamespace implements store.Store.
func (s *Store) CreateNamespace(ctx context.Context, namespace string) error {
	return s.inner.CreateNamespace(ctx, namespace)
}

// DeleteNamespace implements store.Store.
func (s *Store) DeleteNamespace(ctx context.Context, namespace string) error {
	return s.inner.DeleteNamespace(ctx, namespace)
}

// ListNamespaces implements store.Store.
func (s *Store) ListNamespaces(ctx context.Context) ([]string, error) {
	return s.inner.ListNamespaces(ctx)
}

// Close closes the wrapped engine.
func (s *Store) Close() error {
	s.closed.Store(true)
	return s.inner.Close()
}

// Batch implements store.Batcher on the wrapped engine's batch, so sync
// marks (store.WithoutSync) and read-your-writes behave as on the engine.
func (s *Store) Batch(ctx context.Context, fn func(context.Context) error) error {
	return store.Batch(ctx, s.inner, fn)
}

// View implements store.Viewer on the wrapped engine's stable view.
func (s *Store) View(ctx context.Context, fn func(context.Context) error) error {
	return store.View(ctx, s.inner, fn)
}

// CompactPrefix implements store.Compactor.
func (s *Store) CompactPrefix(ctx context.Context, namespace, prefix string) error {
	compactor, ok := s.inner.(store.Compactor)
	if !ok {
		if s.closed.Load() {
			return store.ErrClosed
		}
		return nil
	}
	under, _ := s.plan(namespace, prefix)
	return compactor.CompactPrefix(ctx, namespace, under)
}
