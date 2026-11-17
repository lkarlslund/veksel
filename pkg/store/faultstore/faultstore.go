// Package faultstore provides deterministic storage failures for durability
// and recovery tests. It is never selected as a production backend.
package faultstore

import (
	"context"
	"errors"
	"sync"

	"github.com/lkarlslund/veksel/pkg/store"
)

var ErrInjected = errors.New("injected store failure")

// Store wraps another store and fails the Nth invocation of a named operation.
type Store struct {
	next store.Store
	mu   sync.Mutex
	op   string
	nth  int
}

func New(next store.Store) *Store { return &Store{next: next} }

// Fail arms one deterministic failure. A non-positive occurrence disarms it.
func (s *Store) Fail(operation string, occurrence int) {
	s.mu.Lock()
	s.op, s.nth = operation, occurrence
	s.mu.Unlock()
}

func (s *Store) check(operation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.op != operation || s.nth <= 0 {
		return nil
	}
	s.nth--
	if s.nth == 0 {
		s.op = ""
		return ErrInjected
	}
	return nil
}

func (s *Store) Get(ctx context.Context, ns, key string) ([]byte, error) {
	if err := s.check("get"); err != nil {
		return nil, err
	}
	return s.next.Get(ctx, ns, key)
}
func (s *Store) Set(ctx context.Context, ns, key string, value []byte) error {
	if err := s.check("set"); err != nil {
		return err
	}
	return s.next.Set(ctx, ns, key, value)
}
func (s *Store) Put(ctx context.Context, ns, key string, value []byte) error {
	if err := s.check("put"); err != nil {
		return err
	}
	return s.next.Put(ctx, ns, key, value)
}
func (s *Store) Delete(ctx context.Context, ns, key string) error {
	if err := s.check("delete"); err != nil {
		return err
	}
	return s.next.Delete(ctx, ns, key)
}
func (s *Store) List(ctx context.Context, ns string) ([]string, error) {
	if err := s.check("list"); err != nil {
		return nil, err
	}
	return s.next.List(ctx, ns)
}
func (s *Store) Scan(ctx context.Context, ns, prefix string) ([]string, error) {
	if err := s.check("scan"); err != nil {
		return nil, err
	}
	return s.next.Scan(ctx, ns, prefix)
}
func (s *Store) CompareAndSwap(ctx context.Context, ns, key string, oldValue, newValue []byte) error {
	if err := s.check("compare_and_swap"); err != nil {
		return err
	}
	return s.next.CompareAndSwap(ctx, ns, key, oldValue, newValue)
}
func (s *Store) Iterate(ctx context.Context, ns, prefix string, fn store.IterCallback) error {
	if err := s.check("iterate"); err != nil {
		return err
	}
	return s.next.Iterate(ctx, ns, prefix, fn)
}
func (s *Store) IterateFrom(ctx context.Context, ns, prefix, start string, fn store.IterCallback) error {
	if err := s.check("iterate"); err != nil {
		return err
	}
	return store.IterateFrom(ctx, s.next, ns, prefix, start, fn)
}
func (s *Store) NamespaceExists(ctx context.Context, ns string) (bool, error) {
	if err := s.check("namespace_exists"); err != nil {
		return false, err
	}
	return s.next.NamespaceExists(ctx, ns)
}
func (s *Store) CreateNamespace(ctx context.Context, ns string) error {
	if err := s.check("create_namespace"); err != nil {
		return err
	}
	return s.next.CreateNamespace(ctx, ns)
}
func (s *Store) DeleteNamespace(ctx context.Context, ns string) error {
	if err := s.check("delete_namespace"); err != nil {
		return err
	}
	return s.next.DeleteNamespace(ctx, ns)
}
func (s *Store) ListNamespaces(ctx context.Context) ([]string, error) {
	if err := s.check("list_namespaces"); err != nil {
		return nil, err
	}
	return s.next.ListNamespaces(ctx)
}
func (s *Store) Close() error { return s.next.Close() }
func (s *Store) Batch(ctx context.Context, fn func(context.Context) error) error {
	if err := s.check("batch_begin"); err != nil {
		return err
	}
	batcher, ok := s.next.(store.Batcher)
	if !ok {
		return fn(ctx)
	}
	return batcher.Batch(ctx, func(batchCtx context.Context) error {
		if err := fn(batchCtx); err != nil {
			return err
		}
		return s.check("batch_commit")
	})
}
func (s *Store) View(ctx context.Context, fn func(context.Context) error) error {
	if viewer, ok := s.next.(store.Viewer); ok {
		return viewer.View(ctx, fn)
	}
	return fn(ctx)
}
