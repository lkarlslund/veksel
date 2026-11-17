package faultstore

import (
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
	"github.com/lkarlslund/veksel/pkg/store/storetest"
)

func TestBatchCommitFailureRollsBack(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	if err := backend.CreateNamespace(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	faults := New(backend)
	faults.Fail("batch_commit", 1)
	err = store.Batch(t.Context(), faults, func(ctx context.Context) error {
		return faults.Set(ctx, "test", "key", []byte("value"))
	})
	if !errors.Is(err, ErrInjected) {
		t.Fatalf("batch error = %v", err)
	}
	if _, err := backend.Get(t.Context(), "test", "key"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failed batch became visible: %v", err)
	}
}

func TestProductionBackendsRollbackInjectedCommitFailure(t *testing.T) {
	constructors := map[string]func(string) (store.Store, error){
		"pebble": func(path string) (store.Store, error) { return pebblestore.New(path) },
		"badger": func(path string) (store.Store, error) { return badgerstore.New(path) },
	}
	for name, open := range constructors {
		t.Run(name, func(t *testing.T) {
			backend, err := open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = backend.Close() }()
			if err := backend.CreateNamespace(t.Context(), "test"); err != nil {
				t.Fatal(err)
			}
			faults := New(backend)
			faults.Fail("batch_commit", 1)
			err = store.Batch(t.Context(), faults, func(ctx context.Context) error {
				if err := faults.Set(ctx, "test", "a", []byte("one")); err != nil {
					return err
				}
				return faults.Set(ctx, "test", "b", []byte("two"))
			})
			if !errors.Is(err, ErrInjected) {
				t.Fatalf("batch error = %v", err)
			}
			keys, err := backend.List(t.Context(), "test")
			if err != nil || len(keys) != 0 {
				t.Fatalf("failed batch keys = %v, %v", keys, err)
			}
		})
	}
}

func TestRangeIteration(t *testing.T) {
	storetest.RunRangeIteration(t, func(t *testing.T) store.Store {
		backend, err := pebblestore.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return New(backend)
	})
}
