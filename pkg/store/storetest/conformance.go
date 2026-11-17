// Package storetest provides the shared behavioral contract for Store engines.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
)

// Factory creates an empty store. The caller closes it.
type Factory func(t *testing.T) store.Store

// Run exercises the behavior required from every production store engine.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	t.Run("crud", func(t *testing.T) {
		s := factory(t)
		defer closeStore(t, s)
		ctx := context.Background()

		if _, err := s.Get(ctx, "mail", "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get missing: got %v, want ErrNotFound", err)
		}
		if err := s.Set(ctx, "mail", "b", []byte("one")); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := s.Set(ctx, "mail", "b", []byte("two")); err != nil {
			t.Fatalf("Set overwrite: %v", err)
		}
		got, err := s.Get(ctx, "mail", "b")
		if err != nil || string(got) != "two" {
			t.Fatalf("Get: got %q, %v", got, err)
		}
		if err := s.Put(ctx, "mail", "b", []byte("duplicate")); !errors.Is(err, store.ErrExists) {
			t.Fatalf("Put duplicate: got %v, want ErrExists", err)
		}
		if err := s.Put(ctx, "mail", "a", []byte("first")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.CompareAndSwap(ctx, "mail", "b", []byte("bad"), []byte("three")); !errors.Is(err, store.ErrPreconditionFailed) {
			t.Fatalf("CompareAndSwap mismatch: got %v", err)
		}
		if err := s.CompareAndSwap(ctx, "mail", "b", []byte("two"), []byte("three")); err != nil {
			t.Fatalf("CompareAndSwap: %v", err)
		}
		if err := s.Delete(ctx, "mail", "a"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := s.Delete(ctx, "mail", "a"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Delete missing: got %v, want ErrNotFound", err)
		}
	})

	t.Run("ordered scans", func(t *testing.T) {
		s := factory(t)
		defer closeStore(t, s)
		ctx := context.Background()
		for _, key := range []string{"z", "item/3", "item/1", "item/2", "other"} {
			if err := s.Set(ctx, "records", key, []byte("value:"+key)); err != nil {
				t.Fatalf("Set %q: %v", key, err)
			}
		}
		got, err := s.Scan(ctx, "records", "item/")
		want := []string{"item/1", "item/2", "item/3"}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("Scan: got %v, %v; want %v", got, err, want)
		}
		var iterated []string
		err = s.Iterate(ctx, "records", "item/", func(key string, value []byte) (bool, error) {
			iterated = append(iterated, key+"="+string(value))
			return true, nil
		})
		wantIterated := []string{"item/1=value:item/1", "item/2=value:item/2", "item/3=value:item/3"}
		if err != nil || !reflect.DeepEqual(iterated, wantIterated) {
			t.Fatalf("Iterate: got %v, %v; want %v", iterated, err, wantIterated)
		}
	})

	t.Run("range iteration", func(t *testing.T) {
		RunRangeIteration(t, factory)
	})

	t.Run("namespaces", func(t *testing.T) {
		s := factory(t)
		defer closeStore(t, s)
		ctx := context.Background()
		for _, namespace := range []string{"users", "folders"} {
			if err := s.CreateNamespace(ctx, namespace); err != nil {
				t.Fatalf("CreateNamespace %q: %v", namespace, err)
			}
		}
		if err := s.CreateNamespace(ctx, "users"); !errors.Is(err, store.ErrExists) {
			t.Fatalf("CreateNamespace duplicate: got %v", err)
		}
		if err := s.Set(ctx, "users", "alice", []byte("record")); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := s.ListNamespaces(ctx)
		want := []string{"folders", "users"}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("ListNamespaces: got %v, %v; want %v", got, err, want)
		}
		if err := s.DeleteNamespace(ctx, "users"); err != nil {
			t.Fatalf("DeleteNamespace: %v", err)
		}
		if _, err := s.Get(ctx, "users", "alice"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get deleted namespace value: got %v", err)
		}
	})

	t.Run("batch commit and rollback", func(t *testing.T) {
		s := factory(t)
		defer closeStore(t, s)
		ctx := context.Background()
		if err := store.Batch(ctx, s, func(batchCtx context.Context) error {
			if err := s.Set(batchCtx, "n", "a", []byte("1")); err != nil {
				return err
			}
			if err := s.Set(batchCtx, "n", "b", []byte("2")); err != nil {
				return err
			}
			got, err := s.Get(batchCtx, "n", "a")
			if err != nil || string(got) != "1" {
				return fmt.Errorf("read own write: got %q: %w", got, err)
			}
			return nil
		}); err != nil {
			t.Fatalf("commit Batch: %v", err)
		}
		rollback := errors.New("rollback")
		if err := store.Batch(ctx, s, func(batchCtx context.Context) error {
			if err := s.Set(batchCtx, "n", "a", []byte("changed")); err != nil {
				return err
			}
			return rollback
		}); !errors.Is(err, rollback) {
			t.Fatalf("rollback Batch: got %v", err)
		}
		got, err := s.Get(ctx, "n", "a")
		if err != nil || string(got) != "1" {
			t.Fatalf("rollback value: got %q, %v", got, err)
		}
	})

	t.Run("stable read view", func(t *testing.T) {
		s := factory(t)
		defer closeStore(t, s)
		if _, ok := s.(store.Viewer); !ok {
			t.Fatal("production store does not implement store.Viewer")
		}
		ctx := context.Background()
		if err := s.Set(ctx, "records", "item/1", []byte("one")); err != nil {
			t.Fatal(err)
		}
		err := store.View(ctx, s, func(viewCtx context.Context) error {
			got, err := s.Get(viewCtx, "records", "item/1")
			if err != nil || string(got) != "one" {
				return fmt.Errorf("get in view: got %q: %w", got, err)
			}
			keys, err := s.Scan(viewCtx, "records", "item/")
			if err != nil || !reflect.DeepEqual(keys, []string{"item/1"}) {
				return fmt.Errorf("scan in view: got %v: %w", keys, err)
			}
			return store.View(viewCtx, s, func(nested context.Context) error {
				if !store.InView(nested, s) {
					return errors.New("nested context is not marked as a view")
				}
				_, err := s.Get(nested, "records", "item/1")
				return err
			})
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("concurrent compare and swap", func(t *testing.T) {
		s := factory(t)
		defer closeStore(t, s)
		ctx := context.Background()
		if err := s.Set(ctx, "state", "winner", []byte("open")); err != nil {
			t.Fatalf("Set: %v", err)
		}
		const contenders = 16
		var wg sync.WaitGroup
		results := make(chan error, contenders)
		for i := range contenders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- s.CompareAndSwap(ctx, "state", "winner", []byte("open"), []byte(fmt.Sprintf("%d", i)))
			}()
		}
		wg.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
				continue
			}
			if !errors.Is(err, store.ErrPreconditionFailed) {
				t.Fatalf("CompareAndSwap contender: %v", err)
			}
		}
		if successes != 1 {
			t.Fatalf("successful CompareAndSwap calls: got %d, want 1", successes)
		}
	})

	RunClosed(t, factory)
}

// closedOperations lists every Store operation, plus the optional Batcher,
// Viewer, and Compactor capabilities the store has. Each acts on key "a" of
// the namespace it is given and returns its error.
// RunRangeIteration exercises store.IterateFrom, which every engine serves
// through store.RangeIterator: iteration resumes at start, keeps prefix and
// order semantics, stops early, and sees a batch's own writes.
func RunRangeIteration(t *testing.T, factory Factory) {
	t.Helper()
	s := factory(t)
	defer closeStore(t, s)
	ctx := context.Background()
	if _, ok := s.(store.RangeIterator); !ok {
		t.Fatalf("%T does not implement store.RangeIterator", s)
	}
	namespaces := []string{"journal", "records"}
	for _, namespace := range namespaces {
		if err := s.CreateNamespace(ctx, namespace); err != nil && !errors.Is(err, store.ErrExists) {
			t.Fatalf("CreateNamespace %q: %v", namespace, err)
		}
		for _, key := range []string{"a", "item/1", "item/3", "item/5", "item/7", "z"} {
			if err := s.Set(ctx, namespace, key, []byte("value:"+key)); err != nil {
				t.Fatalf("Set %q: %v", key, err)
			}
		}
	}
	collect := func(ctx context.Context, namespace, prefix, start string, limit int) ([]string, error) {
		var got []string
		err := store.IterateFrom(ctx, s, namespace, prefix, start, func(key string, value []byte) (bool, error) {
			if string(value) != "value:"+key {
				return false, fmt.Errorf("value for %q = %q", key, value)
			}
			got = append(got, key)
			return limit == 0 || len(got) < limit, nil
		})
		return got, err
	}
	cases := []struct {
		prefix, start string
		limit         int
		want          []string
	}{
		{prefix: "item/", start: "", want: []string{"item/1", "item/3", "item/5", "item/7"}},
		{prefix: "item/", start: "a", want: []string{"item/1", "item/3", "item/5", "item/7"}},
		{prefix: "item/", start: "item/3", want: []string{"item/3", "item/5", "item/7"}},
		{prefix: "item/", start: "item/4", want: []string{"item/5", "item/7"}},
		{prefix: "item/", start: "item/4", limit: 1, want: []string{"item/5"}},
		{prefix: "item/", start: "item/8", want: nil},
		{prefix: "item/", start: "j", want: nil},
		{prefix: "item/", start: "\xff", want: nil},
		{prefix: "", start: "item/6", want: []string{"item/7", "z"}},
	}
	for _, namespace := range namespaces {
		for _, tc := range cases {
			got, err := collect(ctx, namespace, tc.prefix, tc.start, tc.limit)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s: IterateFrom(%q, %q) = %v, %v; want %v", namespace, tc.prefix, tc.start, got, err, tc.want)
			}
		}
	}
	err := store.Batch(ctx, s, func(batchCtx context.Context) error {
		if err := s.Set(batchCtx, "journal", "item/4", []byte("value:item/4")); err != nil {
			return err
		}
		if err := s.Delete(batchCtx, "journal", "item/5"); err != nil {
			return err
		}
		got, err := collect(batchCtx, "journal", "item/", "item/2", 0)
		if want := []string{"item/3", "item/4", "item/7"}; err != nil || !reflect.DeepEqual(got, want) {
			return fmt.Errorf("batch IterateFrom = %v, %v; want %v", got, err, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Batch: %v", err)
	}
	got, err := collect(ctx, "journal", "item/", "item/4", 0)
	if want := []string{"item/4", "item/7"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("committed IterateFrom = %v, %v; want %v", got, err, want)
	}
}

func closedOperations(s store.Store) map[string]func(ctx context.Context, ns string) error {
	operations := map[string]func(context.Context, string) error{
		"Get":             func(ctx context.Context, ns string) error { _, err := s.Get(ctx, ns, "a"); return err },
		"Set":             func(ctx context.Context, ns string) error { return s.Set(ctx, ns, "a", []byte("1")) },
		"Put":             func(ctx context.Context, ns string) error { return s.Put(ctx, ns, "a", []byte("1")) },
		"Delete":          func(ctx context.Context, ns string) error { return s.Delete(ctx, ns, "a") },
		"List":            func(ctx context.Context, ns string) error { _, err := s.List(ctx, ns); return err },
		"Scan":            func(ctx context.Context, ns string) error { _, err := s.Scan(ctx, ns, "a"); return err },
		"NamespaceExists": func(ctx context.Context, ns string) error { _, err := s.NamespaceExists(ctx, ns); return err },
		"CreateNamespace": func(ctx context.Context, ns string) error { return s.CreateNamespace(ctx, ns+"-created") },
		"DeleteNamespace": func(ctx context.Context, ns string) error { return s.DeleteNamespace(ctx, ns) },
		"ListNamespaces":  func(ctx context.Context, _ string) error { _, err := s.ListNamespaces(ctx); return err },
		"CompareAndSwap": func(ctx context.Context, ns string) error {
			return s.CompareAndSwap(ctx, ns, "a", []byte("1"), []byte("1"))
		},
		"Iterate": func(ctx context.Context, ns string) error {
			return s.Iterate(ctx, ns, "", func(string, []byte) (bool, error) { return true, nil })
		},
	}
	if batcher, ok := s.(store.Batcher); ok {
		operations["Batch"] = func(ctx context.Context, ns string) error {
			return batcher.Batch(ctx, func(batchCtx context.Context) error { return s.Set(batchCtx, ns, "a", []byte("1")) })
		}
	}
	if viewer, ok := s.(store.Viewer); ok {
		operations["View"] = func(ctx context.Context, ns string) error {
			return viewer.View(ctx, func(viewCtx context.Context) error { _, err := s.Get(viewCtx, ns, "a"); return err })
		}
	}
	if compactor, ok := s.(store.Compactor); ok {
		operations["CompactPrefix"] = func(ctx context.Context, ns string) error { return compactor.CompactPrefix(ctx, ns, "") }
	}
	return operations
}

// seed creates namespace ns holding key "a".
func seed(t *testing.T, s store.Store, ns string) {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateNamespace(ctx, ns); err != nil {
		t.Fatalf("CreateNamespace %q: %v", ns, err)
	}
	if err := s.Set(ctx, ns, "a", []byte("1")); err != nil {
		t.Fatalf("Set %q: %v", ns, err)
	}
}

// RunClosed requires every operation after Close to fail with
// store.ErrClosed instead of reaching the released engine, a second Close to
// succeed, and Close to be safe while operations run concurrently.
func RunClosed(t *testing.T, factory Factory) {
	t.Helper()
	t.Run("operations after close", func(t *testing.T) {
		s := factory(t)
		seed(t, s, "n")
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		for name, operation := range closedOperations(s) {
			if err := operation(context.Background(), "n"); !errors.Is(err, store.ErrClosed) {
				t.Errorf("%s after Close: got %v, want ErrClosed", name, err)
			}
		}
		if err := s.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	})

	t.Run("close during operations", func(t *testing.T) {
		s := factory(t)
		operations := closedOperations(s)
		for name := range operations {
			seed(t, s, name)
		}
		var wg sync.WaitGroup
		started := make(chan struct{}, len(operations))
		failures := make(chan error, len(operations))
		for name, operation := range operations {
			wg.Add(1)
			go func() {
				defer wg.Done()
				started <- struct{}{}
				for {
					err := operation(context.Background(), name)
					if errors.Is(err, store.ErrClosed) {
						return
					}
					// Each operation owns its namespace, but repeating one
					// may find its key or namespace already gone or present.
					if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrExists) {
						failures <- fmt.Errorf("%s: %w", name, err)
						return
					}
				}
			}()
		}
		for range operations {
			<-started
		}
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
	})
}

func closeStore(t *testing.T, s store.Store) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
