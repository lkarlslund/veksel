package model

import (
	"context"

	"github.com/lkarlslund/veksel/pkg/store"
)

// collection is the JSON records of one type kept in one namespace. It holds
// the get/set/list boilerplate shared by the typed entity stores.
type collection[T any] struct {
	ts *TypedStore
	ns string
}

func newCollection[T any](ts *TypedStore, ns string) collection[T] {
	return collection[T]{ts: ts, ns: ns}
}

// get decodes the record at key. A decode error returns the partially decoded
// value together with the error, exactly like TypedStore.Get.
func (c collection[T]) get(ctx context.Context, key string) (T, error) {
	var v T
	err := c.ts.Get(ctx, c.ns, key, &v)
	return v, err
}

func (c collection[T]) set(ctx context.Context, key string, v T) error {
	return c.ts.Set(ctx, c.ns, key, v)
}

func (c collection[T]) put(ctx context.Context, key string, v T) error {
	return c.ts.Put(ctx, c.ns, key, v)
}

func (c collection[T]) delete(ctx context.Context, key string) error {
	return c.ts.Delete(ctx, c.ns, key)
}

// list decodes every record in key order and fails on the first one that
// cannot be read. The result is non-nil on success.
func (c collection[T]) list(ctx context.Context) ([]T, error) {
	keys, err := c.ts.List(ctx, c.ns)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(keys))
	for _, key := range keys {
		v, err := c.get(ctx, key)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// scan calls fn with each readable record in key order until fn returns
// false. Records that cannot be read or decoded are skipped.
func (c collection[T]) scan(ctx context.Context, fn func(key string, v T) bool) error {
	keys, err := c.ts.List(ctx, c.ns)
	if err != nil {
		return err
	}
	for _, key := range keys {
		v, err := c.get(ctx, key)
		if err != nil {
			continue
		}
		if !fn(key, v) {
			break
		}
	}
	return nil
}

// filter returns the readable records accepted by keep, or nil when none are.
func (c collection[T]) filter(ctx context.Context, keep func(T) bool) ([]T, error) {
	var out []T
	err := c.scan(ctx, func(_ string, v T) bool {
		if keep(v) {
			out = append(out, v)
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// find returns the key and value of the first readable record accepted by
// match, or store.ErrNotFound when there is none.
func (c collection[T]) find(ctx context.Context, match func(T) bool) (string, T, error) {
	var (
		key   string
		found T
		ok    bool
	)
	err := c.scan(ctx, func(k string, v T) bool {
		if match(v) {
			key, found, ok = k, v, true
		}
		return !ok
	})
	if err == nil && !ok {
		err = store.ErrNotFound
	}
	return key, found, err
}

// keepAll is a filter predicate that accepts every record.
func keepAll[T any](T) bool { return true }
