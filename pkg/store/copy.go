package store

import (
	"context"
	"fmt"
)

// CopyStats summarizes a backend-to-backend copy.
type CopyStats struct {
	Namespaces int
	Keys       int
}

// Copy streams every namespace, key, and opaque value from source to
// destination. Existing destination values are overwritten. Callers that
// require an empty destination must validate that policy before calling Copy.
func Copy(ctx context.Context, source, destination Store) (CopyStats, error) {
	if source == nil || destination == nil {
		return CopyStats{}, fmt.Errorf("source and destination stores are required")
	}
	namespaces, err := source.ListNamespaces(ctx)
	if err != nil {
		return CopyStats{}, fmt.Errorf("list source namespaces: %w", err)
	}
	stats := CopyStats{Namespaces: len(namespaces)}
	for _, namespace := range namespaces {
		exists, err := destination.NamespaceExists(ctx, namespace)
		if err != nil {
			return stats, fmt.Errorf("check destination namespace %q: %w", namespace, err)
		}
		if !exists {
			if err := destination.CreateNamespace(ctx, namespace); err != nil {
				return stats, fmt.Errorf("create destination namespace %q: %w", namespace, err)
			}
		}
		err = source.Iterate(ctx, namespace, "", func(key string, value []byte) (bool, error) {
			if err := destination.Set(ctx, namespace, key, value); err != nil {
				return false, fmt.Errorf("copy %s/%s: %w", namespace, key, err)
			}
			stats.Keys++
			return true, nil
		})
		if err != nil {
			return stats, err
		}
	}
	return stats, nil
}
