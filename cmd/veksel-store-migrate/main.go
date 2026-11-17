// veksel-store-migrate copies a stopped Veksel installation between storage
// backends without interpreting model values.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func main() {
	fromBackend := flag.String("from-backend", "json", "source backend: json or pebble")
	fromPath := flag.String("from", "./data", "source backend path")
	toBackend := flag.String("to-backend", "pebble", "destination backend: json or pebble")
	toPath := flag.String("to", "./data/pebble", "destination backend path")
	flag.Parse()

	if *fromBackend == *toBackend && *fromPath == *toPath {
		fatalf("source and destination must differ")
	}
	source, err := openStore(store.Backend(*fromBackend), *fromPath)
	if err != nil {
		fatalf("open source: %v", err)
	}
	defer func() { _ = source.Close() }()
	destination, err := openStore(store.Backend(*toBackend), *toPath)
	if err != nil {
		fatalf("open destination: %v", err)
	}
	defer func() { _ = destination.Close() }()

	existing, err := destination.ListNamespaces(context.Background())
	if err != nil {
		fatalf("inspect destination: %v", err)
	}
	if len(existing) != 0 {
		fatalf("destination is not empty (%d namespaces); refusing to overwrite", len(existing))
	}
	stats, err := store.Copy(context.Background(), source, destination)
	if err != nil {
		fatalf("copy store: %v", err)
	}
	verified, err := countStore(context.Background(), destination)
	if err != nil {
		fatalf("verify destination: %v", err)
	}
	if verified != stats {
		fatalf("verification mismatch: copied %+v, destination has %+v", stats, verified)
	}
	fmt.Printf("copied %d keys in %d namespaces from %s to %s\n", stats.Keys, stats.Namespaces, *fromBackend, *toBackend)
}

func countStore(ctx context.Context, backend store.Store) (store.CopyStats, error) {
	namespaces, err := backend.ListNamespaces(ctx)
	if err != nil {
		return store.CopyStats{}, err
	}
	stats := store.CopyStats{Namespaces: len(namespaces)}
	for _, namespace := range namespaces {
		keys, err := backend.List(ctx, namespace)
		if err != nil {
			return stats, err
		}
		stats.Keys += len(keys)
	}
	return stats, nil
}

func openStore(backend store.Backend, path string) (store.Store, error) {
	switch backend {
	case store.BackendJSON:
		return jsonstore.New(path)
	case store.BackendPebble:
		return pebblestore.New(path)
	default:
		return nil, fmt.Errorf("unknown backend %q", backend)
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "veksel-store-migrate: "+format+"\n", args...)
	os.Exit(1)
}
