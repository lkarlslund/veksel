package store_test

import (
	"context"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func TestCopyJSONToPebblePreservesOpaqueValues(t *testing.T) {
	ctx := context.Background()
	source, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	destination, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destination.Close() })

	values := map[string]map[string][]byte{
		"items": {"mail/one": {0, 1, 2, 255}, "mail:two": []byte("{\"subject\":\"hello\"}")},
		"users": {"alice": []byte("{\"id\":\"alice\"}")},
	}
	for namespace, entries := range values {
		if err := source.CreateNamespace(ctx, namespace); err != nil {
			t.Fatal(err)
		}
		for key, value := range entries {
			if err := source.Set(ctx, namespace, key, value); err != nil {
				t.Fatal(err)
			}
		}
	}

	stats, err := store.Copy(ctx, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Namespaces != 2 || stats.Keys != 3 {
		t.Fatalf("stats = %#v, want 2 namespaces and 3 keys", stats)
	}
	for namespace, entries := range values {
		for key, want := range entries {
			got, err := destination.Get(ctx, namespace, key)
			if err != nil || string(got) != string(want) {
				t.Fatalf("%s/%s = %q, %v, want %q", namespace, key, got, err, want)
			}
		}
	}
}
