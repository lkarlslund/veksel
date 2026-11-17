package pebblestore

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		t.Helper()
		s, err := New(t.TempDir())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return s
	})
}
