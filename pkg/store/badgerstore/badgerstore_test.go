package badgerstore

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

func TestReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Set(t.Context(), "items", "one", []byte("durable")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s, err = New(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	got, err := s.Get(t.Context(), "items", "one")
	if err != nil || string(got) != "durable" {
		t.Fatalf("Get after reopen: got %q, %v", got, err)
	}
}
