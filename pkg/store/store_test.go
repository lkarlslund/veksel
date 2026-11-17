package store

import (
	"context"
	"errors"
	"io"
	"testing"
)

type otherKey struct{}

func TestWithoutSync(t *testing.T) {
	if SyncDisabled(context.Background()) {
		t.Fatal("background context reports sync disabled")
	}
	marked := WithoutSync(context.Background())
	if !SyncDisabled(context.WithValue(marked, otherKey{}, 1)) {
		t.Fatal("context derived from WithoutSync lost the mark")
	}
}

// TestStoreIsCloser verifies Store satisfies io.Closer.
func TestStoreIsCloser(t *testing.T) {
	var _ io.Closer = Store(nil)
}

// TestErrorConstants verifies the exported error values are non-nil.
func TestErrorConstants(t *testing.T) {
	if ErrNotFound == nil {
		t.Fatal("ErrNotFound must not be nil")
	}
	if ErrExists == nil {
		t.Fatal("ErrExists must not be nil")
	}
	if ErrPreconditionFailed == nil {
		t.Fatal("ErrPreconditionFailed must not be nil")
	}

	// Verify they are distinct
	if errors.Is(ErrNotFound, ErrExists) {
		t.Fatal("ErrNotFound and ErrExists should not be the same")
	}
	if errors.Is(ErrNotFound, ErrPreconditionFailed) {
		t.Fatal("ErrNotFound and ErrPreconditionFailed should not be the same")
	}
	if errors.Is(ErrExists, ErrPreconditionFailed) {
		t.Fatal("ErrExists and ErrPreconditionFailed should not be the same")
	}
}

// TestBackendConstants verifies backend constants.
func TestBackendConstants(t *testing.T) {
	if BackendJSON != "json" {
		t.Fatalf("BackendJSON expected json, got %q", BackendJSON)
	}
	if BackendPebble != "pebble" {
		t.Fatalf("BackendPebble expected pebble, got %q", BackendPebble)
	}
	if BackendBadger != "badger" {
		t.Fatalf("BackendBadger expected badger, got %q", BackendBadger)
	}
}

// TestIterCallbackTypes verifies the IterCallback signature.
func TestIterCallbackTypes(t *testing.T) {
	var fn IterCallback = func(key string, value []byte) (bool, error) {
		return true, nil
	}
	if fn == nil {
		t.Fatal("callback should not be nil")
	}
}
