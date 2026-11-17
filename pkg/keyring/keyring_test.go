package keyring

import (
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestRingRotationKeepsRetiredKeysAndSharesInstances(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ring, err := For(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := For(t.Context(), backend); err != nil || again != ring {
		t.Fatalf("For returned a second ring for the same backend: %p %p %v", ring, again, err)
	}
	sealed, err := ring.SealSecret("purpose", "id", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	before := ring.Status()
	if SealedKeyID(sealed) != before.ActiveKeyID {
		t.Fatalf("sealed key ID = %q, want %q", SealedKeyID(sealed), before.ActiveKeyID)
	}
	after, err := ring.Rotate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after.ActiveKeyID == before.ActiveKeyID || after.KeyCount != 2 {
		t.Fatalf("rotation status = %+v", after)
	}
	if plaintext, err := ring.OpenSecret("purpose", "id", sealed); err != nil || string(plaintext) != "secret" {
		t.Fatalf("retired key open = %q, %v", plaintext, err)
	}
	if _, err := ring.OpenSecret("purpose", "other", sealed); err == nil {
		t.Fatal("envelope opened under different associated data")
	}
	reloaded, err := Load(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ActiveKeyID() != after.ActiveKeyID {
		t.Fatalf("reloaded active = %q, want %q", reloaded.ActiveKeyID(), after.ActiveKeyID)
	}

	foreignBackend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreignBackend.Close() })
	foreign, err := Load(t.Context(), foreignBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.OpenSecret("purpose", "id", sealed); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("foreign ring open error = %v, want ErrKeyUnavailable", err)
	}
}
