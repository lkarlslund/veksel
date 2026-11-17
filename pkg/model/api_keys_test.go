package model

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func apiKeyTestStore(t *testing.T) *APIKeyStore {
	t.Helper()
	ts := newTestSetup(t)
	if err := ts.EnsureNamespace(t.Context(), NSAPIKeys); err != nil {
		t.Fatal(err)
	}
	return NewAPIKeyStore(ts)
}

func TestAPIKeyRotatePreservesIdentityAndInvalidatesSecret(t *testing.T) {
	keys := apiKeyTestStore(t)
	created, originalSecret, err := keys.CreateWithScopes(t.Context(), "alice", "Laptop", []string{APIKeyScopeMCPWrite, APIKeyScopeMCPRead})
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.UpdateLastUsed(t.Context(), created.ID); err != nil {
		t.Fatal(err)
	}
	before, err := keys.Get(t.Context(), created.ID)
	if err != nil || before.LastUsedAt.IsZero() {
		t.Fatalf("key before rotation = %+v, %v", before, err)
	}

	rotated, replacementSecret, err := keys.Rotate(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if replacementSecret == "" || replacementSecret == originalSecret || rotated.Secret != replacementSecret[:8] {
		t.Fatalf("replacement secret/prefix was not renewed")
	}
	if rotated.ID != created.ID || rotated.UserID != created.UserID || rotated.Name != created.Name || !rotated.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("rotation changed stable identity: before=%+v after=%+v", created, rotated)
	}
	if len(rotated.Scopes) != 2 || rotated.Scopes[0] != APIKeyScopeMCPRead || rotated.Scopes[1] != APIKeyScopeMCPWrite {
		t.Fatalf("rotation changed scopes: %v", rotated.Scopes)
	}
	if !rotated.LastUsedAt.IsZero() || rotated.RotatedAt.IsZero() || rotated.RotationCount != 1 {
		t.Fatalf("rotation evidence = %+v", rotated)
	}
	if matched, err := keys.GetBySecret(t.Context(), originalSecret); err != nil || matched != nil {
		t.Fatalf("old secret still authenticates: key=%+v err=%v", matched, err)
	}
	if matched, err := keys.GetBySecret(t.Context(), replacementSecret); err != nil || matched == nil || matched.ID != created.ID {
		t.Fatalf("replacement does not authenticate: key=%+v err=%v", matched, err)
	}

	second, _, err := keys.Rotate(t.Context(), created.ID)
	if err != nil || second.RotationCount != 2 || second.RotatedAt.Before(rotated.RotatedAt) {
		t.Fatalf("second rotation = %+v, %v", second, err)
	}
	if err := keys.Revoke(t.Context(), created.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keys.Rotate(t.Context(), created.ID); !errors.Is(err, ErrAPIKeyRevoked) {
		t.Fatalf("rotate revoked error = %v", err)
	}
	if err := keys.UpdateLastUsed(t.Context(), created.ID); !errors.Is(err, ErrAPIKeyRevoked) {
		t.Fatalf("update revoked error = %v", err)
	}
}

func TestAPIKeyRotateAndLastUsedCannotRestoreOldHash(t *testing.T) {
	keys := apiKeyTestStore(t)
	created, originalSecret, err := keys.CreateWithScopes(t.Context(), "alice", "Concurrent", []string{APIKeyScopeMCPRead})
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 20; iteration++ {
		var replacement string
		var rotateErr, usedErr error
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			_, replacement, rotateErr = keys.Rotate(t.Context(), created.ID)
		}()
		go func() {
			defer group.Done()
			<-start
			usedErr = keys.UpdateLastUsed(t.Context(), created.ID)
		}()
		close(start)
		group.Wait()
		if rotateErr != nil || usedErr != nil {
			t.Fatalf("iteration %d: rotate=%v last-used=%v", iteration, rotateErr, usedErr)
		}
		if matched, err := keys.GetBySecret(t.Context(), originalSecret); err != nil || matched != nil {
			t.Fatalf("iteration %d: obsolete secret restored: key=%+v err=%v", iteration, matched, err)
		}
		if matched, err := keys.GetBySecret(t.Context(), replacement); err != nil || matched == nil {
			t.Fatalf("iteration %d: replacement missing: key=%+v err=%v", iteration, matched, err)
		}
		originalSecret = replacement
	}
}

func TestAPIKeyRotateMissing(t *testing.T) {
	keys := apiKeyTestStore(t)
	if _, _, err := keys.Rotate(t.Context(), "missing"); err == nil {
		t.Fatal("rotating a missing key succeeded")
	}
	// Secret generation deliberately happens before the short store batch; a
	// missing ID still must not create any credential as a side effect.
	listed, err := keys.ListByUser(t.Context(), "alice")
	if err != nil || len(listed) != 0 {
		t.Fatalf("keys after missing rotation = %+v, %v", listed, err)
	}
}

func TestAPIKeyRotationTimestampIsUTC(t *testing.T) {
	keys := apiKeyTestStore(t)
	created, _, err := keys.Create(t.Context(), "alice", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	rotated, _, err := keys.Rotate(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RotatedAt.Location() != time.UTC {
		t.Fatalf("rotation location = %v", rotated.RotatedAt.Location())
	}
}
