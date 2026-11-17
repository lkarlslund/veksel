package virus

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func newActionTestService(t *testing.T) (*QuarantineActionService, time.Time) {
	t.Helper()
	_, typed := newQuarantineTestStore(t, QuarantinePolicy{})
	service, err := NewQuarantineActionService(t.Context(), typed, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	return service, now
}

func TestQuarantineActionClaimsAreSignedScopedAndReplaySafe(t *testing.T) {
	service, now := newActionTestService(t)
	entry := QuarantineEntry{ID: "entry-1", OwnerID: "Alice", ExpiresAt: now.Add(2 * time.Hour)}
	token, err := service.Issue(t.Context(), entry, QuarantineActionRelease)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := service.Inspect(t.Context(), token)
	if err != nil || claims.EntryID != entry.ID || claims.OwnerID != "alice" || claims.Action != QuarantineActionRelease || claims.ExpiresAt != now.Add(2*time.Hour).Unix() {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	parts := strings.Split(token, ".")
	tampered := parts[0][:len(parts[0])-1] + map[bool]string{true: "A", false: "B"}[parts[0][len(parts[0])-1] != 'A'] + "." + parts[1]
	if _, err := service.Inspect(t.Context(), tampered); !errors.Is(err, ErrQuarantineActionInvalid) {
		t.Fatalf("tampered token error = %v", err)
	}

	claim, err := service.Claim(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Claim(t.Context(), token); !errors.Is(err, ErrQuarantineActionInProgress) {
		t.Fatalf("concurrent claim error = %v", err)
	}
	if err := service.Complete(t.Context(), claim, true); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Inspect(t.Context(), token); !errors.Is(err, ErrQuarantineActionConsumed) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestQuarantineActionFailureReleasesLeaseAndExpiryIsEnforced(t *testing.T) {
	service, now := newActionTestService(t)
	entry := QuarantineEntry{ID: "entry-1", OwnerID: "alice", ExpiresAt: now.Add(time.Hour)}
	token, err := service.Issue(t.Context(), entry, QuarantineActionSpam)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := service.Claim(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Complete(t.Context(), claim, false); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Claim(t.Context(), token); err != nil {
		t.Fatalf("claim after failed operation = %v", err)
	}
	service.now = func() time.Time { return now.Add(time.Hour) }
	if _, err := service.Inspect(t.Context(), token); !errors.Is(err, ErrQuarantineActionExpired) {
		t.Fatalf("expiry error = %v", err)
	}
	removed, err := service.Cleanup(t.Context(), now.Add(time.Hour), 10)
	if err != nil || removed != 1 {
		t.Fatalf("cleanup = %d, %v", removed, err)
	}
}

func TestQuarantineActionSecretPersistsAcrossRestart(t *testing.T) {
	_, typed := newQuarantineTestStore(t, QuarantinePolicy{})
	first, err := NewQuarantineActionService(t.Context(), typed, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first.now = func() time.Time { return now }
	token, err := first.Issue(t.Context(), QuarantineEntry{ID: "entry", OwnerID: "alice", ExpiresAt: now.Add(time.Hour)}, QuarantineActionRelease)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewQuarantineActionService(t.Context(), typed, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second.now = func() time.Time { return now }
	if _, err := second.Inspect(t.Context(), token); err != nil {
		t.Fatalf("inspect after restart: %v", err)
	}
}
