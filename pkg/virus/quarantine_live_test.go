package virus

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestQuarantineStoreSetPolicyAppliesToLaterAdmissions(t *testing.T) {
	quarantine, _ := newQuarantineTestStore(t, QuarantinePolicy{Retention: time.Hour, MaxEntries: 1})
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "one", MessageData: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantine.Add(t.Context(), &QuarantineEntry{ID: "two", MessageData: []byte("b")}); !errors.Is(err, ErrQuarantineCapacity) {
		t.Fatalf("admission over the limit = %v", err)
	}
	if err := quarantine.SetPolicy(QuarantinePolicy{Retention: 48 * time.Hour, MaxEntries: 5}); err != nil {
		t.Fatal(err)
	}
	entry := &QuarantineEntry{ID: "two", MessageData: []byte("b")}
	if _, err := quarantine.Add(t.Context(), entry); err != nil {
		t.Fatalf("admission after raising the limit: %v", err)
	}
	if got := entry.ExpiresAt.Sub(entry.CreatedAt); got != 48*time.Hour {
		t.Fatalf("retention = %s, want 48h", got)
	}
	if err := quarantine.SetPolicy(QuarantinePolicy{Retention: -time.Hour}); err == nil {
		t.Fatal("negative policy accepted")
	}
	if status, _ := quarantine.Status(t.Context()); status.MaxEntries != 5 {
		t.Fatalf("status after rejected policy = %+v", status)
	}
}

func TestQuarantineActionServiceSetTTL(t *testing.T) {
	service, now := newActionTestService(t)
	entry := QuarantineEntry{ID: "entry-1", OwnerID: "alice"}
	expiry := func() int64 {
		t.Helper()
		token, err := service.Issue(t.Context(), entry, QuarantineActionRelease)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
		if err != nil {
			t.Fatal(err)
		}
		var claims QuarantineActionClaims
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		return claims.ExpiresAt
	}
	if got := expiry(); got != now.Add(24*time.Hour).Unix() {
		t.Fatalf("initial expiry = %d", got)
	}
	if err := service.SetTTL(time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := expiry(); got != now.Add(time.Hour).Unix() {
		t.Fatalf("expiry after SetTTL = %d", got)
	}
	if err := service.SetTTL(0); err == nil {
		t.Fatal("zero TTL accepted")
	}
}

func TestQuarantineDigestServiceSetConfig(t *testing.T) {
	service, _, _ := newDigestTestService(t)
	next := service.currentConfig()
	next.MaxEntries, next.FromAddress = 7, "Other <other@example.test>"
	if err := service.SetConfig(next); err != nil {
		t.Fatal(err)
	}
	if got := service.currentConfig(); got.MaxEntries != 7 || got.FromAddress != next.FromAddress {
		t.Fatalf("config = %+v", got)
	}
	next.BaseURL = "ftp://invalid"
	if err := service.SetConfig(next); err == nil {
		t.Fatal("invalid config accepted")
	}
	if got := service.currentConfig(); got.MaxEntries != 7 || got.BaseURL != "https://mail.example.test" {
		t.Fatalf("rejected config replaced the active one: %+v", got)
	}
}
