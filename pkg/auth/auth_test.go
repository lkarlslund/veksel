package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPasswordReturnsNonEmpty(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty string")
	}
}

func TestHashPasswordBcryptPrefix(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	// bcrypt hashes start with $2a$
	if !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("hash does not start with $2a$, got: %s", hash[:5])
	}
}

func TestHashPasswordDifferentEachTime(t *testing.T) {
	t.Parallel()
	h1, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword 1: %v", err)
	}
	h2, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword 2: %v", err)
	}
	if h1 == h2 {
		t.Error("two hashes of the same password should differ (different salt)")
	}
}

func TestComparePasswordCorrect(t *testing.T) {
	t.Parallel()
	password := "my-secret-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !ComparePassword(password, hash) {
		t.Error("ComparePassword should return true for correct password")
	}
}

func TestComparePasswordWrong(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("correct")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if ComparePassword("wrong", hash) {
		t.Error("ComparePassword should return false for wrong password")
	}
}

func TestComparePasswordEmptyPassword(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword empty: %v", err)
	}
	if !ComparePassword("", hash) {
		t.Error("ComparePassword should return true for empty password")
	}
	if ComparePassword("notempty", hash) {
		t.Error("ComparePassword should return false when comparing non-empty to empty hash")
	}
}

func TestComparePasswordEmptyHash(t *testing.T) {
	t.Parallel()
	if ComparePassword("anything", "") {
		t.Error("ComparePassword should return false for empty hash")
	}
}

func TestBcryptCostParameter(t *testing.T) {
	t.Parallel()
	// Verify that DefaultCost is bcrypt.DefaultCost (10).
	if DefaultCost != 10 {
		t.Errorf("DefaultCost = %d, want 10", DefaultCost)
	}

	// Test binaries hash at the minimum cost; check that it is encoded.
	hash, err := HashPassword("test")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// Format: $2a$XX$... where XX is the cost
	parts := strings.Split(hash, "$")
	// parts[0] = "", parts[1] = "2a", parts[2] = "04", parts[3] = rest
	if len(parts) < 3 {
		t.Fatalf("hash has unexpected format: %s", hash[:5])
	}
	if parts[2] != "04" {
		t.Errorf("encoded cost = %s, want 04", parts[2])
	}
}

func TestHashPasswordUnicode(t *testing.T) {
	t.Parallel()
	password := "pässwörd🔒"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword unicode: %v", err)
	}
	if !ComparePassword(password, hash) {
		t.Error("ComparePassword should work with unicode passwords")
	}
}

func TestHashPasswordRejectsOverlongPassword(t *testing.T) {
	t.Parallel()
	if _, err := HashPassword(strings.Repeat("a", 73)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("73-byte password: err = %v, want ErrPasswordTooLong", err)
	}
	password := strings.Repeat("ø", 36) // 72 bytes
	hash, err := HashPassword(password)
	if err != nil || !ComparePassword(password, hash) {
		t.Fatalf("72-byte password: err = %v", err)
	}
}
