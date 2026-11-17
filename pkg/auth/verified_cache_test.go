package auth

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestVerifiedCacheRemembersOnlyMatchesWithinTTL(t *testing.T) {
	t.Parallel()
	cache := newVerifiedCache(2, time.Minute)
	now := time.Unix(1_000_000, 0)
	cache.now = func() time.Time { return now }

	if cache.verified("secret", "hash-1") {
		t.Fatal("empty cache verified a password")
	}
	cache.remember("secret", "hash-1")
	if !cache.verified("secret", "hash-1") {
		t.Fatal("remembered match not verified")
	}
	if cache.verified("other", "hash-1") || cache.verified("secret", "hash-2") {
		t.Fatal("cache verified a different password or a changed hash")
	}
	now = now.Add(2 * time.Minute)
	if cache.verified("secret", "hash-1") {
		t.Fatal("expired match verified")
	}
	for _, hash := range []string{"a", "b", "c"} {
		cache.remember("secret", hash)
	}
	if len(cache.entries) > 2 {
		t.Fatalf("cache holds %d entries, limit 2", len(cache.entries))
	}
	if !cache.verified("secret", "c") {
		t.Fatal("latest match evicted")
	}
}

func TestComparePasswordChecksChangedHashes(t *testing.T) {
	t.Parallel()
	first, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	// The second check is answered from the verified cache.
	for range 2 {
		if !ComparePassword("correct horse", first) {
			t.Fatal("matching password rejected")
		}
	}
	if ComparePassword("wrong horse", first) {
		t.Fatal("wrong password accepted")
	}
	second, err := HashPassword("new horse")
	if err != nil {
		t.Fatal(err)
	}
	if ComparePassword("correct horse", second) {
		t.Fatal("old password accepted against the changed hash")
	}
}

// BenchmarkComparePasswordRepeated measures repeated verification of one
// credential at production cost, as an HTTP Basic client causes.
func BenchmarkComparePasswordRepeated(b *testing.B) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse"), DefaultCost)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if !ComparePassword("correct horse", string(hash)) {
			b.Fatal("rejected")
		}
	}
}
