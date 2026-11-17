package batv

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testCodec(t *testing.T, secrets ...string) (*Codec, func(time.Duration)) {
	t.Helper()
	var raw [][]byte
	for _, secret := range secrets {
		raw = append(raw, []byte(secret))
	}
	codec, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)
	codec.now = func() time.Time { return now }
	return codec, func(delta time.Duration) { now = now.Add(delta) }
}

const secretA, secretB = "batv-test-secret-aaaaaaaaaaaa", "batv-test-secret-bbbbbbbbbbbb"

func TestSignProducesStandardPrvsAddress(t *testing.T) {
	codec, _ := testCodec(t, secretA)
	signed, err := codec.Sign("Alice@Example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^prvs=[0-9][0-9]{3}[0-9a-f]{6}=Alice@Example\.test$`).MatchString(signed) {
		t.Fatalf("signed = %q", signed)
	}
	if again, _ := codec.Sign(signed); again != signed {
		t.Fatalf("re-signed = %q", again)
	}
	// MTAs may fold case anywhere in the address.
	original, err := codec.Verify(strings.ToLower(signed))
	if err != nil || original != "alice@example.test" {
		t.Fatalf("verify = %q, %v", original, err)
	}
	for _, invalid := range []string{"", "nodomain", "@example.test", "alice@"} {
		if _, err := codec.Sign(invalid); err == nil {
			t.Fatalf("signed %q", invalid)
		}
	}
	if _, err := New(nil); err == nil {
		t.Fatal("codec without secrets")
	}
	if _, err := New([][]byte{[]byte("short")}); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestVerifyRejectsTamperingAndExpiry(t *testing.T) {
	codec, advance := testCodec(t, secretA)
	signed, _ := codec.Sign("alice@example.test")
	for name, address := range map[string]string{
		"other user":   strings.Replace(signed, "=alice@", "=mallory@", 1),
		"other domain": strings.Replace(signed, "@example.test", "@evil.test", 1),
		"bad hash":     signed[:9] + "000000" + signed[15:],
		"bad day":      signed[:6] + "x" + signed[7:],
	} {
		if _, err := codec.Verify(address); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %q verified: %v", name, address, err)
		}
	}
	if _, err := codec.Verify("alice@example.test"); !errors.Is(err, ErrNotTagged) {
		t.Fatalf("untagged = %v", err)
	}
	advance(MaxAge * 24 * time.Hour)
	if _, err := codec.Verify(signed); err != nil {
		t.Fatalf("tag at maximum age = %v", err)
	}
	advance(24 * time.Hour)
	if _, err := codec.Verify(signed); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired tag = %v", err)
	}
	// A tag from the future is refused rather than honored for years.
	future, _ := codec.Sign("alice@example.test")
	advance(-3 * 24 * time.Hour)
	if _, err := codec.Verify(future); !errors.Is(err, ErrExpired) {
		t.Fatalf("future tag = %v", err)
	}
}

func TestRotatedSecretsVerify(t *testing.T) {
	old, _ := testCodec(t, secretB)
	signed, _ := old.Sign("alice@example.test")
	rotated, _ := testCodec(t, secretA, secretB)
	if original, err := rotated.Verify(signed); err != nil || original != "alice@example.test" {
		t.Fatalf("rotated verify = %q, %v", original, err)
	}
	fresh, _ := rotated.Sign("alice@example.test")
	if _, err := old.Verify(fresh); err == nil {
		t.Fatal("tag signed by the new secret verified with only the old one")
	}
}

func TestPolicyRequiresTagOnBouncesAfterGrace(t *testing.T) {
	codec, _ := testCodec(t, secretA)
	now := codec.now()
	signed, _ := codec.Sign("alice@example.test")
	forged := strings.Replace(signed, "=alice@", "=bob@", 1)
	policy := &Policy{Codec: codec, Enabled: true, GraceUntil: now.Add(time.Hour)}

	check := func(address string, bounce bool, at time.Time) (string, error) {
		t.Helper()
		return policy.Recipient(address, bounce, at)
	}
	if got, err := check(signed, true, now); err != nil || got != "alice@example.test" {
		t.Fatalf("tagged bounce = %q, %v", got, err)
	}
	if got, err := check("alice@example.test", true, now); err != nil || got != "alice@example.test" {
		t.Fatalf("untagged bounce in grace = %q, %v", got, err)
	}
	later := now.Add(2 * time.Hour)
	if _, err := check("alice@example.test", true, later); !errors.Is(err, ErrUntagged) {
		t.Fatalf("untagged bounce after grace = %v", err)
	}
	if _, err := check(forged, true, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged bounce = %v", err)
	}
	for _, exempt := range []string{"postmaster@example.test", "Abuse@example.test", "SRS0=abcd=AA=remote.example=bob@example.test"} {
		if got, err := check(exempt, true, later); err != nil || got != exempt {
			t.Fatalf("exempt %q = %q, %v", exempt, got, err)
		}
	}
	// Ordinary mail is never rejected, and valid tags are still removed.
	if got, err := check("alice@example.test", false, later); err != nil || got != "alice@example.test" {
		t.Fatalf("ordinary mail = %q, %v", got, err)
	}
	if got, err := check(signed, false, later); err != nil || got != "alice@example.test" {
		t.Fatalf("ordinary mail to tag = %q, %v", got, err)
	}
	if got, err := check(forged, false, later); err != nil || got != forged {
		t.Fatalf("ordinary mail to forged tag = %q, %v", got, err)
	}
	// Disabled, tags still verify so earlier mail can bounce.
	policy.Enabled = false
	if got, err := check(signed, true, later); err != nil || got != "alice@example.test" {
		t.Fatalf("disabled tagged bounce = %q, %v", got, err)
	}
	if got, err := check("alice@example.test", true, later); err != nil || got != "alice@example.test" {
		t.Fatalf("disabled untagged bounce = %q, %v", got, err)
	}
}
