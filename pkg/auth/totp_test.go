package auth

import (
	"strings"
	"testing"
	"time"
)

// TestTOTPRFC6238Vectors checks the SHA1 vectors of RFC 6238 Appendix B,
// truncated to the six digits Veksel uses.
func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, vector := range []struct {
		unix int64
		code string
	}{
		{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"},
		{1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
	} {
		got := TOTPCode(secret, TOTPStep(time.Unix(vector.unix, 0)))
		if want := vector.code[2:]; got != want {
			t.Errorf("TOTP at %d = %s, want %s", vector.unix, got, want)
		}
	}
}

func TestValidateTOTPSkewAndReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	step := TOTPStep(now)
	for offset := int64(-1); offset <= 1; offset++ {
		if got, ok := ValidateTOTP(secret, TOTPCode(secret, step+offset), now, 0); !ok || got != step+offset {
			t.Fatalf("offset %d: step=%d ok=%v", offset, got, ok)
		}
	}
	for _, offset := range []int64{-2, 2} {
		if _, ok := ValidateTOTP(secret, TOTPCode(secret, step+offset), now, 0); ok {
			t.Fatalf("offset %d accepted outside skew", offset)
		}
	}
	if _, ok := ValidateTOTP(secret, TOTPCode(secret, step), now, step); ok {
		t.Fatal("replayed step accepted")
	}
	if _, ok := ValidateTOTP(secret, TOTPCode(secret, step-1), now, step); ok {
		t.Fatal("step before the last accepted step accepted")
	}
	if got, ok := ValidateTOTP(secret, TOTPCode(secret, step+1), now, step); !ok || got != step+1 {
		t.Fatal("next step refused after replay protection")
	}
	if _, ok := ValidateTOTP(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("Veksel", "alice", []byte("12345678901234567890"))
	if !strings.HasPrefix(uri, "otpauth://totp/Veksel:alice?") || !strings.Contains(uri, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") || !strings.Contains(uri, "issuer=Veksel") {
		t.Fatalf("uri = %s", uri)
	}
}

func TestRecoveryCodesHashNormalized(t *testing.T) {
	codes, err := NewRecoveryCodes()
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("codes=%v err=%v", codes, err)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != 11 || code[5] != '-' || seen[code] {
			t.Fatalf("bad or duplicate code %q", code)
		}
		seen[code] = true
	}
	salt := []byte("salt")
	if HashRecoveryCode(salt, codes[0]) != HashRecoveryCode(salt, strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))) {
		t.Fatal("hash is not normalized")
	}
	if HashRecoveryCode(salt, codes[0]) == HashRecoveryCode([]byte("other"), codes[0]) {
		t.Fatal("salt ignored")
	}
}
