package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238): HMAC-SHA1, six digits and a 30-second step,
// which every common authenticator application supports.
const (
	TOTPDigits     = 6
	TOTPPeriod     = 30 * time.Second
	totpSecretSize = 20
	// TOTPSkew is the number of steps accepted on either side of the current
	// one to absorb clock drift.
	TOTPSkew = 1
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit TOTP seed.
func NewTOTPSecret() ([]byte, error) {
	secret := make([]byte, totpSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}
	return secret, nil
}

// TOTPSecretText is the unpadded base32 form authenticator applications
// accept for manual entry.
func TOTPSecretText(secret []byte) string { return totpEncoding.EncodeToString(secret) }

// TOTPURI returns the otpauth:// enrolment URI encoded into QR codes.
func TOTPURI(issuer, account string, secret []byte) string {
	values := url.Values{}
	values.Set("secret", TOTPSecretText(secret))
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", fmt.Sprint(TOTPDigits))
	values.Set("period", fmt.Sprint(int(TOTPPeriod.Seconds())))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + values.Encode()
}

// TOTPStep returns the RFC 6238 time step containing t.
func TOTPStep(t time.Time) int64 { return t.Unix() / int64(TOTPPeriod.Seconds()) }

// TOTPCode computes the code for one time step (RFC 4226 dynamic truncation).
func TOTPCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", TOTPDigits, value%1_000_000)
}

// ValidateTOTP checks code against the steps around now and returns the
// matching step. Steps at or before lastStep are refused so an accepted code
// cannot be replayed, even within its validity window.
func ValidateTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.Join(strings.Fields(code), "")
	if len(code) != TOTPDigits {
		return 0, false
	}
	current := TOTPStep(now)
	for step := current - TOTPSkew; step <= current+TOTPSkew; step++ {
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(TOTPCode(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// Recovery codes are ten groups of five base32 characters split by a dash,
// 50 random bits each.
const (
	RecoveryCodeCount = 10
	recoveryCodeBytes = 7
)

var recoveryEncoding = base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").WithPadding(base32.NoPadding)

// NewRecoveryCodes returns RecoveryCodeCount fresh single-use codes.
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		text := recoveryEncoding.EncodeToString(raw)[:10]
		codes[i] = text[:5] + "-" + text[5:]
	}
	return codes, nil
}

// HashRecoveryCode returns the stored form of code under salt. Input is
// normalized so case, spaces and dashes do not matter when it is typed.
func HashRecoveryCode(salt []byte, code string) string {
	normalized := strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ':
			return -1
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		}
		return r
	}, code)
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))
}
