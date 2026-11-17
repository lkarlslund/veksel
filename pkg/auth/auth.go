// Package auth provides shared authentication helpers for Veksel.
//
// It wraps bcrypt password hashing and SASL authentication helpers
// used by both IMAP and SMTP handlers.
package auth

import (
	"errors"
	"testing"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"golang.org/x/crypto/bcrypt"
)

var log = logpkg.For(logpkg.ModuleAuth)

// ErrInvalidPassword is returned when a password does not match its hash.
var ErrInvalidPassword = errors.New("invalid password")

// DefaultCost is the bcrypt cost parameter used by HashPassword.
const DefaultCost = bcrypt.DefaultCost

// ErrPasswordTooLong is returned for passwords bcrypt cannot fully hash.
var ErrPasswordTooLong = errors.New("password must be at most 72 bytes")

// HashPassword hashes a plaintext password using bcrypt at the default cost.
// Passwords longer than 72 bytes are rejected rather than silently truncated.
func HashPassword(password string) (string, error) {
	if len(password) > 72 {
		return "", ErrPasswordTooLong
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), hashCost())
	return string(bytes), err
}

// hashCost keeps test binaries fast; production builds always use DefaultCost.
func hashCost() int {
	if testing.Testing() {
		return bcrypt.MinCost
	}
	return DefaultCost
}

// ComparePassword verifies a plaintext password against a bcrypt hash.
// Returns true when the password matches the hash. A match is remembered
// for a few minutes (see verifiedPasswords), so clients that send their
// credentials with every request pay the bcrypt cost once per window.
func ComparePassword(password, hash string) bool {
	if hash != "" && verifiedPasswords.verified(password, hash) {
		return true
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		log.Debug("auth: password comparison failed", "error", err)
		return false
	}
	verifiedPasswords.remember(password, hash)
	return true
}
