package model

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// SecondFactors is one account's web sign-in second factors. Protocol logins,
// application passwords and API keys never consult it.
type SecondFactors struct {
	UserID string `json:"user_id"`
	// TOTP is the confirmed authenticator-app factor. Its secret is a sealed
	// envelope owned by the web layer, never plaintext.
	TOTP *TOTPFactor `json:"totp,omitempty"`
	// PendingTOTP holds a sealed secret shown to the user but not yet
	// confirmed with a code.
	PendingTOTP *PendingTOTP `json:"pending_totp,omitempty"`
	// RecoverySalt keys the recovery-code hashes.
	RecoverySalt        []byte         `json:"recovery_salt,omitempty"`
	RecoveryCodes       []RecoveryCode `json:"recovery_codes,omitempty"`
	RecoveryGeneratedAt time.Time      `json:"recovery_generated_at,omitzero"`
	// WebAuthnUserHandle is the random, stable user handle given to
	// authenticators; it never reveals the account name.
	WebAuthnUserHandle []byte           `json:"webauthn_user_handle,omitempty"`
	WebAuthn           []WebAuthnFactor `json:"webauthn,omitempty"`
	UpdatedAt          time.Time        `json:"updated_at"`
}

// TOTPFactor is a confirmed RFC 6238 authenticator.
type TOTPFactor struct {
	SealedSecret []byte    `json:"sealed_secret"`
	EnabledAt    time.Time `json:"enabled_at"`
	// LastStep is the most recent accepted time step; codes for it or any
	// earlier step are refused as replays.
	LastStep   int64     `json:"last_step"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
}

// PendingTOTP is an unconfirmed enrolment.
type PendingTOTP struct {
	SealedSecret []byte    `json:"sealed_secret"`
	CreatedAt    time.Time `json:"created_at"`
}

// RecoveryCode is a hashed single-use code.
type RecoveryCode struct {
	Hash   string    `json:"hash"`
	UsedAt time.Time `json:"used_at,omitzero"`
}

// WebAuthnFactor is one registered security key or passkey. Credential holds
// the WebAuthn library's credential record as JSON.
type WebAuthnFactor struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
	CreatedAt  time.Time       `json:"created_at"`
	LastUsedAt time.Time       `json:"last_used_at,omitzero"`
}

// Enabled reports whether the account must present a second factor.
// Recovery codes alone are a fallback, not a factor.
func (f SecondFactors) Enabled() bool { return f.TOTP != nil || len(f.WebAuthn) > 0 }

// RemainingRecoveryCodes counts unused recovery codes.
func (f SecondFactors) RemainingRecoveryCodes() int {
	remaining := 0
	for _, code := range f.RecoveryCodes {
		if code.UsedAt.IsZero() {
			remaining++
		}
	}
	return remaining
}

// SecondFactorStore persists SecondFactors records. Update serializes
// read-modify-write cycles so single-use checks cannot race.
type SecondFactorStore struct {
	ts *TypedStore
	mu sync.Mutex
}

func NewSecondFactorStore(ts *TypedStore) *SecondFactorStore { return &SecondFactorStore{ts: ts} }

// Get returns the account's record, or an empty record without factors.
func (s *SecondFactorStore) Get(ctx context.Context, userID string) (SecondFactors, error) {
	userID = normalizeID(userID)
	var factors SecondFactors
	err := s.ts.Get(ctx, NSSecondFactors, userID, &factors)
	if errors.Is(err, store.ErrNotFound) {
		return SecondFactors{UserID: userID}, nil
	}
	return factors, err
}

// Update applies change to the current record and stores the result. A
// change that returns an error stores nothing.
func (s *SecondFactorStore) Update(ctx context.Context, userID string, change func(*SecondFactors) error) (SecondFactors, error) {
	userID = normalizeID(userID)
	s.mu.Lock()
	defer s.mu.Unlock()
	factors, err := s.Get(ctx, userID)
	if err != nil {
		return SecondFactors{}, err
	}
	if err := change(&factors); err != nil {
		return SecondFactors{}, err
	}
	factors.UserID, factors.UpdatedAt = userID, time.Now().UTC()
	if err := s.ts.Set(ctx, NSSecondFactors, userID, factors); err != nil {
		return SecondFactors{}, err
	}
	return factors, nil
}

// Delete removes every factor of the account and reports whether any record
// existed.
func (s *SecondFactorStore) Delete(ctx context.Context, userID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.ts.Delete(ctx, NSSecondFactors, normalizeID(userID))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
