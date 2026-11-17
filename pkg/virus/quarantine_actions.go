package virus

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	QuarantineActionRelease = "release"
	QuarantineActionSpam    = "spam"

	quarantineActionVersion = 1
	quarantineActionLease   = 5 * time.Minute
)

var (
	ErrQuarantineActionInvalid    = errors.New("invalid quarantine action")
	ErrQuarantineActionExpired    = errors.New("quarantine action expired")
	ErrQuarantineActionConsumed   = errors.New("quarantine action already used")
	ErrQuarantineActionInProgress = errors.New("quarantine action is in progress")
)

// QuarantineActionClaims are the signed, immutable capability claims. A token
// authorizes exactly one action against one entry for one account owner.
type QuarantineActionClaims struct {
	Version   int    `json:"v"`
	TokenID   string `json:"jti"`
	EntryID   string `json:"entry"`
	OwnerID   string `json:"owner"`
	Action    string `json:"action"`
	ExpiresAt int64  `json:"exp"`
}

type quarantineActionRecord struct {
	Claims     QuarantineActionClaims `json:"claims"`
	ClaimToken string                 `json:"claim_token,omitempty"`
	ClaimedAt  time.Time              `json:"claimed_at,omitzero"`
	ConsumedAt time.Time              `json:"consumed_at,omitzero"`
	CreatedAt  time.Time              `json:"created_at"`
}

// QuarantineActionClaim is a short durable lease held while the authorized
// operation is applied. Call Complete whether the operation succeeds or fails.
type QuarantineActionClaim struct {
	Claims     QuarantineActionClaims
	LeaseToken string
}

type QuarantineActionService struct {
	ts     *model.TypedStore
	secret []byte
	ttl    atomic.Int64
	now    func() time.Time
}

func quarantineActionSecretKey() string    { return "quarantine-action-secret" }
func quarantineActionKey(id string) string { return "quarantine-action:" + id }
func quarantineActionExpiryPrefix() string { return "quarantine-action-expiry:" }
func quarantineActionExpiryKey(claims QuarantineActionClaims) string {
	return fmt.Sprintf("%s%020d:%s", quarantineActionExpiryPrefix(), claims.ExpiresAt, claims.TokenID)
}

// SetTTL changes the lifetime of action links issued from now on.
func (s *QuarantineActionService) SetTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("quarantine action TTL must be positive")
	}
	s.ttl.Store(int64(ttl))
	return nil
}

// NewQuarantineActionService loads or creates the durable signing secret.
func NewQuarantineActionService(ctx context.Context, ts *model.TypedStore, ttl time.Duration) (*QuarantineActionService, error) {
	if ts == nil {
		return nil, errors.New("quarantine action store is required")
	}
	if ttl <= 0 {
		return nil, errors.New("quarantine action TTL must be positive")
	}
	service := &QuarantineActionService{ts: ts, now: time.Now}
	service.ttl.Store(int64(ttl))
	if err := store.Batch(ctx, ts.Store(), func(batchCtx context.Context) error {
		var encoded string
		if err := ts.Get(batchCtx, model.NSMetadata, quarantineActionSecretKey(), &encoded); err == nil {
			secret, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
			if decodeErr != nil || len(secret) != 32 {
				return errors.New("stored quarantine action secret is invalid")
			}
			service.secret = secret
			return nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return fmt.Errorf("generate quarantine action secret: %w", err)
		}
		if err := ts.Put(batchCtx, model.NSMetadata, quarantineActionSecretKey(), base64.RawURLEncoding.EncodeToString(secret)); err != nil {
			return err
		}
		service.secret = secret
		return nil
	}); err != nil {
		return nil, fmt.Errorf("initialize quarantine actions: %w", err)
	}
	return service, nil
}

func validQuarantineAction(action string) bool {
	return action == QuarantineActionRelease || action == QuarantineActionSpam
}

// Issue creates a signed action capability and stores only its lifecycle state.
func (s *QuarantineActionService) Issue(ctx context.Context, entry QuarantineEntry, action string) (string, error) {
	if !validQuarantineAction(action) || entry.ID == "" || entry.OwnerID == "" {
		return "", ErrQuarantineActionInvalid
	}
	now := s.now().UTC()
	expiresAt := now.Add(time.Duration(s.ttl.Load()))
	if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(expiresAt) {
		expiresAt = entry.ExpiresAt
	}
	if !expiresAt.After(now) {
		return "", ErrQuarantineActionExpired
	}
	tokenID, err := newQuarantineID()
	if err != nil {
		return "", err
	}
	claims := QuarantineActionClaims{Version: quarantineActionVersion, TokenID: tokenID, EntryID: entry.ID, OwnerID: strings.ToLower(strings.TrimSpace(entry.OwnerID)), Action: action, ExpiresAt: expiresAt.Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	record := quarantineActionRecord{Claims: claims, CreatedAt: now}
	if err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		if err := s.ts.Put(batchCtx, model.NSMetadata, quarantineActionKey(tokenID), record); err != nil {
			return err
		}
		return s.ts.Set(batchCtx, model.NSMetadata, quarantineActionExpiryKey(claims), tokenID)
	}); err != nil {
		return "", fmt.Errorf("persist quarantine action: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(s.signature(encoded)), nil
}

func (s *QuarantineActionService) signature(encoded string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(encoded))
	return mac.Sum(nil)
}

func (s *QuarantineActionService) parse(token string) (QuarantineActionClaims, error) {
	encoded, signature, found := strings.Cut(strings.TrimSpace(token), ".")
	if !found || encoded == "" || signature == "" {
		return QuarantineActionClaims{}, ErrQuarantineActionInvalid
	}
	provided, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !hmac.Equal(provided, s.signature(encoded)) {
		return QuarantineActionClaims{}, ErrQuarantineActionInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return QuarantineActionClaims{}, ErrQuarantineActionInvalid
	}
	var claims QuarantineActionClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Version != quarantineActionVersion || claims.TokenID == "" || claims.EntryID == "" || claims.OwnerID == "" || !validQuarantineAction(claims.Action) || claims.ExpiresAt <= 0 {
		return QuarantineActionClaims{}, ErrQuarantineActionInvalid
	}
	return claims, nil
}

// Inspect validates a token without claiming or consuming it. It is safe for
// rendering a GET confirmation page because it cannot mutate mail state.
func (s *QuarantineActionService) Inspect(ctx context.Context, token string) (QuarantineActionClaims, error) {
	claims, err := s.parse(token)
	if err != nil {
		return QuarantineActionClaims{}, err
	}
	var record quarantineActionRecord
	if err := s.ts.Get(ctx, model.NSMetadata, quarantineActionKey(claims.TokenID), &record); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return QuarantineActionClaims{}, ErrQuarantineActionInvalid
		}
		return QuarantineActionClaims{}, err
	}
	return s.validateRecord(claims, record, s.now().UTC(), false)
}

// Claim atomically leases a valid action so concurrent requests cannot both
// execute it. An abandoned lease becomes claimable after five minutes.
func (s *QuarantineActionService) Claim(ctx context.Context, token string) (QuarantineActionClaim, error) {
	claims, err := s.parse(token)
	if err != nil {
		return QuarantineActionClaim{}, err
	}
	leaseToken, err := newQuarantineID()
	if err != nil {
		return QuarantineActionClaim{}, err
	}
	now := s.now().UTC()
	err = store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		var record quarantineActionRecord
		if err := s.ts.Get(batchCtx, model.NSMetadata, quarantineActionKey(claims.TokenID), &record); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrQuarantineActionInvalid
			}
			return err
		}
		if _, err := s.validateRecord(claims, record, now, true); err != nil {
			return err
		}
		record.ClaimToken, record.ClaimedAt = leaseToken, now
		return s.ts.Set(batchCtx, model.NSMetadata, quarantineActionKey(claims.TokenID), record)
	})
	if err != nil {
		return QuarantineActionClaim{}, err
	}
	return QuarantineActionClaim{Claims: claims, LeaseToken: leaseToken}, nil
}

func (s *QuarantineActionService) validateRecord(claims QuarantineActionClaims, record quarantineActionRecord, now time.Time, enforceLease bool) (QuarantineActionClaims, error) {
	if record.Claims != claims {
		return QuarantineActionClaims{}, ErrQuarantineActionInvalid
	}
	if !record.ConsumedAt.IsZero() {
		return QuarantineActionClaims{}, ErrQuarantineActionConsumed
	}
	if now.Unix() >= claims.ExpiresAt {
		return QuarantineActionClaims{}, ErrQuarantineActionExpired
	}
	if enforceLease && record.ClaimToken != "" && record.ClaimedAt.Add(quarantineActionLease).After(now) {
		return QuarantineActionClaims{}, ErrQuarantineActionInProgress
	}
	return claims, nil
}

// Complete consumes a successful action or releases a failed action lease.
func (s *QuarantineActionService) Complete(ctx context.Context, claim QuarantineActionClaim, success bool) error {
	if claim.Claims.TokenID == "" || claim.LeaseToken == "" {
		return ErrQuarantineActionInvalid
	}
	return store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		var record quarantineActionRecord
		if err := s.ts.Get(batchCtx, model.NSMetadata, quarantineActionKey(claim.Claims.TokenID), &record); err != nil {
			return err
		}
		if record.Claims != claim.Claims || record.ClaimToken != claim.LeaseToken {
			return ErrQuarantineActionInvalid
		}
		if !record.ConsumedAt.IsZero() {
			return ErrQuarantineActionConsumed
		}
		if success {
			record.ConsumedAt = s.now().UTC()
		} else {
			record.ClaimToken = ""
			record.ClaimedAt = time.Time{}
		}
		return s.ts.Set(batchCtx, model.NSMetadata, quarantineActionKey(claim.Claims.TokenID), record)
	})
}

// Cleanup removes at most limit expired action records and indexes.
func (s *QuarantineActionService) Cleanup(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit < 1 {
		return 0, errors.New("quarantine action cleanup limit must be positive")
	}
	removed := 0
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		keys, err := s.ts.Scan(batchCtx, model.NSMetadata, quarantineActionExpiryPrefix())
		if err != nil {
			return err
		}
		cutoff := fmt.Sprintf("%s%020d:", quarantineActionExpiryPrefix(), now.UTC().Unix()) + "\xff"
		for _, key := range keys {
			if key > cutoff || removed >= limit {
				break
			}
			var tokenID string
			if err := s.ts.Get(batchCtx, model.NSMetadata, key, &tokenID); err != nil {
				return err
			}
			if err := s.ts.Delete(batchCtx, model.NSMetadata, quarantineActionKey(tokenID)); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			if err := s.ts.Delete(batchCtx, model.NSMetadata, key); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}
