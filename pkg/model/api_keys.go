package model

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/store"
)

// API key scopes. MCP scopes govern the Model Context Protocol endpoint; the
// API and key-management scopes govern the REST control plane.
const (
	APIKeyScopeMCPRead    = "mcp.read"
	APIKeyScopeMCPWrite   = "mcp.write"
	APIKeyScopeAPIRead    = "api.read"
	APIKeyScopeAPIWrite   = "api.write"
	APIKeyScopeKeysManage = "keys.manage"
	APIKeyScopeAll        = "*"
)

// legacyAPIKeyScopes are the capabilities of named keys created before
// scopes existed: read and key management only.
var legacyAPIKeyScopes = []string{APIKeyScopeAPIRead, APIKeyScopeKeysManage}

// EffectiveScopes returns the key's scopes, treating keys created before
// scopes existed as read/key-management only.
func (k APIKey) EffectiveScopes() []string {
	if len(k.Scopes) == 0 {
		return legacyAPIKeyScopes
	}
	return k.Scopes
}

// Permits reports whether the key grants scope.
func (k APIKey) Permits(scope string) bool {
	for _, granted := range k.EffectiveScopes() {
		if granted == APIKeyScopeAll || granted == scope {
			return true
		}
	}
	return false
}

// ErrAPIKeyRevoked reports an attempted mutation of an inactive credential.
var ErrAPIKeyRevoked = errors.New("API key is revoked")

// APIKeyStore provides typed CRUD for APIKey entities.
type APIKeyStore struct {
	ts   *TypedStore
	keys collection[APIKey]
}

// NewAPIKeyStore returns an APIKeyStore backed by ts.
func NewAPIKeyStore(ts *TypedStore) *APIKeyStore {
	return &APIKeyStore{ts: ts, keys: newCollection[APIKey](ts, NSAPIKeys)}
}

// Create generates a new API key for a user, hashes it with bcrypt,
// and stores the entity. Returns the full APIKey entity and the plain
// secret key (only shown once).
func (aks *APIKeyStore) Create(ctx context.Context, userID, name string) (*APIKey, string, error) {
	return aks.CreateWithScopes(ctx, userID, name, legacyAPIKeyScopes)
}

// CreateWithScopes creates a key with explicit capabilities.
func (aks *APIKeyStore) CreateWithScopes(ctx context.Context, userID, name string, scopes []string) (*APIKey, string, error) {
	if _, err := aks.ts.UserStore().RequireInteractive(ctx, userID); errors.Is(err, ErrResourceAccount) {
		return nil, "", fmt.Errorf("api-key account: %w", err)
	}
	plainSecret, hash, prefix, err := newAPIKeySecret()
	if err != nil {
		return nil, "", err
	}

	// Build a unique ID from timestamp + random bytes
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, "", err
	}
	keyID := hex.EncodeToString(idBytes)

	ak := &APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      name,
		KeyHash:   hash,
		Secret:    prefix,
		Scopes:    normalizeAPIKeyScopes(scopes),
		CreatedAt: time.Now().UTC(),
	}

	if err := aks.keys.put(ctx, keyID, *ak); err != nil {
		return nil, "", err
	}

	return ak, plainSecret, nil
}

func newAPIKeySecret() (plain, hash, prefix string, err error) {
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return "", "", "", err
	}
	plain = hex.EncodeToString(random)
	hash, err = auth.HashPassword(plain)
	if err != nil {
		return "", "", "", err
	}
	return plain, hash, plain[:8], nil
}

func normalizeAPIKeyScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

// Get returns an API key by its ID.
func (aks *APIKeyStore) Get(ctx context.Context, id string) (*APIKey, error) {
	ak, err := aks.keys.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ak, nil
}

// ListByUser returns all non-revoked API keys for a user.
func (aks *APIKeyStore) ListByUser(ctx context.Context, userID string) ([]APIKey, error) {
	return aks.keys.filter(ctx, func(ak APIKey) bool {
		return ak.UserID == userID && !ak.Revoked
	})
}

// Revoke marks an API key as revoked. The key entity is kept for audit purposes.
func (aks *APIKeyStore) Revoke(ctx context.Context, id string) error {
	return store.Batch(ctx, aks.ts.Store(), func(batchCtx context.Context) error {
		ak, err := aks.Get(batchCtx, id)
		if err != nil {
			return err
		}
		if ak.Revoked {
			return nil
		}
		ak.Revoked = true
		ak.RevokedAt = time.Now().UTC()
		return aks.keys.set(batchCtx, id, *ak)
	})
}

// Rotate replaces one active credential's secret without changing its stable
// identity or authorization. The plain replacement is returned only here.
func (aks *APIKeyStore) Rotate(ctx context.Context, id string) (*APIKey, string, error) {
	plain, hash, prefix, err := newAPIKeySecret()
	if err != nil {
		return nil, "", err
	}
	var rotated *APIKey
	err = store.Batch(ctx, aks.ts.Store(), func(batchCtx context.Context) error {
		ak, err := aks.Get(batchCtx, id)
		if err != nil {
			return err
		}
		if ak.Revoked {
			return ErrAPIKeyRevoked
		}
		ak.KeyHash = hash
		ak.Secret = prefix
		ak.LastUsedAt = time.Time{}
		ak.RotatedAt = time.Now().UTC()
		ak.RotationCount++
		if err := aks.keys.set(batchCtx, id, *ak); err != nil {
			return err
		}
		copy := *ak
		copy.Scopes = append([]string(nil), ak.Scopes...)
		rotated = &copy
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return rotated, plain, nil
}

// GetBySecret looks up an API key entity by comparing the plain secret
// against stored bcrypt hashes. Returns the matching non-revoked key.
func (aks *APIKeyStore) GetBySecret(ctx context.Context, secret string) (*APIKey, error) {
	prefix := secret
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	_, ak, err := aks.keys.find(ctx, func(ak APIKey) bool {
		// The non-secret prefix is stored specifically to avoid one expensive
		// bcrypt comparison per credential. Older records without a prefix keep
		// their compatible scan behavior until they are rotated.
		return !ak.Revoked && (ak.Secret == "" || ak.Secret == prefix) && auth.ComparePassword(secret, ak.KeyHash)
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := aks.ts.UserStore().RequireInteractive(ctx, ak.UserID); errors.Is(err, ErrResourceAccount) {
		return nil, nil
	}
	return &ak, nil
}

// UpdateLastUsed updates the last_used_at timestamp for an API key.
func (aks *APIKeyStore) UpdateLastUsed(ctx context.Context, id string) error {
	return store.Batch(ctx, aks.ts.Store(), func(batchCtx context.Context) error {
		ak, err := aks.Get(batchCtx, id)
		if err != nil {
			return err
		}
		if ak.Revoked {
			return ErrAPIKeyRevoked
		}
		ak.LastUsedAt = time.Now().UTC()
		return aks.keys.set(batchCtx, id, *ak)
	})
}
