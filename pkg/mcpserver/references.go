package mcpserver

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	referenceVersion    = 1
	referenceSecretKey  = "mcp-reference-secret"
	referencePrefix     = "r1."
	ReferenceFolder     = "f"
	ReferenceItem       = "i"
	ReferenceAttachment = "a"
)

var (
	ErrReferenceInvalid = errors.New("invalid MCP reference")
	ErrReferenceExpired = errors.New("expired MCP reference")
)

// ReferenceClaims are the signed identity and authorization boundaries carried
// by an opaque MCP reference. They are deliberately not an authorization cache:
// consumers must still re-run FolderSpace authorization after resolving one.
type ReferenceClaims struct {
	Version   int    `json:"v"`
	Kind      string `json:"k"`
	ActorID   string `json:"a"`
	AccountID string `json:"s"`
	SessionID string `json:"n"`
	Resource  string `json:"r"`
	ExpiresAt int64  `json:"e"`
}

// ReferenceService issues compact signed references using Veksel-managed,
// durable key material. The service is concurrency-safe after construction.
type ReferenceService struct {
	aead cipher.AEAD
	ttl  time.Duration
	now  func() time.Time
}

// NewReferenceService loads or atomically creates the MCP reference signing
// key in system metadata. No item or folder data passes through this store.
func NewReferenceService(ctx context.Context, ts *model.TypedStore, ttl time.Duration) (*ReferenceService, error) {
	if ts == nil {
		return nil, errors.New("MCP reference store is required")
	}
	if ttl <= 0 {
		return nil, errors.New("MCP reference TTL must be positive")
	}
	service := &ReferenceService{ttl: ttl, now: time.Now}
	if err := store.Batch(ctx, ts.Store(), func(batchCtx context.Context) error {
		var encoded string
		if err := ts.Get(batchCtx, model.NSMetadata, referenceSecretKey, &encoded); err == nil {
			secret, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
			if decodeErr != nil || len(secret) != 32 {
				return errors.New("stored MCP reference secret is invalid")
			}
			block, blockErr := aes.NewCipher(secret)
			if blockErr != nil {
				return blockErr
			}
			service.aead, blockErr = cipher.NewGCM(block)
			if blockErr != nil {
				return blockErr
			}
			return nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return fmt.Errorf("generate MCP reference secret: %w", err)
		}
		if err := ts.Put(batchCtx, model.NSMetadata, referenceSecretKey, base64.RawURLEncoding.EncodeToString(secret)); err != nil {
			return err
		}
		block, blockErr := aes.NewCipher(secret)
		if blockErr != nil {
			return blockErr
		}
		service.aead, blockErr = cipher.NewGCM(block)
		if blockErr != nil {
			return blockErr
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("initialize MCP references: %w", err)
	}
	return service, nil
}

func validReferenceKind(kind string) bool {
	return kind == ReferenceFolder || kind == ReferenceItem || kind == ReferenceAttachment
}

func (s *ReferenceService) Issue(kind, actorID, accountID, sessionID, resourceID string) (string, error) {
	actorID = strings.TrimSpace(actorID)
	accountID = strings.TrimSpace(accountID)
	sessionID = strings.TrimSpace(sessionID)
	resourceID = strings.TrimSpace(resourceID)
	if s == nil || s.aead == nil || !validReferenceKind(kind) || actorID == "" || accountID == "" || sessionID == "" || resourceID == "" {
		return "", ErrReferenceInvalid
	}
	claims := ReferenceClaims{
		Version: referenceVersion, Kind: kind, ActorID: actorID,
		AccountID: accountID, SessionID: sessionID, Resource: resourceID,
		ExpiresAt: s.now().UTC().Add(s.ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate MCP reference nonce: %w", err)
	}
	sealed := s.aead.Seal(nonce, nonce, payload, []byte(referencePrefix))
	return referencePrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *ReferenceService) Resolve(reference, kind, actorID, sessionID string) (ReferenceClaims, error) {
	if s == nil || s.aead == nil {
		return ReferenceClaims{}, ErrReferenceInvalid
	}
	reference = strings.TrimSpace(reference)
	if !strings.HasPrefix(reference, referencePrefix) {
		return ReferenceClaims{}, ErrReferenceInvalid
	}
	encoded := strings.TrimPrefix(reference, referencePrefix)
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sealed) < s.aead.NonceSize()+s.aead.Overhead() {
		return ReferenceClaims{}, ErrReferenceInvalid
	}
	// Raw base64 can decode non-canonical final characters whose unused bits
	// differ while producing the same authenticated bytes. Require the exact
	// canonical spelling so every textual mutation is rejected as tampering.
	if base64.RawURLEncoding.EncodeToString(sealed) != encoded {
		return ReferenceClaims{}, ErrReferenceInvalid
	}
	nonce, ciphertext := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	payload, err := s.aead.Open(nil, nonce, ciphertext, []byte(referencePrefix))
	if err != nil {
		return ReferenceClaims{}, ErrReferenceInvalid
	}
	var claims ReferenceClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Version != referenceVersion || !validReferenceKind(claims.Kind) || claims.ActorID == "" || claims.AccountID == "" || claims.SessionID == "" || claims.Resource == "" || claims.ExpiresAt <= 0 {
		return ReferenceClaims{}, ErrReferenceInvalid
	}
	if claims.Kind != kind || claims.ActorID != strings.TrimSpace(actorID) || claims.SessionID != strings.TrimSpace(sessionID) {
		return ReferenceClaims{}, ErrReferenceInvalid
	}
	if !s.now().UTC().Before(time.Unix(claims.ExpiresAt, 0)) {
		return ReferenceClaims{}, ErrReferenceExpired
	}
	return claims, nil
}
