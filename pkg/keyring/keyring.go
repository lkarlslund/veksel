// Package keyring holds the installation key-encryption keys (KEKs).
//
// The ring is a small versioned set of random AES-256 keys stored in the
// system store. Exactly one key is active for new envelopes; retired keys stay
// readable so rotation never strands data sealed earlier. Stored credentials,
// TOTP seeds, DNS provider secrets, and per-account data-encryption keys are
// all sealed with it. The ring protects data at rest in other stores; the
// system store itself, and therefore an installation backup, carries the key
// material.
package keyring

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
	"sync"

	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	// Namespace is the system-store namespace that holds the key ring. Its
	// historical name predates the ring serving more than sync credentials.
	Namespace = "sync_job_credential_keys"
	activeKey = "active"
	keyPrefix = "key:"

	// EnvelopeType and EnvelopeVersion identify a sealed envelope.
	EnvelopeType    = "veksel-sync-credential"
	EnvelopeVersion = 1
)

// ErrKeyUnavailable reports an envelope sealed by a key this ring lacks, such
// as data restored onto a different installation.
var ErrKeyUnavailable = errors.New("installation encryption key is unavailable")

// Envelope is the stored form of a sealed secret.
type Envelope struct {
	Type       string `json:"type"`
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Status exposes rotation evidence without disclosing key bytes.
type Status struct {
	ActiveKeyID string `json:"active_key_id"`
	KeyCount    int    `json:"key_count"`
}

// Ring is the loaded installation key ring. It is safe for concurrent use.
type Ring struct {
	backend store.Store

	mu     sync.RWMutex
	keys   map[string][]byte
	active string
}

var (
	sharedMu sync.Mutex
	shared   = map[store.Store]*Ring{}
)

// For returns the process-wide ring for backend, loading or creating it on
// first use. Every subsystem sealing with the same system store must share one
// ring so a rotation is immediately visible to all of them.
func For(ctx context.Context, backend store.Store) (*Ring, error) {
	if backend == nil {
		return nil, errors.New("key ring store is required")
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if ring := shared[backend]; ring != nil {
		return ring, nil
	}
	ring, err := Load(ctx, backend)
	if err != nil {
		return nil, err
	}
	shared[backend] = ring
	return ring, nil
}

// LoadExisting reads the ring from backend without creating one. It returns
// nil when the store holds no key ring, as offline tools must not add one.
func LoadExisting(ctx context.Context, backend store.Store) (*Ring, error) {
	if _, err := backend.Get(ctx, Namespace, activeKey); errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return Load(ctx, backend)
}

// Load reads the ring from backend, creating the first key when none exists.
// Most callers want For, which shares one ring per backend.
func Load(ctx context.Context, backend store.Store) (*Ring, error) {
	exists, err := backend.NamespaceExists(ctx, Namespace)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, Namespace); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
	}
	ring := &Ring{backend: backend}
	if ring.keys, err = ring.loadKeys(ctx); err != nil {
		return nil, err
	}
	active, err := backend.Get(ctx, Namespace, activeKey)
	if err == nil {
		if _, ok := ring.keys[string(active)]; !ok {
			return nil, errors.New("active installation encryption key is missing")
		}
		ring.active = string(active)
		return ring, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	keyID, key, err := newKey()
	if err != nil {
		return nil, err
	}
	if err := backend.Put(ctx, Namespace, keyPrefix+keyID, []byte(base64.RawURLEncoding.EncodeToString(key))); err != nil {
		return nil, err
	}
	if err := backend.Put(ctx, Namespace, activeKey, []byte(keyID)); err != nil {
		return nil, err
	}
	ring.keys[keyID], ring.active = key, keyID
	return ring, nil
}

func (r *Ring) loadKeys(ctx context.Context) (map[string][]byte, error) {
	ids, err := r.backend.Scan(ctx, Namespace, keyPrefix)
	if err != nil {
		return nil, err
	}
	keys := make(map[string][]byte, len(ids))
	for _, id := range ids {
		encoded, err := r.backend.Get(ctx, Namespace, id)
		if err != nil {
			return nil, err
		}
		key, err := base64.RawURLEncoding.DecodeString(string(encoded))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("installation encryption key %q is invalid", strings.TrimPrefix(id, keyPrefix))
		}
		keys[strings.TrimPrefix(id, keyPrefix)] = key
	}
	return keys, nil
}

func newKey() (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, fmt.Errorf("generate installation encryption key: %w", err)
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, fmt.Errorf("generate installation encryption key ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(idBytes), key, nil
}

// Seal encrypts plaintext with the active key under AES-256-GCM, binding aad
// so an envelope cannot be replayed into another record.
func (r *Ring) Seal(aad, plaintext []byte) ([]byte, error) {
	r.mu.RLock()
	key, keyID := r.keys[r.active], r.active
	r.mu.RUnlock()
	return sealEnvelope(key, keyID, aad, plaintext)
}

// Open decrypts an envelope written by Seal with any retained key.
func (r *Ring) Open(aad, sealed []byte) ([]byte, error) {
	var envelope Envelope
	if err := json.Unmarshal(sealed, &envelope); err != nil {
		return nil, errors.New("invalid sealed envelope")
	}
	if envelope.Type != EnvelopeType || envelope.Version != EnvelopeVersion {
		return nil, errors.New("unsupported sealed envelope")
	}
	r.mu.RLock()
	key, ok := r.keys[envelope.KeyID]
	r.mu.RUnlock()
	if !ok {
		return nil, ErrKeyUnavailable
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, errors.New("invalid sealed envelope nonce")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid sealed envelope ciphertext")
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid sealed envelope nonce")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("decrypt sealed envelope: authentication failed")
	}
	return plaintext, nil
}

// SealSecret seals another subsystem's secret with purpose and id bound as
// associated data; OpenSecret must be given the same values.
func (r *Ring) SealSecret(purpose, id string, plaintext []byte) ([]byte, error) {
	return r.Seal(SecretAAD(purpose, id), plaintext)
}

// OpenSecret decrypts a secret sealed by SealSecret.
func (r *Ring) OpenSecret(purpose, id string, sealed []byte) ([]byte, error) {
	return r.Open(SecretAAD(purpose, id), sealed)
}

// SecretAAD is the associated data SealSecret binds.
func SecretAAD(purpose, id string) []byte { return []byte("veksel-secret:" + purpose + ":" + id) }

// ActiveKeyID returns the version that seals new envelopes.
func (r *Ring) ActiveKeyID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// Status returns non-secret evidence for administration and tests.
func (r *Ring) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Status{ActiveKeyID: r.active, KeyCount: len(r.keys)}
}

// Rotate creates and activates a new key. Retired keys remain readable; each
// owner of sealed data rewraps its envelopes afterwards, so an interrupted
// rotation only leaves envelopes under an older, still available key.
func (r *Ring) Rotate(ctx context.Context) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keyID, key, err := newKey()
	if err != nil {
		return Status{}, err
	}
	if err := r.backend.Put(ctx, Namespace, keyPrefix+keyID, []byte(base64.RawURLEncoding.EncodeToString(key))); err != nil {
		return Status{}, err
	}
	if err := r.backend.Set(ctx, Namespace, activeKey, []byte(keyID)); err != nil {
		return Status{}, err
	}
	keys := make(map[string][]byte, len(r.keys)+1)
	for id, existing := range r.keys {
		keys[id] = existing
	}
	keys[keyID] = key
	r.keys, r.active = keys, keyID
	return Status{ActiveKeyID: r.active, KeyCount: len(r.keys)}, nil
}

// SealedKeyID reports which key version sealed an envelope, or "" when the
// data is not an envelope.
func SealedKeyID(sealed []byte) string {
	var envelope Envelope
	if json.Unmarshal(sealed, &envelope) != nil || envelope.Type != EnvelopeType {
		return ""
	}
	return envelope.KeyID
}

// IsEnvelope reports whether data parses as a sealed envelope.
func IsEnvelope(data []byte) bool {
	var envelope Envelope
	return json.Unmarshal(data, &envelope) == nil && envelope.Type != ""
}

func sealEnvelope(key []byte, keyID string, aad, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{
		Type: EnvelopeType, Version: EnvelopeVersion, KeyID: keyID,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, aad)),
	})
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
