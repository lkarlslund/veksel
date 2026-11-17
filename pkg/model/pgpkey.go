package model

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/pgpkey"
	"github.com/lkarlslund/veksel/pkg/store"
)

// PGPKey is the OpenPGP public key a user published for one of their
// identities. Binary is the minimal transferable public key served by the
// Web Key Directory; Autocrypt asks outgoing mail from the identity to
// carry it in an Autocrypt header.
type PGPKey struct {
	Address     string    `json:"address"`
	UserID      string    `json:"user_id"`
	Fingerprint string    `json:"fingerprint"`
	Created     time.Time `json:"created"`
	Expires     time.Time `json:"expires,omitzero"`
	Binary      []byte    `json:"binary"`
	Autocrypt   bool      `json:"autocrypt"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Expired reports whether the key has expired at now.
func (k PGPKey) Expired(now time.Time) bool { return !k.Expires.IsZero() && now.After(k.Expires) }

// PGPKeyStore stores published keys under their Web Key Directory name, the
// domain and hash of the local part, so a directory lookup is one read.
type PGPKeyStore struct{ keys collection[PGPKey] }

// PGPKeyStore returns the published OpenPGP key store.
func (ts *TypedStore) PGPKeyStore() *PGPKeyStore {
	return &PGPKeyStore{keys: newCollection[PGPKey](ts, NSPGPKeys)}
}

func pgpKeyID(domain, hash string) string { return strings.ToLower(domain) + "/" + hash }

func addressKeyID(address string) string {
	address = normalizeID(address)
	at := strings.LastIndex(address, "@")
	if at <= 0 {
		return ""
	}
	return pgpKeyID(address[at+1:], pgpkey.WKDHash(address[:at]))
}

// Get returns the key published for address.
func (s *PGPKeyStore) Get(ctx context.Context, address string) (PGPKey, error) {
	id := addressKeyID(address)
	if id == "" {
		return PGPKey{}, store.ErrNotFound
	}
	return s.keys.get(ctx, id)
}

// ByHash returns the key whose address has the given directory hash at
// domain.
func (s *PGPKeyStore) ByHash(ctx context.Context, domain, hash string) (PGPKey, error) {
	return s.keys.get(ctx, pgpKeyID(domain, hash))
}

// Set stores or replaces the key of key.Address.
func (s *PGPKeyStore) Set(ctx context.Context, key PGPKey) error {
	key.Address = normalizeID(key.Address)
	id := addressKeyID(key.Address)
	if id == "" {
		return errors.New("key address is not an email address")
	}
	key.UpdatedAt = time.Now().UTC()
	return s.keys.set(ctx, id, key)
}

// Delete removes the key published for address.
func (s *PGPKeyStore) Delete(ctx context.Context, address string) error {
	id := addressKeyID(address)
	if id == "" {
		return store.ErrNotFound
	}
	return s.keys.delete(ctx, id)
}
