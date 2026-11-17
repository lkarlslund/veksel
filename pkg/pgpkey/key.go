// Package pgpkey validates and normalizes user-published OpenPGP public
// keys and serves them over the Web Key Directory (WKD). It implements the
// key handling for Autocrypt Level 1 headers and WKD lookups; it never
// handles private key material and rejects it on upload.
package pgpkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// MaxInputBytes bounds an uploaded key. Real public keys with many
// third-party certifications reach a few hundred kilobytes; larger input is
// refused before parsing.
const MaxInputBytes = 512 << 10

// Key is a validated public key reduced to what a correspondent needs to
// encrypt to its owner: the primary key, the matching user ID with its
// self-signature, and the newest valid encryption subkey. Third-party
// certifications and unrelated user IDs are dropped.
type Key struct {
	// Fingerprint is the upper-case hexadecimal primary key fingerprint.
	Fingerprint string
	Created     time.Time
	// Expires is zero when the key does not expire.
	Expires time.Time
	// Binary is the minimal binary transferable public key.
	Binary []byte
}

// Parse validates data, an ASCII-armored or binary public key (or the
// standard base64 encoding of a binary one), as the public key of address.
// It refuses private keys, several keys, revoked or expired keys, keys that
// cannot encrypt, and keys without a user ID for address.
func Parse(data []byte, address string, now time.Time) (Key, error) {
	if len(data) > MaxInputBytes {
		return Key{}, fmt.Errorf("the key is larger than %d KiB", MaxInputBytes>>10)
	}
	binary, err := decode(data)
	if err != nil {
		return Key{}, err
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(binary))
	if err != nil {
		return Key{}, fmt.Errorf("not a valid OpenPGP key: %w", err)
	}
	if len(entities) != 1 {
		return Key{}, fmt.Errorf("expected one key, found %d", len(entities))
	}
	entity := entities[0]
	if hasPrivateMaterial(entity) {
		return Key{}, errPrivateKey
	}
	if entity.Revoked(now) {
		return Key{}, errors.New("the key is revoked")
	}
	identity := identityFor(entity, address, now)
	if identity == nil {
		return Key{}, fmt.Errorf("the key has no valid user ID for %s", strings.ToLower(strings.TrimSpace(address)))
	}
	if entity.PrimaryKey.KeyExpired(identity.SelfSignature, now) {
		return Key{}, errors.New("the key has expired")
	}
	encryption, ok := entity.EncryptionKey(now)
	if !ok {
		return Key{}, errors.New("the key has no usable encryption subkey")
	}
	minimal := &openpgp.Entity{
		PrimaryKey: entity.PrimaryKey,
		Identities: map[string]*openpgp.Identity{identity.Name: {
			Name: identity.Name, UserId: identity.UserId, SelfSignature: identity.SelfSignature,
			Signatures: []*packet.Signature{identity.SelfSignature},
		}},
	}
	if direct := entity.SelfSignature; direct != nil {
		minimal.SelfSignature, minimal.Signatures = direct, []*packet.Signature{direct}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PublicKey == encryption.PublicKey {
			subkey.Revocations = nil
			minimal.Subkeys = []openpgp.Subkey{subkey}
		}
	}
	var out bytes.Buffer
	if err := minimal.Serialize(&out); err != nil {
		return Key{}, fmt.Errorf("serialize key: %w", err)
	}
	key := Key{Fingerprint: strings.ToUpper(fmt.Sprintf("%x", entity.PrimaryKey.Fingerprint)), Created: entity.PrimaryKey.CreationTime.UTC(), Binary: out.Bytes()}
	if lifetime := identity.SelfSignature.KeyLifetimeSecs; lifetime != nil && *lifetime > 0 {
		key.Expires = entity.PrimaryKey.CreationTime.Add(time.Duration(*lifetime) * time.Second).UTC()
	}
	return key, nil
}

var errPrivateKey = errors.New("this is a private key; upload only the public key")

func hasPrivateMaterial(entity *openpgp.Entity) bool {
	if entity.PrivateKey != nil {
		return true
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil {
			return true
		}
	}
	return false
}

// identityFor returns the unrevoked, unexpired, self-signed user ID whose
// email address is address, or nil.
func identityFor(entity *openpgp.Entity, address string, now time.Time) *openpgp.Identity {
	address = strings.ToLower(strings.TrimSpace(address))
	for _, identity := range entity.Identities {
		if identity.UserId == nil || identity.SelfSignature == nil || identity.Revoked(now) || identity.SelfSignature.SigExpired(now) {
			continue
		}
		if strings.ToLower(identity.UserId.Email) == address {
			return identity
		}
	}
	return nil
}

// decode returns the binary packets of an armored, binary, or base64 key.
func decode(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("the key is empty")
	}
	// Binary packets start with a byte whose top bit is set. They are used
	// as they are, because trailing bytes may look like white space.
	if data[0]&0x80 != 0 {
		return data, nil
	}
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, err := armor.Decode(bytes.NewReader(trimmed))
		if err != nil {
			return nil, fmt.Errorf("not a valid armored key: %w", err)
		}
		switch block.Type {
		case openpgp.PublicKeyType:
			body, err := io.ReadAll(io.LimitReader(block.Body, MaxInputBytes))
			if err != nil {
				return nil, fmt.Errorf("not a valid armored key: %w", err)
			}
			return body, nil
		case openpgp.PrivateKeyType:
			return nil, errPrivateKey
		}
		return nil, fmt.Errorf("expected a public key block, found %q", block.Type)
	}
	// Anything else is taken as base64 of binary packets.
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(trimmed)), ""))
	if err != nil {
		return nil, errors.New("the key is neither armored, binary, nor base64")
	}
	return decoded, nil
}
