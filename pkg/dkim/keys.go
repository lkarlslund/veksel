package dkim

import (
	"cmp"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

// keyRecord is one parsed RFC 6376 section 3.6.1 key record.
type keyRecord struct {
	// public is an *rsa.PublicKey or an ed25519.PublicKey.
	public crypto.PublicKey
	// keyType is the k= tag: rsa or ed25519.
	keyType string
	// hashes is the h= tag; nil allows every hash algorithm.
	hashes []string
	// services is the s= tag; nil (or "*") allows every service.
	services []string
	// testing is the t=y flag: the domain is testing DKIM.
	testing bool
	// strict is the t=s flag: the i= domain must equal d=, never a
	// subdomain of it.
	strict bool
}

var errKeyRevoked = errors.New("key revoked")

// parseKeyRecord parses an RFC 6376 section 3.6.1 key record. An empty p=
// is a revoked key and returns errKeyRevoked.
func parseKeyRecord(record string) (keyRecord, error) {
	tags, err := parseTags(record)
	if err != nil {
		return keyRecord{}, fmt.Errorf("key record: %w", err)
	}
	if version, ok := tags["v"]; ok && version != "DKIM1" {
		return keyRecord{}, errors.New("unsupported key record version")
	}
	encoded, ok := tags["p"]
	if !ok {
		return keyRecord{}, errors.New("key record has no p= tag")
	}
	if encoded == "" {
		return keyRecord{}, errKeyRevoked
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) == 0 {
		return keyRecord{}, errors.New("malformed public key")
	}
	key := keyRecord{keyType: strings.ToLower(tags["k"])}
	if key.keyType == "" {
		key.keyType = "rsa"
	}
	switch key.keyType {
	case "rsa":
		var pub *rsa.PublicKey
		if parsed, err := x509.ParsePKIXPublicKey(data); err == nil {
			pub, _ = parsed.(*rsa.PublicKey)
		} else if parsed, err := x509.ParsePKCS1PublicKey(data); err == nil {
			pub = parsed
		}
		if pub == nil {
			return keyRecord{}, errors.New("malformed RSA public key")
		}
		// RFC 8301 section 3.2: keys under 1024 bits never verify.
		if pub.N.BitLen() < minRSABits {
			return keyRecord{}, fmt.Errorf("RSA key too short (%d bits)", pub.N.BitLen())
		}
		key.public = pub
	case "ed25519":
		if len(data) != ed25519.PublicKeySize {
			return keyRecord{}, errors.New("malformed Ed25519 public key")
		}
		key.public = ed25519.PublicKey(data)
	default:
		return keyRecord{}, fmt.Errorf("unsupported key type %q", key.keyType)
	}
	if value, ok := tags["h"]; ok {
		key.hashes = colonList(value)
	}
	if value, ok := tags["s"]; ok {
		if services := colonList(value); !slices.Contains(services, "*") {
			key.services = services
		}
	}
	for _, flag := range colonList(tags["t"]) {
		switch flag {
		case "y":
			key.testing = true
		case "s":
			key.strict = true
		}
	}
	return key, nil
}

// usableFor reports why the key cannot verify a signature made with
// algorithm (such as rsa-sha256) for e-mail, or "" when it can.
func (k keyRecord) usableFor(algorithm string) string {
	keyType, hash, _ := strings.Cut(algorithm, "-")
	switch {
	case keyType != k.keyType:
		return "key type " + k.keyType + " does not match a=" + algorithm
	case k.hashes != nil && !slices.Contains(k.hashes, hash):
		return "key record does not permit hash " + hash
	case k.services != nil && !slices.Contains(k.services, "email"):
		return "key record is not for e-mail"
	}
	return ""
}

// verifyDigest checks signature over the SHA-256 digest of data. Ed25519
// signs the digest itself (RFC 8463 section 3), RSA the PKCS #1 v1.5
// encoding of it.
func (k keyRecord) verifyDigest(data string, signature []byte) bool {
	digest := sha256.Sum256([]byte(data))
	switch pub := k.public.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(pub, digest[:], signature)
	}
	return false
}

// keyLookupError is a failed key retrieval with its RFC 8601 result:
// temperror for a DNS failure that may clear, permerror otherwise.
type keyLookupError struct {
	status string
	err    error
}

func (e *keyLookupError) Error() string { return e.err.Error() }
func (e *keyLookupError) Unwrap() error { return e.err }

// lookupStatus classifies a resolver error. Only an authoritative "no such
// name or record" answer is permanent; timeouts, SERVFAIL, cancelled
// contexts, and resolver errors of unknown type may clear on retry.
func lookupStatus(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound && !dnsErr.IsTimeout && !dnsErr.IsTemporary {
		return StatusPermError
	}
	return StatusTempError
}

// keyCache resolves and remembers public keys for one message, so a long
// ARC chain or several signatures from one domain cost one DNS lookup.
type keyCache struct {
	verifier Verifier
	keys     map[string][]keyRecord
	errs     map[string]error
	lookups  int
}

// records returns the usable key records published at
// selector._domainkey.domain. Records that do not parse are skipped, as
// RFC 6376 section 3.6.2.2 lets a verifier cycle through several; the
// error, a *keyLookupError, explains a lookup that yields none.
func (k *keyCache) records(ctx context.Context, domain, selector string) ([]keyRecord, error) {
	domain, selector = strings.ToLower(strings.TrimSuffix(domain, ".")), strings.ToLower(selector)
	if domain == "" || selector == "" {
		return nil, &keyLookupError{StatusPermError, errors.New("missing signing domain or selector")}
	}
	name := selector + "._domainkey." + domain
	if keys, ok := k.keys[name]; ok {
		return keys, nil
	}
	if err, ok := k.errs[name]; ok {
		return nil, err
	}
	if k.lookups >= maxKeyLookups {
		return nil, &keyLookupError{StatusPermError, errors.New("too many distinct key lookups")}
	}
	k.lookups++
	keys, err := k.fetch(ctx, name)
	if k.keys == nil {
		k.keys, k.errs = make(map[string][]keyRecord), make(map[string]error)
	}
	if err != nil {
		k.errs[name] = err
		return nil, err
	}
	k.keys[name] = keys
	return keys, nil
}

func (k *keyCache) fetch(ctx context.Context, name string) ([]keyRecord, error) {
	lookupTXT := k.verifier.LookupTXT
	if lookupTXT == nil {
		lookupTXT = net.DefaultResolver.LookupTXT
	}
	records, err := lookupTXT(ctx, name)
	if err != nil {
		return nil, &keyLookupError{lookupStatus(err), fmt.Errorf("key lookup %s: %w", name, err)}
	}
	var keys []keyRecord
	var first error
	for _, record := range records {
		key, err := parseKeyRecord(record)
		if err != nil {
			first = cmp.Or(first, err)
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		if first == nil {
			first = errors.New("no key record")
		}
		return nil, &keyLookupError{StatusPermError, fmt.Errorf("key %s: %w", name, first)}
	}
	return keys, nil
}

// verify checks the b= signature in tags (an ARC-Seal or
// ARC-Message-Signature) over data with a key the d= and s= tags publish.
func (k *keyCache) verify(ctx context.Context, tags map[string]string, data string) error {
	signature, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil || len(signature) == 0 {
		return errors.New("malformed signature")
	}
	algorithm := tags["a"]
	if algorithm != "rsa-sha256" && algorithm != "ed25519-sha256" {
		return fmt.Errorf("unsupported algorithm %q", algorithm)
	}
	keys, err := k.records(ctx, tags["d"], tags["s"])
	if err != nil {
		return err
	}
	reason := "signature did not verify"
	for _, key := range keys {
		if unusable := key.usableFor(algorithm); unusable != "" {
			reason = unusable
			continue
		}
		if key.verifyDigest(data, signature) {
			return nil
		}
		reason = "signature did not verify"
	}
	return errors.New(reason)
}

// parseTags parses an RFC 6376 section 3.2 tag-list. Folding white space
// is removed from values; a malformed tag or a repeated tag name makes the
// whole list invalid.
func parseTags(value string) (map[string]string, error) {
	tags := make(map[string]string)
	parts := strings.Split(value, ";")
	for index, part := range parts {
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			if strings.TrimSpace(part) == "" && index == len(parts)-1 {
				continue // a trailing semicolon is allowed
			}
			return nil, errors.New("malformed tag list")
		}
		name = strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "").Replace(name))
		if !validTagName(name) {
			return nil, fmt.Errorf("invalid tag name %q", name)
		}
		if _, duplicate := tags[name]; duplicate {
			return nil, fmt.Errorf("duplicate tag %q", name)
		}
		tags[name] = strings.Join(strings.FieldsFunc(val, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\r' || r == '\n'
		}), "")
	}
	return tags, nil
}

// validTagName reports an RFC 6376 tag-name: ALPHA *ALNUMPUNC.
func validTagName(name string) bool {
	if name == "" || !(name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z') {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// colonList splits a colon-separated tag value, lower-casing each entry.
func colonList(value string) []string {
	if value == "" {
		return nil
	}
	items := strings.Split(strings.ToLower(value), ":")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}
	return items
}
