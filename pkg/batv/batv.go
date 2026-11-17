// Package batv implements Bounce Address Tag Validation in the prvs format
// of draft-levine-smtp-batv. A server signs the envelope sender of mail it
// originates as
//
//	prvs=KDDDSSSSSS=user@domain
//
// where K is a key digit, DDD the day number modulo 1000, and SSSSSS the
// first three bytes, in hex, of an HMAC-SHA1 over K, DDD, and the original
// address. Legitimate bounces return to the tagged address, so null-sender
// mail to an untagged or forged address is backscatter from forged senders.
package batv

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/srs"
)

const (
	// MaxAge is how many days a tagged address is honored.
	MaxAge = 7

	tagPrefix   = "prvs="
	tagLength   = len(tagPrefix) + 10 // K, DDD, and SSSSSS
	daySlots    = 1000
	hashBytes   = 3
	minSecretSz = 16
)

var (
	// ErrNotTagged reports an address without a prvs tag.
	ErrNotTagged = errors.New("batv: address carries no prvs tag")
	// ErrInvalid reports a malformed or forged tag.
	ErrInvalid = errors.New("batv: invalid prvs tag")
	// ErrExpired reports a tag older than MaxAge days.
	ErrExpired = errors.New("batv: prvs tag has expired")
	// ErrUntagged reports a bounce to an address that requires a tag.
	ErrUntagged = errors.New("batv: bounce to an untagged address")
)

// Codec signs and verifies prvs addresses. The first secret signs; every
// secret verifies, so a secret can be rotated by prepending a new one while
// tags signed by the previous one are still in circulation.
type Codec struct {
	secrets [][]byte
	now     func() time.Time
}

// New returns a codec for secrets.
func New(secrets [][]byte) (*Codec, error) {
	if len(secrets) == 0 {
		return nil, errors.New("batv: at least one secret is required")
	}
	for _, secret := range secrets {
		if len(secret) < minSecretSz {
			return nil, fmt.Errorf("batv: secrets must be at least %d bytes", minSecretSz)
		}
	}
	return &Codec{secrets: secrets, now: time.Now}, nil
}

// IsTagged reports whether local is a prvs local part.
func IsTagged(local string) bool {
	return len(local) > tagLength+1 && strings.EqualFold(local[:len(tagPrefix)], tagPrefix) && local[tagLength] == '='
}

// Sign returns address with a prvs tag. An address that is already tagged is
// returned unchanged.
func (c *Codec) Sign(address string) (string, error) {
	at := strings.LastIndex(address, "@")
	if at <= 0 || at == len(address)-1 {
		return "", fmt.Errorf("batv: cannot sign %q", address)
	}
	if IsTagged(address[:at]) {
		return address, nil
	}
	secret := c.secrets[0]
	key, day := keyID(secret), fmt.Sprintf("%03d", c.day())
	return tagPrefix + key + day + c.hash(secret, key, day, address) + "=" + address, nil
}

// Verify checks a tagged address issued by this server and returns the
// original address.
func (c *Codec) Verify(address string) (string, error) {
	at := strings.LastIndex(address, "@")
	if at <= 0 || !IsTagged(address[:at]) {
		return "", ErrNotTagged
	}
	tag := address[len(tagPrefix):tagLength]
	key, day, hash := tag[:1], tag[1:4], strings.ToLower(tag[4:])
	original := address[tagLength+1:]
	valid := false
	for _, secret := range c.secrets {
		if keyID(secret) == key && hmac.Equal([]byte(c.hash(secret, key, day, original)), []byte(hash)) {
			valid = true
			break
		}
	}
	if !valid {
		return "", ErrInvalid
	}
	stamp := 0
	for _, digit := range day {
		if digit < '0' || digit > '9' {
			return "", ErrInvalid
		}
		stamp = stamp*10 + int(digit-'0')
	}
	// A stamp from the future wraps to an age of almost daySlots days.
	if (c.day()-stamp+daySlots)%daySlots > MaxAge {
		return "", ErrExpired
	}
	return original, nil
}

// hash is the hex HMAC-SHA1 prefix over the key digit, day, and the
// case-folded address, so MTAs that change case do not invalidate it.
func (c *Codec) hash(secret []byte, key, day, address string) string {
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(key + day + strings.ToLower(address)))
	return hex.EncodeToString(mac.Sum(nil)[:hashBytes])
}

func (c *Codec) day() int {
	return int(c.now().Unix()/int64(24*time.Hour/time.Second)) % daySlots
}

// keyID is the tag's key digit for secret, letting verification skip
// secrets that cannot have signed a tag.
func keyID(secret []byte) string {
	sum := sha256.Sum256(secret)
	return string(rune('0' + sum[0]%10))
}

// Policy is the inbound backscatter check for recipients at local domains.
type Policy struct {
	Codec *Codec
	// Enabled requires bounces to carry a valid tag.
	Enabled bool
	// GraceUntil ends the period after enabling in which untagged bounces
	// are still accepted, for mail sent before signing began.
	GraceUntil time.Time
}

// Recipient returns the address to route for a local recipient: with a
// valid tag removed, or unchanged. For a bounce, while the policy is
// enabled, it rejects a forged or expired tag and, after the grace period,
// an untagged address. SRS addresses, which carry their own signature, and
// postmaster and abuse are never required to carry a tag.
func (p *Policy) Recipient(address string, bounce bool, now time.Time) (string, error) {
	at := strings.LastIndex(address, "@")
	if p == nil || p.Codec == nil || at <= 0 {
		return address, nil
	}
	local := address[:at]
	if IsTagged(local) {
		original, err := p.Codec.Verify(address)
		if err == nil {
			return original, nil
		}
		if bounce && p.Enabled {
			return "", err
		}
		return address, nil
	}
	if !bounce || !p.Enabled || now.Before(p.GraceUntil) || srs.IsSRS(local) {
		return address, nil
	}
	switch strings.ToLower(local) {
	case "postmaster", "abuse":
		return address, nil
	}
	return "", ErrUntagged
}
