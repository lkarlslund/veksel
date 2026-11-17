// Package srs implements the Sender Rewriting Scheme used when forwarding
// mail, in the SRS0/SRS1 address format of libsrs2 and Mail::SRS (Shevek,
// "Sender Rewriting Scheme", 2004).
//
// A forwarder replaces the envelope sender user@origin with
//
//	SRS0=HHHH=TT=origin=user@forwarder
//
// where TT is a day-granular base32 timestamp and HHHH a truncated
// HMAC-SHA1 over the timestamp and original address. Rewriting an address
// that is already SRS0 produces a compact SRS1 address that returns through
// the first forwarder instead of growing with each hop. Bounces to the
// rewritten address are verified and routed back to the original sender.
package srs

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// HashLength is the number of base64 hash characters in an address.
	HashLength = 4
	// DefaultMaxAge is how many days a rewritten SRS0 address is honored.
	DefaultMaxAge = 21

	timeBase32  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	timeSlots   = 1024 // two base32 characters
	timeDay     = 24 * time.Hour
	separators  = "=+-" // separators accepted after the SRS0/SRS1 tag
	tagSRS0     = "SRS0"
	tagSRS1     = "SRS1"
	outputSep   = "="
	minSecretSz = 16
)

var (
	// ErrNotSRS reports an address that is not in SRS form.
	ErrNotSRS = errors.New("srs: not an SRS address")
	// ErrInvalid reports a malformed or forged SRS address.
	ErrInvalid = errors.New("srs: invalid SRS address")
	// ErrExpired reports an SRS0 address whose timestamp is too old.
	ErrExpired = errors.New("srs: SRS address has expired")
)

// Codec rewrites and verifies SRS addresses. The first secret signs new
// addresses; every secret verifies, so a new secret can be introduced while
// addresses signed by the previous one are still in circulation.
type Codec struct {
	secrets [][]byte
	maxAge  int
	now     func() time.Time
}

// New returns a codec for secrets, honoring addresses for DefaultMaxAge days.
func New(secrets [][]byte) (*Codec, error) {
	if len(secrets) == 0 {
		return nil, errors.New("srs: at least one secret is required")
	}
	for _, secret := range secrets {
		if len(secret) < minSecretSz {
			return nil, fmt.Errorf("srs: secrets must be at least %d bytes", minSecretSz)
		}
	}
	return &Codec{secrets: secrets, maxAge: DefaultMaxAge, now: time.Now}, nil
}

// IsSRS reports whether local is an SRS0 or SRS1 local part.
func IsSRS(local string) bool {
	if len(local) < 5 || !strings.ContainsRune(separators, rune(local[4])) {
		return false
	}
	tag := strings.ToUpper(local[:4])
	return tag == tagSRS0 || tag == tagSRS1
}

// Forward rewrites sender for mail this server forwards, using domain as the
// new sender domain. An SRS0 or SRS1 sender becomes SRS1; any other sender
// becomes SRS0.
func (c *Codec) Forward(sender, domain string) (string, error) {
	at := strings.LastIndex(sender, "@")
	if at <= 0 || at == len(sender)-1 || domain == "" {
		return "", fmt.Errorf("srs: cannot rewrite %q", sender)
	}
	user, host := sender[:at], sender[at+1:]
	if IsSRS(user) {
		var srsHost, srsUser string
		if strings.EqualFold(user[:4], tagSRS0) {
			// Keep the separator: SRS1=HHHH=host==HHHH=TT=origin=user.
			srsHost, srsUser = host, user[4:]
		} else {
			// SRS1=HHHH=host==rest: re-sign host and "=rest" for this hop.
			hashAndRest := user[5:]
			sep := strings.Index(hashAndRest, outputSep)
			if sep < 0 {
				return "", ErrInvalid
			}
			rest := hashAndRest[sep+1:]
			sep = strings.Index(rest, outputSep)
			if sep <= 0 {
				return "", ErrInvalid
			}
			srsHost, srsUser = rest[:sep], rest[sep+1:]
		}
		hash := c.hash(c.secrets[0], srsHost, srsUser)
		return tagSRS1 + outputSep + hash + outputSep + srsHost + outputSep + srsUser + "@" + domain, nil
	}
	stamp := c.timestamp()
	hash := c.hash(c.secrets[0], stamp, host, user)
	return tagSRS0 + outputSep + hash + outputSep + stamp + outputSep + host + outputSep + user + "@" + domain, nil
}

// Reverse verifies an SRS address issued by this server and returns where
// mail sent to it belongs: the original sender for SRS0, or the previous
// forwarder's SRS0 address for SRS1. The domain of address is not checked.
func (c *Codec) Reverse(address string) (string, error) {
	at := strings.LastIndex(address, "@")
	if at <= 0 {
		return "", ErrNotSRS
	}
	local := address[:at]
	if !IsSRS(local) {
		return "", ErrNotSRS
	}
	fields := local[5:]
	if strings.EqualFold(local[:4], tagSRS0) {
		parts := strings.SplitN(fields, outputSep, 4)
		if len(parts) != 4 || parts[0] == "" || parts[2] == "" || parts[3] == "" {
			return "", ErrInvalid
		}
		hash, stamp, host, user := parts[0], parts[1], parts[2], parts[3]
		if !c.verify(hash, stamp, host, user) {
			return "", ErrInvalid
		}
		if err := c.checkTimestamp(stamp); err != nil {
			return "", err
		}
		return user + "@" + host, nil
	}
	// SRS1=HHHH=host==rest returns to SRS0=rest@host.
	parts := strings.SplitN(fields, outputSep, 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || len(parts[2]) < 2 || !strings.ContainsRune(separators, rune(parts[2][0])) {
		return "", ErrInvalid
	}
	hash, host, srsUser := parts[0], parts[1], parts[2]
	if !c.verify(hash, host, srsUser) {
		return "", ErrInvalid
	}
	return tagSRS0 + srsUser + "@" + host, nil
}

// hash is the truncated base64 HMAC-SHA1 of the case-folded fields, matching
// libsrs2 so intermediate MTAs that change case do not invalidate it.
func (c *Codec) hash(secret []byte, fields ...string) string {
	mac := hmac.New(sha1.New, secret)
	for _, field := range fields {
		mac.Write([]byte(strings.ToLower(field)))
	}
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))[:HashLength]
}

// verify compares the hash case-insensitively against every secret, since
// some MTAs fold the case of local parts.
func (c *Codec) verify(hash string, fields ...string) bool {
	if len(hash) != HashLength {
		return false
	}
	for _, secret := range c.secrets {
		if hmac.Equal([]byte(strings.ToLower(c.hash(secret, fields...))), []byte(strings.ToLower(hash))) {
			return true
		}
	}
	return false
}

func (c *Codec) day() int {
	return int(c.now().Unix()/int64(timeDay/time.Second)) % timeSlots
}

func (c *Codec) timestamp() string {
	day := c.day()
	return string([]byte{timeBase32[(day>>5)&31], timeBase32[day&31]})
}

// checkTimestamp accepts stamps up to maxAge days old. Like libsrs2, a stamp
// from the future wraps to an age of almost timeSlots days and is refused.
func (c *Codec) checkTimestamp(stamp string) error {
	if len(stamp) != 2 {
		return ErrInvalid
	}
	then := 0
	for _, char := range strings.ToUpper(stamp) {
		index := strings.IndexRune(timeBase32, char)
		if index < 0 {
			return ErrInvalid
		}
		then = then<<5 | index
	}
	now := c.day()
	for now < then {
		now += timeSlots
	}
	if now-then > c.maxAge {
		return ErrExpired
	}
	return nil
}
