package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
)

// Bounds of the verified-password cache. Ten minutes covers the polling
// interval of CalDAV, CardDAV and JMAP clients, which send HTTP Basic
// credentials with every request.
const (
	verifiedCacheEntries = 8192
	verifiedCacheTTL     = 10 * time.Minute
)

// verifiedPasswords remembers recent successful password comparisons, so a
// client that authenticates every request pays the deliberate bcrypt cost
// once per window rather than per request.
var verifiedPasswords = newVerifiedCache(verifiedCacheEntries, verifiedCacheTTL)

// verifiedCache holds HMAC digests, under a random per-process key, of a
// stored hash and a password that matched it. No password is kept; a
// changed password has a new hash and never matches an old entry; failed
// comparisons are never cached, so guessing still costs a full bcrypt.
type verifiedCache struct {
	key     []byte
	limit   int
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	entries map[[sha256.Size]byte]time.Time
}

func newVerifiedCache(limit int, ttl time.Duration) *verifiedCache {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("auth: random cache key: " + err.Error())
	}
	return &verifiedCache{key: key, limit: limit, ttl: ttl, now: time.Now, entries: make(map[[sha256.Size]byte]time.Time)}
}

func (c *verifiedCache) digest(password, hash string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(hash))
	mac.Write([]byte{0})
	mac.Write([]byte(password))
	var digest [sha256.Size]byte
	mac.Sum(digest[:0])
	return digest
}

// verified reports whether password recently matched hash.
func (c *verifiedCache) verified(password, hash string) bool {
	digest := c.digest(password, hash)
	c.mu.Lock()
	defer c.mu.Unlock()
	expires, ok := c.entries[digest]
	if ok && c.now().Before(expires) {
		return true
	}
	if ok {
		delete(c.entries, digest)
	}
	return false
}

// remember records that password matched hash.
func (c *verifiedCache) remember(password, hash string) {
	digest := c.digest(password, hash)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.entries) >= c.limit {
		for entry, expires := range c.entries {
			if !now.Before(expires) {
				delete(c.entries, entry)
			}
		}
		// Still full: drop arbitrary entries; they only cost a bcrypt.
		for entry := range c.entries {
			if len(c.entries) < c.limit {
				break
			}
			delete(c.entries, entry)
		}
	}
	c.entries[digest] = now.Add(c.ttl)
}
