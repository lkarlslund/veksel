// Package ratelimit provides a token-bucket rate limiter for per-IP and
// per-user throttling of SMTP, IMAP and HTTP endpoints.
package ratelimit

import (
	"math"
	"sync"
	"time"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

var log = logpkg.For(logpkg.ModuleRateLimit)

// Bucket is a single token-bucket slot.
type Bucket struct {
	// Capacity is the maximum number of tokens (burst size).
	Capacity float64
	// RefillRate is the number of tokens added per second.
	RefillRate float64

	mu       sync.Mutex
	tokens   float64
	lastTime time.Time
	now      func() time.Time
}

// NewBucket creates a bucket that starts full.
func NewBucket(capacity, refillRate float64) *Bucket {
	return newBucket(capacity, refillRate, time.Now)
}

func newBucket(capacity, refillRate float64, now func() time.Time) *Bucket {
	return &Bucket{
		Capacity:   capacity,
		RefillRate: refillRate,
		tokens:     capacity,
		lastTime:   now(),
		now:        now,
	}
}

// refillLocked adds the tokens earned since the last observation. The caller
// must hold b.mu.
func (b *Bucket) refillLocked() {
	now := b.now()
	b.tokens += now.Sub(b.lastTime).Seconds() * b.RefillRate
	b.lastTime = now
	if b.tokens > b.Capacity {
		b.tokens = b.Capacity
	}
}

// Allow checks whether a single token can be consumed.
// It returns true when the request is allowed, false when it must be
// rejected.
func (b *Bucket) Allow() bool {
	return b.AllowN(1)
}

// AllowN checks whether n tokens can be consumed.
func (b *Bucket) AllowN(n float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refillLocked()
	if b.tokens < n {
		return false
	}

	b.tokens -= n
	return true
}

// TokensRemaining returns the current number of available tokens (approximate).
func (b *Bucket) TokensRemaining() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refillLocked()
	return b.tokens
}

// RetryAfter returns how long the caller must wait until n tokens are
// available. It returns zero when n tokens are available now.
func (b *Bucket) RetryAfter(n float64) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refillLocked()
	if b.tokens >= n {
		return 0
	}
	if b.RefillRate <= 0 {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration((n - b.tokens) / b.RefillRate * float64(time.Second))
}

// Limiter manages a map of buckets keyed by arbitrary strings (IP, user ID,
// etc.). It automatically prunes stale entries.
type Limiter struct {
	mu         sync.RWMutex
	buckets    map[string]*Bucket
	capacity   float64
	refillRate float64
	pruneEvery int // prune counter (decremented on each Allow call)
	now        func() time.Time
}

// NewLimiter creates a limiter that shares the same capacity and refill rate
// for every key it tracks.
func NewLimiter(capacity, refillRate float64) *Limiter {
	return &Limiter{
		buckets:    make(map[string]*Bucket),
		capacity:   capacity,
		refillRate: refillRate,
		pruneEvery: 1000,
		now:        time.Now,
	}
}

// SetClock replaces the time source used by the limiter and its buckets. It
// exists so tests can advance time deterministically and must be called
// before the limiter is shared.
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
	for _, b := range l.buckets {
		b.mu.Lock()
		b.now = now
		b.mu.Unlock()
	}
}

// getBucket returns (or lazily creates) the bucket for key.
func (l *Limiter) getBucket(key string) *Bucket {
	l.mu.RLock()
	b, ok := l.buckets[key]
	l.mu.RUnlock()
	if ok {
		return b
	}

	l.mu.Lock()
	// Double-check after acquiring write lock.
	if b, ok = l.buckets[key]; ok {
		l.mu.Unlock()
		return b
	}
	b = newBucket(l.capacity, l.refillRate, l.now)
	l.buckets[key] = b
	l.mu.Unlock()
	return b
}

// RetryAfter reports how long the request identified by key must wait before
// Allow would succeed, without consuming a token. Unknown keys are allowed.
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.RLock()
	b, ok := l.buckets[key]
	l.mu.RUnlock()
	if !ok {
		return 0
	}
	return b.RetryAfter(1)
}

// Refund returns one token to the bucket for key, up to its capacity.
func (l *Limiter) Refund(key string) {
	l.mu.RLock()
	b, ok := l.buckets[key]
	l.mu.RUnlock()
	if !ok {
		return
	}
	b.mu.Lock()
	b.refillLocked()
	b.tokens = min(b.tokens+1, b.Capacity)
	b.mu.Unlock()
}

// Forget drops the bucket for key so its next request starts with a full
// burst.
func (l *Limiter) Forget(key string) {
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

// Allow checks whether the request identified by key is allowed.
func (l *Limiter) Allow(key string) bool {
	b := l.getBucket(key)
	allowed := b.Allow()

	if !allowed {
		log.Warn("ratelimit: rate limit exceeded", "key", key)
	}

	// Periodically prune stale buckets.
	if allowed {
		l.maybePrune()
	}

	return allowed
}

// maybePrune removes buckets that have been idle for a while.
func (l *Limiter) maybePrune() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneEvery--
	if l.pruneEvery > 0 {
		return
	}
	l.pruneEvery = 1000

	now := l.now()
	for key, b := range l.buckets {
		b.mu.Lock()
		// A bucket may only be dropped once it would have refilled
		// completely; otherwise pruning would forgive outstanding debt.
		idleFor := 5 * time.Minute
		if b.RefillRate > 0 {
			idleFor = max(idleFor, time.Duration((b.Capacity-b.tokens)/b.RefillRate*float64(time.Second)))
		}
		idle := now.Sub(b.lastTime) > idleFor
		b.mu.Unlock()
		if idle {
			delete(l.buckets, key)
		}
	}
}

// Reset removes all tracked buckets. Useful for tests.
func (l *Limiter) Reset() {
	l.mu.Lock()
	l.buckets = make(map[string]*Bucket)
	l.mu.Unlock()
}

// GetCapacity returns the current capacity (burst size) of the limiter.
func (l *Limiter) GetCapacity() float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.capacity
}

// GetRefillRate returns the current refill rate (tokens per second) of the limiter.
func (l *Limiter) GetRefillRate() float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.refillRate
}

// SetParams updates the capacity and refill rate of the limiter.
// Existing buckets are updated with the new parameters.
func (l *Limiter) SetParams(capacity, refillRate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.capacity = capacity
	l.refillRate = refillRate
	// Update existing buckets
	for _, b := range l.buckets {
		b.Capacity = capacity
		b.RefillRate = refillRate
	}
}

// SetBucketParams updates the capacity and refill rate for a single key.
// If the bucket does not exist yet, it is created with the given parameters.
func (l *Limiter) SetBucketParams(key string, capacity, refillRate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = newBucket(capacity, refillRate, l.now)
		l.buckets[key] = b
		return
	}
	b.Capacity = capacity
	b.RefillRate = refillRate
}

// --- Convenience constructors for common limits ---

// NewCommandLimiter returns a limiter suitable for per-connection command
// throttling: 10 commands per second, burst 20.
func NewCommandLimiter() *Limiter {
	return NewLimiter(20, 10)
}

// NewSMTPCommandLimiter returns a per-connection limiter for SMTP command
// batches. A client without PIPELINING (Python smtplib, many scripts and
// relays) sends MAIL, one RCPT per recipient and DATA back to back, so one
// message to the 100 recipient limit is over a hundred commands, and several
// messages may follow in the same session. Abuse is bounded by the protocol
// violation, unknown-recipient and authentication limits; this only stops a
// runaway loop: sustained 50 batches per second, burst 300.
func NewSMTPCommandLimiter() *Limiter {
	return NewLimiter(300, 50)
}

// NewIMAPCommandLimiter returns a per-connection limiter for IMAP commands.
// Mail clients legitimately issue hundreds of FETCH, STORE, and SELECT
// commands back to back while synchronizing a mailbox (OfflineIMAP, Thunderbird),
// so this only guards against a runaway or hostile loop: sustained 500
// commands per second, burst 1000.
func NewIMAPCommandLimiter() *Limiter {
	return NewLimiter(1000, 500)
}

// NewHTTPLimiter returns a limiter suitable for HTTP admin API: 60 requests
// per minute per IP (1/s refill, burst 20).
func NewHTTPLimiter() *Limiter {
	return NewLimiter(20, 1)
}

// NewAuthLimiter returns the per-IP limiter protocol sessions consult before
// each authentication attempt. Sessions refund successful attempts, so only
// failures and attempts still in flight count. Its budget equals the per-IP
// failure budget of AuthThrottle: many users behind one shared address log in
// concurrently, and one misconfigured client there must not lock the others
// out before password-verification throttling would.
func NewAuthLimiter() *Limiter {
	return NewLimiter(DefaultAuthFailuresPerIP, DefaultAuthFailuresPerIP/DefaultAuthFailureWindow.Seconds())
}
