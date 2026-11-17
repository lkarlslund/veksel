package ratelimit

import (
	"net/http"
	"sync/atomic"
)

// HTTPMiddleware wraps an http.Handler with per-IP rate limiting.
// When a client exceeds the limit, a 429 Too Many Requests response is
// returned.
type HTTPMiddleware struct {
	limiter *Limiter
	// keyFn extracts the rate-limit key from the request. Defaults to
	// remote IP if nil.
	keyFn func(*http.Request) string
}

// NewHTTPMiddleware creates a middleware that uses the default HTTP limiter
// (60 req/min per IP).
func NewHTTPMiddleware() *HTTPMiddleware {
	return &HTTPMiddleware{limiter: NewHTTPLimiter()}
}

// NewHTTPMiddlewareWithLimiter creates a middleware with a custom limiter.
func NewHTTPMiddlewareWithLimiter(lim *Limiter) *HTTPMiddleware {
	return &HTTPMiddleware{limiter: lim}
}

// Limiter returns the underlying limiter.
func (m *HTTPMiddleware) Limiter() *Limiter {
	return m.limiter
}

// SetKeyFn overrides the default key extraction (remote IP).
func (m *HTTPMiddleware) SetKeyFn(fn func(*http.Request) string) {
	m.keyFn = fn
}

// GetKey returns the key for a request.
func (m *HTTPMiddleware) GetKey(r *http.Request) string {
	if m.keyFn != nil {
		return m.keyFn(r)
	}
	return extractIP(r)
}

// Wrap returns an http.Handler that enforces rate limiting.
func (m *HTTPMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := m.GetKey(r)
		if !m.limiter.Allow(key) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractIP returns the client IP resolved by the trusted-proxy handler
// (httpservice.TrustedProxies), falling back to the transport peer. Forwarding
// headers are never read here.
func extractIP(r *http.Request) string {
	if ip := ClientIP(r.Context()); ip != "" {
		return ip
	}
	return AddrIP(r.RemoteAddr)
}

// --- Per-handler counter for tracking rate-limited requests ---

// RateLimitCounter tracks the number of rate-limited requests.
type RateLimitCounter struct {
	n atomic.Int64
}

// Increment bumps the counter.
func (c *RateLimitCounter) Increment() {
	c.n.Add(1)
}

// Count returns the current count.
func (c *RateLimitCounter) Count() int64 {
	return c.n.Load()
}
