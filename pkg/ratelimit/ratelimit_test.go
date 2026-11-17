package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// --- Bucket tests ---

func TestBucket_Allow_InitialTokens(t *testing.T) {
	b := NewBucket(5, 1)

	// Should allow 5 requests (initial capacity)
	for i := 0; i < 5; i++ {
		if !b.Allow() {
			t.Fatalf("expected allow on request %d", i+1)
		}
	}

	// 6th should be denied
	if b.Allow() {
		t.Fatal("expected deny after exhausting tokens")
	}
}

func TestBucket_Allow_Refill(t *testing.T) {
	b := NewBucket(2, 100) // 100 tokens/sec refill

	// Drain tokens
	b.Allow()
	b.Allow()

	if b.Allow() {
		t.Fatal("expected deny after exhausting tokens")
	}

	// Wait for refill (10 tokens should refill in 100ms at 100/s)
	time.Sleep(150 * time.Millisecond)

	if !b.Allow() {
		t.Fatal("expected allow after refill")
	}
	if !b.Allow() {
		t.Fatal("expected allow after refill (2nd)")
	}
}

func TestBucket_Allow_CapacityCap(t *testing.T) {
	b := NewBucket(3, 1000) // fast refill

	// Wait for tokens to exceed capacity
	time.Sleep(10 * time.Millisecond)

	// Should only allow up to capacity
	allowed := 0
	for i := 0; i < 10; i++ {
		if b.Allow() {
			allowed++
		}
	}

	if allowed != 3 {
		t.Fatalf("expected exactly 3 allowed (capacity), got %d", allowed)
	}
}

func TestBucket_AllowN(t *testing.T) {
	b := NewBucket(10, 1)

	if !b.AllowN(5) {
		t.Fatal("expected AllowN(5) to succeed")
	}

	if !b.AllowN(5) {
		t.Fatal("expected AllowN(5) to succeed (remaining)")
	}

	if b.AllowN(1) {
		t.Fatal("expected AllowN(1) to fail (no tokens left)")
	}
}

func TestBucket_TokensRemaining(t *testing.T) {
	b := NewBucket(10, 0) // no refill

	b.Allow()
	b.Allow()

	remaining := b.TokensRemaining()
	if remaining < 7.5 || remaining > 10 {
		t.Fatalf("expected ~8 remaining, got %f", remaining)
	}
}

func TestBucket_Concurrent(t *testing.T) {
	b := NewBucket(1000, 0)

	var wg sync.WaitGroup
	var allowed int64
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.Allow() {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// All 100 should be allowed (1000 capacity)
	if allowed != 100 {
		t.Fatalf("expected 100 allowed, got %d", allowed)
	}
}

// --- Limiter tests ---

func TestLimiter_Allow_PerKey(t *testing.T) {
	l := NewLimiter(3, 0) // 3 tokens, no refill

	// Key "a" should get 3 allows
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("expected allow for key 'a' on request %d", i+1)
		}
	}

	if l.Allow("a") {
		t.Fatal("expected deny for key 'a' after 3 requests")
	}

	// Key "b" should still be allowed (independent bucket)
	if !l.Allow("b") {
		t.Fatal("expected allow for key 'b' (independent bucket)")
	}
}

func TestLimiter_Reset(t *testing.T) {
	l := NewLimiter(2, 0)

	l.Allow("a")
	l.Allow("a")

	if l.Allow("a") {
		t.Fatal("expected deny")
	}

	l.Reset()

	if !l.Allow("a") {
		t.Fatal("expected allow after reset")
	}
}

func TestLimiter_Concurrent(t *testing.T) {
	l := NewLimiter(100, 0)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "key"
			l.Allow(key)
		}(i)
	}

	wg.Wait()
}

// --- Convenience constructors ---

func TestNewCommandLimiter(t *testing.T) {
	l := NewCommandLimiter()
	if l == nil {
		t.Fatal("expected non-nil limiter")
	}
	if !l.Allow("session-1") {
		t.Fatal("expected first command to be allowed")
	}
}

// A mailbox synchronization from a real client (OfflineIMAP) issued more than
// the generic command burst back to back and was disconnected with BYE.
func TestNewIMAPCommandLimiterAllowsSyncBursts(t *testing.T) {
	l := NewIMAPCommandLimiter()
	for i := 0; i < 500; i++ {
		if !l.Allow("session-1") {
			t.Fatalf("command %d rejected; IMAP synchronization bursts must be allowed", i)
		}
	}
	// The bucket refills over time, so a slow machine may let a few more
	// through; a runaway loop must still be stopped well before this bound.
	limited := false
	for i := 0; i < 20000 && !limited; i++ {
		limited = !l.Allow("session-2")
	}
	if !limited {
		t.Fatal("a runaway command loop must still be limited")
	}
}

func TestNewHTTPLimiter(t *testing.T) {
	l := NewHTTPLimiter()
	if l == nil {
		t.Fatal("expected non-nil limiter")
	}
	if !l.Allow("10.0.0.1") {
		t.Fatal("expected first HTTP request to be allowed")
	}
}

func TestNewAuthLimiter(t *testing.T) {
	l := NewAuthLimiter()
	if l == nil {
		t.Fatal("expected non-nil limiter")
	}
	if !l.Allow("user-1") {
		t.Fatal("expected first auth attempt to be allowed")
	}
}

// --- HTTP middleware tests ---

func TestHTTPMiddleware_Allow(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewHTTPMiddleware()
	handler := m.Wrap(next)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHTTPMiddleware_RateLimit(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use a very small limiter
	m := NewHTTPMiddlewareWithLimiter(NewLimiter(2, 0))
	handler := m.Wrap(next)

	// First 2 requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 3rd should be rate limited
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
}

func TestHTTPMiddleware_DifferentIPs(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewHTTPMiddlewareWithLimiter(NewLimiter(1, 0))
	handler := m.Wrap(next)

	// IP 1 uses its token
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// IP 2 should still be allowed (separate bucket)
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "5.6.7.8:5678"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for different IP, got %d", w.Code)
	}
}

func TestHTTPMiddleware_CustomKeyFn(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewHTTPMiddlewareWithLimiter(NewLimiter(1, 0))
	m.SetKeyFn(func(r *http.Request) string {
		return r.Header.Get("X-User-ID")
	})
	handler := m.Wrap(next)

	// User A uses its token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-User-ID", "user-a")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// User B should still be allowed
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-User-ID", "user-b")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for different user, got %d", w.Code)
	}
}

func TestExtractIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.Header.Set("X-Forwarded-For", "10.0.0.2")
	if ip := extractIP(req); ip != "1.2.3.4" {
		t.Fatalf("forwarding headers were trusted without a resolver: %s", ip)
	}
	req = req.WithContext(WithClientIP(req.Context(), "203.0.113.5"))
	if ip := extractIP(req); ip != "203.0.113.5" {
		t.Fatalf("resolved client IP ignored: %s", ip)
	}
}

func TestRateLimitCounter(t *testing.T) {
	c := &RateLimitCounter{}

	c.Increment()
	c.Increment()

	if c.Count() != 2 {
		t.Fatalf("expected count 2, got %d", c.Count())
	}
}

// --- Integration-style tests ---

func TestBucket_Allow_RapidDrain(t *testing.T) {
	b := NewBucket(10, 1) // 1 token/sec

	// Drain all tokens
	for i := 0; i < 10; i++ {
		if !b.Allow() {
			t.Fatalf("expected allow on request %d", i+1)
		}
	}

	// Should be denied
	if b.Allow() {
		t.Fatal("expected deny after draining")
	}

	// Wait for 1 token to refill
	time.Sleep(1200 * time.Millisecond)

	if !b.Allow() {
		t.Fatal("expected allow after 1.2s refill")
	}
}

func TestLimiter_PruneStaleBuckets(t *testing.T) {
	l := NewLimiter(10000, 0) // high capacity so prune-trigger always succeeds

	// Create a stale bucket
	l.Allow("temp-key")

	// Manually make the bucket stale
	l.mu.Lock()
	if b, ok := l.buckets["temp-key"]; ok {
		b.mu.Lock()
		b.lastTime = time.Now().Add(-10 * time.Minute)
		b.mu.Unlock()
	}
	l.mu.Unlock()

	// Trigger pruning by calling Allow 1000 times (pruneEvery starts at 1000)
	for i := 0; i < 1000; i++ {
		l.Allow("prune-trigger")
	}

	// Check if temp-key was pruned
	l.mu.RLock()
	_, exists := l.buckets["temp-key"]
	l.mu.RUnlock()

	if exists {
		t.Fatal("expected stale bucket to be pruned")
	}
}
