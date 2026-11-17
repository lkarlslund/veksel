package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Default failed-authentication budgets. A client may fail
// DefaultAuthFailuresPerAccount times against one account, and
// DefaultAuthFailuresPerIP times in total, before it must wait. Budgets refill
// continuously over DefaultAuthFailureWindow.
const (
	DefaultAuthFailuresPerAccount = 10
	DefaultAuthFailuresPerIP      = 50
	DefaultAuthFailureWindow      = 15 * time.Minute
)

// ErrAuthThrottled reports that a client exhausted its failed-authentication
// budget. Use errors.Is to detect it and errors.As with *AuthThrottledError
// to obtain the retry delay.
var ErrAuthThrottled = errors.New("too many failed authentication attempts")

// AuthThrottledError carries the delay before the next attempt is admitted.
type AuthThrottledError struct {
	RetryAfter time.Duration
}

func (e *AuthThrottledError) Error() string {
	return fmt.Sprintf("%s; retry after %s", ErrAuthThrottled, e.RetryAfter.Round(time.Second))
}

func (e *AuthThrottledError) Is(target error) bool { return target == ErrAuthThrottled }

// RetryAfterSeconds returns the Retry-After value for err, rounded up to whole
// seconds, or zero when err is not an authentication throttle.
func RetryAfterSeconds(err error) int {
	var throttled *AuthThrottledError
	if !errors.As(err, &throttled) {
		return 0
	}
	return max(1, int((throttled.RetryAfter+time.Second-1)/time.Second))
}

// WriteRetryAfter sets the Retry-After header for a throttled request.
func WriteRetryAfter(w http.ResponseWriter, err error) {
	if seconds := RetryAfterSeconds(err); seconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
}

// AuthThrottle limits failed password verification per client IP and per
// client IP plus account. Callers bracket every password comparison with
// Begin and End: Begin reserves one failure from each budget, or refuses
// before any expensive work runs, and End returns the reservation when the
// credentials were valid. Reserving up front means concurrent guesses cannot
// all slip past the check. Only failures keep their reservation, so
// legitimate users are never throttled by their own successful logins. A nil
// *AuthThrottle admits every attempt.
type AuthThrottle struct {
	perIP      *Limiter
	perAccount *Limiter
	observer   atomic.Pointer[AuthObserver]
}

// AuthObserver is told the outcome of every attempt that names a client IP:
// success after End with valid credentials, failure after End with invalid
// ones or when Begin refuses a throttled client. It runs synchronously and
// must be cheap; the abuse ban engine counts failures with it.
type AuthObserver func(ip, account string, success bool)

// secondFactorAccountPrefix keys second-factor attempts apart from password
// attempts for the same account.
const secondFactorAccountPrefix = "second-factor:"

// SecondFactorAccount returns the throttle account key for second-factor
// (TOTP, recovery code, step-up) attempts by userID.
func SecondFactorAccount(userID string) string { return secondFactorAccountPrefix + userID }

// IsSecondFactorAccount reports whether account was built by
// SecondFactorAccount.
func IsSecondFactorAccount(account string) bool {
	return strings.HasPrefix(account, secondFactorAccountPrefix)
}

// NewAuthThrottle returns a throttle with the default budgets.
func NewAuthThrottle() *AuthThrottle {
	return NewAuthThrottleWithLimits(DefaultAuthFailuresPerIP, DefaultAuthFailuresPerAccount, DefaultAuthFailureWindow)
}

// NewAuthThrottleWithLimits returns a throttle admitting ipFailures failures
// per client IP and accountFailures failures per client IP and account, each
// budget refilling fully over window.
func NewAuthThrottleWithLimits(ipFailures, accountFailures int, window time.Duration) *AuthThrottle {
	return &AuthThrottle{
		perIP:      NewLimiter(float64(ipFailures), float64(ipFailures)/window.Seconds()),
		perAccount: NewLimiter(float64(accountFailures), float64(accountFailures)/window.Seconds()),
	}
}

// SetClock replaces the time source; see Limiter.SetClock.
func (t *AuthThrottle) SetClock(now func() time.Time) {
	t.perIP.SetClock(now)
	t.perAccount.SetClock(now)
}

// SetObserver installs the attempt observer; nil removes it.
func (t *AuthThrottle) SetObserver(observer AuthObserver) {
	if observer == nil {
		t.observer.Store(nil)
		return
	}
	t.observer.Store(&observer)
}

func (t *AuthThrottle) observe(ip, account string, success bool) {
	if observer := t.observer.Load(); observer != nil {
		(*observer)(ip, account, success)
	}
}

// Begin reserves one failed attempt for ip and for ip together with account.
// When either budget is exhausted it reserves nothing and returns an
// *AuthThrottledError; the answer does not depend on whether account exists.
// Attempts without a known client IP are admitted. Every nil return must be
// followed by End.
func (t *AuthThrottle) Begin(ip, account string) error {
	if t == nil || ip == "" {
		return nil
	}
	key := accountKey(ip, account)
	if wait := max(t.perIP.RetryAfter(ip), t.perAccount.RetryAfter(key)); wait > 0 {
		log.Warn("ratelimit: authentication throttled", "ip", ip, "account", account)
		t.observe(ip, account, false)
		return &AuthThrottledError{RetryAfter: wait}
	}
	t.perIP.Allow(ip)
	t.perAccount.Allow(key)
	return nil
}

// End completes an attempt admitted by Begin. A successful attempt returns its
// per-IP reservation and clears the per-account history for ip; a failed one
// keeps both reservations.
func (t *AuthThrottle) End(ip, account string, success bool) {
	if t == nil || ip == "" {
		return
	}
	t.observe(ip, account, success)
	if !success {
		return
	}
	t.perIP.Refund(ip)
	t.perAccount.Forget(accountKey(ip, account))
}

func accountKey(ip, account string) string {
	return ip + "\x00" + strings.ToLower(strings.TrimSpace(account))
}

type clientIPKey struct{}

// WithClientIP records the authenticating client's IP address in ctx for
// credential services that only receive a context.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIP returns the IP stored by WithClientIP, or "" when unknown.
func ClientIP(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}

// AddrIP returns the host part of a network address such as
// net.Conn.RemoteAddr().String() or http.Request.RemoteAddr.
func AddrIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
