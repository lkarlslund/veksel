package ratelimit

import (
	"errors"
	"testing"
	"time"
)

func newTestAuthThrottle(ipFailures, accountFailures int) (*AuthThrottle, *time.Time) {
	now := time.Unix(1_700_000_000, 0)
	throttle := NewAuthThrottleWithLimits(ipFailures, accountFailures, 15*time.Minute)
	throttle.SetClock(func() time.Time { return now })
	return throttle, &now
}

func TestAuthThrottleCountsOnlyFailures(t *testing.T) {
	throttle, now := newTestAuthThrottle(50, 3)
	for range 10 {
		if err := throttle.Begin("192.0.2.1", "alice"); err != nil {
			t.Fatalf("successful logins throttled: %v", err)
		}
		throttle.End("192.0.2.1", "alice", true)
	}
	for range 3 {
		if err := throttle.Begin("192.0.2.1", "Alice "); err != nil {
			t.Fatal(err)
		}
		throttle.End("192.0.2.1", "Alice ", false)
	}
	err := throttle.Begin("192.0.2.1", "alice")
	var throttled *AuthThrottledError
	if !errors.Is(err, ErrAuthThrottled) || !errors.As(err, &throttled) || throttled.RetryAfter != 5*time.Minute {
		t.Fatalf("Begin after budget = %v", err)
	}
	if RetryAfterSeconds(err) != 300 {
		t.Fatalf("RetryAfterSeconds = %d", RetryAfterSeconds(err))
	}
	if err := throttle.Begin("192.0.2.1", "bob"); err != nil {
		t.Fatalf("other account throttled by per-account budget: %v", err)
	}
	throttle.End("192.0.2.1", "bob", true)
	if err := throttle.Begin("192.0.2.2", "alice"); err != nil {
		t.Fatalf("other IP throttled: %v", err)
	}
	throttle.End("192.0.2.2", "alice", true)
	*now = now.Add(5 * time.Minute)
	if err := throttle.Begin("192.0.2.1", "alice"); err != nil {
		t.Fatalf("budget did not refill: %v", err)
	}
}

func TestAuthThrottlePerIPBudgetSpansAccounts(t *testing.T) {
	throttle, _ := newTestAuthThrottle(4, 10)
	for i := range 4 {
		account := string(rune('a' + i))
		if err := throttle.Begin("192.0.2.1", account); err != nil {
			t.Fatal(err)
		}
		throttle.End("192.0.2.1", account, false)
	}
	if err := throttle.Begin("192.0.2.1", "fresh"); !errors.Is(err, ErrAuthThrottled) {
		t.Fatalf("per-IP budget not enforced: %v", err)
	}
	if err := throttle.Begin("", "fresh"); err != nil {
		t.Fatalf("unknown client IP throttled: %v", err)
	}
	var disabled *AuthThrottle
	if err := disabled.Begin("192.0.2.1", "fresh"); err != nil {
		t.Fatalf("nil throttle refused: %v", err)
	}
	disabled.End("192.0.2.1", "fresh", false)
}

func TestAuthThrottleReservesConcurrentAttempts(t *testing.T) {
	throttle, _ := newTestAuthThrottle(50, 2)
	for range 2 {
		if err := throttle.Begin("192.0.2.1", "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if err := throttle.Begin("192.0.2.1", "alice"); !errors.Is(err, ErrAuthThrottled) {
		t.Fatalf("in-flight attempts not reserved: %v", err)
	}
}

func TestLimiterPruneKeepsUnrefilledDebt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewLimiter(1, 1.0/3600)
	l.SetClock(func() time.Time { return now })
	l.Allow("debtor")
	now = now.Add(10 * time.Minute)
	l.maybePruneNow()
	if l.RetryAfter("debtor") == 0 {
		t.Fatal("pruning forgave a bucket that had not refilled")
	}
	now = now.Add(time.Hour)
	l.maybePruneNow()
	l.mu.RLock()
	_, exists := l.buckets["debtor"]
	l.mu.RUnlock()
	if exists {
		t.Fatal("refilled bucket was not pruned")
	}
}

func (l *Limiter) maybePruneNow() {
	l.mu.Lock()
	l.pruneEvery = 1
	l.mu.Unlock()
	l.maybePrune()
}

func TestAuthThrottleObserverSeesEveryOutcome(t *testing.T) {
	throttle, _ := newTestAuthThrottle(50, 1)
	type outcome struct {
		ip, account string
		success     bool
	}
	var seen []outcome
	throttle.SetObserver(func(ip, account string, success bool) { seen = append(seen, outcome{ip, account, success}) })
	second := SecondFactorAccount("alice")
	for _, attempt := range []outcome{{"192.0.2.1", "alice", true}, {"192.0.2.1", second, false}, {"", "alice", false}} {
		if err := throttle.Begin(attempt.ip, attempt.account); err != nil {
			t.Fatal(err)
		}
		throttle.End(attempt.ip, attempt.account, attempt.success)
	}
	if err := throttle.Begin("192.0.2.1", second); !errors.Is(err, ErrAuthThrottled) {
		t.Fatalf("throttled attempt admitted: %v", err)
	}
	want := []outcome{{"192.0.2.1", "alice", true}, {"192.0.2.1", second, false}, {"192.0.2.1", second, false}}
	if len(seen) != len(want) {
		t.Fatalf("observed %+v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("observed %+v, want %+v", seen, want)
		}
	}
	if !IsSecondFactorAccount(second) || IsSecondFactorAccount("alice") {
		t.Fatal("second-factor account keys are not recognised")
	}
}
