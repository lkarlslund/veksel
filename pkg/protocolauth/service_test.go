package protocolauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func protocolAuthFixture(t *testing.T) (*model.TypedStore, *Service) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.UserStore().Create(t.Context(), "alice", "Alice", "primary-password"); err != nil {
		t.Fatal(err)
	}
	if err := typed.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := typed.UserStore().AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	return typed, New(typed)
}

func TestServiceAcceptsPrimaryAndScopedApplicationPassword(t *testing.T) {
	typed, service := protocolAuthFixture(t)
	if result, err := service.Authenticate(t.Context(), "ALICE", "primary-password", model.AppProtocolIMAP); err != nil || result.User.ID != "alice" || result.AppPasswordID != "" {
		t.Fatalf("primary authentication=%+v, %v", result, err)
	}
	if _, err := service.Authenticate(t.Context(), "alice", "primary-password", "unknown"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("primary password accepted for unknown protocol: %v", err)
	}
	created, secret, err := model.NewAppPasswordStore(typed).Create(t.Context(), "alice", "Mail client", []string{model.AppProtocolIMAP, model.AppProtocolSMTP})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Authenticate(t.Context(), "ALICE@EXAMPLE.TEST", secret, model.AppProtocolSMTP)
	if err != nil || result.User.ID != "alice" || result.AppPasswordID != created.ID {
		t.Fatalf("application-password authentication=%+v, %v", result, err)
	}
	if _, err := service.Authenticate(t.Context(), "alice", secret, model.AppProtocolPOP3); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unscoped authentication error=%v", err)
	}
	if _, err := service.Authenticate(t.Context(), "alice", secret, "unknown"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown protocol error=%v", err)
	}
	//lint:ignore SA1012 legacy protocol callbacks may still pass a nil context
	if result, err := service.Authenticate(nil, "alice", secret, model.AppProtocolIMAP); err != nil || result.User.ID != "alice" {
		t.Fatalf("nil-context protocol callback = %+v, %v", result, err)
	}
}

func TestServiceReportsSuccessfulLoginsOnly(t *testing.T) {
	_, service := protocolAuthFixture(t)
	var logins []string
	service.SetLoginObserver(func(_ context.Context, account, ip string) { logins = append(logins, account+"@"+ip) })
	client := ratelimit.WithClientIP(t.Context(), "192.0.2.7")
	if _, err := service.Authenticate(client, "alice", "wrong", model.AppProtocolIMAP); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := service.Authenticate(client, "ALICE", "primary-password", model.AppProtocolIMAP); err != nil {
		t.Fatal(err)
	}
	if len(logins) != 1 || logins[0] != "alice@192.0.2.7" {
		t.Fatalf("observed logins = %q", logins)
	}
	service.SetLoginObserver(nil)
	if _, err := service.Authenticate(client, "alice", "primary-password", model.AppProtocolIMAP); err != nil || len(logins) != 1 {
		t.Fatalf("removed observer still called: %q, %v", logins, err)
	}
}

func TestServiceRejectsDisabledAccountForEveryCredential(t *testing.T) {
	typed, service := protocolAuthFixture(t)
	_, secret, err := model.NewAppPasswordStore(typed).Create(t.Context(), "alice", "Mail client", []string{model.AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}
	user, err := typed.UserStore().Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	user.Enabled = false
	if err := typed.Set(t.Context(), model.NSUsers, user.ID, user); err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"primary-password", secret} {
		if _, err := service.Authenticate(t.Context(), "alice", password, model.AppProtocolIMAP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("disabled account authenticated with %q: %v", password[:5], err)
		}
	}
}

func TestServiceThrottlesRepeatedFailuresBeforeComparingPasswords(t *testing.T) {
	_, service := protocolAuthFixture(t)
	now := time.Unix(1_700_000_000, 0)
	throttle := ratelimit.NewAuthThrottleWithLimits(5, 3, time.Minute)
	throttle.SetClock(func() time.Time { return now })
	service.SetThrottle(throttle)
	compares := 0
	compare := service.compare
	service.compare = func(password, hash string) bool { compares++; return compare(password, hash) }
	attacker := ratelimit.WithClientIP(t.Context(), "192.0.2.1")

	for range 3 {
		if _, err := service.Authenticate(attacker, "alice", "wrong", model.AppProtocolDAV); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure error=%v", err)
		}
	}
	compares = 0
	_, err := service.Authenticate(attacker, "alice", "primary-password", model.AppProtocolDAV)
	if !errors.Is(err, ratelimit.ErrAuthThrottled) || ratelimit.RetryAfterSeconds(err) <= 0 {
		t.Fatalf("throttled error=%v", err)
	}
	if compares != 0 {
		t.Fatalf("password compared %d times while throttled", compares)
	}
	// Unknown accounts consume and report the same per-IP budget.
	for range 2 {
		if _, err := service.Authenticate(attacker, "nobody", "wrong", model.AppProtocolDAV); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("unknown account error=%v", err)
		}
	}
	if _, err := service.Authenticate(attacker, "other", "wrong", model.AppProtocolDAV); !errors.Is(err, ratelimit.ErrAuthThrottled) {
		t.Fatalf("per-IP budget not enforced: %v", err)
	}
	other := ratelimit.WithClientIP(t.Context(), "192.0.2.2")
	if _, err := service.Authenticate(other, "alice", "primary-password", model.AppProtocolDAV); err != nil {
		t.Fatalf("different IP throttled: %v", err)
	}

	now = now.Add(time.Minute)
	if _, err := service.Authenticate(attacker, "alice", "primary-password", model.AppProtocolDAV); err != nil {
		t.Fatalf("login after window: %v", err)
	}
}
