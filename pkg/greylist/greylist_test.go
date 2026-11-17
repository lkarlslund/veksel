package greylist

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func testService(t *testing.T) (*Service, func(time.Duration)) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	config := DefaultConfig()
	config.Enabled = true
	service, err := New(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 18, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	return service, func(delta time.Duration) { now = now.Add(delta) }
}

func TestSetConfigAppliesToNextCheckAndRejectsInvalid(t *testing.T) {
	service, _ := testService(t)
	input := Triplet{RemoteIP: "192.0.2.10", EnvelopeFrom: "a@example.net", Recipient: "b@example.com"}
	disabled := service.Config()
	disabled.Enabled = false
	if err := service.SetConfig(disabled); err != nil {
		t.Fatal(err)
	}
	if decision, err := service.Check(t.Context(), input); err != nil || decision.Action != ActionBypass || service.Enabled() {
		t.Fatalf("disabled decision = %+v, %v", decision, err)
	}
	enabled := disabled
	enabled.Enabled, enabled.MinimumDelay = true, 7*time.Minute
	if err := service.SetConfig(enabled); err != nil {
		t.Fatal(err)
	}
	if decision, err := service.Check(t.Context(), input); err != nil || decision.Action != ActionDefer || decision.RetryAfter != 7*time.Minute {
		t.Fatalf("enabled decision = %+v, %v", decision, err)
	}
	invalid := enabled
	invalid.RetryWindow = time.Minute
	if err := service.SetConfig(invalid); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	if got := service.Config(); got != enabled {
		t.Fatalf("configuration after rejection = %+v, want %+v", got, enabled)
	}
}

func TestCheckDefersThenPassesWithoutSlidingInitialDelay(t *testing.T) {
	service, advance := testService(t)
	input := Triplet{RemoteIP: "192.0.2.44", EnvelopeFrom: "Sender@Example.NET", Recipient: "User@Example.COM"}
	first, err := service.Check(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Action != ActionDefer || first.RetryAfter != 5*time.Minute || first.Attempts != 1 || len(first.TripletID) != 16 {
		t.Fatalf("first decision = %+v", first)
	}
	advance(2 * time.Minute)
	early, err := service.Check(t.Context(), Triplet{RemoteIP: "192.0.2.199", EnvelopeFrom: "sender@example.net", Recipient: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if early.Action != ActionDefer || early.RetryAfter != 3*time.Minute || !early.FirstSeen.Equal(first.FirstSeen) || early.TripletID != first.TripletID {
		t.Fatalf("early decision = %+v", early)
	}
	advance(3 * time.Minute)
	passed, err := service.Check(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if passed.Action != ActionPass || passed.Attempts != 3 || passed.PassedAt.IsZero() {
		t.Fatalf("pass decision = %+v", passed)
	}
	advance(24 * time.Hour)
	known, err := service.Check(t.Context(), input)
	if err != nil || known.Action != ActionPass || !known.PassedAt.Equal(passed.PassedAt) {
		t.Fatalf("known decision = %+v, %v", known, err)
	}
	stats, err := service.Stats(t.Context())
	if err != nil || stats.Checks != 4 || stats.Deferred != 2 || stats.Passed != 2 || stats.StoredEntries != 1 {
		t.Fatalf("stats = %+v, %v", stats, err)
	}
}

func TestCheckResetsLateRetryAndExpiredPass(t *testing.T) {
	service, advance := testService(t)
	input := Triplet{RemoteIP: "2001:db8:1::10", EnvelopeFrom: "sender@example.net", Recipient: "user@example.com"}
	first, _ := service.Check(t.Context(), input)
	advance(4*time.Hour + time.Second)
	late, err := service.Check(t.Context(), input)
	if err != nil || late.Action != ActionDefer || !late.WindowReset || late.RetryAfter != 5*time.Minute || late.FirstSeen.Equal(first.FirstSeen) {
		t.Fatalf("late retry = %+v, %v", late, err)
	}
	advance(5 * time.Minute)
	passed, err := service.Check(t.Context(), Triplet{RemoteIP: "2001:db8:1:0:ffff::", EnvelopeFrom: input.EnvelopeFrom, Recipient: input.Recipient})
	if err != nil || passed.Action != ActionPass {
		t.Fatalf("IPv6-prefix retry = %+v, %v", passed, err)
	}
	advance(36*24*time.Hour + time.Second)
	expired, err := service.Check(t.Context(), input)
	if err != nil || expired.Action != ActionDefer || expired.Attempts != 1 {
		t.Fatalf("expired pass = %+v, %v", expired, err)
	}
	stats, _ := service.Stats(t.Context())
	if stats.WindowResets != 1 || stats.Expired != 1 || stats.StoredEntries != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestBypassDoesNotRequireOrStoreTriplet(t *testing.T) {
	service, _ := testService(t)
	decision, err := service.Check(t.Context(), Triplet{Bypass: true, BypassReason: "authenticated submission"})
	if err != nil || decision.Action != ActionBypass || decision.BypassReason != "authenticated submission" {
		t.Fatalf("bypass = %+v, %v", decision, err)
	}
	keys, err := service.store.Scan(t.Context(), model.NSGreylisting, tripletPrefix)
	if err != nil || len(keys) != 0 {
		t.Fatalf("triplet keys = %v, %v", keys, err)
	}
	stats, _ := service.Stats(t.Context())
	if stats.Checks != 1 || stats.Bypassed != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestExplicitAllowEntriesBypassFromImmutableSnapshot(t *testing.T) {
	service, advance := testService(t)
	now := service.now()
	entries := []AllowEntry{
		{Kind: AllowSourceCIDR, Value: "192.0.2.99/24", Comment: "trusted relay", CreatedBy: "admin"},
		{Kind: AllowSender, Value: "@Example.NET"},
		{Kind: AllowRecipient, Value: "special@EXAMPLE.COM", ExpiresAt: now.Add(time.Hour)},
	}
	for index := range entries {
		created, err := service.CreateAllow(t.Context(), entries[index])
		if err != nil {
			t.Fatal(err)
		}
		entries[index] = created
		if created.ID == "" || created.CreatedAt.IsZero() {
			t.Fatalf("created allow entry = %+v", created)
		}
	}
	if _, err := service.CreateAllow(t.Context(), AllowEntry{Kind: AllowSourceCIDR, Value: "192.0.2.0/24"}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate error = %v", err)
	}
	tests := []Triplet{
		{RemoteIP: "192.0.2.44", EnvelopeFrom: "other@outside.test", Recipient: "user@example.com"},
		{RemoteIP: "203.0.113.44", EnvelopeFrom: "person@example.net", Recipient: "user@example.com"},
		{RemoteIP: "203.0.113.44", EnvelopeFrom: "other@outside.test", Recipient: "special@example.com"},
	}
	for _, input := range tests {
		decision, err := service.Check(t.Context(), input)
		if err != nil || decision.Action != ActionBypass || !strings.Contains(decision.BypassReason, "allow_") {
			t.Fatalf("allow decision for %+v = %+v, %v", input, decision, err)
		}
	}
	listed, err := service.ListAllows(t.Context())
	if err != nil || len(listed) != 3 || listed[0].Kind != AllowRecipient || listed[1].Kind != AllowSender || listed[2].Kind != AllowSourceCIDR {
		t.Fatalf("listed entries = %+v, %v", listed, err)
	}
	advance(time.Hour + time.Second)
	decision, err := service.Check(t.Context(), tests[2])
	if err != nil || decision.Action != ActionDefer {
		t.Fatalf("expired recipient allow = %+v, %v", decision, err)
	}
	if err := service.DeleteAllow(t.Context(), entries[0].ID); err != nil {
		t.Fatal(err)
	}
	decision, err = service.Check(t.Context(), tests[0])
	if err != nil || decision.Action != ActionDefer {
		t.Fatalf("deleted source allow = %+v, %v", decision, err)
	}
}

func TestAllowEntryValidation(t *testing.T) {
	service, _ := testService(t)
	for _, candidate := range []AllowEntry{
		{Kind: "unknown", Value: "anything"},
		{Kind: AllowSourceCIDR, Value: "192.0.2.1"},
		{Kind: AllowSender, Value: "@invalid"},
		{Kind: AllowRecipient, Value: "not an address"},
		{Kind: AllowSender, Value: "a@example.net", ExpiresAt: service.now().Add(-time.Second)},
		{Kind: AllowSender, Value: "a@example.net", Comment: strings.Repeat("x", 513)},
	} {
		if _, err := service.CreateAllow(t.Context(), candidate); err == nil {
			t.Fatalf("invalid allow entry accepted: %+v", candidate)
		}
	}
	if err := service.DeleteAllow(t.Context(), "bad"); err == nil {
		t.Fatal("invalid allow ID accepted")
	}
}

func TestTripletKeysContainNoAddressMaterial(t *testing.T) {
	service, _ := testService(t)
	input := Triplet{RemoteIP: "203.0.113.9", EnvelopeFrom: "secret-sender@example.net", Recipient: "private-user@example.com"}
	if _, err := service.Check(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	keys, err := service.store.Scan(t.Context(), model.NSGreylisting, tripletPrefix)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %v, %v", keys, err)
	}
	key := keys[0]
	for _, secret := range []string{"203.0.113", "secret-sender", "private-user", "example"} {
		if strings.Contains(key, secret) {
			t.Fatalf("privacy-sensitive material %q appears in key %q", secret, key)
		}
	}
	data, err := service.store.Get(t.Context(), model.NSGreylisting, key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sender") || strings.Contains(string(data), "recipient") || strings.Contains(string(data), "203.0.113") {
		t.Fatalf("privacy-sensitive material appears in value %s", data)
	}
}

func TestCleanupIsBoundedAndCursorProgresses(t *testing.T) {
	service, advance := testService(t)
	for index := 1; index <= 5; index++ {
		input := Triplet{RemoteIP: fmt.Sprintf("198.51.100.%d", index), EnvelopeFrom: "sender@example.net", Recipient: fmt.Sprintf("user%d@example.com", index)}
		if _, err := service.Check(t.Context(), input); err != nil {
			t.Fatal(err)
		}
	}
	advance(24*time.Hour + time.Second)
	removed, err := service.Cleanup(t.Context(), 2)
	if err != nil || removed != 2 {
		t.Fatalf("first cleanup = %d, %v", removed, err)
	}
	removed, err = service.Cleanup(t.Context(), 2)
	if err != nil || removed != 2 {
		t.Fatalf("second cleanup = %d, %v", removed, err)
	}
	removed, err = service.Cleanup(t.Context(), 2)
	if err != nil || removed != 1 {
		t.Fatalf("third cleanup = %d, %v", removed, err)
	}
	stats, _ := service.Stats(t.Context())
	if stats.StoredEntries != 0 || stats.CleanupCursor != "" {
		t.Fatalf("stats after cleanup = %+v", stats)
	}
}

func TestStateAndStatisticsSurviveProductionBackendRestart(t *testing.T) {
	backends := map[string]func(string) (store.Store, error){
		"pebble": func(path string) (store.Store, error) { return pebblestore.New(path) },
		"badger": func(path string) (store.Store, error) { return badgerstore.New(path) },
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir()
			backend, err := open(path)
			if err != nil {
				t.Fatal(err)
			}
			config := DefaultConfig()
			config.Enabled = true
			service, err := New(t.Context(), backend, config)
			if err != nil {
				t.Fatal(err)
			}
			firstAt := time.Date(2026, time.August, 18, 8, 0, 0, 0, time.UTC)
			service.now = func() time.Time { return firstAt }
			input := Triplet{RemoteIP: "192.0.2.80", EnvelopeFrom: "sender@example.net", Recipient: "user@example.com"}
			if decision, err := service.Check(t.Context(), input); err != nil || decision.Action != ActionDefer {
				t.Fatalf("first check = %+v, %v", decision, err)
			}
			if err := backend.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			restarted, err := New(t.Context(), reopened, config)
			if err != nil {
				t.Fatal(err)
			}
			restarted.now = func() time.Time { return firstAt.Add(config.MinimumDelay) }
			decision, err := restarted.Check(t.Context(), input)
			if err != nil || decision.Action != ActionPass || !decision.FirstSeen.Equal(firstAt) {
				t.Fatalf("restart check = %+v, %v", decision, err)
			}
			stats, err := restarted.Stats(t.Context())
			if err != nil || stats.Checks != 2 || stats.Deferred != 1 || stats.Passed != 1 || stats.StoredEntries != 1 {
				t.Fatalf("restart stats = %+v, %v", stats, err)
			}
		})
	}
}

func TestConcurrentRetryCreatesOneTripletAndConsistentCounters(t *testing.T) {
	service, _ := testService(t)
	input := Triplet{RemoteIP: "192.0.2.20", EnvelopeFrom: "sender@example.net", Recipient: "user@example.com"}
	const workers = 20
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := service.Check(context.Background(), input)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	stats, err := service.Stats(t.Context())
	if err != nil || stats.Checks != workers || stats.Deferred != workers || stats.StoredEntries != 1 {
		t.Fatalf("stats = %+v, %v", stats, err)
	}
}

func TestCapacityIsBoundedAndFailsOpenExplicitly(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	config := DefaultConfig()
	config.Enabled = true
	config.MaxEntries = 100
	service, err := New(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 100 {
		input := Triplet{RemoteIP: fmt.Sprintf("198.51.100.%d", index%250+1), EnvelopeFrom: "sender@example.net", Recipient: fmt.Sprintf("user-%d@example.com", index)}
		if decision, err := service.Check(t.Context(), input); err != nil || decision.Action != ActionDefer {
			t.Fatalf("fill %d = %+v, %v", index, decision, err)
		}
	}
	decision, err := service.Check(t.Context(), Triplet{RemoteIP: "203.0.113.1", EnvelopeFrom: "sender@example.net", Recipient: "overflow@example.com"})
	if err != nil || decision.Action != ActionBypass || decision.BypassReason != "greylist capacity reached" {
		t.Fatalf("capacity decision = %+v, %v", decision, err)
	}
	stats, err := service.Stats(t.Context())
	if err != nil || stats.StoredEntries != 100 || stats.CapacityPass != 1 || stats.Bypassed != 1 {
		t.Fatalf("capacity stats = %+v, %v", stats, err)
	}
}

func TestDecisionAndCountersRollBackTogetherOnWriteFailure(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	faults := faultstore.New(backend)
	t.Cleanup(func() { _ = faults.Close() })
	config := DefaultConfig()
	config.Enabled = true
	service, err := New(t.Context(), faults, config)
	if err != nil {
		t.Fatal(err)
	}
	faults.Fail("set", 2)
	input := Triplet{RemoteIP: "192.0.2.10", EnvelopeFrom: "sender@example.net", Recipient: "user@example.com"}
	if _, err := service.Check(t.Context(), input); !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("check error = %v, want injected failure", err)
	}
	keys, err := faults.Scan(t.Context(), model.NSGreylisting, tripletPrefix)
	if err != nil || len(keys) != 0 {
		t.Fatalf("rolled-back keys = %v, %v", keys, err)
	}
	stats, err := service.Stats(t.Context())
	if err != nil || stats.Checks != 0 || stats.StoredEntries != 0 {
		t.Fatalf("rolled-back stats = %+v, %v", stats, err)
	}
}

func TestInputAndConfigurationValidation(t *testing.T) {
	config := DefaultConfig()
	config.MinimumDelay = 0
	if err := config.Validate(); err == nil {
		t.Fatal("invalid minimum delay accepted")
	}
	service, _ := testService(t)
	for _, input := range []Triplet{
		{RemoteIP: "not-an-ip", EnvelopeFrom: "a@example.net", Recipient: "b@example.com"},
		{RemoteIP: "192.0.2.1", EnvelopeFrom: "not an address", Recipient: "b@example.com"},
		{RemoteIP: "192.0.2.1", EnvelopeFrom: "a@example.net", Recipient: "not an address"},
	} {
		if _, err := service.Check(t.Context(), input); err == nil {
			t.Fatalf("invalid input accepted: %+v", input)
		}
	}
	config = DefaultConfig()
	config.AutoWhitelistLifetime = time.Hour
	if err := config.Validate(); err == nil {
		t.Fatal("auto-whitelist lifetime under one day accepted")
	}
	config.AutoWhitelistPasses = 0
	if err := config.Validate(); err != nil {
		t.Fatalf("disabled auto-whitelist rejected: %v", err)
	}
}

// passTriplet greylists input once and retries it after the minimum delay.
func passTriplet(t *testing.T, service *Service, advance func(time.Duration), input Triplet) {
	t.Helper()
	if decision, err := service.Check(t.Context(), input); err != nil || decision.Action != ActionDefer {
		t.Fatalf("first attempt = %+v, %v", decision, err)
	}
	advance(service.Config().MinimumDelay)
	if decision, err := service.Check(t.Context(), input); err != nil || decision.Action != ActionPass {
		t.Fatalf("retry = %+v, %v", decision, err)
	}
}

func TestAutoWhitelistAfterPassesSlidesAndExpires(t *testing.T) {
	service, advance := testService(t)
	for index := range 5 {
		passTriplet(t, service, advance, Triplet{RemoteIP: fmt.Sprintf("192.0.2.%d", index+1), EnvelopeFrom: "sender@example.net", Recipient: fmt.Sprintf("user%d@example.com", index)})
	}
	stranger := Triplet{RemoteIP: "192.0.2.200", EnvelopeFrom: "someone@else.example", Recipient: "new@example.com"}
	decision, err := service.Check(t.Context(), stranger)
	if err != nil || decision.Action != ActionBypass || decision.BypassReason != "auto-whitelisted client network" {
		t.Fatalf("whitelisted network = %+v, %v", decision, err)
	}
	if decision, _ := service.Check(t.Context(), Triplet{RemoteIP: "198.51.100.1", EnvelopeFrom: stranger.EnvelopeFrom, Recipient: stranger.Recipient}); decision.Action != ActionDefer {
		t.Fatalf("other network = %+v", decision)
	}
	// Each message extends the whitelisting beyond its first lifetime.
	for range 2 {
		advance(30 * 24 * time.Hour)
		if decision, _ := service.Check(t.Context(), stranger); decision.Action != ActionBypass {
			t.Fatalf("sliding whitelist = %+v", decision)
		}
	}
	stats, _ := service.Stats(t.Context())
	if stats.Promotions != 1 || stats.AutoWhitelisted != 3 || stats.StoredNetworks != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	advance(36*24*time.Hour + time.Second)
	if decision, _ := service.Check(t.Context(), stranger); decision.Action != ActionDefer {
		t.Fatalf("expired whitelist = %+v", decision)
	}
	if _, err := service.Cleanup(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	if stats, _ := service.Stats(t.Context()); stats.StoredNetworks != 0 {
		t.Fatalf("networks after cleanup = %+v", stats)
	}
}

func TestAutoWhitelistCountsPassesWithinPassLifetime(t *testing.T) {
	service, advance := testService(t)
	config := service.Config()
	config.AutoWhitelistPasses = 2
	if err := service.SetConfig(config); err != nil {
		t.Fatal(err)
	}
	passTriplet(t, service, advance, Triplet{RemoteIP: "192.0.2.1", EnvelopeFrom: "a@example.net", Recipient: "one@example.com"})
	advance(config.PassLifetime + time.Second)
	passTriplet(t, service, advance, Triplet{RemoteIP: "192.0.2.1", EnvelopeFrom: "a@example.net", Recipient: "two@example.com"})
	if decision, _ := service.Check(t.Context(), Triplet{RemoteIP: "192.0.2.1", EnvelopeFrom: "b@example.net", Recipient: "three@example.com"}); decision.Action != ActionDefer {
		t.Fatalf("passes outside the lifetime whitelisted the network: %+v", decision)
	}

	config.AutoWhitelistPasses = 0
	if err := service.SetConfig(config); err != nil {
		t.Fatal(err)
	}
	passTriplet(t, service, advance, Triplet{RemoteIP: "203.0.113.1", EnvelopeFrom: "a@example.net", Recipient: "one@example.com"})
	if keys, _ := service.store.Scan(t.Context(), model.NSGreylisting, networkPrefix); len(keys) != 1 {
		t.Fatalf("disabled auto-whitelisting tracked networks: %v", keys)
	}
}

func TestSPFPassSkipsGreylistingWhenEnabled(t *testing.T) {
	service, _ := testService(t)
	input := Triplet{RemoteIP: "192.0.2.10", EnvelopeFrom: "a@example.net", Recipient: "b@example.com", SPFPassDomain: "example.net"}
	if decision, _ := service.Check(t.Context(), input); decision.Action != ActionDefer {
		t.Fatalf("SPF pass skipped while disabled: %+v", decision)
	}
	config := service.Config()
	config.SkipSPFPass = true
	if err := service.SetConfig(config); err != nil {
		t.Fatal(err)
	}
	input.Recipient = "c@example.com"
	if decision, err := service.Check(t.Context(), input); err != nil || decision.Action != ActionBypass || decision.BypassReason != "sender domain passed SPF" {
		t.Fatalf("SPF pass = %+v, %v", decision, err)
	}
	input.SPFPassDomain = ""
	if decision, _ := service.Check(t.Context(), input); decision.Action != ActionDefer {
		t.Fatalf("no SPF pass = %+v", decision)
	}
	if stats, _ := service.Stats(t.Context()); stats.SPFBypassed != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestSPFPassKeysTripletOnSendingPool(t *testing.T) {
	service, advance := testService(t)
	first := Triplet{RemoteIP: "192.0.2.10", EnvelopeFrom: "a@example.net", Recipient: "b@example.com", SPFPassDomain: "example.net"}
	if decision, _ := service.Check(t.Context(), first); decision.Action != ActionDefer {
		t.Fatalf("first = %+v", decision)
	}
	advance(5 * time.Minute)
	pool := first
	pool.RemoteIP = "203.0.113.77"
	if decision, err := service.Check(t.Context(), pool); err != nil || decision.Action != ActionPass {
		t.Fatalf("retry from another pool address = %+v, %v", decision, err)
	}
	// Without SPF, or with SPF for another domain, the network is the key.
	unauthenticated := pool
	unauthenticated.Recipient, unauthenticated.SPFPassDomain = "c@example.com", ""
	if decision, _ := service.Check(t.Context(), unauthenticated); decision.Action != ActionDefer {
		t.Fatalf("unauthenticated = %+v", decision)
	}
	advance(5 * time.Minute)
	unauthenticated.RemoteIP, unauthenticated.SPFPassDomain = "198.51.100.1", "other.example"
	if decision, _ := service.Check(t.Context(), unauthenticated); decision.Action != ActionDefer {
		t.Fatalf("SPF for another domain = %+v", decision)
	}

	config := service.Config()
	config.SPFPoolTriplets = false
	if err := service.SetConfig(config); err != nil {
		t.Fatal(err)
	}
	direct := Triplet{RemoteIP: "192.0.2.10", EnvelopeFrom: "a@example.net", Recipient: "d@example.com", SPFPassDomain: "example.net"}
	passTriplet(t, service, advance, direct)
	direct.RemoteIP = "203.0.113.77"
	if decision, _ := service.Check(t.Context(), direct); decision.Action != ActionDefer {
		t.Fatalf("pool keying while disabled = %+v", decision)
	}
	// Enabling pool keying keeps passes earned by client network.
	config.SPFPoolTriplets = true
	if err := service.SetConfig(config); err != nil {
		t.Fatal(err)
	}
	direct.RemoteIP = "192.0.2.10"
	if decision, _ := service.Check(t.Context(), direct); decision.Action != ActionPass {
		t.Fatalf("network pass after enabling pool keying = %+v", decision)
	}
	direct.RemoteIP = "203.0.113.77"
	if decision, _ := service.Check(t.Context(), direct); decision.Action != ActionPass {
		t.Fatalf("pool retry after adoption = %+v", decision)
	}
}
