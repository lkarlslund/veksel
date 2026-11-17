package main

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/virus"
	webapp "github.com/lkarlslund/veksel/pkg/web/app"
)

func TestEveryAdjustableAppliesNewIntervalWithoutRestart(t *testing.T) {
	var calls atomic.Int64
	setInterval := everyAdjustable(withTestBackground(t, &server{}).background, time.Hour, func() { calls.Add(1) })
	setInterval(time.Hour)
	setInterval(5 * time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("shortened interval never fired: calls=%d", calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

// liveQuarantineServer opens the system store, the quarantine services and the
// digest scheduler against a temporary data directory.
func liveQuarantineServer(t *testing.T) *server {
	t.Helper()
	s := &server{}
	t.Cleanup(func() {
		s.cleanup.run(true)
	})
	if err := s.openRuntime(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	handler, err := webapp.New(s.ts)
	if err != nil {
		t.Fatal(err)
	}
	s.appHandler = handler
	if err := s.openQuarantine(); err != nil {
		t.Fatal(err)
	}
	if err := s.startQuarantineDigests(); err != nil {
		t.Fatal(err)
	}
	return s
}

func patchAndApply(t *testing.T, s *server, changes map[string]any) {
	t.Helper()
	snapshot, err := s.cfgService.Patch(s.cfgService.Current().Revision, changes)
	if err != nil {
		t.Fatal(err)
	}
	s.cfgService.Apply(snapshot, changes)
}

func applyState(t *testing.T, s *server, key string) config.SettingApplyStatus {
	t.Helper()
	for _, status := range s.cfgService.ApplyStates() {
		if status.Key == key {
			return status
		}
	}
	t.Fatalf("no apply state for %s", key)
	return config.SettingApplyStatus{}
}

func TestQuarantineSettingsApplyLive(t *testing.T) {
	s := liveQuarantineServer(t)
	patchAndApply(t, s, map[string]any{"quarantine_max_entries": 1, "quarantine_retention_days": 2, "quarantine_action_ttl_hours": 3})
	for _, key := range []string{"quarantine_max_entries", "quarantine_retention_days", "quarantine_action_ttl_hours"} {
		if status := applyState(t, s, key); status.State != config.ApplyEffective || status.RestartRequired {
			t.Fatalf("%s state = %+v", key, status)
		}
	}
	if _, err := s.quarantineStore.Add(t.Context(), &virus.QuarantineEntry{ID: "one", MessageData: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.quarantineStore.Add(t.Context(), &virus.QuarantineEntry{ID: "two", MessageData: []byte("b")}); !errors.Is(err, virus.ErrQuarantineCapacity) {
		t.Fatalf("admission beyond the live limit = %v", err)
	}
	status, err := s.quarantineStore.Status(t.Context())
	if err != nil || status.MaxEntries != 1 || status.RetentionSeconds != int64((48*time.Hour).Seconds()) {
		t.Fatalf("status = %+v, %v", status, err)
	}
	patchAndApply(t, s, map[string]any{"quarantine_max_entries": 10})
	if _, err := s.quarantineStore.Add(t.Context(), &virus.QuarantineEntry{ID: "two", MessageData: []byte("b")}); err != nil {
		t.Fatalf("admission after raising the limit: %v", err)
	}
}

func TestQuarantineDigestsEnableAndDisableLive(t *testing.T) {
	s := liveQuarantineServer(t)
	digestKeys := []string{"quarantine_digest_enabled", "quarantine_digest_base_url", "quarantine_digest_from", "quarantine_digest_poll_minutes"}
	patchAndApply(t, s, map[string]any{"quarantine_digest_enabled": true, "quarantine_digest_base_url": "https://mail.example.test", "quarantine_digest_from": "Veksel <postmaster@example.test>", "quarantine_digest_poll_minutes": 5})
	for _, key := range digestKeys {
		if status := applyState(t, s, key); status.State != config.ApplyEffective || status.RestartRequired {
			t.Fatalf("%s state = %+v", key, status)
		}
	}
	patchAndApply(t, s, map[string]any{"quarantine_digest_poll_minutes": 10, "quarantine_digest_max_entries": 20})
	if status := applyState(t, s, "quarantine_digest_poll_minutes"); status.State != config.ApplyEffective {
		t.Fatalf("poll interval state = %+v", status)
	}
	patchAndApply(t, s, map[string]any{"quarantine_digest_enabled": false})
	if status := applyState(t, s, "quarantine_digest_enabled"); status.State != config.ApplyEffective {
		t.Fatalf("disable state = %+v", status)
	}
}
