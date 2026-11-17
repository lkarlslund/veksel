package main

import (
	"net/http"
	"slices"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
)

// TestEverySettingAppliesLiveAfterStartup runs the real startup phases on a
// temporary data directory with loopback listeners and requires every
// managed setting to have a live applier. system_engine is the one exception:
// the configuration service refuses to change it, and the offline
// veksel-store-migrate tool moves the system store between engines.
//
// A new setting fails this test until its runtime owner registers an
// applier with the configuration service.
func TestEverySettingAppliesLiveAfterStartup(t *testing.T) {
	s := startLoopbackServer(t)
	if unapplied := s.cfgService.UnappliedKeys(); !slices.Equal(unapplied, []string{"system_engine"}) {
		t.Fatalf("settings without a live applier = %q, want only system_engine", unapplied)
	}
	for _, status := range s.cfgService.ApplyStates() {
		if status.RestartRequired != (status.Key == "system_engine") {
			t.Errorf("%s restart_required = %t", status.Key, status.RestartRequired)
		}
	}
}

// startLoopbackServer runs the real startup phases on a temporary data
// directory with loopback listeners.
func startLoopbackServer(t *testing.T) *server {
	t.Helper()
	dataDir := t.TempDir()
	cfgService, err := config.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfgService.Patch(cfgService.Current().Revision, map[string]any{
		"http_listeners":          []config.HTTPListener{testHTTPListener("default-http", freeTestAddress(t))},
		"smtp_listen":             freeAddress(t),
		"smtp_submission_enabled": false,
		"imap_listen":             freeAddress(t),
		"imap_tls_enabled":        false,
		"pop3_listen":             freeAddress(t),
		"pop3_tls_enabled":        false,
	}); err != nil {
		t.Fatal(err)
	}

	s := &server{mux: http.NewServeMux()}
	started := false
	t.Cleanup(func() {
		if started {
			s.shutdown()
		}
		s.cleanup.run(!s.drained)
	})
	for _, phase := range s.startupPhases(dataDir) {
		if err := phase.run(); err != nil {
			t.Fatal(err)
		}
	}
	started = true
	return s
}
