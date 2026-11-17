package main

import (
	"io"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/certificates"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/httpservice"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func freeTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func testHTTPListener(id, address string) config.HTTPListener {
	return config.HTTPListener{ID: id, Name: id, Enabled: true, Transport: config.HTTPTransport, Address: address, LogLevel: "inherit", Services: config.HTTPServices}
}

// newLiveHTTPServer runs the HTTP phases against a managed configuration
// on loopback listeners, with stub service handlers on the shared mux.
func newLiveHTTPServer(t *testing.T) *server {
	t.Helper()
	cfgService, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cfgService.Patch(cfgService.Current().Revision, map[string]any{"http_listeners": []config.HTTPListener{testHTTPListener("default-http", freeTestAddress(t))}})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	s := withTestBackground(t, &server{mux: http.NewServeMux(), cfgService: cfgService, cfg: snapshot.Config, met: metrics.New(backend)})
	s.ts = model.NewTypedStore(backend, s.cfg.StoreBackend)
	if s.certificates, err = certificates.New(s.ts, nil); err != nil {
		t.Fatal(err)
	}
	if s.trustedProxies, err = httpservice.NewTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	s.applyHTTPServiceState(s.cfg)
	s.mux.Handle("GET /metrics", s.met.ScrapeHandler(func() string { return *s.metricsToken.Load() }))
	for _, path := range []string{"/jmap/api", "/mcp", "/EWS/Exchange.asmx", "/Microsoft-Server-ActiveSync", "/dav/"} {
		s.mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	}
	s.registerAutodiscover()
	if err := s.registerHTTPLiveSettings(); err != nil {
		t.Fatal(err)
	}
	if err := s.bindHTTPListeners(); err != nil {
		t.Fatal(err)
	}
	s.pprofListener.Serve()
	s.httpListeners.Serve()
	t.Cleanup(s.httpListeners.Close)
	t.Cleanup(s.pprofListener.Close)
	return s
}

// patchLive persists changes and applies them the way the admin API does.
func patchLive(t *testing.T, s *server, changes map[string]any) {
	t.Helper()
	snapshot, err := s.cfgService.Patch(s.cfgService.Current().Revision, changes)
	if err != nil {
		t.Fatal(err)
	}
	s.cfgService.Apply(snapshot, changes)
}

func liveGet(t *testing.T, address, path, token string) (int, error) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "http://"+address+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	_ = response.Body.Close()
	return response.StatusCode, nil
}

func TestHTTPSettingsApplyWithoutRestart(t *testing.T) {
	s := newLiveHTTPServer(t)
	unapplied := s.cfgService.UnappliedKeys()
	for _, key := range []string{"http_listeners", "listen_addr", "https_enabled", "https_listen", "https_certificate", "pprof_listen", "metrics_token",
		"dav_enabled", "jmap_enabled", "mcp_enabled", "ews_enabled", "eas_enabled", "webdav_max_file_size",
		"acme_enabled", "acme_accept_tos", "acme_email", "acme_domains", "acme_http_listen", "acme_directory_url", "acme_challenge", "acme_dns_propagation_seconds"} {
		if slices.Contains(unapplied, key) {
			t.Errorf("%s still requires a restart", key)
		}
	}
	address := s.httpListeners.Addrs()["default-http"]
	status := func(path, token string) int {
		t.Helper()
		code, err := liveGet(t, address, path, token)
		if err != nil {
			t.Fatal(err)
		}
		return code
	}

	t.Run("service toggles", func(t *testing.T) {
		for _, toggle := range httpServiceToggles() {
			path := map[string]string{"dav": "/dav/x", "jmap": "/jmap/api", "mcp": "/mcp", "ews": "/EWS/Exchange.asmx", "eas": "/Microsoft-Server-ActiveSync"}[toggle.service]
			patchLive(t, s, map[string]any{toggle.key: false})
			if got := status(path, ""); got != http.StatusNotFound {
				t.Fatalf("%s disabled = %d, want 404", toggle.key, got)
			}
			patchLive(t, s, map[string]any{toggle.key: true})
			if !toggle.compiled {
				if state := applyState(t, s, toggle.key); state.State != config.ApplyFailed || state.Error == "" {
					t.Fatalf("enabling compiled-out %s: %#v", toggle.key, state)
				}
				continue
			}
			if got := status(path, ""); got != http.StatusOK {
				t.Fatalf("%s enabled = %d, want 200", toggle.key, got)
			}
		}
	})

	t.Run("metrics token", func(t *testing.T) {
		const first, second = "first-metrics-token-0123", "second-metrics-token-0123"
		patchLive(t, s, map[string]any{"metrics_token": first})
		if got := status("/metrics", first); got != http.StatusOK {
			t.Fatalf("scrape with token = %d", got)
		}
		patchLive(t, s, map[string]any{"metrics_token": second})
		if got := status("/metrics", first); got != http.StatusUnauthorized {
			t.Fatalf("scrape with rotated-out token = %d", got)
		}
		if got := status("/metrics", second); got != http.StatusOK {
			t.Fatalf("scrape with new token = %d", got)
		}
	})

	t.Run("http listeners", func(t *testing.T) {
		extraAddress := freeTestAddress(t)
		listeners := append(s.cfgService.Current().Config.HTTPListeners, testHTTPListener("extra", extraAddress))
		patchLive(t, s, map[string]any{"http_listeners": listeners})
		if code, err := liveGet(t, extraAddress, "/jmap/api", ""); err != nil || code != http.StatusOK {
			t.Fatalf("added listener: code=%d err=%v", code, err)
		}
		patchLive(t, s, map[string]any{"http_listeners": listeners[:1]})
		for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if _, err := liveGet(t, extraAddress, "/jmap/api", ""); err != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("removed listener still serving")
			}
		}
		if got := status("/jmap/api", ""); got != http.StatusOK {
			t.Fatalf("remaining listener = %d", got)
		}
	})

	t.Run("pprof listener", func(t *testing.T) {
		pprofAddress := freeTestAddress(t)
		patchLive(t, s, map[string]any{"pprof_listen": pprofAddress})
		if code, err := liveGet(t, pprofAddress, "/debug/pprof/", ""); err != nil || code != http.StatusOK {
			t.Fatalf("pprof started live: code=%d err=%v", code, err)
		}
		patchLive(t, s, map[string]any{"pprof_listen": ""})
		if addrs := s.pprofListener.Addrs(); len(addrs) != 0 {
			t.Fatalf("pprof still running on %v", addrs)
		}
	})

	t.Run("acme", func(t *testing.T) {
		challengeAddress := freeTestAddress(t)
		if err := s.certificates.StartHTTPChallenge(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.certificates.Close)
		patchLive(t, s, map[string]any{"acme_enabled": true, "acme_accept_tos": true, "acme_domains": "mail.example.test", "acme_http_listen": challengeAddress})
		if got := s.certificates.ChallengeAddr(); got != challengeAddress {
			t.Fatalf("HTTP-01 listener = %q, want %q", got, challengeAddress)
		}
		patchLive(t, s, map[string]any{"acme_domains": "mail.example.test, *.example.test", "acme_challenge": "auto, mail.example.test=http-01", "acme_dns_propagation_seconds": 60})
		if _, err := s.certificates.TLSConfig(t.Context(), "acme:*.example.test", "", ""); err != nil {
			t.Fatalf("wildcard DNS-01 certificate not available after a live change: %v", err)
		}
		if _, err := s.cfgService.Patch(s.cfgService.Current().Revision, map[string]any{"acme_challenge": "http-01"}); err == nil {
			t.Fatal("a wildcard was accepted with the http-01 challenge")
		}
		patchLive(t, s, map[string]any{"acme_enabled": false})
		if got := s.certificates.ChallengeAddr(); got != "" {
			t.Fatalf("HTTP-01 listener still on %q", got)
		}
	})
}
