package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/veksel/pkg/httpservice"
)

func TestSessionCookiesAreSecureOnlyForTrustedHTTPSProxy(t *testing.T) {
	handler, _ := testHandler(t)
	proxies, err := httpservice.NewTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureTrustedProxies(proxies)
	start := proxies.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ensureCSRF(w, r)
		if err := handler.startSession(w, r, "alice", "csrf-token"); err != nil {
			t.Fatal(err)
		}
	}))
	for _, tc := range []struct {
		remote string
		secure bool
	}{
		{remote: "198.51.100.7:4000", secure: false},
		{remote: "10.0.0.1:4000", secure: true},
	} {
		req := httptest.NewRequest(http.MethodPost, "http://veksel.internal/app/login", nil)
		req.RemoteAddr = tc.remote
		req.Header.Set("X-Forwarded-Proto", "https")
		recorder := httptest.NewRecorder()
		start.ServeHTTP(recorder, req)
		cookies := recorder.Result().Cookies()
		if len(cookies) != 2 {
			t.Fatalf("cookies = %v", cookies)
		}
		for _, cookie := range cookies {
			if cookie.Secure != tc.secure {
				t.Fatalf("peer %s: cookie %s Secure = %v, want %v", tc.remote, cookie.Name, cookie.Secure, tc.secure)
			}
		}
	}
}

func TestTrustedProxiesApplyLive(t *testing.T) {
	_, _, configuration, _, handler := managedTestApp(t)
	proxies, err := httpservice.NewTrustedProxies(nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureTrustedProxies(proxies)
	changes := map[string]any{"http_trusted_proxies": []any{"10.0.0.0/8"}}
	after, err := configuration.Patch(configuration.Current().Revision, changes)
	if err != nil {
		t.Fatal(err)
	}
	handler.applyManagedConfiguration(after, changes)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:4000"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := proxies.Resolve(req).IP; got != "203.0.113.9" {
		t.Fatalf("trusted proxies not applied live: client IP %q", got)
	}
}
