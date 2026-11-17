package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The sign-in page and the application shell must not be framable and must
// run only their own scripts.
func TestRenderedPagesCarrySecurityHeaders(t *testing.T) {
	h, _ := testHandler(t)
	mux := http.NewServeMux()
	h.Register(mux)
	checked := 0
	for _, path := range []string{"/app/login", "/app/setup"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			continue // the other page redirects here before setup completes
		}
		checked++
		policy := response.Header().Get("Content-Security-Policy")
		if !strings.Contains(policy, "script-src 'self'") || !strings.Contains(policy, "frame-ancestors 'none'") || strings.Contains(policy, "unsafe-eval") {
			t.Errorf("%s CSP = %q", path, policy)
		}
		if response.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s X-Frame-Options = %q", path, response.Header().Get("X-Frame-Options"))
		}
	}
	if checked == 0 {
		t.Fatal("no page rendered")
	}
}
