package autodiscover

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// RFC 6764: DAV clients given only a host name (vdirsyncer, DAVx5, Apple,
// Thunderbird) request /.well-known/caldav and /.well-known/carddav first.
func TestWellKnownDAVRedirectsToServiceRoot(t *testing.T) {
	ts := testStoreSetup(t)
	h := testHandler(t, ts)
	for _, path := range []string{"/.well-known/caldav", "/.well-known/carddav"} {
		for _, method := range []string{http.MethodGet, "PROPFIND"} {
			r := httptest.NewRequest(method, path, nil)
			w := httptest.NewRecorder()
			h.Handle(w, r)
			if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/dav/" {
				t.Fatalf("%s %s: status %d location %q", method, path, w.Code, w.Header().Get("Location"))
			}
		}
	}
}
