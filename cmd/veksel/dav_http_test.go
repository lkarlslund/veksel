package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/caldav"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// Discovery as python caldav, Thunderbird, iOS, and Evolution perform it
// when given only the server URL: PROPFIND on "/" was answered 405 by the
// web application, OPTIONS without credentials got 401 instead of the DAV
// capabilities, and the Basic challenge did not announce UTF-8.
func TestDAVEntryDiscovery(t *testing.T) {
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendPebble)
	s := &server{mux: http.NewServeMux(), met: metrics.New(backend), ts: ts, dav: caldav.New(ts, nil)}
	s.mux.Handle("/dav/", http.HandlerFunc(s.serveDAV))
	s.mux.HandleFunc("PROPFIND /{$}", redirectToDAVRoot)

	do := func(method, path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		s.mux.ServeHTTP(recorder, httptest.NewRequest(method, path, strings.NewReader("")))
		return recorder
	}
	if reply := do("PROPFIND", "/"); reply.Code != http.StatusMovedPermanently || reply.Header().Get("Location") != "/dav/" {
		t.Fatalf("PROPFIND / = %d Location %q", reply.Code, reply.Header().Get("Location"))
	}
	options := do(http.MethodOptions, "/dav/")
	if options.Code != http.StatusOK || !strings.Contains(options.Header().Get("DAV"), "calendar-access") || !strings.Contains(options.Header().Get("Allow"), "MKCALENDAR") {
		t.Fatalf("unauthenticated OPTIONS = %d DAV %q Allow %q", options.Code, options.Header().Get("DAV"), options.Header().Get("Allow"))
	}
	propfind := do("PROPFIND", "/dav/")
	if propfind.Code != http.StatusUnauthorized || !strings.Contains(propfind.Header().Get("WWW-Authenticate"), `charset="UTF-8"`) {
		t.Fatalf("unauthenticated PROPFIND = %d challenge %q", propfind.Code, propfind.Header().Get("WWW-Authenticate"))
	}
}
