package static

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	response := httptest.NewRecorder()
	http.StripPrefix("/static", Handler()).ServeHTTP(response, request)
	return response
}

func TestHandlerETagAnd304(t *testing.T) {
	first := get(t, "/static/css/app.css", nil)
	etag := first.Header().Get("ETag")
	if first.Code != 200 || etag == "" || first.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(first.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("unexpected response %d %v", first.Code, first.Header())
	}
	second := get(t, "/static/css/app.css", map[string]string{"If-None-Match": etag})
	if second.Code != http.StatusNotModified || second.Body.Len() != 0 {
		t.Fatalf("want 304, got %d with %d bytes", second.Code, second.Body.Len())
	}
	gz := get(t, "/static/css/app.css", map[string]string{"Accept-Encoding": "gzip"})
	again := get(t, "/static/css/app.css", map[string]string{"Accept-Encoding": "gzip", "If-None-Match": gz.Header().Get("ETag")})
	if again.Code != http.StatusNotModified {
		t.Fatalf("gzip etag revalidation: %d", again.Code)
	}
}

func TestHandlerImmutableOnlyForMatchingVersion(t *testing.T) {
	versioned := get(t, AssetURL("js/app.js"), nil)
	if got := versioned.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("matching version: %q", got)
	}
	for _, target := range []string{"/static/js/app.js", "/static/js/app.js?v=stale"} {
		if got := get(t, target, nil).Header().Get("Cache-Control"); got != "no-cache" {
			t.Fatalf("%s: %q", target, got)
		}
	}
	if get(t, "/static/js/missing.js", nil).Code != http.StatusNotFound {
		t.Fatal("missing asset must 404")
	}
}

func TestHandlerGzipRoundTrips(t *testing.T) {
	original, err := Content.ReadFile("js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	response := get(t, "/static/js/app.js", map[string]string{"Accept-Encoding": "br, gzip;q=0.8"})
	if response.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(response.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("headers %v", response.Header())
	}
	reader, err := gzip.NewReader(bytes.NewReader(response.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := io.ReadAll(reader)
	if !bytes.Equal(decoded, original) || response.Body.Len() >= len(original)/2 {
		t.Fatalf("decoded %d original %d compressed %d", len(decoded), len(original), response.Body.Len())
	}
	if plain := get(t, "/static/js/app.js", nil); plain.Header().Get("Content-Encoding") != "" || !bytes.Equal(plain.Body.Bytes(), original) {
		t.Fatal("identity response must be uncompressed original")
	}
	if refused := get(t, "/static/js/app.js", map[string]string{"Accept-Encoding": "gzip;q=0"}); refused.Header().Get("Content-Encoding") != "" {
		t.Fatal("q=0 must disable gzip")
	}
}

func TestHandlerDoesNotCompressWoff2(t *testing.T) {
	response := get(t, "/static/fonts/inter-var.woff2", map[string]string{"Accept-Encoding": "gzip"})
	if response.Code != 200 || response.Header().Get("Content-Encoding") != "" || response.Header().Get("Content-Type") != "font/woff2" {
		t.Fatalf("%d %v", response.Code, response.Header())
	}
}
