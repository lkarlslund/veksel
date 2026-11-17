package diagnostics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPprofServerExposesProfilesOnly(t *testing.T) {
	server := NewPprofServer("127.0.0.1:0")

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/goroutine", "/debug/pprof/heap"} {
		t.Run(strings.TrimPrefix(path, "/debug/pprof/"), func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", path, response.Code, http.StatusOK)
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("GET /health status = %d, want %d", response.Code, http.StatusNotFound)
	}
}
