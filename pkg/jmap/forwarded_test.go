package jmap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/veksel/pkg/httpservice"
)

func TestSessionURLsHonourForwardedOriginOnlyFromTrustedProxy(t *testing.T) {
	f := newFixture(t)
	mux := http.NewServeMux()
	f.handler.Register(mux)
	proxies, err := httpservice.NewTrustedProxies([]string{"10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	handler := proxies.Handler(mux)
	for _, tc := range []struct{ remote, want string }{
		{remote: "198.51.100.7:4000", want: "http://veksel.internal:8472/jmap/api"},
		{remote: "10.0.0.1:4000", want: "https://mail.example.com/jmap/api"},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://veksel.internal:8472/.well-known/jmap", nil)
		req.RemoteAddr = tc.remote
		req.SetBasicAuth("alice", "password")
		req.Header.Set("X-Forwarded-Host", "mail.example.com")
		req.Header.Set("X-Forwarded-Proto", "https")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		var session map[string]any
		if err := json.NewDecoder(recorder.Body).Decode(&session); err != nil {
			t.Fatalf("status=%d: %v", recorder.Code, err)
		}
		if session["apiUrl"] != tc.want {
			t.Fatalf("peer %s: apiUrl = %v, want %s", tc.remote, session["apiUrl"], tc.want)
		}
	}
}
