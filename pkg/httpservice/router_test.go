package httpservice

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
)

func TestServiceForPath(t *testing.T) {
	tests := map[string]string{
		"/app": "web", "/api/v1/session": "web", "/dav/user/calendar": "dav",
		"/.well-known/jmap": "jmap", "/jmap/api": "jmap", "/mcp": "mcp", "/mcp/session": "mcp", "/EWS/Exchange.asmx": "ews",
		"/Microsoft-Server-ActiveSync": "eas", "/autodiscover/autodiscover.xml": "autodiscover",
		"/.well-known/caldav": "autodiscover",
	}
	for path, want := range tests {
		if got := ServiceForPath(path); got != want {
			t.Errorf("ServiceForPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestHandlerRejectsUnboundService(t *testing.T) {
	handler := Handler(config.HTTPListener{ID: "test", Services: []string{"eas"}}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for path, want := range map[string]int{"/Microsoft-Server-ActiveSync": http.StatusNoContent, "/app": http.StatusNotFound, "/mcp": http.StatusNotFound, "/EWS/Exchange.asmx": http.StatusNotFound} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != want {
			t.Errorf("%s status = %d, want %d", path, response.Code, want)
		}
	}
}

func TestHandlerEmitsConfiguredHSTSOnlyForHTTPSClients(t *testing.T) {
	days := 365
	listener := config.HTTPListener{
		ID: "secure", Transport: config.HTTPSTransport, Services: []string{"web"},
		HSTSMaxAgeDays: &days, HSTSIncludeSubdomains: true, HSTSPreload: true,
	}
	handler := Handler(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, path := range []string{"/app", "/mcp"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		handler.ServeHTTP(response, request)
		if got, want := response.Header().Get("Strict-Transport-Security"), "max-age=31536000; includeSubDomains; preload"; got != want {
			t.Errorf("%s HSTS = %q, want %q", path, got, want)
		}
	}

	clear := listener
	clear.Transport = config.HTTPTransport
	clear.HSTSMaxAgeDays, clear.HSTSIncludeSubdomains, clear.HSTSPreload = nil, false, false
	handler = Handler(clear, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodGet, "/app", nil)
	request.Header.Set("Forwarded", "proto=https")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("clear HTTP listener trusted forwarded HTTPS and emitted HSTS %q", got)
	}

	proxied := listener
	proxied.Transport = config.HTTPTransport
	proxies, err := NewTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	handler = proxies.Handler(Handler(proxied, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	for _, tc := range []struct {
		name, remote, header, value, want string
	}{
		{name: "client Forwarded https through an X-Forwarded proxy", remote: "10.0.0.5:9000", header: "Forwarded", value: "for=203.0.113.9;proto=https"},
		{name: "trusted X-Forwarded-Proto https", remote: "10.0.0.5:9000", header: "X-Forwarded-Proto", value: "https", want: "max-age=31536000; includeSubDomains; preload"},
		{name: "trusted proxy reports http", remote: "10.0.0.5:9000", header: "X-Forwarded-Proto", value: "http"},
		{name: "plain http", remote: "10.0.0.5:9000"},
		{name: "untrusted peer claims https", remote: "198.51.100.7:4321", header: "Forwarded", value: "proto=https"},
	} {
		request := httptest.NewRequest(http.MethodGet, "/app", nil)
		request.RemoteAddr = tc.remote
		if tc.header != "" {
			request.Header.Set(tc.header, tc.value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if got := response.Header().Get("Strict-Transport-Security"); got != tc.want {
			t.Errorf("%s: HSTS = %q, want %q", tc.name, got, tc.want)
		}
	}

	zero := 0
	listener.HSTSMaxAgeDays, listener.HSTSIncludeSubdomains, listener.HSTSPreload = &zero, false, false
	response = httptest.NewRecorder()
	Handler(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/app", nil))
	if got := response.Header().Get("Strict-Transport-Security"); got != "max-age=0" {
		t.Fatalf("HSTS removal header = %q, want max-age=0", got)
	}
}
