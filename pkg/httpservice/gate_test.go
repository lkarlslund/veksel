package httpservice

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServiceGateTogglesServicesWithoutRemounting(t *testing.T) {
	var gate ServiceGate
	handler := gate.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	paths := map[string]string{"jmap": "/jmap/api", "mcp": "/mcp", "ews": "/EWS/Exchange.asmx", "eas": "/Microsoft-Server-ActiveSync", "dav": "/dav/alice/"}
	status := func(path string) int {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		return recorder.Code
	}
	for service, path := range paths {
		if got := status(path); got != http.StatusOK {
			t.Fatalf("%s before any toggle = %d, want 200", service, got)
		}
		gate.Set(service, false)
		if got := status(path); got != http.StatusNotFound {
			t.Fatalf("%s disabled = %d, want 404", service, got)
		}
		if got := status("/app/"); got != http.StatusOK {
			t.Fatalf("web while %s disabled = %d, want 200", service, got)
		}
		gate.Set(service, true)
		if got := status(path); got != http.StatusOK {
			t.Fatalf("%s re-enabled = %d, want 200", service, got)
		}
	}
}
