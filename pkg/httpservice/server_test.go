package httpservice

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLongRunningClassification(t *testing.T) {
	tests := map[string]bool{
		"/dav/files/alice/big.bin":                         true,
		"/jmap/eventsource":                                true,
		"/Microsoft-Server-ActiveSync":                     true,
		"/ews/exchange.asmx":                               true,
		"/api/v1/events":                                   true,
		"/api/v1/admin/backup/download":                    true,
		"/api/v1/workspace/files/report.pdf":               true,
		"/api/v1/workspace/mail/messages/1/attachments/2":  true,
		"/api/v1/export/messages":                          true,
		"/api/v1/workspace/mail/messages":                  false,
		"/app/mail":                                        false,
		"/health":                                          false,
		"/static/js/app.js":                                false,
		"/api/v1/admin/backup-schedule-but-not-a-segment/": false,
	}
	for path, want := range tests {
		if got := LongRunning(httptest.NewRequest(http.MethodGet, path, nil)); got != want {
			t.Errorf("LongRunning(%q) = %v, want %v", path, got, want)
		}
	}
}

// streamFor writes a chunk every 20ms for total, flushing each one.
func streamFor(total time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		for end := time.Now().Add(total); time.Now().Before(end); {
			if _, err := io.WriteString(w, "chunk\n"); err != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
		_, _ = io.WriteString(w, "done\n")
	}
}

func startTimeoutServer(t *testing.T, timeouts Timeouts, handler http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(listener.Addr().String(), handler, timeouts)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "http://" + listener.Addr().String()
}

func TestLongRunningRequestsOutliveOrdinaryRequestDeadline(t *testing.T) {
	timeouts := Timeouts{ReadHeader: time.Second, Idle: time.Second, Request: 100 * time.Millisecond, LongRunning: 5 * time.Second, MaxHeaderBytes: 4 << 10}
	mux := http.NewServeMux()
	mux.Handle("/dav/", streamFor(400*time.Millisecond))
	mux.Handle("/app/", streamFor(400*time.Millisecond))
	base := startTimeoutServer(t, timeouts, mux)

	response, err := http.Get(base + "/dav/stream")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || !strings.HasSuffix(string(body), "done\n") {
		t.Fatalf("long-running stream cut short: %q, %v", body, err)
	}

	response, err = http.Get(base + "/app/stream")
	if err == nil {
		body, err = io.ReadAll(response.Body)
		_ = response.Body.Close()
	}
	if err == nil && strings.HasSuffix(string(body), "done\n") {
		t.Fatal("ordinary request outlived its deadline")
	}
}

func TestServerRejectsOversizedHeaders(t *testing.T) {
	timeouts := DefaultTimeouts
	timeouts.MaxHeaderBytes = 1 << 10
	base := startTimeoutServer(t, timeouts, http.NotFoundHandler())
	request, _ := http.NewRequest(http.MethodGet, base+"/", nil)
	request.Header.Set("X-Padding", strings.Repeat("a", 8<<10))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", response.StatusCode)
	}
}

func TestServerClosesSlowHeaderClients(t *testing.T) {
	timeouts := DefaultTimeouts
	timeouts.ReadHeader = 100 * time.Millisecond
	base := startTimeoutServer(t, timeouts, http.NotFoundHandler())
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("server kept a slow header client open: %v", err)
	}
}
