package httpservice

import (
	"net/http"
	"strings"
	"time"
)

// Timeouts bounds how long clients may hold shared HTTP(S) listener
// connections. Header reading and keep-alive idling are bounded per
// connection; request bodies and responses get a per-request deadline so
// uploads, downloads and long-polls can outlive ordinary requests without a
// blanket server-wide ReadTimeout or WriteTimeout.
type Timeouts struct {
	// ReadHeader bounds reading the request line and headers.
	ReadHeader time.Duration
	// Idle bounds waiting for the next request on a keep-alive connection.
	Idle time.Duration
	// Request is the read and write deadline of an ordinary request.
	Request time.Duration
	// LongRunning is the read and write deadline of transfers and
	// long-polls classified by LongRunning.
	LongRunning time.Duration
	// MaxHeaderBytes caps the request line and headers.
	MaxHeaderBytes int
}

// DefaultTimeouts are the production limits for shared HTTP(S) listeners.
// LongRunning exceeds the 3540 second ActiveSync heartbeat ceiling.
var DefaultTimeouts = Timeouts{
	ReadHeader:     10 * time.Second,
	Idle:           2 * time.Minute,
	Request:        2 * time.Minute,
	LongRunning:    time.Hour,
	MaxHeaderBytes: 64 << 10,
}

// NewServer returns a server for handler bounded by timeouts.
func NewServer(addr string, handler http.Handler, timeouts Timeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           Deadlines(timeouts, handler),
		ReadHeaderTimeout: timeouts.ReadHeader,
		IdleTimeout:       timeouts.Idle,
		MaxHeaderBytes:    timeouts.MaxHeaderBytes,
	}
}

// Deadlines applies the per-request read and write deadline from timeouts.
// It must wrap the server's own ResponseWriter (or one that unwraps to it).
// Both deadlines are set together: once a request body is consumed the
// server reads in the background, and an expired read deadline cancels the
// request context.
func Deadlines(timeouts Timeouts, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := timeouts.Request
		if LongRunning(r) {
			limit = timeouts.LongRunning
		}
		if limit > 0 {
			deadline := time.Now().Add(limit)
			controller := http.NewResponseController(w)
			_ = controller.SetReadDeadline(deadline)
			_ = controller.SetWriteDeadline(deadline)
		}
		next.ServeHTTP(w, r)
	})
}

// longRunningAPISegments name /api/ path segments that stream bulk data or
// hold the request open: exports, imports, backups, attachments, file and
// draft uploads, and the event stream.
var longRunningAPISegments = map[string]struct{}{
	"attachments": {}, "backup": {}, "download": {}, "drafts": {}, "events": {}, "export": {},
	"files": {}, "import": {}, "restore": {}, "support-bundle": {},
}

// LongRunning reports whether r may legitimately outlast an ordinary request:
// protocol services that upload, download or long-poll (WebDAV, JMAP, EWS,
// ActiveSync, MCP) and bulk-transfer or streaming REST endpoints.
func LongRunning(r *http.Request) bool {
	switch ServiceForPath(r.URL.Path) {
	case "dav", "jmap", "ews", "eas", "mcp":
		return true
	}
	path := strings.ToLower(r.URL.Path)
	if !strings.HasPrefix(path, "/api/") {
		return false
	}
	for segment := range strings.SplitSeq(path, "/") {
		if _, ok := longRunningAPISegments[segment]; ok {
			return true
		}
	}
	return false
}
