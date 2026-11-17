package autodiscover

import (
	"net"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/httpservice"
)

// handleMTASTS serves the MTA-STS policy of the domain whose mta-sts host
// the request names (RFC 8461 section 3.3). Senders fetch it over HTTPS with
// a valid certificate for that host, which the TLS front end provides.
func (h *Handler) handleMTASTS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	host := httpservice.RequestClient(r).Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if h.cfg.MTASTSPolicy == nil {
		http.NotFound(w, r)
		return
	}
	policy, ok := h.cfg.MTASTSPolicy(r.Context(), host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=300")
	_, _ = w.Write([]byte(policy))
}
