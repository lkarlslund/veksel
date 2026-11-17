package app

import (
	"context"
	"net/http"
	"net/netip"

	"github.com/lkarlslund/veksel/pkg/bayes"
	"github.com/lkarlslund/veksel/pkg/contentscan"
	"github.com/lkarlslund/veksel/pkg/spam"
)

type contentScannerStatusResponse struct {
	Enabled bool                       `json:"enabled"`
	Engines []contentscan.EngineStatus `json:"engines"`
}

func (h *Handler) apiAdminContentScanners(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	response := contentScannerStatusResponse{Enabled: h.cfg != nil && h.cfg.VirusScanEnabled, Engines: []contentscan.EngineStatus{}}
	if h.contentScanning != nil {
		if engines := h.contentScanning.Status(); engines != nil {
			response.Engines = engines
		}
	}
	jsonResponse(w, http.StatusOK, response)
}

// SpamFiltering is the live built-in spam engine used by SMTP.
type SpamFiltering interface {
	Thresholds() (spam.Thresholds, bool)
}

// SpamBlocklists is the shared blocklist lookup layer and its zone health.
type SpamBlocklists interface {
	Stats() []spam.ZoneStats
	CacheLen() int
	CheckAddress(context.Context, netip.Addr, []spam.Zone) []spam.Listing
}

// ConfigureSpamFiltering installs the live spam engine and blocklist layer.
func (h *Handler) ConfigureSpamFiltering(filtering SpamFiltering, blocklists SpamBlocklists) {
	h.spamFiltering, h.spamBlocklists = filtering, blocklists
}

type spamFilteringResponse struct {
	Enabled      bool             `json:"enabled"`
	Thresholds   spam.Thresholds  `json:"thresholds"`
	CacheEntries int              `json:"cache_entries"`
	Zones        []spam.ZoneStats `json:"zones"`
	// Classifier is the statistical classifier's settings, shared model,
	// and training counters; absent when it is unavailable.
	Classifier *bayes.Status `json:"classifier,omitempty"`
}

// apiAdminSpamFiltering reports the active thresholds, per-zone blocklist
// counters, last errors, and resolver refusals, and the classifier status.
func (h *Handler) apiAdminSpamFiltering(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	response := spamFilteringResponse{Zones: []spam.ZoneStats{}}
	if h.spamFiltering != nil {
		response.Thresholds, response.Enabled = h.spamFiltering.Thresholds()
	}
	if h.spamBlocklists != nil {
		response.CacheEntries = h.spamBlocklists.CacheLen()
		if zones := h.spamBlocklists.Stats(); len(zones) > 0 {
			response.Zones = zones
		}
	}
	if h.spamClassifier != nil {
		status, err := h.spamClassifier.Status(r.Context())
		if err != nil {
			apiError(w, err)
			return
		}
		response.Classifier = &status
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminTestContentScanners(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.contentScanning == nil || len(h.contentScanning.Status()) == 0 {
		jsonError(w, http.StatusServiceUnavailable, "content scanner pipeline is unavailable")
		return
	}
	message := []byte("From: scanner-test@localhost\r\nTo: scanner-test@localhost\r\nSubject: Veksel content scanner test\r\n\r\nThis is a safe scanner connectivity test.\r\n")
	report := h.contentScanning.Scan(r.Context(), contentscan.Message{
		Content: message, Headers: map[string]string{"From": "scanner-test@localhost", "To": "scanner-test@localhost", "Subject": "Veksel content scanner test"},
		EnvelopeFrom: "scanner-test@localhost", Recipient: "scanner-test@localhost",
	})
	h.audit.Log(currentActor(r).ID, "content_scanner.test", "content-scanning", map[string]string{"decision": report.Decision.String()})
	jsonResponse(w, http.StatusOK, report)
}
