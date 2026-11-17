package app

import (
	"net/http"
	"strconv"

	"github.com/lkarlslund/veksel/pkg/spam"
)

const (
	defaultReputationListLimit = 25
	maxReputationListLimit     = 500
)

// SpamReputation is the server-wide sender reputation.
type SpamReputation interface {
	Report(limit int) spam.ReputationReport
	Reset()
	Released(headers map[string]string)
}

// ConfigureSpamReputation installs the sender reputation, which learns from
// quarantine releases and is listed for administrators.
func (h *Handler) ConfigureSpamReputation(reputation SpamReputation) {
	h.spamReputation = reputation
}

// apiAdminSpamReputation lists the authenticated sending domains and
// networks with the best and worst standing, with their decayed counts;
// DELETE forgets every sender first. The optional limit bounds each list.
func (h *Handler) apiAdminSpamReputation(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.spamReputation == nil {
		jsonError(w, http.StatusServiceUnavailable, "sender reputation is unavailable")
		return
	}
	limit := defaultReputationListLimit
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > maxReputationListLimit {
			jsonError(w, http.StatusBadRequest, "limit must be between 1 and "+strconv.Itoa(maxReputationListLimit))
			return
		}
		limit = parsed
	}
	if r.Method == http.MethodDelete {
		h.spamReputation.Reset()
		h.audit.Log(currentActor(r).ID, "admin.spam_reputation.reset", "", nil)
	}
	jsonResponse(w, http.StatusOK, h.spamReputation.Report(limit))
}
