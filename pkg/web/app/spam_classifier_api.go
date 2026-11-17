package app

import (
	"context"
	"net/http"

	"github.com/lkarlslund/veksel/pkg/bayes"
)

// SpamClassifier is the statistical spam classifier: per-account models
// and the optional shared model.
type SpamClassifier interface {
	Stats(context.Context, string) (bayes.Stats, error)
	Reset(context.Context, string) error
	Status(context.Context) (bayes.Status, error)
	ResetGlobal(context.Context) error
}

// ConfigureSpamClassifier installs the statistical spam classifier.
func (h *Handler) ConfigureSpamClassifier(classifier SpamClassifier) {
	h.spamClassifier = classifier
}

// apiSpamClassifier reports, or with DELETE forgets, the current account's
// classifier model: how many spam and ham messages it learned and whether
// it scores yet.
func (h *Handler) apiSpamClassifier(w http.ResponseWriter, r *http.Request) {
	h.serveSpamClassifier(w, r, currentSubject(r).ID, "spam_classifier.reset")
}

// apiAdminUserSpamClassifier reports, or with DELETE forgets, one account's
// classifier model.
func (h *Handler) apiAdminUserSpamClassifier(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	h.serveSpamClassifier(w, r, r.PathValue("id"), "admin.spam_classifier.reset")
}

func (h *Handler) serveSpamClassifier(w http.ResponseWriter, r *http.Request, userID, auditAction string) {
	if h.spamClassifier == nil {
		jsonError(w, http.StatusServiceUnavailable, "the spam classifier is unavailable")
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.spamClassifier.Reset(r.Context(), userID); err != nil {
			apiError(w, err)
			return
		}
		h.audit.Log(currentActor(r).ID, auditAction, userID, nil)
	}
	stats, err := h.spamClassifier.Stats(r.Context(), userID)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, stats)
}

// apiAdminResetSharedSpamClassifier forgets the shared classifier model.
func (h *Handler) apiAdminResetSharedSpamClassifier(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.spamClassifier == nil {
		jsonError(w, http.StatusServiceUnavailable, "the spam classifier is unavailable")
		return
	}
	if err := h.spamClassifier.ResetGlobal(r.Context()); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "admin.spam_classifier.reset_shared", "", nil)
	status, err := h.spamClassifier.Status(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, status)
}
