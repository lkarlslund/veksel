package app

import (
	"errors"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

func (h *Handler) apiSetupStatus(w http.ResponseWriter, r *http.Request) {
	state, err := h.bootstrap.State(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "setup state unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"state": state, "csrf": h.ensureCSRF(w, r)})
}

func (h *Handler) apiSetupCreate(w http.ResponseWriter, r *http.Request) {
	if !h.validPublicCSRF(r) {
		jsonError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	var request struct {
		Token       string `json:"token"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		HostName    string `json:"host_name"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	hostName, err := h.setupHostNameChange(request.HostName)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "host_name: "+err.Error())
		return
	}
	if err := h.bootstrap.CreateOwner(r.Context(), request.Token, request.Username, request.DisplayName, request.Password); err != nil {
		if errors.Is(err, authz.ErrSetupToken) {
			jsonError(w, http.StatusForbidden, err.Error())
			return
		}
		state, stateErr := h.bootstrap.State(r.Context())
		if stateErr == nil && state != authz.SetupReady {
			jsonError(w, http.StatusConflict, err.Error())
			return
		}
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.persistSetupHostName(r.Context(), hostName)
	if err := h.syncAccountManifest(r.Context(), request.Username); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonResponse(w, http.StatusCreated, map[string]string{"id": strings.ToLower(strings.TrimSpace(request.Username))})
}

func (h *Handler) apiSessionLogin(w http.ResponseWriter, r *http.Request) {
	if !h.validPublicCSRF(r) {
		jsonError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := h.authenticateLogin(r, request.Username, request.Password)
	if errors.Is(err, ratelimit.ErrAuthThrottled) {
		ratelimit.WriteRetryAfter(w, err)
		jsonError(w, http.StatusTooManyRequests, "too many failed sign-in attempts; try again later")
		return
	}
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	csrf, err := r.Cookie(csrfCookie)
	if err != nil {
		jsonError(w, http.StatusForbidden, "missing CSRF cookie")
		return
	}
	state, err := h.beginSignIn(w, r, user.ID, csrf.Value)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	if state != "" {
		// The pending sign-in cookie grants nothing until the second factor
		// (or required enrolment) completes.
		jsonResponse(w, http.StatusOK, map[string]string{"user_id": user.ID, "csrf": csrf.Value, "second_factor": state})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"user_id": user.ID, "csrf": csrf.Value})
}
