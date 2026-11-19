package app

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type userAPIKeyView struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Prefix        string   `json:"prefix"`
	Scopes        []string `json:"scopes"`
	CreatedAt     string   `json:"created_at"`
	LastUsedAt    string   `json:"last_used_at,omitempty"`
	RotatedAt     string   `json:"rotated_at,omitempty"`
	RotationCount int      `json:"rotation_count,omitempty"`
	Secret        string   `json:"secret,omitempty"`
}

func projectUserAPIKey(key model.APIKey, secret string) userAPIKeyView {
	view := userAPIKeyView{
		ID: key.ID, Name: key.Name, Prefix: key.Secret, Scopes: append([]string(nil), key.Scopes...),
		CreatedAt: key.CreatedAt.UTC().Format(time.RFC3339), RotationCount: key.RotationCount, Secret: secret,
	}
	if !key.LastUsedAt.IsZero() {
		view.LastUsedAt = key.LastUsedAt.UTC().Format(time.RFC3339)
	}
	if !key.RotatedAt.IsZero() {
		view.RotatedAt = key.RotatedAt.UTC().Format(time.RFC3339)
	}
	return view
}

func (h *Handler) apiUserAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.apiKeys.ListByUser(r.Context(), settingsUserID(r))
	if err != nil {
		apiError(w, err)
		return
	}
	views := make([]userAPIKeyView, 0, len(keys))
	for _, key := range keys {
		views = append(views, projectUserAPIKey(key, ""))
	}
	jsonResponse(w, http.StatusOK, views)
}

func (h *Handler) apiCreateUserAPIKey(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string   `json:"name"`
		WriteAccess bool     `json:"write_access"`
		Scopes      []string `json:"scopes"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 200 {
		jsonError(w, http.StatusBadRequest, "a key name of at most 200 characters is required")
		return
	}
	scopes := request.Scopes
	if len(scopes) == 0 {
		scopes = []string{model.APIKeyScopeMCPRead}
		if request.WriteAccess {
			scopes = append(scopes, model.APIKeyScopeMCPWrite)
		}
	}
	if status, message := h.checkRequestedAPIKeyScopes(r, scopes); status != http.StatusOK {
		jsonError(w, status, message)
		return
	}
	key, secret, err := h.apiKeys.CreateWithScopes(r.Context(), settingsUserID(r), request.Name, scopes)
	if err != nil {
		apiError(w, err)
		return
	}
	h.auditSettings(r, "api_key.create", key.ID, map[string]string{"scopes": strings.Join(key.Scopes, ","), "name": request.Name})
	jsonResponse(w, http.StatusCreated, projectUserAPIKey(*key, secret))
}

// checkRequestedAPIKeyScopes admits MCP scopes for everyone and REST scopes
// for administrators only. A key-authenticated caller cannot issue a key
// with scopes it does not hold itself.
func (h *Handler) checkRequestedAPIKeyScopes(r *http.Request, scopes []string) (int, string) {
	caller, byKey := apiKeyFromContext(r.Context())
	for _, scope := range scopes {
		switch scope {
		case model.APIKeyScopeMCPRead, model.APIKeyScopeMCPWrite:
		case model.APIKeyScopeAPIRead, model.APIKeyScopeAPIWrite, model.APIKeyScopeKeysManage, model.APIKeyScopeAll:
			if !h.isAdmin(r.Context(), settingsUserID(r)) {
				return http.StatusForbidden, "REST API scopes require a system administrator"
			}
		default:
			return http.StatusBadRequest, "invalid API key scope " + strconv.Quote(scope)
		}
		if byKey && !caller.permits(scope) {
			return http.StatusForbidden, "cannot grant a scope the current API key does not hold"
		}
	}
	return http.StatusOK, ""
}

func (h *Handler) apiRotateUserAPIKey(w http.ResponseWriter, r *http.Request) {
	key, err := h.apiKeys.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "API key not found")
		return
	}
	if err != nil {
		apiError(w, err)
		return
	}
	if key.UserID != settingsUserID(r) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	if status, message := h.checkRequestedAPIKeyScopes(r, key.EffectiveScopes()); status != http.StatusOK {
		jsonError(w, status, message)
		return
	}
	rotated, secret, err := h.apiKeys.Rotate(r.Context(), key.ID)
	if errors.Is(err, model.ErrAPIKeyRevoked) {
		jsonError(w, http.StatusConflict, "API key is revoked")
		return
	}
	if err != nil {
		apiError(w, err)
		return
	}
	h.auditSettings(r, "api_key.rotate", key.ID, map[string]string{
		"scopes": strings.Join(rotated.Scopes, ","), "name": rotated.Name,
		"rotation_count": strconv.Itoa(rotated.RotationCount),
	})
	jsonResponse(w, http.StatusOK, projectUserAPIKey(*rotated, secret))
}

func (h *Handler) apiDeleteUserAPIKey(w http.ResponseWriter, r *http.Request) {
	key, err := h.apiKeys.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		apiError(w, err)
		return
	}
	if key.UserID != settingsUserID(r) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.apiKeys.Revoke(r.Context(), key.ID); err != nil {
		apiError(w, err)
		return
	}
	h.auditSettings(r, "api_key.revoke", key.ID, map[string]string{"scopes": strings.Join(key.Scopes, ",")})
	w.WriteHeader(http.StatusNoContent)
}
