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

type userAppPasswordView struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Prefix        string   `json:"prefix"`
	Protocols     []string `json:"protocols"`
	CreatedAt     string   `json:"created_at"`
	LastUsedAt    string   `json:"last_used_at,omitempty"`
	LastProtocol  string   `json:"last_protocol,omitempty"`
	RotatedAt     string   `json:"rotated_at,omitempty"`
	RotationCount int      `json:"rotation_count,omitempty"`
	Secret        string   `json:"secret,omitempty"`
}

func projectUserAppPassword(password model.AppPassword, secret string) userAppPasswordView {
	view := userAppPasswordView{ID: password.ID, Name: password.Name, Prefix: password.SecretPrefix,
		Protocols: append([]string(nil), password.Protocols...), CreatedAt: password.CreatedAt.UTC().Format(time.RFC3339),
		LastProtocol: password.LastProtocol, RotationCount: password.RotationCount, Secret: secret}
	if !password.LastUsedAt.IsZero() {
		view.LastUsedAt = password.LastUsedAt.UTC().Format(time.RFC3339)
	}
	if !password.RotatedAt.IsZero() {
		view.RotatedAt = password.RotatedAt.UTC().Format(time.RFC3339)
	}
	return view
}

func (h *Handler) apiUserAppPasswords(w http.ResponseWriter, r *http.Request) {
	passwords, err := h.appPasswords.ListByUser(r.Context(), settingsUserID(r))
	if err != nil {
		apiError(w, err)
		return
	}
	views := make([]userAppPasswordView, 0, len(passwords))
	for _, password := range passwords {
		views = append(views, projectUserAppPassword(password, ""))
	}
	jsonResponse(w, http.StatusOK, map[string]any{"passwords": views, "protocols": model.SupportedAppProtocols()})
}

func (h *Handler) apiCreateUserAppPassword(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name      string   `json:"name"`
		Protocols []string `json:"protocols"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	password, secret, err := h.appPasswords.Create(r.Context(), settingsUserID(r), request.Name, request.Protocols)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.auditSettings(r, "app_password.create", password.ID, map[string]string{"name": password.Name, "protocols": strings.Join(password.Protocols, ",")})
	jsonResponse(w, http.StatusCreated, projectUserAppPassword(*password, secret))
}

func (h *Handler) ownedAppPassword(w http.ResponseWriter, r *http.Request) (*model.AppPassword, bool) {
	password, err := h.appPasswords.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "application password not found")
		return nil, false
	}
	if err != nil {
		apiError(w, err)
		return nil, false
	}
	if password.UserID != settingsUserID(r) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return nil, false
	}
	return password, true
}

func (h *Handler) apiRotateUserAppPassword(w http.ResponseWriter, r *http.Request) {
	password, ok := h.ownedAppPassword(w, r)
	if !ok {
		return
	}
	rotated, secret, err := h.appPasswords.Rotate(r.Context(), password.ID)
	if errors.Is(err, model.ErrAppPasswordRevoked) {
		jsonError(w, http.StatusConflict, "application password is revoked")
		return
	}
	if err != nil {
		apiError(w, err)
		return
	}
	h.auditSettings(r, "app_password.rotate", password.ID, map[string]string{
		"name": rotated.Name, "protocols": strings.Join(rotated.Protocols, ","), "rotation_count": strconv.Itoa(rotated.RotationCount),
	})
	jsonResponse(w, http.StatusOK, projectUserAppPassword(*rotated, secret))
}

func (h *Handler) apiDeleteUserAppPassword(w http.ResponseWriter, r *http.Request) {
	password, ok := h.ownedAppPassword(w, r)
	if !ok {
		return
	}
	if err := h.appPasswords.Revoke(r.Context(), password.ID); err != nil {
		apiError(w, err)
		return
	}
	h.auditSettings(r, "app_password.revoke", password.ID, map[string]string{"name": password.Name, "protocols": strings.Join(password.Protocols, ",")})
	w.WriteHeader(http.StatusNoContent)
}
