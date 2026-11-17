package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/sharing"
	"github.com/lkarlslund/veksel/pkg/store"
)

func (h *Handler) registerShareManagementRoutes(api apiRouter) {
	api.handle("GET /api/v1/share-links", h.apiShareLinks)
	api.handle("POST /api/v1/share-links", h.apiCreateShareLink)
	api.handle("GET /api/v1/share-links/{id}", h.apiShareLink)
	api.handle("DELETE /api/v1/share-links/{id}", h.apiRevokeShareLink)
}

func (h *Handler) registerPublicShareRoutes(api apiRouter) {
	api.mux.HandleFunc("GET /share/", h.publicSharePage)
	api.public("GET /api/v1/public/share", h.publicShareOpen)
	api.public("GET /api/v1/public/share/items/{id}", h.publicShareReadItem)
	api.public("POST /api/v1/public/share/items", h.publicShareCreateItem)
	api.public("PUT /api/v1/public/share/items/{id}", h.publicShareUpdateItem)
	api.public("DELETE /api/v1/public/share/items/{id}", h.publicShareDeleteItem)
}

func (h *Handler) apiShareLinks(w http.ResponseWriter, r *http.Request) {
	links, err := h.shareLinks.List(r.Context(), currentActor(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, links)
}

func (h *Handler) apiCreateShareLink(w http.ResponseWriter, r *http.Request) {
	var request sharing.CreateRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	issued, err := h.shareLinks.Create(r.Context(), currentActor(r), request)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, map[string]any{"link": issued.Link, "token": issued.Token, "path": "/share/#" + issued.Token})
}

func (h *Handler) apiShareLink(w http.ResponseWriter, r *http.Request) {
	link, err := h.shareLinks.Get(r.Context(), currentActor(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, link)
}

func (h *Handler) apiRevokeShareLink(w http.ResponseWriter, r *http.Request) {
	if _, err := h.shareLinks.Revoke(r.Context(), currentActor(r), r.PathValue("id")); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) publicSharePage(w http.ResponseWriter, r *http.Request) {
	setPublicShareHeaders(w)
	if r.URL.Path != "/share/" {
		http.NotFound(w, r)
		return
	}
	h.render(w, "share.gohtml", map[string]any{"Client": h.clientManifest}, http.StatusOK)
}

func (h *Handler) publicShareOpen(w http.ResponseWriter, r *http.Request) {
	setPublicShareHeaders(w)
	limit, beforeUID, err := publicSharePageParameters(r)
	if err != nil {
		publicShareError(w, err)
		return
	}
	resource, err := h.shareLinks.Open(r.Context(), publicShareToken(r), beforeUID, limit)
	if err != nil {
		publicShareError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, resource)
}

func (h *Handler) publicShareReadItem(w http.ResponseWriter, r *http.Request) {
	setPublicShareHeaders(w)
	item, err := h.shareLinks.ReadItem(r.Context(), publicShareToken(r), r.PathValue("id"))
	if err != nil {
		publicShareError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, item)
}

func (h *Handler) publicShareCreateItem(w http.ResponseWriter, r *http.Request) {
	setPublicShareHeaders(w)
	var request sharing.ItemInput
	if err := decodePublicShareJSON(r, &request); err != nil {
		publicShareError(w, err)
		return
	}
	item, err := h.shareLinks.CreateItem(r.Context(), publicShareToken(r), request)
	if err != nil {
		publicShareError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, item)
}

func (h *Handler) publicShareUpdateItem(w http.ResponseWriter, r *http.Request) {
	setPublicShareHeaders(w)
	var request sharing.ItemInput
	if err := decodePublicShareJSON(r, &request); err != nil {
		publicShareError(w, err)
		return
	}
	item, err := h.shareLinks.UpdateItem(r.Context(), publicShareToken(r), r.PathValue("id"), request)
	if err != nil {
		publicShareError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, item)
}

func (h *Handler) publicShareDeleteItem(w http.ResponseWriter, r *http.Request) {
	setPublicShareHeaders(w)
	if err := h.shareLinks.DeleteItem(r.Context(), publicShareToken(r), r.PathValue("id")); err != nil {
		publicShareError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func publicShareToken(r *http.Request) string {
	scheme, token, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !found || !strings.EqualFold(scheme, "Share") {
		return ""
	}
	return strings.TrimSpace(token)
}

func publicSharePageParameters(r *http.Request) (int, uint32, error) {
	limit := 50
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > sharing.MaxPageSize {
			return 0, 0, fmt.Errorf("%w: invalid page limit", sharing.ErrInvalidInput)
		}
		limit = parsed
	}
	var beforeUID uint64
	if value := strings.TrimSpace(r.URL.Query().Get("before_uid")); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: invalid page cursor", sharing.ErrInvalidInput)
		}
		beforeUID = parsed
	}
	return limit, uint32(beforeUID), nil
}

func decodePublicShareJSON(r *http.Request, value any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("%w: application/json is required", sharing.ErrInvalidInput)
	}
	limit := int64(sharing.MaxItemBytes*2 + (1 << 20))
	decoder := json.NewDecoder(io.LimitReader(r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%w: %v", sharing.ErrInvalidInput, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("%w: request must contain one JSON object", sharing.ErrInvalidInput)
	}
	return nil
}

func setPublicShareHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func publicShareError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sharing.ErrUnavailable), errors.Is(err, sharing.ErrTargetMismatch), errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "share link or resource is unavailable")
	case errors.Is(err, sharing.ErrReadOnly):
		jsonError(w, http.StatusForbidden, "share link is read-only")
	case errors.Is(err, sharing.ErrInvalidInput):
		jsonError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, account.ErrTemporarilyUnavailable):
		w.Header().Set("Retry-After", "5")
		jsonError(w, http.StatusServiceUnavailable, "shared account is temporarily unavailable")
	default:
		jsonError(w, http.StatusServiceUnavailable, "shared resource is temporarily unavailable")
	}
}
