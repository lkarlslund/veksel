package app

import (
	"net/http"

	"github.com/lkarlslund/veksel/pkg/model"
)

func (h *Handler) apiAdminRoutes(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	routes, err := h.ts.OutboundRouteStore().List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, routes)
}

func (h *Handler) apiAdminRoute(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	route, err := h.ts.OutboundRouteStore().Get(r.Context(), r.PathValue("domain"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, route)
}

func (h *Handler) apiAdminCreateRoute(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var route model.OutboundRoute
	if err := decodeJSON(r, &route); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.ts.OutboundRouteStore().Create(r.Context(), route)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "route.create", created.Domain, map[string]string{"transport": string(created.Transport)})
	jsonResponse(w, http.StatusCreated, created)
}

func (h *Handler) apiAdminReplaceRoute(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var route model.OutboundRoute
	if err := decodeJSON(r, &route); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.ts.OutboundRouteStore().Set(r.Context(), r.PathValue("domain"), route)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "route.update", updated.Domain, map[string]string{"transport": string(updated.Transport)})
	jsonResponse(w, http.StatusOK, updated)
}

func (h *Handler) apiAdminDeleteRoute(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	domain := r.PathValue("domain")
	if err := h.ts.OutboundRouteStore().Delete(r.Context(), domain); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "route.delete", domain, nil)
	w.WriteHeader(http.StatusNoContent)
}
