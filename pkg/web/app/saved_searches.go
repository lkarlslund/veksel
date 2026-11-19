package app

import (
	"errors"
	"net/http"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/savedsearch"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

type savedSearchRequest struct {
	Name  string              `json:"name"`
	Query service.SearchQuery `json:"query"`
}

func (h *Handler) apiSavedSearches(w http.ResponseWriter, r *http.Request) {
	definitions, err := h.savedSearches.List(r.Context(), settingsUserID(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"saved_searches": definitions, "maximum": savedsearch.MaxPerOwner})
}

func (h *Handler) apiCreateSavedSearch(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeSavedSearchRequest(w, r)
	if !ok {
		return
	}
	actor := settingsUserID(r)
	definition, err := h.savedSearches.Create(r.Context(), actor, request.Name, request.Query)
	if savedSearchError(w, err) {
		return
	}
	h.auditSettings(r, "saved_search.create", definition.ID, nil)
	h.events.Publish(events.Event{Type: "saved_search.created", Resource: definition.ID, Recipients: []string{actor}})
	jsonResponse(w, http.StatusCreated, definition)
}

func (h *Handler) apiUpdateSavedSearch(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeSavedSearchRequest(w, r)
	if !ok {
		return
	}
	actor := settingsUserID(r)
	definition, err := h.savedSearches.Update(r.Context(), actor, r.PathValue("id"), request.Name, request.Query)
	if savedSearchError(w, err) {
		return
	}
	h.auditSettings(r, "saved_search.update", definition.ID, nil)
	h.events.Publish(events.Event{Type: "saved_search.updated", Resource: definition.ID, Recipients: []string{actor}})
	jsonResponse(w, http.StatusOK, definition)
}

func (h *Handler) apiDeleteSavedSearch(w http.ResponseWriter, r *http.Request) {
	actor, id := settingsUserID(r), r.PathValue("id")
	if savedSearchError(w, h.savedSearches.Delete(r.Context(), actor, id)) {
		return
	}
	h.auditSettings(r, "saved_search.delete", id, nil)
	h.events.Publish(events.Event{Type: "saved_search.deleted", Resource: id, Recipients: []string{actor}})
	w.WriteHeader(http.StatusNoContent)
}

func decodeSavedSearchRequest(w http.ResponseWriter, r *http.Request) (savedSearchRequest, bool) {
	var request savedSearchRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return savedSearchRequest{}, false
	}
	return request, true
}

func savedSearchError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, savedsearch.ErrInvalid):
		jsonError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, savedsearch.ErrLimit):
		jsonError(w, http.StatusConflict, "saved search limit reached")
	case errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "saved search not found")
	default:
		apiError(w, err)
	}
	return true
}
