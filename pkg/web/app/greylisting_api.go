package app

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/store"
)

type greylistingResponse struct {
	Config greylistConfigView    `json:"config"`
	Stats  greylist.Stats        `json:"stats"`
	Allows []greylist.AllowEntry `json:"allows"`
}

type greylistConfigView struct {
	Enabled              bool   `json:"enabled"`
	MinimumDelaySeconds  int64  `json:"minimum_delay_seconds"`
	RetryWindowSeconds   int64  `json:"retry_window_seconds"`
	PendingLifetimeHours int64  `json:"pending_lifetime_hours"`
	PassLifetimeHours    int64  `json:"pass_lifetime_hours"`
	IPv4PrefixBits       int    `json:"ipv4_prefix_bits"`
	IPv6PrefixBits       int    `json:"ipv6_prefix_bits"`
	MaxEntries           uint64 `json:"max_entries"`
}

type greylistCleanupRequest struct {
	Limit int `json:"limit"`
}

type greylistCleanupResponse struct {
	Removed int            `json:"removed"`
	Stats   greylist.Stats `json:"stats"`
}

func (h *Handler) apiAdminGreylisting(w http.ResponseWriter, r *http.Request) {
	if !h.requireGreylisting(w, r) {
		return
	}
	response, err := h.greylistingResponse(r)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminCreateGreylistAllow(w http.ResponseWriter, r *http.Request) {
	if !h.requireGreylisting(w, r) {
		return
	}
	var candidate greylist.AllowEntry
	if err := decodeJSON(r, &candidate); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	candidate.CreatedBy = currentActor(r).ID
	entry, err := h.greylisting.CreateAllow(r.Context(), candidate)
	if err != nil {
		if errors.Is(err, store.ErrExists) {
			jsonError(w, http.StatusConflict, "greylist allow entry already exists")
		} else {
			jsonError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	h.audit.Log(currentActor(r).ID, "greylisting.allow.create", entry.ID, map[string]string{"kind": string(entry.Kind), "value": entry.Value})
	jsonResponse(w, http.StatusCreated, entry)
}

func (h *Handler) apiAdminDeleteGreylistAllow(w http.ResponseWriter, r *http.Request) {
	if !h.requireGreylisting(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := h.greylisting.DeleteAllow(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "greylist allow entry not found")
		} else {
			jsonError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	h.audit.Log(currentActor(r).ID, "greylisting.allow.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiAdminCleanupGreylisting(w http.ResponseWriter, r *http.Request) {
	if !h.requireGreylisting(w, r) {
		return
	}
	request := greylistCleanupRequest{Limit: 1000}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &request); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	removed, err := h.greylisting.Cleanup(r.Context(), request.Limit)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	stats, err := h.greylisting.Stats(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "greylisting.cleanup", "greylisting", map[string]string{"removed": strconv.Itoa(removed), "limit": strconv.Itoa(request.Limit)})
	jsonResponse(w, http.StatusOK, greylistCleanupResponse{Removed: removed, Stats: stats})
}

func (h *Handler) requireGreylisting(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireAdminAPI(w, r) {
		return false
	}
	if h.greylisting == nil {
		jsonError(w, http.StatusServiceUnavailable, "greylisting service is unavailable")
		return false
	}
	return true
}

func (h *Handler) greylistingResponse(r *http.Request) (greylistingResponse, error) {
	stats, err := h.greylisting.Stats(r.Context())
	if err != nil {
		return greylistingResponse{}, err
	}
	allows, err := h.greylisting.ListAllows(r.Context())
	if err != nil {
		return greylistingResponse{}, err
	}
	config := h.greylisting.Config()
	view := greylistConfigView{
		Enabled: config.Enabled, MinimumDelaySeconds: int64(config.MinimumDelay / time.Second),
		RetryWindowSeconds: int64(config.RetryWindow / time.Second), PendingLifetimeHours: int64(config.PendingLifetime / time.Hour),
		PassLifetimeHours: int64(config.PassLifetime / time.Hour), IPv4PrefixBits: config.IPv4PrefixBits,
		IPv6PrefixBits: config.IPv6PrefixBits, MaxEntries: config.MaxEntries,
	}
	return greylistingResponse{Config: view, Stats: stats, Allows: allows}, nil
}
