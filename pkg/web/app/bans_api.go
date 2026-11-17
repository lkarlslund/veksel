package app

import (
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/httpservice"
)

// ConfigureBans installs the abuse ban engine behind the Security → Bans
// administration view.
func (h *Handler) ConfigureBans(bans *ban.Service) { h.bans = bans }

type bansResponse struct {
	Enabled    bool      `json:"enabled"`
	Active     int       `json:"active"`
	IPv6Prefix int       `json:"ipv6_prefix"`
	Durations  []string  `json:"durations"`
	Bans       []ban.Ban `json:"bans"`
}

type banRequest struct {
	// Network is an IP address or CIDR prefix.
	Network string `json:"network"`
	// Duration is a Go duration or whole days/weeks ("1d", "2w"); empty
	// follows the escalation schedule.
	Duration string `json:"duration"`
	Comment  string `json:"comment"`
}

func (h *Handler) apiAdminBans(w http.ResponseWriter, r *http.Request) {
	if !h.requireBans(w, r) {
		return
	}
	policy := h.bans.Policy()
	durations := make([]string, 0, len(policy.Durations))
	for _, duration := range policy.Durations {
		durations = append(durations, duration.String())
	}
	jsonResponse(w, http.StatusOK, bansResponse{
		Enabled: policy.Enabled, Active: h.bans.Active(), IPv6Prefix: policy.IPv6Prefix,
		Durations: durations, Bans: h.bans.List(r.URL.Query().Get("q")),
	})
}

func (h *Handler) apiAdminCreateBan(w http.ResponseWriter, r *http.Request) {
	if !h.requireBans(w, r) {
		return
	}
	var request banRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	network, err := ban.ParseNetwork(request.Network)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var duration time.Duration
	if request.Duration != "" {
		if duration, err = config.ParseBanDuration(request.Duration); err != nil || duration <= 0 {
			jsonError(w, http.StatusBadRequest, "duration must be a positive duration such as 1h, 1d, or 2w")
			return
		}
	}
	// An administrator cannot ban the address they are managing from.
	if client, err := netip.ParseAddr(httpservice.RequestClient(r).IP); err == nil && network.Contains(client.Unmap()) {
		jsonError(w, http.StatusBadRequest, "the network contains your own address")
		return
	}
	created, err := h.bans.Ban(r.Context(), network, duration, currentActor(r).ID, request.Comment)
	switch {
	case errors.Is(err, ban.ErrExempt):
		jsonError(w, http.StatusBadRequest, "the network is loopback or exempt (mail connection limit exemptions or trusted proxies)")
	case err != nil:
		jsonError(w, http.StatusBadRequest, err.Error())
	default:
		jsonResponse(w, http.StatusCreated, created)
	}
}

func (h *Handler) apiAdminDeleteBan(w http.ResponseWriter, r *http.Request) {
	if !h.requireBans(w, r) {
		return
	}
	network, err := ban.ParseNetwork(r.URL.Query().Get("network"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.bans.Unban(r.Context(), network, currentActor(r).ID); err != nil {
		if errors.Is(err, ban.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "ban not found")
		} else {
			apiError(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) requireBans(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireAdminAPI(w, r) {
		return false
	}
	if h.bans == nil {
		jsonError(w, http.StatusServiceUnavailable, "abuse ban engine is unavailable")
		return false
	}
	return true
}
