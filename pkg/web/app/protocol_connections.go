package app

import (
	"net/http"
	"time"
)

type protocolConnectionStatus struct {
	Protocol   string    `json:"protocol"`
	Active     int64     `json:"active"`
	ObservedAt time.Time `json:"observed_at"`
}

func (h *Handler) apiAdminProtocolConnections(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.metrics == nil {
		jsonError(w, http.StatusServiceUnavailable, "protocol connection metrics are unavailable")
		return
	}
	statuses := make([]protocolConnectionStatus, 0, 3)
	for _, protocol := range []string{"imap", "pop3", "smtp"} {
		value, observedAt, ok := h.metrics.CurrentGauge(protocol + "_active_connections")
		if !ok {
			value, observedAt = 0, time.Now().UTC()
		}
		statuses = append(statuses, protocolConnectionStatus{Protocol: protocol, Active: int64(value), ObservedAt: observedAt.UTC()})
	}
	jsonResponse(w, http.StatusOK, map[string]any{"connections": statuses, "generated_at": time.Now().UTC()})
}
