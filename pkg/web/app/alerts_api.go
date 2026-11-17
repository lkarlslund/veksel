package app

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/health"
)

type adminAlertsResponse struct {
	Alerts         []health.Alert `json:"alerts"`
	Active         int            `json:"active"`
	Unacknowledged int            `json:"unacknowledged"`
	Critical       int            `json:"critical"`
	Silenced       int            `json:"silenced"`
}

func (h *Handler) requireAdminAlerts(w http.ResponseWriter, r *http.Request) bool {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return false
	}
	if h.healthAlerts == nil {
		jsonError(w, http.StatusServiceUnavailable, "health alerts are unavailable")
		return false
	}
	return true
}

func (h *Handler) apiAdminAlerts(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAlerts(w, r) {
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			jsonError(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	alerts, err := h.healthAlerts.List(r.Context(), strings.TrimSpace(r.URL.Query().Get("state")), limit)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	response := adminAlertsResponse{Alerts: alerts}
	for _, alert := range alerts {
		if alert.State != health.AlertStateActive {
			continue
		}
		response.Active++
		if alert.AcknowledgedAt.IsZero() {
			response.Unacknowledged++
		}
		if alert.Severity == health.SeverityCritical {
			response.Critical++
		}
		if alert.IsSilenced(now) {
			response.Silenced++
		}
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAlerts(w, r) {
		return
	}
	actor := currentActor(r).ID
	alert, err := h.healthAlerts.Acknowledge(r.Context(), r.PathValue("id"), actor, time.Now())
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(actor, "health.alert.acknowledge", alert.ID, nil)
	jsonResponse(w, http.StatusOK, alert)
}

func (h *Handler) requireAlertNotifier(w http.ResponseWriter, r *http.Request) bool {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return false
	}
	if h.alertNotifier == nil {
		jsonError(w, http.StatusServiceUnavailable, "alert notifications are unavailable")
		return false
	}
	return true
}

func (h *Handler) apiAdminAlertNotifications(w http.ResponseWriter, r *http.Request) {
	if !h.requireAlertNotifier(w, r) {
		return
	}
	status, err := h.alertNotifier.Status(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, status)
}

func (h *Handler) apiAdminTestAlertNotification(w http.ResponseWriter, r *http.Request) {
	if !h.requireAlertNotifier(w, r) {
		return
	}
	results := h.alertNotifier.Test(r.Context())
	failed := 0
	for _, result := range results {
		if !result.OK {
			failed++
		}
	}
	h.audit.Log(currentActor(r).ID, "health.alert.notification_test", "", map[string]string{"channels": strconv.Itoa(len(results)), "failed": strconv.Itoa(failed)})
	jsonResponse(w, http.StatusOK, map[string]any{"results": results})
}

func (h *Handler) apiAdminSilenceAlert(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAlerts(w, r) {
		return
	}
	var request struct {
		Minutes int    `json:"minutes"`
		Reason  string `json:"reason"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Minutes < 1 || request.Minutes > int(health.MaxSilenceDuration/time.Minute) {
		jsonError(w, http.StatusBadRequest, "minutes must be between 1 and 43200")
		return
	}
	actor := currentActor(r).ID
	alert, err := h.healthAlerts.Silence(r.Context(), r.PathValue("id"), actor, request.Reason, time.Duration(request.Minutes)*time.Minute, time.Now())
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(actor, "health.alert.silence", alert.ID, map[string]string{"until": alert.SilencedUntil.Format(time.RFC3339), "reason": alert.SilenceReason})
	jsonResponse(w, http.StatusOK, alert)
}
