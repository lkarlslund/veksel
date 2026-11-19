package app

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// EASDevice is the deliberately redacted account-facing projection of one
// Exchange ActiveSync partnership. Protocol sync keys never cross this seam.
type EASDevice struct {
	ID           string    `json:"id"`
	Type         string    `json:"type,omitempty"`
	Protocol     string    `json:"protocol,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Model        string    `json:"model,omitempty"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	OS           string    `json:"os,omitempty"`
	OSLanguage   string    `json:"os_language,omitempty"`
	LastCommand  string    `json:"last_command,omitempty"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	// WipeRequestedAt and WipeAcknowledgedAt report a remote wipe: requested
	// and, once the device confirmed it, performed.
	WipeRequestedAt    time.Time `json:"wipe_requested_at,omitzero"`
	WipeAcknowledgedAt time.Time `json:"wipe_acknowledged_at,omitzero"`
}

type EASDeviceInventory interface {
	ListEASDevices(context.Context, string) ([]EASDevice, error)
	RemoveEASDevice(context.Context, string, string) (bool, error)
	// WipeEASDevice asks the device to erase itself at its next connection.
	WipeEASDevice(context.Context, string, string) (bool, error)
}

func (h *Handler) ConfigureEASDeviceInventory(inventory EASDeviceInventory) {
	h.easDevices = inventory
}

func (h *Handler) apiEASDevices(w http.ResponseWriter, r *http.Request) {
	if h.easDevices == nil {
		jsonResponse(w, http.StatusOK, map[string]any{"available": false, "devices": []EASDevice{}})
		return
	}
	devices, err := h.easDevices.ListEASDevices(r.Context(), settingsUserID(r))
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "device inventory is unavailable")
		return
	}
	if devices == nil {
		devices = []EASDevice{}
	}
	jsonResponse(w, http.StatusOK, map[string]any{"available": true, "devices": devices})
}

func (h *Handler) apiRemoveEASDevice(w http.ResponseWriter, r *http.Request) {
	if h.easDevices == nil {
		jsonError(w, http.StatusServiceUnavailable, "Exchange ActiveSync is not available in this build")
		return
	}
	deviceID := strings.ToUpper(strings.TrimSpace(r.PathValue("id")))
	if !validEASDeviceID(deviceID) {
		jsonError(w, http.StatusBadRequest, "invalid device ID")
		return
	}
	userID := settingsUserID(r)
	removed, err := h.easDevices.RemoveEASDevice(r.Context(), userID, deviceID)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "device partnership could not be removed")
		return
	}
	h.auditSettings(r, "eas.device.remove", deviceID, map[string]string{"removed": boolString(removed)})
	jsonResponse(w, http.StatusOK, map[string]bool{"removed": removed})
}

// apiWipeEASDevice requests a remote wipe of one of the account's own
// devices, for a lost or stolen phone. The partnership then refuses every
// command until the device confirms the wipe.
func (h *Handler) apiWipeEASDevice(w http.ResponseWriter, r *http.Request) {
	if h.easDevices == nil {
		jsonError(w, http.StatusServiceUnavailable, "Exchange ActiveSync is not available in this build")
		return
	}
	deviceID := strings.ToUpper(strings.TrimSpace(r.PathValue("id")))
	if !validEASDeviceID(deviceID) {
		jsonError(w, http.StatusBadRequest, "invalid device ID")
		return
	}
	userID := settingsUserID(r)
	found, err := h.easDevices.WipeEASDevice(r.Context(), userID, deviceID)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "remote wipe could not be requested")
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "device partnership not found")
		return
	}
	h.auditSettings(r, "eas.device.wipe", deviceID, nil)
	jsonResponse(w, http.StatusOK, map[string]bool{"wipe_requested": true})
}

func validEASDeviceID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
