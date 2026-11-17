package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/pelletier/go-toml/v2"
)

func (h *Handler) apiAdminConfigHistory(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if r.URL.Query().Get("limit") != "" && (err != nil || limit < 1 || limit > config.MaxHistoryRevisions) {
		jsonError(w, http.StatusBadRequest, "limit must be between 1 and "+strconv.Itoa(config.MaxHistoryRevisions))
		return
	}
	history, err := h.configService.History(limit)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"current_revision": h.configService.Current().Revision, "revisions": h.projectConfigHistory(history)})
}

const maxConfigHistoryValueRunes = 2048

type configHistoryValue struct {
	State     string `json:"state"`
	Kind      string `json:"kind"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
}

type configHistoryChange struct {
	Key       string             `json:"key"`
	Label     string             `json:"label"`
	Section   string             `json:"section"`
	Direction string             `json:"direction"`
	Before    configHistoryValue `json:"before"`
	After     configHistoryValue `json:"after"`
	Sensitive bool               `json:"sensitive,omitempty"`
}

type configHistoryRevision struct {
	ID             string                `json:"id"`
	Revision       string                `json:"revision"`
	ParentRevision string                `json:"parent_revision,omitempty"`
	CreatedAt      time.Time             `json:"created_at"`
	Actor          string                `json:"actor"`
	Reason         string                `json:"reason,omitempty"`
	Source         string                `json:"source"`
	Changes        []configHistoryChange `json:"changes"`
}

func (h *Handler) projectConfigHistory(entries []config.RevisionEntry) []configHistoryRevision {
	catalog := make(map[string]struct {
		label, section string
		sensitive      bool
	})
	for _, setting := range h.adminSettingSchema() {
		catalog[setting.Key] = struct {
			label, section string
			sensitive      bool
		}{label: setting.Label, section: setting.Category, sensitive: setting.Sensitive}
	}
	result := make([]configHistoryRevision, 0, len(entries))
	for _, entry := range entries {
		projected := configHistoryRevision{ID: entry.ID, Revision: entry.Revision, ParentRevision: entry.ParentRevision, CreatedAt: entry.CreatedAt, Actor: entry.Actor, Reason: entry.Reason, Source: entry.Source, Changes: make([]configHistoryChange, 0, len(entry.Changes))}
		for _, change := range entry.Changes {
			definition, known := catalog[change.Key]
			if !known {
				continue
			}
			sensitive := change.Sensitive || definition.sensitive
			direction := "changed"
			if change.Before == nil && change.After != nil {
				direction = "added"
			} else if change.Before != nil && change.After == nil {
				direction = "removed"
			}
			projected.Changes = append(projected.Changes, configHistoryChange{Key: change.Key, Label: definition.label, Section: definition.section, Direction: direction, Before: projectConfigHistoryValue(change.Before, sensitive), After: projectConfigHistoryValue(change.After, sensitive), Sensitive: sensitive})
		}
		result = append(result, projected)
	}
	return result
}

func projectConfigHistoryValue(value any, sensitive bool) configHistoryValue {
	if sensitive {
		return configHistoryValue{State: "redacted", Kind: "redacted", Text: "Sensitive value redacted"}
	}
	if value == nil {
		return configHistoryValue{State: "absent", Kind: "absent", Text: "Not set"}
	}
	kind, text, formatted := "scalar", "", false
	switch typed := value.(type) {
	case string:
		kind, text, formatted = "string", typed, true
	case []any:
		kind = "list"
	case map[string]any:
		kind = "object"
	}
	if !formatted {
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return configHistoryValue{State: "unavailable", Kind: "unavailable", Text: "Value unavailable"}
		}
		text = string(encoded)
	}
	runes := []rune(text)
	truncated := len(runes) > maxConfigHistoryValueRunes
	if truncated {
		text = string(runes[:maxConfigHistoryValueRunes]) + "…"
	}
	return configHistoryValue{State: "value", Kind: kind, Text: text, Truncated: truncated}
}

func (h *Handler) apiAdminConfigRestore(w http.ResponseWriter, r *http.Request) {
	if !h.requireOwnerAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	var request struct {
		Revision string `json:"revision"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	snapshot, activation, plan, err := h.configService.RestoreRevisionWithPlan(request.Revision, r.PathValue("revision"), config.MutationMetadata{Actor: currentActor(r).ID, Reason: request.Reason})
	if errors.Is(err, config.ErrRevisionConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.applyManagedConfiguration(snapshot, nil)
	h.audit.Log(currentActor(r).ID, "config.restore", snapshot.Revision, map[string]string{"activation_id": activation.ID, "reason": request.Reason})
	response := h.configResponse(snapshot, plan.RestartRequired)
	response.Plan = &plan
	jsonResponse(w, http.StatusOK, map[string]any{"config": response, "activation": activation})
}

func (h *Handler) apiAdminConfigValidateRestore(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	var request struct {
		Revision string `json:"revision"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan, err := h.configService.PlanRestore(request.Revision, r.PathValue("revision"))
	if errors.Is(err, config.ErrRevisionConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, plan)
}

type configAPIResponse struct {
	Revision        string                      `json:"revision"`
	Values          map[string]any              `json:"values"`
	Schema          []config.SettingSpec        `json:"schema"`
	ApplyState      []config.SettingApplyStatus `json:"apply_state"`
	Plan            *config.ChangePlan          `json:"plan,omitempty"`
	RestartRequired bool                        `json:"restart_required"`
}

type configPatchRequest struct {
	Revision string         `json:"revision"`
	Settings map[string]any `json:"settings"`
	Reason   string         `json:"reason"`
}

func (h *Handler) apiAdminConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, h.configResponse(h.configService.Current(), false))
}

func (h *Handler) apiAdminPatchConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireOwnerAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	var request configPatchRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	after, plan, err := h.configService.PatchWithPlan(request.Revision, request.Settings, config.MutationMetadata{Actor: currentActor(r).ID, Reason: request.Reason, Source: "admin-api"})
	if errors.Is(err, config.ErrRevisionConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.applyManagedConfiguration(after, request.Settings)
	for key := range request.Settings {
		h.audit.Log(currentActor(r).ID, "config.update", key, nil)
	}
	response := h.configResponse(after, plan.RestartRequired)
	response.Plan = &plan
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminValidateConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	var request configPatchRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	snapshot, plan, err := h.configService.PreviewPatch(request.Revision, request.Settings)
	if errors.Is(err, config.ErrRevisionConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	response := h.configResponse(snapshot, plan.RestartRequired)
	response.Plan = &plan
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminRecoverConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireOwnerAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	var request struct {
		Revision string `json:"revision"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	snapshot, err := h.configService.RecoverPrevious(request.Revision)
	if errors.Is(err, config.ErrRevisionConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.applyManagedConfiguration(snapshot, nil)
	h.audit.Log(currentActor(r).ID, "config.recover", snapshot.Revision, nil)
	jsonResponse(w, http.StatusOK, h.configResponse(snapshot, true))
}

func (h *Handler) apiAdminReloadConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	snapshot, err := h.configService.Reload()
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.applyManagedConfiguration(snapshot, nil)
	h.audit.Log(currentActor(r).ID, "config.reload", snapshot.Revision, nil)
	jsonResponse(w, http.StatusOK, h.configResponse(snapshot, true))
}

func (h *Handler) configResponse(snapshot config.Snapshot, restart bool) configAPIResponse {
	encoded, _ := toml.Marshal(snapshot.Config)
	values := make(map[string]any)
	_ = toml.Unmarshal(encoded, &values)
	for _, spec := range snapshot.Schema {
		if spec.Sensitive {
			values[spec.Key] = ""
		}
	}
	response := configAPIResponse{Revision: snapshot.Revision, Values: values, Schema: snapshot.Schema, RestartRequired: restart}
	if h.configService != nil {
		response.ApplyState = h.configService.ApplyStates()
	}
	return response
}
