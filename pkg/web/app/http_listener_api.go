package app

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/lkarlslund/veksel/pkg/config"
)

type httpListenerRequest struct {
	Revision string              `json:"revision"`
	Reason   string              `json:"reason"`
	Listener config.HTTPListener `json:"listener"`
}

func (h *Handler) apiAdminHTTPListeners(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	snapshot := h.configService.Current()
	jsonResponse(w, http.StatusOK, map[string]any{"revision": snapshot.Revision, "listeners": snapshot.Config.HTTPListeners, "services": config.HTTPServices})
}

func (h *Handler) apiAdminCreateHTTPListener(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	var request httpListenerRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Listener.ID = strings.TrimSpace(request.Listener.ID)
	current := h.configService.Current()
	for _, listener := range current.Config.HTTPListeners {
		if listener.ID == request.Listener.ID {
			jsonError(w, http.StatusConflict, "HTTP listener id already exists")
			return
		}
	}
	h.writeHTTPListeners(w, r, request.Revision, append(current.Config.HTTPListeners, request.Listener), request.Reason, "create", request.Listener.ID, http.StatusCreated)
}

func (h *Handler) apiAdminUpdateHTTPListener(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	var request httpListenerRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	request.Listener.ID = id
	current := h.configService.Current()
	listeners := slices.Clone(current.Config.HTTPListeners)
	found := false
	for i := range listeners {
		if listeners[i].ID == id {
			listeners[i] = request.Listener
			found = true
			break
		}
	}
	if !found {
		jsonError(w, http.StatusNotFound, "HTTP listener not found")
		return
	}
	h.writeHTTPListeners(w, r, request.Revision, listeners, request.Reason, "update", id, http.StatusOK)
}

func (h *Handler) apiAdminDeleteHTTPListener(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
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
	id := r.PathValue("id")
	current := h.configService.Current()
	listeners := make([]config.HTTPListener, 0, len(current.Config.HTTPListeners)-1)
	for _, listener := range current.Config.HTTPListeners {
		if listener.ID != id {
			listeners = append(listeners, listener)
		}
	}
	if len(listeners) == len(current.Config.HTTPListeners) {
		jsonError(w, http.StatusNotFound, "HTTP listener not found")
		return
	}
	h.writeHTTPListeners(w, r, request.Revision, listeners, request.Reason, "delete", id, http.StatusOK)
}

func (h *Handler) apiAdminUpdateHTTPBinding(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	service := r.PathValue("service")
	if !slices.Contains(config.HTTPServices, service) {
		jsonError(w, http.StatusNotFound, "HTTP service not found")
		return
	}
	var request struct {
		Revision    string   `json:"revision"`
		ListenerIDs []string `json:"listener_ids"`
		Reason      string   `json:"reason"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	selected := make(map[string]struct{}, len(request.ListenerIDs))
	for _, id := range request.ListenerIDs {
		selected[id] = struct{}{}
	}
	current := h.configService.Current()
	listeners := slices.Clone(current.Config.HTTPListeners)
	for i := range listeners {
		listeners[i].Services = slices.Clone(listeners[i].Services)
		_, wanted := selected[listeners[i].ID]
		bound := slices.Contains(listeners[i].Services, service)
		if wanted && !bound {
			listeners[i].Services = append(listeners[i].Services, service)
		}
		if !wanted && bound {
			listeners[i].Services = slices.DeleteFunc(listeners[i].Services, func(value string) bool { return value == service })
		}
		delete(selected, listeners[i].ID)
	}
	if len(selected) > 0 {
		jsonError(w, http.StatusBadRequest, "binding references an unknown HTTP listener")
		return
	}
	h.writeHTTPListeners(w, r, request.Revision, listeners, request.Reason, "bind", service, http.StatusOK)
}

func (h *Handler) writeHTTPListeners(w http.ResponseWriter, r *http.Request, revision string, listeners []config.HTTPListener, reason, action, id string, status int) {
	after, plan, err := h.configService.PatchWithPlan(revision, map[string]any{"http_listeners": listeners}, config.MutationMetadata{Actor: currentActor(r).ID, Reason: reason, Source: "admin-api"})
	if errors.Is(err, config.ErrRevisionConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.applyManagedConfiguration(after, map[string]any{"http_listeners": listeners})
	h.audit.Log(currentActor(r).ID, "http-listener."+action, id, nil)
	jsonResponse(w, status, map[string]any{"revision": after.Revision, "listeners": after.Config.HTTPListeners, "services": config.HTTPServices, "restart_required": plan.RestartRequired, "plan": plan})
}
