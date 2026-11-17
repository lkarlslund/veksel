package app

import (
	"errors"
	"net/http"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/messagetemplate"
	"github.com/lkarlslund/veksel/pkg/store"
)

type messageTemplateRequest struct {
	Name    string `json:"name"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func (h *Handler) apiMessageTemplates(w http.ResponseWriter, r *http.Request) {
	definitions, err := h.messageTemplates.List(r.Context(), currentActor(r).ID)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"templates": definitions, "maximum": messagetemplate.MaxPerOwner})
}

func (h *Handler) apiCreateMessageTemplate(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeMessageTemplateRequest(w, r)
	if !ok {
		return
	}
	actor := currentActor(r).ID
	definition, err := h.messageTemplates.Create(r.Context(), actor, request.Name, request.Subject, request.Body)
	if messageTemplateError(w, err) {
		return
	}
	h.audit.Log(actor, "message_template.create", definition.ID, nil)
	h.events.Publish(events.Event{Type: "message_template.created", Resource: definition.ID, Recipients: []string{actor}})
	jsonResponse(w, http.StatusCreated, definition)
}

func (h *Handler) apiUpdateMessageTemplate(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeMessageTemplateRequest(w, r)
	if !ok {
		return
	}
	actor := currentActor(r).ID
	definition, err := h.messageTemplates.Update(r.Context(), actor, r.PathValue("id"), request.Name, request.Subject, request.Body)
	if messageTemplateError(w, err) {
		return
	}
	h.audit.Log(actor, "message_template.update", definition.ID, nil)
	h.events.Publish(events.Event{Type: "message_template.updated", Resource: definition.ID, Recipients: []string{actor}})
	jsonResponse(w, http.StatusOK, definition)
}

func (h *Handler) apiDeleteMessageTemplate(w http.ResponseWriter, r *http.Request) {
	actor, id := currentActor(r).ID, r.PathValue("id")
	if messageTemplateError(w, h.messageTemplates.Delete(r.Context(), actor, id)) {
		return
	}
	h.audit.Log(actor, "message_template.delete", id, nil)
	h.events.Publish(events.Event{Type: "message_template.deleted", Resource: id, Recipients: []string{actor}})
	w.WriteHeader(http.StatusNoContent)
}

func decodeMessageTemplateRequest(w http.ResponseWriter, r *http.Request) (messageTemplateRequest, bool) {
	var request messageTemplateRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return messageTemplateRequest{}, false
	}
	return request, true
}

func messageTemplateError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, messagetemplate.ErrInvalid):
		jsonError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, messagetemplate.ErrLimit):
		jsonError(w, http.StatusConflict, "message template limit reached")
	case errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "message template not found")
	default:
		apiError(w, err)
	}
	return true
}
