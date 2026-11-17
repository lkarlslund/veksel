package app

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type browserSessionView struct {
	ID           string `json:"id"`
	IP           string `json:"ip,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	CreatedAt    string `json:"created_at"`
	LastActivity string `json:"last_activity"`
	ExpiresAt    string `json:"expires_at"`
	Current      bool   `json:"current"`
}

func projectBrowserSession(session model.Session, currentID string) browserSessionView {
	format := func(value time.Time) string {
		if value.IsZero() {
			return ""
		}
		return value.UTC().Format(time.RFC3339)
	}
	return browserSessionView{
		ID: session.ID, IP: session.IP, UserAgent: session.UserAgent,
		CreatedAt: format(session.CreatedAt), LastActivity: format(session.LastActivity),
		ExpiresAt: format(session.ExpiresAt), Current: session.ID == currentID,
	}
}

func (h *Handler) apiUserBrowserSessions(w http.ResponseWriter, r *http.Request) {
	current, _ := sessionFromContext(r.Context())
	sessions, err := h.sessions.ListByActor(r.Context(), current.ActorID)
	if err != nil {
		apiError(w, err)
		return
	}
	views := make([]browserSessionView, 0, len(sessions))
	for _, session := range sessions {
		views = append(views, projectBrowserSession(session, current.ID))
	}
	jsonResponse(w, http.StatusOK, map[string]any{"sessions": views, "maximum": maxBrowserSessions})
}

func (h *Handler) apiDeleteUserBrowserSession(w http.ResponseWriter, r *http.Request) {
	current, _ := sessionFromContext(r.Context())
	deleted, err := h.sessions.DeleteOwned(r.Context(), current.ActorID, r.PathValue("id"), current.ID)
	if errors.Is(err, store.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "browser session not found")
		return
	}
	if errors.Is(err, errCurrentSession) {
		jsonError(w, http.StatusConflict, "use sign out to end the current browser session")
		return
	}
	if err != nil {
		apiError(w, err)
		return
	}
	h.recordBrowserSessionRevocations(current.ActorID, []model.Session{deleted}, "user")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiDeleteOtherBrowserSessions(w http.ResponseWriter, r *http.Request) {
	current, _ := sessionFromContext(r.Context())
	deleted, err := h.sessions.DeleteOthers(r.Context(), current.ActorID, current.ID)
	if err != nil {
		apiError(w, err)
		return
	}
	h.recordBrowserSessionRevocations(current.ActorID, deleted, "user_all_others")
	jsonResponse(w, http.StatusOK, map[string]int{"revoked": len(deleted)})
}

func (h *Handler) recordBrowserSessionRevocations(actorID string, sessions []model.Session, reason string) {
	if len(sessions) == 0 {
		return
	}
	h.audit.Log(actorID, "browser_session.revoke", actorID, map[string]string{
		"count": strconv.Itoa(len(sessions)), "reason": reason,
	})
	for _, session := range sessions {
		h.events.Publish(events.Event{
			Type: "browser.session.revoked", Resource: session.ID,
			Data: map[string]any{"reason": reason}, Recipients: []string{actorID},
		})
	}
}
