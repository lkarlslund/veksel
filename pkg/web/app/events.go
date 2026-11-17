package app

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

var eventUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false
		}
		parsed, err := url.Parse(origin)
		return err == nil && parsed.Host == r.Host && (parsed.Scheme == "http" || parsed.Scheme == "https")
	},
}

func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionFromContext(r.Context())
	// Subscribe before completing the handshake so events published right
	// after the client sees the connection open are not lost.
	stream, cancel := h.events.Subscribe(session.ActorID)
	defer cancel()
	connection, err := eventUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		connection.SetReadLimit(1024)
		for {
			if _, _, err := connection.ReadMessage(); err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case event, open := <-stream:
			if !open || connection.WriteJSON(event) != nil {
				return
			}
			if event.Type == "browser.session.revoked" && event.Resource == session.ID {
				return
			}
		case <-ticker.C:
			if _, err := h.sessions.ActiveByID(r.Context(), session.ID); err != nil {
				_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "session ended"), time.Now().Add(5*time.Second))
				return
			}
			if connection.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
				return
			}
		case <-closed:
			return
		}
	}
}
