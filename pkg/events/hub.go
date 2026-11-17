// Package events provides user-scoped application events. REST remains the
// command/query transport; this hub is intentionally events-out only.
package events

import (
	"sync"
	"time"
)

// Event is an immutable notification that tells clients which REST view may
// have changed. Data must not contain message bodies or other secret payloads.
type Event struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Resource   string         `json:"resource,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
	Recipients []string       `json:"-"`
}

// Publisher is implemented by Hub and accepted by application services.
type Publisher interface {
	Publish(Event)
}

type Hub struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{subscribers: make(map[string]map[chan Event]struct{})}
}

// Subscribe returns a bounded event stream and an idempotent cancellation
// function. A slow client loses events and must refresh through REST.
func (h *Hub) Subscribe(userID string) (<-chan Event, func()) {
	stream := make(chan Event, 32)
	h.mu.Lock()
	if h.subscribers[userID] == nil {
		h.subscribers[userID] = make(map[chan Event]struct{})
	}
	h.subscribers[userID][stream] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subscribers[userID], stream)
			if len(h.subscribers[userID]) == 0 {
				delete(h.subscribers, userID)
			}
			close(stream)
			h.mu.Unlock()
		})
	}
	return stream, cancel
}

func (h *Hub) Publish(event Event) {
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	seen := make(map[string]struct{}, len(event.Recipients))
	for _, userID := range event.Recipients {
		if _, exists := seen[userID]; exists {
			continue
		}
		seen[userID] = struct{}{}
		for stream := range h.subscribers[userID] {
			select {
			case stream <- event:
			default:
			}
		}
	}
}
