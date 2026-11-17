package model

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// WebhookDeliveryStatus tracks the lifecycle of a single webhook delivery attempt.
type WebhookDeliveryStatus string

const (
	WebhookDeliveryPending WebhookDeliveryStatus = "pending"
	WebhookDeliverySent    WebhookDeliveryStatus = "sent"
	WebhookDeliveryFailed  WebhookDeliveryStatus = "failed"
)

// WebhookDelivery records a single delivery attempt for a webhook event.
type WebhookDelivery struct {
	ID             string                `json:"id"`
	WebhookID      string                `json:"webhook_id"`
	Event          string                `json:"event"` // event type (e.g. "message.received")
	URL            string                `json:"url"`   // destination URL at time of attempt
	Status         WebhookDeliveryStatus `json:"status"`
	StatusCode     int                   `json:"status_code"`     // HTTP response code, 0 if no response
	ResponseBody   string                `json:"response_body"`   // truncated response body for debugging
	ErrorMessage   string                `json:"error_message"`   // error details if failed
	Attempt        int                   `json:"attempt"`         // current attempt number (1-based)
	MaxAttempts    int                   `json:"max_attempts"`    // configured max attempts
	Signature      string                `json:"signature"`       // HMAC signature sent
	RequestHeaders map[string]string     `json:"request_headers"` // request headers sent (minus auth)
	DurationMs     int                   `json:"duration_ms"`     // request duration in milliseconds
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
	CompletedAt    time.Time             `json:"completed_at"` // when sent or permanently failed
}

// WebhookDeliveryStore provides CRUD operations for webhook delivery records.
type WebhookDeliveryStore struct {
	ts *TypedStore
}

// WebhookDeliverySummary is the bounded aggregate needed to seed runtime
// operational statistics after restart.
type WebhookDeliverySummary struct {
	TerminalFailed        int64
	LastSuccessAt         time.Time
	LastFailureAt         time.Time
	LastTerminalFailureAt time.Time
}

// NewWebhookDeliveryStore creates a new WebhookDeliveryStore.
func NewWebhookDeliveryStore(ts *TypedStore) *WebhookDeliveryStore {
	return &WebhookDeliveryStore{ts: ts}
}

// Create inserts a new delivery record. The store key includes the webhook ID
// prefix so that ListByWebhook can scan efficiently.
func (s *WebhookDeliveryStore) Create(ctx context.Context, d WebhookDelivery) error {
	key := WebhookDeliveryKey(d.WebhookID, d.ID)
	return s.ts.Put(ctx, NSWebhookDeliveries, key, d)
}

// Get returns a delivery by webhook ID and delivery ID.
func (s *WebhookDeliveryStore) Get(ctx context.Context, webhookID, deliveryID string) (*WebhookDelivery, error) {
	var d WebhookDelivery
	key := WebhookDeliveryKey(webhookID, deliveryID)
	if err := s.ts.Get(ctx, NSWebhookDeliveries, key, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Update persists changes to an existing delivery record.
func (s *WebhookDeliveryStore) Update(ctx context.Context, d WebhookDelivery) error {
	key := WebhookDeliveryKey(d.WebhookID, d.ID)
	return s.ts.Set(ctx, NSWebhookDeliveries, key, d)
}

// Delete removes a delivery record by webhook ID and delivery ID.
func (s *WebhookDeliveryStore) Delete(ctx context.Context, webhookID, deliveryID string) error {
	key := WebhookDeliveryKey(webhookID, deliveryID)
	return s.ts.Delete(ctx, NSWebhookDeliveries, key)
}

// ListByWebhook returns all delivery records for a given webhook ID, newest first.
func (s *WebhookDeliveryStore) ListByWebhook(ctx context.Context, webhookID string) ([]WebhookDelivery, error) {
	keys, err := s.ts.Scan(ctx, NSWebhookDeliveries, WebhookDeliveryKeyPrefix(webhookID))
	if err != nil {
		return nil, err
	}
	var deliveries []WebhookDelivery
	for _, k := range keys {
		var d WebhookDelivery
		if err := s.ts.Get(ctx, NSWebhookDeliveries, k, &d); err != nil {
			continue
		}
		deliveries = append(deliveries, d)
	}
	sortWebhookDeliveries(deliveries)
	return deliveries, nil
}

// ListPageByWebhook returns a bounded newest-first page. The cursor is the
// final delivery timestamp and ID from the preceding page. It remains correct
// for random durable event IDs and does not rely on key ordering.
func (s *WebhookDeliveryStore) ListPageByWebhook(ctx context.Context, webhookID string, before time.Time, beforeID string, limit int) ([]WebhookDelivery, int, bool, error) {
	if limit < 1 || limit > 100 {
		return nil, 0, false, fmt.Errorf("webhook delivery page limit must be between 1 and 100")
	}
	deliveries := make([]WebhookDelivery, 0, limit+1)
	total := 0
	err := s.ts.Store().Iterate(ctx, NSWebhookDeliveries, WebhookDeliveryKeyPrefix(webhookID), func(_ string, value []byte) (bool, error) {
		var delivery WebhookDelivery
		if err := json.Unmarshal(value, &delivery); err != nil {
			return false, err
		}
		total++
		at := webhookDeliveryTime(delivery)
		if !before.IsZero() && (!at.Before(before) && !(at.Equal(before) && delivery.ID < beforeID)) {
			return true, nil
		}
		deliveries = append(deliveries, delivery)
		if len(deliveries) > limit+1 {
			sortWebhookDeliveries(deliveries)
			deliveries = deliveries[:limit+1]
		}
		return true, nil
	})
	if err != nil {
		return nil, 0, false, err
	}
	sortWebhookDeliveries(deliveries)
	hasMore := len(deliveries) > limit
	if hasMore {
		deliveries = deliveries[:limit]
	}
	return deliveries, total, hasMore, nil
}

func sortWebhookDeliveries(deliveries []WebhookDelivery) {
	sort.Slice(deliveries, func(i, j int) bool {
		left, right := webhookDeliveryTime(deliveries[i]), webhookDeliveryTime(deliveries[j])
		if left.Equal(right) {
			return deliveries[i].ID > deliveries[j].ID
		}
		return left.After(right)
	})
}

func webhookDeliveryTime(delivery WebhookDelivery) time.Time {
	if !delivery.UpdatedAt.IsZero() {
		return delivery.UpdatedAt
	}
	return delivery.CreatedAt
}

// ListByWebhookAndEvent returns delivery records for a webhook+event combination.
func (s *WebhookDeliveryStore) ListByWebhookAndEvent(ctx context.Context, webhookID, event string) ([]WebhookDelivery, error) {
	all, err := s.ListByWebhook(ctx, webhookID)
	if err != nil {
		return nil, err
	}
	var filtered []WebhookDelivery
	for _, d := range all {
		if d.Event == event {
			filtered = append(filtered, d)
		}
	}
	return filtered, nil
}

// Summary scans retained attempt metadata without retaining response bodies.
// It is used once during dispatcher startup; live requests use cached stats.
func (s *WebhookDeliveryStore) Summary(ctx context.Context) (WebhookDeliverySummary, error) {
	var summary WebhookDeliverySummary
	err := s.ts.Store().Iterate(ctx, NSWebhookDeliveries, "", func(_ string, value []byte) (bool, error) {
		var delivery WebhookDelivery
		if err := json.Unmarshal(value, &delivery); err != nil {
			return false, err
		}
		switch delivery.Status {
		case WebhookDeliverySent:
			if delivery.UpdatedAt.After(summary.LastSuccessAt) {
				summary.LastSuccessAt = delivery.UpdatedAt
			}
		case WebhookDeliveryFailed:
			if delivery.UpdatedAt.After(summary.LastFailureAt) {
				summary.LastFailureAt = delivery.UpdatedAt
			}
			if !delivery.CompletedAt.IsZero() {
				summary.TerminalFailed++
				if delivery.CompletedAt.After(summary.LastTerminalFailureAt) {
					summary.LastTerminalFailureAt = delivery.CompletedAt
				}
			}
		}
		return true, nil
	})
	return summary, err
}
