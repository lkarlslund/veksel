package model

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	WebhookOutboxPending = "pending"
	WebhookOutboxLeased  = "leased"
)

// WebhookOutboxEntry is the durable, secret-free delivery envelope. Payload is
// deliberately kept outside WebhookDelivery, whose records are returned by
// administration APIs.
type WebhookOutboxEntry struct {
	ID            string          `json:"id"`
	EventID       string          `json:"event_id"`
	WebhookID     string          `json:"webhook_id"`
	Event         string          `json:"event"`
	Payload       json.RawMessage `json:"payload"`
	State         string          `json:"state"`
	Attempt       int             `json:"attempt"`
	MaxAttempts   int             `json:"max_attempts"`
	CreatedAt     time.Time       `json:"created_at"`
	NextAttemptAt time.Time       `json:"next_attempt_at"`
	LeaseUntil    time.Time       `json:"lease_until,omitzero"`
	LastError     string          `json:"last_error,omitempty"`
}

// WebhookOutboxStore persists delivery work independently of the process.
type WebhookOutboxStore struct {
	ts      *TypedStore
	entries collection[WebhookOutboxEntry]
}

func NewWebhookOutboxStore(ts *TypedStore) *WebhookOutboxStore {
	return &WebhookOutboxStore{ts: ts, entries: newCollection[WebhookOutboxEntry](ts, NSWebhookOutbox)}
}

func (s *WebhookOutboxStore) Create(ctx context.Context, entry WebhookOutboxEntry) error {
	return s.entries.put(ctx, entry.ID, entry)
}

// CreateBatch admits all destinations atomically on stores with batch support.
func (s *WebhookOutboxStore) CreateBatch(ctx context.Context, entries []WebhookOutboxEntry) error {
	return store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		for _, entry := range entries {
			if err := s.Create(batchCtx, entry); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *WebhookOutboxStore) Get(ctx context.Context, id string) (WebhookOutboxEntry, error) {
	return s.entries.get(ctx, id)
}

func (s *WebhookOutboxStore) Update(ctx context.Context, entry WebhookOutboxEntry) error {
	return s.entries.set(ctx, entry.ID, entry)
}

func (s *WebhookOutboxStore) Delete(ctx context.Context, id string) error {
	return s.entries.delete(ctx, id)
}

func (s *WebhookOutboxStore) List(ctx context.Context) ([]WebhookOutboxEntry, error) {
	entries, err := s.entries.list(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].NextAttemptAt.Equal(entries[j].NextAttemptAt) {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].NextAttemptAt.Before(entries[j].NextAttemptAt)
	})
	return entries, nil
}

// GenerateWebhookEventID returns an unpredictable identity shared by every
// destination of one admitted event and retained across retries.
func GenerateWebhookEventID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate webhook event ID: %w", err)
	}
	return "evt_" + hex.EncodeToString(value[:]), nil
}
