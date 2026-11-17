package model

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// DefaultMaxRetries is the default maximum number of retry attempts for a webhook delivery.
const DefaultMaxRetries = 5

// DefaultBackoffMultiplier is the default multiplier for exponential backoff between retries.
const DefaultBackoffMultiplier = 2.0

// Webhook represents a configured webhook endpoint that receives HTTP
// notifications when specific events occur in the system.
type Webhook struct {
	ID string `json:"id"`
	// OwnerID makes a personal webhook: it receives only its owner's
	// account events and is managed by that user. Empty is a server webhook
	// managed by administrators.
	OwnerID string   `json:"owner_id,omitempty"`
	URL     string   `json:"url"`    // destination URL
	Events  []string `json:"events"` // event types to subscribe to (e.g. "message.received", "contact.created")
	Active  bool     `json:"active"` // whether the webhook is currently active
	Secret  string   `json:"secret"` // shared secret for signature verification

	// Accounts and Domains limit account events (such as message.received)
	// to these account IDs and recipient domains. A webhook with neither
	// receives only server-wide events: one subscription never sees every
	// mailbox's mail.
	Accounts []string `json:"accounts,omitempty"`
	Domains  []string `json:"domains,omitempty"`
	// Addresses limits account events to these exact envelope recipients
	// (an account address or a recipient alias such as domains@example.com).
	Addresses []string `json:"addresses,omitempty"`

	// Include lists optional message content added to message events:
	// WebhookIncludeHeaders, Text, HTML, Attachments and Raw.
	Include []string `json:"include,omitempty"`

	// Retry policy overrides (0 means use global defaults)
	MaxRetries        int     `json:"max_retries"`        // max retry attempts (0 = use default)
	BackoffMultiplier float64 `json:"backoff_multiplier"` // exponential backoff multiplier (0 = use default)

	// Retry tracking fields (populated by the dispatcher)
	RetryCount  int       `json:"retry_count"`   // number of failed delivery attempts for the current event
	LastError   string    `json:"last_error"`    // most recent error message
	NextRetryAt time.Time `json:"next_retry_at"` // when the next retry should occur

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	SecretRotatedAt     time.Time `json:"secret_rotated_at,omitzero"`
	SecretRotationCount int       `json:"secret_rotation_count,omitempty"`
}

// EffectiveMaxRetries returns the configured max retries, falling back to the default.
func (w Webhook) EffectiveMaxRetries() int {
	if w.MaxRetries > 0 {
		return w.MaxRetries
	}
	return DefaultMaxRetries
}

// EffectiveBackoffMultiplier returns the configured backoff multiplier, falling back to the default.
func (w Webhook) EffectiveBackoffMultiplier() float64 {
	if w.BackoffMultiplier > 0 {
		return w.BackoffMultiplier
	}
	return DefaultBackoffMultiplier
}

// SubscribesTo returns true if the webhook is subscribed to the given event type.
// Optional message content a webhook can ask for.
const (
	WebhookIncludeHeaders     = "headers"     // every header field: name -> values
	WebhookIncludeText        = "text"        // decoded plain-text body
	WebhookIncludeHTML        = "html"        // sanitized HTML body
	WebhookIncludeAttachments = "attachments" // attachment name, type, size
	WebhookIncludeRaw         = "raw"         // the RFC 5322 message, base64
)

// WebhookIncludeOptions lists the optional parts in documentation order.
var WebhookIncludeOptions = []string{WebhookIncludeHeaders, WebhookIncludeText, WebhookIncludeHTML, WebhookIncludeAttachments, WebhookIncludeRaw}

// IsWebhookIncludeOption reports whether key is an optional payload part.
func IsWebhookIncludeOption(key string) bool { return slices.Contains(WebhookIncludeOptions, key) }

// WebhookScope says whose data an event is about. The zero scope marks a
// server-wide event.
type WebhookScope struct {
	Account    string
	Recipients []string
}

// Matches reports whether the webhook may receive an event with scope:
// server-wide events go to every subscriber; account events only to
// webhooks whose account or recipient-domain filter matches.
func (w Webhook) Matches(scope WebhookScope) bool {
	if w.OwnerID != "" {
		// Personal: only the owner's own account events, optionally
		// narrowed to some of their addresses.
		if scope.Account == "" || scope.Account != w.OwnerID {
			return false
		}
		if len(w.Addresses) == 0 {
			return true
		}
		for _, recipient := range scope.Recipients {
			if slices.Contains(w.Addresses, strings.ToLower(strings.TrimSpace(recipient))) {
				return true
			}
		}
		return false
	}
	if scope.Account == "" && len(scope.Recipients) == 0 {
		return true
	}
	if scope.Account != "" && slices.Contains(w.Accounts, scope.Account) {
		return true
	}
	for _, recipient := range scope.Recipients {
		recipient = strings.ToLower(strings.TrimSpace(recipient))
		if slices.Contains(w.Addresses, recipient) {
			return true
		}
		if _, domain, ok := strings.Cut(recipient, "@"); ok && slices.Contains(w.Domains, domain) {
			return true
		}
	}
	return false
}

func (w Webhook) SubscribesTo(event string) bool {
	for _, e := range w.Events {
		if e == event {
			return true
		}
	}
	return false
}

// WebhookStore provides CRUD operations for Webhook entities.
type WebhookStore struct {
	ts       *TypedStore
	webhooks collection[Webhook]
}

// NewWebhookStore creates a new WebhookStore.
func NewWebhookStore(ts *TypedStore) *WebhookStore {
	return &WebhookStore{ts: ts, webhooks: newCollection[Webhook](ts, NSWebhooks)}
}

// Create inserts a new webhook. Returns store.ErrExists if the ID already exists.
func (s *WebhookStore) Create(ctx context.Context, wh Webhook) error {
	return s.webhooks.put(ctx, wh.ID, wh)
}

// Get returns a webhook by ID.
func (s *WebhookStore) Get(ctx context.Context, id string) (*Webhook, error) {
	wh, err := s.webhooks.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &wh, nil
}

// Update persists changes to an existing webhook.
func (s *WebhookStore) Update(ctx context.Context, wh Webhook) error {
	return s.webhooks.set(ctx, wh.ID, wh)
}

// UpdateIfUpdatedAt atomically applies an edit only when the caller observed
// the current webhook revision. Secret-rotation evidence is store-owned so an
// ordinary editor can never erase it.
func (s *WebhookStore) UpdateIfUpdatedAt(ctx context.Context, wh Webhook, expected time.Time) (*Webhook, error) {
	var updated *Webhook
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		current, err := s.Get(batchCtx, wh.ID)
		if err != nil {
			return err
		}
		if expected.IsZero() || !current.UpdatedAt.Equal(expected) {
			return store.ErrPreconditionFailed
		}
		wh.CreatedAt = current.CreatedAt
		wh.SecretRotatedAt = current.SecretRotatedAt
		wh.SecretRotationCount = current.SecretRotationCount
		wh.UpdatedAt = nextWebhookRevision(current.UpdatedAt)
		if err := s.webhooks.set(batchCtx, wh.ID, wh); err != nil {
			return err
		}
		copy := wh
		copy.Events = append([]string(nil), wh.Events...)
		updated = &copy
		return nil
	})
	return updated, err
}

// RotateSecret atomically replaces a webhook signing secret. The plain secret
// is returned only to the successful caller and is otherwise never projected.
func (s *WebhookStore) RotateSecret(ctx context.Context, id string, expected time.Time) (*Webhook, string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, "", fmt.Errorf("generate webhook signing secret: %w", err)
	}
	replacement := base64.RawURLEncoding.EncodeToString(random)
	var rotated *Webhook
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		current, err := s.Get(batchCtx, id)
		if err != nil {
			return err
		}
		if expected.IsZero() || !current.UpdatedAt.Equal(expected) {
			return store.ErrPreconditionFailed
		}
		now := nextWebhookRevision(current.UpdatedAt)
		current.Secret = replacement
		current.SecretRotatedAt = now
		current.SecretRotationCount++
		current.UpdatedAt = now
		if err := s.webhooks.set(batchCtx, id, *current); err != nil {
			return err
		}
		copy := *current
		copy.Events = append([]string(nil), current.Events...)
		rotated = &copy
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return rotated, replacement, nil
}

func nextWebhookRevision(previous time.Time) time.Time {
	now := time.Now().UTC()
	if !now.After(previous) {
		return previous.Add(time.Nanosecond)
	}
	return now
}

// Delete removes a webhook by ID.
func (s *WebhookStore) Delete(ctx context.Context, id string) error {
	return s.webhooks.delete(ctx, id)
}

// List returns all configured webhooks.
func (s *WebhookStore) List(ctx context.Context) ([]Webhook, error) {
	return s.webhooks.filter(ctx, keepAll)
}

// GenerateWebhookID creates a unique ID for a new webhook.
func GenerateWebhookID() string {
	return fmt.Sprintf("wh_%d", time.Now().UnixNano())
}
