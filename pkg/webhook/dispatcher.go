// Package webhook provides durable asynchronous webhook dispatch with retry,
// HMAC signatures, delivery tracking, and restart replay.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lkarlslund/veksel/pkg/config"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/netguard"
)

var log = logpkg.For(logpkg.ModuleWebhook)

// maxOutboxPayloadBytes bounds one stored event payload. Summary events are
// small; a webhook that asks for the raw message can carry up to
// MaxRawMessageBytes of it, base64-encoded.
const maxOutboxPayloadBytes = 24 << 20

// MaxRawMessageBytes is the largest message a webhook receives in "raw";
// a larger one is announced with raw_omitted instead.
const MaxRawMessageBytes = 16 << 20

// RetryPolicy defines the retry behavior for failed webhook deliveries.
type RetryPolicy struct {
	MaxRetries        int
	BaseDelay         time.Duration
	BackoffMultiplier float64
	Timeout           time.Duration
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxRetries: 5, BaseDelay: time.Second, BackoffMultiplier: 2, Timeout: 10 * time.Second}
}

func (p RetryPolicy) DelayForAttempt(attempt int) time.Duration {
	if attempt < 1 {
		return p.BaseDelay
	}
	delay := float64(p.BaseDelay)
	for i := 1; i < attempt; i++ {
		delay *= p.BackoffMultiplier
	}
	return time.Duration(delay)
}

type WebhookPayload struct {
	Event     string `json:"event"`
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Payload   any    `json:"payload"`
}

// Stats is a constant-time, payload-free view of dispatcher pressure.
type Stats struct {
	Pending                 int       `json:"pending"`
	InFlight                int       `json:"in_flight"`
	Retrying                int       `json:"retrying"`
	TerminalFailed          int64     `json:"terminal_failed"`
	OldestPendingAgeSeconds float64   `json:"oldest_pending_age_seconds"`
	LastSuccessAt           time.Time `json:"last_success_at,omitzero"`
	LastFailureAt           time.Time `json:"last_failure_at,omitzero"`
	LastTerminalFailureAt   time.Time `json:"last_terminal_failure_at,omitzero"`
	ObservedAt              time.Time `json:"observed_at"`
	Error                   string    `json:"error,omitempty"`
}

type trackedOutbox struct {
	state     string
	attempt   int
	createdAt time.Time
}

// Dispatcher durably admits work before waking its single claim owner. The
// worker is intentionally single-process serialized; leases make an abrupt
// stop replayable by a replacement dispatcher.
type Dispatcher struct {
	mu       sync.Mutex
	admitMu  sync.Mutex
	policyMu sync.RWMutex
	policy   RetryPolicy
	client   *http.Client
	// allowPrivate lets client reach loopback, private, and link-local
	// addresses; deliveries refuse them by default.
	allowPrivate atomic.Bool
	// privateDestinations are internal address:port destinations server
	// webhooks may reach.
	privateDestinations atomic.Pointer[[]config.Destination]
	personalClient      *http.Client
	whStore             *model.WebhookStore
	delStore            *model.WebhookDeliveryStore
	outbox              *model.WebhookOutboxStore
	wake                chan struct{}
	running             bool
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	statsMu             sync.RWMutex
	stats               Stats
	tracked             map[string]trackedOutbox
	oldestAt            time.Time
}

func New(whStore *model.WebhookStore, delStore *model.WebhookDeliveryStore, outbox *model.WebhookOutboxStore, policy RetryPolicy) *Dispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{
		policy: policy, whStore: whStore,
		delStore: delStore, outbox: outbox, wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel,
		tracked: make(map[string]trackedOutbox),
	}
	d.client = (&netguard.Dialer{AllowPrivate: d.allowPrivate.Load, AllowDestination: d.allowedDestination}).Client(0)
	// Personal webhooks are created by any user: they reach public
	// addresses only, whatever the server-webhook settings allow.
	d.personalClient = (&netguard.Dialer{}).Client(0)
	return d
}

// SetAllowPrivateNetworks lets deliveries reach subscriptions on loopback,
// private, and link-local addresses (outbound_http_allow_private_networks).
func (d *Dispatcher) SetAllowPrivateNetworks(allow bool) { d.allowPrivate.Store(allow) }

// SetPrivateDestinations sets the internal destinations server webhooks
// may reach (webhook_private_destinations).
func (d *Dispatcher) SetPrivateDestinations(destinations []config.Destination) {
	d.privateDestinations.Store(&destinations)
}

func (d *Dispatcher) allowedDestination(address netip.AddrPort) bool {
	destinations := d.privateDestinations.Load()
	if destinations == nil {
		return false
	}
	for _, destination := range *destinations {
		if destination.Allows(address) {
			return true
		}
	}
	return false
}

// Policy returns the retry policy applied to new admissions and attempts.
func (d *Dispatcher) Policy() RetryPolicy {
	d.policyMu.RLock()
	defer d.policyMu.RUnlock()
	return d.policy
}

// SetPolicy replaces the retry policy live. Events admitted afterwards take
// their attempt budget from the new policy, and every attempt that starts
// afterwards uses its timeout and backoff; an attempt already in flight
// finishes under the policy it started with.
func (d *Dispatcher) SetPolicy(policy RetryPolicy) {
	d.policyMu.Lock()
	d.policy = policy
	d.policyMu.Unlock()
}

func (d *Dispatcher) Start() {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.wg.Add(1)
	d.admitMu.Lock()
	if err := d.rebuildStats(); err != nil {
		d.statsMu.Lock()
		d.stats.Error = boundedError(err)
		d.stats.ObservedAt = time.Now().UTC()
		d.statsMu.Unlock()
		log.Error("rebuild webhook operational statistics", "error", err)
	}
	d.admitMu.Unlock()
	go d.worker()
	d.mu.Unlock()
}

func (d *Dispatcher) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	d.cancel()
	d.mu.Unlock()
	d.wg.Wait()
}

// Queue persists one immutable envelope per active matching subscription. A
// nil error means work survived process loss; delivery itself remains async.
// Subscribed reports whether an active webhook subscribes to event, so a
// caller can tell a channel that delivers from one that drops everything.
func (d *Dispatcher) Subscribed(event string) bool {
	webhooks, err := d.whStore.List(d.ctx)
	if err != nil {
		return false
	}
	for _, webhook := range webhooks {
		if webhook.Active && webhook.SubscribesTo(event) {
			return true
		}
	}
	return false
}

// Queue admits a server-wide event for every subscriber.
func (d *Dispatcher) Queue(event string, payload any) error {
	return d.QueueFor(event, payload, model.WebhookScope{})
}

// Includes reports which optional payload parts (model.WebhookInclude*)
// the subscribers of event with scope asked for, so the caller only
// builds those.
func (d *Dispatcher) Includes(event string, scope model.WebhookScope) map[string]bool {
	webhooks, err := d.whStore.List(d.ctx)
	if err != nil {
		return nil
	}
	wanted := map[string]bool{}
	for _, webhook := range webhooks {
		if webhook.Active && webhook.SubscribesTo(event) && webhook.Matches(scope) {
			for _, part := range webhook.Include {
				wanted[part] = true
			}
		}
	}
	return wanted
}

// QueueFor admits an event about scope's account: only subscribers whose
// account or domain filter matches receive it. When payload is a map, its
// optional parts (model.WebhookIncludeOptions) are kept only for webhooks
// that include them.
func (d *Dispatcher) QueueFor(event string, payload any, scope model.WebhookScope) error {
	d.admitMu.Lock()
	defer d.admitMu.Unlock()
	event = strings.TrimSpace(event)
	if event == "" {
		return errors.New("webhook event is required")
	}
	encode := func(webhook model.Webhook) ([]byte, error) {
		value := payload
		if fields, ok := payload.(map[string]any); ok {
			trimmed := make(map[string]any, len(fields))
			for key, field := range fields {
				part := strings.TrimSuffix(key, "_omitted")
				if model.IsWebhookIncludeOption(part) && !slices.Contains(webhook.Include, part) {
					continue
				}
				trimmed[key] = field
			}
			value = trimmed
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("marshal webhook payload: %w", err)
		}
		if len(encoded) > maxOutboxPayloadBytes {
			return nil, fmt.Errorf("webhook payload exceeds %d bytes", maxOutboxPayloadBytes)
		}
		return encoded, nil
	}
	if _, err := encode(model.Webhook{}); err != nil {
		return err
	}
	webhooks, err := d.whStore.List(d.ctx)
	if err != nil {
		return fmt.Errorf("list webhook subscriptions: %w", err)
	}
	eventID, err := model.GenerateWebhookEventID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	policy := d.Policy()
	entries := make([]model.WebhookOutboxEntry, 0, len(webhooks))
	for _, webhook := range webhooks {
		if !webhook.Active || !webhook.SubscribesTo(event) || !webhook.Matches(scope) {
			continue
		}
		maxRetries := policy.MaxRetries
		if webhook.MaxRetries > 0 {
			maxRetries = webhook.MaxRetries
		}
		encoded, err := encode(webhook)
		if err != nil {
			return err
		}
		entries = append(entries, model.WebhookOutboxEntry{
			ID: eventID + ":" + webhook.ID, EventID: eventID, WebhookID: webhook.ID,
			Event: event, Payload: encoded, State: model.WebhookOutboxPending,
			MaxAttempts: maxRetries + 1, CreatedAt: now, NextAttemptAt: now,
		})
	}
	if len(entries) == 0 {
		return nil
	}
	if err := d.outbox.CreateBatch(d.ctx, entries); err != nil {
		return fmt.Errorf("admit webhook event: %w", err)
	}
	d.trackAdded(entries)
	select {
	case d.wake <- struct{}{}:
	default:
	}
	return nil
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := d.processDue(); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("process durable webhook outbox", "error", err)
		}
		select {
		case <-d.ctx.Done():
			return
		case <-d.wake:
		case <-ticker.C:
		}
	}
}

func (d *Dispatcher) processDue() error {
	entries, err := d.outbox.List(d.ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, entry := range entries {
		if entry.NextAttemptAt.After(now) || entry.State == model.WebhookOutboxLeased && entry.LeaseUntil.After(now) {
			continue
		}
		if err := d.processEntry(entry, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dispatcher) processEntry(entry model.WebhookOutboxEntry, now time.Time) error {
	policy := d.Policy()
	entry.State = model.WebhookOutboxLeased
	entry.LeaseUntil = now.Add(policy.Timeout + 30*time.Second)
	if err := d.outbox.Update(d.ctx, entry); err != nil {
		return fmt.Errorf("claim webhook outbox %s: %w", entry.ID, err)
	}
	d.trackChanged(entry)
	webhook, err := d.whStore.Get(d.ctx, entry.WebhookID)
	if err != nil || !webhook.Active {
		reason := "webhook was removed before delivery"
		if err == nil {
			reason = "webhook was disabled before delivery"
		}
		if recordErr := d.recordTerminal(entry, reason, now); recordErr != nil {
			return recordErr
		}
		if err := d.outbox.Delete(d.ctx, entry.ID); err != nil {
			return err
		}
		d.trackTerminal(entry.ID, now)
		return nil
	}
	attempt := entry.Attempt + 1
	deliveryID := fmt.Sprintf("%s-%03d", entry.ID, attempt)
	delivery, sendErr := d.send(d.ctx, policy.Timeout, webhook, entry.EventID, entry.Event, entry.Payload, attempt, entry.MaxAttempts, entry.CreatedAt, deliveryID)
	if sendErr == nil {
		log.Info("webhook delivered successfully", "webhook_id", webhook.ID, "event_id", entry.EventID, "attempt", attempt)
		if err := d.outbox.Delete(d.ctx, entry.ID); err != nil {
			return err
		}
		d.trackSuccess(entry.ID, delivery.UpdatedAt)
		return nil
	}
	d.trackAttemptFailure(delivery)
	if attempt >= entry.MaxAttempts {
		if delivery == nil {
			if recordErr := d.recordTerminal(entry, boundedError(sendErr), time.Now().UTC()); recordErr != nil {
				return recordErr
			}
			if err := d.outbox.Delete(d.ctx, entry.ID); err != nil {
				return err
			}
			d.trackTerminal(entry.ID, time.Now().UTC())
			return nil
		}
		delivery.CompletedAt = time.Now().UTC()
		if err := d.delStore.Update(d.ctx, *delivery); err != nil {
			return fmt.Errorf("complete terminal webhook delivery: %w", err)
		}
		log.Error("webhook delivery attempts exhausted", "webhook_id", webhook.ID, "event_id", entry.EventID, "error", sendErr)
		if err := d.outbox.Delete(d.ctx, entry.ID); err != nil {
			return err
		}
		d.trackTerminal(entry.ID, delivery.UpdatedAt)
		return nil
	}
	entry.State, entry.Attempt, entry.LeaseUntil = model.WebhookOutboxPending, attempt, time.Time{}
	if webhook.BackoffMultiplier > 0 {
		policy.BackoffMultiplier = webhook.BackoffMultiplier
	}
	entry.NextAttemptAt = time.Now().UTC().Add(policy.DelayForAttempt(attempt))
	entry.LastError = boundedError(sendErr)
	if err := d.outbox.Update(d.ctx, entry); err != nil {
		return err
	}
	d.trackChanged(entry)
	return nil
}

// Snapshot returns cached counters and computes age from one retained
// timestamp. It performs no store operations or payload decoding.
func (d *Dispatcher) Snapshot(now time.Time) Stats {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	d.statsMu.RLock()
	stats := d.stats
	oldest := d.oldestAt
	d.statsMu.RUnlock()
	if !oldest.IsZero() {
		stats.OldestPendingAgeSeconds = now.Sub(oldest).Seconds()
	}
	stats.OldestPendingAgeSeconds = max(0, stats.OldestPendingAgeSeconds)
	return stats
}

func (d *Dispatcher) rebuildStats() error {
	entries, err := d.outbox.List(d.ctx)
	if err != nil {
		return err
	}
	summary, err := d.delStore.Summary(d.ctx)
	if err != nil {
		return err
	}
	d.statsMu.Lock()
	d.tracked = make(map[string]trackedOutbox, len(entries))
	for _, entry := range entries {
		d.tracked[entry.ID] = trackedOutbox{state: entry.State, attempt: entry.Attempt, createdAt: entry.CreatedAt}
	}
	d.stats = Stats{
		TerminalFailed: summary.TerminalFailed, LastSuccessAt: summary.LastSuccessAt,
		LastFailureAt: summary.LastFailureAt, LastTerminalFailureAt: summary.LastTerminalFailureAt,
	}
	d.stats.Error = ""
	d.recalculateLocked(time.Now().UTC())
	d.statsMu.Unlock()
	return nil
}

func (d *Dispatcher) trackAdded(entries []model.WebhookOutboxEntry) {
	d.statsMu.Lock()
	for _, entry := range entries {
		d.tracked[entry.ID] = trackedOutbox{state: entry.State, attempt: entry.Attempt, createdAt: entry.CreatedAt}
	}
	d.recalculateLocked(time.Now().UTC())
	d.statsMu.Unlock()
}

func (d *Dispatcher) trackChanged(entry model.WebhookOutboxEntry) {
	d.statsMu.Lock()
	d.tracked[entry.ID] = trackedOutbox{state: entry.State, attempt: entry.Attempt, createdAt: entry.CreatedAt}
	d.recalculateLocked(time.Now().UTC())
	d.statsMu.Unlock()
}

func (d *Dispatcher) trackSuccess(id string, at time.Time) {
	d.statsMu.Lock()
	delete(d.tracked, id)
	if at.After(d.stats.LastSuccessAt) {
		d.stats.LastSuccessAt = at
	}
	d.recalculateLocked(time.Now().UTC())
	d.statsMu.Unlock()
}

func (d *Dispatcher) trackAttemptFailure(delivery *model.WebhookDelivery) {
	if delivery == nil {
		return
	}
	d.statsMu.Lock()
	if delivery.UpdatedAt.After(d.stats.LastFailureAt) {
		d.stats.LastFailureAt = delivery.UpdatedAt
	}
	d.statsMu.Unlock()
}

func (d *Dispatcher) trackTerminal(id string, at time.Time) {
	d.statsMu.Lock()
	delete(d.tracked, id)
	d.stats.TerminalFailed++
	if at.After(d.stats.LastFailureAt) {
		d.stats.LastFailureAt = at
	}
	if at.After(d.stats.LastTerminalFailureAt) {
		d.stats.LastTerminalFailureAt = at
	}
	d.recalculateLocked(time.Now().UTC())
	d.statsMu.Unlock()
}

func (d *Dispatcher) recalculateLocked(now time.Time) {
	d.stats.Pending, d.stats.InFlight, d.stats.Retrying = 0, 0, 0
	var oldest time.Time
	for _, entry := range d.tracked {
		if oldest.IsZero() || entry.createdAt.Before(oldest) {
			oldest = entry.createdAt
		}
		if entry.state == model.WebhookOutboxLeased {
			d.stats.InFlight++
		} else if entry.attempt > 0 {
			d.stats.Retrying++
		} else {
			d.stats.Pending++
		}
	}
	d.stats.OldestPendingAgeSeconds = 0
	d.oldestAt = oldest
	if !oldest.IsZero() {
		d.stats.OldestPendingAgeSeconds = max(0, now.Sub(oldest).Seconds())
	}
	d.stats.ObservedAt = now
}

func (d *Dispatcher) recordTerminal(entry model.WebhookOutboxEntry, reason string, now time.Time) error {
	delivery := model.WebhookDelivery{
		ID: entry.ID + "-terminal", WebhookID: entry.WebhookID, Event: entry.Event,
		Status: model.WebhookDeliveryFailed, ErrorMessage: reason, Attempt: entry.Attempt,
		MaxAttempts: entry.MaxAttempts, CreatedAt: entry.CreatedAt, UpdatedAt: now, CompletedAt: now,
	}
	return d.delStore.Update(d.ctx, delivery)
}

func (d *Dispatcher) send(ctx context.Context, timeout time.Duration, webhook *model.Webhook, eventID, event string, payload json.RawMessage, attempt, maxAttempts int, createdAt time.Time, deliveryID string) (*model.WebhookDelivery, error) {
	start := time.Now().UTC()
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("decode admitted webhook payload: %w", err)
	}
	body, err := json.Marshal(WebhookPayload{Event: event, ID: eventID, Timestamp: createdAt.UTC().Format(time.RFC3339), Payload: decoded})
	if err != nil {
		return nil, fmt.Errorf("marshal webhook envelope: %w", err)
	}
	signature := computeHMAC(webhook.Secret, body)
	delivery := model.WebhookDelivery{
		ID: deliveryID, WebhookID: webhook.ID, Event: event, URL: webhook.URL,
		Status: model.WebhookDeliveryPending, Attempt: attempt, MaxAttempts: maxAttempts, Signature: signature,
		RequestHeaders: map[string]string{"Content-Type": "application/json", "X-Webhook-Signature": signature, "X-Webhook-Event": event, "X-Webhook-ID": eventID},
		CreatedAt:      start, UpdatedAt: start,
	}
	if err := d.delStore.Update(ctx, delivery); err != nil {
		return nil, fmt.Errorf("persist pending webhook attempt: %w", err)
	}
	requestCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, webhook.URL, bytes.NewReader(body))
	if err != nil {
		delivery.Status, delivery.ErrorMessage = model.WebhookDeliveryFailed, boundedError(err)
		delivery.UpdatedAt = time.Now().UTC()
		_ = d.delStore.Update(ctx, delivery)
		return &delivery, fmt.Errorf("create webhook request: %w", err)
	}
	for key, value := range delivery.RequestHeaders {
		req.Header.Set(key, value)
	}
	client := d.client
	if webhook.OwnerID != "" {
		client = d.personalClient
	}
	response, err := client.Do(req)
	delivery.DurationMs, delivery.UpdatedAt = int(time.Since(start).Milliseconds()), time.Now().UTC()
	if err != nil {
		delivery.Status, delivery.ErrorMessage = model.WebhookDeliveryFailed, boundedError(err)
		_ = d.delStore.Update(ctx, delivery)
		return &delivery, fmt.Errorf("post webhook: %w", err)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	if readErr != nil {
		delivery.Status, delivery.ErrorMessage = model.WebhookDeliveryFailed, boundedError(readErr)
		_ = d.delStore.Update(ctx, delivery)
		return &delivery, fmt.Errorf("read webhook response: %w", readErr)
	}
	delivery.StatusCode, delivery.ResponseBody = response.StatusCode, string(responseBody)
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		delivery.Status, delivery.CompletedAt = model.WebhookDeliverySent, time.Now().UTC()
		if err := d.delStore.Update(ctx, delivery); err != nil {
			return &delivery, fmt.Errorf("persist successful webhook attempt: %w", err)
		}
		return &delivery, nil
	}
	delivery.Status = model.WebhookDeliveryFailed
	delivery.ErrorMessage = boundedError(fmt.Errorf("http %d: %s", response.StatusCode, responseBody))
	_ = d.delStore.Update(ctx, delivery)
	return &delivery, fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, err.Error())
	runes := []rune(value)
	if len(runes) > 512 {
		runes = runes[:512]
	}
	return string(runes)
}

func computeHMAC(secret string, body []byte) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (d *Dispatcher) Test(ctx context.Context, webhookID string) (*model.WebhookDelivery, error) {
	webhook, err := d.whStore.Get(ctx, webhookID)
	if err != nil {
		return nil, fmt.Errorf("webhook not found: %w", err)
	}
	eventID, err := model.GenerateWebhookEventID()
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]string{"message": "This is a test webhook from Veksel.", "webhook_id": webhookID})
	now := time.Now().UTC()
	delivery, err := d.send(ctx, d.Policy().Timeout, webhook, eventID, "webhook.test", payload, 1, 1, now, eventID+":"+webhookID+"-test")
	return delivery, err
}
