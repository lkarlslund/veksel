package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// TestRetryPolicy_DelayForAttempt verifies exponential backoff calculation.
func TestRetryPolicy_DelayForAttempt(t *testing.T) {
	p := RetryPolicy{
		BaseDelay:         time.Second,
		BackoffMultiplier: 2.0,
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, time.Second},      // attempt 0 = base delay
		{1, time.Second},      // attempt 1 = base delay
		{2, 2 * time.Second},  // attempt 2 = base * 2
		{3, 4 * time.Second},  // attempt 3 = base * 4
		{4, 8 * time.Second},  // attempt 4 = base * 8
		{5, 16 * time.Second}, // attempt 5 = base * 16
	}

	for _, tt := range tests {
		delay := p.DelayForAttempt(tt.attempt)
		if delay != tt.expected {
			t.Errorf("DelayForAttempt(%d) = %v, want %v", tt.attempt, delay, tt.expected)
		}
	}
}

// TestRetryPolicy_DelayForAttempt_CustomMultiplier verifies custom multiplier.
func TestRetryPolicy_DelayForAttempt_CustomMultiplier(t *testing.T) {
	p := RetryPolicy{
		BaseDelay:         500 * time.Millisecond,
		BackoffMultiplier: 3.0,
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 500 * time.Millisecond},
		{2, 1500 * time.Millisecond},
		{3, 4500 * time.Millisecond},
	}

	for _, tt := range tests {
		delay := p.DelayForAttempt(tt.attempt)
		if delay != tt.expected {
			t.Errorf("DelayForAttempt(%d) = %v, want %v", tt.attempt, delay, tt.expected)
		}
	}
}

// TestComputeHMAC verifies HMAC-SHA256 signature generation.
func TestComputeHMAC(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"event":"test"}`)

	sig := computeHMAC(secret, body)

	// Verify the actual HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != expected {
		t.Errorf("computeHMAC() = %s, want %s", sig, expected)
	}
}

// TestComputeHMAC_EmptySecret verifies empty secret returns empty signature.
func TestComputeHMAC_EmptySecret(t *testing.T) {
	sig := computeHMAC("", []byte("test"))
	if sig != "" {
		t.Errorf("computeHMAC with empty secret should return empty string, got: %s", sig)
	}
}

// TestWebhookPayload_Marshal verifies the webhook payload JSON structure.
func TestWebhookPayload_Marshal(t *testing.T) {
	wp := WebhookPayload{
		Event:     "message.received",
		ID:        "evt_123",
		Timestamp: "2024-01-01T00:00:00Z",
		Payload:   map[string]string{"key": "value"},
	}

	data, err := json.Marshal(wp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded WebhookPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Event != wp.Event {
		t.Errorf("Event = %s, want %s", decoded.Event, wp.Event)
	}
	if decoded.ID != wp.ID {
		t.Errorf("ID = %s, want %s", decoded.ID, wp.ID)
	}
}

// TestDefaultRetryPolicy verifies default values.
func TestDefaultRetryPolicy(t *testing.T) {
	p := DefaultRetryPolicy()
	if p.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", p.MaxRetries)
	}
	if p.BaseDelay != time.Second {
		t.Errorf("BaseDelay = %v, want 1s", p.BaseDelay)
	}
	if p.BackoffMultiplier != 2.0 {
		t.Errorf("BackoffMultiplier = %f, want 2.0", p.BackoffMultiplier)
	}
	if p.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", p.Timeout)
	}
}

// newTestDispatcher returns a dispatcher that may reach the loopback test
// servers these tests deliver to.
func newTestDispatcher(whStore *model.WebhookStore, delStore *model.WebhookDeliveryStore, outbox *model.WebhookOutboxStore, policy RetryPolicy) *Dispatcher {
	d := New(whStore, delStore, outbox, policy)
	d.SetAllowPrivateNetworks(true)
	return d
}

func TestDispatcherRefusesPrivateNetworksUnlessAllowed(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	whStore, delStore, outbox := newTestStores(t)
	if err := whStore.Create(t.Context(), model.Webhook{ID: "internal", URL: server.URL, Events: []string{"*"}, Active: true, Secret: "s"}); err != nil {
		t.Fatal(err)
	}
	d := New(whStore, delStore, outbox, DefaultRetryPolicy())
	result, err := d.Test(t.Context(), "internal")
	if err == nil || received.Load() != 0 || result == nil || !strings.Contains(result.ErrorMessage, "private") {
		t.Fatalf("loopback delivery err = %v received = %d result = %+v", err, received.Load(), result)
	}
	d.SetAllowPrivateNetworks(true)
	if result, err := d.Test(t.Context(), "internal"); err != nil || received.Load() != 1 || result.Status != model.WebhookDeliverySent {
		t.Fatalf("allowed delivery err = %v received = %d result = %+v", err, received.Load(), result)
	}
}

// TestDispatcher_Test verifies the Test method sends a request to the webhook URL.
func TestDispatcher_Test(t *testing.T) {
	received := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Webhook-Event") != "webhook.test" {
			t.Errorf("expected X-Webhook-Event: webhook.test, got %s", r.Header.Get("X-Webhook-Event"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	// Create test stores
	whStore, delStore, outbox := newTestStores(t)

	// Create a webhook
	wh := model.Webhook{
		ID:     "test-wh",
		URL:    server.URL,
		Events: []string{"message.received"},
		Active: true,
		Secret: "test-secret",
	}
	if err := whStore.Create(context.Background(), wh); err != nil {
		t.Fatalf("failed to create webhook: %v", err)
	}

	// Create dispatcher
	d := newTestDispatcher(whStore, delStore, outbox, DefaultRetryPolicy())

	// Test the webhook
	result, err := d.Test(context.Background(), "test-wh")
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if !received {
		t.Error("expected webhook to be called")
	}
}

// TestDispatcher_Test_Failed verifies Test returns error on HTTP failure.
func TestDispatcher_Test_Failed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal error`))
	}))
	defer server.Close()

	whStore, delStore, outbox := newTestStores(t)

	wh := model.Webhook{
		ID:     "test-wh-fail",
		URL:    server.URL,
		Events: []string{"message.received"},
		Active: true,
	}
	if err := whStore.Create(context.Background(), wh); err != nil {
		t.Fatalf("failed to create webhook: %v", err)
	}

	d := newTestDispatcher(whStore, delStore, outbox, DefaultRetryPolicy())
	_, err := d.Test(context.Background(), "test-wh-fail")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

// TestDispatcher_Test_NotFound verifies Test returns error for unknown webhook.
func TestDispatcher_Test_NotFound(t *testing.T) {
	whStore, delStore, outbox := newTestStores(t)
	d := newTestDispatcher(whStore, delStore, outbox, DefaultRetryPolicy())
	_, err := d.Test(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent webhook")
	}
}

// TestDispatcher_Queue verifies Queue finds active webhooks subscribed to an event.
func TestDispatcher_Queue(t *testing.T) {
	var delivered atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	whStore, delStore, outbox := newTestStores(t)

	// Create active webhook subscribed to message.received
	wh1 := model.Webhook{
		ID:     "wh-active",
		URL:    server.URL,
		Events: []string{"message.received"},
		Active: true,
	}
	if err := whStore.Create(context.Background(), wh1); err != nil {
		t.Fatalf("failed to create webhook: %v", err)
	}

	// Create inactive webhook (should not be called)
	wh2 := model.Webhook{
		ID:     "wh-inactive",
		URL:    server.URL,
		Events: []string{"message.received"},
		Active: false,
	}
	if err := whStore.Create(context.Background(), wh2); err != nil {
		t.Fatalf("failed to create webhook: %v", err)
	}

	// Create webhook with different event (should not be called)
	wh3 := model.Webhook{
		ID:     "wh-different-event",
		URL:    server.URL,
		Events: []string{"contact.created"},
		Active: true,
	}
	if err := whStore.Create(context.Background(), wh3); err != nil {
		t.Fatalf("failed to create webhook: %v", err)
	}

	d := newTestDispatcher(whStore, delStore, outbox, DefaultRetryPolicy())
	d.Start()
	defer d.Stop()

	// Queue the event
	if err := d.Queue("message.received", map[string]string{"test": "data"}); err != nil {
		t.Fatal(err)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	if got := delivered.Load(); got != 1 {
		t.Errorf("expected 1 delivery, got %d", got)
	}
}

func TestDispatcherReplaysAdmittedWorkAfterRestart(t *testing.T) {
	received := make(chan WebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload WebhookPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	webhooks, deliveries, outbox := newTestStores(t)
	if err := webhooks.Create(t.Context(), model.Webhook{ID: "restart", URL: server.URL, Events: []string{"health.alert.opened"}, Active: true}); err != nil {
		t.Fatal(err)
	}
	beforeRestart := newTestDispatcher(webhooks, deliveries, outbox, DefaultRetryPolicy())
	if err := beforeRestart.Queue("health.alert.opened", map[string]string{"component": "smtp"}); err != nil {
		t.Fatal(err)
	}
	entries, err := outbox.List(t.Context())
	if err != nil || len(entries) != 1 || entries[0].State != model.WebhookOutboxPending {
		t.Fatalf("admitted outbox=%#v err=%v", entries, err)
	}
	afterRestart := newTestDispatcher(webhooks, deliveries, outbox, DefaultRetryPolicy())
	afterRestart.Start()
	defer afterRestart.Stop()
	select {
	case payload := <-received:
		if payload.ID != entries[0].EventID || payload.Event != "health.alert.opened" {
			t.Fatalf("payload=%#v entry=%#v", payload, entries[0])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("restarted dispatcher did not replay admitted work")
	}
	waitFor(t, 3*time.Second, func() bool {
		remaining, listErr := outbox.List(t.Context())
		return listErr == nil && len(remaining) == 0
	})
}

func TestDispatcherRetriesWithStableEventIdentity(t *testing.T) {
	requests := make(chan WebhookPayload, 2)
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload WebhookPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		requests <- payload
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	webhooks, deliveries, outbox := newTestStores(t)
	if err := webhooks.Create(t.Context(), model.Webhook{ID: "retry", URL: server.URL, Events: []string{"message.received"}, Active: true, MaxRetries: 2}); err != nil {
		t.Fatal(err)
	}
	policy := DefaultRetryPolicy()
	policy.BaseDelay = 10 * time.Millisecond
	dispatcher := newTestDispatcher(webhooks, deliveries, outbox, policy)
	dispatcher.Start()
	defer dispatcher.Stop()
	if err := dispatcher.Queue("message.received", map[string]string{"id": "one"}); err != nil {
		t.Fatal(err)
	}
	first, second := <-requests, <-requests
	if first.ID == "" || first.ID != second.ID || first.Timestamp != second.Timestamp {
		t.Fatalf("retry identities changed: first=%#v second=%#v", first, second)
	}
	waitFor(t, 3*time.Second, func() bool {
		records, listErr := deliveries.ListByWebhook(t.Context(), "retry")
		return listErr == nil && len(records) == 2 && records[0].Status == model.WebhookDeliverySent
	})
}

func TestDispatcherReclaimsExpiredLease(t *testing.T) {
	delivered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	webhooks, deliveries, outbox := newTestStores(t)
	if err := webhooks.Create(t.Context(), model.Webhook{ID: "leased", URL: server.URL, Active: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := outbox.Create(t.Context(), model.WebhookOutboxEntry{
		ID: "evt_lease:leased", EventID: "evt_lease", WebhookID: "leased", Event: "test",
		Payload: json.RawMessage(`{"value":1}`), State: model.WebhookOutboxLeased,
		MaxAttempts: 2, CreatedAt: now.Add(-time.Minute), NextAttemptAt: now.Add(-time.Minute), LeaseUntil: now.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(webhooks, deliveries, outbox, DefaultRetryPolicy())
	dispatcher.Start()
	defer dispatcher.Stop()
	select {
	case <-delivered:
	case <-time.After(3 * time.Second):
		t.Fatal("expired webhook lease was not reclaimed")
	}
}

func TestDispatcherSnapshotRebuildsRetryPressureAfterRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	webhooks, deliveries, outbox := newTestStores(t)
	if err := webhooks.Create(t.Context(), model.Webhook{ID: "pressure", URL: server.URL, Events: []string{"event"}, Active: true}); err != nil {
		t.Fatal(err)
	}
	policy := DefaultRetryPolicy()
	policy.BaseDelay = time.Hour
	first := newTestDispatcher(webhooks, deliveries, outbox, policy)
	first.Start()
	if err := first.Queue("event", map[string]string{"value": "one"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool { return first.Snapshot(time.Now()).Retrying == 1 })
	before := first.Snapshot(time.Now().Add(time.Second))
	first.Stop()
	if before.Pending != 0 || before.InFlight != 0 || before.Retrying != 1 || before.OldestPendingAgeSeconds < .9 || before.LastFailureAt.IsZero() {
		t.Fatalf("pre-restart stats = %+v", before)
	}
	second := newTestDispatcher(webhooks, deliveries, outbox, policy)
	second.Start()
	defer second.Stop()
	after := second.Snapshot(time.Now().Add(time.Second))
	if after.Retrying != 1 || after.OldestPendingAgeSeconds < .9 || after.LastFailureAt.IsZero() {
		t.Fatalf("rebuilt stats = %+v", after)
	}
}

func TestDispatcherSnapshotTracksTerminalFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	webhooks, deliveries, outbox := newTestStores(t)
	if err := webhooks.Create(t.Context(), model.Webhook{ID: "terminal", URL: server.URL, Events: []string{"event"}, Active: true}); err != nil {
		t.Fatal(err)
	}
	policy := DefaultRetryPolicy()
	policy.MaxRetries = 0
	dispatcher := newTestDispatcher(webhooks, deliveries, outbox, policy)
	dispatcher.Start()
	defer dispatcher.Stop()
	if err := dispatcher.Queue("event", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool { return dispatcher.Snapshot(time.Now()).TerminalFailed == 1 })
	stats := dispatcher.Snapshot(time.Now())
	if stats.Pending != 0 || stats.InFlight != 0 || stats.Retrying != 0 || stats.LastFailureAt.IsZero() || stats.LastTerminalFailureAt.IsZero() {
		t.Fatalf("terminal stats = %+v", stats)
	}
}

func TestDispatcherRejectsUnboundedPayloadBeforeAdmission(t *testing.T) {
	webhooks, deliveries, outbox := newTestStores(t)
	if err := webhooks.Create(t.Context(), model.Webhook{ID: "large", URL: "https://example.invalid", Events: []string{"large"}, Active: true}); err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(webhooks, deliveries, outbox, DefaultRetryPolicy())
	if err := dispatcher.Queue("large", map[string]string{"value": string(make([]byte, maxOutboxPayloadBytes))}); err == nil {
		t.Fatal("oversized webhook payload was admitted")
	}
	entries, err := outbox.List(t.Context())
	if err != nil || len(entries) != 0 {
		t.Fatalf("outbox=%#v err=%v", entries, err)
	}
}

func TestDispatcherAdmissionIsAtomicAcrossDestinations(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	faults := faultstore.New(backend)
	ts := model.NewTypedStore(faults, store.BackendJSON)
	for _, namespace := range []string{model.NSWebhooks, model.NSWebhookDeliveries, model.NSWebhookOutbox} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	webhooks, deliveries, outbox := model.NewWebhookStore(ts), model.NewWebhookDeliveryStore(ts), model.NewWebhookOutboxStore(ts)
	for _, id := range []string{"one", "two"} {
		if err := webhooks.Create(t.Context(), model.Webhook{ID: id, URL: "https://example.invalid", Events: []string{"event"}, Active: true}); err != nil {
			t.Fatal(err)
		}
	}
	faults.Fail("batch_commit", 1)
	dispatcher := newTestDispatcher(webhooks, deliveries, outbox, DefaultRetryPolicy())
	if err := dispatcher.Queue("event", map[string]string{"value": "safe"}); !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("admission error = %v", err)
	}
	entries, err := outbox.List(t.Context())
	if err != nil || len(entries) != 0 {
		t.Fatalf("partial admission survived: entries=%#v err=%v", entries, err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not satisfied before timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestWebhook_SubscribesTo verifies event subscription matching.
func TestWebhook_SubscribesTo(t *testing.T) {
	wh := model.Webhook{
		Events: []string{"message.received", "contact.created"},
	}

	if !wh.SubscribesTo("message.received") {
		t.Error("expected to subscribe to message.received")
	}
	if !wh.SubscribesTo("contact.created") {
		t.Error("expected to subscribe to contact.created")
	}
	if wh.SubscribesTo("user.deleted") {
		t.Error("should not subscribe to user.deleted")
	}
}

// TestWebhook_EffectiveMaxRetries verifies max retries fallback.
func TestWebhook_EffectiveMaxRetries(t *testing.T) {
	wh := model.Webhook{}
	if wh.EffectiveMaxRetries() != model.DefaultMaxRetries {
		t.Errorf("expected default max retries %d, got %d", model.DefaultMaxRetries, wh.EffectiveMaxRetries())
	}

	wh.MaxRetries = 10
	if wh.EffectiveMaxRetries() != 10 {
		t.Errorf("expected 10, got %d", wh.EffectiveMaxRetries())
	}
}

// TestWebhook_EffectiveBackoffMultiplier verifies backoff multiplier fallback.
func TestWebhook_EffectiveBackoffMultiplier(t *testing.T) {
	wh := model.Webhook{}
	if wh.EffectiveBackoffMultiplier() != model.DefaultBackoffMultiplier {
		t.Errorf("expected default backoff multiplier %f, got %f", model.DefaultBackoffMultiplier, wh.EffectiveBackoffMultiplier())
	}

	wh.BackoffMultiplier = 3.0
	if wh.EffectiveBackoffMultiplier() != 3.0 {
		t.Errorf("expected 3.0, got %f", wh.EffectiveBackoffMultiplier())
	}
}

// TestDeliveryStatus_Constants verifies delivery status constants.
func TestDeliveryStatus_Constants(t *testing.T) {
	if model.WebhookDeliveryPending != "pending" {
		t.Errorf("WebhookDeliveryPending = %s, want pending", model.WebhookDeliveryPending)
	}
	if model.WebhookDeliverySent != "sent" {
		t.Errorf("WebhookDeliverySent = %s, want sent", model.WebhookDeliverySent)
	}
	if model.WebhookDeliveryFailed != "failed" {
		t.Errorf("WebhookDeliveryFailed = %s, want failed", model.WebhookDeliveryFailed)
	}
}

// TestDispatcher_HMACSignature verifies the dispatcher sends correct HMAC signatures.
func TestDispatcher_HMACSignature(t *testing.T) {
	var receivedSig string
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Webhook-Signature")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	whStore, delStore, outbox := newTestStores(t)

	wh := model.Webhook{
		ID:        "wh-hmac",
		URL:       server.URL,
		Events:    []string{"webhook.test"},
		Active:    true,
		Secret:    "my-secret-key",
		CreatedAt: time.Now().UTC().Add(-time.Minute),
		UpdatedAt: time.Now().UTC().Add(-time.Minute),
	}
	if err := whStore.Create(context.Background(), wh); err != nil {
		t.Fatalf("failed to create webhook: %v", err)
	}

	d := newTestDispatcher(whStore, delStore, outbox, DefaultRetryPolicy())
	_, err := d.Test(context.Background(), "wh-hmac")
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	if receivedSig == "" {
		t.Error("expected HMAC signature header")
	}
	if len(receivedSig) < 7 {
		t.Errorf("signature too short: %s", receivedSig)
	}
	if receivedSig != computeHMAC(wh.Secret, receivedBody) {
		t.Fatal("initial delivery was not signed with the configured secret")
	}
	previousSignature := receivedSig
	_, replacement, err := whStore.RotateSecret(t.Context(), wh.ID, wh.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Test(t.Context(), wh.ID); err != nil {
		t.Fatal(err)
	}
	if receivedSig == previousSignature || receivedSig != computeHMAC(replacement, receivedBody) || receivedSig == computeHMAC(wh.Secret, receivedBody) {
		t.Fatal("delivery after rotation was not signed exclusively with the replacement secret")
	}
}

// newTestStores creates in-memory webhook and delivery stores for testing.
func newTestStores(t *testing.T) (*model.WebhookStore, *model.WebhookDeliveryStore, *model.WebhookOutboxStore) {
	t.Helper()
	// Use the jsonstore backend with a temp directory
	tmpDir := t.TempDir()
	s, err := jsonstore.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	ts := model.NewTypedStore(s, store.BackendJSON)

	// Ensure namespaces
	ctx := context.Background()
	for _, ns := range []string{model.NSWebhooks, model.NSWebhookDeliveries, model.NSWebhookOutbox} {
		_ = ts.CreateNamespace(ctx, ns) // the namespace may already exist
	}

	return model.NewWebhookStore(ts), model.NewWebhookDeliveryStore(ts), model.NewWebhookOutboxStore(ts)
}

func TestDispatcherSetPolicyAppliesToNewWorkLive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	webhooks, deliveries, outbox := newTestStores(t)
	if err := webhooks.Create(t.Context(), model.Webhook{ID: "live", URL: server.URL, Events: []string{"message.received"}, Active: true}); err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(webhooks, deliveries, outbox, RetryPolicy{MaxRetries: 0, BaseDelay: time.Millisecond, BackoffMultiplier: 2, Timeout: 10 * time.Second})

	if err := dispatcher.Queue("message.received", "first"); err != nil {
		t.Fatal(err)
	}
	dispatcher.SetPolicy(RetryPolicy{MaxRetries: 3, BaseDelay: time.Hour, BackoffMultiplier: 2, Timeout: 50 * time.Millisecond})
	if err := dispatcher.Queue("message.received", "second"); err != nil {
		t.Fatal(err)
	}
	entries, err := outbox.List(t.Context())
	if err != nil || len(entries) != 2 {
		t.Fatalf("outbox=%#v err=%v", entries, err)
	}
	budgets := map[int]bool{}
	var retrying model.WebhookOutboxEntry
	for _, entry := range entries {
		budgets[entry.MaxAttempts] = true
		if entry.MaxAttempts == 4 {
			retrying = entry
		}
	}
	if !budgets[1] || !budgets[4] {
		t.Fatalf("attempt budgets = %v, want the old budget 1 kept and the new budget 4 applied", budgets)
	}

	// The new timeout bounds the attempt, and the new base delay schedules
	// its retry.
	start := time.Now()
	if err := dispatcher.processEntry(retrying, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("attempt took %v, want the live 50ms timeout", elapsed)
	}
	updated, err := outbox.Get(t.Context(), retrying.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Attempt != 1 || time.Until(updated.NextAttemptAt) < 30*time.Minute {
		t.Fatalf("retry scheduled at %v (attempt %d), want the live one-hour base delay", updated.NextAttemptAt, updated.Attempt)
	}
	if got := dispatcher.Policy(); got.MaxRetries != 3 || got.Timeout != 50*time.Millisecond {
		t.Fatalf("policy = %+v", got)
	}
}
