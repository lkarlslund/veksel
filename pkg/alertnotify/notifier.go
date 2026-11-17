// Package alertnotify delivers durable health-alert transitions and account
// quota warnings to operators and users through mail, subscribed webhooks,
// and a generic JSON push URL. Delivery state lives on the alert records and
// in the health-alert namespace, so notifications survive restarts without
// being repeated.
package alertnotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/netguard"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Notification outcomes recorded on alerts.
const (
	OutcomeSent       = "sent"
	OutcomeDigest     = "digest"
	OutcomeCoalesced  = "coalesced"
	OutcomeSilenced   = "silenced"
	OutcomeDisabled   = "disabled"
	OutcomeFailed     = "failed"
	OutcomeRetrying   = "retrying"
	EventDigest       = "health.alert.digest"
	EventTest         = "health.alert.test"
	ChannelEmail      = "email"
	ChannelWebhook    = "webhook"
	ChannelPush       = "push"
	digestInterval    = 24 * time.Hour
	maxAttempts       = 8
	maxRetryDelay     = time.Hour
	pushTimeout       = 10 * time.Second
	maxErrorRunes     = 400
	digestMarkerKey   = "notify:digest"
	maxDigestAlerts   = 100
	maxPushBodyDrain  = 4 << 10
	notificationTitle = "Veksel"
)

// Policy is the live alert delivery configuration.
type Policy struct {
	Enabled     bool
	Recipients  []string
	URL         string
	Token       string
	MinInterval time.Duration
	Digest      string
	// AllowPrivateNetworks lets the default push client reach a URL on a
	// loopback, private, or link-local address.
	AllowPrivateNetworks bool
}

// PolicyFromConfig derives the delivery policy from managed configuration.
func PolicyFromConfig(cfg *config.Config) Policy {
	recipients, _ := config.ParseAlertEmailRecipients(cfg.AlertEmailRecipients)
	return Policy{
		Enabled: cfg.AlertNotificationsEnabled, Recipients: recipients,
		URL: strings.TrimSpace(cfg.AlertNotifyURL), Token: cfg.AlertNotifyToken,
		MinInterval: time.Duration(cfg.AlertMinIntervalMinutes) * time.Minute, Digest: cfg.AlertDigest,
		AllowPrivateNetworks: cfg.OutboundHTTPAllowPrivateNetworks,
	}
}

// Message is one channel-neutral notification.
type Message struct {
	ID       string
	Event    string
	Subject  string
	Text     string
	Severity string
	At       time.Time
	Payload  map[string]any
}

// Channels are the delivery sinks. Mail admits one generated message for one
// recipient into the durable outbound queue; Webhook admits one event for
// every matching webhook subscription. HTTP posts push notifications.
type Channels struct {
	Mail    func(ctx context.Context, recipient string, message Message) error
	Webhook func(event string, payload any) error
	// WebhookSubscribed reports whether an active webhook subscribes to the
	// event; without it a running dispatcher counts as configured.
	WebhookSubscribed func(event string) bool
	HTTP              *http.Client
}

// webhookConfigured reports whether alert events reach any webhook: a
// dispatcher with no subscription to health.alert.opened delivers nothing.
func (c Channels) webhookConfigured() bool {
	return c.Webhook != nil && (c.WebhookSubscribed == nil || c.WebhookSubscribed("health.alert.opened"))
}

// ChannelResult is the outcome of one delivery attempt on one channel.
type ChannelResult struct {
	Channel string    `json:"channel"`
	Target  string    `json:"target,omitempty"`
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
}

// ChannelStatus describes one configured channel for administration.
type ChannelStatus struct {
	ID         string        `json:"id"`
	Label      string        `json:"label"`
	Configured bool          `json:"configured"`
	Target     string        `json:"target,omitempty"`
	Last       ChannelResult `json:"last,omitzero"`
}

// Status is the administration view of alert delivery.
type Status struct {
	Enabled            bool            `json:"enabled"`
	Digest             string          `json:"digest"`
	MinIntervalMinutes int             `json:"min_interval_minutes"`
	Pending            int             `json:"pending"`
	NextDigestAt       time.Time       `json:"next_digest_at,omitzero"`
	Channels           []ChannelStatus `json:"channels"`
}

// Notifier turns pending alert transitions into channel deliveries.
type Notifier struct {
	alerts   *health.AlertStore
	backend  store.Store
	channels Channels
	now      func() time.Time

	run      sync.Mutex
	mu       sync.Mutex
	policy   Policy
	lastByCh map[string]ChannelResult
}

// New creates a notifier. backend holds the digest schedule beside the
// alert records.
func New(alerts *health.AlertStore, backend store.Store, channels Channels, policy Policy) (*Notifier, error) {
	if alerts == nil || backend == nil {
		return nil, errors.New("alert notifier requires the alert store and its backend")
	}
	n := &Notifier{alerts: alerts, backend: backend, channels: channels, now: func() time.Time { return time.Now().UTC() },
		policy: clonePolicy(policy), lastByCh: make(map[string]ChannelResult)}
	if n.channels.HTTP == nil {
		n.channels.HTTP = (&netguard.Dialer{AllowPrivate: n.allowPrivateNetworks}).Client(pushTimeout)
	}
	return n, nil
}

func (n *Notifier) allowPrivateNetworks() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.policy.AllowPrivateNetworks
}

// SetPolicy replaces the delivery policy live.
func (n *Notifier) SetPolicy(policy Policy) {
	n.mu.Lock()
	n.policy = clonePolicy(policy)
	n.mu.Unlock()
}

func (n *Notifier) currentPolicy() Policy {
	n.mu.Lock()
	defer n.mu.Unlock()
	return clonePolicy(n.policy)
}

func clonePolicy(policy Policy) Policy {
	policy.Recipients = slices.Clone(policy.Recipients)
	return policy
}

// Process delivers, defers, coalesces, or batches every pending alert
// transition. It is safe to call after every evaluation and at startup;
// concurrent calls are serialized.
func (n *Notifier) Process(ctx context.Context) error {
	n.run.Lock()
	defer n.run.Unlock()
	policy, now := n.currentPolicy(), n.now()
	pending, err := n.alerts.PendingNotifications(ctx)
	if err != nil {
		return err
	}
	var digest []health.Alert
	var errs []error
	for _, alert := range pending {
		state := alert.Notification
		outcome := ""
		switch {
		case !policy.Enabled:
			outcome = OutcomeDisabled
		case alert.IsSilenced(now):
			outcome = OutcomeSilenced
		case !state.LastAt.IsZero() && alert.State == state.LastState && alert.Severity == state.LastSeverity:
			// The alert flapped back to the state operators were last told.
			outcome = OutcomeCoalesced
		case state.LastAt.IsZero() && alert.State == health.AlertStateResolved:
			// Operators were never told about this alert; its end is no news.
			outcome = OutcomeCoalesced
		}
		if outcome != "" {
			errs = append(errs, n.record(ctx, alert, func(note *health.AlertNotification) {
				note.Pending, note.PendingAt, note.Attempts, note.NextAttemptAt = "", time.Time{}, 0, time.Time{}
				note.LastOutcome = outcome
				if outcome != OutcomeDisabled {
					note.Suppressed++
				}
			}))
			continue
		}
		if state.NextAttemptAt.After(now) {
			continue
		}
		if policy.Digest == config.AlertDigestDaily {
			digest = append(digest, alert)
			continue
		}
		if policy.MinInterval > 0 && !state.LastAt.IsZero() && now.Sub(state.LastAt) < policy.MinInterval && !escalates(alert) {
			continue
		}
		results := n.deliver(ctx, policy, alertMessage(alert))
		errs = append(errs, n.finish(ctx, []health.Alert{alert}, results, OutcomeSent, now))
	}
	if policy.Enabled && policy.Digest == config.AlertDigestDaily {
		errs = append(errs, n.processDigest(ctx, policy, digest, now))
	}
	return errors.Join(errs...)
}

// escalates reports whether an active alert is more severe than the last
// notification, which bypasses the re-notify interval.
func escalates(alert health.Alert) bool {
	last := alert.Notification
	return alert.State == health.AlertStateActive && last.LastState == health.AlertStateActive &&
		severityRank(alert.Severity) > severityRank(last.LastSeverity)
}

func severityRank(severity string) int {
	switch severity {
	case health.SeverityCritical:
		return 3
	case health.SeverityWarning:
		return 2
	default:
		return 1
	}
}

func (n *Notifier) processDigest(ctx context.Context, policy Policy, alerts []health.Alert, now time.Time) error {
	last, err := n.digestMarker(ctx)
	if err != nil {
		return err
	}
	if last.IsZero() {
		return n.setDigestMarker(ctx, now)
	}
	if now.Sub(last) < digestInterval {
		return nil
	}
	if len(alerts) > maxDigestAlerts {
		alerts = alerts[:maxDigestAlerts]
	}
	var errs []error
	if len(alerts) > 0 {
		results := n.deliver(ctx, policy, digestMessage(alerts, now))
		errs = append(errs, n.finish(ctx, alerts, results, OutcomeDigest, now))
		if !delivered(results) {
			return errors.Join(errs...)
		}
	}
	return errors.Join(append(errs, n.setDigestMarker(ctx, now))...)
}

// finish records a delivery on each alert: success clears the pending
// transition; when every channel failed it is retried with backoff.
func (n *Notifier) finish(ctx context.Context, alerts []health.Alert, results []ChannelResult, outcome string, now time.Time) error {
	ok := delivered(results)
	failures := failureText(results)
	var errs []error
	for _, alert := range alerts {
		errs = append(errs, n.record(ctx, alert, func(note *health.AlertNotification) {
			note.LastError = failures
			if ok {
				note.LastType, note.LastState, note.LastSeverity, note.LastAt = note.Pending, alert.State, alert.Severity, now
				note.Pending, note.PendingAt, note.Attempts, note.NextAttemptAt = "", time.Time{}, 0, time.Time{}
				note.LastOutcome = outcome
				return
			}
			note.Attempts++
			if note.Attempts >= maxAttempts {
				note.Pending, note.PendingAt, note.Attempts, note.NextAttemptAt = "", time.Time{}, 0, time.Time{}
				note.LastOutcome = OutcomeFailed
				return
			}
			note.NextAttemptAt, note.LastOutcome = now.Add(retryDelay(note.Attempts)), OutcomeRetrying
		}))
	}
	return errors.Join(errs...)
}

func (n *Notifier) record(ctx context.Context, alert health.Alert, apply func(*health.AlertNotification)) error {
	_, err := n.alerts.UpdateNotification(ctx, alert.ID, alert.Notification.PendingAt, apply)
	return err
}

func retryDelay(attempt int) time.Duration {
	delay := time.Minute << max(0, attempt-1)
	return min(delay, maxRetryDelay)
}

func delivered(results []ChannelResult) bool {
	if len(results) == 0 {
		return true
	}
	for _, result := range results {
		if result.OK {
			return true
		}
	}
	return false
}

func failureText(results []ChannelResult) string {
	var failures []string
	for _, result := range results {
		if !result.OK {
			failures = append(failures, result.Channel+": "+result.Error)
		}
	}
	return bounded(strings.Join(failures, "; "))
}

// Test sends a test notification through every configured channel,
// regardless of the enabled, interval, and digest policy.
func (n *Notifier) Test(ctx context.Context) []ChannelResult {
	now := n.now()
	message := Message{
		ID: "test-" + now.Format("20060102T150405.000000000"), Event: EventTest, Severity: health.SeverityInfo, At: now,
		Subject: "[" + notificationTitle + "] Test notification",
		Text:    "This is a test of the Veksel alert notification channels.\r\nNo action is required.\r\n",
		Payload: map[string]any{"test": true, "sent_at": now.Format(time.RFC3339)},
	}
	return n.deliver(ctx, n.currentPolicy(), message)
}

// Status reports configured channels and their latest delivery evidence.
func (n *Notifier) Status(ctx context.Context) (Status, error) {
	policy := n.currentPolicy()
	status := Status{Enabled: policy.Enabled, Digest: policy.Digest, MinIntervalMinutes: int(policy.MinInterval / time.Minute)}
	pending, err := n.alerts.PendingNotifications(ctx)
	if err != nil {
		return Status{}, err
	}
	status.Pending = len(pending)
	if policy.Digest == config.AlertDigestDaily {
		if last, err := n.digestMarker(ctx); err == nil && !last.IsZero() {
			status.NextDigestAt = last.Add(digestInterval)
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	emailTarget := ""
	if len(policy.Recipients) > 0 {
		emailTarget = strings.Join(policy.Recipients, ", ")
	}
	status.Channels = []ChannelStatus{
		{ID: ChannelEmail, Label: "Administrator email", Configured: len(policy.Recipients) > 0 && n.channels.Mail != nil, Target: emailTarget, Last: n.lastByCh[ChannelEmail]},
		{ID: ChannelWebhook, Label: "Webhook subscriptions", Configured: n.channels.webhookConfigured(), Target: "health.alert.* subscriptions", Last: n.lastByCh[ChannelWebhook]},
		{ID: ChannelPush, Label: "HTTP push", Configured: policy.URL != "", Target: redactURL(policy.URL), Last: n.lastByCh[ChannelPush]},
	}
	return status, nil
}

// redactURL keeps only the scheme and host: push URLs often carry an
// application token in the path or query.
func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// deliver sends one message through every configured channel.
func (n *Notifier) deliver(ctx context.Context, policy Policy, message Message) []ChannelResult {
	var results []ChannelResult
	add := func(channel, target string, err error) {
		result := ChannelResult{Channel: channel, Target: target, OK: err == nil, At: n.now()}
		if err != nil {
			result.Error = bounded(err.Error())
		}
		results = append(results, result)
	}
	if n.channels.Mail != nil {
		for _, recipient := range policy.Recipients {
			add(ChannelEmail, recipient, n.channels.Mail(ctx, recipient, message))
		}
	}
	if n.channels.Webhook != nil {
		add(ChannelWebhook, message.Event, n.channels.Webhook(message.Event, message.Payload))
	}
	if policy.URL != "" {
		add(ChannelPush, redactURL(policy.URL), n.push(ctx, policy, message))
	}
	// Keep one result per channel, preferring a failure among several
	// recipients so the administration view does not hide it.
	latest := make(map[string]ChannelResult, len(results))
	for _, result := range results {
		if previous, seen := latest[result.Channel]; !seen || previous.OK {
			latest[result.Channel] = result
		}
	}
	n.mu.Lock()
	maps.Copy(n.lastByCh, latest)
	n.mu.Unlock()
	return results
}

// PushBody is the documented JSON document posted to alert_notify_url. Its
// title, message, and priority fields match Gotify's message API; generic
// receivers can use event, severity, and data.
type PushBody struct {
	Source    string         `json:"source"`
	Event     string         `json:"event"`
	Title     string         `json:"title"`
	Message   string         `json:"message"`
	Priority  int            `json:"priority"`
	Severity  string         `json:"severity"`
	Timestamp string         `json:"timestamp"`
	Data      map[string]any `json:"data,omitempty"`
}

func (n *Notifier) push(ctx context.Context, policy Policy, message Message) error {
	body, err := json.Marshal(PushBody{
		Source: "veksel", Event: message.Event, Title: message.Subject, Message: message.Text,
		Priority: pushPriority(message), Severity: message.Severity, Timestamp: message.At.UTC().Format(time.RFC3339), Data: message.Payload,
	})
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, policy.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Veksel-Alerts/1")
	if policy.Token != "" {
		request.Header.Set("Authorization", "Bearer "+policy.Token)
	}
	response, err := n.channels.HTTP.Do(request)
	if err != nil {
		// The URL may embed a credential; report the failure without it.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("push to %s failed: %w", redactURL(policy.URL), urlErr.Err)
		}
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxPushBodyDrain))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("push receiver returned HTTP %d", response.StatusCode)
	}
	return nil
}

func pushPriority(message Message) int {
	if message.Payload["transition"] == health.TransitionResolved {
		return 3
	}
	switch message.Severity {
	case health.SeverityCritical:
		return 5
	case health.SeverityWarning:
		return 4
	default:
		return 3
	}
}

// alertPayload is the stable machine-readable form of one alert, shared by
// webhooks and push data.
func alertPayload(alert health.Alert, transition string) map[string]any {
	payload := map[string]any{
		"alert_id": alert.ID, "component_id": alert.ComponentID, "component": alert.ComponentLabel,
		"severity": alert.Severity, "state": alert.State, "observed_state": alert.ObservedState,
		"reason": alert.Reason, "transition": transition, "occurrences": alert.Occurrences,
		"active_since": alert.ActiveSince.UTC().Format(time.RFC3339),
	}
	if !alert.ResolvedAt.IsZero() {
		payload["resolved_at"] = alert.ResolvedAt.UTC().Format(time.RFC3339)
	}
	return payload
}

func alertMessage(alert health.Alert) Message {
	transition := alert.Notification.Pending
	subject := fmt.Sprintf("[%s] %s: %s alert %s", notificationTitle, strings.ToUpper(alert.Severity), alert.ComponentLabel, transition)
	if transition == health.TransitionResolved {
		subject = fmt.Sprintf("[%s] Resolved: %s", notificationTitle, alert.ComponentLabel)
	}
	text := &strings.Builder{}
	writeAlert(text, alert, transition)
	return Message{
		ID:    "alert-" + alert.ID + "-" + alert.Notification.PendingAt.UTC().Format("20060102T150405.000000000"),
		Event: "health.alert." + transition, Subject: subject, Text: text.String(), Severity: alert.Severity,
		At: alert.Notification.PendingAt, Payload: alertPayload(alert, transition),
	}
}

func digestMessage(alerts []health.Alert, now time.Time) Message {
	text := &strings.Builder{}
	fmt.Fprintf(text, "%d alert change(s) since the last digest.\r\n\r\n", len(alerts))
	payloads := make([]map[string]any, 0, len(alerts))
	severity := health.SeverityInfo
	for _, alert := range alerts {
		writeAlert(text, alert, alert.Notification.Pending)
		text.WriteString("\r\n")
		payloads = append(payloads, alertPayload(alert, alert.Notification.Pending))
		if alert.State == health.AlertStateActive && severityRank(alert.Severity) > severityRank(severity) {
			severity = alert.Severity
		}
	}
	return Message{
		ID: "digest-" + now.UTC().Format("20060102T150405"), Event: EventDigest, Severity: severity, At: now,
		Subject: fmt.Sprintf("[%s] Alert digest: %d change(s)", notificationTitle, len(alerts)),
		Text:    text.String(), Payload: map[string]any{"count": len(alerts), "alerts": payloads},
	}
}

func writeAlert(text *strings.Builder, alert health.Alert, transition string) {
	fmt.Fprintf(text, "%s: %s\r\n", alert.ComponentLabel, transition)
	fmt.Fprintf(text, "  Severity: %s\r\n  State: %s (observed %s)\r\n", alert.Severity, alert.State, alert.ObservedState)
	if alert.Reason != "" {
		fmt.Fprintf(text, "  Reason: %s\r\n", oneLine(alert.Reason))
	}
	fmt.Fprintf(text, "  Active since: %s\r\n  Occurrences: %d\r\n", alert.ActiveSince.UTC().Format(time.RFC1123Z), alert.Occurrences)
	if !alert.ResolvedAt.IsZero() {
		fmt.Fprintf(text, "  Resolved at: %s\r\n", alert.ResolvedAt.UTC().Format(time.RFC1123Z))
	}
	for _, key := range slices.Sorted(maps.Keys(alert.Details)) {
		fmt.Fprintf(text, "  %s: %s\r\n", key, oneLine(alert.Details[key]))
	}
	fmt.Fprintf(text, "  Alert ID: %s\r\n", alert.ID)
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func bounded(value string) string {
	runes := []rune(oneLine(value))
	if len(runes) > maxErrorRunes {
		return string(runes[:maxErrorRunes]) + "…"
	}
	return string(runes)
}

type digestMarker struct {
	LastAt time.Time `json:"last_at"`
}

func (n *Notifier) digestMarker(ctx context.Context) (time.Time, error) {
	encoded, err := n.backend.Get(ctx, model.NSHealthAlerts, digestMarkerKey)
	if errors.Is(err, store.ErrNotFound) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	var marker digestMarker
	if err := json.Unmarshal(encoded, &marker); err != nil {
		return time.Time{}, fmt.Errorf("decode alert digest marker: %w", err)
	}
	return marker.LastAt, nil
}

func (n *Notifier) setDigestMarker(ctx context.Context, at time.Time) error {
	encoded, err := json.Marshal(digestMarker{LastAt: at.UTC()})
	if err != nil {
		return err
	}
	return n.backend.Set(ctx, model.NSHealthAlerts, digestMarkerKey, encoded)
}
