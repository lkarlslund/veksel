package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	AlertStateActive   = "active"
	AlertStateResolved = "resolved"

	TransitionOpened    = "opened"
	TransitionEscalated = "escalated"
	TransitionReopened  = "reopened"
	TransitionResolved  = "resolved"

	MaxSilenceDuration = 30 * 24 * time.Hour
)

// Alert is durable operator-owned state derived from a health component.
// Acknowledgement and silence affect presentation and delivery, never the
// component's readiness contribution.
type Alert struct {
	ID             string            `json:"id"`
	ComponentID    string            `json:"component_id"`
	ComponentLabel string            `json:"component_label"`
	ComponentKind  string            `json:"component_kind"`
	State          string            `json:"state"`
	ObservedState  string            `json:"observed_state"`
	Severity       string            `json:"severity"`
	Reason         string            `json:"reason,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
	FirstSeen      time.Time         `json:"first_seen"`
	ActiveSince    time.Time         `json:"active_since"`
	LastSeen       time.Time         `json:"last_seen"`
	ResolvedAt     time.Time         `json:"resolved_at,omitzero"`
	Occurrences    int64             `json:"occurrences"`
	AcknowledgedAt time.Time         `json:"acknowledged_at,omitzero"`
	AcknowledgedBy string            `json:"acknowledged_by,omitempty"`
	SilencedUntil  time.Time         `json:"silenced_until,omitzero"`
	SilencedBy     string            `json:"silenced_by,omitempty"`
	SilenceReason  string            `json:"silence_reason,omitempty"`
	Revision       int64             `json:"revision"`
	// Notification is the durable delivery state of this alert's channels.
	Notification AlertNotification `json:"notification,omitzero"`
}

// AlertNotification records channel delivery for one alert. Evaluate marks a
// transition pending in the same write that records it, so a notification
// survives a crash between the state change and its delivery; the notifier
// clears it once delivered, coalesced, or suppressed.
type AlertNotification struct {
	Pending       string    `json:"pending,omitempty"`
	PendingAt     time.Time `json:"pending_at,omitzero"`
	Attempts      int       `json:"attempts,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitzero"`
	LastType      string    `json:"last_type,omitempty"`
	LastState     string    `json:"last_state,omitempty"`
	LastSeverity  string    `json:"last_severity,omitempty"`
	LastAt        time.Time `json:"last_at,omitzero"`
	LastOutcome   string    `json:"last_outcome,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Suppressed    int64     `json:"suppressed,omitempty"`
}

// markPending records a transition awaiting delivery, replacing any older
// undelivered transition: channels report the latest state only.
func (n *AlertNotification) markPending(transition string, at time.Time) {
	n.Pending, n.PendingAt, n.Attempts, n.NextAttemptAt = transition, at, 0, time.Time{}
}

// MarshalJSON keeps optional lifecycle timestamps optional on the wire. Go's
// encoding/json does not apply omitempty to a zero time.Time value, and a
// serialized year-one timestamp is truthy to browser clients.
func (a Alert) MarshalJSON() ([]byte, error) {
	type alertJSON Alert
	var resolvedAt, acknowledgedAt, silencedUntil *time.Time
	if !a.ResolvedAt.IsZero() {
		value := a.ResolvedAt
		resolvedAt = &value
	}
	if !a.AcknowledgedAt.IsZero() {
		value := a.AcknowledgedAt
		acknowledgedAt = &value
	}
	if !a.SilencedUntil.IsZero() {
		value := a.SilencedUntil
		silencedUntil = &value
	}
	return json.Marshal(struct {
		alertJSON
		ResolvedAt     *time.Time `json:"resolved_at,omitzero"`
		AcknowledgedAt *time.Time `json:"acknowledged_at,omitzero"`
		SilencedUntil  *time.Time `json:"silenced_until,omitzero"`
	}{alertJSON: alertJSON(a), ResolvedAt: resolvedAt, AcknowledgedAt: acknowledgedAt, SilencedUntil: silencedUntil})
}

func (a Alert) IsSilenced(now time.Time) bool {
	return !a.SilencedUntil.IsZero() && now.Before(a.SilencedUntil)
}

// Transition describes a meaningful alert state change suitable for events.
type Transition struct {
	Type  string `json:"type"`
	Alert Alert  `json:"alert"`
}

// AlertStore persists and serializes alert lifecycle mutations.
type AlertStore struct {
	backend store.Store
	mu      sync.Mutex
}

func NewAlertStore(ctx context.Context, backend store.Store) (*AlertStore, error) {
	if backend == nil {
		return nil, errors.New("health alert store is required")
	}
	exists, err := backend.NamespaceExists(ctx, model.NSHealthAlerts)
	if err != nil {
		return nil, fmt.Errorf("inspect health-alert namespace: %w", err)
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, model.NSHealthAlerts); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, fmt.Errorf("create health-alert namespace: %w", err)
		}
	}
	return &AlertStore{backend: backend}, nil
}

// Evaluate reconciles one snapshot into durable alerts and returns only
// opened, escalated, reopened, or resolved transitions. Repeated evidence
// refreshes one record without producing notification floods.
func (s *AlertStore) Evaluate(ctx context.Context, snapshot Snapshot) ([]Transition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := snapshot.GeneratedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var transitions []Transition
	err := store.Batch(ctx, s.backend, func(batchCtx context.Context) error {
		current, err := s.listLocked(batchCtx)
		if err != nil {
			return err
		}
		byID := make(map[string]Alert, len(current))
		for _, alert := range current {
			byID[alert.ID] = alert
		}
		observed := make(map[string]struct{})
		for _, component := range snapshot.Components {
			if !component.Desired || (component.State != StateDegraded && component.State != StateUnavailable) {
				continue
			}
			id := alertID(component.ID)
			observed[id] = struct{}{}
			alert, found := byID[id]
			transition := ""
			switch {
			case !found:
				alert = Alert{ID: id, ComponentID: component.ID, FirstSeen: now, ActiveSince: now, Occurrences: 1}
				transition = TransitionOpened
			case alert.State == AlertStateResolved:
				alert.State, alert.ActiveSince, alert.ResolvedAt = AlertStateActive, now, time.Time{}
				alert.Occurrences++
				alert.AcknowledgedAt, alert.AcknowledgedBy = time.Time{}, ""
				alert.SilencedUntil, alert.SilencedBy, alert.SilenceReason = time.Time{}, "", ""
				transition = TransitionReopened
			case severityRank(component.Severity) > severityRank(alert.Severity):
				alert.AcknowledgedAt, alert.AcknowledgedBy = time.Time{}, ""
				transition = TransitionEscalated
			}
			alert.State = AlertStateActive
			alert.ComponentLabel, alert.ComponentKind = component.Label, component.Kind
			alert.ObservedState, alert.Severity, alert.Reason = component.State, component.Severity, component.Reason
			alert.Details, alert.LastSeen = cloneDetails(component.Details), now
			alert.Revision++
			if transition != "" {
				alert.Notification.markPending(transition, now)
			}
			if err := s.setLocked(batchCtx, alert); err != nil {
				return err
			}
			byID[id] = alert
			if transition != "" {
				transitions = append(transitions, Transition{Type: transition, Alert: alert})
			}
		}
		for id, alert := range byID {
			if !strings.HasPrefix(id, "runtime:") || alert.State != AlertStateActive {
				continue
			}
			if _, found := observed[id]; found {
				continue
			}
			alert.State, alert.ResolvedAt, alert.LastSeen = AlertStateResolved, now, now
			alert.Revision++
			alert.Notification.markPending(TransitionResolved, now)
			if err := s.setLocked(batchCtx, alert); err != nil {
				return err
			}
			transitions = append(transitions, Transition{Type: TransitionResolved, Alert: alert})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("evaluate health alerts: %w", err)
	}
	sortTransitions(transitions)
	return transitions, nil
}

// List returns detached alert records sorted active-first, severity-first, and
// newest-active-first. Limit is bounded to protect administration responses.
func (s *AlertStore) List(ctx context.Context, state string, limit int) ([]Alert, error) {
	if state != "" && state != AlertStateActive && state != AlertStateResolved {
		return nil, errors.New("invalid alert state filter")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		return nil, errors.New("alert limit cannot exceed 500")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	alerts, err := s.listLocked(ctx)
	if err != nil {
		return nil, err
	}
	filtered := alerts[:0]
	for _, alert := range alerts {
		if state == "" || alert.State == state {
			filtered = append(filtered, alert)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].State != filtered[j].State {
			return filtered[i].State == AlertStateActive
		}
		if filtered[i].Severity != filtered[j].Severity {
			return severityRank(filtered[i].Severity) > severityRank(filtered[j].Severity)
		}
		if !filtered[i].ActiveSince.Equal(filtered[j].ActiveSince) {
			return filtered[i].ActiveSince.After(filtered[j].ActiveSince)
		}
		return filtered[i].ID < filtered[j].ID
	})
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return cloneAlerts(filtered), nil
}

func (s *AlertStore) Acknowledge(ctx context.Context, id, actor string, now time.Time) (Alert, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return Alert{}, errors.New("acknowledgement actor is required")
	}
	return s.mutate(ctx, id, func(alert *Alert) error {
		if alert.State != AlertStateActive {
			return errors.New("resolved alerts cannot be acknowledged")
		}
		alert.AcknowledgedAt, alert.AcknowledgedBy = normalizedNow(now), bounded(actor, 200)
		return nil
	})
}

func (s *AlertStore) Silence(ctx context.Context, id, actor, reason string, duration time.Duration, now time.Time) (Alert, error) {
	actor, reason = strings.TrimSpace(actor), bounded(reason, maxReasonRunes)
	if actor == "" || reason == "" {
		return Alert{}, errors.New("silence actor and reason are required")
	}
	if duration <= 0 || duration > MaxSilenceDuration {
		return Alert{}, fmt.Errorf("silence duration must be between one nanosecond and %s", MaxSilenceDuration)
	}
	return s.mutate(ctx, id, func(alert *Alert) error {
		if alert.State != AlertStateActive {
			return errors.New("resolved alerts cannot be silenced")
		}
		at := normalizedNow(now)
		alert.SilencedUntil, alert.SilencedBy, alert.SilenceReason = at.Add(duration), bounded(actor, 200), reason
		return nil
	})
}

// PendingNotifications returns detached alerts with an undelivered
// transition, oldest pending first.
func (s *AlertStore) PendingNotifications(ctx context.Context) ([]Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alerts, err := s.listLocked(ctx)
	if err != nil {
		return nil, err
	}
	pending := alerts[:0]
	for _, alert := range alerts {
		if alert.Notification.Pending != "" {
			pending = append(pending, alert)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if !pending[i].Notification.PendingAt.Equal(pending[j].Notification.PendingAt) {
			return pending[i].Notification.PendingAt.Before(pending[j].Notification.PendingAt)
		}
		return pending[i].ID < pending[j].ID
	})
	return cloneAlerts(pending), nil
}

// UpdateNotification applies delivery bookkeeping to one alert. pendingAt
// identifies the pending transition the caller handled: when Evaluate
// recorded a newer transition meanwhile, that newer one stays pending.
func (s *AlertStore) UpdateNotification(ctx context.Context, id string, pendingAt time.Time, apply func(*AlertNotification)) (Alert, error) {
	return s.mutate(ctx, id, func(alert *Alert) error {
		current := alert.Notification
		apply(&alert.Notification)
		if !current.PendingAt.Equal(pendingAt) {
			alert.Notification.Pending, alert.Notification.PendingAt = current.Pending, current.PendingAt
			alert.Notification.Attempts, alert.Notification.NextAttemptAt = current.Attempts, current.NextAttemptAt
		}
		return nil
	})
}

func (s *AlertStore) mutate(ctx context.Context, id string, apply func(*Alert) error) (Alert, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Alert{}, errors.New("alert ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Alert
	err := store.Batch(ctx, s.backend, func(batchCtx context.Context) error {
		alert, err := s.getLocked(batchCtx, id)
		if err != nil {
			return err
		}
		if err := apply(&alert); err != nil {
			return err
		}
		alert.Revision++
		if err := s.setLocked(batchCtx, alert); err != nil {
			return err
		}
		result = alert
		return nil
	})
	return result, err
}

func (s *AlertStore) listLocked(ctx context.Context) ([]Alert, error) {
	alerts := make([]Alert, 0)
	err := s.backend.Iterate(ctx, model.NSHealthAlerts, "alert:", func(_ string, value []byte) (bool, error) {
		var alert Alert
		if err := json.Unmarshal(value, &alert); err != nil {
			return false, fmt.Errorf("decode health alert: %w", err)
		}
		alerts = append(alerts, alert)
		return true, nil
	})
	return alerts, err
}

func (s *AlertStore) getLocked(ctx context.Context, id string) (Alert, error) {
	encoded, err := s.backend.Get(ctx, model.NSHealthAlerts, "alert:"+id)
	if err != nil {
		return Alert{}, err
	}
	var alert Alert
	if err := json.Unmarshal(encoded, &alert); err != nil {
		return Alert{}, fmt.Errorf("decode health alert: %w", err)
	}
	return alert, nil
}

func (s *AlertStore) setLocked(ctx context.Context, alert Alert) error {
	encoded, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	return s.backend.Set(ctx, model.NSHealthAlerts, "alert:"+alert.ID, encoded)
}

func alertID(componentID string) string { return "runtime:" + componentID }

func severityRank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	default:
		return 1
	}
}

func normalizedNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}

func cloneAlerts(alerts []Alert) []Alert {
	result := make([]Alert, len(alerts))
	for index, alert := range alerts {
		alert.Details = cloneDetails(alert.Details)
		result[index] = alert
	}
	return result
}

func sortTransitions(transitions []Transition) {
	sort.Slice(transitions, func(i, j int) bool {
		if transitions[i].Alert.ID == transitions[j].Alert.ID {
			return transitions[i].Type < transitions[j].Type
		}
		return transitions[i].Alert.ID < transitions[j].Alert.ID
	})
}
