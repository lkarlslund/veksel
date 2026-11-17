package health

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestAlertJSONOmitsAbsentLifecycleTimestamps(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	alert := Alert{ID: "runtime:smtp", FirstSeen: now, ActiveSince: now, LastSeen: now}
	payload, err := json.Marshal(alert)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"resolved_at", "acknowledged_at", "silenced_until", "0001-01-01"} {
		if strings.Contains(string(payload), absent) {
			t.Errorf("zero alert JSON contains %q: %s", absent, payload)
		}
	}
	alert.ResolvedAt, alert.AcknowledgedAt, alert.SilencedUntil = now, now.Add(time.Minute), now.Add(time.Hour)
	payload, err = json.Marshal(alert)
	if err != nil {
		t.Fatal(err)
	}
	for _, present := range []string{"resolved_at", "acknowledged_at", "silenced_until"} {
		if !strings.Contains(string(payload), present) {
			t.Errorf("populated alert JSON omits %q: %s", present, payload)
		}
	}
}

func testAlertStore(t *testing.T) (*AlertStore, store.Store) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	alerts, err := NewAlertStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	return alerts, backend
}

func unhealthySnapshot(at time.Time, state, severity string) Snapshot {
	return Snapshot{GeneratedAt: at, Components: []Component{{Observation: Observation{
		ID: "smtp", Label: "SMTP", Kind: "listener", Desired: true, Required: true,
		State: state, Severity: severity, Reason: "bind failed", Details: map[string]string{"address": ":25"},
	}, Since: at, ObservedAt: at}}}
}

func TestAlertLifecycleDeduplicatesEscalatesResolvesAndReopens(t *testing.T) {
	alerts, _ := testAlertStore(t)
	first := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	transitions, err := alerts.Evaluate(t.Context(), unhealthySnapshot(first, StateDegraded, SeverityWarning))
	if err != nil || len(transitions) != 1 || transitions[0].Type != TransitionOpened {
		t.Fatalf("open transitions=%#v err=%v", transitions, err)
	}
	if transitions, err = alerts.Evaluate(t.Context(), unhealthySnapshot(first.Add(time.Minute), StateDegraded, SeverityWarning)); err != nil || len(transitions) != 0 {
		t.Fatalf("repeat transitions=%#v err=%v", transitions, err)
	}
	listed, err := alerts.List(t.Context(), AlertStateActive, 10)
	if err != nil || len(listed) != 1 || listed[0].Occurrences != 1 || !listed[0].ActiveSince.Equal(first) || listed[0].Revision != 2 {
		t.Fatalf("active alerts=%#v err=%v", listed, err)
	}
	transitions, err = alerts.Evaluate(t.Context(), unhealthySnapshot(first.Add(2*time.Minute), StateUnavailable, SeverityCritical))
	if err != nil || len(transitions) != 1 || transitions[0].Type != TransitionEscalated {
		t.Fatalf("escalation transitions=%#v err=%v", transitions, err)
	}
	healthy := Snapshot{Status: StatusReady, GeneratedAt: first.Add(3 * time.Minute), Components: []Component{{Observation: Observation{ID: "smtp", Label: "SMTP", Kind: "listener", Desired: true, Required: true, State: StateHealthy, Severity: SeverityInfo}}}}
	transitions, err = alerts.Evaluate(t.Context(), healthy)
	if err != nil || len(transitions) != 1 || transitions[0].Type != TransitionResolved || transitions[0].Alert.State != AlertStateResolved {
		t.Fatalf("resolve transitions=%#v err=%v", transitions, err)
	}
	transitions, err = alerts.Evaluate(t.Context(), unhealthySnapshot(first.Add(4*time.Minute), StateUnavailable, SeverityCritical))
	if err != nil || len(transitions) != 1 || transitions[0].Type != TransitionReopened || transitions[0].Alert.Occurrences != 2 || !transitions[0].Alert.ActiveSince.Equal(first.Add(4*time.Minute)) {
		t.Fatalf("reopen transitions=%#v err=%v", transitions, err)
	}
}

func TestAlertAcknowledgementAndSilenceDoNotMaskActiveState(t *testing.T) {
	alerts, _ := testAlertStore(t)
	now := time.Now().UTC()
	if _, err := alerts.Evaluate(t.Context(), unhealthySnapshot(now, StateUnavailable, SeverityCritical)); err != nil {
		t.Fatal(err)
	}
	acknowledged, err := alerts.Acknowledge(t.Context(), "runtime:smtp", "admin", now.Add(time.Minute))
	if err != nil || acknowledged.State != AlertStateActive || acknowledged.AcknowledgedBy != "admin" {
		t.Fatalf("acknowledged=%#v err=%v", acknowledged, err)
	}
	silenced, err := alerts.Silence(t.Context(), "runtime:smtp", "admin", "maintenance", 2*time.Hour, now.Add(2*time.Minute))
	if err != nil || !silenced.IsSilenced(now.Add(time.Hour)) || silenced.State != AlertStateActive {
		t.Fatalf("silenced=%#v err=%v", silenced, err)
	}
	if _, err := alerts.Silence(t.Context(), "runtime:smtp", "admin", "too long", MaxSilenceDuration+time.Second, now); err == nil {
		t.Fatal("overlong silence succeeded")
	}
	if transitions, err := alerts.Evaluate(t.Context(), unhealthySnapshot(now.Add(3*time.Minute), StateUnavailable, SeverityCritical)); err != nil || len(transitions) != 0 {
		t.Fatalf("acknowledged repeat transitions=%#v err=%v", transitions, err)
	}
	listed, _ := alerts.List(t.Context(), AlertStateActive, 10)
	if len(listed) != 1 || listed[0].AcknowledgedBy != "admin" || listed[0].SilencedBy != "admin" {
		t.Fatalf("operator state not retained: %#v", listed)
	}
}

func TestAlertStorePersistsAcrossReopenAndRejectsInvalidMutations(t *testing.T) {
	alerts, backend := testAlertStore(t)
	now := time.Now().UTC()
	if _, err := alerts.Evaluate(t.Context(), unhealthySnapshot(now, StateDegraded, SeverityWarning)); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewAlertStore(context.Background(), backend)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := reopened.List(t.Context(), "", 10)
	if err != nil || len(listed) != 1 || listed[0].ID != "runtime:smtp" {
		t.Fatalf("reopened alerts=%#v err=%v", listed, err)
	}
	if _, err := reopened.Acknowledge(t.Context(), "missing", "admin", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing acknowledge error = %v", err)
	}
	if _, err := reopened.List(t.Context(), "invalid", 10); err == nil {
		t.Fatal("invalid filter succeeded")
	}
	if _, err := reopened.List(t.Context(), "", 501); err == nil {
		t.Fatal("unbounded list succeeded")
	}
}
