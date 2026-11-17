package dnsprovider_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/dnsprovider/dnsprovidertest"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/netguard"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type auditEntry struct{ actor, action, target string }

type recordingAudit struct {
	mu      sync.Mutex
	entries []auditEntry
	details []map[string]string
}

func (a *recordingAudit) Log(actor, action, target string, details map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, auditEntry{actor, action, target})
	a.details = append(a.details, details)
}

func (a *recordingAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.entries))
	for _, entry := range a.entries {
		out = append(out, entry.action)
	}
	return out
}

func newTestZones(t *testing.T) (*dnsprovider.Zones, *dnsprovidertest.Memory, *recordingAudit, *model.TypedStore) {
	t.Helper()
	zones, audit, ts := newZones(t)
	memory := &dnsprovidertest.Memory{}
	zones.SetFactory(func(zone model.DNSZone, secret string) (dnsprovider.Provider, error) {
		if secret != "cf-secret-token" {
			return nil, errors.New("credential was not opened")
		}
		return memory, nil
	})
	return zones, memory, audit, ts
}

// newZones opens zones with the real provider factory.
func newZones(t *testing.T) (*dnsprovider.Zones, *recordingAudit, *model.TypedStore) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	sealer, err := migration.NewStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	audit := &recordingAudit{}
	zones, err := dnsprovider.NewZones(t.Context(), ts, sealer, audit)
	if err != nil {
		t.Fatal(err)
	}
	return zones, audit, ts
}

func TestWebhookProviderReachesPrivateNetworksOnlyWhenAllowed(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	t.Cleanup(server.Close)
	zones, _, _ := newZones(t)
	secret := "hook-token"
	if _, err := zones.Put(t.Context(), "admin", "example.test", dnsprovider.ZoneInput{Provider: dnsprovider.KindWebhook, Settings: map[string]string{"url": server.URL}, Secret: &secret}); err != nil {
		t.Fatal(err)
	}
	desired := []dnsprovider.Desired{{Record: dnsprovider.Record{Type: "TXT", Name: "_dmarc.example.test", Value: "v=DMARC1; p=none"}, Prefix: "v=dmarc1"}}
	if _, err := zones.Plan(t.Context(), "example.test", desired, dnsprovider.Scope{Purpose: "example.test"}); !errors.Is(err, netguard.ErrForbiddenAddress) || calls.Load() != 0 {
		t.Fatalf("loopback provider error = %v calls = %d", err, calls.Load())
	}
	zones.SetAllowPrivateNetworks(true)
	if _, err := zones.Plan(t.Context(), "example.test", desired, dnsprovider.Scope{Purpose: "example.test"}); err != nil || calls.Load() == 0 {
		t.Fatalf("allowed provider error = %v calls = %d", err, calls.Load())
	}
}

func configure(t *testing.T, zones *dnsprovider.Zones) {
	t.Helper()
	secret := "cf-secret-token"
	if _, err := zones.Put(t.Context(), "admin", "Example.Test.", dnsprovider.ZoneInput{Provider: dnsprovider.KindCloudflare, Settings: map[string]string{"zone_id": "z1"}, Secret: &secret}); err != nil {
		t.Fatal(err)
	}
}

func TestZoneCredentialsAreSealedAndRedacted(t *testing.T) {
	zones, _, audit, ts := newTestZones(t)
	ctx := t.Context()
	if _, err := zones.Put(ctx, "admin", "example.test", dnsprovider.ZoneInput{Provider: dnsprovider.KindCloudflare}); err == nil {
		t.Fatal("cloudflare zone without a token was accepted")
	}
	if _, err := zones.Put(ctx, "admin", "example.test", dnsprovider.ZoneInput{Provider: dnsprovider.KindRFC2136, Settings: map[string]string{"server": "ns1", "key_name": "k", "secret": "x"}}); err == nil {
		t.Fatal("unknown setting accepted")
	}
	configure(t, zones)
	stored, err := model.NewDNSZoneStore(ts).Get(ctx, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.SealedSecret) == 0 || strings.Contains(string(stored.SealedSecret), "cf-secret-token") {
		t.Fatalf("credential is not sealed at rest: %q", stored.SealedSecret)
	}
	views, err := zones.List(ctx)
	if err != nil || len(views) != 1 || !views[0].SecretSet || views[0].Zone != "example.test" {
		t.Fatalf("views: %+v %v", views, err)
	}
	// Re-saving settings without a secret keeps the stored credential.
	if _, err := zones.Put(ctx, "admin", "example.test", dnsprovider.ZoneInput{Provider: dnsprovider.KindCloudflare}); err != nil {
		t.Fatal(err)
	}
	if _, err := zones.Plan(ctx, "example.test", nil, dnsprovider.Scope{Purpose: "example.test"}); err != nil {
		t.Fatalf("kept credential does not open: %v", err)
	}
	for _, details := range audit.details {
		for _, value := range details {
			if strings.Contains(value, "cf-secret-token") {
				t.Fatal("audit details leak the credential")
			}
		}
	}
	if _, err := zones.ForName(ctx, "sub.example.test"); err != nil {
		t.Fatalf("subdomain zone match: %v", err)
	}
	if !errors.Is(func() error { _, err := zones.ForName(ctx, "example.net"); return err }(), dnsprovider.ErrNoProvider) {
		t.Fatal("unrelated name matched a zone")
	}
}

func TestApplyNeverTouchesForeignRecordsWithoutConfirmation(t *testing.T) {
	zones, memory, audit, _ := newTestZones(t)
	configure(t, zones)
	ctx := t.Context()
	memory.Add("TXT", "example.test", "v=spf1 include:other -all")
	desired := []dnsprovider.Desired{
		{Record: dnsprovider.Record{Type: "TXT", Name: "example.test", Value: "v=spf1 mx -all"}, Prefix: "v=spf1"},
		{Record: dnsprovider.Record{Type: "TXT", Name: "s1._domainkey.example.test", Value: "v=DKIM1; p=ONE"}, Prefix: "v=dkim1"},
	}
	scope := dnsprovider.Scope{Purpose: "example.test"}
	result, err := zones.Apply(ctx, "admin", "example.test", desired, scope, dnsprovider.ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := memory.Values("TXT", "example.test"); len(got) != 1 || got[0] != "v=spf1 include:other -all" {
		t.Fatalf("foreign SPF changed without confirmation: %v", got)
	}
	if result.Changes[0].Action != dnsprovider.ActionConflict || result.Changes[0].Applied || !result.Changes[1].Applied {
		t.Fatalf("result: %+v", result.Changes)
	}

	// Rotation: s1 retires, s2 is published; only the owned s1 is deleted.
	memory.Add("TXT", "legacy._domainkey.example.test", "v=DKIM1; p=FOREIGN")
	desired[1] = dnsprovider.Desired{Record: dnsprovider.Record{Type: "TXT", Name: "s2._domainkey.example.test", Value: "v=DKIM1; p=TWO"}, Prefix: "v=dkim1"}
	if _, err := zones.Apply(ctx, "admin", "example.test", desired, scope, dnsprovider.ApplyOptions{OverwriteConflicts: true}); err != nil {
		t.Fatal(err)
	}
	if len(memory.Values("TXT", "s1._domainkey.example.test")) != 0 || len(memory.Values("TXT", "s2._domainkey.example.test")) != 1 {
		t.Fatal("rotation did not retire s1 and publish s2")
	}
	if len(memory.Values("TXT", "legacy._domainkey.example.test")) != 1 {
		t.Fatal("a record Veksel did not create was deleted")
	}
	if got := memory.Values("TXT", "example.test"); len(got) != 1 || got[0] != "v=spf1 mx -all" {
		t.Fatalf("confirmed conflict was not overwritten: %v", got)
	}
	// The overwritten SPF is now owned and is updated without confirmation.
	desired[0].Value = "v=spf1 mx a -all"
	plan, err := zones.Plan(ctx, "example.test", desired, scope)
	if err != nil || plan.Changes[0].Action != dnsprovider.ActionUpdate {
		t.Fatalf("adopted record plan: %+v %v", plan.Changes, err)
	}
	actions := strings.Join(audit.actions(), ",")
	for _, want := range []string{"dns.zone.configure", "dns.record.create", "dns.record.update", "dns.record.delete"} {
		if !strings.Contains(actions, want) {
			t.Errorf("audit missing %s: %s", want, actions)
		}
	}
}

func TestFailedPublishDegradesHealthUntilASuccess(t *testing.T) {
	zones, memory, audit, _ := newTestZones(t)
	ctx := t.Context()
	if obs := zones.Observation(ctx); obs.State != health.StateDisabled {
		t.Fatalf("no zones: %+v", obs)
	}
	configure(t, zones)
	memory.FailWrites = errors.New("provider unavailable")
	desired := []dnsprovider.Desired{{Record: dnsprovider.Record{Type: "TXT", Name: "_dmarc.example.test", Value: "v=DMARC1; p=none"}, Prefix: "v=dmarc1"}}
	if _, err := zones.Apply(ctx, "admin", "example.test", desired, dnsprovider.Scope{Purpose: "example.test"}, dnsprovider.ApplyOptions{}); err == nil {
		t.Fatal("failed write reported success")
	}
	obs := zones.Observation(ctx)
	if obs.State != health.StateDegraded || obs.Severity != health.SeverityWarning || !strings.Contains(obs.Reason, "provider unavailable") {
		t.Fatalf("observation: %+v", obs)
	}
	if !strings.Contains(strings.Join(audit.actions(), ","), "dns.record.failed") {
		t.Fatal("failure was not audited")
	}
	memory.FailWrites = nil
	if _, err := zones.Apply(ctx, "admin", "example.test", desired, dnsprovider.Scope{Purpose: "example.test"}, dnsprovider.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if obs := zones.Observation(ctx); obs.State != health.StateHealthy {
		t.Fatalf("recovered observation: %+v", obs)
	}
}

func TestPresentTXTWaitsForPropagationAndCleansUp(t *testing.T) {
	zones, memory, _, _ := newTestZones(t)
	configure(t, zones)
	var asked []string
	zones.SetPropagation(dnsprovider.Propagation{Interval: time.Millisecond, Nameservers: func(_ context.Context, zone string) ([]string, error) {
		asked = append(asked, zone)
		return nil, errors.New("not reachable in this test")
	}})
	ctx := t.Context()
	if _, err := zones.PresentTXT(ctx, "_acme-challenge.example.test", "token-value", 20*time.Millisecond); err == nil {
		t.Fatal("propagation failure was ignored")
	}
	if len(memory.Values("TXT", "_acme-challenge.example.test")) != 0 || len(asked) == 0 || asked[0] != "example.test" {
		t.Fatalf("failed challenge must be cleaned up after asking the zone's servers: %v %v", memory.Values("TXT", "_acme-challenge.example.test"), asked)
	}
}
