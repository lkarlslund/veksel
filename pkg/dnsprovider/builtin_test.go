package dnsprovider_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
)

func TestBuiltinZoneLifecycleAndValidation(t *testing.T) {
	zones, _, audit, _ := newTestZones(t)
	ctx := t.Context()
	if _, err := zones.AddHostedRecord(ctx, "admin", "example.test", dnsprovider.Record{Type: "A", Name: "example.test", Value: "192.0.2.1"}); err == nil {
		t.Fatal("records need a built-in zone")
	}
	view, err := zones.Put(ctx, "admin", "Example.Test.", dnsprovider.ZoneInput{Provider: dnsprovider.KindBuiltin})
	if err != nil || view.Provider != dnsprovider.KindBuiltin || view.SecretSet {
		t.Fatalf("builtin zone without credential: %+v %v", view, err)
	}
	hosted, ok := zones.Hosted().Zone("example.test")
	if !ok || hosted.Serial == 0 || len(hosted.Keys) != 1 || !hosted.Keys[0].Active || len(hosted.Keys[0].SealedPrivate) == 0 {
		t.Fatalf("hosted zone: %+v", hosted)
	}
	serial := hosted.Serial

	rejected := []dnsprovider.Record{
		{Type: "NS", Name: "example.test", Value: "ns.example.net."},
		{Type: "A", Name: "example.org", Value: "192.0.2.1"},
		{Type: "A", Name: "www.example.test", Value: "not-an-address"},
		{Type: "CNAME", Name: "example.test", Value: "elsewhere.example.net."},
	}
	for _, rec := range rejected {
		if _, err := zones.AddHostedRecord(ctx, "admin", "example.test", rec); err == nil {
			t.Errorf("%s %s %s was accepted", rec.Type, rec.Name, rec.Value)
		}
	}
	added, err := zones.AddHostedRecord(ctx, "admin", "example.test", dnsprovider.Record{Type: "caa", Name: "Example.Test.", Value: `0 issue "letsencrypt.org"`})
	if err != nil || added.ID == "" || added.Type != "CAA" || added.TTL != dnsprovider.DefaultTTL {
		t.Fatalf("CAA: %+v %v", added, err)
	}
	if _, err := zones.AddHostedRecord(ctx, "admin", "example.test", dnsprovider.Record{Type: "CNAME", Name: "www.example.test", Value: "example.test."}); err != nil {
		t.Fatal(err)
	}
	if _, err := zones.AddHostedRecord(ctx, "admin", "example.test", dnsprovider.Record{Type: "TXT", Name: "www.example.test", Value: "x"}); err == nil || !strings.Contains(err.Error(), "CNAME") {
		t.Fatalf("CNAME must not share its name: %v", err)
	}
	hosted, _ = zones.Hosted().Zone("example.test")
	if hosted.Serial <= serial {
		t.Fatalf("serial %d did not increase from %d", hosted.Serial, serial)
	}
	if err := zones.DeleteHostedRecord(ctx, "admin", "example.test", added.ID); err != nil {
		t.Fatal(err)
	}
	if err := zones.DeleteHostedRecord(ctx, "admin", "example.test", added.ID); err == nil {
		t.Fatal("deleting a missing record must fail")
	}

	// Switching to another provider stops hosting the zone.
	secret := "cf-secret-token"
	if _, err := zones.Put(ctx, "admin", "example.test", dnsprovider.ZoneInput{Provider: dnsprovider.KindCloudflare, Secret: &secret}); err != nil {
		t.Fatal(err)
	}
	if _, ok := zones.Hosted().Zone("example.test"); ok {
		t.Fatal("zone still hosted after switching provider")
	}
	if _, err := zones.HostedZone(ctx, "example.test"); !errors.Is(err, dnsprovider.ErrNotHosted) {
		t.Fatalf("HostedZone of an external zone: %v", err)
	}
	if _, err := zones.Put(ctx, "admin", "example.test", dnsprovider.ZoneInput{Provider: dnsprovider.KindBuiltin}); err != nil {
		t.Fatal(err)
	}
	view2, _ := zones.List(ctx)
	if len(view2) != 1 || view2[0].SecretSet {
		t.Fatalf("switching to builtin must drop the credential: %+v", view2)
	}
	if err := zones.Delete(ctx, "admin", "example.test"); err != nil {
		t.Fatal(err)
	}
	if len(zones.Hosted().Zones()) != 0 {
		t.Fatal("deleting the zone must stop hosting it")
	}
	actions := strings.Join(audit.actions(), " ")
	if !strings.Contains(actions, "dns.record.create") || !strings.Contains(actions, "dns.record.delete") {
		t.Fatalf("custom record changes are audited: %s", actions)
	}
}
