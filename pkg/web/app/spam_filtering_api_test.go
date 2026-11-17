package app

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/spam"
)

type fakeSpamBlocklists []spam.ZoneStats

func (f fakeSpamBlocklists) Stats() []spam.ZoneStats { return f }
func (f fakeSpamBlocklists) CacheLen() int           { return 3 }
func (f fakeSpamBlocklists) CheckAddress(context.Context, netip.Addr, []spam.Zone) []spam.Listing {
	return nil
}

func TestAdminSpamFilteringStatus(t *testing.T) {
	server, _, _, _, handler := managedTestApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "owner")

	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/security/antispam", "", "")
	var disabled spamFilteringResponse
	decodeResponse(t, response, &disabled)
	if response.StatusCode != http.StatusOK || disabled.Enabled || disabled.Zones == nil {
		t.Fatalf("unconfigured status = %+v status=%d", disabled, response.StatusCode)
	}

	engine, err := spam.NewEngine(spam.Config{Thresholds: spam.DefaultThresholds()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var filtering spam.Switch
	filtering.Set(engine)
	refused := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	handler.ConfigureSpamFiltering(&filtering, fakeSpamBlocklists{{Zone: "zen.spamhaus.org", Kind: spam.ZoneDNSBL, Lookups: 4, Refused: 1, LastRefusedAt: refused}})
	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/security/antispam", "", "")
	var status spamFilteringResponse
	decodeResponse(t, response, &status)
	if !status.Enabled || status.Thresholds != spam.DefaultThresholds() || status.CacheEntries != 3 || len(status.Zones) != 1 || status.Zones[0].Refused != 1 || !status.Zones[0].LastRefusedAt.Equal(refused) {
		t.Fatalf("status = %+v", status)
	}
}
