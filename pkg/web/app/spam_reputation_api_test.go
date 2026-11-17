package app

import (
	"net/http"
	"testing"

	"github.com/lkarlslund/veksel/pkg/spam"
)

func TestAdminSpamReputationListsAndResets(t *testing.T) {
	server, _, _, _, handler := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	url := server.URL + "/api/v1/admin/security/antispam/reputation"

	response := authenticatedJSON(t, client, http.MethodGet, url, "", "")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured status = %d", response.StatusCode)
	}

	reputation := &spam.Reputation{}
	reputation.SetSettings(true, 3)
	handler.ConfigureSpamReputation(reputation)
	bad := spam.ReputationKeys{Domain: "bad.example", Network: "203.0.113.0/24"}
	good := spam.ReputationKeys{Domain: "good.example"}
	for range 6 {
		reputation.Record(bad, spam.RepJunked)
		reputation.Record(good, spam.RepAccepted)
	}
	reputation.Record(spam.ReputationKeys{Domain: "thin.example"}, spam.RepJunked)

	response = authenticatedJSON(t, client, http.MethodGet, url+"?limit=1", "", "")
	var report spam.ReputationReport
	decodeResponse(t, response, &report)
	if response.StatusCode != http.StatusOK || !report.Enabled || report.MinSamples != 3 || report.Tracked != 4 {
		t.Fatalf("report = %+v status=%d", report, response.StatusCode)
	}
	if len(report.BadDomains) != 1 || report.BadDomains[0].Key != "bad.example" || report.BadDomains[0].BadRatio != 1 ||
		len(report.GoodDomains) != 1 || report.GoodDomains[0].Key != "good.example" ||
		len(report.BadNetworks) != 1 || report.BadNetworks[0].Key != "203.0.113.0/24" || len(report.GoodNetworks) != 1 {
		t.Fatalf("lists = %+v", report)
	}

	response = authenticatedJSON(t, client, http.MethodGet, url+"?limit=0", "", "")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad limit status = %d", response.StatusCode)
	}

	response = authenticatedJSON(t, client, http.MethodDelete, url, csrf, "")
	decodeResponse(t, response, &report)
	if response.StatusCode != http.StatusOK || report.Tracked != 0 || len(report.BadDomains) != 0 {
		t.Fatalf("after reset = %+v status=%d", report, response.StatusCode)
	}
}
