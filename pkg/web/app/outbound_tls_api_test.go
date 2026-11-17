package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/dane"
	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/tlsrpt"
)

type testMTASTSAdmin struct {
	entries   []mtasts.CacheEntry
	refreshed string
}

func (a *testMTASTSAdmin) List(context.Context) ([]mtasts.CacheEntry, error) {
	return append([]mtasts.CacheEntry(nil), a.entries...), nil
}

func (a *testMTASTSAdmin) Refresh(_ context.Context, domain string) (mtasts.Result, error) {
	a.refreshed = domain
	return mtasts.Result{Source: mtasts.SourceLive, Policy: &mtasts.Policy{PolicyDomain: domain, Mode: mtasts.ModeEnforce}}, nil
}

type testTLSReportAdmin struct {
	days []string
	jobs []tlsrpt.ReportJob
}

func (a *testTLSReportAdmin) Days(context.Context) ([]string, error) {
	return append([]string(nil), a.days...), nil
}

func (a *testTLSReportAdmin) Jobs(context.Context) ([]tlsrpt.ReportJob, error) {
	return append([]tlsrpt.ReportJob(nil), a.jobs...), nil
}

func TestOutboundTLSAdministrationAPI(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "owner")
	now := time.Now().UTC()
	policies := &testMTASTSAdmin{entries: []mtasts.CacheEntry{
		{Domain: "active.example", Policy: &mtasts.Policy{Mode: mtasts.ModeEnforce, MX: []string{"mx.active.example"}}, PolicyID: "one", ExpiresAt: now.Add(time.Hour), LastCheckedAt: now},
		{Domain: "broken.example", LastFailure: &mtasts.Failure{Type: mtasts.FailureHTTPS, Message: "fetch failed"}, LastCheckedAt: now},
	}}
	reports := &testTLSReportAdmin{days: []string{"2026-08-17"}, jobs: []tlsrpt.ReportJob{{
		ID: "report-one", Day: "2026-08-17", PolicyDomain: "active.example", Status: tlsrpt.ReportRetrying,
		Policy: tlsrpt.ReportingPolicy{Domain: "active.example", URIs: []string{"mailto:reports@active.example"}},
		Report: tlsrpt.Report{Policies: []tlsrpt.ReportPolicy{{Summary: tlsrpt.ReportSummary{Successful: 7, Failure: 2}, FailureDetails: []tlsrpt.FailureDetail{{ResultType: tlsrpt.ResultValidationFailure}}}}},
		GZIP:   []byte("secret-machine-payload"), Attempts: 2, LastError: "temporary delivery failure", UpdatedAt: now,
	}}}
	handler.ConfigureOutboundTLS(policies, reports, true)
	handler.ConfigureDANE(func() dane.Status {
		return dane.Status{Enabled: true, Active: true, Source: dane.SourceSystem, Resolvers: []string{"127.0.0.53:53"}, Validating: dane.ValidatingYes}
	})

	response := authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/outbound-tls/status", "", "")
	var status struct {
		SchedulerRunning bool           `json:"scheduler_running"`
		PolicyStates     map[string]int `json:"policy_states"`
		ReportStates     map[string]int `json:"report_states"`
		RetainedDays     int            `json:"retained_days"`
		DANE             dane.Status    `json:"dane"`
	}
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !status.SchedulerRunning || status.PolicyStates["active"] != 1 || status.PolicyStates["failed"] != 1 || status.ReportStates[tlsrpt.ReportRetrying] != 1 || status.RetainedDays != 1 ||
		!status.DANE.Active || status.DANE.Validating != dane.ValidatingYes || status.DANE.Resolvers[0] != "127.0.0.53:53" {
		t.Fatalf("status=%d response=%+v", response.StatusCode, status)
	}

	response = authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/outbound-tls/mta-sts?q=active&state=active&sort=expires&direction=desc&page=1&page_size=25", "", "")
	var policyPage adminMTASTSPage
	if err := json.NewDecoder(response.Body).Decode(&policyPage); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || policyPage.Total != 1 || len(policyPage.Items) != 1 || policyPage.Items[0].Domain != "active.example" || !policyPage.Items[0].Effective {
		t.Fatalf("policy page status=%d response=%+v", response.StatusCode, policyPage)
	}

	response = authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/outbound-tls/reports?status=retrying&q=active&page=1&page_size=25", "", "")
	var reportPage adminTLSReportPage
	if err := json.NewDecoder(response.Body).Decode(&reportPage); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || reportPage.Total != 1 || len(reportPage.Items) != 1 || reportPage.Items[0].SuccessfulSessions != 7 || reportPage.Items[0].FailedSessions != 2 || reportPage.Items[0].FailureDetails != 1 {
		t.Fatalf("report page status=%d response=%+v", response.StatusCode, reportPage)
	}
	encoded, err := json.Marshal(reportPage)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-machine-payload") || strings.Contains(string(encoded), `"gzip"`) {
		t.Fatalf("report API exposed the machine payload: %s", encoded)
	}

	response = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/outbound-tls/mta-sts/new.example/refresh", csrf, `{}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || policies.refreshed != "new.example" {
		t.Fatalf("refresh status=%d domain=%q", response.StatusCode, policies.refreshed)
	}

	if err := ts.UserStore().Create(t.Context(), "viewer", "Viewer", "password123"); err != nil {
		t.Fatal(err)
	}
	viewer := testClient(t)
	loginExistingUser(t, viewer, server.URL, "viewer")
	response = authenticatedJSON(t, viewer, http.MethodGet, server.URL+"/api/v1/admin/outbound-tls/status", "", "")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin status = %d", response.StatusCode)
	}
}

func TestOutboundTLSAdministrationValidatesQueries(t *testing.T) {
	server, _, _, _, handler := managedTestApp(t)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "owner")
	handler.ConfigureOutboundTLS(&testMTASTSAdmin{}, &testTLSReportAdmin{}, false)
	for _, endpoint := range []string{
		"/api/v1/admin/outbound-tls/mta-sts?state=unknown",
		"/api/v1/admin/outbound-tls/mta-sts?sort=unknown",
		"/api/v1/admin/outbound-tls/mta-sts?direction=sideways",
		"/api/v1/admin/outbound-tls/reports?status=unknown",
		"/api/v1/admin/outbound-tls/reports?sort=unknown",
		"/api/v1/admin/outbound-tls/reports?page_size=101",
	} {
		response := authenticatedJSON(t, admin, http.MethodGet, server.URL+endpoint, "", "")
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s status=%d, want 400", endpoint, response.StatusCode)
		}
	}
}
