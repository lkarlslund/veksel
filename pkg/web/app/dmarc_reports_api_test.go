package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/dmarc"
)

type testDMARCAdmin struct {
	days      []string
	jobs      []dmarc.AggregateReportJob
	processed string
}

func (a *testDMARCAdmin) Days(context.Context) ([]string, error) {
	return append([]string(nil), a.days...), nil
}
func (a *testDMARCAdmin) Jobs(context.Context) ([]dmarc.AggregateReportJob, error) {
	return append([]dmarc.AggregateReportJob(nil), a.jobs...), nil
}
func (a *testDMARCAdmin) ProcessDay(_ context.Context, day string) ([]dmarc.AggregateReportJob, error) {
	a.processed = day
	return append([]dmarc.AggregateReportJob(nil), a.jobs...), nil
}

func TestDMARCAggregateAdministrationIsAdminOnlyAndPayloadFree(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "owner")
	now := time.Now().UTC()
	service := &testDMARCAdmin{days: []string{"2026-08-26"}, jobs: []dmarc.AggregateReportJob{{ID: "job", Day: "2026-08-26", PolicyDomain: "sender.test", Destination: "mailto:reports@external.test", Recipient: "reports@external.test", Status: dmarc.AggregateReportRetrying, ReportID: "report", Filename: "report.xml.gz", GZIP: []byte("secret-payload"), Attempts: 2, LastError: "temporary", UpdatedAt: now}}}
	handler.ConfigureDMARCAggregates(service, service, true)
	response := authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/security/dmarc-reports?status=retrying&q=sender&page=1&page_size=25", "", "")
	var page adminDMARCReportPage
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	encoded, _ := json.Marshal(page)
	if response.StatusCode != http.StatusOK || page.Total != 1 || !page.Running || strings.Contains(string(encoded), "secret-payload") || strings.Contains(string(encoded), `"gzip"`) {
		t.Fatalf("status=%d page=%+v JSON=%s", response.StatusCode, page, encoded)
	}
	response = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/security/dmarc-reports/2026-08-26/retry", csrf, `{}`)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || service.processed != "2026-08-26" {
		t.Fatalf("retry status=%d day=%q", response.StatusCode, service.processed)
	}
	if err := ts.UserStore().Create(t.Context(), "viewer", "Viewer", "password123"); err != nil {
		t.Fatal(err)
	}
	viewer := testClient(t)
	loginExistingUser(t, viewer, server.URL, "viewer")
	response = authenticatedJSON(t, viewer, http.MethodGet, server.URL+"/api/v1/admin/security/dmarc-reports", "", "")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer status=%d", response.StatusCode)
	}
}

func TestDMARCAggregateAdministrationValidatesInput(t *testing.T) {
	server, _, _, _, handler := managedTestApp(t)
	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "owner")
	service := &testDMARCAdmin{}
	handler.ConfigureDMARCAggregates(service, service, true)
	for _, endpoint := range []string{"/api/v1/admin/security/dmarc-reports?status=unknown", "/api/v1/admin/security/dmarc-reports?page_size=101"} {
		response := authenticatedJSON(t, admin, http.MethodGet, server.URL+endpoint, "", "")
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status=%d", endpoint, response.StatusCode)
		}
	}
	response := authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/security/dmarc-reports/not-a-day/retry", csrf, `{}`)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad retry status=%d", response.StatusCode)
	}
}
