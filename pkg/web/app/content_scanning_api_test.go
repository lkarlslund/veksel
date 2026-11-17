package app

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/contentscan"
)

type appScannerFunc func(context.Context, contentscan.Message) (contentscan.Result, error)

func (appScannerFunc) Name() string { return "test-engine" }

func (f appScannerFunc) Scan(ctx context.Context, message contentscan.Message) (contentscan.Result, error) {
	return f(ctx, message)
}

func TestAdminContentScannerStatusAndTestAction(t *testing.T) {
	server, _, _, _, handler := managedTestApp(t)
	pipeline, err := contentscan.New(contentscan.Engine{
		Scanner: appScannerFunc(func(_ context.Context, message contentscan.Message) (contentscan.Result, error) {
			if len(message.Content) == 0 || message.Recipient != "scanner-test@localhost" {
				t.Errorf("test message = %+v", message)
			}
			return contentscan.Result{Verdict: contentscan.VerdictClean}, nil
		}),
		Timeout: time.Second, MaxInputBytes: 4096, FailurePolicy: contentscan.FailurePolicyDefer,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureContentScanning(pipeline)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/security/scanners", "", "")
	var before contentScannerStatusResponse
	decodeResponse(t, response, &before)
	if response.StatusCode != http.StatusOK || len(before.Engines) != 1 || before.Engines[0].Scans != 0 {
		t.Fatalf("status before test = %+v status=%d", before, response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/security/scanners/test", csrf, "{}")
	var report contentscan.Report
	decodeResponse(t, response, &report)
	if response.StatusCode != http.StatusOK || report.Decision != contentscan.DecisionAllow || len(report.Results) != 1 || report.Results[0].Verdict != contentscan.VerdictClean {
		t.Fatalf("test report = %+v status=%d", report, response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/security/scanners", "", "")
	var after contentScannerStatusResponse
	decodeResponse(t, response, &after)
	if len(after.Engines) != 1 || after.Engines[0].Scans != 1 || after.Engines[0].LastVerdict != contentscan.VerdictClean {
		t.Fatalf("status after test = %+v", after)
	}
}

func TestAdminContentScannerEndpointsRequireAdminAndCSRF(t *testing.T) {
	server, ts, _, _, _ := managedTestApp(t)
	owner := testClient(t)
	setupAndLogin(t, server, owner, "owner")
	response := authenticatedJSON(t, owner, http.MethodPost, server.URL+"/api/v1/admin/security/scanners/test", "", "{}")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", response.StatusCode)
	}
	if err := ts.UserStore().Create(t.Context(), "reader", "Reader", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "reader"); err != nil {
		t.Fatal(err)
	}
	reader := testClient(t)
	setupAndLogin(t, server, reader, "reader")
	response = authenticatedJSON(t, reader, http.MethodGet, server.URL+"/api/v1/admin/security/scanners", "", "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user status = %d", response.StatusCode)
	}
}
