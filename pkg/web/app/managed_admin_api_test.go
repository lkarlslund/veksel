package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/accountverify"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func managedTestApp(t *testing.T) (*httptest.Server, *model.TypedStore, *config.Service, *account.Manager, *Handler) {
	t.Helper()
	root := t.TempDir()
	backend, err := jsonstore.New(filepath.Join(root, "system"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := ts.EnsureNamespace(context.Background(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := New(ts)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := config.Open(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := account.NewManagerWithRoots([]account.Root{
		{ID: "fast", Path: filepath.Join(root, "accounts-fast")},
		{ID: "bulk", Path: filepath.Join(root, "accounts-bulk")},
	}, "fast", store.BackendPebble, account.WithKeyRing(handler.migrationJobs.KeyRing()))
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureAdministration(configuration.Current().Config, nil)
	if err := handler.ConfigureManagedConfiguration(configuration); err != nil {
		t.Fatal(err)
	}
	handler.ConfigureAccountStorage(accounts)
	verification, err := accountverify.New(t.Context(), ts, accounts, accountverify.Policy{Interval: 7 * 24 * time.Hour, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureAccountVerification(verification)
	routed, err := service.NewAccountFolderSpace(t.Context(), ts, accounts, authz.New(ts))
	if err != nil {
		t.Fatal(err)
	}
	durable, err := service.NewDurableFolderSpace(t.Context(), backend, routed)
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureMigrations(durable, nil)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	return server, ts, configuration, accounts, handler
}

func TestAdminConfigHistoryProjectsAndRedactsChanges(t *testing.T) {
	server, typed, configuration, _, _ := managedTestApp(t)
	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "owner")
	secret := "projection-must-never-return-this-secret"
	current := configuration.Current()
	response := authenticatedJSON(t, admin, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+current.Revision+`","reason":"projection test","settings":{"smtp_max_recipients":321,"relay_password":"`+secret+`"}}`)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("PATCH config status=%d body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/config/history?limit=1", "", "")
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(body), secret) {
		t.Fatalf("history status=%d leaked=%t body=%s", response.StatusCode, strings.Contains(string(body), secret), body)
	}
	var payload struct {
		Revisions []configHistoryRevision `json:"revisions"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Revisions) != 1 {
		t.Fatalf("history payload=%+v err=%v", payload, err)
	}
	changes := make(map[string]configHistoryChange)
	for _, change := range payload.Revisions[0].Changes {
		changes[change.Key] = change
	}
	if got := changes["smtp_max_recipients"]; got.Label != "Maximum recipients" || got.Section != "smtp" || got.Before.Text != "100" || got.After.Text != "321" || got.Direction != "changed" {
		t.Fatalf("ordinary history change=%+v", got)
	}
	if got := changes["relay_password"]; !got.Sensitive || got.Before.State != "redacted" || got.After.State != "redacted" || got.Before.Text != "Sensitive value redacted" || got.After.Text != "Sensitive value redacted" {
		t.Fatalf("sensitive history change=%+v", got)
	}

	if err := typed.UserStore().Create(t.Context(), "viewer", "Viewer", "password123"); err != nil {
		t.Fatal(err)
	}
	viewer := testClient(t)
	loginExistingUser(t, viewer, server.URL, "viewer")
	response, err := viewer.Get(server.URL + "/api/v1/admin/config/history")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin history status=%d", response.StatusCode)
	}
}

func TestProjectConfigHistoryValueStatesAndBounds(t *testing.T) {
	tests := []struct {
		name      string
		value     any
		sensitive bool
		state     string
		kind      string
		text      string
		truncated bool
	}{
		{name: "absent", state: "absent", kind: "absent", text: "Not set"},
		{name: "empty string", value: "", state: "value", kind: "string", text: ""},
		{name: "object", value: map[string]any{"z": float64(2), "a": true}, state: "value", kind: "object", text: "{\n  \"a\": true,\n  \"z\": 2\n}"},
		{name: "redacted", value: "private", sensitive: true, state: "redacted", kind: "redacted", text: "Sensitive value redacted"},
		{name: "bounded", value: strings.Repeat("x", maxConfigHistoryValueRunes+10), state: "value", kind: "string", text: strings.Repeat("x", maxConfigHistoryValueRunes) + "…", truncated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := projectConfigHistoryValue(test.value, test.sensitive)
			if got.State != test.state || got.Kind != test.kind || got.Text != test.text || got.Truncated != test.truncated {
				t.Fatalf("projection=%+v", got)
			}
		})
	}
}

func TestManagedConfigAndAccountStorageAPI(t *testing.T) {
	server, ts, configuration, accounts, handler := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	owner, err := ts.UserStore().Get(t.Context(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := accounts.Ensure(t.Context(), owner, "owner@example.test", []string{"owner@example.test"}); err != nil {
		t.Fatal(err)
	}
	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/account-verifications", "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET account verifications status = %d", response.StatusCode)
	}
	var scheduled struct {
		Policy struct {
			Enabled       bool `json:"enabled"`
			IntervalHours int  `json:"interval_hours"`
			Workers       int  `json:"workers"`
		} `json:"policy"`
		Statuses []accountverify.Status `json:"statuses"`
	}
	if err := json.NewDecoder(response.Body).Decode(&scheduled); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if scheduled.Policy.Enabled || scheduled.Policy.IntervalHours != 168 || scheduled.Policy.Workers != 1 || len(scheduled.Statuses) != 1 || scheduled.Statuses[0].Login != "owner" {
		t.Fatalf("scheduled verification response = %+v", scheduled)
	}
	if err := ts.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	ordinary := testClient(t)
	loginExistingUser(t, ordinary, server.URL, "ordinary")
	response = authenticatedJSON(t, ordinary, http.MethodGet, server.URL+"/api/v1/admin/account-verifications", "", "")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary GET account verifications status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/account-storage/owner/checks?repair=true", csrf, `{}`)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("POST account repair status = %d", response.StatusCode)
	}
	var integrityJob account.LifecycleJob
	if err := json.NewDecoder(response.Body).Decode(&integrityJob); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobs, jobsErr := accounts.LifecycleJobs("owner")
		if jobsErr != nil {
			t.Fatal(jobsErr)
		}
		if len(jobs) > 0 && jobs[0].ID == integrityJob.ID && jobs[0].Phase == account.LifecycleCompleted {
			integrityJob = jobs[0]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if integrityJob.Phase != account.LifecycleCompleted || integrityJob.ReportID == "" || integrityJob.Integrity == nil {
		t.Fatalf("integrity lifecycle job = %+v", integrityJob)
	}
	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/account-storage/owner/checks/"+integrityJob.ReportID, "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET integrity report status = %d", response.StatusCode)
	}
	var integrityReport account.IntegrityReport
	if err := json.NewDecoder(response.Body).Decode(&integrityReport); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if !integrityReport.Healthy || !integrityReport.Repair {
		t.Fatalf("integrity report = %+v", integrityReport)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/mail/drafts", csrf,
		`{"from":"owner@example.test","to":["other@example.test"],"subject":"Account local","body":"stored in account"}`)
	var draft service.ItemSummary
	if err := json.NewDecoder(response.Body).Decode(&draft); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated || draft.ID == "" {
		t.Fatalf("draft status=%d draft=%+v", response.StatusCode, draft)
	}
	if _, err := ts.ItemStore().Get(t.Context(), draft.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("draft leaked into system store: %v", err)
	}
	generation, release, err := accounts.Acquire("owner")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects).ItemStore().Get(t.Context(), draft.ID)
	release()
	if err != nil || !strings.Contains(string(stored.Data), "stored in account") {
		t.Fatalf("account-local draft=%+v err=%v", stored, err)
	}

	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/config", "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET config status = %d", response.StatusCode)
	}
	var current configAPIResponse
	if err := json.NewDecoder(response.Body).Decode(&current); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+current.Revision+`","reason":"raise recipient limit","settings":{"smtp_max_recipients":321}}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PATCH config status = %d", response.StatusCode)
	}
	var updated configAPIResponse
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if configuration.Current().Config.SmtpMaxRecipients != 321 {
		t.Fatal("configuration patch was not persisted")
	}
	applyByKey := make(map[string]config.SettingApplyStatus, len(updated.ApplyState))
	for _, state := range updated.ApplyState {
		applyByKey[state.Key] = state
	}
	if state := applyByKey["smtp_max_recipients"]; state.State != config.ApplyPendingRestart || state.Desired != int64(321) && state.Desired != float64(321) {
		t.Fatalf("SMTP apply state = %+v", state)
	}
	if updated.Plan == nil || !updated.Plan.RestartRequired || len(updated.Plan.Changes) != 1 || updated.Plan.Changes[0].Key != "smtp_max_recipients" || len(updated.Plan.DependencyGroups) != 1 || updated.Plan.DependencyGroups[0].ID != "smtp" {
		t.Fatalf("SMTP change plan = %+v", updated.Plan)
	}
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+current.Revision+`","settings":{"smtp_enabled":false}}`)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("stale PATCH status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/config/history?limit=10", "", "")
	var historyPayload struct {
		CurrentRevision string                  `json:"current_revision"`
		Revisions       []configHistoryRevision `json:"revisions"`
	}
	if err := json.NewDecoder(response.Body).Decode(&historyPayload); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || historyPayload.CurrentRevision != updated.Revision || len(historyPayload.Revisions) != 2 || historyPayload.Revisions[0].Actor != "owner" || historyPayload.Revisions[0].Reason != "raise recipient limit" {
		t.Fatalf("config history status=%d payload=%+v", response.StatusCode, historyPayload)
	}
	latestChanges := historyPayload.Revisions[0].Changes
	if len(latestChanges) != 1 || latestChanges[0].Key != "smtp_max_recipients" || latestChanges[0].Label != "Maximum recipients" || latestChanges[0].Section != "smtp" || latestChanges[0].Direction != "changed" || latestChanges[0].Before.Text != "100" || latestChanges[0].After.Text != "321" {
		t.Fatalf("projected configuration diff = %+v", latestChanges)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/config/history/"+current.Revision+"/validate", csrf,
		`{"revision":"`+updated.Revision+`"}`)
	var restorePlan config.ChangePlan
	if err := json.NewDecoder(response.Body).Decode(&restorePlan); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || restorePlan.BaseRevision != updated.Revision || restorePlan.ProposedRevision != current.Revision || len(restorePlan.Changes) != 1 {
		t.Fatalf("restore plan status=%d plan=%+v", response.StatusCode, restorePlan)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/config/history/"+current.Revision+"/restore", csrf,
		`{"revision":"`+updated.Revision+`","reason":"restore test baseline"}`)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("restore config status=%d body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()
	if configuration.Current().Revision != current.Revision || configuration.Current().Config.SmtpMaxRecipients != 100 {
		t.Fatalf("restored config = %+v", configuration.Current())
	}
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+current.Revision+`","reason":"adjust quota pressure","settings":{"quota_warning_percent":82,"quota_critical_percent":96}}`)
	var quotaPolicyUpdate configAPIResponse
	if err := json.NewDecoder(response.Body).Decode(&quotaPolicyUpdate); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || quotaPolicyUpdate.Plan == nil || quotaPolicyUpdate.Plan.RestartRequired || len(quotaPolicyUpdate.Plan.DependencyGroups) != 1 || quotaPolicyUpdate.Plan.DependencyGroups[0].ID != "quota-pressure" {
		t.Fatalf("quota policy update status=%d response=%+v", response.StatusCode, quotaPolicyUpdate)
	}
	quotaApply := make(map[string]config.SettingApplyStatus, len(quotaPolicyUpdate.ApplyState))
	for _, state := range quotaPolicyUpdate.ApplyState {
		quotaApply[state.Key] = state
	}
	if quotaApply["quota_warning_percent"].State != config.ApplyEffective || quotaApply["quota_critical_percent"].State != config.ApplyEffective {
		t.Fatalf("quota apply state = %+v", quotaApply)
	}
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+quotaPolicyUpdate.Revision+`","reason":"schedule account checks","settings":{"account_verification_enabled":true,"account_verification_interval_hours":24,"account_verification_workers":2}}`)
	var verificationPolicyUpdate configAPIResponse
	if err := json.NewDecoder(response.Body).Decode(&verificationPolicyUpdate); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	policy := handler.accountVerification.Policy()
	if response.StatusCode != http.StatusOK || verificationPolicyUpdate.Plan == nil || verificationPolicyUpdate.Plan.RestartRequired || len(verificationPolicyUpdate.Plan.DependencyGroups) != 1 || verificationPolicyUpdate.Plan.DependencyGroups[0].ID != "account-storage" || !policy.Enabled || policy.Interval != 24*time.Hour || policy.Workers != 2 {
		t.Fatalf("verification policy update status=%d response=%+v runtime=%+v", response.StatusCode, verificationPolicyUpdate, policy)
	}
	verificationApply := make(map[string]config.SettingApplyStatus, len(verificationPolicyUpdate.ApplyState))
	for _, state := range verificationPolicyUpdate.ApplyState {
		verificationApply[state.Key] = state
	}
	if verificationApply["account_verification_enabled"].State != config.ApplyEffective || verificationApply["account_verification_interval_hours"].State != config.ApplyEffective || verificationApply["account_verification_workers"].State != config.ApplyEffective {
		t.Fatalf("verification apply state = %+v", verificationApply)
	}
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+verificationPolicyUpdate.Revision+`","reason":"adjust health policy","settings":{"alert_evaluation_seconds":30,"alert_webhook_warning_minutes":12,"alert_webhook_critical_minutes":48,"alert_storage_warning_free_percent":18,"alert_storage_critical_free_percent":6,"alert_notifications_enabled":false}}`)
	var alertPolicyUpdate configAPIResponse
	if err := json.NewDecoder(response.Body).Decode(&alertPolicyUpdate); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || alertPolicyUpdate.Plan == nil || alertPolicyUpdate.Plan.RestartRequired || len(alertPolicyUpdate.Plan.DependencyGroups) != 1 || alertPolicyUpdate.Plan.DependencyGroups[0].ID != "health-alerts" {
		t.Fatalf("alert policy update status=%d response=%+v", response.StatusCode, alertPolicyUpdate)
	}
	if handler.cfg.AlertEvaluationSeconds != 30 || handler.cfg.AlertWebhookWarningMinutes != 12 || handler.cfg.AlertWebhookCriticalMinutes != 48 || handler.cfg.AlertStorageWarningFreePercent != 18 || handler.cfg.AlertStorageCriticalFreePercent != 6 || handler.cfg.AlertNotificationsEnabled {
		t.Fatalf("live alert policy = %+v", handler.cfg)
	}
	alertApply := make(map[string]config.SettingApplyStatus, len(alertPolicyUpdate.ApplyState))
	for _, state := range alertPolicyUpdate.ApplyState {
		alertApply[state.Key] = state
	}
	if alertApply["alert_evaluation_seconds"].State != config.ApplyEffective || alertApply["alert_webhook_warning_minutes"].State != config.ApplyEffective || alertApply["alert_webhook_critical_minutes"].State != config.ApplyEffective || alertApply["alert_storage_warning_free_percent"].State != config.ApplyEffective || alertApply["alert_storage_critical_free_percent"].State != config.ApplyEffective || alertApply["alert_notifications_enabled"].State != config.ApplyEffective {
		t.Fatalf("alert apply state = %+v", alertApply)
	}

	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/account-storage", "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET account storage status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/account-storage/owner/conversions", csrf, `{"engine":"badger"}`)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("POST conversion status = %d", response.StatusCode)
	}
	var conversion account.ConversionJob
	if err := json.NewDecoder(response.Body).Decode(&conversion); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	deadline = time.Now().Add(5 * time.Second)
	for {
		entry, found := accounts.ByLogin("owner")
		if found && entry.Manifest.Engine == store.BackendBadger {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("converted account = %+v, found=%v", entry, found)
		}
		time.Sleep(10 * time.Millisecond)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/account-storage/owner/conversions/"+conversion.ID+"/retained", csrf, `{"confirmation":"cleanup:`+conversion.ID+`"}`)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("DELETE retained conversion generation status = %d", response.StatusCode)
	}
	var conversionCleanup account.LifecycleJob
	if err := json.NewDecoder(response.Body).Decode(&conversionCleanup); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobs, jobsErr := accounts.LifecycleJobs("owner")
		if jobsErr != nil {
			t.Fatal(jobsErr)
		}
		for _, job := range jobs {
			if job.ID == conversionCleanup.ID && job.Phase == account.LifecycleCompleted {
				conversionCleanup = job
				break
			}
		}
		if conversionCleanup.Phase == account.LifecycleCompleted {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conversionCleanup.Phase != account.LifecycleCompleted || conversionCleanup.ParentJobID != conversion.ID {
		t.Fatalf("conversion cleanup = %+v", conversionCleanup)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/account-storage/owner/move", csrf, `{"root_id":"bulk"}`)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("POST account move status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	deadline = time.Now().Add(5 * time.Second)
	var moved account.Entry
	var found bool
	for time.Now().Before(deadline) {
		moved, found = accounts.ByLogin("owner")
		if found && moved.RootID == "bulk" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found || moved.RootID != "bulk" {
		t.Fatalf("moved account = %+v, found=%v", moved, found)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/account-storage/owner", csrf, `{"confirmation":"wrong"}`)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unconfirmed DELETE account storage status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/account-storage/owner", csrf, `{"confirmation":"purge:`+moved.Manifest.ID+`"}`)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("confirmed DELETE account storage status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, found = accounts.ByLogin("owner"); !found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if found {
		t.Fatal("purged account remains discoverable")
	}
	// The purge job records completion just after the account disappears.
	var lifecycle []account.LifecycleJob
	allCompleted := func() bool {
		for _, job := range lifecycle {
			if job.Phase != account.LifecycleCompleted {
				return false
			}
		}
		return true
	}
	for deadline = time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/account-storage/owner/lifecycle", "", "")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET lifecycle status = %d", response.StatusCode)
		}
		lifecycle = nil
		if err := json.NewDecoder(response.Body).Decode(&lifecycle); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if allCompleted() || !time.Now().Before(deadline) {
			break
		}
	}
	if len(lifecycle) != 4 {
		t.Fatalf("lifecycle jobs = %+v", lifecycle)
	}
	for _, job := range lifecycle {
		if job.Phase != account.LifecycleCompleted {
			t.Fatalf("lifecycle job did not complete: %+v", job)
		}
	}
}
