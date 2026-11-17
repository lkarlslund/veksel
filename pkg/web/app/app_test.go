package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// testHandlers maps test server URLs to the handler behind them so setup
// helpers can read the one-time setup token the server would print at startup.
var testHandlers sync.Map

func serveTestApp(t *testing.T, handler *Handler, mux *http.ServeMux) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(mux)
	testHandlers.Store(server.URL, handler)
	t.Cleanup(func() { testHandlers.Delete(server.URL) })
	return server
}

func setupTokenFor(t *testing.T, server *httptest.Server) string {
	t.Helper()
	handler, ok := testHandlers.Load(server.URL)
	if !ok {
		t.Fatalf("server %s was not created by serveTestApp", server.URL)
	}
	token, err := handler.(*Handler).SetupToken(t.Context())
	if err != nil {
		t.Fatalf("setup token: %v", err)
	}
	return token
}

func setupAndLogin(t *testing.T, server *httptest.Server, client *http.Client, username string) string {
	t.Helper()
	resp, err := client.Get(server.URL + "/app/setup")
	if err != nil {
		t.Fatalf("get setup: %v", err)
	}
	_ = resp.Body.Close()
	csrf := csrfCookieValue(t, client, server.URL)
	resp, err = client.PostForm(server.URL+"/app/setup", url.Values{
		"_csrf": {csrf}, "token": {setupTokenFor(t, server)}, "username": {username}, "display_name": {username},
		"password": {"password123"}, "confirm": {"password123"},
	})
	if err != nil {
		t.Fatalf("post setup: %v", err)
	}
	_ = resp.Body.Close()
	resp, err = client.PostForm(server.URL+"/app/login", url.Values{
		"_csrf": {csrf}, "username": {username}, "password": {"password123"},
	})
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	_ = resp.Body.Close()
	return csrf
}

func testApp(t *testing.T) (*httptest.Server, *model.TypedStore) {
	t.Helper()
	handler, ts := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	return server, ts
}

func testHandler(t *testing.T) (*Handler, *model.TypedStore) {
	t.Helper()
	s, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return testHandlerOn(t, s)
}

// testHandlerOn creates a handler over s, which the caller closes.
func testHandlerOn(t *testing.T, s store.Store) (*Handler, *model.TypedStore) {
	t.Helper()
	ts := model.NewTypedStore(s, store.BackendJSON)
	for _, namespace := range []string{
		model.NSDomains, model.NSOutboundRoutes, model.NSUsers, model.NSEmails, model.NSRecipientAliases, model.NSUserAliases, model.NSFolders, model.NSItems, model.NSAPIKeys, model.NSAppPasswords,
		model.NSCerts, model.NSACMECache,
		model.NSSessions, model.NSRoles, model.NSGroups, model.NSPolicyBindings,
		model.NSPolicyIndexes, model.NSAuthorizationMetadata, model.NSSettings, model.NSMetadata, model.NSAudit, model.NSPGPKeys,
	} {
		if err := ts.EnsureNamespace(context.Background(), namespace); err != nil {
			t.Fatalf("ensure namespace %q: %v", namespace, err)
		}
	}
	handler, err := New(ts)
	if err != nil {
		t.Fatalf("create app handler: %v", err)
	}
	handler.ConfigureAdministration(config.Default(), nil)
	return handler, ts
}

func testClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar}
}

type acceptingSubmissionQueue struct {
	messages int
	queued   []*queue.Message
}

func (q *acceptingSubmissionQueue) EnqueueBatch(messages []*queue.Message) error {
	q.messages += len(messages)
	q.queued = append(q.queued, messages...)
	return nil
}

type failedProtocolControl struct{}

func (failedProtocolControl) StartIMAP()          {}
func (failedProtocolControl) StopIMAP()           {}
func (failedProtocolControl) IsIMAPRunning() bool { return false }
func (failedProtocolControl) StartSMTP()          {}
func (failedProtocolControl) StopSMTP()           {}
func (failedProtocolControl) IsSMTPRunning() bool { return false }
func (failedProtocolControl) StartPOP3()          {}
func (failedProtocolControl) StopPOP3()           {}
func (failedProtocolControl) IsPOP3Running() bool { return false }
func (failedProtocolControl) ProtocolRuntimeStatus(protocol string) ProtocolRuntimeStatus {
	if protocol == "smtp" {
		return ProtocolRuntimeStatus{Running: false, Error: "submission is enabled but no certificate is assigned"}
	}
	return ProtocolRuntimeStatus{}
}

func TestAdminSettingsPreserveDesiredAndFailedRuntimeState(t *testing.T) {
	server, _, configuration, _, handler := managedTestApp(t)
	current := configuration.Current()
	after, err := configuration.Patch(current.Revision, map[string]any{"smtp_enabled": true, "smtp_submission_enabled": true})
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureAdministration(after.Config, failedProtocolControl{})
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	response, err := client.Get(server.URL + "/api/v1/admin/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var payload struct {
		Settings       []model.Setting                  `json:"settings"`
		ProtocolStatus map[string]ProtocolRuntimeStatus `json:"protocol_status"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	desired, receiptSetting := false, false
	for _, setting := range payload.Settings {
		if setting.Key == "smtp_enabled" {
			desired = string(setting.ValueJSON) == "true"
		}
		if setting.Key == "queue_receipt_retention_days" {
			receiptSetting = setting.Advanced && string(setting.ValueJSON) == "7"
		}
	}
	runtime := payload.ProtocolStatus["smtp"]
	if !desired || !receiptSetting || runtime.Running || !strings.Contains(runtime.Error, "no certificate") {
		t.Fatalf("desired/runtime state lost: desired=%v runtime=%#v", desired, runtime)
	}
}

func TestAdminQueueReceiptPruneIsAuthorizedAuditedAndBounded(t *testing.T) {
	handler, ts := testHandler(t)
	mailQueue := queue.New(&queue.Config{ProcessPeriod: time.Hour})
	t.Cleanup(mailQueue.Close)
	handler.SetSystemQueue(mailQueue)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)

	unauthenticated := testClient(t)
	resp := authenticatedJSON(t, unauthenticated, http.MethodPost, server.URL+"/api/v1/admin/queue/receipts/prune", "", `{"older_than_days":7,"limit":10,"dry_run":true}`)
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("unauthenticated status=%d body=%s", resp.StatusCode, body)
	}
	_ = resp.Body.Close()

	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	loginPage, err := bob.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = loginPage.Body.Close()
	bobCSRF := csrfCookieValue(t, bob, server.URL)
	loginResponse, err := bob.PostForm(server.URL+"/app/login", url.Values{"_csrf": {bobCSRF}, "username": {"bob"}, "password": {"password123"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResponse.Body.Close()
	resp = authenticatedJSON(t, bob, http.MethodPost, server.URL+"/api/v1/admin/queue/receipts/prune", bobCSRF, `{"older_than_days":7,"limit":10,"dry_run":true}`)
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("non-admin status=%d body=%s", resp.StatusCode, body)
	}
	_ = resp.Body.Close()

	resp = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/receipts/prune", csrf, `{"older_than_days":0,"limit":10}`)
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("invalid prune status=%d body=%s", resp.StatusCode, body)
	}
	_ = resp.Body.Close()

	resp = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/receipts/prune", csrf, `{"older_than_days":7,"limit":10,"dry_run":true}`)
	var result struct {
		Result queue.ReceiptPruneResult `json:"result"`
		Error  string                   `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !result.Result.DryRun || result.Result.Examined != 0 || result.Error != "" {
		t.Fatalf("prune status=%d result=%+v", resp.StatusCode, result)
	}
	entries, err := audit.New(ts).QueryReverse(t.Context(), time.Time{}, "queue.receipts.prune", "", 10)
	if err != nil || len(entries) != 1 || entries[0].Actor != "alice" || entries[0].Details["dry_run"] != "true" {
		t.Fatalf("audit entries=%+v error=%v", entries, err)
	}
}

func TestAdminAuditPageIsCursorPagedAndAdminOnly(t *testing.T) {
	handler, ts := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)

	unauthenticated := testClient(t)
	response, err := unauthenticated.Get(server.URL + "/api/v1/admin/audit/page")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.StatusCode)
	}
	_ = response.Body.Close()

	admin := testClient(t)
	setupAndLogin(t, server, admin, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	loginPage, err := bob.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = loginPage.Body.Close()
	bobCSRF := csrfCookieValue(t, bob, server.URL)
	loginResponse, err := bob.PostForm(server.URL+"/app/login", url.Values{"_csrf": {bobCSRF}, "username": {"bob"}, "password": {"password123"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResponse.Body.Close()
	response, err = bob.Get(server.URL + "/api/v1/admin/audit/page")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin status = %d", response.StatusCode)
	}
	_ = response.Body.Close()

	for i := 1; i <= 5; i++ {
		handler.audit.Log("alice", "page.test", fmt.Sprintf("target-%d", i), nil)
	}
	type auditPage struct {
		Entries            []audit.Entry `json:"entries"`
		Total              int           `json:"total"`
		PageSize           int           `json:"page_size"`
		NextBeforeSequence int64         `json:"next_before_sequence"`
	}
	readPage := func(path string) auditPage {
		t.Helper()
		resp, err := admin.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("GET %s status=%d body=%s", path, resp.StatusCode, body)
		}
		var page auditPage
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			t.Fatal(err)
		}
		return page
	}
	first := readPage("/api/v1/admin/audit/page?page_size=2")
	if first.PageSize != 2 || first.Total < 5 || len(first.Entries) != 2 || first.Entries[0].Target != "target-5" || first.Entries[1].Target != "target-4" || first.NextBeforeSequence != first.Entries[1].Sequence {
		t.Fatalf("first page = %+v", first)
	}
	second := readPage("/api/v1/admin/audit/page?page_size=2&before_sequence=" + strconv.FormatInt(first.NextBeforeSequence, 10))
	if len(second.Entries) != 2 || second.Entries[0].Target != "target-3" || second.Entries[1].Target != "target-2" {
		t.Fatalf("second page = %+v", second)
	}

	response, err = admin.Get(server.URL + "/api/v1/admin/audit/page?page_size=101")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid page size status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestAdminMessageTraceMaintenanceReportsPreviewsRebuildsAndAudits(t *testing.T) {
	handler, ts := testHandler(t)
	traces, err := messagetrace.New(t.Context(), ts.Store())
	if err != nil {
		t.Fatal(err)
	}
	handler.SetMessageTrace(traces)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)

	unauthenticated := testClient(t)
	resp, err := unauthenticated.Get(server.URL + "/api/v1/admin/message-trace/status")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "trace-admin")
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	policy := mailpolicy.Result{Revision: "revision-ui", Rules: []mailpolicy.RuleResult{{RuleID: "reject-large", Matched: true, Conditions: []mailpolicy.ConditionResult{{Field: mailpolicy.FieldSizeBytes, Operator: mailpolicy.OperatorGreaterThan, Matched: true}}, Actions: []mailpolicy.Action{{Type: mailpolicy.ActionReject, Value: "too large"}}}}, Actions: []mailpolicy.Action{{Type: mailpolicy.ActionReject, Value: "too large"}}}
	if err := traces.Record(t.Context(), messagetrace.Record{QueueID: "expired-trace", Policy: policy}, messagetrace.Event{Time: old, Status: "delivered"}); err != nil {
		t.Fatal(err)
	}
	resp, err = admin.Get(server.URL + "/api/v1/admin/message-trace/status")
	if err != nil {
		t.Fatal(err)
	}
	var status messagetrace.MaintenanceStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || status.Index.State != "ready" || status.Stats.Records != 1 {
		t.Fatalf("status=%d payload=%+v", resp.StatusCode, status)
	}
	resp, err = admin.Get(server.URL + "/api/v1/admin/message-trace?after=not-a-time")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid trace range status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	rangeURL := server.URL + "/api/v1/admin/message-trace?after=" + url.QueryEscape(old.Add(-time.Hour).Format(time.RFC3339)) + "&before=" + url.QueryEscape(old.Add(time.Hour).Format(time.RFC3339))
	resp, err = admin.Get(rangeURL)
	if err != nil {
		t.Fatal(err)
	}
	var rangePage messagetrace.Page
	if err := json.NewDecoder(resp.Body).Decode(&rangePage); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(rangePage.Records) != 1 || rangePage.Records[0].QueueID != "expired-trace" {
		t.Fatalf("range status=%d payload=%+v", resp.StatusCode, rangePage)
	}
	resp, err = admin.Get(server.URL + "/api/v1/admin/message-trace/expired-trace")
	if err != nil {
		t.Fatal(err)
	}
	var detail messagetrace.Record
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || detail.Policy.Revision != "revision-ui" || len(detail.Policy.Rules) != 1 || detail.Policy.Rules[0].RuleID != "reject-large" {
		t.Fatalf("trace policy detail status=%d payload=%+v", resp.StatusCode, detail.Policy)
	}

	resp = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/message-trace/prune", csrf, `{"older_than_days":7,"limit":1,"dry_run":true}`)
	var preview struct {
		Result messagetrace.PruneResult `json:"result"`
		Error  string                   `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || preview.Result.Examined != 1 || preview.Result.Removed != 0 || preview.Error != "" {
		t.Fatalf("preview status=%d payload=%+v", resp.StatusCode, preview)
	}
	if _, err := traces.Get(t.Context(), "expired-trace"); err != nil {
		t.Fatalf("dry run removed trace: %v", err)
	}

	resp = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/message-trace/prune", csrf, `{"older_than_days":7,"limit":1}`)
	var pruned struct {
		Result messagetrace.PruneResult `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pruned); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if pruned.Result.Removed != 1 {
		t.Fatalf("prune payload=%+v", pruned)
	}
	resp = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/message-trace/index/rebuild", csrf, `{}`)
	var rebuilt messagetrace.IndexStatus
	if err := json.NewDecoder(resp.Body).Decode(&rebuilt); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || rebuilt.State != "ready" || rebuilt.Records != 0 {
		t.Fatalf("rebuild status=%d payload=%+v", resp.StatusCode, rebuilt)
	}
	entries, err := audit.New(ts).QueryReverse(t.Context(), time.Time{}, "message_trace.prune", "trace-admin", 10)
	if err != nil || len(entries) != 2 || entries[0].Target != "message-trace" {
		t.Fatalf("prune audits=%+v error=%v", entries, err)
	}
	rebuildEntries, err := audit.New(ts).QueryReverse(t.Context(), time.Time{}, "message_trace.index.rebuild", "trace-admin", 10)
	if err != nil || len(rebuildEntries) != 1 || rebuildEntries[0].Details["records"] != "0" {
		t.Fatalf("rebuild audits=%+v error=%v", rebuildEntries, err)
	}
}

func csrfCookieValue(t *testing.T, client *http.Client, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	for _, cookie := range client.Jar.Cookies(u) {
		if cookie.Name == csrfCookie {
			return cookie.Value
		}
	}
	t.Fatal("CSRF cookie not found")
	return ""
}

func TestFaviconIsPubliclyAvailableFromApplicationMux(t *testing.T) {
	server, _ := testApp(t)
	response, err := http.Get(server.URL + "/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "image/svg+xml" || len(body) < 200 {
		t.Fatalf("favicon status=%d type=%q bytes=%d", response.StatusCode, response.Header.Get("Content-Type"), len(body))
	}
}

func TestSetupLoginAndOwnerNavigation(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)

	resp, err := client.Get(server.URL + "/app/setup")
	if err != nil {
		t.Fatalf("get setup: %v", err)
	}
	_ = resp.Body.Close()
	csrf := csrfCookieValue(t, client, server.URL)
	resp, err = client.PostForm(server.URL+"/app/setup", url.Values{
		"_csrf": {csrf}, "token": {setupTokenFor(t, server)}, "username": {"alice"}, "display_name": {"Alice"},
		"password": {"password123"}, "confirm": {"password123"},
	})
	if err != nil {
		t.Fatalf("post setup: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "system owner account is ready") {
		t.Fatalf("setup response status=%d body=%s", resp.StatusCode, body)
	}

	resp, err = client.PostForm(server.URL+"/app/login", url.Values{
		"_csrf": {csrf}, "username": {"alice"}, "password": {"password123"},
	})
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Administration") {
		t.Fatalf("login response status=%d body=%s", resp.StatusCode, body)
	}
	keys, err := ts.List(t.Context(), model.NSSessions)
	if err != nil || len(keys) != 1 {
		t.Fatalf("session keys = %v, %v", keys, err)
	}
	if keys[0] == csrf || len(keys[0]) != 64 {
		t.Fatalf("session key was not hashed: %q", keys[0])
	}
}

func TestSetupRejectsMissingCSRF(t *testing.T) {
	server, _ := testApp(t)
	resp, err := http.PostForm(server.URL+"/app/setup", url.Values{
		"username": {"alice"}, "password": {"password123"}, "confirm": {"password123"},
	})
	if err != nil {
		t.Fatalf("post setup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestLogoutRequiresSubmittedCSRFToken(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// The CSRF cookie alone is what a cross-site form post would carry.
	resp, err := client.PostForm(server.URL+"/app/logout", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without token: status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	resp, err = client.PostForm(server.URL+"/app/logout", url.Values{"_csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("logout with token: status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
}

func TestSetupRequiresStartupToken(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	token := setupTokenFor(t, server)

	resp, err := client.Get(server.URL + "/app/setup?token=" + url.QueryEscape(token))
	if err != nil {
		t.Fatalf("get setup: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), `name="token" value="`+token+`"`) {
		t.Fatalf("setup link did not carry the token: %s", body)
	}
	csrf := csrfCookieValue(t, client, server.URL)
	for _, attempt := range []string{"", "guess"} {
		resp, err = client.PostForm(server.URL+"/app/setup", url.Values{
			"_csrf": {csrf}, "token": {attempt}, "username": {"mallory"},
			"password": {"password123"}, "confirm": {"password123"},
		})
		if err != nil {
			t.Fatalf("post setup: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("token %q: status = %d, want %d", attempt, resp.StatusCode, http.StatusForbidden)
		}
	}
	if users, err := model.NewUserStore(ts).List(t.Context()); err != nil || len(users) != 0 {
		t.Fatalf("users after rejected setup = %v, %v", users, err)
	}
}

func TestExistingOwnerlessStoreIsBlocked(t *testing.T) {
	server, ts := testApp(t)
	if err := model.NewUserStore(ts).Create(t.Context(), "legacy", "Legacy", "password123"); err != nil {
		t.Fatalf("create legacy user: %v", err)
	}
	resp, err := http.Get(server.URL + "/app/setup")
	if err != nil {
		t.Fatalf("get setup: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Automatic upgrade is disabled") {
		t.Fatalf("blocked response status=%d body=%s", resp.StatusCode, body)
	}
}

func TestRegularUserCannotOpenAdmin(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	if err := model.NewUserStore(ts).Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	// Give the store an owner so login is enabled, without granting Bob admin.
	if err := model.NewUserStore(ts).Create(t.Context(), "owner", "Owner", "password123"); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "owner"},
		Resource:  model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		Effect:    model.EffectAllow, RoleID: "system.owner", Inheritance: model.InheritanceSubtree,
		GrantedBy: "test",
	}); err != nil {
		t.Fatalf("grant owner: %v", err)
	}
	resp, err := client.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	_ = resp.Body.Close()
	csrf := csrfCookieValue(t, client, server.URL)
	resp, err = client.PostForm(server.URL+"/app/login", url.Values{"_csrf": {csrf}, "username": {"bob"}, "password": {"password123"}})
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	_ = resp.Body.Close()
	resp, err = client.Get(server.URL + "/app/admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestAuthorizationRESTFolderGrant(t *testing.T) {
	server, ts := testApp(t)
	ownerClient := testClient(t)
	csrf := setupAndLogin(t, server, ownerClient, "alice")
	if err := model.NewUserStore(ts).Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create grantee: %v", err)
	}

	body := []byte(`{"principal":{"kind":"user","id":"bob"},"effect":"allow","role_id":"folder.viewer","inheritance":"self"}`)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/folders/alice:INBOX/grants", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := ownerClient.Do(req)
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}
	responseBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create grant status=%d body=%s", resp.StatusCode, responseBody)
	}
	var createdGrant model.PolicyBinding
	if err := json.Unmarshal(responseBody, &createdGrant); err != nil {
		t.Fatalf("decode created grant: %v", err)
	}

	bobClient := testClient(t)
	resp, err = bobClient.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatalf("get Bob login: %v", err)
	}
	_ = resp.Body.Close()
	bobCSRF := csrfCookieValue(t, bobClient, server.URL)
	resp, err = bobClient.PostForm(server.URL+"/app/login", url.Values{"_csrf": {bobCSRF}, "username": {"bob"}, "password": {"password123"}})
	if err != nil {
		t.Fatalf("login Bob: %v", err)
	}
	_ = resp.Body.Close()

	checkBody := []byte(`{"action":"folder.items.read","resource":{"kind":"folder","id":"alice:INBOX"}}`)
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/authorization/check", bytes.NewReader(checkBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", bobCSRF)
	resp, err = bobClient.Do(req)
	if err != nil {
		t.Fatalf("check Bob permission: %v", err)
	}
	responseBody, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(responseBody), `"allowed":true`) {
		t.Fatalf("check status=%d body=%s", resp.StatusCode, responseBody)
	}

	resp, err = bobClient.Get(server.URL + "/api/v1/folders/alice:INBOX/grants")
	if err != nil {
		t.Fatalf("list grants as Bob: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Bob list grants status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	_ = resp.Body.Close()

	resp, err = bobClient.Get(server.URL + "/api/v1/grants")
	if err != nil {
		t.Fatalf("list managed grants as Bob: %v", err)
	}
	responseBody, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(responseBody) != "[]\n" {
		t.Fatalf("Bob managed grants status=%d body=%s", resp.StatusCode, responseBody)
	}
	resp = authenticatedJSON(t, bobClient, http.MethodDelete, server.URL+"/api/v1/grants/"+createdGrant.ID, bobCSRF, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Bob revoke managed grant status=%d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestManagedGrantOverviewFiltersAndRevokesThroughRBAC(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create grantee: %v", err)
	}
	if err := ts.UserStore().Create(t.Context(), "charlie", "Charlie", "password123"); err != nil {
		t.Fatalf("create unrelated owner: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "charlie"); err != nil {
		t.Fatalf("create unrelated folders: %v", err)
	}
	unrelated, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: "charlie:INBOX"},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderViewer,
		Inheritance: model.InheritanceSelf, GrantedBy: "charlie",
	})
	if err != nil {
		t.Fatalf("create unrelated grant: %v", err)
	}

	resp := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/folders/alice:INBOX/grants", csrf, `{"principal":{"kind":"user","id":"bob"},"effect":"allow","role_id":"folder.viewer","inheritance":"self"}`)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create grant status=%d body=%s", resp.StatusCode, body)
	}
	var created model.PolicyBinding
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created grant: %v", err)
	}

	resp, err = client.Get(server.URL + "/api/v1/grants")
	if err != nil {
		t.Fatalf("list managed grants: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var grants []model.PolicyBinding
	if err := json.Unmarshal(body, &grants); err != nil {
		t.Fatalf("decode managed grants: %v; body=%s", err, body)
	}
	if resp.StatusCode != http.StatusOK || len(grants) != 1 || grants[0].ID != created.ID {
		t.Fatalf("managed grants status=%d grants=%#v", resp.StatusCode, grants)
	}
	for _, grant := range grants {
		if grant.Resource.Kind == model.ResourceSystem || grant.Resource.Kind == model.ResourceDomain {
			t.Fatalf("self-service overview leaked administrative binding: %#v", grant)
		}
	}

	resp, err = client.Get(server.URL + "/api/v1/grants/" + created.ID)
	if err != nil {
		t.Fatalf("inspect managed grant: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), created.ID) {
		t.Fatalf("inspect managed grant status=%d body=%s", resp.StatusCode, body)
	}

	resp, err = client.Get(server.URL + "/api/v1/grants/" + created.ID + "/effective-access")
	if err != nil {
		t.Fatalf("effective managed grant: %v", err)
	}
	var effective service.ManagedGrantEffective
	if err := json.NewDecoder(resp.Body).Decode(&effective); err != nil {
		t.Fatalf("decode effective access: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !effective.Active || effective.Status != "allow" || len(effective.Decisions) != 4 {
		t.Fatalf("effective access status=%d result=%+v", resp.StatusCode, effective)
	}
	for _, decision := range effective.Decisions {
		if !decision.Allowed {
			t.Fatalf("viewer permission denied: %+v", decision)
		}
	}

	expires := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	updateBody := fmt.Sprintf(`{"effect":"allow","role_id":"folder.editor","inheritance":"subtree","expires_at":%q,"expected_updated_at":%q}`, expires.Format(time.RFC3339), created.UpdatedAt.Format(time.RFC3339Nano))
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/grants/"+created.ID, csrf, updateBody)
	var updated model.PolicyBinding
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated grant: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || updated.ID != created.ID || updated.Principal != created.Principal || updated.Resource != created.Resource || updated.RoleID != authz.RoleFolderEditor || updated.Inheritance != model.InheritanceSubtree || !updated.ExpiresAt.Equal(expires) || !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Fatalf("updated grant status=%d binding=%+v", resp.StatusCode, updated)
	}

	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/grants/"+created.ID, csrf, updateBody)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale managed grant update status=%d, want %d", resp.StatusCode, http.StatusConflict)
	}

	for _, endpoint := range []string{"/api/v1/grants/" + unrelated.ID, "/api/v1/grants/" + unrelated.ID + "/effective-access"} {
		resp, err = client.Get(server.URL + endpoint)
		if err != nil {
			t.Fatalf("request unrelated managed grant: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("unrelated managed grant %s status=%d, want %d", endpoint, resp.StatusCode, http.StatusForbidden)
		}
	}
	unrelatedUpdate := fmt.Sprintf(`{"effect":"allow","role_id":"folder.viewer","inheritance":"self","expires_at":null,"expected_updated_at":%q}`, unrelated.UpdatedAt.Format(time.RFC3339Nano))
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/grants/"+unrelated.ID, csrf, unrelatedUpdate)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unrelated managed grant update status=%d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/grants/"+created.ID, csrf, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete managed grant status=%d", resp.StatusCode)
	}
	resp, err = client.Get(server.URL + "/api/v1/grants")
	if err != nil {
		t.Fatalf("list managed grants after delete: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "[]\n" {
		t.Fatalf("managed grants after delete status=%d body=%s", resp.StatusCode, body)
	}
}

func TestGuidedGrantCustomFolderPayloadThroughREST(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create grantee: %v", err)
	}
	expires := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	body := fmt.Sprintf(`{"principal":{"kind":"user","id":"bob"},"effect":"deny","permissions":["folder.items.read","folder.items.delete"],"inheritance":"subtree","expires_at":%q}`, expires.Format(time.RFC3339))
	resp := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/folders/alice:INBOX/grants", csrf, body)
	var created model.PolicyBinding
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode custom grant: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || created.Effect != model.EffectDeny || created.Inheritance != model.InheritanceSubtree || created.RoleID != "" || !created.ExpiresAt.Equal(expires) {
		t.Fatalf("custom grant status=%d binding=%+v", resp.StatusCode, created)
	}
	wantPermissions := []string{string(authz.FolderItemsDelete), string(authz.FolderItemsRead)}
	if !slices.Equal(created.Permissions, wantPermissions) {
		t.Fatalf("custom permissions = %v, want %v", created.Permissions, wantPermissions)
	}

	resp = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/folders/alice:INBOX/grants", csrf, `{"principal":{"kind":"user","id":"bob"},"effect":"allow","permissions":[],"inheritance":"self"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty custom grant status=%d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestAuthorizationRESTRequiresCSRF(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/groups", strings.NewReader(`{"id":"team","name":"Team"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post group: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestDelegationSessionIsRecheckedAfterRevocation(t *testing.T) {
	server, ts := testApp(t)
	ownerClient := testClient(t)
	setupAndLogin(t, server, ownerClient, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create Bob: %v", err)
	}
	if err := ts.UserStore().Create(t.Context(), "carol", "Carol", "password123"); err != nil {
		t.Fatalf("create Carol: %v", err)
	}
	binding, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "carol"},
		Effect:    model.EffectAllow, RoleID: authz.RoleAccountDelegate,
		Inheritance: model.InheritanceSelf, GrantedBy: "carol",
	})
	if err != nil {
		t.Fatalf("grant delegation: %v", err)
	}

	client := testClient(t)
	resp, err := client.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatalf("get Bob login: %v", err)
	}
	_ = resp.Body.Close()
	csrf := csrfCookieValue(t, client, server.URL)
	resp, err = client.PostForm(server.URL+"/app/login", url.Values{"_csrf": {csrf}, "username": {"bob"}, "password": {"password123"}})
	if err != nil {
		t.Fatalf("login Bob: %v", err)
	}
	_ = resp.Body.Close()

	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/session/delegation", csrf, `{"subject_id":"carol"}`)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"acting_mode":"delegation"`) {
		t.Fatalf("start delegation status=%d body=%s", resp.StatusCode, body)
	}
	if err := model.NewPolicyStore(ts).Delete(t.Context(), binding.ID); err != nil {
		t.Fatalf("revoke delegation: %v", err)
	}
	resp, err = client.Get(server.URL + "/api/v1/session")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"subject_id":"bob"`) || !strings.Contains(string(body), `"acting_mode":""`) {
		t.Fatalf("revalidated session status=%d body=%s", resp.StatusCode, body)
	}
}

func TestImpersonationRequiresPasswordAndReason(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create Bob: %v", err)
	}

	resp := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/session/impersonation", csrf, `{"subject_id":"bob","password":"wrong","reason":"support case"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong password status=%d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/session/impersonation", csrf, `{"subject_id":"bob","password":"password123","reason":"support case"}`)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"acting_mode":"impersonation"`) || !strings.Contains(string(body), `"acting_reason":"support case"`) {
		t.Fatalf("impersonate status=%d body=%s", resp.StatusCode, body)
	}
	// The workspace while impersonating is Bob's, not Bob's plus everything
	// the administrator can reach.
	resp, err := client.Get(server.URL + "/api/v1/workspace/folders")
	if err != nil {
		t.Fatal(err)
	}
	var folders []struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&folders); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for _, folder := range folders {
		if folder.UserID == "alice" {
			t.Fatal("impersonated workspace lists the administrator's own folders")
		}
	}
	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/session/impersonation", csrf, "")
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"subject_id":"alice"`) {
		t.Fatalf("stop impersonation status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/folders")
	if err != nil {
		t.Fatal(err)
	}
	folders = nil
	_ = json.NewDecoder(resp.Body).Decode(&folders)
	_ = resp.Body.Close()
	if !slices.ContainsFunc(folders, func(folder struct {
		UserID string `json:"user_id"`
	}) bool {
		return folder.UserID == "alice"
	}) {
		t.Fatal("the administrator's folders are missing after returning to their account")
	}
}

func authenticatedJSON(t *testing.T, client *http.Client, method, endpoint, csrf, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	return resp
}

func TestEventWebSocketIsSessionAuthenticatedAndUserScoped(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create Bob: %v", err)
	}
	u, _ := url.Parse(server.URL)
	header := http.Header{"Origin": []string{server.URL}}
	for _, cookie := range client.Jar.Cookies(u) {
		header.Add("Cookie", cookie.String())
	}
	connection, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/events", header)
	if err != nil {
		if response != nil {
			t.Fatalf("connect event stream status=%d: %v", response.StatusCode, err)
		}
		t.Fatalf("connect event stream: %v", err)
	}
	defer connection.Close()
	resp := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/session/impersonation", csrf, `{"subject_id":"bob","password":"password123","reason":"support case"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start impersonation status=%d", resp.StatusCode)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	var event struct {
		Type     string `json:"type"`
		Resource string `json:"resource"`
	}
	if err := connection.ReadJSON(&event); err != nil {
		t.Fatalf("read event: %v", err)
	}
	if event.Type != "session.impersonation.started" || event.Resource != "bob" {
		encoded, _ := json.Marshal(event)
		t.Fatalf("event = %s", encoded)
	}
}

func TestUnifiedAdminCreatesDomainAccountAndIdentity(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	for _, request := range []struct {
		endpoint string
		body     string
	}{
		{endpoint: "/api/v1/admin/domains", body: `{"id":"example.test"}`},
		{endpoint: "/api/v1/admin/users", body: `{"id":"bob","display_name":"Bob","password":"password123"}`},
		{endpoint: "/api/v1/admin/identities", body: `{"address":"bob@example.test","user_id":"bob","primary":true}`},
	} {
		resp := authenticatedJSON(t, client, http.MethodPost, server.URL+request.endpoint, csrf, request.body)
		responseBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST %s status=%d body=%s", request.endpoint, resp.StatusCode, responseBody)
		}
	}
	identity, err := ts.UserStore().GetEmailAddress(t.Context(), "bob@example.test")
	if err != nil || identity.UserID != "bob" || !identity.Primary {
		t.Fatalf("identity=%#v err=%v", identity, err)
	}
	if _, err := ts.FolderStore().GetByPath(t.Context(), "bob", "Calendar"); err != nil {
		t.Fatalf("Bob default folders missing: %v", err)
	}
}

func TestUnifiedAdminDeletesDomainWithoutIdentityIndex(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	if err := ts.DomainStore().Create(t.Context(), "empty.test"); err != nil {
		t.Fatal(err)
	}
	response := authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/domains/empty.test", csrf, "")
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", response.StatusCode, body)
	}
	if _, err := ts.DomainStore().Get(t.Context(), "empty.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted domain error=%v", err)
	}
}

func TestUnifiedAdminResourcePagesAndPersistentSettings(t *testing.T) {
	server, ts, configuration, _, _ := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	resp, err := client.Get(server.URL + "/app/admin/domains")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="domains"`) || !strings.Contains(string(body), "Mail flow") || !strings.Contains(string(body), `id="admin-setting-search"`) || !strings.Contains(string(body), `id="admin-config-history"`) || !strings.Contains(string(body), `id="admin-config-dialog"`) || !strings.Contains(string(body), `id="admin-alert-drawer"`) || !strings.Contains(string(body), `id="admin-alert-button"`) {
		t.Fatalf("domains page status=%d body=%s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), `class="nav-icon"`) {
		t.Fatal("administration top-level navigation still contains prefixed icons")
	}
	if !strings.Contains(string(body), `href="/app/admin/health">Health</a>`) {
		t.Fatal("administration navigation is missing the health center")
	}
	if !strings.Contains(string(body), `href="/app/admin/notifications">Notifications</a>`) {
		t.Fatal("administration navigation is missing notifications")
	}
	if !strings.Contains(string(body), `href="/app/admin/recipients">Aliases &amp; groups</a>`) {
		t.Fatal("administration navigation is missing recipient aliases")
	}
	if !strings.Contains(string(body), `href="/app/admin/policies">Mail policies</a>`) {
		t.Fatal("administration navigation is missing mail policies")
	}
	if !strings.Contains(string(body), `href="/app/admin/outbound-tls">Outbound TLS</a>`) {
		t.Fatal("administration navigation is missing outbound TLS")
	}
	if !strings.Contains(string(body), `href="/app/admin/operations/queue">Queue</a>`) || !strings.Contains(string(body), `href="/app/admin/operations/trace">Message trace</a>`) || !strings.Contains(string(body), `href="/app/admin/operations/support">Support bundle</a>`) {
		t.Fatal("administration navigation is missing task-focused operations pages")
	}
	if strings.Contains(string(body), `id="workspace-modal"`) || !strings.Contains(string(body), `class="workspace-shell workspace-page" id="admin-control-plane"`) {
		t.Fatal("administration must render as a full page, not inside the workspace modal")
	}
	resp, err = client.Get(server.URL + "/app/admin/logs")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="logs"`) || !strings.Contains(string(body), `href="/app/admin/operations/logging">Log levels</a>`) {
		t.Fatalf("logs page status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/recipients")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="recipients"`) {
		t.Fatalf("recipients page status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/operations/queue")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="operations"`) || !strings.Contains(string(body), `data-operation="queue"`) {
		t.Fatalf("queue operations page status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/operations/support")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="operations"`) || !strings.Contains(string(body), `data-operation="support"`) {
		t.Fatalf("support operations page status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/operations")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-operation="overview"`) {
		t.Fatalf("legacy operations route status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="health"`) {
		t.Fatalf("health page status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/notifications")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="notifications"`) {
		t.Fatalf("notifications page status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/policies")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="policies"`) {
		t.Fatalf("mail policies page status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/outbound-tls")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="outbound-tls"`) {
		t.Fatalf("outbound TLS page status=%d body=%s", resp.StatusCode, body)
	}

	resp, err = client.Get(server.URL + "/app/admin/protocols/imap")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-section="protocols" data-protocol="imap"`) || !strings.Contains(string(body), ">SMTP</a>") || !strings.Contains(string(body), "(DAV)</a>") || !strings.Contains(string(body), `id="admin-menu-toggle"`) || !strings.Contains(string(body), `aria-controls="admin-menu-body"`) {
		t.Fatalf("IMAP protocol page status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/admin/protocols/managesieve")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-protocol="managesieve"`) || !strings.Contains(string(body), ">ManageSieve</a>") {
		t.Fatalf("ManageSieve protocol page status=%d body=%s", resp.StatusCode, body)
	}

	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/settings", csrf, `{"settings":{"smtp_listen":"0.0.0.0:2525","smtp_enabled":false}}`)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch settings status=%d body=%s", resp.StatusCode, body)
	}
	if value := configuration.Current().Config.SmtpListen; value != "0.0.0.0:2525" {
		t.Fatalf("stored listen=%q", value)
	}

	for _, request := range []struct{ method, endpoint, body string }{
		{http.MethodPost, "/api/v1/admin/domains", `{"id":"example.test"}`},
		{http.MethodPatch, "/api/v1/admin/domains/example.test", `{"enabled":false,"virus_scan_enabled":true}`},
		{http.MethodPost, "/api/v1/admin/users", `{"id":"bob","display_name":"Bob","password":"password123"}`},
		{http.MethodPatch, "/api/v1/admin/users/bob", `{"display_name":"Robert","enabled":true,"password":""}`},
	} {
		resp = authenticatedJSON(t, client, request.method, server.URL+request.endpoint, csrf, request.body)
		responseBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			t.Fatalf("%s %s status=%d body=%s", request.method, request.endpoint, resp.StatusCode, responseBody)
		}
	}
	domain, _ := ts.DomainStore().Get(t.Context(), "example.test")
	user, _ := ts.UserStore().Get(t.Context(), "bob")
	if domain.Enabled || user.DisplayName != "Robert" {
		t.Fatalf("domain=%#v user=%#v", domain, user)
	}

	// The domain catch-all must name an enabled local identity.
	catchAll := func(target string) int {
		resp := authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/domains/example.test", csrf, `{"catch_all":"`+target+`"}`)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if status := catchAll("bob@example.test"); status != http.StatusBadRequest {
		t.Fatalf("unknown catch-all target status = %d", status)
	}
	if err := ts.UserStore().AddEmailAddress(t.Context(), "bob@example.test", "bob", "example.test", true); err != nil {
		t.Fatal(err)
	}
	if status := catchAll("Bob@Example.test"); status != http.StatusOK {
		t.Fatalf("catch-all status = %d", status)
	}
	resp = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/domains", csrf, "")
	listed, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if domain, _ = ts.DomainStore().Get(t.Context(), "example.test"); domain.CatchAll != "bob@example.test" || !strings.Contains(string(listed), `"catch_all":"bob@example.test"`) {
		t.Fatalf("catch-all = %q, listing %s", domain.CatchAll, listed)
	}
	if status := catchAll(""); status != http.StatusOK {
		t.Fatalf("clear catch-all status = %d", status)
	}
	if domain, _ = ts.DomainStore().Get(t.Context(), "example.test"); domain.CatchAll != "" {
		t.Fatalf("cleared catch-all = %q", domain.CatchAll)
	}
}

func TestUserSettingsWorkspaceAndVacation(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().AddEmailAddress(t.Context(), "bob@example.test", "bob", "example.test", true); err != nil {
		t.Fatal(err)
	}
	authorization := service.NewAuthorization(ts, authz.New(ts))
	if _, err := authorization.CreateIdentityGrant(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceIdentity, ID: "bob@example.test"},
		Effect:    model.EffectAllow, Permissions: []string{string(authz.IdentitySendOnBehalf)}, Inheritance: model.InheritanceSelf,
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(server.URL + "/app/settings/vacation")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `id="workspace-modal"`) || !strings.Contains(string(body), "Automatic holiday reply") || !strings.Contains(string(body), `aria-label="Administration"`) || strings.Count(string(body), `data-theme-toggle`) != 1 || strings.Contains(string(body), `data-theme-choice`) || !strings.Contains(string(body), `/static/js/theme.js`) {
		t.Fatalf("settings workspace status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/settings/sync")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	syncPage := string(body)
	jobsIndex := strings.Index(syncPage, `id="migration-jobs"`)
	profileDialogIndex := strings.Index(syncPage, `id="migration-profile-dialog"`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(syncPage, `id="add-sync-profile"`) || !strings.Contains(syncPage, "Add sync profile") || !strings.Contains(syncPage, `id="migration-form"`) || !strings.Contains(syncPage, "Synchronization") || !strings.Contains(syncPage, `id="migration-security-label"`) || !strings.Contains(syncPage, `id="migration-endpoint-help"`) || !strings.Contains(syncPage, `id="migration-summary-step"`) || !strings.Contains(syncPage, `id="migration-run-dialog"`) || !strings.Contains(syncPage, `id="migration-detail-dialog"`) || !strings.Contains(syncPage, "Reconciliation evidence") || !strings.Contains(syncPage, "Select all") || !strings.Contains(syncPage, "Select none") || jobsIndex < 0 || profileDialogIndex < 0 || jobsIndex > profileDialogIndex {
		t.Fatalf("migration workspace status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/settings/storage")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `id="user-storage-settings"`) || !strings.Contains(string(body), "Storage &amp; quota") {
		t.Fatalf("storage workspace status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/app/settings/rules")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	rulesPage := string(body)
	for _, required := range []string{`id="automation-settings"`, `id="automation-rule-rows"`, `id="automation-rule-dialog"`, `id="automation-run-dialog"`, `id="automation-history-dialog"`, `id="automation-detail-dialog"`, "Rules &amp; automation", "Run history", "Add rule"} {
		if resp.StatusCode != http.StatusOK || !strings.Contains(rulesPage, required) {
			t.Fatalf("rules workspace missing %q: status=%d body=%s", required, resp.StatusCode, rulesPage)
		}
	}
	resp, err = client.Get(server.URL + "/app/settings/notifications")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	notificationPage := string(body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(notificationPage, `id="user-notification-settings"`) || !strings.Contains(notificationPage, "Notifications") || !strings.Contains(notificationPage, `class="active" aria-current="page" href="/app/settings/notifications"`) || strings.Contains(notificationPage, `aria-current="page" href="/app/settings/profile"`) || !strings.Contains(notificationPage, `class="workspace-menu-toggle"`) || !strings.Contains(notificationPage, `aria-controls="settings-menu-body"`) || strings.Contains(notificationPage, `data-ui-state="settings-navigation"`) {
		t.Fatalf("notification workspace status=%d body=%s", resp.StatusCode, body)
	}
	settingsPages := []struct {
		section string
		title   string
	}{
		{section: "access", title: "Access grants"},
		{section: "delegation", title: "Delegation"},
		{section: "share-links", title: "Share links"},
	}
	for _, page := range settingsPages {
		resp, err = client.Get(server.URL + "/app/settings/" + page.section)
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		settingsPage := string(body)
		for _, required := range []string{
			`id="access-management"`, `id="grant-rows"`, `id="new-grant"`,
			`id="grant-management-dialog"`, `id="grant-dialog"`,
			`class="active" aria-current="page" href="/app/settings/` + page.section + `"`,
			`<h1 tabindex="-1" autofocus>` + page.title + "</h1>",
		} {
			if resp.StatusCode != http.StatusOK || !strings.Contains(settingsPage, required) {
				t.Errorf("%s settings workspace missing %q (status %d)", page.section, required, resp.StatusCode)
			}
		}
		for _, other := range settingsPages {
			if other.section != page.section && strings.Contains(settingsPage, `aria-current="page" href="/app/settings/`+other.section+`"`) {
				t.Errorf("%s settings workspace also marks %s current", page.section, other.section)
			}
		}
		for _, repeated := range []string{`<span class="eyebrow">Shared access</span>`, `<h2>Grants you manage</h2>`} {
			if strings.Contains(settingsPage, repeated) {
				t.Errorf("%s settings workspace repeats its page title through %q", page.section, repeated)
			}
		}
	}

	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/user/profile", csrf, `{"display_name":"Alice Updated"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile update status=%d", resp.StatusCode)
	}
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/user/profile", csrf, `{"new_password":"replacement123"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("password update without current password status=%d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/vacation", csrf, `{"enabled":true,"start":"2027-07-01T08:00:00Z","end":"2027-07-14T18:00:00Z","subject":"On holiday","message":"I will respond when I return."}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vacation update status=%d", resp.StatusCode)
	}
	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/signatures/alice@example.test", csrf, `{"text":"Kind regards,\r\nAlice <unsafe>","new_messages":true,"replies_forwards":true}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signature update status=%d", resp.StatusCode)
	}
	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/signatures/bob@example.test", csrf, `{"text":"Not mine","new_messages":true}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delegated signature update status=%d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	user, err := ts.UserStore().Get(t.Context(), "alice")
	if err != nil || user.DisplayName != "Alice Updated" || !user.VacationEnabled || user.VacationSubject != "On holiday" || user.MailSignatures["alice@example.test"].Text != "Kind regards,\nAlice <unsafe>" {
		t.Fatalf("updated user=%#v err=%v", user, err)
	}

	resp, err = client.Get(server.URL + "/api/v1/user/settings")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	settingsBody := string(body)
	if resp.StatusCode != http.StatusOK ||
		!strings.Contains(settingsBody, `"address":"alice@example.test","primary":true,"modes":["normal","send_as"],"signature":{"text":"Kind regards,\nAlice \u003cunsafe\u003e","new_messages":true,"replies_forwards":true}}`) ||
		!strings.Contains(settingsBody, `"address":"bob@example.test","primary":false,"delegated":true,"modes":["send_as","send_on_behalf"]`) {
		t.Fatalf("user settings response status=%d body=%s", resp.StatusCode, body)
	}
	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/identities/alice@example.test", csrf, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("identity delete status=%d", resp.StatusCode)
	}
	user, err = ts.UserStore().Get(t.Context(), "alice")
	if err != nil || len(user.MailSignatures) != 0 {
		t.Fatalf("identity deletion retained signature: %#v, %v", user.MailSignatures, err)
	}
}

func TestAdminIdentityLifecycleAPI(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "admin")
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"address":"first@example.test","user_id":"admin","primary":false}`,
		`{"address":"second@example.test","user_id":"admin","primary":false}`,
	} {
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/identities", csrf, body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("create identity status=%d", response.StatusCode)
		}
	}
	response, err := client.Get(server.URL + "/api/v1/admin/users/admin/identities")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"id":"first@example.test"`) || !strings.Contains(string(body), `"id":"second@example.test"`) {
		t.Fatalf("identity list status=%d body=%s", response.StatusCode, body)
	}
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/identities/second@example.test", csrf, `{"enabled":true,"primary":true}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("promote identity status=%d", response.StatusCode)
	}
	first, _ := ts.UserStore().GetEmailAddress(t.Context(), "first@example.test")
	second, _ := ts.UserStore().GetEmailAddress(t.Context(), "second@example.test")
	if first.Primary || !second.Primary {
		t.Fatalf("primary identities first=%+v second=%+v", first, second)
	}
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/identities/second@example.test", csrf, `{"enabled":false,"primary":true}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("disabled primary status=%d, want %d", response.StatusCode, http.StatusBadRequest)
	}
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/identities/second@example.test", csrf, `{"enabled":false,"primary":false}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disable identity status=%d", response.StatusCode)
	}
	first, _ = ts.UserStore().GetEmailAddress(t.Context(), "first@example.test")
	if !first.Primary {
		t.Fatalf("replacement identity was not promoted: %+v", first)
	}
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/identities/first@example.test", "", `{"enabled":true,"primary":true}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("identity update without CSRF status=%d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

func TestClientManifestIsEmbeddedAndServed(t *testing.T) {
	manifest, err := buildClientManifest()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.HTML == "" || manifest.JavaScript == "" || manifest.CSS == "" || manifest.Revision == "" {
		t.Fatalf("incomplete client manifest: %#v", manifest)
	}

	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	resp, err := client.Get(server.URL + "/app/mail")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-client-javascript="`+manifest.JavaScript+`"`) {
		t.Fatalf("embedded manifest status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = client.Get(server.URL + "/api/v1/client-manifest")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store, max-age=0" || !strings.Contains(string(body), `"revision":"`+manifest.Revision+`"`) {
		t.Fatalf("manifest endpoint status=%d cache=%q body=%s", resp.StatusCode, resp.Header.Get("Cache-Control"), body)
	}
}

func TestWorkspaceCalendarAndContactAPIs(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	calendarID := model.FolderKey("alice", "Calendar")
	ical := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Veksel Test//EN\r\nBEGIN:VEVENT\r\nUID:planning-1\r\nDTSTAMP:20260801T000000Z\r\nSUMMARY:Planning\\, weekly\r\nDESCRIPTION:Bring\\nfolded \r\n notes\r\nDTSTART:20260817T090000Z\r\nDTEND:20260817T100000Z\r\nLOCATION:Studio\\; North\r\nORGANIZER;CN=Boss:mailto:boss@example.test\r\nATTENDEE;CN=Alice:mailto:alice@example.test\r\nCATEGORIES:Planning,Internal\r\nURL:https://calendar.example.test/event/1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	planningID, err := ts.ItemStore().Append(t.Context(), calendarID, []byte(ical), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(server.URL + "/api/v1/workspace/calendar/events?folder_id=" + url.QueryEscape(calendarID) + "&start=2026-08-01T00%3A00%3A00Z&end=2026-09-01T00%3A00%3A00Z")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"summary":"Planning, weekly"`) || !strings.Contains(string(body), `"location":"Studio; North"`) || !strings.Contains(string(body), `"description":"Bring\nfolded notes"`) || !strings.Contains(string(body), `"organizer":"Boss \u003cboss@example.test\u003e"`) || !strings.Contains(string(body), `"attendees":["Alice \u003calice@example.test\u003e"]`) || !strings.Contains(string(body), `"categories":["Planning","Internal"]`) {
		t.Fatalf("calendar events status=%d body=%s", resp.StatusCode, body)
	}
	resp = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/calendar/events", csrf,
		`{"folder_id":"`+calendarID+`","summary":"Review","start":"2026-08-18T12:00:00Z","end":"2026-08-18T13:00:00Z","location":"North room"}`)
	var event workspaceCalendarEvent
	if err := json.NewDecoder(resp.Body).Decode(&event); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || event.ID == "" || event.Summary != "Review" {
		t.Fatalf("created event status=%d event=%#v", resp.StatusCode, event)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/calendar/events/" + url.PathEscape(event.ID))
	if err != nil {
		t.Fatal(err)
	}
	var projectedEvent workspaceCalendarEvent
	if err := json.NewDecoder(resp.Body).Decode(&projectedEvent); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || projectedEvent.ID != event.ID || projectedEvent.FolderID != calendarID || projectedEvent.Summary != "Review" {
		t.Fatalf("calendar event projection status=%d event=%#v", resp.StatusCode, projectedEvent)
	}
	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/calendar/events/"+url.PathEscape(event.ID), csrf,
		`{"folder_id":"`+calendarID+`","summary":"Updated review","start":"2026-08-18T14:00:00Z","end":"2026-08-18T15:30:00Z","description":"Bring notes"}`)
	if err := json.NewDecoder(resp.Body).Decode(&event); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || event.Summary != "Updated review" || event.Description != "Bring notes" {
		t.Fatalf("updated event status=%d event=%#v", resp.StatusCode, event)
	}
	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/calendar/events/"+url.PathEscape(planningID), csrf,
		`{"folder_id":"`+calendarID+`","summary":"Planning, weekly","start":"2026-08-20T09:00:00Z","end":"2026-08-20T10:00:00Z"}`)
	olderUpdateBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update older indexed event status=%d body=%s", resp.StatusCode, olderUpdateBody)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/calendar/events?folder_id=" + url.QueryEscape(calendarID) + "&start=2026-08-01T00%3A00%3A00Z&end=2026-09-01T00%3A00%3A00Z")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"summary":"Updated review"`) || strings.Contains(string(body), `"summary":"Review"`) || !strings.Contains(string(body), `"dtstart":"2026-08-20T09:00:00Z"`) || strings.Contains(string(body), `"dtstart":"2026-08-17T09:00:00Z"`) {
		t.Fatalf("incremental calendar projection status=%d body=%s", resp.StatusCode, body)
	}
	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/calendar/events/"+url.PathEscape(event.ID), csrf, "")
	_ = resp.Body.Close()
	trashedEvent, _ := ts.ItemStore().Get(t.Context(), event.ID)
	if resp.StatusCode != http.StatusNoContent || trashedEvent.TrashedAt.IsZero() {
		t.Fatalf("delete event status=%d item=%#v", resp.StatusCode, trashedEvent)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/calendar/events?folder_id=" + url.QueryEscape(calendarID) + "&start=2026-08-01T00%3A00%3A00Z&end=2026-09-01T00%3A00%3A00Z")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), `"summary":"Updated review"`) {
		t.Fatalf("trashed event remained indexed status=%d body=%s", resp.StatusCode, body)
	}
	recurringResponse := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/calendar/events", csrf,
		`{"folder_id":"`+calendarID+`","summary":"Recurring review","start":"2026-08-03T09:00:00Z","end":"2026-08-03T10:00:00Z","recurrence":"weekly"}`)
	var recurring workspaceCalendarEvent
	if err := json.NewDecoder(recurringResponse.Body).Decode(&recurring); err != nil {
		t.Fatal(err)
	}
	_ = recurringResponse.Body.Close()
	if recurringResponse.StatusCode != http.StatusCreated || recurring.ID == "" {
		t.Fatalf("created recurring event status=%d event=%#v", recurringResponse.StatusCode, recurring)
	}
	occurrenceResponse := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/calendar/events/"+url.PathEscape(recurring.ID), csrf,
		`{"folder_id":"`+calendarID+`","summary":"Recurring review","start":"2026-08-10T13:15:00Z","end":"2026-08-10T14:15:00Z","recurrence_id":"2026-08-10T09:00:00Z","recurrence_scope":"occurrence"}`)
	_ = occurrenceResponse.Body.Close()
	if occurrenceResponse.StatusCode != http.StatusOK {
		t.Fatalf("updated recurring occurrence status=%d", occurrenceResponse.StatusCode)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/calendar/events?folder_id=" + url.QueryEscape(calendarID) + "&start=2026-08-01T00%3A00%3A00Z&end=2026-08-18T23%3A59%3A59Z")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"dtstart":"2026-08-10T13:15:00Z"`) || !strings.Contains(string(body), `"recurrence_id":"2026-08-10T09:00:00Z"`) {
		t.Fatalf("recurring occurrence projection status=%d body=%s", resp.StatusCode, body)
	}

	contactsID := model.FolderKey("alice", "Contacts")
	// The editor sends one payload shape, photo_changed included, to create and update.
	createBody := `{"fn":"Ada Lovelace","given_name":"Ada","family_name":"Lovelace","org":"Analytical Engines","emails":["ada@example.test"],"addresses":[{"type":"work","street":"1 Engine Way","locality":"London"}],"custom_fields":{"Favourite colour":"teal"},"photo_data":"AQID","photo_type":"PNG","photo_changed":true}`
	resp = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts?folder_id="+url.QueryEscape(contactsID), csrf, createBody)
	var created model.Contact
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || created.ID == "" || created.CustomFields["FAVOURITE-COLOUR"] != "teal" || len(created.PhotoData) != 3 {
		t.Fatalf("created contact status=%d contact=%#v", resp.StatusCode, created)
	}
	for _, body := range []string{
		`{"fn":"Grace Hopper","emails":["grace@example.test"]}`,
		`{"fn":"Katherine Johnson","emails":["katherine@example.test"]}`,
	} {
		createdResp := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts?folder_id="+url.QueryEscape(contactsID), csrf, body)
		_ = createdResp.Body.Close()
		if createdResp.StatusCode != http.StatusCreated {
			t.Fatalf("create additional contact status=%d", createdResp.StatusCode)
		}
	}

	resp, err = client.Get(server.URL + "/api/v1/workspace/contacts/page?limit=2&folder_id=" + url.QueryEscape(contactsID))
	if err != nil {
		t.Fatal(err)
	}
	var firstContactPage workspaceContactPage
	if err := json.NewDecoder(resp.Body).Decode(&firstContactPage); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(firstContactPage.Contacts) != 2 || firstContactPage.Total != 3 || firstContactPage.NextBeforeUID == 0 {
		t.Fatalf("first contact page status=%d page=%#v", resp.StatusCode, firstContactPage)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/contacts/page?limit=2&folder_id=" + url.QueryEscape(contactsID) + "&before_uid=" + strconv.FormatUint(uint64(firstContactPage.NextBeforeUID), 10))
	if err != nil {
		t.Fatal(err)
	}
	var secondContactPage workspaceContactPage
	if err := json.NewDecoder(resp.Body).Decode(&secondContactPage); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(secondContactPage.Contacts) != 1 || secondContactPage.Total != 3 || secondContactPage.Contacts[0].ID == firstContactPage.Contacts[0].ID || secondContactPage.Contacts[0].ID == firstContactPage.Contacts[1].ID {
		t.Fatalf("second contact page status=%d page=%#v", resp.StatusCode, secondContactPage)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/contact?item_id=" + url.QueryEscape(created.ID))
	if err != nil {
		t.Fatal(err)
	}
	var fetched model.Contact
	if err := json.NewDecoder(resp.Body).Decode(&fetched); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || fetched.ID != created.ID || fetched.FolderID != contactsID {
		t.Fatalf("get contact status=%d contact=%#v", resp.StatusCode, fetched)
	}
	createdItem, err := ts.ItemStore().Get(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	photoURL := server.URL + "/api/v1/workspace/contacts/" + url.PathEscape(created.ID) + "/photo?v=" + contactPhotoVersion(createdItem.UpdatedAt)
	resp, err = client.Get(photoURL)
	if err != nil {
		t.Fatal(err)
	}
	photo, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if resp.StatusCode != http.StatusOK || !bytes.Equal(photo, []byte{1, 2, 3}) || resp.Header.Get("Content-Type") != "image/png" || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") || etag == "" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("contact photo status=%d type=%q cache=%q etag=%q body=%v", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"), etag, photo)
	}
	request, err := http.NewRequest(http.MethodGet, photoURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("If-None-Match", etag)
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional contact photo status=%d, want 304", resp.StatusCode)
	}
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	loginExistingUser(t, bob, server.URL, "bob")
	resp, err = bob.Get(photoURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("other user's contact photo status=%d, want 403", resp.StatusCode)
	}

	cardDAVItem, err := ts.ItemStore().Get(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	cardDAVData := bytes.Replace(cardDAVItem.Data, []byte("END:VCARD\r\n"), []byte("ADR;TYPE=OTHER:;;Preserved Road;Odense;;;DK\r\nIMPP;TYPE=HOME:xmpp:ada@example.test\r\nX-ABUID:carddav-extension\r\nEND:VCARD\r\n"), 1)
	if _, err := ts.ItemStore().UpdateContent(t.Context(), created.ID, cardDAVData, cardDAVItem.Headers); err != nil {
		t.Fatal(err)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/contact?item_id=" + url.QueryEscape(created.ID))
	if err != nil {
		t.Fatal(err)
	}
	var afterCardDAV model.Contact
	if err := json.NewDecoder(resp.Body).Decode(&afterCardDAV); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	updateBody := `{"uid":"` + created.UID + `","mod_seq":` + strconv.FormatUint(afterCardDAV.ModSeq, 10) + `,"fn":"Ada Byron","given_name":"Ada","family_name":"Byron","emails":["ada@example.test"],"custom_fields":{"Language":"Go"}}`
	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/contact?item_id="+url.QueryEscape(created.ID), csrf, updateBody)
	var updated model.Contact
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || updated.FN != "Ada Byron" || updated.CustomFields["LANGUAGE"] != "Go" {
		t.Fatalf("updated contact status=%d contact=%#v", resp.StatusCode, updated)
	}
	preservedItem, err := ts.ItemStore().Get(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, property := range []string{"ADR;TYPE=OTHER:;;Preserved Road;Odense;;;DK", "IMPP;TYPE=HOME:xmpp:ada@example.test", "X-ABUID:carddav-extension"} {
		if !bytes.Contains(preservedItem.Data, []byte(property)) {
			t.Errorf("web edit stripped CardDAV property %q:\n%s", property, preservedItem.Data)
		}
	}
	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/contact?item_id="+url.QueryEscape(created.ID), csrf, updateBody)
	staleBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(staleBody), "contact changed; reload") {
		t.Fatalf("stale contact update status=%d body=%s", resp.StatusCode, staleBody)
	}

	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/contact?item_id="+url.QueryEscape(created.ID), csrf, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete contact status=%d", resp.StatusCode)
	}
}

func TestWorkspaceFoldersExposeEffectiveItemCapabilities(t *testing.T) {
	server, ts := testApp(t)
	owner := testClient(t)
	csrf := setupAndLogin(t, server, owner, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create Bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatalf("create Bob folders: %v", err)
	}

	response := authenticatedJSON(t, owner, http.MethodPost, server.URL+"/api/v1/workspace/folders", csrf, `{"name":"Editable team","type":"calendar","parent_id":""}`)
	var editable model.Folder
	if err := json.NewDecoder(response.Body).Decode(&editable); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create editable calendar status=%d", response.StatusCode)
	}

	policies := model.NewPolicyStore(ts)
	for _, grant := range []struct {
		folderID string
		roleID   string
	}{
		{folderID: model.FolderKey("alice", "Calendar"), roleID: authz.RoleFolderViewer},
		{folderID: editable.ID, roleID: authz.RoleFolderEditor},
	} {
		if _, err := policies.Create(t.Context(), model.PolicyBinding{
			Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
			Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: grant.folderID},
			Effect:    model.EffectAllow, RoleID: grant.roleID,
			Inheritance: model.InheritanceSelf, GrantedBy: "alice",
		}); err != nil {
			t.Fatalf("grant %s on %s: %v", grant.roleID, grant.folderID, err)
		}
	}

	bob := testClient(t)
	loginExistingUser(t, bob, server.URL, "bob")
	response, err := bob.Get(server.URL + "/api/v1/workspace/folders")
	if err != nil {
		t.Fatal(err)
	}
	var folders []workspaceFolder
	if err := json.NewDecoder(response.Body).Decode(&folders); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list folders status=%d", response.StatusCode)
	}
	byID := make(map[string]workspaceFolder, len(folders))
	for _, folder := range folders {
		byID[folder.ID] = folder
	}
	owned := byID[model.FolderKey("bob", "Calendar")].Capabilities
	if !owned.ReadItems || !owned.CreateItems || !owned.UpdateItems || !owned.DeleteItems {
		t.Fatalf("owned calendar capabilities = %+v, want all item mutations", owned)
	}
	viewer := byID[model.FolderKey("alice", "Calendar")].Capabilities
	if !viewer.ReadItems || viewer.CreateItems || viewer.UpdateItems || viewer.DeleteItems {
		t.Fatalf("viewer calendar capabilities = %+v, want read-only", viewer)
	}
	editor := byID[editable.ID].Capabilities
	if !editor.ReadItems || !editor.CreateItems || !editor.UpdateItems || !editor.DeleteItems {
		t.Fatalf("editor calendar capabilities = %+v, want all item mutations", editor)
	}
}

func TestWorkspaceContactGroupsUseAuthorizedFolderSpace(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	contactsID := model.FolderKey("alice", "Contacts")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts?folder_id="+url.QueryEscape(contactsID), csrf,
		`{"fn":"Project team","kind":"GROUP","members":["ada@example.test","urn:uuid:member-2","MAILTO:ADA@example.test"]}`)
	var group model.Contact
	if err := json.NewDecoder(response.Body).Decode(&group); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated || group.Kind != "group" || len(group.Members) != 2 || group.Members[0] != "mailto:ada@example.test" || group.Members[1] != "urn:uuid:member-2" {
		t.Fatalf("created group status=%d group=%#v", response.StatusCode, group)
	}
	item, err := ts.ItemStore().Get(t.Context(), group.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, property := range []string{"VERSION:4.0", "KIND:group", "MEMBER:mailto:ada@example.test", "MEMBER:urn:uuid:member-2"} {
		if !bytes.Contains(item.Data, []byte(property)) {
			t.Errorf("stored group is missing %q:\n%s", property, item.Data)
		}
	}
	withOpaque := bytes.Replace(item.Data, []byte("END:VCARD\r\n"), []byte("X-CLIENT-STATE:keep\r\nEND:VCARD\r\n"), 1)
	if _, err := ts.ItemStore().UpdateContent(t.Context(), group.ID, withOpaque, item.Headers); err != nil {
		t.Fatal(err)
	}
	response, err = client.Get(server.URL + "/api/v1/workspace/contact?item_id=" + url.QueryEscape(group.ID))
	if err != nil {
		t.Fatal(err)
	}
	var current model.Contact
	if err := json.NewDecoder(response.Body).Decode(&current); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	update, err := json.Marshal(model.Contact{FN: "Core team", Kind: "group", Members: []string{"ada@example.test", "https://directory.example.test/members/2"}, ModSeq: current.ModSeq})
	if err != nil {
		t.Fatal(err)
	}
	response = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/contact?item_id="+url.QueryEscape(group.ID), csrf, string(update))
	var updated model.Contact
	if err := json.NewDecoder(response.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || updated.FN != "Core team" || updated.Kind != "group" || len(updated.Members) != 2 || updated.Members[1] != "https://directory.example.test/members/2" {
		t.Fatalf("updated group status=%d group=%#v", response.StatusCode, updated)
	}
	item, err = ts.ItemStore().Get(t.Context(), group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(item.Data, []byte("X-CLIENT-STATE:keep")) || bytes.Contains(item.Data, []byte("urn:uuid:member-2")) {
		t.Fatalf("group update did not preserve opaque state or remove old member:\n%s", item.Data)
	}

	for name, body := range map[string]string{
		"individual with members": `{"fn":"Not a group","members":["a@example.test"]}`,
		"relative member URI":     `{"fn":"Broken group","kind":"group","members":["relative/member"]}`,
		"unsupported kind":        `{"fn":"Room","kind":"location"}`,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts?folder_id="+url.QueryEscape(contactsID), csrf, body)
			defer invalid.Body.Close()
			if invalid.StatusCode != http.StatusBadRequest {
				payload, _ := io.ReadAll(invalid.Body)
				t.Fatalf("status=%d body=%s", invalid.StatusCode, payload)
			}
		})
	}
	members := make([]string, maxContactGroupMembers+1)
	for index := range members {
		members[index] = fmt.Sprintf("member%d@example.test", index)
	}
	overflow, err := json.Marshal(model.Contact{FN: "Too large", Kind: "group", Members: members})
	if err != nil {
		t.Fatal(err)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts?folder_id="+url.QueryEscape(contactsID), csrf, string(overflow))
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized group status=%d, want 400", response.StatusCode)
	}

	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	loginExistingUser(t, bob, server.URL, "bob")
	response, err = bob.Get(server.URL + "/api/v1/workspace/contact?item_id=" + url.QueryEscape(group.ID))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized group read status=%d, want 403", response.StatusCode)
	}

	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/contact?item_id="+url.QueryEscape(group.ID), csrf, "")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("trash group status=%d", response.StatusCode)
	}
}

func TestContactSuggestionsSearchOnlyRBACVisibleAddressBooks(t *testing.T) {
	handler, ts := testHandler(t)
	recorder := &searchRecorder{}
	handler.ConfigureSearch(recorder)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	ownerClient := testClient(t)
	setupAndLogin(t, server, ownerClient, "alice")
	contactsID := model.FolderKey("alice", "Contacts")
	contact := model.Contact{FN: "Ada Lovelace", Nickname: "Enchantress", Emails: []string{"ada@example.test", "ada@work.example"}, Phones: []string{"+45 1234"}, Note: "private analytical notes", PhotoData: []byte{1, 2, 3}, PhotoType: "PNG"}
	itemID, err := ts.ItemStore().Append(t.Context(), contactsID, model.ContactToVCard(contact), nil)
	if err != nil {
		t.Fatalf("append contact: %v", err)
	}
	photoUpdated := time.Date(2026, time.August, 27, 10, 11, 12, 13, time.UTC)
	recorder.page = service.SearchPage{Hits: []service.SearchHit{{ItemID: itemID, FolderID: contactsID, Type: model.FolderTypeContacts, Name: contact.FN, ContactEmails: contact.Emails, ContactHasPhoto: true, Updated: photoUpdated}}, Total: 1, IndexID: "idx-contacts"}
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatalf("create Bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatalf("create Bob folders: %v", err)
	}
	bobClient := testClient(t)
	resp, err := bobClient.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	csrf := csrfCookieValue(t, bobClient, server.URL)
	resp, err = bobClient.PostForm(server.URL+"/app/login", url.Values{"_csrf": {csrf}, "username": {"bob"}, "password": {"password123"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	getSuggestions := func(query string) []contactSuggestion {
		t.Helper()
		response, requestErr := bobClient.Get(server.URL + "/api/v1/workspace/contacts/suggestions?q=" + url.QueryEscape(query))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("suggestions status=%d body=%s", response.StatusCode, body)
		}
		var suggestions []contactSuggestion
		if err := json.NewDecoder(response.Body).Decode(&suggestions); err != nil {
			t.Fatal(err)
		}
		return suggestions
	}
	if suggestions := getSuggestions("ada"); len(suggestions) != 0 {
		t.Fatalf("private suggestions leaked before grant: %#v", suggestions)
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: contactsID},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderViewer,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatalf("share address book: %v", err)
	}
	recorder.err = service.ErrForbidden
	if suggestions := getSuggestions("enchantress"); len(suggestions) != 0 {
		t.Fatalf("folder grant bypassed separate search permission: %#v", suggestions)
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"},
		Effect:    model.EffectAllow, RoleID: authz.RoleAccountSearcher,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatalf("grant account search: %v", err)
	}
	recorder.err = nil
	suggestions := getSuggestions("enchantress")
	if len(suggestions) != 2 || suggestions[0].Name != "Ada Lovelace" || suggestions[0].UserID != "alice" {
		t.Fatalf("shared suggestions=%#v", suggestions)
	}
	wantPhotoURL := "/api/v1/workspace/contacts/" + url.PathEscape(itemID) + "/photo?v=" + url.QueryEscape(contactPhotoVersion(photoUpdated))
	if suggestions[0].PhotoURL != wantPhotoURL || suggestions[1].PhotoURL != wantPhotoURL {
		t.Fatalf("suggestion photo URLs = %q, %q; want %q", suggestions[0].PhotoURL, suggestions[1].PhotoURL, wantPhotoURL)
	}
	photoResponse, err := bobClient.Get(server.URL + suggestions[0].PhotoURL)
	if err != nil {
		t.Fatal(err)
	}
	photo, _ := io.ReadAll(photoResponse.Body)
	_ = photoResponse.Body.Close()
	if photoResponse.StatusCode != http.StatusOK || !bytes.Equal(photo, contact.PhotoData) || photoResponse.Header.Get("Cross-Origin-Resource-Policy") != "same-origin" || photoResponse.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("delegated suggestion photo status=%d headers=%v body=%v", photoResponse.StatusCode, photoResponse.Header, photo)
	}
	if recorder.query.AccountID != "alice" || recorder.query.Text != "" || recorder.query.Limit != 12 || recorder.query.Filter == nil || recorder.query.Filter.Field != "contact_suggest" || recorder.query.Filter.Operator != service.SearchContains || recorder.query.Filter.Value != "enchantress" {
		t.Fatalf("suggestion index query = %+v", recorder.query)
	}
	encoded, _ := json.Marshal(suggestions)
	if strings.Contains(string(encoded), "1234") || strings.Contains(string(encoded), "private analytical") || strings.Contains(string(encoded), "photo_data") || strings.Contains(string(encoded), "AQID") {
		t.Fatalf("suggestions leaked non-address contact fields: %s", encoded)
	}
	recorder.page = service.SearchPage{Hits: []service.SearchHit{{ItemID: itemID, FolderID: contactsID, Type: model.FolderTypeContacts, Name: contact.FN, ContactEmails: contact.Emails, Updated: photoUpdated}}, Total: 1, IndexID: "idx-contacts"}
	withoutPhoto := getSuggestions("ada")
	withoutPhotoJSON, _ := json.Marshal(withoutPhoto)
	if len(withoutPhoto) != 2 || withoutPhoto[0].PhotoURL != "" || strings.Contains(string(withoutPhotoJSON), "photo_url") {
		t.Fatalf("contact without indexed photo exposed a photo URL: %#v", withoutPhoto)
	}
	recorder.page = service.SearchPage{Hits: []service.SearchHit{}, IndexID: "idx-contacts"}
	if suggestions := getSuggestions("private analytical"); len(suggestions) != 0 {
		t.Fatalf("private notes were searchable: %#v", suggestions)
	}
}

func TestWorkspaceMIMEProjectionAndAttachmentDownload(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	raw := strings.Join([]string{
		"From: sender@example.test", "To: alice@example.test", "Subject: Files",
		"MIME-Version: 1.0", "Content-Type: multipart/mixed; boundary=x", "",
		"--x", "Content-Type: text/html; charset=utf-8", "", `<p>Hello</p><img src="https://tracker.test/pixel"><script>bad()</script>`,
		"--x", `Content-Type: text/plain; name="hello.txt"`, `Content-Disposition: attachment; filename="hello.txt"`, "Content-Transfer-Encoding: base64", "", "aGVsbG8=",
		"--x--", "",
	}, "\r\n")
	itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID))
	if err != nil {
		t.Fatal(err)
	}
	var projection service.MessageProjection
	if err := json.NewDecoder(response.Body).Decode(&projection); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(projection.HTML, "script") || !projection.RemoteContentBlocked || len(projection.Attachments) != 1 {
		t.Fatalf("status=%d projection=%+v", response.StatusCode, projection)
	}
	if !projection.Attachments[0].Previewable {
		t.Fatalf("plain-text attachment was not marked previewable: %+v", projection.Attachments[0])
	}
	download, err := client.Get(server.URL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID) + "/attachments/" + projection.Attachments[0].PartID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(download.Body)
	_ = download.Body.Close()
	if err != nil || download.StatusCode != http.StatusOK || string(data) != "hello" || !strings.HasPrefix(download.Header.Get("Content-Disposition"), "attachment;") || download.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(download.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("download status=%d headers=%v data=%q err=%v", download.StatusCode, download.Header, data, err)
	}
	preview, err := client.Get(server.URL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID) + "/attachments/" + projection.Attachments[0].PartID + "/preview")
	if err != nil {
		t.Fatal(err)
	}
	previewData, err := io.ReadAll(preview.Body)
	_ = preview.Body.Close()
	if err != nil || preview.StatusCode != http.StatusOK || string(previewData) != "hello" || !strings.HasPrefix(preview.Header.Get("Content-Disposition"), "inline;") || preview.Header.Get("Content-Type") != "text/plain" || preview.Header.Get("X-Content-Type-Options") != "nosniff" || preview.Header.Get("Cross-Origin-Resource-Policy") != "same-origin" || preview.Header.Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(preview.Header.Get("Content-Security-Policy"), "frame-ancestors 'self'") || preview.Header.Get("Cache-Control") != "private, no-store" || preview.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("preview status=%d headers=%v data=%q err=%v", preview.StatusCode, preview.Header, previewData, err)
	}

	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	setupAndLogin(t, server, bob, "bob")
	response, err = bob.Get(server.URL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized MIME projection status = %d", response.StatusCode)
	}
	preview, err = bob.Get(server.URL + "/api/v1/workspace/mail/messages/" + url.PathEscape(itemID) + "/attachments/" + projection.Attachments[0].PartID + "/preview")
	if err != nil {
		t.Fatal(err)
	}
	_ = preview.Body.Close()
	if preview.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized attachment preview status = %d", preview.StatusCode)
	}
}

func TestWorkspaceMIMEPreviewRejectsUnsafeAndOversizedAttachments(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	appendMessage := func(contentType, name string, content []byte) string {
		t.Helper()
		raw := append([]byte(strings.Join([]string{
			"From: sender@example.test", "To: alice@example.test", "Subject: Preview boundary",
			"MIME-Version: 1.0", "Content-Type: " + contentType + `; name="` + name + `"`,
			`Content-Disposition: attachment; filename="` + name + `"`, "", "",
		}, "\r\n")), content...)
		itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return itemID
	}
	unsafeID := appendMessage("text/html", "active.html", []byte("<script>alert(1)</script>"))
	response, err := client.Get(server.URL + "/api/v1/workspace/mail/messages/" + url.PathEscape(unsafeID) + "/attachments/1/preview")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("unsafe preview status = %d, want %d", response.StatusCode, http.StatusUnsupportedMediaType)
	}

	oversizedID := appendMessage("text/plain", "large.txt", bytes.Repeat([]byte("x"), service.MaxTextPreviewBytes+1))
	response, err = client.Get(server.URL + "/api/v1/workspace/mail/messages/" + url.PathEscape(oversizedID) + "/attachments/1/preview")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized preview status = %d, want %d", response.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func TestWorkspaceFilePreviewIsAuthorizedBoundedAndDownloadIndependent(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	filesID := model.FolderKey("alice", "Files")
	create := func(folderID, name, contentType string, data []byte) model.Item {
		t.Helper()
		item, err := ts.ItemStore().AppendItem(t.Context(), folderID, model.Item{Name: name, Data: data, Headers: map[string]string{"Content-Type": contentType}})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	plain := create(filesID, "notes.txt", "text/plain; charset=utf-8", []byte("hello files"))

	response, err := client.Get(server.URL + "/api/v1/workspace/items?folder_id=" + url.QueryEscape(filesID))
	if err != nil {
		t.Fatal(err)
	}
	var summaries []service.ItemSummary
	if err := json.NewDecoder(response.Body).Decode(&summaries); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || len(summaries) != 1 || !summaries[0].Previewable {
		t.Fatalf("file summaries status=%d summaries=%+v", response.StatusCode, summaries)
	}

	response, err = client.Get(server.URL + "/api/v1/workspace/files/" + url.PathEscape(plain.ID) + "/preview")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "hello files" || response.Header.Get("Content-Type") != "text/plain; charset=utf-8" || !strings.HasPrefix(response.Header.Get("Content-Disposition"), "inline;") || response.Header.Get("Cache-Control") != "private, no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" || response.Header.Get("Cross-Origin-Resource-Policy") != "same-origin" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Fatalf("file preview status=%d headers=%v body=%q err=%v", response.StatusCode, response.Header, body, err)
	}

	response, err = client.Get(server.URL + "/api/v1/workspace/files/" + url.PathEscape(plain.ID) + "/content")
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "hello files" || !strings.HasPrefix(response.Header.Get("Content-Disposition"), "attachment;") {
		t.Fatalf("file download status=%d headers=%v body=%q err=%v", response.StatusCode, response.Header, body, err)
	}

	unsafe := create(filesID, "active.html", "text/html", []byte("<script>alert(1)</script>"))
	response, err = client.Get(server.URL + "/api/v1/workspace/files/" + url.PathEscape(unsafe.ID) + "/preview")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("unsafe file preview status = %d, want %d", response.StatusCode, http.StatusUnsupportedMediaType)
	}

	oversized := create(filesID, "large.txt", "text/plain", bytes.Repeat([]byte("x"), service.MaxTextPreviewBytes+1))
	response, err = client.Get(server.URL + "/api/v1/workspace/files/" + url.PathEscape(oversized.ID) + "/preview")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized file preview status = %d, want %d", response.StatusCode, http.StatusRequestEntityTooLarge)
	}

	mailItem := create(model.InboxFolderID("alice"), "not-a-file.txt", "text/plain", []byte("mail data"))
	response, err = client.Get(server.URL + "/api/v1/workspace/files/" + url.PathEscape(mailItem.ID) + "/preview")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("non-file-folder preview status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}

	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	setupAndLogin(t, server, bob, "bob")
	response, err = bob.Get(server.URL + "/api/v1/workspace/files/" + url.PathEscape(plain.ID) + "/preview")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-account file preview status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

func TestWorkspaceFolderAndBulkItemMutationAPIs(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	filesID := model.FolderKey("alice", "Files")
	resp := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/folders", csrf,
		`{"name":"Projects","type":"files","parent_id":"`+filesID+`"}`)
	var folder model.Folder
	if err := json.NewDecoder(resp.Body).Decode(&folder); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || folder.ID == "" || folder.ParentID != filesID {
		t.Fatalf("create folder status=%d folder=%#v", resp.StatusCode, folder)
	}
	stableID := folder.ID
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(folder.ID), csrf,
		`{"name":"Active projects","parent_id":"`+filesID+`"}`)
	if err := json.NewDecoder(resp.Body).Decode(&folder); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || folder.ID != stableID || folder.Name != "Active projects" {
		t.Fatalf("move folder status=%d folder=%#v", resp.StatusCode, folder)
	}
	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(folder.ID), csrf, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("trash folder status=%d", resp.StatusCode)
	}
	resp = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(folder.ID)+"/restore", csrf, `{}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("restore folder status=%d", resp.StatusCode)
	}

	itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte("message"), map[string]string{"Subject": "Bulk"})
	if err != nil {
		t.Fatal(err)
	}
	actionURL := server.URL + "/api/v1/workspace/items/actions"
	resp = authenticatedJSON(t, client, http.MethodPost, actionURL, csrf, `{"item_ids":["`+itemID+`"],"action":"mark_read"}`)
	var actionResult struct {
		Items []model.Item `json:"items"`
		Count int          `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&actionResult); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || actionResult.Count != 1 || len(actionResult.Items) != 1 || actionResult.Items[0].ID != itemID || !containsString(actionResult.Items[0].Flags, model.FlagSeen) {
		t.Fatalf("mark read status=%d result=%#v", resp.StatusCode, actionResult)
	}
	item, _ := ts.ItemStore().Get(t.Context(), itemID)
	if !containsString(item.Flags, model.FlagSeen) {
		t.Fatalf("seen flag missing: %#v", item.Flags)
	}
	archive, _ := ts.FolderStore().GetByPath(t.Context(), "alice", "Archive")
	resp = authenticatedJSON(t, client, http.MethodPost, actionURL, csrf, `{"item_ids":["`+itemID+`"],"action":"move","destination_folder_id":"`+archive.ID+`"}`)
	_ = resp.Body.Close()
	item, _ = ts.ItemStore().Get(t.Context(), itemID)
	if resp.StatusCode != http.StatusOK || item.FolderID != archive.ID {
		t.Fatalf("move status=%d item=%#v", resp.StatusCode, item)
	}
	resp = authenticatedJSON(t, client, http.MethodPost, actionURL, csrf, `{"item_ids":["`+itemID+`"],"action":"trash"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("trash item status=%d", resp.StatusCode)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/trash")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), itemID) {
		t.Fatalf("trash listing status=%d body=%s", resp.StatusCode, body)
	}
	resp = authenticatedJSON(t, client, http.MethodPost, actionURL, csrf, `{"item_ids":["`+itemID+`"],"action":"restore"}`)
	_ = resp.Body.Close()
	item, _ = ts.ItemStore().Get(t.Context(), itemID)
	if resp.StatusCode != http.StatusOK || item.ID != itemID || item.FolderID != archive.ID || !item.TrashedAt.IsZero() {
		t.Fatalf("restore status=%d item=%#v", resp.StatusCode, item)
	}

	fileURL := server.URL + "/api/v1/workspace/files/notes.txt?folder_id=" + url.QueryEscape(filesID)
	resp = authenticatedJSON(t, client, http.MethodPut, fileURL, csrf, "hello files")
	var file service.ItemSummary
	if err := json.NewDecoder(resp.Body).Decode(&file); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || file.ID == "" || file.Name != "notes.txt" {
		t.Fatalf("put file status=%d file=%#v", resp.StatusCode, file)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/files/" + url.PathEscape(file.ID) + "/content")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello files" {
		t.Fatalf("file content status=%d body=%q", resp.StatusCode, body)
	}
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/workspace/files/"+url.PathEscape(file.ID), csrf,
		`{"folder_id":"`+filesID+`","name":"renamed.txt"}`)
	if err := json.NewDecoder(resp.Body).Decode(&file); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || file.ID == "" || file.Name != "renamed.txt" {
		t.Fatalf("rename file status=%d file=%#v", resp.StatusCode, file)
	}
	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/files/"+url.PathEscape(file.ID), csrf, "")
	_ = resp.Body.Close()
	trashedFile, _ := ts.ItemStore().Get(t.Context(), file.ID)
	if resp.StatusCode != http.StatusNoContent || trashedFile.TrashedAt.IsZero() {
		t.Fatalf("delete file status=%d item=%#v", resp.StatusCode, trashedFile)
	}
}

func TestWorkspaceFileReuploadAfterTrashAndRestoreConflict(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	filesID := model.FolderKey("alice", "Files")
	fileURL := server.URL + "/api/v1/workspace/files/notes.txt?folder_id=" + url.QueryEscape(filesID)
	put := func(content string) service.ItemSummary {
		t.Helper()
		resp := authenticatedJSON(t, client, http.MethodPut, fileURL, csrf, content)
		defer resp.Body.Close()
		var file service.ItemSummary
		if err := json.NewDecoder(resp.Body).Decode(&file); err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("put status=%d err=%v", resp.StatusCode, err)
		}
		return file
	}
	listed := func() []service.ItemSummary {
		t.Helper()
		resp, err := client.Get(server.URL + "/api/v1/workspace/items?folder_id=" + url.QueryEscape(filesID))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var items []service.ItemSummary
		if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
			t.Fatal(err)
		}
		return items
	}
	first := put("first")
	resp := authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/files/"+url.PathEscape(first.ID), csrf, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || len(listed()) != 0 {
		t.Fatalf("trash status=%d listed=%#v", resp.StatusCode, listed())
	}
	second := put("second")
	if second.ID == first.ID || second.Name != "notes.txt" {
		t.Fatalf("reupload reused trashed item: first=%#v second=%#v", first, second)
	}
	if items := listed(); len(items) != 1 || items[0].ID != second.ID {
		t.Fatalf("listing after reupload = %#v", items)
	}
	resp, err := client.Get(server.URL + "/api/v1/workspace/trash")
	if err != nil {
		t.Fatal(err)
	}
	var trash struct {
		Items []service.ItemSummary `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&trash); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(trash.Items) != 1 || trash.Items[0].ID != first.ID || trash.Items[0].OriginalName != "notes.txt" {
		t.Fatalf("trash = %#v", trash.Items)
	}
	actionURL := server.URL + "/api/v1/workspace/items/actions"
	resp = authenticatedJSON(t, client, http.MethodPost, actionURL, csrf, `{"item_ids":["`+first.ID+`"],"action":"restore"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || len(listed()) != 1 {
		t.Fatalf("restore over live name status=%d, want conflict", resp.StatusCode)
	}
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/workspace/files/"+url.PathEscape(second.ID), csrf,
		`{"folder_id":"`+filesID+`","name":"notes-new.txt"}`)
	_ = resp.Body.Close()
	resp = authenticatedJSON(t, client, http.MethodPost, actionURL, csrf, `{"item_ids":["`+first.ID+`"],"action":"restore"}`)
	_ = resp.Body.Close()
	names := map[string]string{}
	for _, item := range listed() {
		names[item.Name] = item.ID
	}
	if resp.StatusCode != http.StatusOK || names["notes.txt"] != first.ID || names["notes-new.txt"] != second.ID {
		t.Fatalf("restore status=%d names=%v", resp.StatusCode, names)
	}
}

func TestCalendarManagementDefaultRenameMoveDeleteAndRestore(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	resp := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/folders", csrf, `{"name":"Team","type":"calendar","parent_id":""}`)
	var team model.Folder
	if err := json.NewDecoder(resp.Body).Decode(&team); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || team.Type != model.FolderTypeCalendar {
		t.Fatalf("create status=%d folder=%#v", resp.StatusCode, team)
	}
	resp = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/folders", csrf, `{"name":"Team","type":"calendar","parent_id":""}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate calendar status=%d, want %d", resp.StatusCode, http.StatusConflict)
	}
	resp = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/folders", csrf, `{"name":"Planning","type":"calendar","parent_id":"`+team.ID+`"}`)
	var planning model.Folder
	if err := json.NewDecoder(resp.Body).Decode(&planning); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(team.ID), csrf, `{"name":"Shared team","parent_id":"","default":true}`)
	if err := json.NewDecoder(resp.Body).Decode(&team); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || team.SpecialUse != model.SpecialUseCalendar || team.Name != "Shared team" {
		t.Fatalf("update status=%d folder=%#v", resp.StatusCode, team)
	}
	movedChild, err := ts.FolderStore().Get(t.Context(), planning.ID)
	if err != nil || movedChild.Path != "Shared team/Planning" {
		t.Fatalf("child=%#v error=%v", movedChild, err)
	}
	original, err := ts.FolderStore().Get(t.Context(), model.FolderKey("alice", "Calendar"))
	if err != nil || original.SpecialUse != "" {
		t.Fatalf("original=%#v error=%v", original, err)
	}
	if _, err := ts.ItemStore().Append(t.Context(), team.ID, []byte("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"), map[string]string{"UID": "retained"}); err != nil {
		t.Fatal(err)
	}
	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(team.ID), csrf, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete default status=%d", resp.StatusCode)
	}
	original, _ = ts.FolderStore().Get(t.Context(), original.ID)
	if original.SpecialUse != model.SpecialUseCalendar {
		t.Fatalf("replacement default=%#v", original)
	}
	trashed, _ := ts.FolderStore().Get(t.Context(), team.ID)
	if trashed.TrashedAt.IsZero() || trashed.ItemCount != 1 {
		t.Fatalf("trashed calendar=%#v", trashed)
	}
	resp = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(team.ID)+"/restore", csrf, `{}`)
	var restored model.Folder
	if err := json.NewDecoder(resp.Body).Decode(&restored); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || restored.SpecialUse != "" || restored.ItemCount != 1 {
		t.Fatalf("restore status=%d folder=%#v", resp.StatusCode, restored)
	}
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: restored.ID},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderManager,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	bobCSRF := setupAndLogin(t, server, bob, "bob")
	resp = authenticatedJSON(t, bob, http.MethodPatch, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(restored.ID), bobCSRF, `{"default":true}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("shared calendar default status=%d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"},
		Effect:    model.EffectAllow, RoleID: authz.RoleAccountDelegate,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	resp = authenticatedJSON(t, bob, http.MethodPut, server.URL+"/api/v1/session/delegation", bobCSRF, `{"subject_id":"alice"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start delegation status=%d", resp.StatusCode)
	}
	resp = authenticatedJSON(t, bob, http.MethodPatch, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(restored.ID), bobCSRF, `{"default":true}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delegated default status=%d", resp.StatusCode)
	}
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(restored.ID), csrf, `{"default":false}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("clear default status=%d", resp.StatusCode)
	}
	resp = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(original.ID), csrf, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete protected system calendar status=%d", resp.StatusCode)
	}
	resp = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/workspace/folders/"+url.PathEscape(original.ID), csrf, `{"name":"Renamed system calendar","parent_id":""}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("rename protected system calendar status=%d", resp.StatusCode)
	}
}

func TestSyncJobAPIRetainsStructuredRedactedTerminalFailure(t *testing.T) {
	handler, ts := testHandler(t)
	handler.migrationSources["eas"] = func(context.Context, migration.SourceOptions) (migration.Source, error) {
		return nil, errors.New("not used")
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")

	job, err := handler.migrationJobs.Create(t.Context(), migration.Job{OwnerID: "alice", DestinationID: "alice", SourceType: "eas"})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := handler.migrationJobs.RecordFatalAttempt(t.Context(), job.ID,
		errors.New("request throttled; retry later password=source-secret"),
		migration.FailureContext{Phase: migration.FailurePhaseSourceRead, FolderID: "51", FolderName: "Calendar", Checkpoint: "sync-key"})
	if err != nil {
		t.Fatal(err)
	}

	response, err := client.Get(server.URL + "/api/v1/sync-jobs/" + url.PathEscape(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	var current struct {
		migration.Job
		Source migration.SourceDescriptor `json:"source"`
	}
	if err := json.NewDecoder(response.Body).Decode(&current); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || current.RunTerminalFailure == nil {
		t.Fatalf("job status=%d terminal=%#v", response.StatusCode, current.RunTerminalFailure)
	}
	if current.Source.Type != "eas" || current.Source.Name != "Exchange ActiveSync (EAS)" || current.Source.Capabilities.Direction != migration.DirectionSourceToVeksel || !current.Source.Capabilities.SourceReadOnly || !current.Source.Capabilities.IncrementalCheckpoints || !current.Source.Capabilities.SourceDeletionTracking {
		t.Fatalf("source descriptor=%+v", current.Source)
	}
	terminal := current.RunTerminalFailure
	if terminal.Phase != migration.FailurePhaseSourceRead || terminal.FolderID != "51" || terminal.FolderName != "Calendar" || terminal.Checkpoint != "sync-key" || !terminal.RetryRecommended || terminal.OccurredAt.IsZero() || strings.Contains(terminal.Message, "source-secret") || !strings.Contains(terminal.Message, "[redacted]") {
		t.Fatalf("terminal failure=%#v", terminal)
	}
	if terminal.Message != failed.RunFatalError {
		t.Fatalf("message=%q legacy fatal=%q", terminal.Message, failed.RunFatalError)
	}
	failed.RunFolderResults = []migration.FolderReconciliation{{SourceFolderID: "51", SourceFolderName: "Calendar", State: "failed"}}
	if err := handler.migrationJobs.SaveRun(t.Context(), failed); err != nil {
		t.Fatal(err)
	}

	response, err = client.Get(server.URL + "/api/v1/sync-jobs")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Jobs              []syncJobResponse            `json:"jobs"`
		SourceDescriptors []migration.SourceDescriptor `json:"source_descriptors"`
	}
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || len(list.Jobs) != 1 || list.Jobs[0].Source.Capabilities.Direction != migration.DirectionSourceToVeksel || len(list.SourceDescriptors) != 1 || list.SourceDescriptors[0].Capabilities.Direction != migration.DirectionSourceToVeksel {
		t.Fatalf("sync list status=%d response=%+v", response.StatusCode, list)
	}

	response, err = client.Get(server.URL + "/api/v1/sync-jobs/" + url.PathEscape(job.ID) + "/runs")
	if err != nil {
		t.Fatal(err)
	}
	var history struct {
		Runs       []migration.RunRecord `json:"runs"`
		Total      int                   `json:"total"`
		PageSize   int                   `json:"page_size"`
		NextCursor string                `json:"next_cursor"`
	}
	if err := json.NewDecoder(response.Body).Decode(&history); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || history.Total != 1 || history.PageSize != 10 || history.NextCursor != "" || len(history.Runs) != 1 || len(history.Runs[0].FolderResults) != 0 || history.Runs[0].TerminalFailure == nil || history.Runs[0].TerminalFailure.Message != terminal.Message {
		t.Fatalf("run history status=%d history=%#v", response.StatusCode, history)
	}
	response, err = client.Get(server.URL + "/api/v1/sync-jobs/" + url.PathEscape(job.ID) + "/runs/" + url.PathEscape(history.Runs[0].ID))
	if err != nil {
		t.Fatal(err)
	}
	var runDetail migration.RunRecord
	if err := json.NewDecoder(response.Body).Decode(&runDetail); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || runDetail.ID != history.Runs[0].ID || len(runDetail.FolderResults) != 1 || runDetail.TerminalFailure == nil || runDetail.TerminalFailure.Message != terminal.Message {
		t.Fatalf("run detail status=%d run=%#v", response.StatusCode, runDetail)
	}
	response, err = client.Get(server.URL + "/api/v1/sync-jobs/" + url.PathEscape(job.ID) + "/runs?page_size=51")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid history page size status=%d", response.StatusCode)
	}
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	loginPage, err := bob.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = loginPage.Body.Close()
	bobCSRF := csrfCookieValue(t, bob, server.URL)
	loginResponse, err := bob.PostForm(server.URL+"/app/login", url.Values{"_csrf": {bobCSRF}, "username": {"bob"}, "password": {"password123"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResponse.Body.Close()
	for _, endpoint := range []string{
		"/api/v1/sync-jobs/" + url.PathEscape(job.ID) + "/runs",
		"/api/v1/sync-jobs/" + url.PathEscape(job.ID) + "/runs/" + url.PathEscape(history.Runs[0].ID),
	} {
		response, err := bob.Get(server.URL + endpoint)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("foreign sync evidence %s status=%d", endpoint, response.StatusCode)
		}
	}
}

func TestManualSyncStartPublishesOwnerScopedEvent(t *testing.T) {
	handler, _ := testHandler(t)
	handler.migrationSources["fake"] = func(context.Context, migration.SourceOptions) (migration.Source, error) {
		return &completedSyncSource{}, nil
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	ownerEvents, cancelOwnerEvents := handler.events.Subscribe("alice")
	t.Cleanup(cancelOwnerEvents)
	otherEvents, cancelOtherEvents := handler.events.Subscribe("bob")
	t.Cleanup(cancelOtherEvents)
	job, err := handler.migrationJobs.Create(t.Context(), migration.Job{
		OwnerID: "alice", DestinationID: "alice", SourceType: "fake", Schedule: migration.ScheduleManual,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/sync-jobs/"+url.PathEscape(job.ID)+"/start", csrf, `{}`)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("start status=%d body=%s", response.StatusCode, body)
	}
	select {
	case event := <-ownerEvents:
		if event.Type != "sync.started" || event.Resource != job.ID || len(event.Data) != 0 {
			t.Fatalf("start event = %#v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("manual sync start event was not published")
	}
	select {
	case event := <-otherEvents:
		t.Fatalf("manual sync start event leaked to another user: %#v", event)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestWorkspaceDraftRESTPersistsMailItem(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	resp := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/mail/drafts", csrf,
		`{"from":"alice@example.test","to":["bob@example.test"],"cc":["team@example.test"],"bcc":["private@example.test"],"subject":"First draft","body":"Work in progress","importance":"high"}`)
	var draft service.ItemSummary
	if err := json.NewDecoder(resp.Body).Decode(&draft); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || draft.ID == "" || !containsString(draft.Flags, model.FlagDraft) {
		t.Fatalf("create draft status=%d draft=%#v", resp.StatusCode, draft)
	}
	stored, err := ts.ItemStore().Get(t.Context(), draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	draftsFolder, _ := ts.FolderStore().SpecialFolder(t.Context(), "alice", model.SpecialUseDrafts)
	if stored.FolderID != draftsFolder.ID || service.MessageImportance(stored.Headers) != service.MailImportanceHigh || !strings.Contains(string(stored.Data), "Importance: high\r\n") || !strings.Contains(string(stored.Data), "Bcc: private@example.test\r\n") || !strings.Contains(string(stored.Data), "\r\n\r\nWork in progress") {
		t.Fatalf("stored draft = %#v data=%q", stored, stored.Data)
	}

	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/mail/drafts/"+url.PathEscape(draft.ID), csrf,
		`{"from":"alice@example.test","to":["bob@example.test"],"subject":"Updated draft","body":"Ready soon","importance":"low","attachments":[{"name":"notes.txt","content_type":"text/plain","data":"ZmlsZSBkYXRh"}]}`)
	if err := json.NewDecoder(resp.Body).Decode(&draft); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	stored, _ = ts.ItemStore().Get(t.Context(), draft.ID)
	if resp.StatusCode != http.StatusOK || stored.Headers["Subject"] != "Updated draft" || !strings.HasPrefix(stored.Headers["Content-Type"], "multipart/mixed") {
		t.Fatalf("update draft status=%d item=%#v", resp.StatusCode, stored)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/mail/drafts/" + url.PathEscape(draft.ID))
	if err != nil {
		t.Fatal(err)
	}
	var recovered service.Submission
	if err := json.NewDecoder(resp.Body).Decode(&recovered); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || recovered.Body != "Ready soon" || recovered.Importance != service.MailImportanceLow || len(recovered.Attachments) != 1 || recovered.Attachments[0].Name != "notes.txt" || string(recovered.Attachments[0].Data) != "file data" {
		t.Fatalf("recovered draft status=%d draft=%+v", resp.StatusCode, recovered)
	}

	resp = authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/workspace/mail/drafts/"+url.PathEscape(draft.ID), csrf,
		`{"from":"alice@example.test","to":["bob@example.test"],"subject":"Text-only update","body":"Attachment should remain"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attachment-preserving update status=%d", resp.StatusCode)
	}
	resp, err = client.Get(server.URL + "/api/v1/workspace/mail/drafts/" + url.PathEscape(draft.ID))
	if err != nil {
		t.Fatal(err)
	}
	recovered = service.Submission{}
	if err := json.NewDecoder(resp.Body).Decode(&recovered); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if recovered.Body != "Attachment should remain" || len(recovered.Attachments) != 1 || recovered.Attachments[0].Name != "notes.txt" {
		t.Fatalf("attachment lost when update omitted attachment payload: %+v", recovered)
	}
}

func TestWorkspaceDraftRejectsInvalidImportanceWithoutCreatingItem(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/mail/drafts", csrf,
		`{"from":"alice@example.test","to":["bob@example.test"],"subject":"Invalid","body":"No","importance":"critical"}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("invalid importance status=%d body=%s", response.StatusCode, payload)
	}
	drafts, folderErr := ts.FolderStore().SpecialFolder(t.Context(), "alice", model.SpecialUseDrafts)
	if folderErr != nil {
		t.Fatal(folderErr)
	}
	ids, err := ts.ItemStore().List(t.Context(), drafts.ID)
	if err != nil || len(ids) != 0 {
		t.Fatalf("invalid importance draft IDs=%v err=%v", ids, err)
	}
}

func TestWorkspaceDraftAcceptsPayloadBeyondDefaultJSONLimit(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	body, err := json.Marshal(service.Submission{
		From: "alice@example.test", To: []string{"bob@example.test"}, Subject: "Large draft", Body: "Attached",
		Attachments: []service.SubmissionAttachment{{Name: "large.bin", ContentType: "application/octet-stream", Size: 2 << 20, Data: bytes.Repeat([]byte("x"), 2<<20)}},
	})
	if err != nil {
		t.Fatalf("encode large draft: %v", err)
	}
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/mail/drafts", csrf, string(body))
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("large draft status=%d body=%s", response.StatusCode, payload)
	}
}

func TestMailSubmissionReusesSavedDraftAttachments(t *testing.T) {
	handler, ts := testHandler(t)
	mailQueue := &acceptingSubmissionQueue{}
	handler.SetMailQueue(mailQueue)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/mail/drafts", csrf,
		`{"from":"alice@example.test","to":["recipient@example.net"],"subject":"Attachment only","attachments":[{"name":"proof.txt","content_type":"text/plain","data":"cHJvb2Y="}]}`)
	var draft service.ItemSummary
	if err := json.NewDecoder(response.Body).Decode(&draft); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create attachment draft status=%d", response.StatusCode)
	}

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/mail/submissions", csrf,
		`{"draft_id":"`+draft.ID+`","from":"alice@example.test","to":["recipient@example.net"],"subject":"Attachment only","body":""}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted || mailQueue.messages != 1 {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("draft-backed submission status=%d queued=%d body=%s", response.StatusCode, mailQueue.messages, payload)
	}
}

func TestMailSubmissionRESTValidatesAndQueuesImportance(t *testing.T) {
	handler, ts := testHandler(t)
	mailQueue := &acceptingSubmissionQueue{}
	handler.SetMailQueue(mailQueue)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/mail/submissions", csrf,
		`{"from":"alice@example.test","to":["recipient@example.net"],"subject":"Urgent","body":"Read me","importance":"high"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted || len(mailQueue.queued) != 1 || service.MessageImportance(mailQueue.queued[0].Headers) != service.MailImportanceHigh {
		t.Fatalf("high importance status=%d queued=%+v", response.StatusCode, mailQueue.queued)
	}

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/mail/submissions", csrf,
		`{"from":"alice@example.test","to":["recipient@example.net"],"subject":"Invalid","body":"No","importance":"critical"}`)
	payload, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || len(mailQueue.queued) != 1 || !strings.Contains(string(payload), "importance") {
		t.Fatalf("invalid importance status=%d queued=%d body=%s", response.StatusCode, len(mailQueue.queued), payload)
	}
}

func TestWorkspaceItemPageUsesCursorAndAccountingTotal(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	for index := range 3 {
		if _, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte("message"), map[string]string{"Subject": fmt.Sprintf("Message %d", index+1)}); err != nil {
			t.Fatal(err)
		}
	}

	response, err := client.Get(server.URL + "/api/v1/workspace/items/page?folder_id=" + url.QueryEscape(model.InboxFolderID("alice")) + "&limit=2")
	if err != nil {
		t.Fatal(err)
	}
	var first service.ItemSummaryPage
	if err := json.NewDecoder(response.Body).Decode(&first); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || first.Total != 3 || len(first.Items) != 2 || first.Items[0].UID <= first.Items[1].UID || first.NextBeforeUID == 0 {
		t.Fatalf("first page status=%d page=%#v", response.StatusCode, first)
	}

	response, err = client.Get(server.URL + "/api/v1/workspace/items/page?folder_id=" + url.QueryEscape(model.InboxFolderID("alice")) + "&limit=2&before_uid=" + strconv.FormatUint(uint64(first.NextBeforeUID), 10))
	if err != nil {
		t.Fatal(err)
	}
	var second service.ItemSummaryPage
	if err := json.NewDecoder(response.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || second.Total != 3 || len(second.Items) != 1 || second.NextBeforeUID != 0 {
		t.Fatalf("second page status=%d page=%#v", response.StatusCode, second)
	}
}

func TestWorkspaceItemPageSupportsChronologicalFolderCursor(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	dates := []time.Time{
		time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC),
		time.Date(2023, 8, 27, 15, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC),
		time.Date(2024, 1, 2, 11, 0, 0, 0, time.UTC),
	}
	created := make([]model.Item, 0, len(dates))
	for index, date := range dates {
		item, err := ts.ItemStore().AppendItem(t.Context(), model.InboxFolderID("alice"), model.Item{Data: []byte("message"), Headers: map[string]string{"Subject": fmt.Sprintf("Message %d", index+1)}, InternalDate: date})
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, item)
	}
	base := server.URL + "/api/v1/workspace/items/page?folder_id=" + url.QueryEscape(model.InboxFolderID("alice")) + "&limit=2&order=internal_date_desc"
	response, err := client.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	var first service.ItemSummaryPage
	if err := json.NewDecoder(response.Body).Decode(&first); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || first.Total != 4 || len(first.Items) != 2 || first.Items[0].ID != created[0].ID || first.Items[1].ID != created[2].ID || first.NextCursor == "" || first.NextBeforeUID != 0 {
		t.Fatalf("first chronological page status=%d page=%#v", response.StatusCode, first)
	}
	response, err = client.Get(base + "&cursor=" + url.QueryEscape(first.NextCursor))
	if err != nil {
		t.Fatal(err)
	}
	var second service.ItemSummaryPage
	if err := json.NewDecoder(response.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || second.Total != 4 || len(second.Items) != 2 || second.Items[0].ID != created[3].ID || second.Items[1].ID != created[1].ID || second.NextCursor != "" {
		t.Fatalf("second chronological page status=%d page=%#v", response.StatusCode, second)
	}
	response, err = client.Get(base + "&around_item_id=" + url.QueryEscape(created[3].ID))
	if err != nil {
		t.Fatal(err)
	}
	var window service.ItemSummaryPage
	if err := json.NewDecoder(response.Body).Decode(&window); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || window.Total != 4 || len(window.Items) != 3 || window.Items[0].ID != created[2].ID || window.Items[1].ID != created[3].ID || window.Items[2].ID != created[1].ID || window.NextCursor != "" {
		t.Fatalf("anchored chronological window status=%d page=%#v", response.StatusCode, window)
	}
	plain := server.URL + "/api/v1/workspace/items/page?folder_id=" + url.QueryEscape(model.InboxFolderID("alice"))
	for _, requestURL := range []string{
		base + "&cursor=invalid",
		base + "&before_uid=2",
		base + "&cursor=invalid&around_item_id=" + url.QueryEscape(created[3].ID),
		plain + "&order=unsupported",
		plain + "&cursor=invalid",
		plain + "&around_item_id=" + url.QueryEscape(created[3].ID),
	} {
		response, err = client.Get(requestURL)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid chronological query %q status=%d", requestURL, response.StatusCode)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	setupAndLogin(t, server, bob, "bob")
	for _, requestURL := range []string{base, base + "&around_item_id=" + url.QueryEscape(created[3].ID)} {
		response, err = bob.Get(requestURL)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("cross-account chronological page %q status=%d", requestURL, response.StatusCode)
		}
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestDenseWorkspaceMarkupDoesNotRepeatPageTitles(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	for _, test := range []struct {
		path, required, forbidden string
	}{
		{"/app/mail", `class="mail-layout"`, `<h1>Mail</h1>`},
		{"/app/calendar", `id="calendar-views"`, `<h1>calendar</h1>`},
		{"/app/contacts", `class="contacts-workspace"`, `<h1>contacts</h1>`},
		{"/app/search", `class="global-search-workspace"`, `<h1>Search</h1>`},
		{"/app/trash", `class="trash-workspace"`, `<h1>Trash</h1>`},
		{"/app/quarantine", `class="quarantine-workspace"`, `<h1>quarantine</h1>`},
	} {
		resp, err := client.Get(server.URL + test.path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), test.required) || !strings.Contains(string(body), `id="confirm-dialog"`) || strings.Contains(string(body), test.forbidden) {
			t.Fatalf("workspace %s status=%d", test.path, resp.StatusCode)
		}
	}
}

func TestHomeExposesEveryPrimaryFolderWorkspace(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	resp, err := client.Get(server.URL + "/app/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("home status=%d", resp.StatusCode)
	}
	markup := string(body)
	for _, required := range []string{
		`class="home-dashboard"`,
		`id="home-mail"`,
		`id="home-events"`,
		`id="home-status"`,
		`href="/app/mail"`,
		`href="/app/calendar"`,
		`href="/app/contacts"`,
		`href="/app/files"`,
		`href="/app/sharing"`,
	} {
		if !strings.Contains(markup, required) {
			t.Errorf("home markup does not contain %q", required)
		}
	}
	for _, forbidden := range []string{`class="hero"`, `feature-grid`, `Everything you own, share, and send`} {
		if strings.Contains(markup, forbidden) {
			t.Errorf("home markup still contains marketing content %q", forbidden)
		}
	}
}

func TestMailWorkspaceMarkupExposesNarrowPaneNavigation(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	resp, err := client.Get(server.URL + "/app/mail")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	source := string(body)
	for _, required := range []string{`id="mail-layout"`, `id="mail-folders-toggle"`, `id="mail-folders-close"`, `id="mail-reader-back"`, `id="mail-reader-position"`, `aria-live="polite"`} {
		if !strings.Contains(source, required) {
			t.Errorf("mail workspace markup does not contain %q", required)
		}
	}
}

func TestAppShowsProfileDisplayName(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	if err := model.NewUserStore(ts).Update(t.Context(), "alice", func(user *model.User) { user.DisplayName = "Alice Example" }); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(server.URL + "/app/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, want := range []string{"Hello, Alice Example", `data-subject="alice"`, `data-actor="alice">Alice Example<`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("home page lacks %q", want)
		}
	}
}
