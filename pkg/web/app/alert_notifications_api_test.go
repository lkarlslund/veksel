package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/config"
)

type fakeAlertNotifier struct {
	mu     sync.Mutex
	policy alertnotify.Policy
	tests  int
}

func (f *fakeAlertNotifier) SetPolicy(policy alertnotify.Policy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy = policy
}

func (f *fakeAlertNotifier) current() alertnotify.Policy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policy
}

func (f *fakeAlertNotifier) Status(context.Context) (alertnotify.Status, error) {
	policy := f.current()
	return alertnotify.Status{Enabled: policy.Enabled, Digest: policy.Digest, Channels: []alertnotify.ChannelStatus{
		{ID: alertnotify.ChannelEmail, Label: "Administrator email", Configured: len(policy.Recipients) > 0, Target: strings.Join(policy.Recipients, ", ")},
	}}, nil
}

func (f *fakeAlertNotifier) Test(context.Context) []alertnotify.ChannelResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tests++
	return []alertnotify.ChannelResult{{Channel: alertnotify.ChannelEmail, Target: "ops@example.com", OK: true, At: time.Now()}, {Channel: alertnotify.ChannelPush, OK: false, Error: "push receiver returned HTTP 401"}}
}

func TestAlertDeliverySettingsApplyLiveAndRedactToken(t *testing.T) {
	server, typed, configuration, _, handler := managedTestApp(t)
	notifier := &fakeAlertNotifier{}
	handler.ConfigureAlertNotifier(notifier)
	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "owner")
	secret := "alert-token-must-never-return"
	// Push receivers such as ntfy and Gotify carry their credential in the
	// URL, so the URL is redacted like the token.
	urlSecret := "url-embedded-push-credential"
	leaks := func(body []byte) bool {
		return strings.Contains(string(body), secret) || strings.Contains(string(body), urlSecret)
	}
	response := authenticatedJSON(t, admin, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+configuration.Current().Revision+`","reason":"route alerts","settings":{"alert_email_recipients":["ops@example.com","OPS@example.com"],"alert_notify_url":"https://push.example.com/message?token=`+urlSecret+`","alert_notify_token":"`+secret+`","alert_min_interval_minutes":5,"alert_digest":"daily","quota_warning_emails_enabled":false}}`)
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || leaks(body) {
		t.Fatalf("PATCH status=%d leaked=%t body=%s", response.StatusCode, leaks(body), body)
	}
	var update configAPIResponse
	if err := json.Unmarshal(body, &update); err != nil {
		t.Fatal(err)
	}
	if update.Plan == nil || update.Plan.RestartRequired {
		t.Fatalf("plan = %+v", update.Plan)
	}
	for _, state := range update.ApplyState {
		if strings.HasPrefix(state.Key, "alert_") && state.State != config.ApplyEffective {
			t.Fatalf("%s apply state = %+v", state.Key, state)
		}
	}
	policy := notifier.current()
	if !policy.Enabled || len(policy.Recipients) != 1 || policy.Recipients[0] != "ops@example.com" || policy.Token != secret || !strings.Contains(policy.URL, urlSecret) || policy.MinInterval != 5*time.Minute || policy.Digest != config.AlertDigestDaily || handler.cfg.QuotaWarningEmailsEnabled {
		t.Fatalf("live policy = %+v quota mail=%t", policy, handler.cfg.QuotaWarningEmailsEnabled)
	}
	// Disabling notifications through the existing health group reaches the
	// notifier as well.
	response = authenticatedJSON(t, admin, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+update.Revision+`","reason":"mute","settings":{"alert_notifications_enabled":false}}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || notifier.current().Enabled {
		t.Fatalf("disable status=%d policy=%+v", response.StatusCode, notifier.current())
	}
	for _, read := range []string{"/api/v1/admin/config", "/api/v1/admin/settings", "/api/v1/admin/config/history?limit=10"} {
		response = authenticatedJSON(t, admin, http.MethodGet, server.URL+read, "", "")
		body, _ = io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || leaks(body) {
			t.Fatalf("GET %s status=%d leaked=%t", read, response.StatusCode, leaks(body))
		}
	}
	response = authenticatedJSON(t, admin, http.MethodPatch, server.URL+"/api/v1/admin/config", csrf,
		`{"revision":"`+configuration.Current().Revision+`","reason":"bad","settings":{"alert_notify_url":"ftp://push.example.com"}}`)
	_ = response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("invalid alert push URL accepted")
	}

	response = authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/alerts/notifications", "", "")
	var status alertnotify.Status
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || status.Digest != config.AlertDigestDaily || len(status.Channels) != 1 || status.Channels[0].Target != "ops@example.com" {
		t.Fatalf("status code=%d body=%+v", response.StatusCode, status)
	}
	response = authenticatedJSON(t, admin, http.MethodPost, server.URL+"/api/v1/admin/alerts/notifications/test", csrf, `{}`)
	var tested struct {
		Results []alertnotify.ChannelResult `json:"results"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tested); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || len(tested.Results) != 2 || notifier.tests != 1 || tested.Results[1].OK {
		t.Fatalf("test code=%d results=%+v", response.StatusCode, tested.Results)
	}

	if err := typed.UserStore().Create(t.Context(), "viewer", "Viewer", "password123"); err != nil {
		t.Fatal(err)
	}
	viewer := testClient(t)
	loginExistingUser(t, viewer, server.URL, "viewer")
	forbidden, err := viewer.Get(server.URL + "/api/v1/admin/alerts/notifications")
	if err != nil {
		t.Fatal(err)
	}
	_ = forbidden.Body.Close()
	if forbidden.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin status = %d", forbidden.StatusCode)
	}
}
