package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/sendguard"
)

func expectJSON[T any](t *testing.T, response *http.Response, want int) T {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("status = %d, want %d: %s", response.StatusCode, want, body)
	}
	var value T
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return value
}

func TestSendLimitsAndCredentialResetThroughAdminAPI(t *testing.T) {
	handler, ts := testHandler(t)
	guard, err := sendguard.New(t.Context(), ts, sendguard.Config{Defaults: sendguard.Limits{RecipientsPerHour: 1}})
	if err != nil {
		t.Fatal(err)
	}
	mailQueue := queue.New(&queue.Config{Screen: guard.Screen, Delivery: func(context.Context, *queue.Message) error {
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, RetryAfter: time.Hour}
	}})
	t.Cleanup(mailQueue.Close)
	guard.AttachQueue(mailQueue)
	handler.SetMailQueue(mailQueue)
	handler.ConfigureSendGuard(guard)
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
	submit := func() *http.Response {
		return authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/mail/submissions", csrf,
			`{"from":"alice@example.test","to":["recipient@example.net"],"subject":"Hello","body":"Hi"}`)
	}
	_ = expectJSON[map[string]any](t, submit(), http.StatusAccepted)
	limited := submit()
	if retry := limited.Header.Get("Retry-After"); retry == "" || retry == "0" {
		t.Fatalf("Retry-After = %q", retry)
	}
	rejection := expectJSON[map[string]string](t, limited, http.StatusTooManyRequests)
	if !strings.Contains(rejection["error"], "sending limit reached: at most 1 recipients per hour") {
		t.Fatalf("429 reason = %q", rejection["error"])
	}

	status := expectJSON[sendguard.AccountStatus](t, authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/users/alice/sending", csrf, ""), http.StatusOK)
	if status.Usage.RecipientsHour != 1 || status.Effective.RecipientsPerHour != 1 || status.Override != nil {
		t.Fatalf("sending status = %+v", status)
	}
	status = expectJSON[sendguard.AccountStatus](t, authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/admin/users/alice/sending/limits", csrf,
		`{"recipients_per_hour":5,"recipients_per_day":null}`), http.StatusOK)
	if status.Effective.RecipientsPerHour != 5 || status.Override == nil || status.Override.RecipientsPerDay != nil {
		t.Fatalf("override status = %+v", status)
	}
	_ = expectJSON[map[string]any](t, submit(), http.StatusAccepted)
	if response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/admin/users/alice/sending/limits", csrf, `{"messages_per_hour":-1}`); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("negative override status = %d", response.StatusCode)
	}
	if holds := expectJSON[[]sendguard.HeldAccount](t, authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/outbound/holds", csrf, ""), http.StatusOK); len(holds) != 0 {
		t.Fatalf("holds = %+v", holds)
	}
	if released := expectJSON[map[string]int](t, authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/users/alice/sending/release", csrf, "{}"), http.StatusOK); released["released"] != 0 {
		t.Fatalf("release = %+v", released)
	}

	if _, _, err := model.NewAppPasswordStore(ts).Create(t.Context(), "alice", "phone", []string{model.AppProtocolIMAP}); err != nil {
		t.Fatal(err)
	}
	reset := expectJSON[credentialReset](t, authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/users/alice/credentials/reset", csrf, "{}"), http.StatusOK)
	if !reset.PasswordReset || len(reset.GeneratedPassword) < 20 || reset.SessionsRevoked < 1 || reset.AppPasswordsRevoked != 1 {
		t.Fatalf("credential reset = %+v", reset)
	}
	user, _ := ts.UserStore().Get(t.Context(), "alice")
	if auth.ComparePassword("password123", user.PasswordHash) || !auth.ComparePassword(reset.GeneratedPassword, user.PasswordHash) {
		t.Fatal("password was not replaced by the generated one")
	}
	if response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/users/alice/sending", csrf, ""); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session still works: %d", response.StatusCode)
	}
}
