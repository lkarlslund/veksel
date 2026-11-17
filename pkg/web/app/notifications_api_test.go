package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/model"
)

type webhookTesterFunc func(context.Context, string) (*model.WebhookDelivery, error)

func (fn webhookTesterFunc) Test(ctx context.Context, id string) (*model.WebhookDelivery, error) {
	return fn(ctx, id)
}

func TestAdminWebhookLifecycleNeverDisclosesSecrets(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/notifications/webhooks", csrf,
		`{"url":"https://hooks.example.test/veksel","events":["message.received","health.alert.opened"],"accounts":["alice"],"secret":"top-secret","max_retries":7,"backoff_multiplier":3}`)
	body := readResponseBody(t, response)
	if response.StatusCode != http.StatusCreated || strings.Contains(body, "top-secret") || strings.Contains(body, `"secret"`) {
		t.Fatalf("create status=%d body=%s", response.StatusCode, body)
	}
	var created adminWebhookView
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	if !created.HasSecret || created.MaxRetries != 7 || created.BackoffMultiplier != 3 {
		t.Fatalf("created webhook = %+v", created)
	}
	stored, err := model.NewWebhookStore(ts).Get(t.Context(), created.ID)
	if err != nil || stored.Secret != "top-secret" {
		t.Fatalf("stored webhook=%+v err=%v", stored, err)
	}

	rotationBody, _ := json.Marshal(map[string]any{"updated_at": created.UpdatedAt})
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/notifications/webhooks/"+created.ID+"/rotate-secret", "", string(rotationBody))
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("rotation without CSRF status=%d", response.StatusCode)
	}
	if err := ts.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	ordinary := testClient(t)
	ordinaryCSRF := loginExistingUser(t, ordinary, server.URL, "ordinary")
	response = authenticatedJSON(t, ordinary, http.MethodPost, server.URL+"/api/v1/admin/notifications/webhooks/"+created.ID+"/rotate-secret", ordinaryCSRF, string(rotationBody))
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin rotation status=%d", response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/notifications/webhooks/"+created.ID+"/rotate-secret", csrf, string(rotationBody))
	body = readResponseBody(t, response)
	var rotation adminWebhookRotationView
	if err := json.Unmarshal([]byte(body), &rotation); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(rotation.Secret) < 40 || rotation.Secret == "top-secret" || rotation.SecretRotationCount != 1 || rotation.SecretRotatedAt == "" {
		t.Fatalf("rotation status=%d response=%+v", response.StatusCode, rotation)
	}
	stored, err = model.NewWebhookStore(ts).Get(t.Context(), created.ID)
	if err != nil || stored.Secret != rotation.Secret || stored.SecretRotationCount != 1 {
		t.Fatalf("stored rotation=%+v err=%v", stored, err)
	}
	response, err = client.Get(server.URL + "/api/v1/admin/notifications/webhooks")
	if err != nil {
		t.Fatal(err)
	}
	redactedList := readResponseBody(t, response)
	if strings.Contains(redactedList, rotation.Secret) || strings.Contains(redactedList, `"secret"`) {
		t.Fatalf("list disclosed rotated secret: %s", redactedList)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/notifications/webhooks/"+created.ID+"/rotate-secret", csrf, string(rotationBody))
	staleRotation := readResponseBody(t, response)
	if response.StatusCode != http.StatusConflict || !strings.Contains(staleRotation, "resource changed") {
		t.Fatalf("stale rotation status=%d body=%s", response.StatusCode, staleRotation)
	}

	update, _ := json.Marshal(map[string]any{"url": "https://hooks.example.test/updated", "active": false, "updated_at": rotation.UpdatedAt})
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/notifications/webhooks/"+created.ID, csrf, string(update))
	body = readResponseBody(t, response)
	if response.StatusCode != http.StatusOK || strings.Contains(body, "top-secret") {
		t.Fatalf("update status=%d body=%s", response.StatusCode, body)
	}
	var updated adminWebhookView
	if err := json.Unmarshal([]byte(body), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Active || !updated.HasSecret || updated.URL != "https://hooks.example.test/updated" {
		t.Fatalf("updated webhook = %+v", updated)
	}

	clear, _ := json.Marshal(map[string]any{"secret": "", "updated_at": updated.UpdatedAt})
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/notifications/webhooks/"+created.ID, csrf, string(clear))
	body = readResponseBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("clear secret status=%d body=%s", response.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &updated); err != nil || updated.HasSecret {
		t.Fatalf("cleared webhook=%+v err=%v", updated, err)
	}

	handler.ConfigureWebhooks(webhookTesterFunc(func(_ context.Context, id string) (*model.WebhookDelivery, error) {
		return &model.WebhookDelivery{ID: "test", WebhookID: id, Event: "webhook.test", Status: model.WebhookDeliverySent, Signature: "sha256=private", RequestHeaders: map[string]string{"X-Webhook-Signature": "private"}, UpdatedAt: time.Now().UTC()}, nil
	}))
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/notifications/webhooks/"+created.ID+"/test", csrf, `{}`)
	body = readResponseBody(t, response)
	if response.StatusCode != http.StatusOK || strings.Contains(body, "signature") || strings.Contains(body, "private") {
		t.Fatalf("test status=%d body=%s", response.StatusCode, body)
	}

	entries, err := audit.New(ts).QueryReverse(t.Context(), time.Time{}, "", "owner", 20)
	webhookAudits := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Action, "webhook.") {
			webhookAudits++
		}
	}
	if err != nil || webhookAudits < 5 {
		t.Fatalf("audit entries=%+v err=%v", entries, err)
	}
	for _, entry := range entries {
		if entry.Action == "webhook.secret.rotate" && strings.Contains(fmt.Sprint(entry.Details), rotation.Secret) {
			t.Fatal("rotation audit disclosed the secret")
		}
	}
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/notifications/webhooks/"+created.ID, csrf, "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", response.StatusCode)
	}
}

func TestAdminWebhookDeliveryPagesAndValidation(t *testing.T) {
	server, ts, _, _, _ := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	for _, body := range []string{
		`{"url":"ftp://example.test/hook","events":["message.received"]}`,
		`{"url":"https://user:pass@example.test/hook","events":["message.received"]}`,
		`{"url":"https://example.test/hook","events":[],"max_retries":21}`,
		`{"url":"https://example.test/hook","events":["message.received"]}`,
		`{"url":"https://example.test/hook","events":["message.received"],"domains":["not a domain"]}`,
	} {
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/notifications/webhooks", csrf, body)
		_ = readResponseBody(t, response)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid webhook status=%d", response.StatusCode)
		}
	}

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/notifications/webhooks", csrf,
		`{"url":"https://example.test/hook","events":["message.received"],"domains":["example.test"]}`)
	var webhook adminWebhookView
	decodeResponse(t, response, &webhook)
	base := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	deliveries := model.NewWebhookDeliveryStore(ts)
	for index := range 3 {
		at := base.Add(time.Duration(index) * time.Minute)
		if err := deliveries.Create(t.Context(), model.WebhookDelivery{ID: string(rune('a' + index)), WebhookID: webhook.ID, Event: "message.received", Status: model.WebhookDeliverySent, Signature: "hidden", UpdatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	response, err := client.Get(server.URL + "/api/v1/admin/notifications/webhooks/" + webhook.ID + "/deliveries?page_size=2")
	if err != nil {
		t.Fatal(err)
	}
	var first adminWebhookDeliveryPage
	decodeResponse(t, response, &first)
	if first.Total != 3 || len(first.Items) != 2 || first.NextCursor == "" || first.Items[0].ID != "c" {
		t.Fatalf("first page = %+v", first)
	}
	response, err = client.Get(server.URL + "/api/v1/admin/notifications/webhooks/" + webhook.ID + "/deliveries?page_size=2&cursor=" + first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	var second adminWebhookDeliveryPage
	decodeResponse(t, response, &second)
	if second.Total != 3 || len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].ID != "a" {
		t.Fatalf("second page = %+v", second)
	}
}

func readResponseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func decodeResponse(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

// TestPersonalWebhooksAreOwnedAndScoped: a user manages only their own
// webhooks, which cannot reach other accounts or server-wide events, and
// administrators' server list does not mix them in.
func TestPersonalWebhooksAreOwnedAndScoped(t *testing.T) {
	server, ts, _, _, _ := managedTestApp(t)
	ownerClient := testClient(t)
	ownerCSRF := setupAndLogin(t, server, ownerClient, "owner")
	for _, id := range []string{"bob", "carol"} {
		if err := ts.UserStore().Create(t.Context(), id, id, "password123"); err != nil {
			t.Fatal(err)
		}
	}
	bob, bobCSRF := loginAs(t, server, "bob")
	carol, carolCSRF := loginAs(t, server, "carol")

	for _, invalid := range []string{
		`{"url":"https://bot.example.test/hook","events":["message.received"],"accounts":["carol"]}`,
		`{"url":"https://bot.example.test/hook","events":["message.received"],"domains":["example.test"]}`,
		`{"url":"https://bot.example.test/hook","events":["health.alert.opened"]}`,
	} {
		response := authenticatedJSON(t, bob, http.MethodPost, server.URL+"/api/v1/user/webhooks", bobCSRF, invalid)
		if body := readResponseBody(t, response); response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", invalid, response.StatusCode, body)
		}
	}
	response := authenticatedJSON(t, bob, http.MethodPost, server.URL+"/api/v1/user/webhooks", bobCSRF,
		`{"url":"https://bot.example.test/hook","events":["message.received"],"addresses":["signup@example.test"],"include":["raw"]}`)
	body := readResponseBody(t, response)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.StatusCode, body)
	}
	var created adminWebhookView
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	stored, err := model.NewWebhookStore(ts).Get(t.Context(), created.ID)
	if err != nil || stored.OwnerID != "bob" {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	// Carol cannot see, change or delete Bob's webhook.
	response = authenticatedJSON(t, carol, http.MethodGet, server.URL+"/api/v1/user/webhooks", carolCSRF, "")
	if body := readResponseBody(t, response); strings.Contains(body, created.ID) {
		t.Fatalf("carol lists bob's webhook: %s", body)
	}
	response = authenticatedJSON(t, carol, http.MethodDelete, server.URL+"/api/v1/user/webhooks/"+created.ID, carolCSRF, "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("carol delete status=%d", response.StatusCode)
	}
	// The administrators' server list holds server webhooks only.
	response = authenticatedJSON(t, ownerClient, http.MethodGet, server.URL+"/api/v1/admin/notifications/webhooks", ownerCSRF, "")
	if body := readResponseBody(t, response); strings.Contains(body, created.ID) {
		t.Fatalf("admin server list includes a personal webhook: %s", body)
	}
	response = authenticatedJSON(t, bob, http.MethodDelete, server.URL+"/api/v1/user/webhooks/"+created.ID, bobCSRF, "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("bob delete status=%d", response.StatusCode)
	}
}
