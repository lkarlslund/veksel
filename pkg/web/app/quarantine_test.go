package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/virus"
)

type recordingQuarantineQueue struct {
	messages []*queue.Message
	err      error
}

type recordingContentTrainer struct {
	content []byte
	spam    bool
	calls   int
	err     error
}

func (t *recordingContentTrainer) Learn(_ context.Context, content []byte, spam bool) error {
	t.calls++
	t.content = append([]byte(nil), content...)
	t.spam = spam
	return t.err
}

func (q *recordingQuarantineQueue) EnqueueBatch(messages []*queue.Message) error {
	if q.err != nil {
		return q.err
	}
	q.messages = append(q.messages, messages...)
	return nil
}
func (q *recordingQuarantineQueue) Size() int          { return len(q.messages) }
func (q *recordingQuarantineQueue) Stats() queue.Stats { return queue.Stats{Size: len(q.messages)} }
func (q *recordingQuarantineQueue) PruneReceipts(context.Context, time.Time, int, bool) (queue.ReceiptPruneResult, error) {
	return queue.ReceiptPruneResult{}, nil
}
func (q *recordingQuarantineQueue) List(queue.Status) []*queue.Message { return q.messages }
func (q *recordingQuarantineQueue) Retry(string) bool                  { return false }
func (q *recordingQuarantineQueue) Remove(string) bool                 { return false }
func (q *recordingQuarantineQueue) Cancel(string) bool                 { return false }
func (q *recordingQuarantineQueue) Hold(string) bool                   { return false }
func (q *recordingQuarantineQueue) HoldWithReason(string, string) bool { return false }
func (q *recordingQuarantineQueue) Release(string) bool                { return false }

func loginExistingUser(t *testing.T, client *http.Client, serverURL, username string) string {
	t.Helper()
	response, err := client.Get(serverURL + "/app/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	_ = response.Body.Close()
	csrf := csrfCookieValue(t, client, serverURL)
	response, err = client.PostForm(serverURL+"/app/login", url.Values{"_csrf": {csrf}, "username": {username}, "password": {"password123"}})
	if err != nil {
		t.Fatalf("login %s: %v", username, err)
	}
	_ = response.Body.Close()
	return csrf
}

func quarantineRequest(t *testing.T, client *http.Client, method, rawURL, csrf string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	return response
}

func decodeQuarantineResponse[T any](t *testing.T, response *http.Response) T {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	var value T
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return value
}

func TestQuarantinePagingInspectionAndRelease(t *testing.T) {
	handler, typedStore := testHandler(t)
	mailQueue := &recordingQuarantineQueue{}
	handler.SetSystemQueue(mailQueue)
	trainer := &recordingContentTrainer{}
	handler.ConfigureContentTrainer(trainer)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	users := model.NewUserStore(typedStore)
	if err := users.AddEmailAddress(t.Context(), "alice@example.com", "alice", "example.com", true); err != nil {
		t.Fatalf("add identity: %v", err)
	}
	quarantine := virus.NewQuarantineStore(typedStore)
	for _, entry := range []virus.QuarantineEntry{
		{ID: "one", Sender: "first@example.net", Recipient: "alice@example.com", Subject: "Alpha", Date: "2026-08-15T10:00:00Z", VirusName: "Test.One", MessageSize: 100, Headers: map[string]string{"Subject": "Alpha"}, MessageData: []byte("Subject: Alpha\r\nFrom: first@example.net\r\n\r\nfirst body"), ReasonType: "content_scan", Reason: "malware detected", AuthenticationResults: "mx.example; spf=pass", ScanTranscript: `{"decision":"quarantine","results":[{"engine":"clamav","verdict":"malware"}]}`},
		{ID: "two", Sender: "second@example.net", Recipient: "alice@example.com", Subject: "Beta", Date: "2026-08-16T10:00:00Z", VirusName: "Test.Two", MessageSize: 200, Headers: map[string]string{"Subject": "Beta"}, MessageData: []byte("Subject: Beta\r\nFrom: second@example.net\r\n\r\nsecond body")},
	} {
		if _, err := quarantine.Add(t.Context(), &entry); err != nil {
			t.Fatalf("add quarantine entry: %v", err)
		}
	}
	response := quarantineRequest(t, client, http.MethodGet, server.URL+"/api/v1/quarantine?page=1&page_size=1&sort=subject&direction=asc", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", response.StatusCode)
	}
	page := decodeQuarantineResponse[quarantinePage](t, response)
	if page.Total != 2 || page.Pages != 2 || len(page.Entries) != 1 || page.Entries[0].ID != "one" {
		t.Fatalf("unexpected page: %+v", page)
	}
	response = quarantineRequest(t, client, http.MethodGet, server.URL+"/api/v1/quarantine/one", "", nil)
	detail := decodeQuarantineResponse[quarantineView](t, response)
	if string(detail.MessageData) != "Subject: Alpha\r\nFrom: first@example.net\r\n\r\nfirst body" {
		t.Fatalf("message data = %q", detail.MessageData)
	}
	if !detail.TrainingAvailable || detail.ReasonType != "content_scan" || detail.Reason != "malware detected" || detail.AuthenticationResults == "" || detail.ScanTranscript == "" {
		t.Fatalf("quarantine evidence = %+v", detail)
	}
	response = quarantineRequest(t, client, http.MethodPost, server.URL+"/api/v1/quarantine/one/train", "", []byte(`{"classification":"spam"}`))
	if response.StatusCode != http.StatusForbidden || trainer.calls != 0 {
		_ = response.Body.Close()
		t.Fatalf("training without CSRF status = %d calls=%d", response.StatusCode, trainer.calls)
	}
	_ = response.Body.Close()
	response = quarantineRequest(t, client, http.MethodPost, server.URL+"/api/v1/quarantine/one/train", csrf, []byte(`{"classification":"junk"}`))
	if response.StatusCode != http.StatusBadRequest || trainer.calls != 0 {
		_ = response.Body.Close()
		t.Fatalf("invalid training status = %d calls=%d", response.StatusCode, trainer.calls)
	}
	_ = response.Body.Close()
	response = quarantineRequest(t, client, http.MethodPost, server.URL+"/api/v1/quarantine/one/train", csrf, []byte(`{"classification":"spam"}`))
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("training status = %d body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()
	if trainer.calls != 1 || !trainer.spam || string(trainer.content) != string(detail.MessageData) {
		t.Fatalf("training call = calls=%d spam=%v content=%q", trainer.calls, trainer.spam, trainer.content)
	}
	if _, err := quarantine.Get(t.Context(), "one"); err != nil {
		t.Fatalf("training removed quarantine entry: %v", err)
	}
	trainer.err = errors.New("trainer unavailable")
	response = quarantineRequest(t, client, http.MethodPost, server.URL+"/api/v1/quarantine/one/train", csrf, []byte(`{"classification":"ham"}`))
	if response.StatusCode != http.StatusServiceUnavailable {
		_ = response.Body.Close()
		t.Fatalf("failed training status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	trainer.err = nil
	response = quarantineRequest(t, client, http.MethodPost, server.URL+"/api/v1/quarantine/one/release", csrf, nil)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("release status = %d body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()
	if _, err := quarantine.Get(t.Context(), "one"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("released quarantine entry still exists: %v", err)
	}
	if len(mailQueue.messages) != 1 {
		t.Fatalf("release queue messages = %d, want 1", len(mailQueue.messages))
	}
	queued := mailQueue.messages[0]
	if queued.TargetFolderID != model.InboxFolderID("alice") || queued.TargetOwnerID != "alice" || string(queued.Content) != "Subject: Alpha\r\nFrom: first@example.net\r\n\r\nfirst body" {
		t.Fatalf("released queue message = %+v", queued)
	}
	// A retried HTTP request resolves through the durable receipt and must not
	// enqueue a second delivery.
	response = quarantineRequest(t, client, http.MethodPost, server.URL+"/api/v1/quarantine/one/release", csrf, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("repeat release status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	if len(mailQueue.messages) != 1 {
		t.Fatalf("repeat release enqueued %d messages, want 1", len(mailQueue.messages))
	}

	mailQueue.err = errors.New("queue storage unavailable")
	response = quarantineRequest(t, client, http.MethodPost, server.URL+"/api/v1/quarantine/two/release", csrf, nil)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("failed release status = %d, want 503", response.StatusCode)
	}
	_ = response.Body.Close()
	if _, err := quarantine.Get(t.Context(), "two"); err != nil {
		t.Fatalf("release removed content before queue acceptance: %v", err)
	}
}

func TestQuarantinePrivacySpamConfirmationAndPrivateLists(t *testing.T) {
	server, typedStore := testApp(t)
	ownerClient := testClient(t)
	setupAndLogin(t, server, ownerClient, "owner")
	users := model.NewUserStore(typedStore)
	for _, userID := range []string{"bob", "carol"} {
		if err := users.Create(t.Context(), userID, userID, "password123"); err != nil {
			t.Fatalf("create %s: %v", userID, err)
		}
		if err := model.NewFolderStore(typedStore).EnsureForUser(t.Context(), userID); err != nil {
			t.Fatalf("ensure %s folders: %v", userID, err)
		}
		if err := users.AddEmailAddress(t.Context(), userID+"@example.com", userID, "example.com", true); err != nil {
			t.Fatalf("add %s identity: %v", userID, err)
		}
	}
	quarantine := virus.NewQuarantineStore(typedStore)
	for _, entry := range []virus.QuarantineEntry{
		{ID: "bob-message", Sender: "Spammer <SPAMMER@evil.example>", Recipient: "bob@example.com", Subject: "Spam", Date: "2026-08-16T10:00:00Z", MessageData: []byte("Subject: Spam\r\n\r\nspam")},
		{ID: "carol-message", Sender: "other@example.net", Recipient: "carol@example.com", Subject: "Private", Date: "2026-08-16T11:00:00Z"},
	} {
		if _, err := quarantine.Add(t.Context(), &entry); err != nil {
			t.Fatalf("add quarantine entry: %v", err)
		}
	}
	bobClient := testClient(t)
	csrf := loginExistingUser(t, bobClient, server.URL, "bob")
	page := decodeQuarantineResponse[quarantinePage](t, quarantineRequest(t, bobClient, http.MethodGet, server.URL+"/api/v1/quarantine", "", nil))
	if page.Total != 1 || len(page.Entries) != 1 || page.Entries[0].ID != "bob-message" {
		t.Fatalf("Bob can see another user's quarantine: %+v", page)
	}
	forbidden := quarantineRequest(t, bobClient, http.MethodGet, server.URL+"/api/v1/quarantine/carol-message", "", nil)
	if forbidden.StatusCode != http.StatusForbidden {
		_ = forbidden.Body.Close()
		t.Fatalf("other user's detail status = %d, want 403", forbidden.StatusCode)
	}
	_ = forbidden.Body.Close()
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	response := quarantineRequest(t, bobClient, http.MethodPost, server.URL+"/api/v1/spam-lists/allow", csrf, []byte(fmt.Sprintf(`{"entry":"trusted.example","expires_at":%q}`, expiresAt.Format(time.RFC3339))))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("add allow entry status = %d", response.StatusCode)
	}
	var lists spamListsResponse
	if err := json.NewDecoder(response.Body).Decode(&lists); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(lists.Allow) != 1 || lists.Allow[0] != "trusted.example" || len(lists.AllowEntries) != 1 || lists.AllowEntries[0].ExpiresAt != expiresAt.Format(time.RFC3339) {
		t.Fatalf("sender lists response = %+v", lists)
	}
	invalid := quarantineRequest(t, bobClient, http.MethodPost, server.URL+"/api/v1/spam-lists/block", csrf, []byte(`{"entry":"past.example","expires_at":"2020-01-01T00:00:00Z"}`))
	if invalid.StatusCode != http.StatusBadRequest {
		t.Fatalf("past expiry status = %d, want 400", invalid.StatusCode)
	}
	_ = invalid.Body.Close()
	response = quarantineRequest(t, bobClient, http.MethodPost, server.URL+"/api/v1/quarantine/bob-message/spam", csrf, nil)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("confirm spam status = %d body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()
	if got := users.GetSpamWhitelist(t.Context(), "bob"); len(got) != 1 || got[0] != "trusted.example" {
		t.Fatalf("Bob allow list = %v", got)
	}
	if got := users.GetSpamBlacklist(t.Context(), "bob"); len(got) != 1 || got[0] != "spammer@evil.example" {
		t.Fatalf("Bob block list = %v", got)
	}
	if got := users.GetSpamBlacklist(t.Context(), "carol"); len(got) != 0 {
		t.Fatalf("Carol block list changed: %v", got)
	}
	if _, err := quarantine.Get(t.Context(), "bob-message"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("confirmed spam entry still exists: %v", err)
	}
}

func TestQuarantineDigestPreferencesAdminStatusAndSignedRelease(t *testing.T) {
	handler, typedStore := testHandler(t)
	mailQueue := &recordingQuarantineQueue{}
	handler.SetSystemQueue(mailQueue)
	quarantine := virus.NewQuarantineStore(typedStore, virus.QuarantinePolicy{Retention: 30 * 24 * time.Hour, MaxEntries: 100, MaxBytes: 1 << 20})
	quarantine.SetOwnerResolver(func(ctx context.Context, recipient string) (string, error) {
		identity, err := typedStore.UserStore().GetEmailAddress(ctx, recipient)
		return identity.UserID, err
	})
	actions, err := virus.NewQuarantineActionService(t.Context(), typedStore, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureQuarantine(quarantine)
	handler.ConfigureQuarantineActions(actions)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	digests, err := virus.NewQuarantineDigestService(typedStore, quarantine, actions, func(context.Context, string) (string, error) {
		return "alice@example.com", nil
	}, virus.QuarantineDigestConfig{BaseURL: server.URL, FromAddress: "postmaster@example.com", MaxEntries: 50, MaxJobsPerRun: 10, MaxAttempts: 3, RetryBase: time.Minute, JobRetention: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureQuarantineDigests(digests)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	if err := typedStore.UserStore().AddEmailAddress(t.Context(), "alice@example.com", "alice", "example.com", true); err != nil {
		t.Fatal(err)
	}
	entry := virus.QuarantineEntry{ID: "digest-release", OwnerID: "alice", Sender: "sender@example.net", Recipient: "alice@example.com", Subject: "Review me", MessageData: []byte("Subject: Review me\r\n\r\nbody")}
	if _, err := quarantine.Add(t.Context(), &entry); err != nil {
		t.Fatal(err)
	}

	preferenceResponse := quarantineRequest(t, client, http.MethodGet, server.URL+"/api/v1/quarantine/digest", "", nil)
	if preferenceResponse.StatusCode != http.StatusOK {
		t.Fatalf("preference status = %d", preferenceResponse.StatusCode)
	}
	preference := decodeQuarantineResponse[quarantineDigestPreferenceResponse](t, preferenceResponse)
	if !preference.Available || preference.Preference.Schedule != virus.QuarantineDigestOff {
		t.Fatalf("default preference = %+v", preference)
	}
	updatedResponse := quarantineRequest(t, client, http.MethodPut, server.URL+"/api/v1/quarantine/digest", csrf, []byte(`{"schedule":"daily","hour_utc":8,"weekday":1}`))
	if updatedResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(updatedResponse.Body)
		_ = updatedResponse.Body.Close()
		t.Fatalf("update preference status = %d body=%s", updatedResponse.StatusCode, body)
	}
	updated := decodeQuarantineResponse[quarantineDigestPreferenceResponse](t, updatedResponse)
	if updated.Preference.Schedule != virus.QuarantineDigestDaily || updated.Preference.NextRunAt.IsZero() {
		t.Fatalf("updated preference = %+v", updated)
	}

	statusResponse := quarantineRequest(t, client, http.MethodGet, server.URL+"/api/v1/admin/quarantine/status", "", nil)
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatalf("admin status = %d", statusResponse.StatusCode)
	}
	status := decodeQuarantineResponse[map[string]any](t, statusResponse)
	storage := status["storage"].(map[string]any)
	if int(storage["entries"].(float64)) != 1 || status["digests_enabled"] != true {
		t.Fatalf("admin quarantine status = %+v", status)
	}

	token, err := actions.Issue(t.Context(), entry, virus.QuarantineActionRelease)
	if err != nil {
		t.Fatal(err)
	}
	publicClient := testClient(t)
	confirmation, err := publicClient.Get(server.URL + "/quarantine/action?token=" + url.QueryEscape(token))
	if err != nil {
		t.Fatal(err)
	}
	confirmationBody, _ := io.ReadAll(confirmation.Body)
	_ = confirmation.Body.Close()
	if confirmation.StatusCode != http.StatusOK || !bytes.Contains(confirmationBody, []byte("Release this message?")) || confirmation.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("confirmation status=%d headers=%v body=%s", confirmation.StatusCode, confirmation.Header, confirmationBody)
	}
	if _, err := quarantine.Get(t.Context(), entry.ID); err != nil {
		t.Fatalf("GET confirmation mutated quarantine: %v", err)
	}
	executed, err := publicClient.PostForm(server.URL+"/quarantine/action", url.Values{"token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	_ = executed.Body.Close()
	if executed.StatusCode != http.StatusOK || len(mailQueue.messages) != 1 {
		t.Fatalf("execute status=%d queued=%d", executed.StatusCode, len(mailQueue.messages))
	}
	replay, err := publicClient.PostForm(server.URL+"/quarantine/action", url.Values{"token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	_ = replay.Body.Close()
	if replay.StatusCode != http.StatusConflict || len(mailQueue.messages) != 1 {
		t.Fatalf("replay status=%d queued=%d", replay.StatusCode, len(mailQueue.messages))
	}

	rebuild := quarantineRequest(t, client, http.MethodPost, server.URL+"/api/v1/admin/quarantine/rebuild", csrf, nil)
	if rebuild.StatusCode != http.StatusOK {
		t.Fatalf("rebuild status = %d", rebuild.StatusCode)
	}
	_ = rebuild.Body.Close()
}

func TestSignedQuarantineSpamActionIsOwnerScopedAndIdempotent(t *testing.T) {
	handler, typedStore := testHandler(t)
	quarantine := virus.NewQuarantineStore(typedStore, virus.QuarantinePolicy{Retention: 24 * time.Hour})
	actions, err := virus.NewQuarantineActionService(t.Context(), typedStore, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureQuarantine(quarantine)
	handler.ConfigureQuarantineActions(actions)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	if err := typedStore.UserStore().AddEmailAddress(t.Context(), "alice@example.com", "alice", "example.com", true); err != nil {
		t.Fatal(err)
	}
	entry := virus.QuarantineEntry{ID: "digest-spam", OwnerID: "alice", Sender: "Spammer <spam@evil.example>", Recipient: "alice@example.com", Subject: "Spam", MessageData: []byte("spam")}
	if _, err := quarantine.Add(t.Context(), &entry); err != nil {
		t.Fatal(err)
	}
	token, err := actions.Issue(t.Context(), entry, virus.QuarantineActionSpam)
	if err != nil {
		t.Fatal(err)
	}
	response, err := testClient(t).PostForm(server.URL+"/quarantine/action", url.Values{"token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("spam action status = %d", response.StatusCode)
	}
	blocked := typedStore.UserStore().GetSpamBlacklist(t.Context(), "alice")
	if len(blocked) != 1 || blocked[0] != "spam@evil.example" {
		t.Fatalf("blocked senders = %v", blocked)
	}
	receipt, err := quarantine.GetSpamReceipt(t.Context(), entry.ID)
	if err != nil || receipt.OwnerID != "alice" || receipt.Blocked != "spam@evil.example" {
		t.Fatalf("spam receipt = %+v, %v", receipt, err)
	}
}
