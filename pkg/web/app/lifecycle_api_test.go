package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/scheduledsend"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func lifecycleRequest(t *testing.T, client *http.Client, method, endpoint, csrf string, body any, want int, result any) {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), method, endpoint, &encoded)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		var failure any
		_ = json.NewDecoder(resp.Body).Decode(&failure)
		t.Fatalf("%s %s: status=%d want=%d response=%v", method, endpoint, resp.StatusCode, want, failure)
	}
	if result != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			t.Fatalf("decode %s %s: %v", method, endpoint, err)
		}
	}
}

func lifecycleLogin(t *testing.T, server *httptest.Server, username, password string) (*http.Client, string) {
	t.Helper()
	client := testClient(t)
	var setup struct {
		CSRF string `json:"csrf"`
	}
	lifecycleRequest(t, client, http.MethodGet, server.URL+"/api/v1/setup", "", nil, http.StatusOK, &setup)
	var login struct {
		CSRF string `json:"csrf"`
	}
	lifecycleRequest(t, client, http.MethodPost, server.URL+"/api/v1/session/login", setup.CSRF,
		map[string]string{"username": username, "password": password}, http.StatusOK, &login)
	return client, login.CSRF
}

func TestScratchServerAdministrativeAndMailLifecycleThroughREST(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{
		model.NSDomains, model.NSOutboundRoutes, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems,
		model.NSQueue, model.NSSessions, model.NSRoles, model.NSGroups, model.NSPolicyBindings,
		model.NSPolicyIndexes, model.NSAuthorizationMetadata, model.NSSettings, model.NSMetadata, model.NSAudit,
	} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatalf("ensure %s: %v", namespace, err)
		}
	}
	engine := authz.New(ts)
	space := service.NewFolderSpace(ts, engine)
	delivery := func(ctx context.Context, msg *queue.Message) error {
		identity, identityErr := ts.UserStore().GetEmailAddress(ctx, msg.Recipient)
		if identityErr == nil && identity.Enabled {
			_, createErr := space.CreateItem(ctx, service.UserAccess(identity.UserID, "lifecycle-queue"), model.InboxFolderID(identity.UserID), service.ItemInput{
				Data: queue.BuildMessage(msg.Headers, msg.Body), Headers: msg.Headers,
			})
			return createErr
		}
		route, routeErr := ts.OutboundRouteStore().Get(ctx, recipientDomain(msg.Recipient))
		if routeErr != nil || !route.Enabled {
			return fmt.Errorf("5.1.1 no route for recipient")
		}
		return fmt.Errorf("4.4.1 simulated %s transport deferral", route.Transport)
	}
	mailQueue, err := queue.NewPersistent(t.Context(), backend, &queue.Config{Delivery: delivery, ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mailQueue.Close)
	handler, err := New(ts)
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureAdministration(config.Default(), nil)
	handler.ConfigureMigrations(space, nil)
	handler.SetMailQueue(mailQueue)
	scheduledMail, err := handler.ConfigureScheduledSubmissions(t.Context(), scheduledsend.Config{MinDelay: time.Nanosecond, Tick: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	handler.SetSystemQueue(mailQueue)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)

	admin := testClient(t)
	var setup struct {
		State string `json:"state"`
		CSRF  string `json:"csrf"`
	}
	lifecycleRequest(t, admin, http.MethodGet, server.URL+"/api/v1/setup", "", nil, http.StatusOK, &setup)
	if setup.State != "ready" || setup.CSRF == "" {
		t.Fatalf("unexpected setup state: %#v", setup)
	}
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/setup", "", map[string]string{"username": "owner", "password": "password123"}, http.StatusForbidden, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/setup", setup.CSRF,
		map[string]string{"username": "owner", "password": "password123"}, http.StatusForbidden, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/setup", setup.CSRF,
		map[string]string{"token": setupTokenFor(t, server), "username": "owner", "display_name": "System Owner", "password": "password123"}, http.StatusCreated, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/setup", setup.CSRF,
		map[string]string{"username": "second", "password": "password123"}, http.StatusConflict, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/session/login", setup.CSRF,
		map[string]string{"username": "owner", "password": "wrong-password"}, http.StatusUnauthorized, nil)
	var login struct {
		CSRF string `json:"csrf"`
	}
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/session/login", setup.CSRF,
		map[string]string{"username": "OWNER", "password": "password123"}, http.StatusOK, &login)
	if login.CSRF == "" {
		t.Fatal("login did not return a CSRF token")
	}

	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/domains", login.CSRF, map[string]string{"id": "LOCAL.TEST"}, http.StatusCreated, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/domains", login.CSRF, map[string]string{"id": "local.test"}, http.StatusConflict, nil)
	var route model.OutboundRoute
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/routes", login.CSRF,
		map[string]any{"domain": "ROUTED.TEST", "transport": "mx", "enabled": true}, http.StatusCreated, &route)
	if route.Domain != "routed.test" || route.Transport != model.OutboundTransportMX || route.RelayPort != 25 {
		t.Fatalf("unexpected route: %#v", route)
	}
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/routes", login.CSRF,
		map[string]any{"domain": "alternate.test", "transport": "relay", "relay_host": "smtp.alternate.test", "relay_port": 2525, "enabled": true}, http.StatusCreated, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/routes", login.CSRF,
		map[string]any{"domain": "disabled.test", "transport": "mx", "enabled": false}, http.StatusCreated, nil)

	for _, account := range []struct{ ID, Name string }{{"alice", "Alice"}, {"bob", "Bob"}} {
		lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/users", login.CSRF,
			map[string]string{"id": account.ID, "display_name": account.Name, "password": "password123"}, http.StatusCreated, nil)
		lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/identities", login.CSRF,
			map[string]any{"address": account.ID + "@local.test", "user_id": account.ID, "primary": true}, http.StatusCreated, nil)
	}

	alice, aliceCSRF := lifecycleLogin(t, server, "alice", "password123")
	bob, _ := lifecycleLogin(t, server, "bob", "password123")
	lifecycleRequest(t, alice, http.MethodGet, server.URL+"/api/v1/admin/routes", "", nil, http.StatusForbidden, nil)
	lifecycleRequest(t, alice, http.MethodPost, server.URL+"/api/v1/mail/submissions", "", map[string]any{
		"from": "alice@local.test", "to": []string{"bob@local.test"}, "subject": "Local delivery", "body": "hello Bob",
	}, http.StatusForbidden, nil)
	var localSubmission service.SubmissionResult
	lifecycleRequest(t, alice, http.MethodPost, server.URL+"/api/v1/mail/submissions", aliceCSRF, map[string]any{
		"from": "alice@local.test", "to": []string{"bob@local.test"}, "subject": "Local delivery", "body": "hello Bob",
	}, http.StatusAccepted, &localSubmission)
	if localSubmission.SentItemID == "" || len(localSubmission.Recipients) != 1 {
		t.Fatalf("unexpected submission: %#v", localSubmission)
	}

	var bobFolders []model.Folder
	lifecycleRequest(t, bob, http.MethodGet, server.URL+"/api/v1/workspace/folders", "", nil, http.StatusOK, &bobFolders)
	var bobInbox string
	for _, folder := range bobFolders {
		if folder.SpecialUse == model.SpecialUseInbox {
			bobInbox = folder.ID
		}
	}
	if bobInbox == "" {
		t.Fatal("Bob has no Inbox")
	}
	var bobItems []service.ItemSummary
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		lifecycleRequest(t, bob, http.MethodGet, server.URL+"/api/v1/workspace/items?folder_id="+bobInbox, "", nil, http.StatusOK, &bobItems)
		if len(bobItems) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(bobItems) != 1 || bobItems[0].Headers["Subject"] != "Local delivery" {
		t.Fatalf("Bob Inbox items: %#v", bobItems)
	}
	var delivered model.Item
	lifecycleRequest(t, bob, http.MethodGet, server.URL+"/api/v1/workspace/item?item_id="+bobItems[0].ID, "", nil, http.StatusOK, &delivered)
	if !bytes.Contains(delivered.Data, []byte("hello Bob")) {
		t.Fatalf("delivered body missing: %q", delivered.Data)
	}

	var scheduledDraft service.ItemSummary
	lifecycleRequest(t, alice, http.MethodPost, server.URL+"/api/v1/workspace/mail/drafts", aliceCSRF, map[string]any{
		"from": "alice@local.test", "to": []string{"bob@local.test"}, "subject": "Scheduled delivery", "body": "send this later", "require_tls": true,
	}, http.StatusCreated, &scheduledDraft)
	if scheduledDraft.ID == "" {
		t.Fatal("scheduled draft was not created")
	}
	var reopenedDraft service.Submission
	lifecycleRequest(t, alice, http.MethodGet, server.URL+"/api/v1/workspace/mail/drafts/"+scheduledDraft.ID, "", nil, http.StatusOK, &reopenedDraft)
	if !reopenedDraft.RequireTLS {
		t.Fatalf("reopened draft lost REQUIRETLS: %+v", reopenedDraft)
	}
	dueAt := time.Now().UTC().Add(time.Hour)
	var scheduled scheduledsend.Job
	lifecycleRequest(t, alice, http.MethodPost, server.URL+"/api/v1/mail/scheduled", "", map[string]any{"draft_id": scheduledDraft.ID, "due_at": dueAt}, http.StatusForbidden, nil)
	lifecycleRequest(t, alice, http.MethodPost, server.URL+"/api/v1/mail/scheduled", aliceCSRF, map[string]any{"draft_id": scheduledDraft.ID, "due_at": dueAt}, http.StatusCreated, &scheduled)
	lifecycleRequest(t, bob, http.MethodGet, server.URL+"/api/v1/mail/scheduled/"+scheduled.ID, "", nil, http.StatusNotFound, nil)
	lifecycleRequest(t, alice, http.MethodPatch, server.URL+"/api/v1/mail/scheduled/"+scheduled.ID, aliceCSRF, map[string]any{"due_at": dueAt.Add(time.Hour)}, http.StatusOK, &scheduled)
	lifecycleRequest(t, alice, http.MethodPost, server.URL+"/api/v1/mail/scheduled/"+scheduled.ID+"/send", aliceCSRF, map[string]any{}, http.StatusAccepted, &scheduled)
	if err := scheduledMail.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		lifecycleRequest(t, alice, http.MethodGet, server.URL+"/api/v1/mail/scheduled/"+scheduled.ID, "", nil, http.StatusOK, &scheduled)
		if scheduled.State == scheduledsend.StateCompleted {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if scheduled.State != scheduledsend.StateCompleted || scheduled.Submission.ID == "" {
		t.Fatalf("scheduled submission = %+v", scheduled)
	}
	for time.Now().Before(deadline) {
		lifecycleRequest(t, bob, http.MethodGet, server.URL+"/api/v1/workspace/items?folder_id="+bobInbox, "", nil, http.StatusOK, &bobItems)
		if len(bobItems) == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(bobItems) != 2 {
		t.Fatalf("scheduled delivery did not reach Bob: %#v", bobItems)
	}

	var routedSubmission service.SubmissionResult
	lifecycleRequest(t, alice, http.MethodPost, server.URL+"/api/v1/mail/submissions", aliceCSRF, map[string]any{
		"from": "alice@local.test", "to": []string{"person@routed.test"}, "subject": "Routed delivery", "body": "leave through MX",
	}, http.StatusAccepted, &routedSubmission)
	var queued []*queue.Message
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		lifecycleRequest(t, admin, http.MethodGet, server.URL+"/api/v1/admin/queue", "", nil, http.StatusOK, &queued)
		if len(queued) == 1 && queued[0].Status == queue.StatusRetrying {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(queued) != 1 {
		t.Fatalf("queued deliveries: %#v", queued)
	}
	if queued[0].Recipient != "person@routed.test" || queued[0].EnvelopeSender != "alice@local.test" || queued[0].Headers["Subject"] != "Routed delivery" || queued[0].Status != queue.StatusRetrying {
		t.Fatalf("unexpected routed queue item: %#v", queued[0])
	}
	if queued[0].Body != nil || queued[0].Content != nil {
		t.Fatal("queue administration API exposed message content")
	}
	queuedID := queued[0].ID
	lifecycleRequest(t, alice, http.MethodGet, server.URL+"/api/v1/admin/queue/"+queuedID, "", nil, http.StatusForbidden, nil)
	var queueDetail queue.QueueMessageDetail
	lifecycleRequest(t, admin, http.MethodGet, server.URL+"/api/v1/admin/queue/"+queuedID, "", nil, http.StatusOK, &queueDetail)
	if queueDetail.ID != queuedID || queueDetail.Recipient != "person@routed.test" || queueDetail.Subject != "Routed delivery" || len(queueDetail.Attempts) == 0 {
		t.Fatalf("queue detail: %#v", queueDetail)
	}
	lifecycleRequest(t, admin, http.MethodGet, server.URL+"/api/v1/admin/queue/missing", "", nil, http.StatusNotFound, nil)
	mailQueue.Close()
	restoredQueue, err := queue.NewPersistent(t.Context(), backend, &queue.Config{Delivery: delivery, ProcessPeriod: time.Hour})
	if err != nil {
		t.Fatalf("restore durable queue: %v", err)
	}
	t.Cleanup(restoredQueue.Close)
	handler.SetMailQueue(restoredQueue)
	handler.SetSystemQueue(restoredQueue)
	queued = nil
	lifecycleRequest(t, admin, http.MethodGet, server.URL+"/api/v1/admin/queue", "", nil, http.StatusOK, &queued)
	if len(queued) != 1 || queued[0].ID != queuedID || queued[0].Recipient != "person@routed.test" {
		t.Fatalf("queue did not survive restart: %#v", queued)
	}
	var bulkResult struct {
		Results []queueActionResult `json:"results"`
	}
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/actions", login.CSRF,
		map[string]any{"action": "hold", "ids": []string{queuedID}, "reason": "Route maintenance"}, http.StatusOK, &bulkResult)
	if len(bulkResult.Results) != 1 || bulkResult.Results[0].Status != "paused" || restoredQueue.Get(queuedID).Status != queue.StatusPaused || restoredQueue.Get(queuedID).HoldReason != "Route maintenance" {
		t.Fatalf("bulk hold result=%#v message=%#v", bulkResult, restoredQueue.Get(queuedID))
	}
	lifecycleRequest(t, alice, http.MethodPost, server.URL+"/api/v1/admin/queue/"+queuedID+"/reroute", aliceCSRF,
		map[string]string{"route": "alternate.test", "reason": "operator recovery"}, http.StatusForbidden, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/"+queuedID+"/reroute", "",
		map[string]string{"route": "alternate.test", "reason": "operator recovery"}, http.StatusForbidden, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/"+queuedID+"/reroute", login.CSRF,
		map[string]string{"route": "missing.test", "reason": "operator recovery"}, http.StatusBadRequest, nil)
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/"+queuedID+"/reroute", login.CSRF,
		map[string]string{"route": "disabled.test", "reason": "operator recovery"}, http.StatusConflict, nil)
	var rerouteResult struct {
		Change queue.RouteChange `json:"change"`
	}
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/"+queuedID+"/reroute", login.CSRF,
		map[string]string{"route": "ALTERNATE.TEST", "reason": "Route maintenance recovery"}, http.StatusOK, &rerouteResult)
	rerouted := restoredQueue.Get(queuedID)
	if rerouteResult.Change.Current != "alternate.test" || rerouted.AdministrativeRoute != "alternate.test" || rerouted.Status != queue.StatusPaused || len(rerouted.RouteChanges) != 1 || rerouted.RouteChanges[0].Actor != "owner" {
		t.Fatalf("reroute result=%#v message=%#v", rerouteResult, rerouted)
	}
	var reroutedDetail queue.QueueMessageDetail
	lifecycleRequest(t, admin, http.MethodGet, server.URL+"/api/v1/admin/queue/"+queuedID, "", nil, http.StatusOK, &reroutedDetail)
	if reroutedDetail.AdministrativeRoute != "alternate.test" || len(reroutedDetail.RouteChanges) != 1 || reroutedDetail.RouteChanges[0].Reason != "Route maintenance recovery" {
		t.Fatalf("reroute detail=%#v", reroutedDetail)
	}
	var auditEntries []struct {
		Actor   string            `json:"actor"`
		Action  string            `json:"action"`
		Target  string            `json:"target"`
		Details map[string]string `json:"details"`
	}
	lifecycleRequest(t, admin, http.MethodGet, server.URL+"/api/v1/admin/audit", "", nil, http.StatusOK, &auditEntries)
	foundRerouteAudit := false
	for _, entry := range auditEntries {
		if entry.Action == "queue.reroute" && entry.Target == queuedID && entry.Actor == "owner" && entry.Details["route"] == "alternate.test" && entry.Details["reason"] == "Route maintenance recovery" {
			foundRerouteAudit = true
		}
	}
	if !foundRerouteAudit {
		t.Fatalf("queue reroute audit missing from %#v", auditEntries)
	}
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/actions", login.CSRF,
		map[string]any{"action": "hold", "ids": []string{queuedID, queuedID}}, http.StatusBadRequest, nil)
	bulkResult.Results = nil
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/actions", login.CSRF,
		map[string]any{"action": "release", "ids": []string{queuedID}}, http.StatusOK, &bulkResult)
	if len(bulkResult.Results) != 1 || bulkResult.Results[0].Status != "pending" {
		t.Fatalf("bulk release result=%#v", bulkResult)
	}

	var aliceFolders []model.Folder
	lifecycleRequest(t, alice, http.MethodGet, server.URL+"/api/v1/workspace/folders", "", nil, http.StatusOK, &aliceFolders)
	var sentID string
	for _, folder := range aliceFolders {
		if folder.SpecialUse == model.SpecialUseSent {
			sentID = folder.ID
		}
	}
	var sentItems []service.ItemSummary
	lifecycleRequest(t, alice, http.MethodGet, server.URL+"/api/v1/workspace/items?folder_id="+sentID, "", nil, http.StatusOK, &sentItems)
	if len(sentItems) != 3 {
		t.Fatalf("Sent should contain one copy per submission, got %d", len(sentItems))
	}

	lifecycleRequest(t, admin, http.MethodPut, server.URL+"/api/v1/admin/routes/routed.test", login.CSRF,
		map[string]any{"transport": "relay", "relay_host": "smtp.route.test", "relay_port": 2525, "require_tls": true, "enabled": true}, http.StatusOK, &route)
	if route.Transport != model.OutboundTransportRelay || route.RelayHost != "smtp.route.test" || route.RelayPort != 2525 || !route.RequireTLS {
		t.Fatalf("route update failed: %#v", route)
	}
	lifecycleRequest(t, admin, http.MethodDelete, server.URL+"/api/v1/admin/routes/routed.test", login.CSRF, nil, http.StatusNoContent, nil)
	lifecycleRequest(t, admin, http.MethodGet, server.URL+"/api/v1/admin/routes/routed.test", "", nil, http.StatusNotFound, nil)
	if restoredQueue.Get(queuedID) == nil {
		t.Fatal("deleting a route unexpectedly deleted already accepted queue work")
	}
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/"+queuedID+"/cancel", login.CSRF, nil, http.StatusOK, nil)
	if restoredQueue.Get(queuedID).Status != queue.StatusCancelled {
		t.Fatalf("queue cancellation was not durable: %#v", restoredQueue.Get(queuedID))
	}
	lifecycleRequest(t, admin, http.MethodPost, server.URL+"/api/v1/admin/queue/"+queuedID+"/retry", login.CSRF, nil, http.StatusConflict, nil)
}

func recipientDomain(address string) string {
	for index := len(address) - 1; index >= 0; index-- {
		if address[index] == '@' {
			return address[index+1:]
		}
	}
	return ""
}
