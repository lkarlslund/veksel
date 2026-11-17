package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/mailstate"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/scheduledsend"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestMailPreferencesDefaultValidateAndPersist(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	settings := decodeTestJSON[userSettingsResponse](t, mustGet(t, client, server.URL+"/api/v1/user/settings"))
	if settings.MailPreferences.UndoSendSeconds != model.DefaultUndoSendSeconds || settings.MailPreferences.Shortcuts != "owa" {
		t.Fatalf("default preferences = %+v", settings.MailPreferences)
	}
	for _, invalid := range []string{`{"undo_send_seconds":7,"shortcuts":"owa"}`, `{"undo_send_seconds":10,"shortcuts":"vim"}`} {
		response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/mail-preferences", csrf, invalid)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status=%d", invalid, response.StatusCode)
		}
	}
	response := authenticatedJSON(t, client, http.MethodPut, server.URL+"/api/v1/user/mail-preferences", csrf, `{"undo_send_seconds":0,"shortcuts":"gmail"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("save preferences status=%d", response.StatusCode)
	}
	settings = decodeTestJSON[userSettingsResponse](t, mustGet(t, client, server.URL+"/api/v1/user/settings"))
	if settings.MailPreferences.UndoSendSeconds != 0 || settings.MailPreferences.Shortcuts != "gmail" {
		t.Fatalf("saved preferences = %+v", settings.MailPreferences)
	}
}

func TestUndoSendHoldsDraftUntilWindowAndCancelReturnsIt(t *testing.T) {
	handler, ts := testHandler(t)
	mailQueue := &acceptingSubmissionQueue{}
	handler.SetMailQueue(mailQueue)
	scheduler, err := handler.ConfigureScheduledSubmissions(t.Context(), scheduledsend.Config{Tick: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
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
	saveDraft := func(subject string) service.ItemSummary {
		t.Helper()
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/mail/drafts", csrf, `{"from":"alice@example.test","to":["recipient@example.net"],"subject":"`+subject+`","body":"Hello"}`)
		defer response.Body.Close()
		var draft service.ItemSummary
		if err := json.NewDecoder(response.Body).Decode(&draft); err != nil || response.StatusCode != http.StatusCreated {
			t.Fatalf("draft status=%d err=%v", response.StatusCode, err)
		}
		return draft
	}
	hold := func(draftID string, seconds int) (scheduledSubmissionView, int) {
		t.Helper()
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/mail/scheduled", csrf, `{"draft_id":"`+draftID+`","undo_seconds":`+strconv.Itoa(seconds)+`}`)
		defer response.Body.Close()
		var job scheduledSubmissionView
		_ = json.NewDecoder(response.Body).Decode(&job)
		return job, response.StatusCode
	}
	draft := saveDraft("Recall me")
	if _, status := hold(draft.ID, 31); status != http.StatusBadRequest {
		t.Fatalf("31 second hold status=%d", status)
	}
	job, status := hold(draft.ID, 10)
	if status != http.StatusCreated || !job.Undo || job.State != scheduledsend.StatePending {
		t.Fatalf("hold status=%d job=%+v", status, job)
	}
	// Nothing is queued or filed in Sent during the window.
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if mailQueue.messages != 0 {
		t.Fatalf("queued during the undo window: %d", mailQueue.messages)
	}
	sent := decodeTestJSON[mailindex.Page](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/list?folder_id="+url.QueryEscape(model.SentFolderID("alice"))))
	if sent.Total != 0 {
		t.Fatalf("Sent copy before sending: %+v", sent.Items)
	}
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/mail/scheduled/"+job.ID+"/cancel", csrf, `{}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("undo status=%d", response.StatusCode)
	}
	restored := decodeTestJSON[service.Submission](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/drafts/"+draft.ID))
	if restored.Subject != "Recall me" {
		t.Fatalf("undone draft = %+v", restored)
	}
	if err := scheduler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if mailQueue.messages != 0 {
		t.Fatalf("undone message was queued")
	}
}

func TestPinSnoozeAndFollowUpActionsThroughTheMailList(t *testing.T) {
	handler, ts := testHandler(t)
	states, err := handler.ConfigureMailState(t.Context(), mailstate.Config{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	_ = ts
	inbox := model.InboxFolderID("alice")
	base := now.Add(-48 * time.Hour)
	old := seedMail(t, handler, inbox, "From: a@example.net\nSubject: Old\n\nold\n", base, model.FlagSeen)
	newer := seedMail(t, handler, inbox, "From: b@example.net\nSubject: Newer\n\nnewer\n", base.Add(time.Hour), model.FlagSeen)
	later := seedMail(t, handler, inbox, "From: c@example.net\nSubject: Later\n\nlater\n", base.Add(2*time.Hour), model.FlagSeen)
	act := func(body string) (map[string]any, int) {
		t.Helper()
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, body)
		defer response.Body.Close()
		payload, _ := io.ReadAll(response.Body)
		var result map[string]any
		_ = json.Unmarshal(payload, &result)
		return result, response.StatusCode
	}
	list := func(folderID string) mailindex.Page {
		t.Helper()
		return decodeTestJSON[mailindex.Page](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/list?view=messages&folder_id="+url.QueryEscape(folderID)))
	}

	if _, status := act(`{"item_ids":["` + old.ID + `"],"action":"pin"}`); status != http.StatusOK {
		t.Fatalf("pin status=%d", status)
	}
	page := list(inbox)
	if page.Items[0].ID != old.ID || !slices.Contains(page.Items[0].Flags, model.KeywordPinned) {
		t.Fatalf("pinned message not first: %+v", page.Items)
	}

	wake := now.Add(3 * time.Hour)
	if _, status := act(`{"item_ids":["` + later.ID + `"],"action":"snooze","until":"` + now.Add(-time.Minute).Format(time.RFC3339) + `"}`); status != http.StatusBadRequest {
		t.Fatalf("snooze into the past status=%d", status)
	}
	result, status := act(`{"item_ids":["` + later.ID + `"],"action":"snooze","until":"` + wake.Format(time.RFC3339) + `"}`)
	if status != http.StatusOK {
		t.Fatalf("snooze status=%d %v", status, result)
	}
	snoozedFolder := result["items"].([]any)[0].(map[string]any)["folder_id"].(string)
	if page = list(inbox); page.Total != 2 {
		t.Fatalf("snoozed message still in Inbox: %+v", page.Items)
	}
	snoozed := list(snoozedFolder)
	if snoozed.Total != 1 || snoozed.Items[0].SnoozedUntil == nil || !snoozed.Items[0].SnoozedUntil.Equal(wake) {
		t.Fatalf("Snoozed view = %+v", snoozed.Items)
	}
	states.SetClock(func() time.Time { return wake })
	if settled, err := states.RunOnce(t.Context()); err != nil || settled != 1 {
		t.Fatalf("wake settled=%d err=%v", settled, err)
	}
	if page = list(inbox); page.Total != 3 || page.Unread != 1 {
		t.Fatalf("woken message not back unread: %+v", page)
	}
	states.SetClock(func() time.Time { return time.Now().UTC() })

	due := now.Add(24 * time.Hour)
	if _, status := act(`{"item_ids":["` + newer.ID + `"],"action":"follow_up","due_at":"` + due.Format(time.RFC3339) + `","reminder_at":"` + now.Add(-time.Minute).Format(time.RFC3339) + `"}`); status != http.StatusOK {
		t.Fatalf("follow-up status=%d", status)
	}
	if _, status := act(`{"item_ids":["` + old.ID + `"],"action":"flag"}`); status != http.StatusOK {
		t.Fatalf("flag status=%d", status)
	}
	page = list(inbox)
	for _, item := range page.Items {
		if item.ID == newer.ID && (item.FollowUp == nil || item.FollowUp.DueAt == nil || !item.FollowUp.DueAt.Equal(due)) {
			t.Fatalf("follow-up mark = %+v", item.FollowUp)
		}
	}
	var smart struct {
		Items []followUpRow `json:"items"`
	}
	smart = decodeTestJSON[struct {
		Items []followUpRow `json:"items"`
	}](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/follow-ups"))
	if len(smart.Items) != 2 || smart.Items[0].ID != newer.ID || smart.Items[1].ID != old.ID || smart.Items[0].FolderName == "" {
		t.Fatalf("follow-up view = %+v", smart.Items)
	}
	reminders := decodeTestJSON[[]mailReminder](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/reminders"))
	if len(reminders) != 1 || reminders[0].ItemID != newer.ID || reminders[0].Subject != "Newer" {
		t.Fatalf("reminders = %+v", reminders)
	}
	if _, status := act(`{"item_ids":["` + newer.ID + `"],"action":"dismiss_reminder"}`); status != http.StatusOK {
		t.Fatalf("dismiss status=%d", status)
	}
	if reminders = decodeTestJSON[[]mailReminder](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/reminders")); len(reminders) != 0 {
		t.Fatalf("dismissed reminders = %+v", reminders)
	}
	if _, status := act(`{"item_ids":["` + newer.ID + `"],"action":"complete"}`); status != http.StatusOK {
		t.Fatalf("complete status=%d", status)
	}
	smart = decodeTestJSON[struct {
		Items []followUpRow `json:"items"`
	}](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/follow-ups"))
	if len(smart.Items) != 1 || smart.Items[0].ID != old.ID {
		t.Fatalf("follow-up view after complete = %+v", smart.Items)
	}
	if records, _ := states.FollowUps(t.Context(), "alice"); len(records) != 0 {
		t.Fatalf("records after complete = %+v", records)
	}
}
