package app

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func decodeTestJSON[T any](t *testing.T, response *http.Response) T {
	t.Helper()
	defer response.Body.Close()
	var value T
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d for %s", response.StatusCode, response.Request.URL)
	}
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func seedMail(t *testing.T, handler *Handler, folderID, message string, date time.Time, flags ...string) model.Item {
	t.Helper()
	item, err := handler.folderSpace.CreateItem(t.Context(), service.UserAccess("alice", "test"), folderID, service.ItemInput{Data: []byte(strings.ReplaceAll(message, "\n", "\r\n")), InternalDate: date, Flags: flags})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestWorkspaceMailListServesPreviewFiltersSortAndUnreadCounts(t *testing.T) {
	handler, ts := testHandler(t)
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
	inbox := model.InboxFolderID("alice")
	base := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	toMe := seedMail(t, handler, inbox, "From: Zed <zed@example.net>\nTo: alice@example.test\nSubject: Quarterly numbers\n\nThe numbers are in.\n", base)
	flagged := seedMail(t, handler, inbox, "From: amy@example.net\nTo: list@example.net\nSubject: Newsletter\n\nWeekly digest\n", base.Add(time.Hour), model.FlagSeen, model.FlagFlagged)

	list := func(query string) mailindex.Page {
		response, err := client.Get(server.URL + "/api/v1/workspace/mail/list?folder_id=" + url.QueryEscape(inbox) + query)
		if err != nil {
			t.Fatal(err)
		}
		return decodeTestJSON[mailindex.Page](t, response)
	}
	page := list("")
	if page.Total != 2 || page.Unread != 1 || page.Items[0].ID != flagged.ID || page.Items[1].Preview != "The numbers are in." {
		t.Fatalf("default page = %+v", page)
	}
	if page = list("&filter=to_me"); len(page.Items) != 1 || page.Items[0].ID != toMe.ID {
		t.Fatalf("to-me page = %+v", page)
	}
	if page = list("&filter=flagged"); len(page.Items) != 1 || page.Items[0].ID != flagged.ID {
		t.Fatalf("flagged page = %+v", page)
	}
	if page = list("&sort=from&dir=asc&limit=1"); len(page.Items) != 1 || page.Items[0].ID != flagged.ID || page.NextCursor != "1" {
		t.Fatalf("sorted page = %+v", page)
	}
	for _, invalid := range []string{"&filter=spam", "&sort=priority", "&dir=up", "&limit=0", "&cursor=1&around_item_id=x"} {
		response, err := client.Get(server.URL + "/api/v1/workspace/mail/list?folder_id=" + url.QueryEscape(inbox) + invalid)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status=%d, want 400", invalid, response.StatusCode)
		}
	}

	unreadCounts := func() map[string]int64 {
		response, err := client.Get(server.URL + "/api/v1/workspace/folders?include=unread")
		if err != nil {
			t.Fatal(err)
		}
		folders := decodeTestJSON[[]workspaceFolder](t, response)
		counts := map[string]int64{}
		for _, folder := range folders {
			if folder.UnreadCount != nil {
				counts[folder.ID] = *folder.UnreadCount
			} else if folder.Type == model.FolderTypeMail {
				t.Fatalf("mail folder %s has no unread count", folder.Path)
			}
		}
		return counts
	}
	if counts := unreadCounts(); counts[inbox] != 1 {
		t.Fatalf("unread counts = %v", counts)
	}
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, `{"item_ids":["`+toMe.ID+`"],"action":"mark_read"}`)
	_ = response.Body.Close()
	if counts := unreadCounts(); counts[inbox] != 0 {
		t.Fatalf("unread counts after read = %v", counts)
	}
	plain, err := client.Get(server.URL + "/api/v1/workspace/folders")
	if err != nil {
		t.Fatal(err)
	}
	for _, folder := range decodeTestJSON[[]workspaceFolder](t, plain) {
		if folder.UnreadCount != nil {
			t.Fatal("unread counts must be opt-in so other workspaces do not pay for them")
		}
	}
}

func TestWorkspaceMailListRequiresItemReadAccess(t *testing.T) {
	handler, ts := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	loginExistingUser(t, bob, server.URL, "bob")
	response, err := bob.Get(server.URL + "/api/v1/workspace/mail/list?folder_id=" + url.QueryEscape(model.InboxFolderID("alice")))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound && response.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign mailbox list status=%d", response.StatusCode)
	}
}

func TestWorkspaceItemActionsArchiveJunkAndBlockSender(t *testing.T) {
	handler, ts := testHandler(t)
	trainer := &recordingContentTrainer{}
	handler.ConfigureContentTrainer(trainer)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	inbox := model.InboxFolderID("alice")
	base := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	keep := seedMail(t, handler, inbox, "From: Pat <pat@example.net>\nSubject: Keep\n\nbody\n", base)
	spam := seedMail(t, handler, inbox, "From: \"Spammer\" <Offers@Spam.example>\nSubject: Win\n\nbuy\n", base.Add(time.Minute))
	folders, err := ts.FolderStore().ListForUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	special := map[string]string{}
	for _, folder := range folders {
		special[folder.SpecialUse] = folder.ID
	}
	act := func(action string, ids ...string) map[string]any {
		body, _ := json.Marshal(map[string]any{"item_ids": ids, "action": action})
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, string(body))
		return decodeTestJSON[map[string]any](t, response)
	}
	folderOf := func(id string) string {
		item, err := ts.ItemStore().GetMetadata(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		return item.FolderID
	}

	act("archive", keep.ID)
	if folderOf(keep.ID) != special[model.SpecialUseArchive] {
		t.Fatalf("archived message is in %s", folderOf(keep.ID))
	}
	act("archive", keep.ID) // already archived: a no-op, not an error
	if folderOf(keep.ID) != special[model.SpecialUseArchive] {
		t.Fatal("re-archiving must leave the message in Archive")
	}

	result := act("junk", spam.ID)
	if folderOf(spam.ID) != special[model.SpecialUseJunk] || trainer.calls != 1 || !trainer.spam || result["trained"] != float64(1) {
		t.Fatalf("junk: folder=%s trainer=%+v result=%v", folderOf(spam.ID), trainer, result)
	}
	act("not_junk", spam.ID)
	if folderOf(spam.ID) != inbox || trainer.calls != 2 || trainer.spam {
		t.Fatalf("not junk: folder=%s trainer=%+v", folderOf(spam.ID), trainer)
	}
	result = act("block_sender", spam.ID)
	blocked, err := ts.UserStore().ReadSpamListEntries(t.Context(), "alice", model.SpamListBlock)
	if err != nil {
		t.Fatal(err)
	}
	if folderOf(spam.ID) != special[model.SpecialUseJunk] || len(blocked) != 1 || blocked[0].Value != "offers@spam.example" {
		t.Fatalf("block sender: folder=%s blocked=%+v result=%v", folderOf(spam.ID), blocked, result)
	}
	if senders, _ := result["blocked_senders"].([]any); len(senders) != 1 || senders[0] != "offers@spam.example" {
		t.Fatalf("block sender response = %v", result)
	}
}
