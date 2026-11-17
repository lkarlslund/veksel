package app

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestWorkspaceMailConversationsGroupThreadsAndScopeActions(t *testing.T) {
	handler, ts := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	inbox, sent := model.InboxFolderID("alice"), model.SentFolderID("alice")
	base := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	root := seedMail(t, handler, inbox, "From: Bob <bob@example.net>\nMessage-Id: <root@example.net>\nSubject: Offsite\n\nwhere?\n", base)
	answer := seedMail(t, handler, sent, "From: Alice <alice@example.test>\nMessage-Id: <answer@example.test>\nIn-Reply-To: <root@example.net>\nSubject: Re: Offsite\n\nthe lake\n", base.Add(time.Hour), model.FlagSeen)
	chained := seedMail(t, handler, inbox, "From: Bob <bob@example.net>\nMessage-Id: <chain@example.net>\nReferences: <root@example.net> <answer@example.test>\nSubject: Re: Offsite\n\ngreat\n", base.Add(2*time.Hour))
	orphanA := seedMail(t, handler, inbox, "From: Dan <dan@example.net>\nMessage-Id: <o1@example.net>\nIn-Reply-To: <gone@example.net>\nSubject: Re: Minutes\n\nfirst\n", base.Add(3*time.Hour))
	orphanB := seedMail(t, handler, inbox, "From: Eve <eve@example.net>\nMessage-Id: <o2@example.net>\nReferences: <gone@example.net>\nSubject: Re: Minutes\n\nsecond\n", base.Add(4*time.Hour))
	budget := seedMail(t, handler, inbox, "From: Fay <fay@example.net>\nMessage-Id: <budget@example.net>\nSubject: Budget\n\ndraft\n", base.Add(-24*time.Hour), model.FlagSeen)
	headerless := seedMail(t, handler, inbox, "From: Gus <gus@example.net>\nSubject: RE: Budget\n\nlooks fine\n", base.Add(5*time.Hour))
	stale := seedMail(t, handler, inbox, "From: Gus <gus@example.net>\nSubject: Re: Budget\n\nnext year\n", base.AddDate(0, 3, 0))

	list := func(query string) mailindex.Page {
		t.Helper()
		response, err := client.Get(server.URL + "/api/v1/workspace/mail/list?view=conversations&folder_id=" + url.QueryEscape(inbox) + query)
		if err != nil {
			t.Fatal(err)
		}
		return decodeTestJSON[mailindex.Page](t, response)
	}
	page := list("")
	members := func(row mailindex.Summary) []string { return slices.Sorted(slices.Values(row.Conversation.ItemIDs)) }
	sorted := func(ids ...string) []string { return slices.Sorted(slices.Values(ids)) }
	if page.Total != 4 || page.FolderSize != 7 || len(page.Items) != 4 {
		t.Fatalf("conversation page = %+v", page)
	}
	want := [][]string{{stale.ID}, {budget.ID, headerless.ID}, {orphanA.ID, orphanB.ID}, {root.ID, chained.ID}}
	for n, row := range page.Items {
		if !slices.Equal(members(row), sorted(want[n]...)) {
			t.Fatalf("row %d members = %v, want %v", n, members(row), sorted(want[n]...))
		}
	}
	offsite := page.Items[3]
	if offsite.ID != chained.ID || offsite.Conversation.Count != 3 || offsite.Conversation.Unread != 2 || len(offsite.Conversation.Messages) != 3 || offsite.Conversation.Messages[1].ID != answer.ID || offsite.Conversation.Messages[1].FolderID != sent {
		t.Fatalf("cross-folder conversation = %+v", offsite.Conversation)
	}
	if plain := decodeTestJSON[mailindex.Page](t, mustGet(t, client, server.URL+"/api/v1/workspace/mail/list?folder_id="+url.QueryEscape(inbox))); plain.Total != 7 || plain.Items[0].Conversation != nil {
		t.Fatalf("message view = %+v", plain)
	}
	response := mustGet(t, client, server.URL+"/api/v1/workspace/mail/list?view=threads&folder_id="+url.QueryEscape(inbox))
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown view status=%d", response.StatusCode)
	}

	act := func(action string, conversations ...string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"conversation_ids": conversations, "folder_id": inbox, "action": action})
		return decodeTestJSON[map[string]any](t, authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, string(body)))
	}
	if result := act("mark_read", page.Items[2].Conversation.ID); result["count"] != float64(2) {
		t.Fatalf("mark conversation read = %v", result)
	}
	folders, err := ts.FolderStore().ListForUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	archive := ""
	for _, folder := range folders {
		if folder.SpecialUse == model.SpecialUseArchive {
			archive = folder.ID
		}
	}
	act("archive", offsite.Conversation.ID)
	for id, folder := range map[string]string{root.ID: archive, chained.ID: archive, answer.ID: sent} {
		item, err := ts.ItemStore().GetMetadata(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if item.FolderID != folder {
			t.Fatalf("item %s in %s, want %s: conversation actions stay within the listed folder", id, item.FolderID, folder)
		}
	}
	page = list("")
	if page.Total != 3 || page.Items[2].Conversation.Unread != 0 {
		t.Fatalf("after conversation actions = %+v", page.Items)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf, `{"conversation_ids":["conv-unknown"],"folder_id":"`+inbox+`","action":"mark_read"}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown conversation status=%d", response.StatusCode)
	}
}

func mustGet(t *testing.T, client *http.Client, target string) *http.Response {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
