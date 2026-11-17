package mailindex

import (
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestConversationsTrackThreadsIncrementallyAcrossFolders(t *testing.T) {
	space, backend, access, inbox := testSpace(t)
	sent, err := space.GetFolderByPath(t.Context(), access, "Sent")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	original := deliver(t, space, access, inbox.ID, "From: Bob <bob@example.test>\nMessage-Id: <A@example.test>\nSubject: Plan\n\nfirst\n", base)
	index := New(backend)
	current := func(id string) model.Folder {
		folder, err := space.GetFolder(t.Context(), access, id)
		if err != nil {
			t.Fatal(err)
		}
		return folder
	}
	list := func(query Query) Page {
		t.Helper()
		query.Conversations, query.Related = true, []model.Folder{current(sent.ID)}
		if query.Limit == 0 {
			query.Limit = 50
		}
		page, err := index.List(t.Context(), space, access, current(inbox.ID), query)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	if page := list(Query{}); page.Total != 1 || page.Items[0].Conversation.Count != 1 {
		t.Fatalf("single message conversation = %+v", page)
	}
	built := space.fullPages

	reply := deliver(t, space, access, sent.ID, "From: Alice <alice@example.test>\nMessage-Id: <r1@example.test>\nIn-Reply-To: <a@example.test>\nSubject: Re: Plan\n\nmy answer\n", base.Add(time.Hour), model.FlagSeen)
	page := list(Query{})
	conversation := page.Items[0].Conversation
	if page.Total != 1 || conversation.Count != 2 || len(conversation.ItemIDs) != 1 || conversation.ItemIDs[0] != original.ID {
		t.Fatalf("cross-folder reply = %+v", conversation)
	}
	if conversation.Messages[0].ID != reply.ID || conversation.Messages[0].FolderID != sent.ID || conversation.Preview != "my answer" || strings.Join(conversation.Participants, ",") != "Alice,Bob" || conversation.Unread != 1 {
		t.Fatalf("conversation summary = %+v", conversation)
	}
	firstID := conversation.ID

	followUp := deliver(t, space, access, inbox.ID, "From: Bob <bob@example.test>\nMessage-Id: <f@example.test>\nReferences: <a@example.test> <r1@example.test>\nSubject: Re: Plan\n\nthanks\n", base.Add(2*time.Hour), model.FlagSeen, model.FlagFlagged)
	unrelated := deliver(t, space, access, inbox.ID, "From: Carol <carol@example.test>\nMessage-Id: <u@example.test>\nSubject: Lunch\n\nnoon?\n", base.Add(90*time.Minute), model.FlagSeen)
	page = list(Query{})
	if page.Total != 2 || page.FolderSize != 3 || page.Items[0].ID != followUp.ID || page.Items[1].ID != unrelated.ID {
		t.Fatalf("conversation rows = %+v", page.Items)
	}
	conversation = page.Items[0].Conversation
	if conversation.ID != firstID || conversation.Count != 3 || strings.Join(conversation.ItemIDs, ",") != followUp.ID+","+original.ID || !conversation.Flagged {
		t.Fatalf("grown conversation = %+v", conversation)
	}
	if space.fullPages != built {
		t.Fatalf("thread keys must be maintained from the change journal: %d payload pages, want %d", space.fullPages, built)
	}
	if page = list(Query{Filter: FilterUnread}); page.Total != 1 || page.Items[0].ID != followUp.ID {
		t.Fatalf("unread conversation filter = %+v", page.Items)
	}
	if page = list(Query{AroundItemID: original.ID, Limit: 1}); len(page.Items) != 1 || page.Items[0].ID != followUp.ID {
		t.Fatalf("around a non-representative member = %+v", page.Items)
	}
	// Removing the root keeps the replies together through their shared
	// ancestor IDs.
	if _, err := space.TrashItem(t.Context(), access, original.ID); err != nil {
		t.Fatal(err)
	}
	if page = list(Query{}); page.Total != 2 || page.Items[0].Conversation.Count != 2 || page.Items[0].Conversation.ID != firstID {
		t.Fatalf("after trashing the root = %+v", page.Items[0].Conversation)
	}
	if plain, err := index.List(t.Context(), space, access, current(inbox.ID), Query{Limit: 50}); err != nil || plain.Total != 2 || plain.Items[0].Conversation != nil {
		t.Fatalf("message mode = %+v, %v", plain, err)
	}
}
