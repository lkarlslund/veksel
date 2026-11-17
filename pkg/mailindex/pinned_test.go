package mailindex

import (
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestPinnedMessagesLeadDateSortedLists(t *testing.T) {
	space, backend, access, inbox := testSpace(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	old := deliver(t, space, access, inbox.ID, "From: a@example.test\nSubject: Old pinned\n\nx\n", base, model.KeywordPinned)
	middle := deliver(t, space, access, inbox.ID, "From: b@example.test\nSubject: Middle\n\nx\n", base.Add(time.Hour))
	newest := deliver(t, space, access, inbox.ID, "From: c@example.test\nSubject: Newest\n\nx\n", base.Add(2*time.Hour))
	reply := deliver(t, space, access, inbox.ID, "From: d@example.test\nSubject: Re: Old pinned\n\nx\n", base.Add(3*time.Hour))
	index := New(backend)
	order := func(query Query) string {
		t.Helper()
		query.Limit = 50
		page, err := index.List(t.Context(), space, access, inbox, query)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(page.Items))
		for _, item := range page.Items {
			ids = append(ids, item.ID)
		}
		return strings.Join(ids, ",")
	}
	if got, want := order(Query{Sort: SortDate}), strings.Join([]string{old.ID, reply.ID, newest.ID, middle.ID}, ","); got != want {
		t.Fatalf("newest-first with pin = %s, want %s", got, want)
	}
	if got, want := order(Query{Sort: SortDate, Ascending: true}), strings.Join([]string{old.ID, middle.ID, newest.ID, reply.ID}, ","); got != want {
		t.Fatalf("oldest-first with pin = %s, want %s", got, want)
	}
	// Other sort keys ignore pins.
	if got, want := order(Query{Sort: SortFrom, Ascending: true}), strings.Join([]string{old.ID, middle.ID, newest.ID, reply.ID}, ","); got != want {
		t.Fatalf("from sort = %s, want %s", got, want)
	}
	// A conversation with a pinned listed message is pinned as a whole.
	page, err := index.List(t.Context(), space, access, inbox, Query{Sort: SortDate, Limit: 50, Conversations: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 || page.Items[0].Conversation == nil || !page.Items[0].Conversation.Pinned || page.Items[0].Conversation.Count != 2 {
		t.Fatalf("conversation rows = %+v", page.Items)
	}
}
