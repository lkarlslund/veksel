package mailindex

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type countingSpace struct {
	*service.FolderSpaceService
	fullPages int
}

func (s *countingSpace) ListItemPage(ctx context.Context, access service.AccessContext, folderID string, query service.ItemPageQuery) (service.ItemPage, error) {
	if query.IncludeData {
		s.fullPages++
	}
	return s.FolderSpaceService.ListItemPage(ctx, access, folderID, query)
}

func testSpace(t *testing.T) (*countingSpace, store.Store, service.AccessContext, model.Folder) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	space := &countingSpace{FolderSpaceService: service.NewFolderSpace(ts, authz.New(ts))}
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if !inbox.HasIndex(model.MailListIndex, listVersion) || !inbox.HasIndex(model.MailUnseenIndex, unseenVersion) {
		t.Fatalf("mail folders must declare the mail indexes: %+v", inbox.Indexes)
	}
	return space, backend, access, inbox
}

func deliver(t *testing.T, space service.FolderSpace, access service.AccessContext, folderID, message string, date time.Time, flags ...string) model.Item {
	t.Helper()
	item, err := space.CreateItem(t.Context(), access, folderID, service.ItemInput{Data: []byte(strings.ReplaceAll(message, "\n", "\r\n")), InternalDate: date, Flags: flags})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestListProjectsPreviewMarksFiltersAndSorts(t *testing.T) {
	space, backend, access, inbox := testSpace(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	plain := deliver(t, space, access, inbox.ID, "From: Zed <zed@example.test>\nTo: alice@example.test\nSubject: Re: Lunch\nImportance: high\n\nLet's   meet\nat noon "+strings.Repeat("tomorrow ", 30)+"\n", base)
	html := deliver(t, space, access, inbox.ID, "From: Bob <bob@example.test>\nTo: team@example.test\nSubject: Agenda\nContent-Type: text/html\n\n<p>Hello <b>team</b></p><script>x()</script>\n", base.Add(time.Hour), model.FlagSeen, model.FlagFlagged)
	attached := deliver(t, space, access, inbox.ID, "From: amy@example.test\nCc: Alice <ALICE@example.test>\nSubject: Report\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nSee attached.\n--b\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=report.pdf\n\nJVBERi0=\n--b--\n", base.Add(2*time.Hour), model.FlagSeen, model.FlagAnswered)

	index := New(backend)
	page, err := index.List(t.Context(), space, access, inbox, Query{Sort: SortDate, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || page.FolderSize != 3 || page.Unread != 1 || len(page.Items) != 3 {
		t.Fatalf("unexpected page totals: %+v", page)
	}
	if page.Items[0].ID != attached.ID || page.Items[2].ID != plain.ID {
		t.Fatalf("default order must be newest first: %v", []string{page.Items[0].ID, page.Items[1].ID, page.Items[2].ID})
	}
	first := page.Items[2]
	if !strings.HasPrefix(first.Preview, "Let's meet at noon tomorrow") || !strings.HasSuffix(first.Preview, "…") || len([]rune(first.Preview)) != PreviewRunes+1 {
		t.Fatalf("plain preview = %q", first.Preview)
	}
	if first.Headers["Importance"] != "high" || first.Headers["Subject"] != "Re: Lunch" || first.HasAttachments {
		t.Fatalf("plain projection = %+v", first)
	}
	if page.Items[1].Preview != "Hello team" {
		t.Fatalf("html preview = %q", page.Items[1].Preview)
	}
	if !page.Items[0].HasAttachments || page.Items[0].Preview != "See attached." {
		t.Fatalf("attachment projection = %+v", page.Items[0])
	}

	for _, tc := range []struct {
		query Query
		want  []string
	}{
		{Query{Filter: FilterUnread}, []string{plain.ID}},
		{Query{Filter: FilterFlagged}, []string{html.ID}},
		{Query{Filter: FilterAttachments}, []string{attached.ID}},
		{Query{Filter: FilterToMe, Addresses: []string{"alice@example.test"}}, []string{attached.ID, plain.ID}},
		{Query{Sort: SortFrom, Ascending: true}, []string{attached.ID, html.ID, plain.ID}},
		{Query{Sort: SortSubject, Ascending: true}, []string{html.ID, plain.ID, attached.ID}},
		{Query{Sort: SortSize}, []string{plain.ID, attached.ID, html.ID}},
		{Query{Sort: SortDate, Ascending: true}, []string{plain.ID, html.ID, attached.ID}},
	} {
		tc.query.Limit = 50
		got, err := index.List(t.Context(), space, access, inbox, tc.query)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(got.Items))
		for _, item := range got.Items {
			ids = append(ids, item.ID)
		}
		if strings.Join(ids, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%+v = %v, want %v", tc.query, ids, tc.want)
		}
	}

	paged, err := index.List(t.Context(), space, access, inbox, Query{Limit: 2})
	if err != nil || len(paged.Items) != 2 || paged.NextCursor != "2" {
		t.Fatalf("first page = %+v, %v", paged, err)
	}
	rest, err := index.List(t.Context(), space, access, inbox, Query{Limit: 2, Cursor: paged.NextCursor})
	if err != nil || len(rest.Items) != 1 || rest.NextCursor != "" || rest.Items[0].ID != plain.ID {
		t.Fatalf("second page = %+v, %v", rest, err)
	}
	around, err := index.List(t.Context(), space, access, inbox, Query{Limit: 2, AroundItemID: plain.ID})
	if err != nil || around.Offset != 1 || around.Items[len(around.Items)-1].ID != plain.ID {
		t.Fatalf("around window = %+v, %v", around, err)
	}
}

func TestProjectionsCatchUpWithoutReparsingTheFolder(t *testing.T) {
	space, backend, access, inbox := testSpace(t)
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	first := deliver(t, space, access, inbox.ID, "From: a@example.test\nSubject: one\n\nfirst body\n", base)
	deliver(t, space, access, inbox.ID, "From: b@example.test\nSubject: two\n\nsecond body\n", base.Add(time.Minute))
	index := New(backend)
	folder := func() model.Folder {
		current, err := space.GetFolder(t.Context(), access, inbox.ID)
		if err != nil {
			t.Fatal(err)
		}
		return current
	}
	unseen, err := index.Unseen(t.Context(), space, access, folder(), folderindex.PriorityFolder)
	if err != nil || unseen != 2 {
		t.Fatalf("unseen = %d, %v", unseen, err)
	}
	if space.fullPages != 0 {
		t.Fatalf("unread counts must enumerate metadata only, read %d payload pages", space.fullPages)
	}
	if _, err := index.List(t.Context(), space, access, folder(), Query{Limit: 10}); err != nil {
		t.Fatal(err)
	}
	built := space.fullPages
	if _, err := space.SetFlags(t.Context(), access, first.ID, []string{model.FlagSeen, model.FlagFlagged}); err != nil {
		t.Fatal(err)
	}
	deliver(t, space, access, inbox.ID, "From: c@example.test\nSubject: three\n\nthird body\n", base.Add(2*time.Minute))
	if unseen, err = index.Unseen(t.Context(), space, access, folder(), folderindex.PriorityFolder); err != nil || unseen != 2 {
		t.Fatalf("unseen after read + delivery = %d, %v", unseen, err)
	}
	page, err := index.List(t.Context(), space, access, folder(), Query{Filter: FilterFlagged, Limit: 10})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != first.ID || page.Items[0].Preview != "first body" || page.FolderSize != 3 {
		t.Fatalf("flagged after catch-up = %+v, %v", page, err)
	}
	if space.fullPages != built {
		t.Fatalf("catch-up re-enumerated the folder: %d payload pages, want %d", space.fullPages, built)
	}
	trash, err := space.GetFolderByPath(t.Context(), access, "Trash")
	if err != nil {
		t.Fatal(err)
	}
	trashPage, err := index.List(t.Context(), space, access, trash, Query{Limit: 10})
	if err != nil || len(trashPage.Items) != 0 {
		t.Fatalf("empty trash = %+v, %v", trashPage, err)
	}
	if _, err := space.TrashItem(t.Context(), access, first.ID); err != nil {
		t.Fatal(err)
	}
	if page, err = index.List(t.Context(), space, access, folder(), Query{Limit: 10}); err != nil || page.Total != 2 {
		t.Fatalf("inbox after trash = %+v, %v", page, err)
	}
	trashFolder, _ := space.GetFolder(t.Context(), access, trash.ID)
	if trashPage, err = index.List(t.Context(), space, access, trashFolder, Query{Limit: 10}); err != nil || len(trashPage.Items) != 1 || trashPage.Items[0].ID != first.ID {
		t.Fatalf("trash after trash = %+v, %v", trashPage, err)
	}
}

func TestParseFilterAndSort(t *testing.T) {
	if filter, err := ParseFilter("all"); err != nil || filter != FilterAll {
		t.Fatalf("all = %q, %v", filter, err)
	}
	if _, err := ParseFilter("spam"); err == nil {
		t.Fatal("unknown filters must be rejected")
	}
	if sortKey, err := ParseSort(""); err != nil || sortKey != SortDate {
		t.Fatalf("default sort = %q, %v", sortKey, err)
	}
	if _, err := ParseSort("priority"); err == nil {
		t.Fatal("unknown sort keys must be rejected")
	}
}

func TestProjectDecodesStoredEncodedWords(t *testing.T) {
	item := model.Item{Headers: map[string]string{"Subject": "Re: Tilbud =?utf-8?q?p=C3=A5?= tagrenovering", "From": "Anders =?utf-8?q?Kj=C3=A6r?= <anders@example.test>"}}
	got := project(item).Headers
	if got["Subject"] != "Re: Tilbud på tagrenovering" || got["From"] != "Anders Kjær <anders@example.test>" {
		t.Fatalf("headers %q", got)
	}
}
