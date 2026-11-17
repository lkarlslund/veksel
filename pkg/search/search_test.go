package search

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type pagedIndexSpace struct {
	service.FolderSpace
	pages     map[uint32]service.ItemPage
	pageCalls int
	listCalls int
	limits    []int
}

func (s *pagedIndexSpace) ListItemPage(_ context.Context, _ service.AccessContext, _ string, query service.ItemPageQuery) (service.ItemPage, error) {
	s.pageCalls++
	s.limits = append(s.limits, query.Limit)
	if !query.IncludeData {
		return service.ItemPage{}, errors.New("index rebuild requested metadata-only page")
	}
	return s.pages[query.BeforeUID], nil
}

func (s *pagedIndexSpace) ListItems(context.Context, service.AccessContext, string, service.ItemQuery) ([]model.Item, error) {
	s.listCalls++
	return nil, errors.New("unbounded item listing must not be used")
}

func TestIndexRebuildEnumeratesFolderPayloadsInBoundedPages(t *testing.T) {
	space := &pagedIndexSpace{pages: map[uint32]service.ItemPage{
		0: {Items: []model.Item{{ID: "5"}, {ID: "4"}}, NextBeforeUID: 4},
		4: {Items: []model.Item{{ID: "3"}, {ID: "2"}}, NextBeforeUID: 2},
		2: {Items: []model.Item{{ID: "1"}}},
	}}
	var ids []string
	err := forEachFolderItem(t.Context(), space, service.UserAccess("alice", "test"), "folder", 2, func(items []model.Item) error {
		for _, item := range items {
			ids = append(ids, item.ID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ids, ","); got != "5,4,3,2,1" {
		t.Fatalf("visited IDs = %q", got)
	}
	if space.pageCalls != 3 || space.listCalls != 0 {
		t.Fatalf("listing calls = %d paged, %d unbounded; want 3, 0", space.pageCalls, space.listCalls)
	}
	for _, limit := range space.limits {
		if limit != 2 {
			t.Fatalf("page limit = %d, want 2", limit)
		}
	}
}

func TestIndexRebuildCapsPagesAtPagerLimit(t *testing.T) {
	space := &pagedIndexSpace{pages: map[uint32]service.ItemPage{0: {Items: []model.Item{{ID: "1"}}}}}
	// The default search_batch_size (256) exceeds the pager's maximum.
	if err := forEachFolderItem(t.Context(), space, service.UserAccess("alice", "test"), "folder", 256, func([]model.Item) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(space.limits) != 1 || space.limits[0] != service.MaxItemPageLimit {
		t.Fatalf("page limits = %v, want [%d]", space.limits, service.MaxItemPageLimit)
	}
}

func TestIndexRebuildRejectsNonAdvancingFolderPage(t *testing.T) {
	space := &pagedIndexSpace{pages: map[uint32]service.ItemPage{
		0: {Items: []model.Item{{ID: "2"}}, NextBeforeUID: 2},
		2: {Items: []model.Item{{ID: "2"}}, NextBeforeUID: 2},
	}}
	err := forEachFolderItem(t.Context(), space, service.UserAccess("alice", "test"), "folder", 1, func([]model.Item) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("non-advancing page error = %v", err)
	}
}

func TestExtractMailMIMEAndHTML(t *testing.T) {
	attachmentBody := base64.StdEncoding.EncodeToString([]byte("attachment-only marker"))
	raw := strings.Join([]string{
		"From: =?UTF-8?Q?Alice_=C3=86gir?= <alice@example.test>",
		"To: Bob <bob@example.test>",
		"Subject: =?UTF-8?Q?Quarterly_=E2=9C=93?=",
		"Content-Type: multipart/mixed; boundary=parts", "", "--parts",
		"Content-Type: text/html; charset=utf-8", "", "<p>Important <b>needle</b></p><script>secret()</script>",
		"--parts", "Content-Type: application/pdf; name=report.pdf",
		"Content-Disposition: attachment; filename=report.pdf", "", "ignored",
		"--parts", "Content-Type: text/plain; charset=utf-8; name=notes.txt",
		"Content-Disposition: attachment; filename=notes.txt", "Content-Transfer-Encoding: base64", "", attachmentBody,
		"--parts--", "",
	}, "\r\n")
	doc := extract(model.Folder{ID: "alice:INBOX", Name: "INBOX", Type: model.FolderTypeMail}, model.Item{ID: "i1", FolderID: "alice:INBOX", Data: []byte(raw)}, 0)
	if doc.Subject != "Quarterly ✓" || !strings.Contains(doc.Sender, "Alice Ægir") {
		t.Fatalf("headers not decoded: %+v", doc)
	}
	if !strings.Contains(doc.Content, "Important needle") || strings.Contains(doc.Content, "secret") {
		t.Fatalf("HTML text = %q", doc.Content)
	}
	if doc.Attachment != "report.pdf notes.txt" {
		t.Fatalf("attachment = %q", doc.Attachment)
	}
	if doc.AttachmentText != "attachment-only marker" || strings.Contains(doc.Content, "attachment-only") {
		t.Fatalf("body = %q, attachment text = %q", doc.Content, doc.AttachmentText)
	}
	if !doc.HasAttachment {
		t.Fatal("attachment presence was not extracted")
	}
}

func TestAttachmentExtractionIsBoundedAndRejectsBinary(t *testing.T) {
	text := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 256)))
	raw := strings.Join([]string{
		"Content-Type: multipart/mixed; boundary=parts", "", "--parts",
		"Content-Type: text/plain", "", "body", "--parts",
		"Content-Type: text/plain; name=large.txt", "Content-Disposition: attachment; filename=large.txt",
		"Content-Transfer-Encoding: base64", "", text, "--parts--", "",
	}, "\r\n")
	doc := extract(model.Folder{ID: "inbox", Type: model.FolderTypeMail}, model.Item{ID: "i1", FolderID: "inbox", Data: []byte(raw)}, 32)
	if !doc.Truncated || len(doc.Content)+len(doc.AttachmentText) > 32 || !strings.HasPrefix(doc.AttachmentText, "aaa") {
		t.Fatalf("bounded document = body %q attachment %q truncated=%v", doc.Content, doc.AttachmentText, doc.Truncated)
	}
	binary := "Content-Type: text/plain; name=fake.txt\r\nContent-Disposition: attachment; filename=fake.txt\r\n\r\ntext\x00binary"
	doc = extract(model.Folder{ID: "inbox", Type: model.FolderTypeMail}, model.Item{ID: "i2", FolderID: "inbox", Data: []byte(binary)}, 128)
	if doc.AttachmentText != "" || !doc.HasAttachment {
		t.Fatalf("binary attachment projection = %+v", doc)
	}
}

func TestSearchConfigDefaultsToBoundedExtraction(t *testing.T) {
	config := (Config{}).normalized()
	if config.MaxExtractedBytes != 1<<20 {
		t.Fatalf("default extracted bytes = %d, want %d", config.MaxExtractedBytes, 1<<20)
	}
}

func TestSearchableFolderTypesExcludeAccountControlMetadata(t *testing.T) {
	for _, folderType := range []model.FolderType{
		model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts,
		model.FolderTypeFiles, model.FolderTypeNotes,
	} {
		if !searchableFolderType(folderType) {
			t.Fatalf("ordinary item folder %q is not searchable", folderType)
		}
	}
	for _, folderType := range []model.FolderType{
		model.FolderTypeSavedSearch, model.FolderTypeMailTemplate, model.FolderTypeSieve,
		model.FolderTypeScheduleInbox, model.FolderTypeScheduleOutbox,
	} {
		if searchableFolderType(folderType) {
			t.Fatalf("control/protocol folder %q entered the user content index", folderType)
		}
	}
}

func TestExtractContactProvidesNormalizedSortFields(t *testing.T) {
	data := model.ContactToVCard(model.Contact{
		FN: "Zoë Ångström", Org: "Example Labs", Emails: []string{"ZOE@Example.Test"}, Phones: []string{"+45 12 34"}, PhotoData: []byte{1, 2, 3}, PhotoType: "PNG",
	})
	doc := extract(model.Folder{ID: "contacts", Name: "Contacts", Type: model.FolderTypeContacts}, model.Item{ID: "c1", FolderID: "contacts", Data: data}, 0)
	if doc.Name != "Zoë Ångström" || doc.Title != "Zoë Ångström" || doc.ContactName != "zoë ångström" || doc.ContactOrg != "example labs" || doc.ContactEmail != "zoe@example.test" || doc.ContactPhone != "+45 12 34" || doc.ContactOrgView != "Example Labs" || doc.ContactPhoneView != "+45 12 34" || !doc.ContactHasPhoto {
		t.Fatalf("contact document = %+v", doc)
	}
	if !strings.Contains(doc.Content, "ZOE@Example.Test") {
		t.Fatalf("contact content = %q", doc.Content)
	}
	if doc.ContactSuggest != "Zoë Ångström  Example Labs ZOE@Example.Test" {
		t.Fatalf("contact suggestion projection = %q", doc.ContactSuggest)
	}
}

func TestExtractContactGroupProjectsKindAndMemberCount(t *testing.T) {
	t.Parallel()
	data := model.ContactToVCard(model.Contact{FN: "Project team", Kind: "group", Members: []string{"mailto:a@example.test", "urn:uuid:b"}})
	doc := extract(model.Folder{ID: "contacts", Name: "Contacts", Type: model.FolderTypeContacts}, model.Item{ID: "group-1", FolderID: "contacts", Data: data}, 0)
	if doc.ContactKind != "group" || doc.ContactMembers != 2 || doc.Name != "Project team" || !strings.Contains(doc.Content, "mailto:a@example.test") {
		t.Fatalf("contact group document = %+v", doc)
	}
}

func TestSearchQueryComplexityLimits(t *testing.T) {
	root := service.SearchFilter{Operator: service.SearchNot}
	cursor := &root
	for range 17 {
		cursor.Children = []service.SearchFilter{{Operator: service.SearchNot}}
		cursor = &cursor.Children[0]
	}
	if err := validateSearchQuery(service.SearchQuery{Filter: &root}); err == nil {
		t.Fatal("overly deep filter was accepted")
	}
	if err := validateSearchQuery(service.SearchQuery{Text: strings.Repeat("x", (16<<10)+1)}); err == nil {
		t.Fatal("oversized query was accepted")
	}
	if err := validateSearchQuery(service.SearchQuery{AccountID: strings.Repeat("a", 321)}); err == nil {
		t.Fatal("oversized account identity was accepted")
	}
	if err := validateSearchQuery(service.SearchQuery{FolderIDs: []string{strings.Repeat("f", 1025)}}); err == nil {
		t.Fatal("oversized folder identity was accepted")
	}
	if err := validateSearchQuery(service.SearchQuery{Filter: &service.SearchFilter{Operator: service.SearchEquals, Field: strings.Repeat("f", 129), Value: "x"}}); err == nil {
		t.Fatal("oversized filter field was accepted")
	}
}

func TestBleveSearchOwnerAndSeparateRBACGrant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	system := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := system.EnsureNamespace(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}
	accounts, err := account.NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	for _, login := range []string{"alice", "bob"} {
		displayName := strings.ToUpper(login[:1]) + login[1:]
		if err := system.UserStore().Create(ctx, login, displayName, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := system.FolderStore().CreateForUser(ctx, login); err != nil {
			t.Fatal(err)
		}
		user, _ := system.UserStore().Get(ctx, login)
		if _, _, err := accounts.Ensure(ctx, user, login+"@example.test", nil); err != nil {
			t.Fatal(err)
		}
	}
	engine := authz.New(system)
	routed, err := service.NewAccountFolderSpace(ctx, system, accounts, engine)
	if err != nil {
		t.Fatal(err)
	}
	durable, err := service.NewDurableFolderSpace(ctx, backend, routed)
	if err != nil {
		t.Fatal(err)
	}
	item, err := durable.CreateItem(ctx, service.UserAccess("alice", "test"), model.InboxFolderID("alice"), service.ItemInput{Data: []byte("From: sender@example.test\r\nSubject: Hidden project\r\n\r\nunique-needle body")})
	if err != nil {
		t.Fatal(err)
	}
	attachmentMessage := strings.Join([]string{
		"From: sender@example.test", "Subject: Attachment search", "Content-Type: multipart/mixed; boundary=x", "", "--x",
		"Content-Type: text/plain", "", "ordinary body", "--x", "Content-Type: text/plain; name=notes.txt",
		"Content-Disposition: attachment; filename=notes.txt", "", "deep-attachment-marker", "--x--", "",
	}, "\r\n")
	attachmentItem, err := durable.CreateItem(ctx, service.UserAccess("alice", "test"), model.InboxFolderID("alice"), service.ItemInput{Data: []byte(attachmentMessage)})
	if err != nil {
		t.Fatal(err)
	}
	contactsFolder := model.FolderKey("alice", "Contacts")
	for _, contact := range []model.Contact{
		{FN: "Grace Hopper", Org: "Navy", Emails: []string{"grace@example.test"}},
		{FN: "Ada Lovelace", Nickname: "Enchantress", Org: "Analytical Engines", Emails: []string{"ada@example.test"}, Note: "private analytical notes"},
		{FN: "Katherine Johnson", Org: "NASA", Emails: []string{"katherine@example.test"}},
	} {
		if _, err := durable.CreateItem(ctx, service.UserAccess("alice", "test"), contactsFolder, service.ItemInput{Data: model.ContactToVCard(contact)}); err != nil {
			t.Fatal(err)
		}
	}
	blocking := &blockingFolderSpace{
		FolderSpace: durable, FolderChangeReader: durable,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	manager, err := New(ctx, accounts, blocking, engine, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	waitReady(t, manager, service.UserAccess("alice", "test"), "alice")

	ownerPage, err := manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{Text: "unique-needle", Types: []model.FolderType{model.FolderTypeMail}})
	if err != nil || len(ownerPage.Hits) != 1 || ownerPage.Hits[0].ItemID != item.ID {
		t.Fatalf("owner search = %+v, %v", ownerPage, err)
	}
	if len(ownerPage.Facets.Types) != 1 || ownerPage.Facets.Types[0].Value != "mail" || ownerPage.Facets.Types[0].Count != 1 {
		t.Fatalf("type facets = %+v", ownerPage.Facets.Types)
	}
	if len(ownerPage.Facets.Folders) != 1 || ownerPage.Facets.Folders[0].Value != model.InboxFolderID("alice") || ownerPage.Facets.Folders[0].Label != "INBOX" || ownerPage.Facets.Folders[0].Count != 1 {
		t.Fatalf("folder facets = %+v", ownerPage.Facets.Folders)
	}
	expressionPage, err := manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{
		Expression: `from:sender@example.test subject:"Hidden project" body:unique-needle is:unread type:mail`,
	})
	if err != nil || len(expressionPage.Hits) != 1 || expressionPage.Hits[0].ItemID != item.ID {
		t.Fatalf("structured expression search = %+v, %v", expressionPage, err)
	}
	// A field filter must match all of its tokens: a different mailbox at the
	// same domain is not a match for from:<address>.
	if otherSender, err := manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{Expression: `from:carol@example.test`}); err != nil || len(otherSender.Hits) != 0 {
		t.Fatalf("from:carol@example.test = %+v, %v", otherSender, err)
	}
	attachmentPage, err := manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{Expression: `attachmenttext:deep-attachment-marker`})
	if err != nil || len(attachmentPage.Hits) != 1 || attachmentPage.Hits[0].ItemID != attachmentItem.ID {
		t.Fatalf("attachment text search = %+v, %v", attachmentPage, err)
	}
	filterOnlyPage, err := manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{
		Filter: &service.SearchFilter{Operator: service.SearchContains, Field: "subject", Value: "Attachment"}, Limit: 5,
	})
	if err != nil || len(filterOnlyPage.Hits) != 1 {
		t.Fatalf("filter-only search = %+v, %v", filterOnlyPage, err)
	}
	if _, err := json.Marshal(filterOnlyPage); err != nil {
		t.Fatalf("filter-only result is not JSON-safe: %v", err)
	}
	contactPage, err := manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{
		FolderIDs: []string{contactsFolder}, Types: []model.FolderType{model.FolderTypeContacts}, Sort: "contact_name", Limit: 2,
	})
	if err != nil || contactPage.Total != 3 || len(contactPage.Hits) != 2 || contactPage.Hits[0].Name != "Ada Lovelace" || contactPage.Hits[1].Name != "Grace Hopper" || contactPage.NextCursor == "" {
		t.Fatalf("first sorted contact page = %+v, %v", contactPage, err)
	}
	contactPage, err = manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{
		FolderIDs: []string{contactsFolder}, Types: []model.FolderType{model.FolderTypeContacts}, Sort: "contact_name", Limit: 2, Cursor: contactPage.NextCursor,
	})
	if err != nil || len(contactPage.Hits) != 1 || contactPage.Hits[0].Name != "Katherine Johnson" {
		t.Fatalf("second sorted contact page = %+v, %v", contactPage, err)
	}
	suggestionPage, err := manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{
		FolderIDs: []string{contactsFolder}, Types: []model.FolderType{model.FolderTypeContacts},
		Filter: &service.SearchFilter{Operator: service.SearchContains, Field: "contact_suggest", Value: "enchantress"}, Limit: 12,
	})
	if err != nil || len(suggestionPage.Hits) != 1 || suggestionPage.Hits[0].Name != "Ada Lovelace" || len(suggestionPage.Hits[0].ContactEmails) != 1 || suggestionPage.Hits[0].ContactEmails[0] != "ada@example.test" {
		t.Fatalf("contact suggestion search = %+v, %v", suggestionPage, err)
	}
	suggestionPage, err = manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{
		FolderIDs: []string{contactsFolder}, Types: []model.FolderType{model.FolderTypeContacts},
		Filter: &service.SearchFilter{Operator: service.SearchContains, Field: "contact_suggest", Value: "private analytical"}, Limit: 12,
	})
	if err != nil || len(suggestionPage.Hits) != 0 {
		t.Fatalf("private contact fields entered autocomplete index = %+v, %v", suggestionPage, err)
	}

	policies := model.NewPolicyStore(system)
	if _, err := policies.Create(ctx, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"},
		Effect:    model.EffectAllow, RoleID: authz.RoleAccountSearcher, Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	page, err := manager.Search(ctx, service.UserAccess("bob", "test"), service.SearchQuery{AccountID: "alice", Text: "unique-needle"})
	if err != nil || len(page.Hits) != 0 {
		t.Fatalf("search-only grant leaked result: %+v, %v", page, err)
	}
	if len(page.Facets.Types) != 0 || len(page.Facets.Folders) != 0 {
		t.Fatalf("search-only grant leaked facets: %+v", page.Facets)
	}
	if _, err := policies.Create(ctx, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: model.InboxFolderID("alice")},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderViewer, Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	page, err = manager.Search(ctx, service.UserAccess("bob", "test"), service.SearchQuery{AccountID: "alice", Text: "unique-needle"})
	if err != nil || len(page.Hits) != 1 {
		t.Fatalf("search plus read = %+v, %v", page, err)
	}

	before, err := manager.SearchStatus(ctx, service.UserAccess("alice", "test"), "alice")
	if err != nil {
		t.Fatal(err)
	}
	blocking.enabled.Store(true)
	if err := manager.RequestSearchRebuild(ctx, service.UserAccess("alice", "test"), "alice"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocking.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("replacement index did not start")
	}
	status, err := manager.SearchStatus(ctx, service.UserAccess("alice", "test"), "alice")
	if err != nil || !status.Rebuilding || status.State != "building" || status.ServingIndexID != before.IndexID || status.ServingDocuments != before.Documents {
		t.Fatalf("blue-green rebuild status = %+v, %v", status, err)
	}
	page, err = manager.Search(ctx, service.UserAccess("alice", "test"), service.SearchQuery{Text: "unique-needle"})
	if err != nil || len(page.Hits) != 1 {
		t.Fatalf("active index unavailable during rebuild: %+v, %v", page, err)
	}
	close(blocking.release)
	waitReady(t, manager, service.UserAccess("alice", "test"), "alice")
	after, err := manager.SearchStatus(ctx, service.UserAccess("alice", "test"), "alice")
	if err != nil || after.Rebuilding || after.IndexID == before.IndexID {
		t.Fatalf("replacement index was not promoted: before=%+v after=%+v err=%v", before, after, err)
	}
}

type blockingFolderSpace struct {
	service.FolderSpace
	service.FolderChangeReader
	enabled atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type folderCheckpointSpace struct {
	service.FolderSpace
	service.FolderChangeReader
	mu        sync.Mutex
	calls     map[string]int
	blockID   string
	blocking  atomic.Bool
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
}

type expiringCheckpointSpace struct {
	service.FolderSpace
	service.FolderChangeReader
	expireState string
	expired     atomic.Bool
}

func (s *expiringCheckpointSpace) ListChanges(ctx context.Context, access service.AccessContext, scope service.ChangeScope, state string, limit int) (service.ChangePage, error) {
	if state == s.expireState && s.expired.CompareAndSwap(false, true) {
		return service.ChangePage{}, service.ErrChangeStateExpired
	}
	return s.FolderChangeReader.ListChanges(ctx, access, scope, state, limit)
}

func newFolderCheckpointSpace(space service.FolderSpace, changes service.FolderChangeReader) *folderCheckpointSpace {
	return &folderCheckpointSpace{
		FolderSpace: space, FolderChangeReader: changes, calls: make(map[string]int),
		entered: make(chan struct{}), release: make(chan struct{}),
	}
}

func (s *folderCheckpointSpace) ListItems(ctx context.Context, access service.AccessContext, folderID string, query service.ItemQuery) ([]model.Item, error) {
	s.mu.Lock()
	s.calls[folderID]++
	s.mu.Unlock()
	if s.blocking.Load() && folderID == s.blockID {
		s.enterOnce.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.FolderSpace.ListItems(ctx, access, folderID, query)
}

func (s *folderCheckpointSpace) callCount(folderID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[folderID]
}

func (s *blockingFolderSpace) ListItems(ctx context.Context, access service.AccessContext, folderID string, query service.ItemQuery) ([]model.Item, error) {
	if s.enabled.Load() {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.FolderSpace.ListItems(ctx, access, folderID, query)
}

func TestSearchRebuildResumesCommittedFoldersAcrossRestart(t *testing.T) {
	for _, engine := range account.ProductionEngines {
		engine := engine
		t.Run(string(engine), func(t *testing.T) {
			ctx := t.Context()
			backend, err := jsonstore.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			system := model.NewTypedStore(backend, store.BackendJSON)
			for _, namespace := range model.Namespaces() {
				if err := system.EnsureNamespace(ctx, namespace); err != nil {
					t.Fatal(err)
				}
			}
			if err := system.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
				t.Fatal(err)
			}
			if err := system.FolderStore().CreateForUser(ctx, "alice"); err != nil {
				t.Fatal(err)
			}
			accountRoot := t.TempDir()
			accounts, err := account.NewManager(accountRoot, engine)
			if err != nil {
				t.Fatal(err)
			}
			defer accounts.Close()
			user, _ := system.UserStore().Get(ctx, "alice")
			if _, _, err := accounts.Ensure(ctx, user, "alice@example.test", nil); err != nil {
				t.Fatal(err)
			}
			entry, found := accounts.ByLogin("alice")
			if !found {
				t.Fatal("account was not discovered")
			}
			engineAuthz := authz.New(system)
			routed, err := service.NewAccountFolderSpace(ctx, system, accounts, engineAuthz)
			if err != nil {
				t.Fatal(err)
			}
			durable, err := service.NewDurableFolderSpace(ctx, backend, routed)
			if err != nil {
				t.Fatal(err)
			}
			access := service.UserAccess("alice", "test")
			for index := 0; index < 6; index++ {
				folder, createErr := durable.CreateFolder(ctx, access, fmt.Sprintf("Resume %02d", index), model.FolderTypeMail, "")
				if createErr != nil {
					t.Fatal(createErr)
				}
				if _, createErr = durable.CreateItem(ctx, access, folder.ID, service.ItemInput{Data: []byte(fmt.Sprintf("From: source@example.test\r\nSubject: Folder %d\r\n\r\nresume-seed-%d", index, index))}); createErr != nil {
					t.Fatal(createErr)
				}
			}
			folders, err := durable.ListFolders(ctx, access, service.FolderQuery{IncludeTrashed: true})
			if err != nil {
				t.Fatal(err)
			}
			folders = slices.DeleteFunc(folders, func(folder model.Folder) bool { return !searchableFolderType(folder.Type) })
			sort.Slice(folders, func(i, j int) bool { return folders[i].ID < folders[j].ID })
			targetIndex := -1
			completedMail := model.Folder{}
			for index := 0; index+1 < len(folders); index++ {
				if folders[index].Type == model.FolderTypeMail {
					completedMail = folders[index]
					targetIndex = index + 1
					break
				}
			}
			if targetIndex < 1 {
				t.Fatalf("searchable folder order has no resumable boundary: %+v", folders)
			}

			firstSpace := newFolderCheckpointSpace(durable, durable)
			manager, err := New(ctx, accounts, firstSpace, engineAuthz, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			waitReady(t, manager, access, "alice")
			before, err := manager.SearchStatus(ctx, access, "alice")
			if err != nil {
				t.Fatal(err)
			}
			firstSpace.blockID = folders[targetIndex].ID
			firstSpace.blocking.Store(true)
			if err := manager.RequestSearchRebuild(ctx, access, "alice"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-firstSpace.entered:
			case <-time.After(10 * time.Second):
				t.Fatal("replacement rebuild did not reach the interruption boundary")
			}
			building, err := manager.SearchStatus(ctx, access, "alice")
			if err != nil || !building.Rebuilding || building.ServingIndexID != before.IndexID || building.LastCompletedFolderID != folders[targetIndex-1].ID {
				t.Fatalf("interrupted build status = %+v, %v", building, err)
			}
			if page, searchErr := manager.Search(ctx, access, service.SearchQuery{Text: "resume-seed"}); searchErr != nil || len(page.Hits) == 0 {
				t.Fatalf("serving index unavailable during replacement: %+v, %v", page, searchErr)
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			partial, err := loadBuildState(entry.Path)
			if err != nil || partial.IndexID == "" || partial.IndexID == before.IndexID || partial.LastFolderID != folders[targetIndex-1].ID || partial.Checkpoint == "" {
				t.Fatalf("durable partial build = %+v, %v", partial, err)
			}
			if _, err := os.Stat(filepath.Join(entry.Path, "search", "indexes", partial.IndexID)); err != nil {
				t.Fatalf("partial generation was removed: %v", err)
			}
			mutation, err := durable.CreateItem(ctx, access, completedMail.ID, service.ItemInput{Data: []byte("From: source@example.test\r\nSubject: Downtime mutation\r\n\r\nresume-downtime-marker")})
			if err != nil {
				t.Fatal(err)
			}

			resumedSpace := newFolderCheckpointSpace(durable, durable)
			manager, err = New(ctx, accounts, resumedSpace, engineAuthz, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			waitReady(t, manager, access, "alice")
			after, err := manager.SearchStatus(ctx, access, "alice")
			if err != nil || after.IndexID != partial.IndexID || after.ResumeCount != 1 || after.LastResumedAt.IsZero() || after.BuildStartedAt.IsZero() {
				t.Fatalf("resumed build status = %+v, %v", after, err)
			}
			for _, folder := range folders[:targetIndex] {
				if calls := resumedSpace.callCount(folder.ID); calls != 0 {
					t.Fatalf("completed folder %q was rescanned %d time(s)", folder.ID, calls)
				}
			}
			page, err := manager.Search(ctx, access, service.SearchQuery{Text: "resume-downtime-marker"})
			foundMutation := false
			for _, hit := range page.Hits {
				foundMutation = foundMutation || hit.ItemID == mutation.ID
			}
			if err != nil || !foundMutation {
				t.Fatalf("downtime mutation was not reconciled: %+v, %v", page, err)
			}
			if _, err := os.Stat(buildStatePath(entry.Path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed build checkpoint remains: %v", err)
			}
		})
	}
}

func TestSearchRebuildRejectsInvalidOrExpiredPartialAndHonorsManualFreshRequest(t *testing.T) {
	ctx := t.Context()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	system := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := system.EnsureNamespace(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := system.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := system.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	accounts, err := account.NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	user, _ := system.UserStore().Get(ctx, "alice")
	if _, _, err := accounts.Ensure(ctx, user, "alice@example.test", nil); err != nil {
		t.Fatal(err)
	}
	entry, _ := accounts.ByLogin("alice")
	engineAuthz := authz.New(system)
	routed, err := service.NewAccountFolderSpace(ctx, system, accounts, engineAuthz)
	if err != nil {
		t.Fatal(err)
	}
	durable, err := service.NewDurableFolderSpace(ctx, backend, routed)
	if err != nil {
		t.Fatal(err)
	}
	access := service.UserAccess("alice", "test")
	manager, err := New(ctx, accounts, durable, engineAuthz, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	waitReady(t, manager, access, "alice")
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	checkpoint, err := durable.CurrentChangeState(ctx, access, service.ChangeScope{Object: service.ChangeObjectItem})
	if err != nil {
		t.Fatal(err)
	}
	newPartial := func(t *testing.T) persistedState {
		t.Helper()
		id, err := newIndexID()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(entry.Path, "search", "indexes", id)
		index, err := bleve.New(path, indexMapping())
		if err != nil {
			t.Fatal(err)
		}
		if err := index.Close(); err != nil {
			t.Fatal(err)
		}
		state := persistedState{
			Version: mappingVersion, IndexID: id, Checkpoint: checkpoint,
			ActiveGeneration: entry.Manifest.ActiveGeneration, State: "building",
			BuildStartedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
		if err := saveBuildState(entry.Path, state); err != nil {
			t.Fatal(err)
		}
		return state
	}

	corrupt := newPartial(t)
	corruptPath := filepath.Join(entry.Path, "search", "indexes", corrupt.IndexID)
	if err := os.RemoveAll(corruptPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(corruptPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corruptPath, "invalid"), []byte("not a Bleve index"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err = New(ctx, accounts, durable, engineAuthz, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	waitReady(t, manager, access, "alice")
	status, err := manager.SearchStatus(ctx, access, "alice")
	if err != nil || status.IndexID == corrupt.IndexID {
		t.Fatalf("corrupt partial was promoted: %+v, %v", status, err)
	}
	if _, err := os.Stat(corruptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt partial was not removed: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	expired := newPartial(t)
	expiring := &expiringCheckpointSpace{FolderSpace: durable, FolderChangeReader: durable, expireState: expired.Checkpoint}
	manager, err = New(ctx, accounts, expiring, engineAuthz, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	waitReady(t, manager, access, "alice")
	status, err = manager.SearchStatus(ctx, access, "alice")
	if err != nil || !expiring.expired.Load() || status.IndexID == expired.IndexID || status.ResumeCount != 0 {
		t.Fatalf("expired checkpoint recovery = %+v expired=%t error=%v", status, expiring.expired.Load(), err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	manual := newPartial(t)
	manager, err = New(ctx, accounts, durable, engineAuthz, Config{Enabled: false, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RequestSearchRebuild(ctx, access, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconfigure(Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute}); err != nil {
		t.Fatal(err)
	}
	waitReady(t, manager, access, "alice")
	status, err = manager.SearchStatus(ctx, access, "alice")
	if err != nil || status.IndexID == manual.IndexID || status.ResumeCount != 0 {
		t.Fatalf("manual fresh rebuild = %+v, %v", status, err)
	}
	if _, err := os.Stat(filepath.Join(entry.Path, "search", "indexes", manual.IndexID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("operator-discarded partial remains: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSearchBuildStateValidationBoundsCoordinatorMetadata(t *testing.T) {
	valid := persistedState{
		Version: mappingVersion, IndexID: "idx_0123456789abcdef", Checkpoint: "change-state",
		ActiveGeneration: "gen_current", State: "building", BuildStartedAt: time.Now().UTC(),
	}
	if err := validBuildState(valid, "gen_current"); err != nil {
		t.Fatalf("valid build state: %v", err)
	}
	tests := map[string]persistedState{
		"mapping":       func() persistedState { state := valid; state.Version++; return state }(),
		"generation":    func() persistedState { state := valid; state.ActiveGeneration = "gen_old"; return state }(),
		"identity":      func() persistedState { state := valid; state.IndexID = "../escape"; return state }(),
		"checkpoint":    func() persistedState { state := valid; state.Checkpoint = ""; return state }(),
		"started":       func() persistedState { state := valid; state.BuildStartedAt = time.Time{}; return state }(),
		"state":         func() persistedState { state := valid; state.State = "ready"; return state }(),
		"folder length": func() persistedState { state := valid; state.LastFolderID = strings.Repeat("f", 1025); return state }(),
	}
	for name, state := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validBuildState(state, "gen_current"); err == nil {
				t.Fatal("invalid coordinator state was accepted")
			}
		})
	}
}

func TestSearchCatchUpFailureDoesNotBecomeAReplacementBuild(t *testing.T) {
	serving := persistedState{Version: mappingVersion, IndexID: "idx_ready", ActiveGeneration: "gen_current", State: "ready"}
	catchUpFailure := &persistedState{Version: mappingVersion, State: "failed", LastError: "temporary change reader failure"}
	if needsSearchRebuild(serving, catchUpFailure, false, "gen_current") {
		t.Fatal("a transient catch-up failure was promoted to a full replacement rebuild")
	}
	partialFailure := *catchUpFailure
	partialFailure.IndexID = "idx_partial"
	if !needsSearchRebuild(serving, &partialFailure, false, "gen_current") {
		t.Fatal("a failed durable replacement was not resumed")
	}
	if !needsSearchRebuild(serving, nil, true, "gen_current") {
		t.Fatal("an explicit rebuild request was ignored")
	}
}

func TestIncrementalSearchAndRestartAcrossProductionEngines(t *testing.T) {
	if testing.Short() {
		t.Skip("slow production-engine restart scenario")
	}
	for _, engine := range account.ProductionEngines {
		engine := engine
		t.Run(string(engine), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			backend, err := jsonstore.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			system := model.NewTypedStore(backend, store.BackendJSON)
			for _, namespace := range model.Namespaces() {
				if err := system.EnsureNamespace(ctx, namespace); err != nil {
					t.Fatal(err)
				}
			}
			if err := system.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
				t.Fatal(err)
			}
			if err := system.FolderStore().CreateForUser(ctx, "alice"); err != nil {
				t.Fatal(err)
			}
			accountRoot := t.TempDir()
			accounts, err := account.NewManager(accountRoot, engine)
			if err != nil {
				t.Fatal(err)
			}
			user, _ := system.UserStore().Get(ctx, "alice")
			if _, _, err := accounts.Ensure(ctx, user, "alice@example.test", nil); err != nil {
				t.Fatal(err)
			}
			entry, found := accounts.ByLogin("alice")
			if !found {
				t.Fatal("created account was not discoverable")
			}
			abandoned := filepath.Join(entry.Path, "search", "indexes", "idx_abandoned")
			if err := os.MkdirAll(abandoned, 0o700); err != nil {
				t.Fatal(err)
			}
			engineAuthz := authz.New(system)
			routed, err := service.NewAccountFolderSpace(ctx, system, accounts, engineAuthz)
			if err != nil {
				t.Fatal(err)
			}
			durable, err := service.NewDurableFolderSpace(ctx, backend, routed)
			if err != nil {
				t.Fatal(err)
			}
			manager, err := New(ctx, accounts, durable, engineAuthz, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			access := service.UserAccess("alice", "test")
			waitReady(t, manager, access, "alice")
			if _, err := os.Stat(abandoned); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("abandoned index was not reconciled: %v", err)
			}
			before, err := manager.SearchStatus(ctx, access, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if before.IndexBytes <= 0 {
				t.Fatalf("ready index disk size = %d, want positive", before.IndexBytes)
			}

			item, err := durable.CreateItem(ctx, access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("From: sender@example.test\r\nSubject: Incremental marker\r\n\r\nfreshly-indexed"), Flags: []string{model.FlagSeen}})
			if err != nil {
				t.Fatal(err)
			}
			waitHits(t, manager, access, service.SearchQuery{Text: "freshly-indexed"}, 1)
			waitHits(t, manager, access, service.SearchQuery{Filter: &service.SearchFilter{Operator: service.SearchEquals, Field: "flag", Value: model.FlagSeen}}, 1)
			runtime := manager.runtime("alice")
			// closeIdle skips an index while catch-up runs; a pass woken by
			// the queries above may still be finishing.
			closed := false
			for deadline := time.Now().Add(5 * time.Second); !closed && time.Now().Before(deadline); {
				runtime.mu.Lock()
				runtime.lastUsed = time.Now().Add(-2 * time.Minute)
				runtime.mu.Unlock()
				manager.closeIdle(time.Now().Add(-manager.settings().IdleClose))
				runtime.mu.Lock()
				closed = runtime.index == nil
				runtime.mu.Unlock()
				if !closed {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if !closed {
				t.Fatal("idle search index stayed open")
			}
			waitHits(t, manager, access, service.SearchQuery{Text: "freshly-indexed"}, 1)
			if _, err := durable.TrashItem(ctx, access, item.ID); err != nil {
				t.Fatal(err)
			}
			waitHits(t, manager, access, service.SearchQuery{Text: "freshly-indexed"}, 0)
			waitHits(t, manager, access, service.SearchQuery{Text: "freshly-indexed", IncludeTrash: true}, 1)

			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			if err := accounts.Close(); err != nil {
				t.Fatal(err)
			}
			accounts, err = account.NewManager(accountRoot, engine)
			if err != nil {
				t.Fatal(err)
			}
			defer accounts.Close()
			engineAuthz = authz.New(system)
			routed, err = service.NewAccountFolderSpace(ctx, system, accounts, engineAuthz)
			if err != nil {
				t.Fatal(err)
			}
			durable, err = service.NewDurableFolderSpace(ctx, backend, routed)
			if err != nil {
				t.Fatal(err)
			}
			manager, err = New(ctx, accounts, durable, engineAuthz, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			waitReady(t, manager, access, "alice")
			after, err := manager.SearchStatus(ctx, access, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if after.IndexID != before.IndexID {
				t.Fatalf("restart rebuilt stable index: before %q, after %q", before.IndexID, after.IndexID)
			}
			restartedRuntime := manager.runtime("alice")
			deadline := time.Now().Add(10 * time.Second)
			var cold, validated bool
			for time.Now().Before(deadline) {
				restartedRuntime.mu.Lock()
				cold, validated = restartedRuntime.index == nil, restartedRuntime.validated
				restartedRuntime.mu.Unlock()
				if cold && validated {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !cold || !validated {
				t.Fatalf("unchanged restarted index cold=%t validated=%t, want both true", cold, validated)
			}
			waitHits(t, manager, access, service.SearchQuery{Text: "freshly-indexed", IncludeTrash: true}, 1)

			// A ready state pointing at an unreadable derived generation must be
			// detected without an operator request. Canonical account data remains
			// untouched and is used to build a clean replacement.
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			brokenID := after.IndexID
			brokenPath := filepath.Join(entry.Path, "search", "indexes", brokenID)
			if err := os.RemoveAll(brokenPath); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(brokenPath, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(brokenPath, "not-an-index"), []byte("corrupt"), 0o600); err != nil {
				t.Fatal(err)
			}
			manager, err = New(ctx, accounts, durable, engineAuthz, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			recovered := waitRecovered(t, manager, access, "alice", brokenID)
			if recovered.IndexID == brokenID || recovered.LastRecoveryIndexID != brokenID || recovered.LastRecoveryReason == "" || recovered.LastRecoveryAt.IsZero() {
				t.Fatalf("corrupt index %q recovery = %+v", brokenID, recovered)
			}
			quarantined, err := os.ReadDir(filepath.Join(entry.Path, "search", "quarantine"))
			if err != nil || len(quarantined) != 1 {
				t.Fatalf("quarantined generations = %v, %v", quarantined, err)
			}
			if _, err := os.Stat(filepath.Join(entry.Path, "search", "quarantine", quarantined[0].Name(), "veksel-recovery.json")); err != nil {
				t.Fatalf("quarantine record: %v", err)
			}
			waitHits(t, manager, access, service.SearchQuery{Text: "freshly-indexed", IncludeTrash: true}, 1)
		})
	}
}

func waitRecovered(t *testing.T, manager *Manager, access service.AccessContext, accountID, brokenID string) service.SearchIndexStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, err := manager.SearchStatus(t.Context(), access, accountID)
		if err == nil && status.State == "ready" && status.IndexID != brokenID && status.LastRecoveryIndexID == brokenID {
			return status
		}
		time.Sleep(20 * time.Millisecond)
	}
	status, _ := manager.SearchStatus(t.Context(), access, accountID)
	t.Fatalf("search index %q did not recover: %+v", brokenID, status)
	return service.SearchIndexStatus{}
}

func waitReady(t testing.TB, manager *Manager, access service.AccessContext, accountID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, err := manager.SearchStatus(t.Context(), access, accountID)
		if err == nil && status.State == "ready" {
			return
		}
		if err != nil && !errors.Is(err, service.ErrSearchUnavailable) {
			t.Fatalf("search status: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	status, _ := manager.SearchStatus(t.Context(), access, accountID)
	t.Fatalf("search index did not become ready: %+v", status)
}

func waitHits(t testing.TB, manager *Manager, access service.AccessContext, query service.SearchQuery, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		page, err := manager.Search(t.Context(), access, query)
		if err == nil && len(page.Hits) == count {
			return
		}
		if err != nil && !errors.Is(err, service.ErrSearchUnavailable) {
			t.Fatalf("search: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	page, err := manager.Search(t.Context(), access, query)
	t.Fatalf("wanted %d hits, got %+v (%v)", count, page, err)
}
