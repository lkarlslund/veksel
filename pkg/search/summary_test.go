package search

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// itemReadCountingSpace counts payload reads so tests can tell index-served
// contact summaries from the item read fallback.
type itemReadCountingSpace struct {
	service.FolderSpace
	service.FolderChangeReader
	reads atomic.Int64
}

func (s *itemReadCountingSpace) GetItem(ctx context.Context, access service.AccessContext, id string) (model.Item, error) {
	s.reads.Add(1)
	return s.FolderSpace.GetItem(ctx, access, id)
}

func TestContactSummariesServeFromIndexWithFallbacks(t *testing.T) {
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
	accounts, err := account.NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	for _, login := range []string{"alice", "bob"} {
		if err := system.UserStore().Create(ctx, login, login, "password123"); err != nil {
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
	alice := service.UserAccess("alice", "test")
	contactsFolder := model.FolderKey("alice", "Contacts")
	items := make(map[string]model.Item)
	for _, contact := range []model.Contact{
		{FN: "Ada Lovelace", Org: "Analytical Engines", Emails: []string{"ada@example.test", "ada@home.test"}, Phones: []string{"+44 1"}, PhotoData: []byte("jpeg-bytes"), PhotoType: "JPEG"},
		{FN: "Grace Hopper", Org: "Navy", Emails: []string{"grace@example.test"}, Categories: []string{"Project North"}},
		{FN: "Katherine Johnson", Org: "NASA", Emails: []string{"katherine@example.test"}},
	} {
		item, err := durable.CreateItem(ctx, alice, contactsFolder, service.ItemInput{Data: model.ContactToVCard(contact)})
		if err != nil {
			t.Fatal(err)
		}
		items[contact.FN] = item
	}
	attachment := strings.Repeat("QUJD", 4096)
	mailRaw := "From: Ann <ann@example.test>\r\nSubject: Budget review\r\nMessage-ID: <budget@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nThe budget is attached.\r\n--b\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n" + attachment + "\r\n--b--\r\n"
	mailHeaders, _ := model.ParseMessageHeaders([]byte(mailRaw))
	if _, err := durable.CreateItem(ctx, alice, model.InboxFolderID("alice"), service.ItemInput{Data: []byte(mailRaw), Headers: mailHeaders, Flags: []string{model.FlagSeen}}); err != nil {
		t.Fatal(err)
	}
	space := &itemReadCountingSpace{FolderSpace: durable, FolderChangeReader: durable}
	// A batch of two lets the update and delete below catch up without the
	// bounded catch-up delay.
	manager, err := New(ctx, accounts, space, engine, Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	waitReady(t, manager, alice, "alice")
	// Mail hits are served from the stored summary too, without reading the
	// message and its attachments.
	mailPage, err := manager.Search(ctx, alice, service.SearchQuery{Text: "budget", Types: []model.FolderType{model.FolderTypeMail}, OmitSnippets: true, Limit: 10})
	if err != nil || len(mailPage.Hits) != 1 || mailPage.Hits[0].Title != "Budget review" || !strings.Contains(mailPage.Hits[0].Sender, "ann@example.test") || !slices.Contains(mailPage.Hits[0].Flags, model.FlagSeen) {
		t.Fatalf("mail summary page = %+v, %v", mailPage, err)
	}
	if reads := space.reads.Swap(0); reads != 0 {
		t.Fatalf("mail search read %d items; want summaries served from the index", reads)
	}
	query := service.SearchQuery{FolderIDs: []string{contactsFolder}, Types: []model.FolderType{model.FolderTypeContacts}, Sort: "contact_name", Limit: 10}
	names := func(page service.SearchPage) []string {
		result := make([]string, 0, len(page.Hits))
		for _, hit := range page.Hits {
			result = append(result, hit.Name)
		}
		return result
	}

	page, err := manager.Search(ctx, alice, query)
	if err != nil || !slices.Equal(names(page), []string{"Ada Lovelace", "Grace Hopper", "Katherine Johnson"}) {
		t.Fatalf("contact page = %+v, %v", page, err)
	}
	ada := page.Hits[0]
	if ada.ItemID != items["Ada Lovelace"].ID || ada.FolderName != "Contacts" || ada.Type != model.FolderTypeContacts || ada.ContactOrg != "Analytical Engines" || ada.ContactPhone != "+44 1" || !ada.ContactHasPhoto || !slices.Equal(ada.ContactEmails, []string{"ada@example.test", "ada@home.test"}) {
		t.Fatalf("index summary lost contact fields: %+v", ada)
	}
	if !ada.Updated.Equal(items["Ada Lovelace"].UpdatedAt) || ada.Updated.UnixNano() != items["Ada Lovelace"].UpdatedAt.UnixNano() {
		t.Fatalf("summary update time %v lost precision of %v", ada.Updated, items["Ada Lovelace"].UpdatedAt)
	}
	if reads := space.reads.Swap(0); reads != 0 {
		t.Fatalf("listing read %d items; want summaries served from the index", reads)
	}
	textQuery := query
	textQuery.Text, textQuery.OmitSnippets = "Grace", true
	if page, err := manager.Search(ctx, alice, textQuery); err != nil || !slices.Equal(names(page), []string{"Grace Hopper"}) || len(page.Hits[0].Snippets) != 0 {
		t.Fatalf("snippet-free text search = %+v, %v", page, err)
	}
	if reads := space.reads.Swap(0); reads != 0 {
		t.Fatalf("snippet-free text search read %d items", reads)
	}
	textQuery.OmitSnippets = false
	if page, err := manager.Search(ctx, alice, textQuery); err != nil || len(page.Hits) != 1 || len(page.Hits[0].Snippets) == 0 {
		t.Fatalf("text search lost snippets = %+v, %v", page, err)
	}
	categoryQuery := query
	categoryQuery.Filter = &service.SearchFilter{Operator: service.SearchEquals, Field: "category", Value: "PROJECT north"}
	if page, err := manager.Search(ctx, alice, categoryQuery); err != nil || !slices.Equal(names(page), []string{"Grace Hopper"}) || !slices.Equal(page.Hits[0].ContactCategories, []string{"Project North"}) {
		t.Fatalf("category filter = %+v, %v", page, err)
	}
	space.reads.Store(0)

	// Documents indexed before summaries existed take the item read path.
	rt := manager.runtime("alice")
	rt.mu.Lock()
	idx, checkpoint := rt.index, rt.state.Checkpoint
	rt.mu.Unlock()
	folder, err := durable.GetFolder(ctx, alice, contactsFolder)
	if err != nil {
		t.Fatal(err)
	}
	legacy := extract(folder, items["Grace Hopper"], 0)
	legacy.Summary = ""
	if err := idx.Index(legacy.ItemID, legacy); err != nil {
		t.Fatal(err)
	}
	page, err = manager.Search(ctx, alice, query)
	if err != nil || !slices.Equal(names(page), []string{"Ada Lovelace", "Grace Hopper", "Katherine Johnson"}) || page.Hits[1].ContactOrg != "Navy" {
		t.Fatalf("legacy document page = %+v, %v", page, err)
	}
	if reads := space.reads.Swap(0); reads != 1 {
		t.Fatalf("legacy document fallback read %d items, want 1", reads)
	}

	// Items changed after the index checkpoint are read, never served stale.
	katherine := model.ContactToVCard(model.Contact{FN: "Katherine Goble", Org: "NASA", Emails: []string{"katherine@example.test"}})
	if _, err := durable.UpdateItem(ctx, alice, items["Katherine Johnson"].ID, katherine, nil); err != nil {
		t.Fatal(err)
	}
	if err := durable.DeleteItem(ctx, alice, items["Ada Lovelace"].ID); err != nil {
		t.Fatal(err)
	}
	pending, known := manager.pendingItemChanges(ctx, "alice", checkpoint)
	_, updatedPending := pending[items["Katherine Johnson"].ID]
	_, deletedPending := pending[items["Ada Lovelace"].ID]
	if !known || !updatedPending || !deletedPending {
		t.Fatalf("pending changes = %v (known %v)", pending, known)
	}
	page, err = manager.Search(ctx, alice, query)
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range page.Hits {
		if hit.ItemID == items["Ada Lovelace"].ID || hit.Name == "Katherine Johnson" {
			t.Fatalf("stale summary served after change: %+v", page.Hits)
		}
	}

	// A caller who can discover the folder but not read its items sees no
	// summaries; one with folder read access is served from the index.
	roles := model.NewRoleStore(system)
	if err := roles.Set(ctx, model.Role{
		ID: "test.discover", Name: "Discover", ResourceKinds: []model.ResourceKind{model.ResourceFolder},
		Permissions: []string{string(authz.FolderDiscover), string(authz.FolderItemsList)},
	}); err != nil {
		t.Fatal(err)
	}
	policies := model.NewPolicyStore(system)
	for _, binding := range []model.PolicyBinding{
		{Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"}, RoleID: authz.RoleAccountSearcher},
		{Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: contactsFolder}, RoleID: "test.discover"},
	} {
		binding.Principal = model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
		binding.Effect, binding.Inheritance, binding.GrantedBy = model.EffectAllow, model.InheritanceSelf, "alice"
		if _, err := policies.Create(ctx, binding); err != nil {
			t.Fatal(err)
		}
	}
	bob := service.UserAccess("bob", "test")
	bobQuery := query
	bobQuery.AccountID = "alice"
	page, err = manager.Search(ctx, bob, bobQuery)
	if err != nil || len(page.Hits) != 0 {
		t.Fatalf("discover-only grant leaked summaries: %+v, %v", page, err)
	}
	if _, err := policies.Create(ctx, model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: contactsFolder},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderViewer, Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(25 * time.Millisecond) {
		rt.mu.Lock()
		caughtUp := rt.state.Checkpoint != checkpoint
		rt.mu.Unlock()
		if caughtUp {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("search index did not catch up")
		}
	}
	space.reads.Store(0)
	page, err = manager.Search(ctx, bob, bobQuery)
	if err != nil || !slices.Equal(names(page), []string{"Grace Hopper", "Katherine Goble"}) {
		t.Fatalf("folder reader page = %+v, %v", page, err)
	}
	if reads := space.reads.Load(); reads != 1 {
		t.Fatalf("folder reader read %d items; want only the legacy document read", reads)
	}
}
