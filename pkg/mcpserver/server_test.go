package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type testSpace struct {
	service.FolderSpace
	mu         sync.Mutex
	accesses   []service.AccessContext
	itemData   []byte
	mediaType  string
	folderType model.FolderType
}

func (s *testSpace) record(access service.AccessContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accesses = append(s.accesses, access)
}

func (s *testSpace) ListFolders(_ context.Context, access service.AccessContext, _ service.FolderQuery) ([]model.Folder, error) {
	s.record(access)
	return []model.Folder{{ID: "folder-" + access.Subject.ID, UserID: access.Subject.ID, Name: "Inbox", Path: "INBOX", Type: model.FolderTypeMail, ItemCount: 3}}, nil
}

func (s *testSpace) GetFolder(_ context.Context, access service.AccessContext, folderID string) (model.Folder, error) {
	s.record(access)
	folderType := s.folderType
	if folderType == "" {
		folderType = model.FolderTypeFiles
	}
	return model.Folder{ID: folderID, UserID: access.Subject.ID, Type: folderType}, nil
}

func (s *testSpace) ListItemPage(_ context.Context, access service.AccessContext, folderID string, query service.ItemPageQuery) (service.ItemPage, error) {
	s.record(access)
	return service.ItemPage{Items: []model.Item{{ID: "item-" + access.Subject.ID, FolderID: folderID, Headers: map[string]string{"Subject": "Hello"}, Size: 5}}, Total: 3, NextCursor: query.Cursor + "next"}, nil
}

func (s *testSpace) GetItem(_ context.Context, access service.AccessContext, itemID string) (model.Item, error) {
	s.record(access)
	data, mediaType := s.itemData, s.mediaType
	if data == nil {
		data = []byte("hello")
	}
	if mediaType == "" {
		mediaType = "text/plain"
	}
	return model.Item{ID: itemID, FolderID: "folder-" + access.Subject.ID, Data: bytes.Clone(data), Headers: map[string]string{"Content-Type": mediaType}, Size: int64(len(data))}, nil
}

type testSearch struct {
	mu       sync.Mutex
	accesses []service.AccessContext
	queries  []service.SearchQuery
}

func (s *testSearch) Search(_ context.Context, access service.AccessContext, query service.SearchQuery) (service.SearchPage, error) {
	s.mu.Lock()
	s.accesses = append(s.accesses, access)
	s.queries = append(s.queries, query)
	s.mu.Unlock()
	return service.SearchPage{Hits: []service.SearchHit{{ItemID: "hit-" + access.Subject.ID, Type: model.FolderTypeMail, Title: query.Expression}}, Total: 1, IndexID: "index"}, nil
}

func (*testSearch) SearchStatus(context.Context, service.AccessContext, string) (service.SearchIndexStatus, error) {
	return service.SearchIndexStatus{}, nil
}

func (*testSearch) RequestSearchRebuild(context.Context, service.AccessContext, string) error {
	return nil
}

type bearerTransport struct {
	token string
	next  http.RoundTripper
}

func (t bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.next.RoundTrip(clone)
}

type fixture struct {
	server *httptest.Server
	typed  *model.TypedStore
	keys   *model.APIKeyStore
	users  *model.UserStore
	space  *testSpace
	search *testSearch
	refs   *ReferenceService
}

func newFixture(t *testing.T) (*fixture, map[string]string) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSAPIKeys, model.NSMetadata} {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	users, keys := typed.UserStore(), model.NewAPIKeyStore(typed)
	secrets := make(map[string]string)
	for _, userID := range []string{"alice", "bob"} {
		if err := users.Create(t.Context(), userID, userID, "secret"); err != nil {
			t.Fatal(err)
		}
		_, secret, err := keys.CreateWithScopes(t.Context(), userID, userID+" MCP", []string{ReadScope})
		if err != nil {
			t.Fatal(err)
		}
		secrets[userID] = secret
	}
	space, search := &testSpace{}, &testSearch{}
	references, err := NewReferenceService(t.Context(), typed, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHandler(keys, users, space, search, references, nil))
	t.Cleanup(server.Close)
	return &fixture{server: server, typed: typed, keys: keys, users: users, space: space, search: search, refs: references}, secrets
}

func connect(t *testing.T, endpoint, token string) *mcp.ClientSession {
	t.Helper()
	client := &http.Client{Transport: bearerTransport{token: token, next: http.DefaultTransport}}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "veksel-test", Version: "1"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func decodeStructured[T any](t *testing.T, result *mcp.CallToolResult) T {
	t.Helper()
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var output T
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	return output
}

func TestConcurrentPrincipalsRemainIsolated(t *testing.T) {
	fixture, secrets := newFixture(t)
	type result struct {
		userID string
		output *mcp.CallToolResult
		err    error
	}
	results := make(chan result, 2)
	sessions := map[string]*mcp.ClientSession{
		"alice": connect(t, fixture.server.URL, secrets["alice"]),
		"bob":   connect(t, fixture.server.URL, secrets["bob"]),
	}
	for _, userID := range []string{"alice", "bob"} {
		go func() {
			response, err := sessions[userID].CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{}})
			results <- result{userID: userID, output: response, err: err}
		}()
	}
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		output := decodeStructured[listFoldersOutput](t, got.output)
		if output.AccountID != got.userID || len(output.Folders) != 1 || output.Folders[0].ID != "folder-"+got.userID {
			t.Fatalf("principal %q received another account: %#v", got.userID, output)
		}
	}
}

func TestDelegatedAccountBuildsDelegationContext(t *testing.T) {
	fixture, secrets := newFixture(t)
	session := connect(t, fixture.server.URL, secrets["alice"])
	response, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{"account_id": "bob"}})
	if err != nil {
		t.Fatal(err)
	}
	output := decodeStructured[listFoldersOutput](t, response)
	if output.AccountID != "bob" {
		t.Fatalf("account = %q, want bob", output.AccountID)
	}
	fixture.space.mu.Lock()
	defer fixture.space.mu.Unlock()
	access := fixture.space.accesses[len(fixture.space.accesses)-1]
	if access.Actor.ID != "alice" || access.Subject.ID != "bob" || access.Mode != authz.ActingDelegation || access.Protocol != "mcp" {
		t.Fatalf("unexpected delegated access: %#v", access)
	}
}

func TestDelegatedAccountIsHiddenAndThenAllowedByFolderSpaceRBAC(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSAPIKeys, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes, model.NSAuthorizationMetadata, model.NSMetadata} {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	for _, userID := range []string{"alice", "bob"} {
		if err := typed.UserStore().Create(t.Context(), userID, userID, "secret"); err != nil {
			t.Fatal(err)
		}
		if err := typed.FolderStore().CreateForUser(t.Context(), userID); err != nil {
			t.Fatal(err)
		}
	}
	keys := model.NewAPIKeyStore(typed)
	_, secret, err := keys.CreateWithScopes(t.Context(), "alice", "MCP", []string{ReadScope})
	if err != nil {
		t.Fatal(err)
	}
	references, err := NewReferenceService(t.Context(), typed, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHandler(keys, typed.UserStore(), service.NewFolderSpace(typed, authz.New(typed)), nil, references, nil))
	t.Cleanup(server.Close)
	session := connect(t, server.URL, secret)
	denied, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{"account_id": "bob"}})
	if err != nil {
		t.Fatal(err)
	}
	if denied.IsError {
		t.Fatalf("safe empty discovery failed: %v", denied.GetError())
	}
	deniedOutput := decodeStructured[listFoldersOutput](t, denied)
	if len(deniedOutput.Folders) != 0 {
		t.Fatalf("cross-account folders leaked without delegation: %#v", deniedOutput)
	}
	policyStore := model.NewPolicyStore(typed)
	binding, err := policyStore.Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "bob"},
		Effect:    model.EffectAllow, RoleID: authz.RoleAccountDelegate,
		Inheritance: model.InheritanceSelf, GrantedBy: "bob",
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{"account_id": "bob"}})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.IsError {
		t.Fatalf("delegated folder discovery failed: %v", allowed.GetError())
	}
	output := decodeStructured[listFoldersOutput](t, allowed)
	if output.AccountID != "bob" || len(output.Folders) == 0 {
		t.Fatalf("unexpected delegated folders: %#v", output)
	}
	page, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_items", Arguments: map[string]any{"folder_ref": output.Folders[0].Reference}})
	if err != nil || page.IsError {
		t.Fatalf("delegated reference was not usable: result=%#v error=%v", page, err)
	}
	if err := policyStore.Delete(t.Context(), binding.ID); err != nil {
		t.Fatal(err)
	}
	deniedAfterRevoke, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_items", Arguments: map[string]any{"folder_ref": output.Folders[0].Reference}})
	if err == nil && !deniedAfterRevoke.IsError {
		t.Fatal("reference bypassed live FolderSpace RBAC after delegation was revoked")
	}
}

func TestAuthenticationScopeAndRevocation(t *testing.T) {
	fixture, secrets := newFixture(t)
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, fixture.server.URL, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d", response.StatusCode)
	}
	_, wrongScopeSecret, err := fixture.keys.CreateWithScopes(t.Context(), "alice", "REST only", []string{"api.read"})
	if err != nil {
		t.Fatal(err)
	}
	wrongScopeClient := &http.Client{Transport: bearerTransport{token: wrongScopeSecret, next: http.DefaultTransport}}
	_, err = mcp.NewClient(&mcp.Implementation{Name: "wrong-scope", Version: "1"}, nil).Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: fixture.server.URL, HTTPClient: wrongScopeClient, DisableStandaloneSSE: true}, nil)
	if err == nil {
		t.Fatal("credential without mcp.read connected")
	}

	session := connect(t, fixture.server.URL, secrets["alice"])
	itemResult, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_get_item", Arguments: map[string]any{"item_id": "before-revoke"}})
	if err != nil {
		t.Fatal(err)
	}
	resourceURI := decodeStructured[getItemOutput](t, itemResult).Item.ResourceURI
	keys, err := fixture.keys.ListByUser(t.Context(), "alice")
	if err != nil || len(keys) != 2 {
		t.Fatalf("list keys: %v, %#v", err, keys)
	}
	var mcpKeyID string
	for _, key := range keys {
		if slices.Contains(key.Scopes, ReadScope) {
			mcpKeyID = key.ID
		}
	}
	_, replacement, err := fixture.keys.Rotate(t.Context(), mcpKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: resourceURI}); err == nil {
		t.Fatal("rotated credential retained resource access to an existing session")
	}
	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{}}); err == nil {
		t.Fatal("rotated credential retained tool access to an existing session")
	}
	replacementSession := connect(t, fixture.server.URL, replacement)
	if _, err := replacementSession.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{}}); err != nil {
		t.Fatalf("replacement credential could not call a tool: %v", err)
	}
	replacementItem, err := replacementSession.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_get_item", Arguments: map[string]any{"item_id": "after-rotate"}})
	if err != nil {
		t.Fatalf("replacement credential could not get an item: %v", err)
	}
	replacementResourceURI := decodeStructured[getItemOutput](t, replacementItem).Item.ResourceURI
	if _, err := replacementSession.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: replacementResourceURI}); err != nil {
		t.Fatalf("replacement credential could not use its authorized resource: %v", err)
	}
	if err := fixture.keys.Revoke(t.Context(), mcpKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := replacementSession.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: replacementResourceURI}); err == nil {
		t.Fatal("revoked credential retained resource access to an existing session")
	}
	if _, err := replacementSession.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{}}); err == nil {
		t.Fatal("revoked credential retained access to an existing session")
	}
}

func TestReadToolsAreBoundedAndUseFolderAndSearchCapabilities(t *testing.T) {
	fixture, secrets := newFixture(t)
	session := connect(t, fixture.server.URL, secrets["alice"])
	page, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_items", Arguments: map[string]any{"folder_id": "folder-alice", "cursor": "c", "limit": 1000}})
	if err != nil {
		t.Fatal(err)
	}
	items := decodeStructured[listItemsOutput](t, page)
	if items.Total != 3 || items.NextCursor != "cnext" || len(items.Items) != 1 {
		t.Fatalf("unexpected item page: %#v", items)
	}
	if items.Items[0].Reference == "" || items.Items[0].ResourceURI == "" {
		t.Fatalf("item lacks safe follow-up references: %#v", items.Items[0])
	}
	itemResult, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_get_item", Arguments: map[string]any{"item_id": "item-alice"}})
	if err != nil {
		t.Fatal(err)
	}
	item := decodeStructured[getItemOutput](t, itemResult)
	if item.Text != "hello" || item.Base64 != "" {
		t.Fatalf("unexpected item content: %#v", item)
	}
	searchResult, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_search", Arguments: map[string]any{"query": "subject:hello"}})
	if err != nil {
		t.Fatal(err)
	}
	search := decodeStructured[searchOutput](t, searchResult)
	if search.Total != 1 || len(search.Hits) != 1 || search.Hits[0].ItemID != "hit-alice" {
		t.Fatalf("unexpected search: %#v", search)
	}
	if search.Hits[0].Reference == "" || search.Hits[0].ResourceURI == "" {
		t.Fatalf("search hit lacks safe follow-up references: %#v", search.Hits[0])
	}
}

func TestOpaqueReferenceToolAndResourceFlow(t *testing.T) {
	fixture, secrets := newFixture(t)
	session := connect(t, fixture.server.URL, secrets["alice"])

	templates, err := session.ListResourceTemplates(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	templateURIs := []string{templates.ResourceTemplates[0].URITemplate, templates.ResourceTemplates[1].URITemplate}
	slices.Sort(templateURIs)
	if len(templates.ResourceTemplates) != 2 || !slices.Equal(templateURIs, []string{"veksel://attachment/{reference}{?offset}", "veksel://item/{reference}{?offset}"}) {
		t.Fatalf("unexpected resource templates: %#v", templates.ResourceTemplates)
	}

	folderResult, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	folders := decodeStructured[listFoldersOutput](t, folderResult)
	if len(folders.Folders) != 1 || folders.Folders[0].Reference == "" {
		t.Fatalf("folder reference missing: %#v", folders)
	}
	itemResult, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_items", Arguments: map[string]any{"folder_ref": folders.Folders[0].Reference}})
	if err != nil {
		t.Fatal(err)
	}
	items := decodeStructured[listItemsOutput](t, itemResult)
	if len(items.Items) != 1 || items.Items[0].Reference == "" {
		t.Fatalf("item reference missing: %#v", items)
	}
	searchResult, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_search", Arguments: map[string]any{"query": "hello", "folder_refs": []string{folders.Folders[0].Reference}}})
	if err != nil || searchResult.IsError {
		t.Fatalf("search by folder reference failed: result=%#v error=%v", searchResult, err)
	}
	fixture.search.mu.Lock()
	lastQuery := fixture.search.queries[len(fixture.search.queries)-1]
	fixture.search.mu.Unlock()
	if !slices.Equal(lastQuery.FolderIDs, []string{"folder-alice"}) {
		t.Fatalf("folder reference resolved to query IDs %#v", lastQuery.FolderIDs)
	}
	getResult, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_get_item", Arguments: map[string]any{"item_ref": items.Items[0].Reference}})
	if err != nil {
		t.Fatal(err)
	}
	got := decodeStructured[getItemOutput](t, getResult)
	if got.Text != "hello" || got.Item.ResourceURI == "" {
		t.Fatalf("unexpected referenced item: %#v", got)
	}
	resource, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: items.Items[0].ResourceURI})
	if err != nil {
		t.Fatal(err)
	}
	if len(resource.Contents) != 1 || resource.Contents[0].Text != "hello" || resource.Contents[0].MIMEType != "text/plain" {
		t.Fatalf("unexpected resource: %#v", resource.Contents)
	}
}

func TestAttachmentProjectionAndBoundedResourceRemainOpaqueAndAuthorized(t *testing.T) {
	fixture, secrets := newFixture(t)
	payload := bytes.Repeat([]byte{0xab}, maximumInlineBytes+37)
	fixture.space.folderType = model.FolderTypeMail
	fixture.space.itemData = []byte(strings.Join([]string{
		"From: alice@example.test", "To: alice@example.test", "Subject: attachment", "MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=x", "", "--x", "Content-Type: text/plain; charset=utf-8", "", "safe body",
		"--x", `Content-Type: application/octet-stream; name="large.bin"`, `Content-Disposition: inline; filename="large.bin"`,
		"Content-ID: <large@example.test>", "Content-Transfer-Encoding: base64", "", base64.StdEncoding.EncodeToString(payload), "--x--", "",
	}, "\r\n"))
	session := connect(t, fixture.server.URL, secrets["alice"])
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_project_message", Arguments: map[string]any{"item_id": "message-alice"}})
	if err != nil || result.IsError {
		t.Fatalf("project message: result=%#v error=%v", result, err)
	}
	projection := decodeStructured[projectMessageOutput](t, result)
	if projection.Text != "safe body" || len(projection.Attachments) != 1 {
		t.Fatalf("projection = %#v", projection)
	}
	attachment := projection.Attachments[0]
	if attachment.Name != "large.bin" || !attachment.Inline || attachment.ContentID != "large@example.test" || attachment.Reference == "" || !strings.HasPrefix(attachment.ResourceURI, "veksel://attachment/") {
		t.Fatalf("attachment metadata = %#v", attachment)
	}
	first, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: attachment.ResourceURI})
	if err != nil || len(first.Contents) != 1 || len(first.Contents[0].Blob) != maximumInlineBytes || first.Contents[0].Meta["complete"] != false {
		t.Fatalf("first attachment chunk = %#v, error=%v", first, err)
	}
	nextValue := first.Contents[0].Meta["next_uri"]
	nextURI, ok := nextValue.(string)
	// The token is sealed and random, so it can contain "1.2" by chance; the
	// part path must not appear as a readable parameter.
	if !ok || !strings.HasPrefix(nextURI, "veksel://attachment/r1.") || strings.Contains(nextURI, "message-alice") || strings.Contains(nextURI, "part") {
		t.Fatalf("unsafe continuation URI = %#v (type %T), meta=%#v", nextValue, nextValue, first.Contents[0].Meta)
	}
	second, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: nextURI})
	if err != nil || len(second.Contents[0].Blob) != 37 || second.Contents[0].Meta["complete"] != true {
		t.Fatalf("second attachment chunk = %#v, error=%v", second, err)
	}
	if _, err := connect(t, fixture.server.URL, secrets["bob"]).ReadResource(t.Context(), &mcp.ReadResourceParams{URI: attachment.ResourceURI}); err == nil {
		t.Fatal("another principal read the attachment reference")
	}
}

func TestMessageProjectionRejectsMalformedMIMEAndNonMailItems(t *testing.T) {
	fixture, secrets := newFixture(t)
	session := connect(t, fixture.server.URL, secrets["alice"])
	fixture.space.folderType = model.FolderTypeMail
	fixture.space.itemData = []byte("Content-Type: multipart/mixed\r\n\r\nbroken")
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_project_message", Arguments: map[string]any{"item_id": "broken"}})
	if err == nil && !result.IsError {
		t.Fatal("malformed MIME projected successfully")
	}
	fixture.space.folderType = model.FolderTypeFiles
	fixture.space.itemData = []byte("plain file")
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_project_message", Arguments: map[string]any{"item_id": "file"}})
	if err == nil && !result.IsError {
		t.Fatal("non-mail item projected as a message")
	}
}

func TestReferencesRejectTamperingOtherPrincipalsSessionsAndAccounts(t *testing.T) {
	fixture, secrets := newFixture(t)
	alice := connect(t, fixture.server.URL, secrets["alice"])
	folderResult, err := alice.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_folders", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	reference := decodeStructured[listFoldersOutput](t, folderResult).Folders[0].Reference

	assertRejected := func(t *testing.T, session *mcp.ClientSession, value string, arguments map[string]any) {
		t.Helper()
		arguments["folder_ref"] = value
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_list_items", Arguments: arguments})
		if err != nil {
			return
		}
		if !result.IsError {
			t.Fatalf("reference unexpectedly accepted: %#v", result.StructuredContent)
		}
	}
	t.Run("tampered", func(t *testing.T) {
		last := reference[len(reference)-1]
		replacement := byte('A')
		if last == replacement {
			replacement = 'B'
		}
		assertRejected(t, alice, reference[:len(reference)-1]+string(replacement), map[string]any{})
	})
	t.Run("different principal", func(t *testing.T) {
		assertRejected(t, connect(t, fixture.server.URL, secrets["bob"]), reference, map[string]any{})
	})
	t.Run("different session", func(t *testing.T) {
		assertRejected(t, connect(t, fixture.server.URL, secrets["alice"]), reference, map[string]any{})
	})
	t.Run("account mismatch", func(t *testing.T) {
		assertRejected(t, alice, reference, map[string]any{"account_id": "bob"})
	})
}

func TestResourceTransferIsBoundedAndContinuesWithoutPaths(t *testing.T) {
	fixture, secrets := newFixture(t)
	fixture.space.itemData = bytes.Repeat([]byte{0xab}, maximumInlineBytes+37)
	fixture.space.mediaType = "application/octet-stream"
	session := connect(t, fixture.server.URL, secrets["alice"])
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_get_item", Arguments: map[string]any{"item_id": "large"}})
	if err != nil {
		t.Fatal(err)
	}
	item := decodeStructured[getItemOutput](t, result)
	first, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: item.Item.ResourceURI})
	if err != nil {
		t.Fatal(err)
	}
	content := first.Contents[0]
	if len(content.Blob) != maximumInlineBytes || content.Text != "" || content.Meta["complete"] != false {
		t.Fatalf("unexpected first resource chunk: bytes=%d meta=%#v", len(content.Blob), content.Meta)
	}
	nextURI, ok := content.Meta["next_uri"].(string)
	if !ok || nextURI == "" {
		t.Fatalf("missing continuation URI: %#v", content.Meta)
	}
	second, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: nextURI})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Contents[0].Blob) != 37 || second.Contents[0].Meta["complete"] != true {
		t.Fatalf("unexpected final resource chunk: bytes=%d meta=%#v", len(second.Contents[0].Blob), second.Contents[0].Meta)
	}
	for _, uri := range []string{item.Item.ResourceURI, nextURI} {
		if len(uri) < len("veksel://") || uri[:len("veksel://")] != "veksel://" {
			t.Fatalf("resource exposed a non-Veksel URI: %q", uri)
		}
	}
}

func TestReferenceSigningKeyPersistsButSessionBoundarySurvivesRestart(t *testing.T) {
	fixture, secrets := newFixture(t)
	firstSession := connect(t, fixture.server.URL, secrets["alice"])
	result, err := firstSession.CallTool(t.Context(), &mcp.CallToolParams{Name: "veksel_get_item", Arguments: map[string]any{"item_id": "restart-item"}})
	if err != nil {
		t.Fatal(err)
	}
	resourceURI := decodeStructured[getItemOutput](t, result).Item.ResourceURI

	reloadedReferences, err := NewReferenceService(t.Context(), fixture.typed, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	directReference, err := fixture.refs.Issue(ReferenceItem, "alice", "bob", "stable-session", "private-item-id")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := reloadedReferences.Resolve(directReference, ReferenceItem, "alice", "stable-session")
	if err != nil || claims.AccountID != "bob" || claims.Resource != "private-item-id" {
		t.Fatalf("durable signing key did not survive reload: claims=%#v error=%v", claims, err)
	}
	newServer := httptest.NewServer(NewHandler(fixture.keys, fixture.users, fixture.space, fixture.search, reloadedReferences, nil))
	t.Cleanup(newServer.Close)
	newSession := connect(t, newServer.URL, secrets["alice"])
	if _, err := newSession.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: resourceURI}); err == nil {
		t.Fatal("reference from a pre-restart session remained usable")
	}
}

func TestReferenceExpiry(t *testing.T) {
	fixture, _ := newFixture(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	fixture.refs.now = func() time.Time { return now }
	reference, err := fixture.refs.Issue(ReferenceItem, "alice", "alice", "session", "item")
	if err != nil {
		t.Fatal(err)
	}
	fixture.refs.now = func() time.Time { return now.Add(31 * time.Minute) }
	if _, err := fixture.refs.Resolve(reference, ReferenceItem, "alice", "session"); !errors.Is(err, ErrReferenceExpired) {
		t.Fatalf("Resolve() error = %v, want expired", err)
	}
}

func TestItemResourceURIRejectsNonCanonicalInputs(t *testing.T) {
	for _, rawURI := range []string{
		"file:///etc/passwd",
		"veksel://user@item/reference",
		"veksel://item/reference%2Fchild",
		"veksel://item/reference?path=/etc/passwd",
		"veksel://item/reference?offset=0&offset=1",
		"veksel://item/reference?offset=-1",
		"veksel://item/reference#fragment",
	} {
		t.Run(rawURI, func(t *testing.T) {
			if _, _, err := parseItemResourceURI(rawURI); !errors.Is(err, ErrReferenceInvalid) {
				t.Fatalf("parseItemResourceURI(%q) error = %v, want invalid", rawURI, err)
			}
		})
	}
}

func TestAttachmentResourceURIRejectsNonCanonicalInputs(t *testing.T) {
	for _, rawURI := range []string{
		"veksel://item/reference", "veksel://attachment/reference/part", "veksel://user@attachment/reference",
		"veksel://attachment/reference?offset=-1", "veksel://attachment/reference?part=1.2", "veksel://attachment/reference#fragment",
	} {
		if _, _, err := parseAttachmentResourceURI(rawURI); !errors.Is(err, ErrReferenceInvalid) {
			t.Fatalf("parseAttachmentResourceURI(%q) error = %v, want invalid", rawURI, err)
		}
	}
}
