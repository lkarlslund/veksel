package jmap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/background"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestMaintenanceMapsToRetryableServerFail(t *testing.T) {
	got := serverError(account.ErrTemporarilyUnavailable)
	if got.Type != "serverFail" || got.Description != "account temporarily unavailable; retry later" {
		t.Fatalf("maintenance mapping = %+v", got)
	}
}

func TestQuotaMapsToOverQuota(t *testing.T) {
	got := serverError(model.ErrQuotaExceeded)
	if got.Type != "overQuota" || got.Description != "account quota exceeded" {
		t.Fatalf("quota mapping = %+v", got)
	}
}

func TestJMAPSearchFilterCoversMailboxKeywordAttachmentAndHeader(t *testing.T) {
	filter, err := jmapSearchFilter(map[string]any{
		"inMailbox":          "alice:inbox",
		"inMailboxOtherThan": []any{"alice:trash", "alice:junk"},
		"hasKeyword":         "$seen",
		"notKeyword":         "$draft",
		"hasAttachment":      true,
		"header":             []any{"List-Id", "example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if filter == nil || filter.Operator != service.SearchAll || len(filter.Children) != 7 {
		t.Fatalf("translated filter = %+v", filter)
	}
	if filter.Children[1].Operator != service.SearchNot || filter.Children[2].Value != model.FlagSeen || filter.Children[3].Children[0].Value != model.FlagDraft {
		t.Fatalf("mailbox/keyword translation = %+v", filter.Children)
	}
}

func TestJMAPSearchFilterNOTMatchesNoneOfSeveralConditions(t *testing.T) {
	filter, err := jmapSearchFilter(map[string]any{"operator": "NOT", "conditions": []any{
		map[string]any{"subject": "one"}, map[string]any{"subject": "two"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// RFC 8620 §5.5: NOT matches when none of its conditions match.
	if filter.Operator != service.SearchNot || len(filter.Children) != 1 || filter.Children[0].Operator != service.SearchAny || len(filter.Children[0].Children) != 2 {
		t.Fatalf("NOT filter = %+v", filter)
	}
}

type fixture struct {
	handler  *Handler
	ts       *model.TypedStore
	space    service.FolderSpace
	server   *httptest.Server
	cfg      Config
	accounts *testAccounts
	group    *background.Group
}

func newFixture(t *testing.T) *fixture {
	return buildFixture(t, nil)
}

// buildFixture creates the alice/bob test server; wrap may decorate the
// folder space (for example with automation and iMIP observers).
func buildFixture(t *testing.T, wrap func(*model.TypedStore, store.Store, service.FolderSpace) service.FolderSpace) *fixture {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, ns := range model.Namespaces() {
		if err := ts.EnsureNamespace(t.Context(), ns); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"alice", "bob"} {
		if err := ts.UserStore().Create(t.Context(), id, strings.ToUpper(id), "password"); err != nil {
			t.Fatal(err)
		}
		if err := ts.FolderStore().CreateForUser(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	var space service.FolderSpace = service.NewFolderSpace(ts, authz.New(ts))
	if wrap != nil {
		space = wrap(ts, backend, space)
	}
	accounts := &testAccounts{root: t.TempDir()}
	t.Cleanup(accounts.close)
	f := &fixture{ts: ts, space: space, accounts: accounts, cfg: Config{Space: space, Authorizer: authz.New(ts), Directory: NewModelDirectory(ts), PushInterval: 20 * time.Millisecond,
		Accounts: accounts, State: backend,
		Authenticate: func(_ context.Context, user, pass string) (model.User, error) {
			if pass != "password" {
				return model.User{}, store.ErrNotFound
			}
			return ts.UserStore().Get(t.Context(), user)
		}}}
	f.start(t)
	return f
}

// start builds a handler, its background group and its server over the
// fixture's stores; restart does it again as a process restart would.
func (f *fixture) start(t *testing.T) {
	t.Helper()
	group := background.New(context.Background())
	t.Cleanup(group.Stop)
	cfg := f.cfg
	cfg.Go = group.Go
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	f.handler, f.group, f.server = h, group, server
}

// restart stops the handler's background work, closes and reopens the
// account stores, and starts a fresh handler over them.
func (f *fixture) restart(t *testing.T) {
	t.Helper()
	f.group.Stop()
	f.server.Close()
	f.accounts.close()
	f.start(t)
}

// testAccounts gives every account its own store directory, as the account
// manager gives every account its own index.
type testAccounts struct {
	root   string
	mu     sync.Mutex
	open   map[string]store.Store
	purged map[string]bool
}

func (a *testAccounts) WithIndex(ctx context.Context, accountID string, fn func(context.Context, store.Store) error) error {
	a.mu.Lock()
	if a.purged[accountID] {
		a.mu.Unlock()
		return store.ErrNotFound
	}
	index, ok := a.open[accountID]
	if !ok {
		var err error
		if index, err = jsonstore.New(filepath.Join(a.root, accountID)); err != nil {
			a.mu.Unlock()
			return err
		}
		if a.open == nil {
			a.open = map[string]store.Store{}
		}
		a.open[accountID] = index
	}
	a.mu.Unlock()
	return fn(ctx, index)
}

func (a *testAccounts) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, index := range a.open {
		_ = index.Close()
		delete(a.open, id)
	}
}

// purge removes an account's storage the way Manager.Purge does.
func (a *testAccounts) purge(t *testing.T, accountID string) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if index, ok := a.open[accountID]; ok {
		_ = index.Close()
		delete(a.open, accountID)
	}
	if err := os.RemoveAll(filepath.Join(a.root, accountID)); err != nil {
		t.Fatal(err)
	}
	if a.purged == nil {
		a.purged = map[string]bool{}
	}
	a.purged[accountID] = true
}

func (f *fixture) request(t *testing.T, method, path, body, user, pass string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func decodeResponse(t *testing.T, r *http.Response) map[string]any {
	t.Helper()
	defer r.Body.Close()
	var value map[string]any
	if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSessionDiscoveryRequiresAuthenticationAndAdvertisesRFCURLs(t *testing.T) {
	f := newFixture(t)
	unauth := f.request(t, "GET", "/.well-known/jmap", "", "", "")
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", unauth.StatusCode)
	}
	unauth.Body.Close()
	response := f.request(t, "GET", "/.well-known/jmap", "", "alice", "password")
	if response.StatusCode != 200 {
		t.Fatalf("status=%d", response.StatusCode)
	}
	session := decodeResponse(t, response)
	if session["username"] != "alice" || session["apiUrl"] != f.server.URL+"/jmap/api" {
		t.Fatalf("session=%#v", session)
	}
	caps := session["capabilities"].(map[string]any)
	for _, cap := range []string{CoreCapability, MailCapability, SubmissionCapability, VacationCapability} {
		if _, ok := caps[cap]; !ok {
			t.Errorf("missing capability %s", cap)
		}
	}
	accounts := session["accounts"].(map[string]any)
	if len(accounts) != 1 || accounts["alice"] == nil {
		t.Fatalf("accounts=%#v", accounts)
	}
}

func TestCoreEchoAndUnknownMethod(t *testing.T) {
	f := newFixture(t)
	body := `{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{"hello":"world"},"a"],["Nope/get",{},"b"]]}`
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "alice", "password"))
	calls := v["methodResponses"].([]any)
	first := calls[0].([]any)
	if first[0] != "Core/echo" || first[1].(map[string]any)["hello"] != "world" {
		t.Fatalf("first=%#v", first)
	}
	second := calls[1].([]any)
	if second[0] != "error" || second[1].(map[string]any)["type"] != "unknownMethod" {
		t.Fatalf("second=%#v", second)
	}
}

func TestMailboxAndEmailGetUseFolderSpace(t *testing.T) {
	f := newFixture(t)
	access := service.UserAccess("alice", "test")
	inbox, err := f.space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: Sender <sender@example.test>\r\nTo: Alice <alice@example.test>\r\nSubject: Hello JMAP\r\nMessage-ID: <one@example.test>\r\nDate: Tue, 15 Aug 2023 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMessage body")
	item, err := f.space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: raw, Flags: []string{model.FlagSeen}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/get",{"accountId":"alice"},"m"],["Email/get",{"accountId":"alice","ids":["` + item.ID + `"],"fetchTextBodyValues":true},"e"]]}`
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "alice", "password"))
	calls := v["methodResponses"].([]any)
	mailboxes := calls[0].([]any)[1].(map[string]any)["list"].([]any)
	if len(mailboxes) < 6 {
		t.Fatalf("mailboxes=%d", len(mailboxes))
	}
	emails := calls[1].([]any)[1].(map[string]any)["list"].([]any)
	email := emails[0].(map[string]any)
	if email["subject"] != "Hello JMAP" || email["preview"] != "Message body" {
		t.Fatalf("email=%#v", email)
	}
	if !email["keywords"].(map[string]any)["$seen"].(bool) {
		t.Fatal("seen keyword missing")
	}
}

func TestMailboxSetCreateUpdateDestroy(t *testing.T) {
	f := newFixture(t)
	body := `{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/set",{"accountId":"alice","create":{"work":{"name":"Work","isSubscribed":true}}},"a"],["Mailbox/set",{"accountId":"alice","update":{"#work":{"name":"Projects"}}},"b"]]}`
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "alice", "password"))
	calls := v["methodResponses"].([]any)
	created := calls[0].([]any)[1].(map[string]any)["created"].(map[string]any)["work"].(map[string]any)["id"].(string)
	if _, err := f.space.GetFolder(t.Context(), service.UserAccess("alice", "test"), created); err != nil {
		t.Fatal(err)
	}
	second := calls[1].([]any)
	if second[0] != "Mailbox/set" {
		t.Fatalf("response=%#v", second)
	}
}

func TestFolderShareIsVisibleButCannotWrite(t *testing.T) {
	f := newFixture(t)
	alice := service.UserAccess("alice", "test")
	inbox, err := f.space.GetFolderByPath(t.Context(), alice, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	_, err = model.NewPolicyStore(f.ts).Create(t.Context(), model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: inbox.ID}, Effect: model.EffectAllow, RoleID: authz.RoleFolderViewer, Inheritance: model.InheritanceSelf, GrantedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	session := decodeResponse(t, f.request(t, "GET", "/.well-known/jmap", "", "bob", "password"))
	if session["accounts"].(map[string]any)["alice"] == nil {
		t.Fatalf("shared account absent: %#v", session["accounts"])
	}
	read := `{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/get",{"accountId":"alice"},"r"],["Email/set",{"accountId":"alice","create":{"x":{"mailboxIds":{"` + inbox.ID + `":true},"subject":"forbidden"}}},"w"]]}`
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", read, "bob", "password"))
	calls := v["methodResponses"].([]any)
	if len(calls[0].([]any)[1].(map[string]any)["list"].([]any)) != 1 {
		t.Fatal("share leaked other folders")
	}
	notCreated := calls[1].([]any)[1].(map[string]any)["notCreated"].(map[string]any)
	if notCreated["x"] == nil {
		t.Fatalf("write unexpectedly succeeded: %#v", calls[1])
	}
}

func TestAccountDelegateWritesTargetAccountAndMayReadMetadata(t *testing.T) {
	f := newFixture(t)
	_, err := model.NewPolicyStore(f.ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"},
		Effect:    model.EffectAllow, RoleID: authz.RoleAccountDelegate,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"using":["urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission"],"methodCalls":[["Mailbox/set",{"accountId":"alice","create":{"delegated":{"name":"Delegated"}}},"m"],["Identity/get",{"accountId":"alice"},"i"]]}`
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "bob", "password"))
	calls := v["methodResponses"].([]any)
	created := calls[0].([]any)[1].(map[string]any)["created"].(map[string]any)["delegated"].(map[string]any)["id"].(string)
	folder, err := f.ts.FolderStore().Get(t.Context(), created)
	if err != nil || folder.UserID != "alice" {
		t.Fatalf("folder=%#v err=%v", folder, err)
	}
	identities := calls[1].([]any)[1].(map[string]any)["list"].([]any)
	if len(identities) != 1 || identities[0].(map[string]any)["email"] != "alice@example.test" {
		t.Fatalf("identities=%#v", identities)
	}
}

func TestUnsharedAccountIsNotDiscoverable(t *testing.T) {
	f := newFixture(t)
	body := `{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/get",{"accountId":"alice"},"x"]]}`
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "bob", "password"))
	call := v["methodResponses"].([]any)[0].([]any)
	if call[0] != "error" || call[1].(map[string]any)["type"] != "accountNotFound" {
		t.Fatalf("response=%#v", call)
	}
}

func TestUploadAndDownloadAreRBACScopedFolderItems(t *testing.T) {
	f := newFixture(t)
	req, err := http.NewRequest("POST", f.server.URL+"/jmap/upload/alice", bytes.NewBufferString("blob body"))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("alice", "password")
	req.Header.Set("Content-Type", "text/plain")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	uploaded := decodeResponse(t, response)
	blobID := uploaded["blobId"].(string)
	download := f.request(t, "GET", "/jmap/download/alice/"+blobID+"/note.txt", "", "alice", "password")
	data, _ := io.ReadAll(download.Body)
	download.Body.Close()
	if string(data) != "blob body" {
		t.Fatalf("data=%q", data)
	}
	denied := f.request(t, "GET", "/jmap/download/alice/"+blobID+"/note.txt", "", "bob", "password")
	if denied.StatusCode != 404 {
		t.Fatalf("cross-account status=%d", denied.StatusCode)
	}
	denied.Body.Close()
}

func TestVacationSingletonRoundTrip(t *testing.T) {
	f := newFixture(t)
	body := `{"using":["urn:ietf:params:jmap:vacationresponse"],"methodCalls":[["VacationResponse/set",{"accountId":"alice","update":{"singleton":{"isEnabled":true,"fromDate":"2026-08-16","subject":"Away","textBody":"On holiday"}}},"s"],["VacationResponse/get",{"accountId":"alice"},"g"]]}`
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "alice", "password"))
	calls := v["methodResponses"].([]any)
	vacation := calls[1].([]any)[1].(map[string]any)["list"].([]any)[0].(map[string]any)
	if vacation["isEnabled"] != true || vacation["textBody"] != "On holiday" {
		t.Fatalf("vacation=%#v", vacation)
	}
}

func TestResultReferenceAndJSONPointer(t *testing.T) {
	prior := map[string][]methodResult{"a": {{name: "Email/query", value: map[string]any{"ids": []string{"one", "two"}}}}}
	raw, err := resolveReferences(json.RawMessage(`{"accountId":"alice","#ids":{"resultOf":"a","name":"Email/query","path":"/ids"}}`), prior)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if len(value["ids"].([]any)) != 2 {
		t.Fatalf("value=%#v", value)
	}
	if _, err := jsonPointer(value, "not-a-pointer"); err == nil {
		t.Fatal("invalid pointer accepted")
	}
}

func TestChangesCurrentAndStaleState(t *testing.T) {
	f := newFixture(t)
	state, err := f.handler.journalState(t.Context(), accountAccess("alice", "alice"), service.ChangeObjectFolder)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/changes",{"accountId":"alice","sinceState":"` + state + `"},"same"],["Mailbox/changes",{"accountId":"alice","sinceState":"old"},"old"]]}`
	v := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "alice", "password"))
	calls := v["methodResponses"].([]any)
	if calls[0].([]any)[0] != "Mailbox/changes" || calls[1].([]any)[1].(map[string]any)["type"] != "cannotCalculateChanges" {
		t.Fatalf("calls=%#v", calls)
	}
}

func TestEmailChangesUsesRetainedJournal(t *testing.T) {
	f := newFixture(t)
	access := accountAccess("alice", "alice")
	state, err := f.handler.journalState(t.Context(), access, service.ChangeObjectItem)
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := f.space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: changed\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.space.SetFlags(t.Context(), access, created.ID, []string{model.FlagSeen}); err != nil {
		t.Fatal(err)
	}
	body := `{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/changes",{"accountId":"alice","sinceState":"` + state + `"},"changes"]]}`
	response := decodeResponse(t, f.request(t, "POST", "/jmap/api", body, "alice", "password"))
	call := response["methodResponses"].([]any)[0].([]any)
	result := call[1].(map[string]any)
	createdIDs := result["created"].([]any)
	if call[0] != "Email/changes" || len(createdIDs) != 1 || createdIDs[0] != created.ID || len(result["updated"].([]any)) != 0 {
		t.Fatalf("changes=%#v", call)
	}
}

func TestMIMEParsingMultipartAndTruncation(t *testing.T) {
	boundary := "b"
	raw := []byte("Subject: Multipart\r\nContent-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhello world\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=x.bin\r\n\r\nabc\r\n--b--\r\n")
	view := newEmailView(model.Item{ID: "i", FolderID: "f", Data: raw, Size: int64(len(raw)), InternalDate: time.Now()}, "i", raw)
	values := view.bodyValues(emailOptions{fetchText: true, maxBytes: 5})
	if !view.hasAttachment() || len(view.attachments) != 1 || !values["1.1"].IsTruncated || values["1.1"].Value != "hello" {
		t.Fatalf("attachments=%v values=%#v", view.attachments, values)
	}
}

func FuzzResolveReferences(f *testing.F) {
	f.Add(`{"accountId":"alice"}`)
	f.Add(`{"#ids":{"resultOf":"x","name":"Email/query","path":"/ids"}}`)
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = resolveReferences(json.RawMessage(input), map[string][]methodResult{"x": {{name: "Email/query", value: map[string]any{"ids": []string{"a"}}}}})
	})
}
