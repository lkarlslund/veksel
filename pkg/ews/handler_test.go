package ews

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestMaintenanceMapsToServerBusy(t *testing.T) {
	code, message := ewsError(account.ErrTemporarilyUnavailable)
	if code != "ErrorServerBusy" || !strings.Contains(message, "retry") {
		t.Fatalf("maintenance mapping = %q, %q", code, message)
	}
}

func TestExpiredJournalMapsToInvalidSyncState(t *testing.T) {
	code, message := ewsError(service.ErrChangeStateExpired)
	if code != "ErrorInvalidSyncStateData" || !strings.Contains(message, "full synchronization") {
		t.Fatalf("expired state mapping = %q, %q", code, message)
	}
}

func TestExpectedModSeqUsesDocumentedConflictModes(t *testing.T) {
	for _, test := range []struct {
		name       string
		resolution string
		changeKey  string
		current    uint64
		want       uint64
		wantError  bool
	}{
		{name: "default auto resolve", changeKey: "7", current: 9, want: 7},
		{name: "explicit auto resolve", resolution: "AutoResolve", changeKey: "7", current: 9, want: 7},
		{name: "never overwrite", resolution: "NeverOverwrite", changeKey: "7", current: 9, want: 7},
		{name: "always overwrite snapshots current", resolution: "AlwaysOverwrite", current: 9, want: 9},
		{name: "auto resolve requires key", resolution: "AutoResolve", current: 9, wantError: true},
		{name: "unknown mode", resolution: "Merge", changeKey: "7", current: 9, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ewsExpectedModSeq(test.resolution, test.changeKey, test.current)
			if (err != nil) != test.wantError || got != test.want {
				t.Fatalf("ewsExpectedModSeq(%q, %q, %d) = %d, %v; want %d, error=%t", test.resolution, test.changeKey, test.current, got, err, test.want, test.wantError)
			}
		})
	}
}

func TestQuotaMapsToQuotaExceeded(t *testing.T) {
	code, message := ewsError(model.ErrQuotaExceeded)
	if code != "ErrorQuotaExceeded" || !strings.Contains(message, "quota") {
		t.Fatalf("quota mapping = %q, %q", code, message)
	}
}

func testHandler(t *testing.T) (*Handler, *service.FolderSpaceService) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(ts, authz.New(ts))
	handler, err := New(Config{
		Space: space,
		Authenticate: func(_ context.Context, username, password string) (string, error) {
			if (username == "alice" || username == "bob") && password == "secret" {
				return username, nil
			}
			return "", context.Canceled
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, space
}

func ewsRequest(t *testing.T, handler http.Handler, operation string) *httptest.ResponseRecorder {
	return ewsRequestAs(t, handler, operation, "alice", "secret")
}

func ewsRequestAs(t *testing.T, handler http.Handler, operation, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body := `<s:Envelope xmlns:s="` + soapNS + `" xmlns:m="` + msgNS + `" xmlns:t="` + typeNS + `"><s:Body>` + operation + `</s:Body></s:Envelope>`
	request := httptest.NewRequest(http.MethodPost, "/EWS/Exchange.asmx", strings.NewReader(body))
	request.SetBasicAuth(username, password)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestUpdateItemPreservesMIMEAndReturnsChangeKey(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Subject: Before\r\nImportance: low\r\nX-Priority: 5\r\nPriority: non-urgent\r\nX-Custom: first\r\n\tcontinued\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody stays byte-for-byte\r\n")
	created, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: raw, Headers: model.ParseItemHeaders(raw)})
	if err != nil {
		t.Fatal(err)
	}
	operation := `<m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AutoResolve"><m:ItemChanges><t:ItemChange><t:ItemId Id="` + encodeID("i:", created.ID) + `" ChangeKey="` + strconv.FormatUint(created.ModSeq, 10) + `"/><t:Updates>` +
		`<t:SetItemField><t:FieldURI FieldURI="item:Subject"/><t:Message><t:Subject>After &amp; retained</t:Subject></t:Message></t:SetItemField>` +
		`<t:SetItemField><t:FieldURI FieldURI="item:Importance"/><t:Message><t:Importance>High</t:Importance></t:Message></t:SetItemField>` +
		`</t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>`
	response := ewsRequest(t, handler, operation)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "UpdateItemResponse") {
		t.Fatalf("update response: status=%d body=%s", response.Code, response.Body.String())
	}
	updated, err := space.GetItem(t.Context(), access, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ModSeq <= created.ModSeq || !strings.Contains(response.Body.String(), `ChangeKey="`+strconv.FormatUint(updated.ModSeq, 10)+`"`) {
		t.Fatalf("updated mod-sequence=%d original=%d response=%s", updated.ModSeq, created.ModSeq, response.Body.String())
	}
	got := string(updated.Data)
	for _, retained := range []string{"X-Custom: first\r\n\tcontinued", "\r\n\r\nbody stays byte-for-byte\r\n", "Subject: After & retained", "Importance: high", "X-Priority: 1", "Priority: urgent"} {
		if !strings.Contains(got, retained) {
			t.Errorf("updated MIME omitted %q:\n%s", retained, got)
		}
	}
	if service.MessageImportance(updated.Headers) != service.MailImportanceHigh || updated.Headers["Subject"] != "After & retained" {
		t.Fatalf("updated headers=%#v", updated.Headers)
	}
}

func TestUpdateItemSimpleBodyAndFullMIMEReplacement(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	raw := []byte("Subject: Draft\r\nX-Keep: yes\r\nContent-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: base64\r\n\r\nb2xk")
	created, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: raw, Headers: model.ParseItemHeaders(raw)})
	if err != nil {
		t.Fatal(err)
	}
	bodyUpdate := `<m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="NeverOverwrite"><m:ItemChanges><t:ItemChange><t:ItemId Id="` + encodeID("i:", created.ID) + `" ChangeKey="` + strconv.FormatUint(created.ModSeq, 10) + `"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="item:Body"/><t:Message><t:Body BodyType="HTML">  &lt;p&gt;new &amp; exact&lt;/p&gt;  </t:Body></t:Message></t:SetItemField></t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>`
	response := ewsRequest(t, handler, bodyUpdate)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "Fault") {
		t.Fatalf("body update response: %s", response.Body.String())
	}
	updated, _ := space.GetItem(t.Context(), access, created.ID)
	got := string(updated.Data)
	for _, expected := range []string{"X-Keep: yes", `Content-Type: text/html; charset="utf-8"`, "Content-Transfer-Encoding: 8bit", "\r\n\r\n  <p>new & exact</p>  "} {
		if !strings.Contains(got, expected) {
			t.Errorf("body update omitted %q:\n%s", expected, got)
		}
	}
	replacement := []byte("Subject: Replaced\r\nX-New: true\r\n\r\nreplacement body")
	mimeUpdate := `<m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AlwaysOverwrite"><m:ItemChanges><t:ItemChange><t:ItemId Id="` + encodeID("i:", created.ID) + `"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="item:MimeContent"/><t:Message><t:MimeContent>` + base64.StdEncoding.EncodeToString(replacement) + `</t:MimeContent></t:Message></t:SetItemField></t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>`
	response = ewsRequest(t, handler, mimeUpdate)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "Fault") {
		t.Fatalf("MIME update response: %s", response.Body.String())
	}
	updated, _ = space.GetItem(t.Context(), access, created.ID)
	if string(updated.Data) != string(replacement) || updated.Headers["Subject"] != "Replaced" {
		t.Fatalf("full replacement data=%q headers=%#v", updated.Data, updated.Headers)
	}
}

func TestUpdateItemRejectsStaleUnsupportedAndMultipartWithoutEffects(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	raw := []byte("Subject: Original\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nbody\r\n--x--\r\n")
	created, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: raw, Headers: model.ParseItemHeaders(raw)})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := space.UpdateItem(t.Context(), access, created.ID, bytes.ReplaceAll(raw, []byte("Original"), []byte("Current")), map[string]string{"Subject": "Current", "Content-Type": "multipart/mixed; boundary=x"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(changeKey, field, value string) *httptest.ResponseRecorder {
		return ewsRequest(t, handler, `<m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AutoResolve"><m:ItemChanges><t:ItemChange><t:ItemId Id="`+encodeID("i:", created.ID)+`" ChangeKey="`+changeKey+`"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="`+field+`"/><t:Message>`+value+`</t:Message></t:SetItemField></t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>`)
	}
	stale := request(strconv.FormatUint(created.ModSeq, 10), "item:Subject", `<t:Subject>Stale</t:Subject>`)
	if !strings.Contains(stale.Body.String(), "ErrorIrresolvableConflict") {
		t.Fatalf("stale response: %s", stale.Body.String())
	}
	unsupported := request(strconv.FormatUint(updated.ModSeq, 10), "calendar:Start", `<t:Start>2026-01-01T00:00:00Z</t:Start>`)
	if !strings.Contains(unsupported.Body.String(), "ErrorInvalidPropertyRequest") {
		t.Fatalf("unsupported response: %s", unsupported.Body.String())
	}
	multipart := request(strconv.FormatUint(updated.ModSeq, 10), "item:Body", `<t:Body BodyType="Text">changed</t:Body>`)
	if !strings.Contains(multipart.Body.String(), "ErrorInvalidPropertyRequest") {
		t.Fatalf("multipart response: %s", multipart.Body.String())
	}
	malformed := request(strconv.FormatUint(updated.ModSeq, 10), "item:MimeContent", `<t:MimeContent>not-base64***</t:MimeContent>`)
	if !strings.Contains(malformed.Body.String(), "ErrorInvalidPropertyRequest") {
		t.Fatalf("malformed MIME response: %s", malformed.Body.String())
	}
	stored, _ := space.GetItem(t.Context(), access, created.ID)
	if stored.ModSeq != updated.ModSeq || string(stored.Data) != string(updated.Data) {
		t.Fatalf("rejected requests changed item: before=%d/%q after=%d/%q", updated.ModSeq, updated.Data, stored.ModSeq, stored.Data)
	}
}

func TestUpdateItemHonorsFolderSpaceRBAC(t *testing.T) {
	handler, space := testHandler(t)
	alice := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), alice, "INBOX")
	raw := []byte("Subject: Private\r\n\r\nbody")
	created, err := space.CreateItem(t.Context(), alice, inbox.ID, service.ItemInput{Data: raw, Headers: model.ParseItemHeaders(raw)})
	if err != nil {
		t.Fatal(err)
	}
	operation := `<m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AutoResolve"><m:ItemChanges><t:ItemChange><t:ItemId Id="` + encodeID("i:", created.ID) + `" ChangeKey="` + strconv.FormatUint(created.ModSeq, 10) + `"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="item:Subject"/><t:Message><t:Subject>Leaked</t:Subject></t:Message></t:SetItemField></t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>`
	response := ewsRequestAs(t, handler, operation, "bob", "secret")
	if !strings.Contains(response.Body.String(), "ErrorAccessDenied") {
		t.Fatalf("RBAC response: %s", response.Body.String())
	}
	stored, _ := space.GetItem(t.Context(), alice, created.ID)
	if stored.ModSeq != created.ModSeq || string(stored.Data) != string(raw) {
		t.Fatal("unauthorized EWS update changed the item")
	}
}

func TestFindFolderUsesFolderSpace(t *testing.T) {
	handler, _ := testHandler(t)
	response := ewsRequest(t, handler, `<m:FindFolder><m:ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/></m:ParentFolderIds></m:FindFolder>`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "INBOX") || !strings.Contains(response.Body.String(), "FindFolderResponse") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestCreateAndGetMIMEItem(t *testing.T) {
	handler, _ := testHandler(t)
	raw := "Subject: Migrated\r\nFrom: sender@example.test\r\n\r\nhello"
	create := `<m:CreateItem><m:SavedItemFolderId><t:DistinguishedFolderId Id="inbox"/></m:SavedItemFolderId><m:Items><t:Message><t:MimeContent>` + base64.StdEncoding.EncodeToString([]byte(raw)) + `</t:MimeContent></t:Message></m:Items></m:CreateItem>`
	response := ewsRequest(t, handler, create)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "CreateItemResponse") {
		t.Fatalf("create response: status=%d body=%s", response.Code, response.Body.String())
	}

	access := service.UserAccess("alice", "test")
	inbox, err := handler.space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	items, err := handler.space.ListItems(t.Context(), access, inbox.ID, service.ItemQuery{})
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%v err=%v", items, err)
	}
	get := `<m:GetItem><m:ItemIds><t:ItemId Id="` + encodeID("i:", items[0].ID) + `"/></m:ItemIds></m:GetItem>`
	response = ewsRequest(t, handler, get)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), base64.StdEncoding.EncodeToString([]byte(raw))) {
		t.Fatalf("get response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCreateAndGetStructuredItemImportance(t *testing.T) {
	handler, _ := testHandler(t)
	create := `<m:CreateItem><m:SavedItemFolderId><t:DistinguishedFolderId Id="inbox"/></m:SavedItemFolderId><m:Items><t:Message><t:Subject>Urgent</t:Subject><t:Importance>High</t:Importance><t:Body BodyType="Text">Read me</t:Body></t:Message></m:Items></m:CreateItem>`
	response := ewsRequest(t, handler, create)
	if response.Code != http.StatusOK {
		t.Fatalf("create response: status=%d body=%s", response.Code, response.Body.String())
	}
	access := service.UserAccess("alice", "test")
	inbox, err := handler.space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	items, err := handler.space.ListItems(t.Context(), access, inbox.ID, service.ItemQuery{})
	if err != nil || len(items) != 1 || service.MessageImportance(items[0].Headers) != service.MailImportanceHigh {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	get := `<m:GetItem><m:ItemIds><t:ItemId Id="` + encodeID("i:", items[0].ID) + `"/></m:ItemIds></m:GetItem>`
	response = ewsRequest(t, handler, get)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<t:Importance>High</t:Importance>") {
		t.Fatalf("get response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestEWSImportanceMapsConventionalHeaders(t *testing.T) {
	for _, test := range []struct {
		headers map[string]string
		want    string
	}{
		{headers: nil, want: "Normal"},
		{headers: map[string]string{"Priority": "non-urgent"}, want: "Low"},
		{headers: map[string]string{"X-Priority": "2"}, want: "High"},
	} {
		if got := ewsImportance(test.headers); got != test.want {
			t.Errorf("ewsImportance(%v) = %q, want %q", test.headers, got, test.want)
		}
	}
}

func TestEWSRequiresAuthentication(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/EWS/Exchange.asmx", strings.NewReader(`<s:Envelope xmlns:s="`+soapNS+`"><s:Body/></s:Envelope>`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestFindItemHonorsIndexedPaging(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"one", "two", "three"} {
		if _, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: " + subject + "\r\n\r\n")}); err != nil {
			t.Fatal(err)
		}
	}
	operation := `<m:FindItem><m:IndexedPageItemView MaxEntriesReturned="1" Offset="1" BasePoint="Beginning"/><m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></m:ParentFolderIds></m:FindItem>`
	response := ewsRequest(t, handler, operation)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Count(body, "<t:Message>") != 1 || !strings.Contains(body, `TotalItemsInView="3"`) || !strings.Contains(body, `IndexedPagingOffset="2"`) || !strings.Contains(body, `IncludesLastItemInRange="false"`) {
		t.Fatalf("unexpected paged response: %s", body)
	}
}

func TestCreateItemSendDispositionSubmitsMIME(t *testing.T) {
	handler, _ := testHandler(t)
	var submitted []byte
	handler.submit = func(_ context.Context, userID string, raw []byte) error {
		if userID != "alice" {
			t.Fatalf("userID=%q", userID)
		}
		submitted = append([]byte(nil), raw...)
		return nil
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@example.test\r\nSubject: EWS\r\n\r\nhello")
	operation := `<m:CreateItem MessageDisposition="SendAndSaveCopy"><m:Items><t:Message><t:MimeContent>` + base64.StdEncoding.EncodeToString(raw) + `</t:MimeContent></t:Message></m:Items></m:CreateItem>`
	response := ewsRequest(t, handler, operation)
	if response.Code != http.StatusOK || string(submitted) != string(raw) || !strings.Contains(response.Body.String(), "CreateItemResponse") {
		t.Fatalf("status=%d submitted=%q body=%s", response.Code, submitted, response.Body.String())
	}
}

func TestCopyItemKeepsSourceAndEmptyFolderKeepsFolder(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	archive, _ := space.GetFolderByPath(t.Context(), access, "Archive")
	item, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: copy\r\n\r\n")})
	if err != nil {
		t.Fatal(err)
	}
	copyRequest := `<m:CopyItem><m:ToFolderId><t:FolderId Id="` + encodeID("f:", archive.ID) + `"/></m:ToFolderId><m:ItemIds><t:ItemId Id="` + encodeID("i:", item.ID) + `"/></m:ItemIds></m:CopyItem>`
	if response := ewsRequest(t, handler, copyRequest); response.Code != http.StatusOK {
		t.Fatalf("copy status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := space.GetItem(t.Context(), access, item.ID); err != nil {
		t.Fatalf("copy removed source: %v", err)
	}
	copies, _ := space.ListItems(t.Context(), access, archive.ID, service.ItemQuery{})
	if len(copies) != 1 {
		t.Fatalf("archive copies=%d", len(copies))
	}
	emptyRequest := `<m:EmptyFolder><m:FolderIds><t:FolderId Id="` + encodeID("f:", archive.ID) + `"/></m:FolderIds></m:EmptyFolder>`
	if response := ewsRequest(t, handler, emptyRequest); response.Code != http.StatusOK {
		t.Fatalf("empty status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := space.GetFolder(t.Context(), access, archive.ID); err != nil {
		t.Fatalf("empty removed folder: %v", err)
	}
	copies, _ = space.ListItems(t.Context(), access, archive.ID, service.ItemQuery{})
	if len(copies) != 0 {
		t.Fatalf("items after empty=%d", len(copies))
	}
}

func TestSyncFolderItemsPagesAndReportsDeletion(t *testing.T) {
	handler, space := testHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	var items []model.Item
	for _, subject := range []string{"one", "two", "three"} {
		item, createErr := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: " + subject + "\r\n\r\n")})
		if createErr != nil {
			t.Fatal(createErr)
		}
		items = append(items, item)
	}
	operation := `<m:SyncFolderItems><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape><m:SyncFolderId><t:FolderId Id="` + encodeID("f:", inbox.ID) + `"/></m:SyncFolderId><m:MaxChangesReturned>2</m:MaxChangesReturned></m:SyncFolderItems>`
	first := ewsRequest(t, handler, operation)
	if first.Code != http.StatusOK || strings.Count(first.Body.String(), "<t:Create>") != 2 || !strings.Contains(first.Body.String(), "<m:IncludesLastItemInRange>false") {
		t.Fatalf("first sync: status=%d body=%s", first.Code, first.Body.String())
	}
	state := xmlElementText(first.Body.String(), "m:SyncState")
	second := ewsRequest(t, handler, strings.Replace(operation, "<m:ItemShape>", "<m:SyncState>"+state+"</m:SyncState><m:ItemShape>", 1))
	if second.Code != http.StatusOK || strings.Count(second.Body.String(), "<t:Create>") != 1 || !strings.Contains(second.Body.String(), "<m:IncludesLastItemInRange>true") {
		t.Fatalf("second sync: status=%d body=%s", second.Code, second.Body.String())
	}
	if err := space.DeleteItem(t.Context(), access, items[0].ID); err != nil {
		t.Fatal(err)
	}
	state = xmlElementText(second.Body.String(), "m:SyncState")
	deleted := ewsRequest(t, handler, strings.Replace(operation, "<m:ItemShape>", "<m:SyncState>"+state+"</m:SyncState><m:ItemShape>", 1))
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), "<t:Delete>") || !strings.Contains(deleted.Body.String(), encodeID("i:", items[0].ID)) {
		t.Fatalf("deletion sync: status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}

func xmlElementText(document, name string) string {
	startTag, endTag := "<"+name+">", "</"+name+">"
	start := strings.Index(document, startTag)
	if start < 0 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(document[start:], endTag)
	if end < 0 {
		return ""
	}
	return document[start : start+end]
}
