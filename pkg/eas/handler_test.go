package eas

import (
	"context"
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

type unavailableFolderSpace struct{ service.FolderSpace }

func (s unavailableFolderSpace) ListFolders(context.Context, service.AccessContext, service.FolderQuery) ([]model.Folder, error) {
	return nil, account.ErrTemporarilyUnavailable
}

func (s unavailableFolderSpace) CurrentChangeState(context.Context, service.AccessContext, service.ChangeScope) (string, error) {
	return "", account.ErrTemporarilyUnavailable
}

func (s unavailableFolderSpace) ListChanges(context.Context, service.AccessContext, service.ChangeScope, string, int) (service.ChangePage, error) {
	return service.ChangePage{}, account.ErrTemporarilyUnavailable
}

type quotaFolderSpace struct{ service.FolderSpace }

func (s quotaFolderSpace) ListFolders(context.Context, service.AccessContext, service.FolderQuery) ([]model.Folder, error) {
	return nil, model.ErrQuotaExceeded
}

func (s quotaFolderSpace) CurrentChangeState(context.Context, service.AccessContext, service.ChangeScope) (string, error) {
	return "", model.ErrQuotaExceeded
}

func (s quotaFolderSpace) ListChanges(context.Context, service.AccessContext, service.ChangeScope, string, int) (service.ChangePage, error) {
	return service.ChangePage{}, model.ErrQuotaExceeded
}

type expiredChangeFolderSpace struct{ service.FolderSpace }

func (s expiredChangeFolderSpace) CurrentChangeState(ctx context.Context, access service.AccessContext, scope service.ChangeScope) (string, error) {
	return s.FolderSpace.(service.FolderChangeReader).CurrentChangeState(ctx, access, scope)
}

func (s expiredChangeFolderSpace) ListChanges(context.Context, service.AccessContext, service.ChangeScope, string, int) (service.ChangePage, error) {
	return service.ChangePage{}, service.ErrChangeStateExpired
}

func testEASHandler(t *testing.T) (*Handler, service.FolderSpace) {
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
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(ts, authz.New(ts))
	handler, err := New(t.Context(), Config{
		Space: space, Store: backend,
		Authenticate: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", context.Canceled
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, space
}

func easRequest(t *testing.T, handler http.Handler, command string, body *Node) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = Encode(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/Microsoft-Server-ActiveSync?Cmd="+command+"&User=alice&DeviceId=A1B2C3&DeviceType=Test", strings.NewReader(string(payload)))
	request.SetBasicAuth("alice", "secret")
	request.Header.Set("MS-ASProtocolVersion", "16.1")
	request.Header.Set("Content-Type", "application/vnd.ms-sync.wbxml")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder) *Node {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	root, err := Decode(response.Body.Bytes())
	if err != nil {
		t.Fatalf("decode response: %v; body=%x", err, response.Body.Bytes())
	}
	return root
}

func TestOptionsAdvertisesCommandsAndVersions(t *testing.T) {
	handler, _ := testEASHandler(t)
	request := httptest.NewRequest(http.MethodOptions, "/Microsoft-Server-ActiveSync", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("MS-ASProtocolCommands"), "FolderSync") || !strings.Contains(response.Header().Get("MS-ASProtocolVersions"), "16.1") {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
}

func TestSuccessfulSettingsRecordsBoundedDeviceInventory(t *testing.T) {
	handler, _ := testEASHandler(t)
	body := E(18, "Settings", E(18, "Set", E(18, "DeviceInformation",
		T(18, "Model", "Nordic Phone"), T(18, "FriendlyName", "Alice phone"),
		T(18, "OS", "TestOS 1"), T(18, "OSLanguage", "da-DK"))))
	payload, err := Encode(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/Microsoft-Server-ActiveSync?Cmd=Settings&User=alice&DeviceId=A1B2C3&DeviceType=Phone", strings.NewReader(string(payload)))
	request.SetBasicAuth("alice", "secret")
	request.Header.Set("MS-ASProtocolVersion", "16.1")
	request.Header.Set("User-Agent", "Veksel Device Test/1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	devices, err := handler.DeviceStates().List(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %#v", devices)
	}
	device := devices[0]
	if device.DeviceID != "A1B2C3" || device.DeviceType != "Phone" || device.Protocol != "16.1" || device.LastCommand != "Settings" || device.UserAgent != "Veksel Device Test/1" || device.Model != "Nordic Phone" || device.FriendlyName != "Alice phone" || device.OS != "TestOS 1" || device.OSLanguage != "da-DK" || device.FirstSeenAt.IsZero() || device.LastSeenAt.IsZero() {
		t.Fatalf("device = %#v", device)
	}
}

func TestMaintenanceReturnsRetryableHTTPResponse(t *testing.T) {
	handler, space := testEASHandler(t)
	handler.space = unavailableFolderSpace{FolderSpace: space}
	response := easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", "0")))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "5" {
		t.Fatalf("status=%d retry-after=%q body=%q", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
}

func TestQuotaReturnsInsufficientStorage(t *testing.T) {
	handler, space := testEASHandler(t)
	handler.space = quotaFolderSpace{FolderSpace: space}
	response := easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", "0")))
	if response.Code != http.StatusInsufficientStorage || !strings.Contains(response.Body.String(), "quota") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestFolderSyncAndSyncReadGenericItems(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: Hello\r\nImportance: high\r\nX-Priority: 1\r\n\r\nBody"), Headers: map[string]string{"Subject": "Hello", "Importance": "high", "X-Priority": "1"}}); err != nil {
		t.Fatal(err)
	}

	folderResponse := decodeResponse(t, easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", "0"))))
	if folderResponse.Tag != "FolderSync" || nodeText(folderResponse, "Status") != "1" {
		t.Fatalf("folder response=%#v", folderResponse)
	}
	var inboxID string
	for _, add := range folderResponse.Descendant("Changes").ChildrenNamed("Add") {
		if nodeText(add, "DisplayName") == "INBOX" {
			inboxID = nodeText(add, "ServerId")
		}
	}
	if inboxID == "" {
		t.Fatal("INBOX missing from FolderSync")
	}
	initialRequest := E(0, "Sync", E(0, "Collections", E(0, "Collection", T(0, "SyncKey", "0"), T(0, "CollectionId", inboxID))))
	initialResponse := decodeResponse(t, easRequest(t, handler, "Sync", initialRequest))
	if initialResponse.Descendant("Commands") != nil {
		t.Fatalf("initial Sync returned collection contents: %#v", initialResponse)
	}
	syncKey := nodeText(initialResponse, "SyncKey")
	if syncKey == "" || syncKey == "0" {
		t.Fatalf("initial Sync key = %q", syncKey)
	}
	syncRequest := E(0, "Sync", E(0, "Collections", E(0, "Collection", T(0, "SyncKey", syncKey), T(0, "CollectionId", inboxID), T(0, "GetChanges", "1"))))
	syncResponse := decodeResponse(t, easRequest(t, handler, "Sync", syncRequest))
	if syncResponse.Descendant("Subject") == nil || syncResponse.Descendant("Subject").Text != "Hello" {
		t.Fatalf("sync response=%#v", syncResponse)
	}
	if syncResponse.Descendant("Importance") == nil || syncResponse.Descendant("Importance").Text != "2" {
		t.Fatalf("sync importance response=%#v", syncResponse)
	}
}

func TestEASImportanceMapsConventionalHeaders(t *testing.T) {
	for _, test := range []struct {
		headers map[string]string
		want    string
	}{
		{headers: nil, want: "1"},
		{headers: map[string]string{"Importance": "low"}, want: "0"},
		{headers: map[string]string{"X-Priority": "1 (Highest)"}, want: "2"},
	} {
		if got := easImportance(test.headers); got != test.want {
			t.Errorf("easImportance(%v) = %q, want %q", test.headers, got, test.want)
		}
	}
}

func TestSyncPagesInitialItemsThenReportsDeletion(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	var items []model.Item
	for _, subject := range []string{"one", "two", "three"} {
		item, createErr := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: " + subject + "\r\n\r\n"), Headers: map[string]string{"Subject": subject}})
		if createErr != nil {
			t.Fatal(createErr)
		}
		items = append(items, item)
	}
	collectionID := encodeServerID("f:", inbox.ID)
	initial := decodeResponse(t, easRequest(t, handler, "Sync", E(0, "Sync", E(0, "Collections", E(0, "Collection",
		T(0, "SyncKey", "0"), T(0, "CollectionId", collectionID), T(0, "WindowSize", "2"))))))
	key := nodeText(initial, "SyncKey")

	first := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, key, 2)))
	if got := len(first.Descendant("Commands").ChildrenNamed("Add")); got != 2 || first.Descendant("MoreAvailable") == nil {
		t.Fatalf("first page adds=%d response=%#v", got, first)
	}
	key = nodeText(first, "SyncKey")
	second := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, key, 2)))
	if got := len(second.Descendant("Commands").ChildrenNamed("Add")); got != 1 || second.Descendant("MoreAvailable") != nil {
		t.Fatalf("second page adds=%d response=%#v", got, second)
	}

	if err := space.DeleteItem(t.Context(), access, items[0].ID); err != nil {
		t.Fatal(err)
	}
	key = nodeText(second, "SyncKey")
	deleted := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, key, 2)))
	command := deleted.Descendant("Delete")
	if command == nil || nodeText(command, "ServerId") != encodeServerID("i:", items[0].ID) {
		t.Fatalf("deletion response=%#v", deleted)
	}
}

func TestSyncExpiredJournalForcesCollectionReset(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	collectionID := encodeServerID("f:", inbox.ID)
	initial := decodeResponse(t, easRequest(t, handler, "Sync", E(0, "Sync", E(0, "Collections", E(0, "Collection",
		T(0, "SyncKey", "0"), T(0, "CollectionId", collectionID))))))
	key := nodeText(initial, "SyncKey")
	if key == "" || key == "0" {
		t.Fatalf("initial key = %q", key)
	}
	baseline := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, key, 10)))
	key = nodeText(baseline, "SyncKey")
	handler.space = expiredChangeFolderSpace{FolderSpace: space}
	reset := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, key, 10)))
	collection := reset.Descendant("Collection")
	if collection == nil || nodeText(collection, "Status") != "3" || nodeText(collection, "SyncKey") != "0" {
		t.Fatalf("expired journal response = %#v", reset)
	}
}

func easSyncRequest(collectionID, key string, window int) *Node {
	return E(0, "Sync", E(0, "Collections", E(0, "Collection",
		T(0, "SyncKey", key), T(0, "CollectionId", collectionID), T(0, "GetChanges", "1"), T(0, "WindowSize", strconv.Itoa(window)))))
}

func TestEASFolderTypeUsesFolderHierarchyValues(t *testing.T) {
	tests := []struct {
		folder model.Folder
		want   string
	}{
		{folder: model.Folder{Type: model.FolderTypeMail}, want: "12"},
		{folder: model.Folder{Type: model.FolderTypeCalendar}, want: "13"},
		{folder: model.Folder{Type: model.FolderTypeContacts}, want: "14"},
		{folder: model.Folder{Type: model.FolderTypeNotes}, want: "17"},
		{folder: model.Folder{Type: model.FolderTypeCalendar, SpecialUse: model.SpecialUseCalendar}, want: "8"},
		{folder: model.Folder{Type: model.FolderTypeContacts, SpecialUse: model.SpecialUseContacts}, want: "9"},
	}
	for _, test := range tests {
		if got := easFolderType(test.folder); got != test.want {
			t.Errorf("easFolderType(%#v) = %q, want %q", test.folder, got, test.want)
		}
		if got := folderTypeFromEAS(test.want); got != test.folder.Type {
			t.Errorf("folderTypeFromEAS(%q) = %q, want %q", test.want, got, test.folder.Type)
		}
	}
}

func TestEASRejectsInvalidDeviceID(t *testing.T) {
	handler, _ := testEASHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/Microsoft-Server-ActiveSync?Cmd=Sync&DeviceId=../bad", nil)
	request.SetBasicAuth("alice", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestSendMailSubmitsOpaqueMIME(t *testing.T) {
	handler, _ := testEASHandler(t)
	var submitted []byte
	handler.submit = func(_ context.Context, userID string, raw []byte) error {
		if userID != "alice" {
			t.Fatalf("userID=%q", userID)
		}
		submitted = append([]byte(nil), raw...)
		return nil
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@example.test\r\nSubject: EAS\r\n\r\nhello")
	response := easRequest(t, handler, "SendMail", E(21, "SendMail", T(21, "ClientId", "client-1"), O(21, "MIME", raw)))
	// The server completes Date and Message-ID and otherwise sends the
	// client's bytes unchanged.
	if response.Code != http.StatusOK || response.Body.Len() != 0 || !strings.HasSuffix(string(submitted), string(raw)) || !strings.Contains(string(submitted), "\r\nMessage-ID: <") {
		t.Fatalf("status=%d response=%x submitted=%q", response.Code, response.Body.Bytes(), submitted)
	}
}
