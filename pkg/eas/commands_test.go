package eas

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// fakeAccount is an in-memory Account for command tests.
type fakeAccount struct {
	oof       OutOfOffice
	directory []Profile
}

func (a *fakeAccount) Profile(_ context.Context, userID string) (Profile, error) {
	return Profile{ID: userID, DisplayName: "Alice Example", Addresses: []string{"alice@example.test", "a@example.test"}, TimeZone: "Europe/Copenhagen"}, nil
}

func (a *fakeAccount) FreeBusy(_ context.Context, _ service.AccessContext, address string, start, _ time.Time) ([]BusyPeriod, bool, error) {
	if address != "bob@example.test" {
		return nil, false, nil
	}
	return []BusyPeriod{{Start: start.Add(30 * time.Minute), End: start.Add(90 * time.Minute)}, {Start: start.Add(2 * time.Hour), End: start.Add(150 * time.Minute), Tentative: true}}, true, nil
}

func (a *fakeAccount) OutOfOffice(context.Context, string) (OutOfOffice, error) { return a.oof, nil }

func (a *fakeAccount) SetOutOfOffice(_ context.Context, _ string, oof OutOfOffice) error {
	a.oof = oof
	return nil
}

func (a *fakeAccount) Directory(_ context.Context, _ string, query string, limit int) ([]Profile, error) {
	var result []Profile
	for _, entry := range a.directory {
		if strings.Contains(strings.ToLower(entry.DisplayName+" "+entry.primary()), strings.ToLower(query)) && len(result) < limit {
			result = append(result, entry)
		}
	}
	return result, nil
}

// easCall is one request with explicit protocol details.
type easCall struct {
	command     string
	version     string
	policyKey   string
	query       string
	contentType string
	raw         []byte
	body        *Node
	device      string
}

func (c easCall) do(t *testing.T, handler http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	payload := c.raw
	if c.body != nil {
		var err error
		if payload, err = Encode(c.body); err != nil {
			t.Fatal(err)
		}
	}
	device := c.device
	if device == "" {
		device = "A1B2C3"
	}
	target := "/Microsoft-Server-ActiveSync?Cmd=" + c.command + "&User=alice&DeviceId=" + device + "&DeviceType=Test" + c.query
	if c.command == "" {
		target = "/Microsoft-Server-ActiveSync?" + c.query
	}
	request := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	request.SetBasicAuth("alice", "secret")
	if c.version != "" {
		request.Header.Set("MS-ASProtocolVersion", c.version)
	}
	if c.policyKey != "" {
		request.Header.Set("X-MS-PolicyKey", c.policyKey)
	}
	contentType := c.contentType
	if contentType == "" {
		contentType = "application/vnd.ms-sync.wbxml"
	}
	request.Header.Set("Content-Type", contentType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func folderSyncIDs(t *testing.T, handler *Handler) map[string]*Node {
	t.Helper()
	root := decodeResponse(t, easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", "0"))))
	result := map[string]*Node{}
	for _, add := range root.Descendant("Changes").ChildrenNamed("Add") {
		result[nodeText(add, "DisplayName")] = add
	}
	return result
}

// TestBase64RequestLineFromWindowsMail replays the binary query string of
// MS-ASHTTP 2.2.1.1.1.1 that Windows Mail sends instead of Cmd=...&DeviceId=.
func TestBase64RequestLineFromWindowsMail(t *testing.T) {
	handler, _ := testEASHandler(t)
	var line bytes.Buffer
	line.WriteByte(141) // 14.1
	line.WriteByte(9)   // FolderSync
	_ = binary.Write(&line, binary.LittleEndian, uint16(0x0409))
	device := []byte{0xB4, 0xA2, 0xF6, 0xE1, 0xC3, 0xD5, 0x4E, 0x21, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0xA6, 0xB7}
	line.WriteByte(byte(len(device)))
	line.Write(device)
	line.WriteByte(4)
	_ = binary.Write(&line, binary.LittleEndian, uint32(0))
	line.WriteByte(11)
	line.WriteString("WindowsMail")
	line.Write([]byte{8, 5})
	line.WriteString("alice")
	response := easCall{query: base64.StdEncoding.EncodeToString(line.Bytes()), body: E(7, "FolderSync", T(7, "SyncKey", "0"))}.do(t, handler)
	root := decodeResponse(t, response)
	if nodeText(root, "Status") != "1" {
		t.Fatalf("FolderSync over a base64 request line = %#v", root)
	}
	devices, err := handler.DeviceStates().List(t.Context(), "alice")
	if err != nil || len(devices) != 1 || devices[0].DeviceID != "B4A2F6E1C3D54E21A0B1C2D3E4F5A6B7" || devices[0].DeviceType != "WindowsMail" || devices[0].Protocol != "14.1" {
		t.Fatalf("devices = %#v, %v", devices, err)
	}
}

// TestProvisionTwoPhaseAndPolicyKeyEnforcement follows MS-ASPROV 4.1: a
// temporary key with the policy document, the acknowledged permanent key,
// and a stale X-MS-PolicyKey sending the device back to Provision.
func TestProvisionTwoPhaseAndPolicyKeyEnforcement(t *testing.T) {
	handler, _ := testEASHandler(t)
	phaseOne := decodeResponse(t, easCall{command: "Provision", version: "14.1", body: E(14, "Provision",
		E(18, "DeviceInformation", E(18, "Set", T(18, "Model", "Pixel 9"))),
		E(14, "Policies", E(14, "Policy", T(14, "PolicyType", provisioningPolicyType))))}.do(t, handler))
	temporary := nodeText(phaseOne.Descendant("Policy"), "PolicyKey")
	if childText(phaseOne, "Status") != "1" || temporary == "" || phaseOne.Descendant("EASProvisionDoc") == nil || nodeText(phaseOne.Descendant("DeviceInformation"), "Status") != "1" {
		t.Fatalf("phase one = %#v", phaseOne)
	}
	if nodeText(phaseOne.Descendant("EASProvisionDoc"), "AllowHTMLEmail") != "1" {
		t.Fatalf("policy document lacks permissive settings: %#v", phaseOne.Descendant("EASProvisionDoc"))
	}
	phaseTwo := decodeResponse(t, easCall{command: "Provision", version: "14.1", body: E(14, "Provision", E(14, "Policies", E(14, "Policy",
		T(14, "PolicyType", provisioningPolicyType), T(14, "PolicyKey", temporary), T(14, "Status", "1"))))}.do(t, handler))
	final := nodeText(phaseTwo.Descendant("Policy"), "PolicyKey")
	if final == "" || final == temporary || phaseTwo.Descendant("EASProvisionDoc") != nil {
		t.Fatalf("phase two = %#v", phaseTwo)
	}
	ok := decodeResponse(t, easCall{command: "FolderSync", version: "14.1", policyKey: final, body: E(7, "FolderSync", T(7, "SyncKey", "0"))}.do(t, handler))
	if nodeText(ok, "Status") != "1" {
		t.Fatalf("FolderSync with the permanent key = %#v", ok)
	}
	stale := decodeResponse(t, easCall{command: "FolderSync", version: "14.1", policyKey: temporary, body: E(7, "FolderSync", T(7, "SyncKey", "0"))}.do(t, handler))
	if nodeText(stale, "Status") != statusInvalidPolicyKey {
		t.Fatalf("FolderSync with a stale key = %#v", stale)
	}
	legacy := easCall{command: "FolderSync", version: "12.1", policyKey: temporary, body: E(7, "FolderSync", T(7, "SyncKey", "0"))}.do(t, handler)
	if legacy.Code != 449 {
		t.Fatalf("protocol 12.1 stale key status = %d", legacy.Code)
	}
}

// TestRemoteWipeRefusesCommandsUntilWiped covers the remote wipe sequence of
// MS-ASPROV 4.3.
func TestRemoteWipeRefusesCommandsUntilWiped(t *testing.T) {
	handler, _ := testEASHandler(t)
	decodeResponse(t, easCall{command: "FolderSync", version: "14.1", body: E(7, "FolderSync", T(7, "SyncKey", "0"))}.do(t, handler))
	if found, err := handler.DeviceStates().RequestWipe(t.Context(), "alice", "A1B2C3"); err != nil || !found {
		t.Fatalf("RequestWipe = %v, %v", found, err)
	}
	refused := decodeResponse(t, easCall{command: "FolderSync", version: "14.1", body: E(7, "FolderSync", T(7, "SyncKey", "0"))}.do(t, handler))
	if nodeText(refused, "Status") != statusRemoteWipeRequested {
		t.Fatalf("FolderSync during a pending wipe = %#v", refused)
	}
	provision := decodeResponse(t, easCall{command: "Provision", version: "14.1", body: E(14, "Provision", E(14, "Policies", E(14, "Policy", T(14, "PolicyType", provisioningPolicyType))))}.do(t, handler))
	if provision.Child("RemoteWipe") == nil {
		t.Fatalf("Provision during a pending wipe = %#v", provision)
	}
	acknowledged := decodeResponse(t, easCall{command: "Provision", version: "14.1", body: E(14, "Provision", E(14, "RemoteWipe", T(14, "Status", "1")))}.do(t, handler))
	if childText(acknowledged, "Status") != "1" {
		t.Fatalf("wipe acknowledgement = %#v", acknowledged)
	}
	state, err := handler.DeviceStates().Load(t.Context(), "alice", "A1B2C3")
	if err != nil || state.WipeAcknowledgedAt.IsZero() || !state.WipePending {
		t.Fatalf("state after acknowledgement = %#v, %v", state, err)
	}
}

// TestFolderSyncPublishesOnlyActiveSyncClasses checks that file, script,
// scheduling, search and template folders stay off the device and that
// default folders carry their MS-ASCMD types.
func TestFolderSyncPublishesOnlyActiveSyncClasses(t *testing.T) {
	handler, _ := testEASHandler(t)
	folders := folderSyncIDs(t, handler)
	for _, hidden := range []string{"Files", "Sieve scripts", "schedule-inbox", "schedule-outbox", "Saved searches", "Message templates"} {
		if folders[hidden] != nil {
			t.Errorf("FolderSync published %q", hidden)
		}
	}
	for name, want := range map[string]string{"INBOX": "2", "Drafts": "3", "Trash": "4", "Sent": "5", "Calendar": "8", "Contacts": "9", "Junk": "12", "Recent recipients": "19"} {
		if folders[name] == nil || nodeText(folders[name], "Type") != want {
			t.Errorf("folder %q = %#v, want type %s", name, folders[name], want)
		}
	}
}

// TestFolderCreateIsNotEchoedAndValidatesKey replays FolderCreate followed
// by an incremental FolderSync: the device already has the folder.
func TestFolderCreateIsNotEchoedAndValidatesKey(t *testing.T) {
	handler, _ := testEASHandler(t)
	root := decodeResponse(t, easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", "0"))))
	key := nodeText(root, "SyncKey")
	bad := decodeResponse(t, easRequest(t, handler, "FolderCreate", E(7, "FolderCreate", T(7, "SyncKey", "stale"), T(7, "ParentId", "0"), T(7, "DisplayName", "Projects"), T(7, "Type", "12"))))
	if nodeText(bad, "Status") != "9" {
		t.Fatalf("FolderCreate with a stale key = %#v", bad)
	}
	created := decodeResponse(t, easRequest(t, handler, "FolderCreate", E(7, "FolderCreate", T(7, "SyncKey", key), T(7, "ParentId", "0"), T(7, "DisplayName", "Projects"), T(7, "Type", "12"))))
	if nodeText(created, "Status") != "1" || nodeText(created, "ServerId") == "" {
		t.Fatalf("FolderCreate = %#v", created)
	}
	duplicate := decodeResponse(t, easRequest(t, handler, "FolderCreate", E(7, "FolderCreate", T(7, "SyncKey", nodeText(created, "SyncKey")), T(7, "ParentId", "0"), T(7, "DisplayName", "Projects"), T(7, "Type", "12"))))
	if nodeText(duplicate, "Status") != "2" {
		t.Fatalf("duplicate FolderCreate = %#v", duplicate)
	}
	next := decodeResponse(t, easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", nodeText(created, "SyncKey")))))
	if nodeText(next, "Status") != "1" || nodeText(next, "Count") != "0" {
		t.Fatalf("FolderSync after FolderCreate = %#v", next)
	}
	system := decodeResponse(t, easRequest(t, handler, "FolderDelete", E(7, "FolderDelete", T(7, "SyncKey", nodeText(next, "SyncKey")), T(7, "ServerId", nodeText(folderSyncIDs(t, handler)["INBOX"], "ServerId")))))
	if nodeText(system, "Status") != "9" && nodeText(system, "Status") != "3" {
		t.Fatalf("FolderDelete of INBOX = %#v", system)
	}
}

// TestFolderSyncRetryWithPreviousKey replays a FolderSync whose response
// was lost: the old key still returns the same changes.
func TestFolderSyncRetryWithPreviousKey(t *testing.T) {
	handler, space := testEASHandler(t)
	root := decodeResponse(t, easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", "0"))))
	key := nodeText(root, "SyncKey")
	if _, err := space.CreateFolder(t.Context(), service.UserAccess("alice", "test"), "Receipts", model.FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	first := decodeResponse(t, easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", key))))
	retry := decodeResponse(t, easRequest(t, handler, "FolderSync", E(7, "FolderSync", T(7, "SyncKey", key))))
	if nodeText(first, "DisplayName") != "Receipts" || nodeText(retry, "DisplayName") != "Receipts" || nodeText(retry, "Status") != "1" {
		t.Fatalf("first = %#v retry = %#v", first, retry)
	}
}

// TestMoveItemsStatusCodes pins MS-ASCMD 2.2.3.177.9: 3 is success, 1 an
// invalid source and 4 the same folder. Success was once reported as 1.
func TestMoveItemsStatusCodes(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	archive, _ := space.GetFolderByPath(t.Context(), access, "Archive")
	item, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: move me\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	source := encodeServerID("i:", item.ID)
	moved := decodeResponse(t, easRequest(t, handler, "MoveItems", E(5, "MoveItems",
		E(5, "Move", T(5, "SrcMsgId", source), T(5, "SrcFldId", encodeServerID("f:", inbox.ID)), T(5, "DstFldId", encodeServerID("f:", archive.ID))),
		E(5, "Move", T(5, "SrcMsgId", encodeServerID("i:", "missing")), T(5, "SrcFldId", encodeServerID("f:", inbox.ID)), T(5, "DstFldId", encodeServerID("f:", archive.ID))),
	)))
	responses := moved.ChildrenNamed("Response")
	if len(responses) != 2 || childText(responses[0], "Status") != moveSuccess || childText(responses[0], "DstMsgId") == "" || childText(responses[1], "Status") != moveInvalidSource {
		t.Fatalf("MoveItems = %#v", moved)
	}
	same := decodeResponse(t, easRequest(t, handler, "MoveItems", E(5, "MoveItems",
		E(5, "Move", T(5, "SrcMsgId", childText(responses[0], "DstMsgId")), T(5, "SrcFldId", encodeServerID("f:", archive.ID)), T(5, "DstFldId", encodeServerID("f:", archive.ID))))))
	if nodeText(same, "Status") != moveSameFolder {
		t.Fatalf("MoveItems into the same folder = %#v", same)
	}
}

// TestGetItemEstimateResponseShape follows MS-ASCMD 2.2.1.9: one Response
// with its own Status per collection, and status 3 before the first Sync.
func TestGetItemEstimateResponseShape(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	collectionID := encodeServerID("f:", inbox.ID)
	for _, subject := range []string{"one", "two"} {
		if _, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: " + subject + "\r\n\r\nbody")}); err != nil {
			t.Fatal(err)
		}
	}
	estimate := func(key string) *Node {
		return decodeResponse(t, easRequest(t, handler, "GetItemEstimate", E(6, "GetItemEstimate", E(6, "Collections", E(6, "Collection", T(0, "SyncKey", key), T(6, "CollectionId", collectionID))))))
	}
	if root := estimate("0"); nodeText(root.Child("Response"), "Status") != "3" {
		t.Fatalf("estimate before Sync = %#v", root)
	}
	initial := decodeResponse(t, easRequest(t, handler, "Sync", E(0, "Sync", E(0, "Collections", E(0, "Collection", T(0, "SyncKey", "0"), T(0, "CollectionId", collectionID))))))
	root := estimate(nodeText(initial, "SyncKey"))
	response := root.Child("Response")
	if response == nil || childText(response, "Status") != "1" || nodeText(response, "Estimate") != "2" || root.Child("Status") != nil {
		t.Fatalf("estimate = %#v", root)
	}
}

// TestPingLongPollsUntilChange replays a Ping that waits: it returns status
// 2 with the folder once mail arrives, and validates its parameters.
func TestPingLongPollsUntilChange(t *testing.T) {
	handler, space := testEASHandler(t)
	handler.pingPoll = 10 * time.Millisecond
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	collectionID := encodeServerID("f:", inbox.ID)
	initialSync(t, handler, collectionID)

	missing := decodeResponse(t, easRequest(t, handler, "Ping", nil))
	if nodeText(missing, "Status") != pingMissingParams {
		t.Fatalf("empty first Ping = %#v", missing)
	}
	low := decodeResponse(t, easRequest(t, handler, "Ping", E(13, "Ping", T(13, "HeartbeatInterval", "5"), E(13, "Folders", E(13, "Folder", T(13, "Id", collectionID), T(13, "Class", "Email"))))))
	if nodeText(low, "Status") != pingBadHeartbeat || nodeText(low, "HeartbeatInterval") != "60" {
		t.Fatalf("Ping below the heartbeat minimum = %#v", low)
	}
	done := make(chan *Node, 1)
	started := time.Now()
	go func() {
		done <- decodeResponse(t, easRequest(t, handler, "Ping", E(13, "Ping", T(13, "HeartbeatInterval", "300"), E(13, "Folders", E(13, "Folder", T(13, "Id", collectionID), T(13, "Class", "Email"))))))
	}()
	time.Sleep(50 * time.Millisecond)
	// A command from the same device proceeds while the Ping waits.
	decodeResponse(t, easRequest(t, handler, "Settings", E(18, "Settings", E(18, "DeviceInformation", E(18, "Set", T(18, "Model", "Phone"))))))
	if _, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: new\r\n\r\nbody")}); err != nil {
		t.Fatal(err)
	}
	select {
	case root := <-done:
		if nodeText(root, "Status") != pingChanges || nodeText(root, "Folder") != collectionID || time.Since(started) > 10*time.Second {
			t.Fatalf("Ping = %#v", root)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Ping did not report the new message")
	}
	// The next empty Ping reuses the folders and interval; the change is
	// still unsynchronized, so it answers at once.
	again := decodeResponse(t, easRequest(t, handler, "Ping", nil))
	if nodeText(again, "Status") != pingChanges {
		t.Fatalf("repeated empty Ping = %#v", again)
	}
}

// TestSettingsUserInformationAndOutOfOffice replays the Settings requests
// iOS and Outlook send after account creation.
func TestSettingsUserInformationAndOutOfOffice(t *testing.T) {
	handler, _ := testEASHandler(t)
	account := &fakeAccount{oof: OutOfOffice{Enabled: true, Message: "Away until Monday"}}
	handler.account = account
	root := decodeResponse(t, easCall{command: "Settings", version: "14.1", body: E(18, "Settings",
		E(18, "Oof", E(18, "Get", T(18, "BodyType", "Text"))),
		E(18, "DeviceInformation", E(18, "Set", T(18, "Model", "iPhone"))),
		E(18, "UserInformation", E(18, "Get")))}.do(t, handler))
	if childText(root, "Status") != "1" || nodeText(root.Child("Oof"), "OofState") != "1" || !strings.Contains(nodeText(root.Child("Oof"), "ReplyMessage"), "Away until Monday") {
		t.Fatalf("Oof Get = %#v", root)
	}
	if nodeText(root.Child("DeviceInformation"), "Status") != "1" {
		t.Fatalf("DeviceInformation Set = %#v", root)
	}
	info := root.Child("UserInformation")
	if nodeText(info, "PrimarySmtpAddress") != "alice@example.test" || nodeText(info, "UserDisplayName") != "Alice Example" || len(info.Descendant("EmailAddresses").ChildrenNamed("SmtpAddress")) != 2 {
		t.Fatalf("UserInformation = %#v", info)
	}
	set := decodeResponse(t, easCall{command: "Settings", version: "14.1", body: E(18, "Settings", E(18, "Oof", E(18, "Set",
		T(18, "OofState", "2"), T(18, "StartTime", "2026-12-20T00:00:00.000Z"), T(18, "EndTime", "2027-01-02T00:00:00.000Z"),
		E(18, "OofMessage", E(18, "AppliesToInternal"), T(18, "Enabled", "1"), T(18, "ReplyMessage", "On holiday"), T(18, "BodyType", "TEXT")))))}.do(t, handler))
	if nodeText(set.Child("Oof"), "Status") != "1" || !account.oof.Enabled || account.oof.Message != "On holiday" || account.oof.Start.IsZero() {
		t.Fatalf("Oof Set = %#v, stored %#v", set, account.oof)
	}
}

// TestSearchAndResolveRecipientsUseTheDirectory replays GAL lookups made
// while composing.
func TestSearchAndResolveRecipientsUseTheDirectory(t *testing.T) {
	handler, _ := testEASHandler(t)
	handler.account = &fakeAccount{directory: []Profile{{ID: "bob", DisplayName: "Bob Builder", Addresses: []string{"bob@example.test"}}}}
	gal := decodeResponse(t, easRequest(t, handler, "Search", E(15, "Search", E(15, "Store", T(15, "Name", "GAL"), T(15, "Query", "bob"), E(15, "Options", T(15, "Range", "0-9"))))))
	if nodeText(gal, "EmailAddress") != "bob@example.test" || nodeText(gal, "Total") != "1" || nodeText(gal, "Range") != "0-0" {
		t.Fatalf("GAL search = %#v", gal)
	}
	resolved := decodeResponse(t, easRequest(t, handler, "ResolveRecipients", E(10, "ResolveRecipients", T(10, "To", "bob"), T(10, "To", "nobody@example.org"),
		E(10, "Options", E(10, "Availability", T(10, "StartTime", "2026-11-02T08:00:00.000Z"), T(10, "EndTime", "2026-11-02T11:00:00.000Z"))))))
	if got := nodeText(resolved, "MergedFreeBusy"); got != "022010" {
		t.Fatalf("MergedFreeBusy = %q in %#v", got, resolved)
	}
	responses := resolved.ChildrenNamed("Response")
	if len(responses) != 2 || childText(responses[0], "Status") != "1" || nodeText(responses[0], "EmailAddress") != "bob@example.test" || childText(responses[1], "Status") != "4" {
		t.Fatalf("ResolveRecipients = %#v", resolved)
	}
}

// TestUnimplementedCommandIsNotImplemented keeps unknown commands from
// receiving an empty success that clients read as a malformed response.
func TestUnimplementedCommandIsNotImplemented(t *testing.T) {
	handler, _ := testEASHandler(t)
	if response := easRequest(t, handler, "ValidateCert", nil); response.Code != http.StatusNotImplemented {
		t.Fatalf("ValidateCert status = %d", response.Code)
	}
}
