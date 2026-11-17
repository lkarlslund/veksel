package eas

import (
	"context"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func addCommand(t *testing.T, collectionID, key string, commands ...*Node) *Node {
	t.Helper()
	request := easSyncRequest(collectionID, key, 100)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands", commands...))
	return request
}

// TestReplayedDraftSendIsNotSentTwice covers a lost response to a 16.1
// Add carrying Send: the retried request must not submit the draft again.
func TestReplayedDraftSendIsNotSentTwice(t *testing.T) {
	handler, space := testEASHandler(t)
	handler.account = &fakeAccount{}
	submissions := 0
	handler.submit = func(context.Context, string, []byte) error {
		submissions++
		return nil
	}
	drafts, _ := space.GetFolderByPath(t.Context(), service.UserAccess("alice", "test"), "Drafts")
	collectionID := encodeServerID("f:", drafts.ID)
	request := addCommand(t, collectionID, initialSync(t, handler, collectionID), E(0, "Add", T(0, "ClientId", "send-1"), E(0, "ApplicationData",
		T(2, "To", "bob@example.test"), T(2, "Subject", "Now"), E(17, "Body", T(17, "Type", "1"), T(17, "Data", "hi")), E(22, "Send"))))
	first := decodeResponse(t, easRequest(t, handler, "Sync", request))
	retry := decodeResponse(t, easRequest(t, handler, "Sync", request))
	if submissions != 1 || nodeText(first.Descendant("Responses"), "Status") != "1" || nodeText(retry.Descendant("Responses"), "Status") != "1" {
		t.Fatalf("submissions = %d first = %#v retry = %#v", submissions, first, retry)
	}
}

// TestReplayedSyncStillSuppressesOwnChanges covers a lost response to the
// request that read the journal entry of the device's own Add.
func TestReplayedSyncStillSuppressesOwnChanges(t *testing.T) {
	handler, space := testEASHandler(t)
	contacts, _ := space.GetFolderByPath(t.Context(), service.UserAccess("alice", "test"), "Contacts")
	collectionID := encodeServerID("f:", contacts.ID)
	added := decodeResponse(t, easRequest(t, handler, "Sync", addCommand(t, collectionID, initialSync(t, handler, collectionID),
		E(0, "Add", T(0, "ClientId", "c-1"), E(0, "ApplicationData", T(1, "FirstName", "Erik"))))))
	request := easSyncRequest(collectionID, nodeText(added, "SyncKey"), 100)
	lost := decodeResponse(t, easRequest(t, handler, "Sync", request))
	retry := decodeResponse(t, easRequest(t, handler, "Sync", request))
	if lost.Descendant("Commands") != nil || retry.Descendant("Commands") != nil {
		t.Fatalf("own Add echoed: lost = %#v retry = %#v", lost, retry)
	}
}

// TestReplayedAddIsNotReportedBack covers a lost response to a request
// carrying an Add while the collection still remembered an earlier own
// change: the retry answers the Add and must not also send the item back.
func TestReplayedAddIsNotReportedBack(t *testing.T) {
	handler, space := testEASHandler(t)
	contacts, _ := space.GetFolderByPath(t.Context(), service.UserAccess("alice", "test"), "Contacts")
	collectionID := encodeServerID("f:", contacts.ID)
	added := decodeResponse(t, easRequest(t, handler, "Sync", addCommand(t, collectionID, initialSync(t, handler, collectionID),
		E(0, "Add", T(0, "ClientId", "c-1"), E(0, "ApplicationData", T(1, "FirstName", "Erik"))))))
	request := addCommand(t, collectionID, nodeText(added, "SyncKey"),
		E(0, "Add", T(0, "ClientId", "c-2"), E(0, "ApplicationData", T(1, "FirstName", "Anna"))))
	lost := decodeResponse(t, easRequest(t, handler, "Sync", request))
	retry := decodeResponse(t, easRequest(t, handler, "Sync", request))
	serverID := nodeText(lost.Descendant("Responses"), "ServerId")
	if serverID == "" || nodeText(retry.Descendant("Responses"), "ServerId") != serverID {
		t.Fatalf("lost = %#v retry = %#v", lost, retry)
	}
	if lost.Descendant("Commands") != nil || retry.Descendant("Commands") != nil {
		t.Fatalf("own Add reported back: lost = %#v retry = %#v", lost, retry)
	}
}

// TestOwnChangeDoesNotHideLaterDeletion covers another client deleting a
// message right after the device marked it read.
func TestOwnChangeDoesNotHideLaterDeletion(t *testing.T) {
	handler, space, inbox, item := mailFixture(t)
	collectionID := encodeServerID("f:", inbox.ID)
	root := syncWithOptions(t, handler, collectionID, nil)
	serverID := encodeServerID("i:", item.ID)
	changed := decodeResponse(t, easRequest(t, handler, "Sync", addCommand(t, collectionID, nodeText(root, "SyncKey"),
		E(0, "Change", T(0, "ServerId", serverID), E(0, "ApplicationData", T(2, "Read", "1"))))))
	if err := space.DeleteItem(t.Context(), service.UserAccess("alice", "imap"), item.ID); err != nil {
		t.Fatal(err)
	}
	next := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(changed, "SyncKey"), 100)))
	if deleted := next.Descendant("Delete"); deleted == nil || childText(deleted, "ServerId") != serverID {
		t.Fatalf("deletion after own change hidden: %#v", next)
	}
}

// TestOtherClientEditDuringOwnChangeIsReported covers another client
// editing an item right after the device changed it, before the device's
// echo is recorded: the other client's edit must still reach the device.
func TestOtherClientEditDuringOwnChangeIsReported(t *testing.T) {
	handler, space, inbox, item := mailFixture(t)
	collectionID := encodeServerID("f:", inbox.ID)
	root := syncWithOptions(t, handler, collectionID, nil)
	serverID := encodeServerID("i:", item.ID)
	beforeEchoHook = func(id string) {
		if _, err := space.SetFlags(t.Context(), service.UserAccess("alice", "imap"), id, []string{model.FlagSeen, model.FlagFlagged}); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeEchoHook = nil })
	changed := decodeResponse(t, easRequest(t, handler, "Sync", addCommand(t, collectionID, nodeText(root, "SyncKey"),
		E(0, "Change", T(0, "ServerId", serverID), E(0, "ApplicationData", T(2, "Read", "1"))))))
	beforeEchoHook = nil
	next := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(changed, "SyncKey"), 100)))
	change := next.Descendant("Change")
	if change == nil || childText(change, "ServerId") != serverID || nodeText(change.Descendant("Flag"), "Status") != "2" {
		t.Fatalf("other client's edit hidden: %#v", next)
	}
}

// TestTruncatedPageKeepsLaterOwnChangeSuppressed covers a page that holds
// an earlier journal entry of an item the device changed, while the
// device's own entry lies beyond the window: the own change must not come
// back to the device in a later window.
func TestTruncatedPageKeepsLaterOwnChangeSuppressed(t *testing.T) {
	handler, space, inbox, item := mailFixture(t)
	other := service.UserAccess("alice", "imap")
	second, err := space.CreateItem(t.Context(), other, inbox.ID, service.ItemInput{Data: []byte(multipartMessage), Headers: map[string]string{"Subject": "Second"}})
	if err != nil {
		t.Fatal(err)
	}
	collectionID := encodeServerID("f:", inbox.ID)
	root := syncWithOptions(t, handler, collectionID, nil)
	if _, err := space.SetFlags(t.Context(), other, second.ID, []string{model.FlagFlagged}); err != nil {
		t.Fatal(err)
	}
	if _, err := space.SetFlags(t.Context(), other, item.ID, []string{model.FlagFlagged}); err != nil {
		t.Fatal(err)
	}
	serverID := encodeServerID("i:", item.ID)
	// Window 1: the page holds only the second item's edit, so the device's
	// change of the first item applies without a conflict.
	request := easSyncRequest(collectionID, nodeText(root, "SyncKey"), 1)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands",
		E(0, "Change", T(0, "ServerId", serverID), E(0, "ApplicationData", T(2, "Read", "1")))))
	response := decodeResponse(t, easRequest(t, handler, "Sync", request))
	for range 4 {
		if nodeText(response.Descendant("Responses"), "Status") != "" {
			t.Fatalf("Change rejected: %#v", response)
		}
		if commands := response.Descendant("Commands"); commands != nil {
			for _, change := range commands.ChildrenNamed("Change") {
				if childText(change, "ServerId") == serverID && nodeText(change, "Read") == "1" {
					t.Fatalf("own change reported back: %#v", response)
				}
			}
		}
		response = decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(response, "SyncKey"), 1)))
	}
}

type failingFolderSpace struct {
	service.FolderSpace
	failFolder string
}

func (s failingFolderSpace) GetFolder(ctx context.Context, access service.AccessContext, id string) (model.Folder, error) {
	if id == s.failFolder {
		return model.Folder{}, account.ErrTemporarilyUnavailable
	}
	return s.FolderSpace.GetFolder(ctx, access, id)
}

func (s failingFolderSpace) CurrentChangeState(ctx context.Context, access service.AccessContext, scope service.ChangeScope) (string, error) {
	return s.FolderSpace.(service.FolderChangeReader).CurrentChangeState(ctx, access, scope)
}

func (s failingFolderSpace) ListChanges(ctx context.Context, access service.AccessContext, scope service.ChangeScope, state string, limit int) (service.ChangePage, error) {
	return s.FolderSpace.(service.FolderChangeReader).ListChanges(ctx, access, scope, state, limit)
}

// TestLaterCollectionFailureKeepsEarlierCommands covers a multi-collection
// Sync whose second collection is temporarily unavailable after the first
// collection's Add was applied: the state must be kept so a retry does not
// create the contact twice.
func TestLaterCollectionFailureKeepsEarlierCommands(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	contacts, _ := space.GetFolderByPath(t.Context(), access, "Contacts")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	contactsID, inboxID := encodeServerID("f:", contacts.ID), encodeServerID("f:", inbox.ID)
	contactsKey, inboxKey := initialSync(t, handler, contactsID), initialSync(t, handler, inboxID)
	request := E(0, "Sync", E(0, "Collections",
		E(0, "Collection", T(0, "SyncKey", contactsKey), T(0, "CollectionId", contactsID),
			E(0, "Commands", E(0, "Add", T(0, "ClientId", "c-1"), E(0, "ApplicationData", T(1, "FirstName", "Erik"))))),
		E(0, "Collection", T(0, "SyncKey", inboxKey), T(0, "CollectionId", inboxID)),
	))
	handler.space = failingFolderSpace{FolderSpace: space, failFolder: inbox.ID}
	first := decodeResponse(t, easRequest(t, handler, "Sync", request))
	collections := first.Descendant("Collections").ChildrenNamed("Collection")
	if len(collections) != 2 || childText(collections[1], "Status") != syncStatusServerError || nodeText(collections[0], "ServerId") == "" {
		t.Fatalf("Sync = %#v", first)
	}
	handler.space = space
	retried := E(0, "Sync", E(0, "Collections",
		E(0, "Collection", T(0, "SyncKey", nodeText(first.Descendant("Collection"), "SyncKey")), T(0, "CollectionId", contactsID)),
		E(0, "Collection", T(0, "SyncKey", inboxKey), T(0, "CollectionId", inboxID)),
	))
	decodeResponse(t, easRequest(t, handler, "Sync", retried))
	items, _ := space.ListItems(t.Context(), access, contacts.ID, service.ItemQuery{})
	if len(items) != 1 {
		t.Fatalf("contacts = %d", len(items))
	}
}

// TestPendingWipeSurvivesPartnershipRemoval keeps a requested wipe in force
// when the owner removes the partnership before the device connected.
func TestPendingWipeSurvivesPartnershipRemoval(t *testing.T) {
	handler, _ := testEASHandler(t)
	decodeResponse(t, easCall{command: "FolderSync", version: "14.1", body: E(7, "FolderSync", T(7, "SyncKey", "0"))}.do(t, handler))
	if _, err := handler.DeviceStates().RequestWipe(t.Context(), "alice", "A1B2C3"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.DeviceStates().Remove(t.Context(), "alice", "A1B2C3"); err != nil {
		t.Fatal(err)
	}
	refused := decodeResponse(t, easCall{command: "FolderSync", version: "14.1", body: E(7, "FolderSync", T(7, "SyncKey", "0"))}.do(t, handler))
	if nodeText(refused, "Status") != statusRemoteWipeRequested {
		t.Fatalf("FolderSync after removal = %#v", refused)
	}
	decodeResponse(t, easCall{command: "Provision", version: "14.1", body: E(14, "Provision", E(14, "RemoteWipe", T(14, "Status", "1")))}.do(t, handler))
	if removed, err := handler.DeviceStates().Remove(t.Context(), "alice", "A1B2C3"); err != nil || !removed {
		t.Fatalf("Remove after acknowledgement = %v, %v", removed, err)
	}
	if devices, _ := handler.DeviceStates().List(t.Context(), "alice"); len(devices) != 0 {
		t.Fatalf("partnership kept after acknowledged wipe: %#v", devices)
	}
}

// TestItemMovedByDeviceIsNotReportedAgain covers a server-side flag change
// (SmartReply marks the original answered) on a message the device then
// moved away: the device already removed it, so neither Sync nor
// GetItemEstimate reports it.
func TestItemMovedByDeviceIsNotReportedAgain(t *testing.T) {
	handler, space, inbox, item := mailFixture(t)
	access := service.UserAccess("alice", "test")
	archive, _ := space.GetFolderByPath(t.Context(), access, "Archive")
	collectionID := encodeServerID("f:", inbox.ID)
	root := syncWithOptions(t, handler, collectionID, nil)
	if _, err := space.SetFlags(t.Context(), access, item.ID, []string{model.FlagAnswered}); err != nil {
		t.Fatal(err)
	}
	decodeResponse(t, easRequest(t, handler, "MoveItems", E(5, "MoveItems", E(5, "Move", T(5, "SrcMsgId", encodeServerID("i:", item.ID)), T(5, "SrcFldId", collectionID), T(5, "DstFldId", encodeServerID("f:", archive.ID))))))
	key := nodeText(root, "SyncKey")
	estimate := decodeResponse(t, easRequest(t, handler, "GetItemEstimate", E(6, "GetItemEstimate", E(6, "Collections", E(6, "Collection", T(0, "SyncKey", key), T(6, "CollectionId", collectionID))))))
	next := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, key, 100)))
	if nodeText(estimate, "Estimate") != "0" || next.Descendant("Commands") != nil {
		t.Fatalf("estimate = %#v sync = %#v", estimate, next)
	}
}
