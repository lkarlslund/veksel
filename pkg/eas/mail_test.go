package eas

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const multipartMessage = "From: Bob <bob@example.test>\r\nTo: Alice <alice@example.test>\r\nSubject: Report\r\nMessage-ID: <report-1@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n" +
	"--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n" +
	"--inner\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThe quarterly report is attached. It is long enough to truncate.\r\n" +
	"--inner\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><p>The quarterly <b>report</b> is attached.</p></body></html>\r\n" +
	"--inner--\r\n" +
	"--outer\r\nContent-Type: application/pdf; name=report.pdf\r\nContent-Disposition: attachment; filename=report.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQgdGVzdA==\r\n" +
	"--outer--\r\n"

func mailFixture(t *testing.T) (*Handler, service.FolderSpace, model.Folder, model.Item) {
	t.Helper()
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	item, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte(multipartMessage), Headers: map[string]string{"Subject": "Report"}})
	if err != nil {
		t.Fatal(err)
	}
	return handler, space, inbox, item
}

func syncWithOptions(t *testing.T, handler *Handler, collectionID string, options *Node) *Node {
	t.Helper()
	initial := decodeResponse(t, easRequest(t, handler, "Sync", E(0, "Sync", E(0, "Collections", E(0, "Collection", T(0, "SyncKey", "0"), T(0, "CollectionId", collectionID), options)))))
	return decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(initial, "SyncKey"), 100)))
}

// TestSyncHonorsBodyPreference replays the Options of Android (plain text,
// 50 bytes), iOS (HTML) and a MIME client: Type 4 was once sent to every
// client, which Samsung and Gmail render as raw MIME source.
func TestSyncHonorsBodyPreference(t *testing.T) {
	cases := []struct {
		name    string
		options *Node
		check   func(t *testing.T, add *Node)
	}{
		{"plain truncated", E(0, "Options", E(17, "BodyPreference", T(17, "Type", "1"), T(17, "TruncationSize", "50"), T(17, "Preview", "20"))), func(t *testing.T, add *Node) {
			body := add.Descendant("Body")
			if childText(body, "Type") != "1" || childText(body, "Truncated") != "1" || len(childText(body, "Data")) != 50 || !strings.HasPrefix(childText(body, "Data"), "The quarterly report") || childText(body, "Preview") == "" {
				t.Fatalf("plain body = %#v", body)
			}
			if nodeText(add, "DisplayName") != "report.pdf" || nodeText(add, "FileReference") == "" || nodeText(add, "Method") != "1" {
				t.Fatalf("attachments = %#v", add.Descendant("Attachments"))
			}
		}},
		{"html", E(0, "Options", E(17, "BodyPreference", T(17, "Type", "2"), T(17, "TruncationSize", "200000"))), func(t *testing.T, add *Node) {
			body := add.Descendant("Body")
			if childText(body, "Type") != "2" || childText(body, "Truncated") != "" || !strings.Contains(childText(body, "Data"), "<b>report</b>") {
				t.Fatalf("html body = %#v", body)
			}
			if nodeText(add, "NativeBodyType") != "2" || nodeText(add, "MessageClass") != "IPM.Note" {
				t.Fatalf("message = %#v", add)
			}
		}},
		{"mime", E(0, "Options", T(0, "MIMESupport", "2"), E(17, "BodyPreference", T(17, "Type", "4"))), func(t *testing.T, add *Node) {
			body := add.Descendant("Body")
			if childText(body, "Type") != "4" || !strings.Contains(childText(body, "Data"), "Content-Type: multipart/mixed") || add.Descendant("Attachments") != nil {
				t.Fatalf("mime body = %#v", body)
			}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			handler, _, inbox, _ := mailFixture(t)
			root := syncWithOptions(t, handler, encodeServerID("f:", inbox.ID), test.options)
			add := root.Descendant("Add")
			if add == nil || nodeText(add, "Subject") != "Report" || nodeText(add, "From") != "Bob <bob@example.test>" {
				t.Fatalf("Sync = %#v", root)
			}
			test.check(t, add)
		})
	}
}

// TestItemOperationsFetchesAttachmentAndFullBody replays the FileReference
// fetch and the untruncated body download a client issues on open.
func TestItemOperationsFetchesAttachmentAndFullBody(t *testing.T) {
	handler, _, inbox, item := mailFixture(t)
	collectionID := encodeServerID("f:", inbox.ID)
	root := syncWithOptions(t, handler, collectionID, E(0, "Options", E(17, "BodyPreference", T(17, "Type", "1"), T(17, "TruncationSize", "10"))))
	reference := nodeText(root, "FileReference")
	fetched := decodeResponse(t, easRequest(t, handler, "ItemOperations", E(20, "ItemOperations", E(20, "Fetch", T(20, "Store", "Mailbox"), T(17, "FileReference", reference)))))
	data, _ := base64.StdEncoding.DecodeString(nodeText(fetched.Descendant("Properties"), "Data"))
	if nodeText(fetched.Descendant("Fetch"), "Status") != "1" || string(data) != "%PDF-1.4 test" || nodeText(fetched, "ContentType") != "application/pdf" {
		t.Fatalf("attachment fetch = %#v", fetched)
	}
	ranged := decodeResponse(t, easRequest(t, handler, "ItemOperations", E(20, "ItemOperations", E(20, "Fetch", T(20, "Store", "Mailbox"), T(17, "FileReference", reference), E(20, "Options", T(20, "Range", "0-3"))))))
	data, _ = base64.StdEncoding.DecodeString(nodeText(ranged.Descendant("Properties"), "Data"))
	if string(data) != "%PDF" || nodeText(ranged, "Total") != "13" {
		t.Fatalf("ranged fetch = %#v", ranged)
	}
	full := decodeResponse(t, easRequest(t, handler, "ItemOperations", E(20, "ItemOperations", E(20, "Fetch", T(20, "Store", "Mailbox"),
		T(0, "CollectionId", collectionID), T(0, "ServerId", encodeServerID("i:", item.ID)),
		E(20, "Options", E(17, "BodyPreference", T(17, "Type", "1")))))))
	body := full.Descendant("Body")
	if nodeText(full.Descendant("Fetch"), "Status") != "1" || childText(body, "Truncated") != "" || !strings.Contains(childText(body, "Data"), "long enough to truncate") {
		t.Fatalf("full fetch = %#v", full)
	}
	missing := decodeResponse(t, easRequest(t, handler, "ItemOperations", E(20, "ItemOperations", E(20, "Fetch", T(20, "Store", "Mailbox"), T(17, "FileReference", encodeServerID("a:", item.ID+"/9.9"))))))
	if nodeText(missing.Descendant("Fetch"), "Status") != "15" {
		t.Fatalf("missing attachment = %#v", missing)
	}
}

// TestSyncClientChangesAreAppliedAndNotEchoed replays read/flag changes and
// a delete with the default DeletesAsMoves, which must move to Trash.
func TestSyncClientChangesAreAppliedAndNotEchoed(t *testing.T) {
	handler, space, inbox, item := mailFixture(t)
	access := service.UserAccess("alice", "test")
	collectionID := encodeServerID("f:", inbox.ID)
	root := syncWithOptions(t, handler, collectionID, nil)
	serverID := encodeServerID("i:", item.ID)
	request := easSyncRequest(collectionID, nodeText(root, "SyncKey"), 100)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands",
		E(0, "Change", T(0, "ServerId", serverID), E(0, "ApplicationData", T(2, "Read", "1"), E(2, "Flag", T(2, "Status", "2"), T(2, "FlagType", "Follow up"))))))
	changed := decodeResponse(t, easRequest(t, handler, "Sync", request))
	if changed.Descendant("Commands") != nil || changed.Descendant("Responses") != nil {
		t.Fatalf("Change response = %#v", changed)
	}
	stored, _ := space.GetItem(t.Context(), access, item.ID)
	if !hasFlag(stored.Flags, model.FlagSeen) || !hasFlag(stored.Flags, model.FlagFlagged) {
		t.Fatalf("flags = %v", stored.Flags)
	}
	quiet := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(changed, "SyncKey"), 100)))
	if quiet.Descendant("Commands") != nil {
		t.Fatalf("own change echoed: %#v", quiet)
	}
	request = easSyncRequest(collectionID, nodeText(quiet, "SyncKey"), 100)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands", E(0, "Delete", T(0, "ServerId", serverID))))
	deleted := decodeResponse(t, easRequest(t, handler, "Sync", request))
	if deleted.Descendant("Responses") != nil {
		t.Fatalf("Delete response = %#v", deleted)
	}
	trash, _ := space.GetFolderByPath(t.Context(), access, "Trash")
	moved, err := space.GetItem(t.Context(), access, item.ID)
	if err != nil || moved.FolderID != trash.ID {
		t.Fatalf("deleted item = %#v, %v (want it in Trash)", moved, err)
	}
	missing := easSyncRequest(collectionID, nodeText(deleted, "SyncKey"), 100)
	missing.Descendant("Collection").Children = append(missing.Descendant("Collection").Children, E(0, "Commands", E(0, "Change", T(0, "ServerId", serverID), E(0, "ApplicationData", T(2, "Read", "0")))))
	notFound := decodeResponse(t, easRequest(t, handler, "Sync", missing))
	if nodeText(notFound.Descendant("Responses"), "Status") != syncStatusNotFound {
		t.Fatalf("Change of a moved item = %#v", notFound)
	}
}

// TestSyncConflictServerWins applies MS-ASCMD Conflict 1 (the default): a
// client edit of an item that changed on the server is superseded.
func TestSyncConflictServerWins(t *testing.T) {
	handler, space, inbox, item := mailFixture(t)
	access := service.UserAccess("alice", "test")
	collectionID := encodeServerID("f:", inbox.ID)
	root := syncWithOptions(t, handler, collectionID, nil)
	if _, err := space.SetFlags(t.Context(), access, item.ID, []string{model.FlagFlagged}); err != nil {
		t.Fatal(err)
	}
	request := easSyncRequest(collectionID, nodeText(root, "SyncKey"), 100)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands",
		E(0, "Change", T(0, "ServerId", encodeServerID("i:", item.ID)), E(0, "ApplicationData", T(2, "Read", "1")))))
	response := decodeResponse(t, easRequest(t, handler, "Sync", request))
	change := response.Descendant("Commands").Child("Change")
	if change == nil || nodeText(change, "Read") != "0" || nodeText(change.Descendant("Flag"), "Status") != "2" {
		t.Fatalf("conflict response = %#v", response)
	}
	stored, _ := space.GetItem(t.Context(), access, item.ID)
	if hasFlag(stored.Flags, model.FlagSeen) {
		t.Fatalf("client change applied despite server-wins conflict: %v", stored.Flags)
	}
}

// TestSyncRetryWithPreviousKeyReplays covers a lost Sync response: the
// client repeats its request with the old key and must receive the same
// window, and its Add must not be created twice.
func TestSyncRetryWithPreviousKeyReplays(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	contacts, _ := space.GetFolderByPath(t.Context(), access, "Contacts")
	collectionID := encodeServerID("f:", contacts.ID)
	key := initialSync(t, handler, collectionID)
	request := easSyncRequest(collectionID, key, 100)
	request.Descendant("Collection").Children = append(request.Descendant("Collection").Children, E(0, "Commands",
		E(0, "Add", T(0, "ClientId", "c-1"), E(0, "ApplicationData", T(1, "FirstName", "Carol"), T(1, "LastName", "Jensen")))))
	first := decodeResponse(t, easRequest(t, handler, "Sync", request))
	retry := decodeResponse(t, easRequest(t, handler, "Sync", request))
	if nodeText(first, "ServerId") == "" || nodeText(retry, "ServerId") != nodeText(first, "ServerId") || nodeText(retry.Descendant("Collection"), "Status") != "1" {
		t.Fatalf("first = %#v retry = %#v", first, retry)
	}
	items, err := space.ListItems(t.Context(), access, contacts.ID, service.ItemQuery{})
	if err != nil || len(items) != 1 {
		t.Fatalf("contacts after retry = %d, %v", len(items), err)
	}
	stale := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, "not-a-key", 100)))
	if nodeText(stale, "Status") != syncStatusInvalidKey || nodeText(stale, "SyncKey") != "0" {
		t.Fatalf("unknown key = %#v", stale)
	}
}

// TestMailArrivingDuringPrimingIsSentOnce covers mail delivered between the
// SyncKey 0 request and the first window: it is enumerated and must not be
// replayed from the change journal as a second Add.
func TestMailArrivingDuringPrimingIsSentOnce(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	collectionID := encodeServerID("f:", inbox.ID)
	key := initialKey(t, handler, inbox.ID)
	if _, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: early\r\n\r\nbody")}); err != nil {
		t.Fatal(err)
	}
	first := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, key, 100)))
	second := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(first, "SyncKey"), 100)))
	if len(first.Descendant("Commands").ChildrenNamed("Add")) != 1 || second.Descendant("Commands") != nil {
		t.Fatalf("first = %#v second = %#v", first, second)
	}
}

// TestEmptySyncRepeatsCachedRequest covers the empty Sync body that 12.1+
// clients send to repeat their last request.
func TestEmptySyncRepeatsCachedRequest(t *testing.T) {
	handler, space, inbox, _ := mailFixture(t)
	if root := decodeResponse(t, easRequest(t, handler, "Sync", nil)); nodeText(root, "Status") != syncStatusIncomplete {
		t.Fatalf("empty Sync without a cached request = %#v", root)
	}
	collectionID := encodeServerID("f:", inbox.ID)
	syncWithOptions(t, handler, collectionID, nil)
	if _, err := space.CreateItem(t.Context(), service.UserAccess("alice", "test"), inbox.ID, service.ItemInput{Data: []byte("Subject: later\r\n\r\nbody")}); err != nil {
		t.Fatal(err)
	}
	root := decodeResponse(t, easRequest(t, handler, "Sync", nil))
	if nodeText(root.Descendant("Add"), "Subject") != "later" {
		t.Fatalf("empty Sync = %#v", root)
	}
}

// TestSmartReplyAppendsOriginalMessage replays a SmartReply without
// ReplaceMime from a client that relies on the server to quote.
func TestSmartReplyAppendsOriginalMessage(t *testing.T) {
	handler, space, _, item := mailFixture(t)
	var submitted string
	handler.submit = func(_ context.Context, _ string, raw []byte) error {
		submitted = string(raw)
		return nil
	}
	handler.account = &fakeAccount{}
	reply := "To: bob@example.test\r\nSubject: RE: Report\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThanks!"
	response := easRequest(t, handler, "SmartReply", E(21, "SmartReply", T(21, "ClientId", "reply-1"),
		E(21, "Source", T(21, "ItemId", encodeServerID("i:", item.ID))), E(21, "SaveInSentItems"), O(21, "MIME", []byte(reply))))
	if response.Code != 200 || response.Body.Len() != 0 {
		t.Fatalf("SmartReply status = %d body = %x", response.Code, response.Body.Bytes())
	}
	for _, want := range []string{"In-Reply-To: <report-1@example.test>", "From: \"Alice Example\" <alice@example.test>", "Thanks!", "-----Original Message-----", "The quarterly report is attached."} {
		if !strings.Contains(submitted, want) {
			t.Errorf("submitted reply lacks %q:\n%s", want, submitted)
		}
	}
	stored, _ := space.GetItem(t.Context(), service.UserAccess("alice", "test"), item.ID)
	if !hasFlag(stored.Flags, model.FlagAnswered) {
		t.Fatalf("original not marked answered: %v", stored.Flags)
	}
	again := decodeResponse(t, easRequest(t, handler, "SmartReply", E(21, "SmartReply", T(21, "ClientId", "reply-1"),
		E(21, "Source", T(21, "ItemId", encodeServerID("i:", item.ID))), O(21, "MIME", []byte(reply)))))
	if childText(again, "Status") != statusMessagePreviouslySent {
		t.Fatalf("retried SmartReply = %#v", again)
	}
	missing := decodeResponse(t, easRequest(t, handler, "SmartForward", E(21, "SmartForward", T(21, "ClientId", "fwd-1"),
		E(21, "Source", T(21, "ItemId", encodeServerID("i:", "gone"))), O(21, "MIME", []byte(reply)))))
	if childText(missing, "Status") != statusItemNotFound {
		t.Fatalf("SmartForward of a missing item = %#v", missing)
	}
}

// TestSmartForwardCarriesOriginalAttachments checks the forward keeps the
// original's attachment.
func TestSmartForwardCarriesOriginalAttachments(t *testing.T) {
	handler, _, _, item := mailFixture(t)
	var submitted string
	handler.submit = func(_ context.Context, _ string, raw []byte) error {
		submitted = string(raw)
		return nil
	}
	forward := "From: alice@example.test\r\nTo: carol@example.org\r\nSubject: FW: Report\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body>FYI</body></html>"
	response := easRequest(t, handler, "SmartForward", E(21, "SmartForward", T(21, "ClientId", "fwd-1"),
		E(21, "Source", T(21, "ItemId", encodeServerID("i:", item.ID))), O(21, "MIME", []byte(forward))))
	if response.Code != 200 || response.Body.Len() != 0 {
		t.Fatalf("SmartForward status = %d body = %x", response.Code, response.Body.Bytes())
	}
	for _, want := range []string{"multipart/mixed", "filename=report.pdf", "JVBERi0xLjQgdGVzdA==", "FYI", "<blockquote>"} {
		if !strings.Contains(submitted, want) {
			t.Errorf("forward lacks %q:\n%s", want, submitted)
		}
	}
}

// TestSendMailProtocol121RawMIME replays the 12.1 form: a message/rfc822
// body with SaveInSent in the query string.
func TestSendMailProtocol121RawMIME(t *testing.T) {
	handler, _ := testEASHandler(t)
	var submitted string
	handler.submit = func(_ context.Context, _ string, raw []byte) error {
		submitted = string(raw)
		return nil
	}
	raw := "From: alice@example.test\r\nTo: bob@example.test\r\nSubject: legacy\r\n\r\nbody"
	response := easCall{command: "SendMail", version: "12.1", query: "&SaveInSent=T", contentType: "message/rfc822", raw: []byte(raw)}.do(t, handler)
	if response.Code != 200 || !strings.HasSuffix(submitted, raw) {
		t.Fatalf("status = %d submitted = %q", response.Code, submitted)
	}
}

// TestMeetingRequestMailCarriesMeetingRequest checks that an iMIP invite is
// presented with the MeetingRequest element clients use for Accept/Decline.
func TestMeetingRequestMailCarriesMeetingRequest(t *testing.T) {
	handler, space := testEASHandler(t)
	access := service.UserAccess("alice", "test")
	inbox, _ := space.GetFolderByPath(t.Context(), access, "INBOX")
	invite := "From: bob@example.test\r\nTo: alice@example.test\r\nSubject: Planning\r\nMIME-Version: 1.0\r\nContent-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
		"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:plan-1@example.test\r\nDTSTAMP:20261101T100000Z\r\nDTSTART:20261110T090000Z\r\nDTEND:20261110T100000Z\r\nSUMMARY:Planning\r\nORGANIZER;CN=Bob:mailto:bob@example.test\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:alice@example.test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	item, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte(invite)})
	if err != nil {
		t.Fatal(err)
	}
	root := syncWithOptions(t, handler, encodeServerID("f:", inbox.ID), nil)
	add := root.Descendant("Add")
	request := add.Descendant("MeetingRequest")
	if nodeText(add, "MessageClass") != "IPM.Schedule.Meeting.Request" || request == nil || childText(request, "StartTime") != "2026-11-10T09:00:00.000Z" || uidFromGlobalObjectID(childText(request, "GlobalObjId")) != "plan-1@example.test" {
		t.Fatalf("meeting request = %#v", add)
	}
	scheduler := &fakeScheduler{}
	handler.scheduler = scheduler
	answered := decodeResponse(t, easRequest(t, handler, "MeetingResponse", E(8, "MeetingResponse", E(8, "Request",
		T(8, "UserResponse", "2"), T(8, "CollectionId", encodeServerID("f:", inbox.ID)), T(8, "RequestId", encodeServerID("i:", item.ID))))))
	if nodeText(answered, "Status") != "1" || scheduler.itemID != item.ID || scheduler.partStat != "TENTATIVE" {
		t.Fatalf("MeetingResponse = %#v scheduler = %#v", answered, scheduler)
	}
}

// TestProtocol16DraftSaveAndSend replays the 16.1 draft flow: Sync Add in
// Drafts creates a draft, and a Change carrying Send submits and removes it.
func TestProtocol16DraftSaveAndSend(t *testing.T) {
	handler, space := testEASHandler(t)
	handler.account = &fakeAccount{}
	var submitted string
	handler.submit = func(_ context.Context, _ string, raw []byte) error {
		submitted = string(raw)
		return nil
	}
	access := service.UserAccess("alice", "test")
	drafts, _ := space.GetFolderByPath(t.Context(), access, "Drafts")
	collectionID := encodeServerID("f:", drafts.ID)
	key := initialSync(t, handler, collectionID)
	add := easSyncRequest(collectionID, key, 100)
	add.Descendant("Collection").Children = append(add.Descendant("Collection").Children, E(0, "Commands", E(0, "Add", T(0, "ClientId", "draft-1"), E(0, "ApplicationData",
		T(2, "To", "bob@example.test"), T(2, "Subject", "Draft subject"), E(17, "Body", T(17, "Type", "1"), T(17, "Data", "First version"))))))
	created := decodeResponse(t, easRequest(t, handler, "Sync", add))
	serverID := nodeText(created.Descendant("Responses"), "ServerId")
	itemID, err := decodeServerID(serverID, "i:")
	if err != nil {
		t.Fatalf("draft Add = %#v", created)
	}
	draft, _ := space.GetItem(t.Context(), access, itemID)
	if !strings.Contains(string(draft.Data), "Subject: Draft subject") || !hasFlag(draft.Flags, model.FlagDraft) {
		t.Fatalf("draft = %q flags %v", draft.Data, draft.Flags)
	}
	send := easSyncRequest(collectionID, nodeText(created, "SyncKey"), 100)
	send.Descendant("Collection").Children = append(send.Descendant("Collection").Children, E(0, "Commands", E(0, "Change", T(0, "ServerId", serverID), E(0, "ApplicationData",
		T(2, "To", "bob@example.test"), T(2, "Subject", "Final subject"), E(17, "Body", T(17, "Type", "1"), T(17, "Data", "Final version")), E(22, "Send")))))
	sent := decodeResponse(t, easRequest(t, handler, "Sync", send))
	if sent.Descendant("Responses") != nil || !strings.Contains(submitted, "Subject: Final subject") || !strings.Contains(submitted, "Final version") {
		t.Fatalf("Send response = %#v submitted = %q", sent, submitted)
	}
	if _, err := space.GetItem(t.Context(), access, itemID); err == nil {
		if item, _ := space.GetItem(t.Context(), access, itemID); item.TrashedAt.IsZero() && item.FolderID == drafts.ID {
			t.Fatalf("sent draft still in Drafts")
		}
	}
	next := decodeResponse(t, easRequest(t, handler, "Sync", easSyncRequest(collectionID, nodeText(sent, "SyncKey"), 100)))
	if deleted := next.Descendant("Delete"); deleted == nil || childText(deleted, "ServerId") != serverID {
		t.Fatalf("sent draft not removed from the device: %#v", next)
	}
}

type fakeScheduler struct{ itemID, partStat string }

func (s *fakeScheduler) Respond(_ context.Context, _ service.AccessContext, itemID, partStat string) error {
	s.itemID, s.partStat = itemID, partStat
	return nil
}
