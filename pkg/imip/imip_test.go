package imip

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

type fixture struct {
	typed   *model.TypedStore
	space   *rules.FolderSpace
	service *Service
	mu      sync.Mutex
	sent    []Outgoing
	// local holds the Inbox copies sent to local attendees; Send delivers
	// them like the server's local delivery path does.
	local []Outgoing
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := t.Context()
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.DomainStore().Create(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	for _, login := range []string{"alice", "bob"} {
		if err := typed.UserStore().Create(ctx, login, strings.ToUpper(login), "password123"); err != nil {
			t.Fatal(err)
		}
		if err := typed.FolderStore().CreateForUser(ctx, login); err != nil {
			t.Fatal(err)
		}
		if err := typed.UserStore().AddEmailAddress(ctx, login+"@example.com", login, "example.com", true); err != nil {
			t.Fatal(err)
		}
	}
	base := service.NewFolderSpace(typed, authz.New(typed))
	engine, err := rules.NewEngine(ctx, backend, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	space, err := rules.NewFolderSpace(base, engine)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{typed: typed, space: space}
	f.service, err = New(ctx, Config{
		Space: space, Store: backend, Identity: typed.UserStore().GetEmailAddress,
		Resolve: func(ctx context.Context, address string) (model.RecipientRoute, error) {
			return typed.ResolveRecipient(ctx, address, "+")
		},
		Send: func(ctx context.Context, message Outgoing) error {
			f.mu.Lock()
			if !message.Local {
				f.sent = append(f.sent, message)
				f.mu.Unlock()
				return nil
			}
			f.local = append(f.local, message)
			f.mu.Unlock()
			for _, recipient := range message.To {
				route, err := typed.ResolveRecipient(ctx, recipient, "+")
				if err != nil {
					return err
				}
				owner := route.Identity.UserID
				inbox, err := space.GetFolderByPath(ctx, service.UserAccess(owner, "test"), "INBOX")
				if err != nil {
					return err
				}
				if _, err := space.CreateItem(ctx, service.UserAccess(owner, "system-queue"), inbox.ID, service.ItemInput{Data: message.Raw}); err != nil {
					return err
				}
				f.service.ProcessDelivered(ctx, owner, message.Raw)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	space.SetItemObserver(f.service)
	return f
}

// takeLocal returns and clears the Inbox copies sent to local attendees.
func (f *fixture) takeLocal() []Outgoing {
	f.mu.Lock()
	defer f.mu.Unlock()
	local := f.local
	f.local = nil
	return local
}

func (f *fixture) takeSent() []Outgoing {
	f.mu.Lock()
	defer f.mu.Unlock()
	sent := f.sent
	f.sent = nil
	return sent
}

func (f *fixture) folder(t *testing.T, user, path string) model.Folder {
	t.Helper()
	folder, err := f.space.GetFolderByPath(t.Context(), service.UserAccess(user, "test"), path)
	if err != nil {
		t.Fatal(err)
	}
	return folder
}

func eventICS(uid, start string, sequence string, attendees ...string) []byte {
	lines := []string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Test//EN", "BEGIN:VEVENT",
		"UID:" + uid, "DTSTAMP:20261001T080000Z", "DTSTART:" + start, "DURATION:PT1H", "SEQUENCE:" + sequence,
		"SUMMARY:Planning", "ORGANIZER;CN=Alice:mailto:alice@example.com"}
	lines = append(lines, attendees...)
	lines = append(lines, "BEGIN:VALARM", "ACTION:DISPLAY", "TRIGGER:-PT15M", "DESCRIPTION:Soon", "END:VALARM", "END:VEVENT", "END:VCALENDAR", "")
	return []byte(strings.Join(lines, "\r\n"))
}

// mimeCalendar returns the decoded text/calendar part, its method parameter,
// and whether an application/ics attachment is present.
func mimeCalendar(t *testing.T, raw []byte) (string, string, bool) {
	t.Helper()
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var calendarData, method string
	attachment := false
	var walk func(contentType string, body io.Reader)
	walk = func(contentType string, body io.Reader) {
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(mediaType, "multipart/") {
			reader := multipart.NewReader(body, params["boundary"])
			for {
				part, err := reader.NextRawPart()
				if err == io.EOF {
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				data, _ := io.ReadAll(part)
				if part.Header.Get("Content-Transfer-Encoding") == "base64" {
					data, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(string(data), "\r\n", ""))
					if err != nil {
						t.Fatal(err)
					}
				}
				partType := part.Header.Get("Content-Type")
				if partMedia, partParams, _ := mime.ParseMediaType(partType); partMedia == "text/calendar" {
					calendarData, method = string(data), partParams["method"]
				} else if partMedia == "application/ics" {
					attachment = true
				}
				walk(partType, bytes.NewReader(data))
			}
		}
	}
	walk(message.Header.Get("Content-Type"), message.Body)
	return calendarData, method, attachment
}

func TestOutgoingRequestOnlyToExternalAttendees(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice := service.UserAccess("alice", "caldav")
	calendarFolder := f.folder(t, "alice", "Calendar")
	item, err := f.space.CreateItem(ctx, alice, calendarFolder.ID, service.ItemInput{Name: "plan.ics", Data: eventICS("plan-1", "20261101T100000Z", "0",
		"ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com",
		"ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;SCHEDULE-STATUS=1.0:mailto:carol@remote.test",
		"ATTENDEE;SCHEDULE-AGENT=CLIENT:mailto:dave@remote.test")})
	if err != nil {
		t.Fatal(err)
	}
	sent := f.takeSent()
	if len(sent) != 1 || sent[0].From != "alice@example.com" || len(sent[0].To) != 1 || sent[0].To[0] != "carol@remote.test" || sent[0].UID != "plan-1" {
		t.Fatalf("sent = %+v, want one REQUEST to carol only", sent)
	}
	ics, method, attachment := mimeCalendar(t, sent[0].Raw)
	if method != "REQUEST" || !attachment || !strings.Contains(ics, "METHOD:REQUEST") {
		t.Fatalf("method = %q attachment = %t\n%s", method, attachment, ics)
	}
	if strings.Contains(ics, "SCHEDULE-") || strings.Contains(ics, "VALARM") {
		t.Fatalf("REQUEST leaks CalDAV scheduling parameters or alarms:\n%s", ics)
	}
	if !strings.Contains(string(sent[0].Raw), "Subject: Invitation: Planning") || !strings.Contains(string(sent[0].Raw), `From: "Alice" <alice@example.com>`) {
		t.Fatalf("headers:\n%s", sent[0].Raw[:400])
	}

	// A save that changes nothing attendees depend on sends nothing.
	if _, err := f.space.UpdateItem(ctx, alice, item.ID, item.Data, nil); err != nil {
		t.Fatal(err)
	}
	described := bytes.Replace(item.Data, []byte("SUMMARY:Planning"), []byte("SUMMARY:Planning\r\nDESCRIPTION:Agenda"), 1)
	if _, err := f.space.UpdateItem(ctx, alice, item.ID, described, nil); err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); len(sent) != 0 {
		t.Fatalf("no-op saves sent %d messages", len(sent))
	}

	// A new time is an update for every external attendee.
	moved := bytes.Replace(described, []byte("DTSTART:20261101T100000Z"), []byte("DTSTART:20261101T120000Z"), 1)
	if _, err := f.space.UpdateItem(ctx, alice, item.ID, moved, nil); err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); len(sent) != 1 || sent[0].To[0] != "carol@remote.test" || !strings.Contains(string(sent[0].Raw), "Subject: Updated invitation: Planning") {
		t.Fatalf("time change sent %+v", sent)
	}
}

func TestOutgoingCancelOnRemovalAndDeletion(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice := service.UserAccess("alice", "web")
	calendarFolder := f.folder(t, "alice", "Calendar")
	item, err := f.space.CreateItem(ctx, alice, calendarFolder.ID, service.ItemInput{Name: "sync.ics", Data: eventICS("sync-1", "20261102T090000Z", "0",
		"ATTENDEE:mailto:carol@remote.test", "ATTENDEE:mailto:erin@remote.test")})
	if err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); len(sent) != 1 || len(sent[0].To) != 2 {
		t.Fatalf("initial invitations = %+v", sent)
	}
	// Removing carol and adding frank cancels carol and invites frank only.
	updated := eventICS("sync-1", "20261102T090000Z", "0", "ATTENDEE:mailto:erin@remote.test", "ATTENDEE:mailto:frank@remote.test")
	if _, err := f.space.UpdateItem(ctx, alice, item.ID, updated, nil); err != nil {
		t.Fatal(err)
	}
	sent := f.takeSent()
	if len(sent) != 2 {
		t.Fatalf("attendee change sent %d messages, want CANCEL and REQUEST", len(sent))
	}
	cancel, method, _ := mimeCalendar(t, sent[0].Raw)
	if method != "CANCEL" || sent[0].To[0] != "carol@remote.test" || len(sent[0].To) != 1 || !strings.Contains(cancel, "STATUS:CANCELLED") || strings.Contains(cancel, "erin@") {
		t.Fatalf("per-attendee CANCEL = %v\n%s", sent[0].To, cancel)
	}
	if _, method, _ := mimeCalendar(t, sent[1].Raw); method != "REQUEST" || len(sent[1].To) != 1 || sent[1].To[0] != "frank@remote.test" {
		t.Fatalf("added attendee REQUEST = %v %s", sent[1].To, method)
	}
	// Deleting the event cancels everyone still invited.
	if _, err := f.space.TrashItem(ctx, alice, item.ID); err != nil {
		t.Fatal(err)
	}
	sent = f.takeSent()
	if len(sent) != 1 || len(sent[0].To) != 2 {
		t.Fatalf("deletion sent %+v", sent)
	}
	if cancel, method, _ := mimeCalendar(t, sent[0].Raw); method != "CANCEL" || !strings.Contains(cancel, "SEQUENCE:1") {
		t.Fatalf("deletion CANCEL method %q\n%s", method, cancel)
	}
	if f.service.hasState(ctx, item.ID) {
		t.Fatal("scheduling state survived deletion")
	}
}

func TestOutgoingDisabledSendsNothing(t *testing.T) {
	f := newFixture(t)
	f.service.SetEnabled(false)
	calendarFolder := f.folder(t, "alice", "Calendar")
	if _, err := f.space.CreateItem(t.Context(), service.UserAccess("alice", "web"), calendarFolder.ID, service.ItemInput{Name: "x.ics", Data: eventICS("x-1", "20261102T090000Z", "0", "ATTENDEE:mailto:carol@remote.test")}); err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); len(sent) != 0 {
		t.Fatalf("disabled iMIP sent %d messages", len(sent))
	}
}

func imipMail(from, to, method string, ics []byte) []byte {
	return []byte("From: " + from + "\r\nTo: " + to + "\r\nSubject: iMIP\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=b1\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nInvitation\r\n" +
		"--b1\r\nContent-Type: text/calendar; method=" + method + "; charset=utf-8\r\n\r\n" + string(ics) + "\r\n--b1--\r\n")
}

func replyICS(uid, attendee, partStat string) []byte {
	return []byte(strings.Join([]string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Remote//EN", "METHOD:REPLY", "BEGIN:VEVENT",
		"UID:" + uid, "DTSTAMP:20261005T080000Z", "SEQUENCE:0", "ORGANIZER:mailto:alice@example.com",
		"ATTENDEE;PARTSTAT=" + partStat + ":mailto:" + attendee, "END:VEVENT", "END:VCALENDAR", ""}, "\r\n"))
}

func partStat(t *testing.T, data []byte, address string) string {
	t.Helper()
	event, err := calendar.Project(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, participant := range event.Participants {
		if participant.Address == address {
			return participant.PartStat
		}
	}
	return ""
}

func TestIncomingReplyUpdatesOrganizerEventAndRejectsSpoofing(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice := service.UserAccess("alice", "caldav")
	calendarFolder := f.folder(t, "alice", "Calendar")
	item, err := f.space.CreateItem(ctx, alice, calendarFolder.ID, service.ItemInput{Name: "review.ics", Headers: map[string]string{"UID": "review-1"},
		Data: eventICS("review-1", "20261103T090000Z", "0", "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:carol@remote.test")})
	if err != nil {
		t.Fatal(err)
	}
	f.takeSent()

	// Mallory cannot answer for carol.
	f.service.ProcessDelivered(ctx, "alice", imipMail("mallory@remote.test", "alice@example.com", "REPLY", replyICS("review-1", "carol@remote.test", "DECLINED")))
	current, err := f.space.GetItem(ctx, alice, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := partStat(t, current.Data, "carol@remote.test"); got != "NEEDS-ACTION" {
		t.Fatalf("spoofed REPLY changed PARTSTAT to %q", got)
	}

	f.service.ProcessDelivered(ctx, "alice", imipMail("Carol <carol@remote.test>", "alice@example.com", "REPLY", replyICS("review-1", "carol@remote.test", "ACCEPTED")))
	current, err = f.space.GetItem(ctx, alice, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := partStat(t, current.Data, "carol@remote.test"); got != "ACCEPTED" {
		t.Fatalf("REPLY PARTSTAT = %q, want ACCEPTED\n%s", got, current.Data)
	}
	if !strings.Contains(string(current.Data), "SEQUENCE:0") || strings.Contains(string(current.Data), "RSVP") {
		t.Fatalf("REPLY changed more than PARTSTAT:\n%s", current.Data)
	}
	if sent := f.takeSent(); len(sent) != 0 {
		t.Fatalf("applying a REPLY mailed attendees: %+v", sent)
	}
}

func requestFromZed(uid string) []byte {
	return []byte(strings.Join([]string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Remote//EN", "METHOD:REQUEST", "BEGIN:VEVENT",
		"UID:" + uid, "DTSTAMP:20261005T080000Z", "DTSTART:20261110T130000Z", "DTEND:20261110T140000Z", "SEQUENCE:0",
		"SUMMARY:Vendor call", "LOCATION:Video", "ORGANIZER;CN=Zed:mailto:zed@remote.test",
		"ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:bob@example.com", "END:VEVENT", "END:VCALENDAR", ""}, "\r\n"))
}

func TestIncomingRequestLandsInCalendarAndRespondSendsReply(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	bob := service.UserAccess("bob", "web")
	raw := imipMail("Zed <zed@remote.test>", "bob@example.com", "REQUEST", requestFromZed("vendor-1"))
	f.service.ProcessDelivered(ctx, "bob", raw)
	stored, err := f.service.findEvent(ctx, bob, "bob", "vendor-1")
	if err != nil {
		t.Fatalf("invitation not stored: %v", err)
	}
	if got := partStat(t, stored.Data, "bob@example.com"); got != "NEEDS-ACTION" || strings.Contains(string(stored.Data), "METHOD:") {
		t.Fatalf("stored invitation PARTSTAT %q:\n%s", got, stored.Data)
	}
	if f.folder(t, "bob", "Calendar").ID != stored.FolderID {
		t.Fatal("invitation not filed in the default calendar")
	}

	inbox := f.folder(t, "bob", "INBOX")
	message, err := f.space.CreateItem(ctx, bob, inbox.ID, service.ItemInput{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Respond(ctx, service.UserAccess("alice", "web"), message.ID, "ACCEPTED"); err == nil {
		t.Fatal("another account answered bob's invitation")
	}
	invitation, err := f.service.Respond(ctx, bob, message.ID, "accepted")
	if err != nil {
		t.Fatal(err)
	}
	if invitation.Response != "ACCEPTED" || !invitation.CanRespond || invitation.Event.Summary != "Vendor call" {
		t.Fatalf("invitation after reply = %+v", invitation)
	}
	sent := f.takeSent()
	if len(sent) != 1 || sent[0].From != "bob@example.com" || sent[0].To[0] != "zed@remote.test" {
		t.Fatalf("reply sent = %+v", sent)
	}
	reply, method, _ := mimeCalendar(t, sent[0].Raw)
	if method != "REPLY" || !strings.Contains(reply, "PARTSTAT=ACCEPTED") || !strings.Contains(string(sent[0].Raw), "Subject: Accepted: Vendor call") {
		t.Fatalf("REPLY method %q:\n%s", method, reply)
	}
	stored, err = f.service.findEvent(ctx, bob, "bob", "vendor-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := partStat(t, stored.Data, "bob@example.com"); got != "ACCEPTED" {
		t.Fatalf("calendar copy PARTSTAT = %q", got)
	}

	// The organizer's CANCEL marks the copy cancelled.
	cancel := bytes.Replace(requestFromZed("vendor-1"), []byte("METHOD:REQUEST"), []byte("METHOD:CANCEL"), 1)
	cancel = bytes.Replace(cancel, []byte("SEQUENCE:0"), []byte("SEQUENCE:1"), 1)
	f.service.ProcessDelivered(ctx, "bob", imipMail("zed@remote.test", "bob@example.com", "CANCEL", cancel))
	stored, err = f.service.findEvent(ctx, bob, "bob", "vendor-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stored.Data), "STATUS:CANCELLED") {
		t.Fatalf("CANCEL not applied:\n%s", stored.Data)
	}
}

func TestIncomingRequestCannotHijackOwnEvent(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice := service.UserAccess("alice", "caldav")
	calendarFolder := f.folder(t, "alice", "Calendar")
	item, err := f.space.CreateItem(ctx, alice, calendarFolder.ID, service.ItemInput{Name: "own.ics", Headers: map[string]string{"UID": "own-1"},
		Data: eventICS("own-1", "20261103T090000Z", "0", "ATTENDEE:mailto:carol@remote.test")})
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.ReplaceAll(requestFromZed("own-1"), []byte("bob@example.com"), []byte("alice@example.com"))
	forged = bytes.Replace(forged, []byte("SEQUENCE:0"), []byte("SEQUENCE:9"), 1)
	f.service.ProcessDelivered(ctx, "alice", imipMail("zed@remote.test", "alice@example.com", "REQUEST", forged))
	current, err := f.space.GetItem(ctx, alice, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.Data, item.Data) {
		t.Fatalf("third-party REQUEST modified the organizer's event:\n%s", current.Data)
	}
	// A REQUEST whose From is not its ORGANIZER is ignored too.
	f.service.ProcessDelivered(ctx, "bob", imipMail("mallory@remote.test", "bob@example.com", "REQUEST", requestFromZed("vendor-2")))
	if _, err := f.service.findEvent(ctx, service.UserAccess("bob", "test"), "bob", "vendor-2"); err == nil {
		t.Fatal("REQUEST from a non-organizer was stored")
	}
}

func TestIncomingIgnoresMalformedAndOversizedCalendars(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	f.service.ProcessDelivered(ctx, "bob", imipMail("zed@remote.test", "bob@example.com", "REQUEST", []byte("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nnot ical")))
	huge := bytes.Replace(requestFromZed("huge-1"), []byte("LOCATION:Video"), []byte("LOCATION:"+strings.Repeat("x", maxCalendarBytes)), 1)
	f.service.ProcessDelivered(ctx, "bob", imipMail("zed@remote.test", "bob@example.com", "REQUEST", huge))
	if _, err := f.service.findEvent(ctx, service.UserAccess("bob", "test"), "bob", "huge-1"); err == nil {
		t.Fatal("oversized invitation was stored")
	}
}
