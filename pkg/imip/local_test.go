package imip

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestLocalAttendeesReceiveRequestsUpdatesAndCancels(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice, bob := service.UserAccess("alice", "web"), service.UserAccess("bob", "test")
	item, err := f.space.CreateItem(ctx, alice, f.folder(t, "alice", "Calendar").ID, service.ItemInput{Name: "team.ics", Headers: map[string]string{"UID": "team-1"},
		Data: eventICS("team-1", "20261105T090000Z", "0", "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:bob@example.com", "ATTENDEE:mailto:carol@remote.test")})
	if err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); len(sent) != 1 || sent[0].To[0] != "carol@remote.test" {
		t.Fatalf("mail went to %+v, want only the external attendee", sent)
	}
	copyItem, err := f.service.findEvent(ctx, bob, "bob", "team-1")
	if err != nil {
		t.Fatalf("local attendee copy missing: %v", err)
	}
	if copyItem.FolderID != f.folder(t, "bob", "Calendar").ID || partStat(t, copyItem.Data, "bob@example.com") != "NEEDS-ACTION" || strings.Contains(string(copyItem.Data), "VALARM") || strings.Contains(string(copyItem.Data), "METHOD") {
		t.Fatalf("copy:\n%s", copyItem.Data)
	}

	// Bob accepts from his calendar copy with a comment; the answer lands
	// directly on alice's event without any mail.
	invitation, err := f.service.Answer(ctx, bob, copyItem.ID, Answer{PartStat: "accepted", Comment: "Count me in"})
	if err != nil {
		t.Fatal(err)
	}
	if invitation.Response != "ACCEPTED" {
		t.Fatalf("answer = %+v", invitation)
	}
	if sent := f.takeSent(); len(sent) != 0 {
		t.Fatalf("local reply mailed %+v", sent)
	}
	organizer, err := f.space.GetItem(ctx, alice, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := partStat(t, organizer.Data, "bob@example.com"); got != "ACCEPTED" {
		t.Fatalf("organizer copy PARTSTAT = %q", got)
	}
	view := f.service.Scheduling(ctx, f.folder(t, "alice", "Calendar"), organizer)
	if !view.IsOrganizer || view.Comments["bob@example.com"] != "Count me in" {
		t.Fatalf("organizer scheduling view = %+v", view)
	}
	copyItem, _ = f.service.findEvent(ctx, bob, "bob", "team-1")
	if got := partStat(t, copyItem.Data, "bob@example.com"); got != "ACCEPTED" {
		t.Fatalf("attendee copy PARTSTAT = %q", got)
	}
	if view := f.service.Scheduling(ctx, f.folder(t, "bob", "Calendar"), copyItem); view.IsOrganizer || !view.CanRespond || view.Response != "ACCEPTED" {
		t.Fatalf("attendee scheduling view = %+v", view)
	}
	// Another account cannot answer for bob.
	if _, err := f.service.Answer(ctx, alice, copyItem.ID, Answer{PartStat: "DECLINED"}); err == nil {
		t.Fatal("alice answered bob's invitation")
	}

	// A new time reaches bob's copy as a new revision.
	moved := bytes.Replace(organizer.Data, []byte("DTSTART:20261105T090000Z"), []byte("DTSTART:20261105T130000Z"), 1)
	moved = bytes.Replace(moved, []byte("SEQUENCE:0"), []byte("SEQUENCE:1"), 1)
	moved = bytes.Replace(moved, []byte("PARTSTAT=ACCEPTED"), []byte("PARTSTAT=NEEDS-ACTION"), 1)
	if _, err := f.space.UpdateItem(ctx, alice, item.ID, moved, nil); err != nil {
		t.Fatal(err)
	}
	copyItem, _ = f.service.findEvent(ctx, bob, "bob", "team-1")
	if !strings.Contains(string(copyItem.Data), "DTSTART:20261105T130000Z") || partStat(t, copyItem.Data, "bob@example.com") != "NEEDS-ACTION" {
		t.Fatalf("update not delivered:\n%s", copyItem.Data)
	}
	if sent := f.takeSent(); len(sent) != 1 || !strings.Contains(string(sent[0].Raw), "Updated invitation") {
		t.Fatalf("external update = %+v", sent)
	}

	// Removing bob cancels his copy only.
	var kept []string
	for _, line := range strings.Split(string(moved), "\r\n") {
		if !strings.Contains(line, "bob@example.com") {
			kept = append(kept, line)
		}
	}
	uninvited := []byte(strings.Join(kept, "\r\n"))
	if _, err := f.space.UpdateItem(ctx, alice, item.ID, uninvited, nil); err != nil {
		t.Fatal(err)
	}
	copyItem, _ = f.service.findEvent(ctx, bob, "bob", "team-1")
	if !strings.Contains(string(copyItem.Data), "STATUS:CANCELLED") {
		t.Fatalf("removed attendee copy not cancelled:\n%s", copyItem.Data)
	}
	if sent := f.takeSent(); len(sent) != 0 {
		t.Fatalf("removing a local attendee mailed %+v", sent)
	}
}

func TestLocalAttendeeCopyCancelledWhenOrganizerDeletes(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice := service.UserAccess("alice", "web")
	item, err := f.space.CreateItem(ctx, alice, f.folder(t, "alice", "Calendar").ID, service.ItemInput{Name: "x.ics", Data: eventICS("del-1", "20261105T090000Z", "0", "ATTENDEE:mailto:bob@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.space.TrashItem(ctx, alice, item.ID); err != nil {
		t.Fatal(err)
	}
	copyItem, err := f.service.findEvent(ctx, service.UserAccess("bob", "test"), "bob", "del-1")
	if err != nil || !strings.Contains(string(copyItem.Data), "STATUS:CANCELLED") {
		t.Fatalf("deleted meeting copy = %v\n%s", err, copyItem.Data)
	}
	if f.service.hasState(ctx, item.ID) {
		t.Fatal("state survived deletion")
	}
}

func TestCounterProposalAcceptAndDecline(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice, bob := service.UserAccess("alice", "web"), service.UserAccess("bob", "web")
	item, err := f.space.CreateItem(ctx, alice, f.folder(t, "alice", "Calendar").ID, service.ItemInput{Name: "c.ics", Headers: map[string]string{"UID": "counter-1"},
		Data: eventICS("counter-1", "20261106T090000Z", "0", "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com", "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol@remote.test")})
	if err != nil {
		t.Fatal(err)
	}
	f.takeSent()
	copyItem, err := f.service.findEvent(ctx, bob, "bob", "counter-1")
	if err != nil {
		t.Fatal(err)
	}
	proposedStart := time.Date(2026, 11, 6, 14, 0, 0, 0, time.UTC)
	if _, err := f.service.Answer(ctx, bob, copyItem.ID, Answer{ProposedStart: proposedStart, ProposedEnd: proposedStart.Add(-time.Hour)}); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("backwards proposal err = %v", err)
	}
	if _, err := f.service.Answer(ctx, bob, copyItem.ID, Answer{Comment: "Morning is full", ProposedStart: proposedStart, ProposedEnd: proposedStart.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	organizer, _ := f.space.GetItem(ctx, alice, item.ID)
	view := f.service.Scheduling(ctx, f.folder(t, "alice", "Calendar"), organizer)
	if len(view.Proposals) != 1 || view.Proposals[0].Attendee != "bob@example.com" || !view.Proposals[0].Start.Equal(proposedStart) || view.Proposals[0].Comment != "Morning is full" || view.Proposals[0].Counter != nil {
		t.Fatalf("proposals = %+v", view.Proposals)
	}

	// Carol proposes by mail; a COUNTER from someone else is ignored.
	counter := strings.Join([]string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Remote//EN", "METHOD:COUNTER", "BEGIN:VEVENT",
		"UID:counter-1", "DTSTAMP:20261005T080000Z", "SEQUENCE:0", "DTSTART:20261107T090000Z", "DTEND:20261107T100000Z", "SUMMARY:Planning",
		"ORGANIZER:mailto:alice@example.com", "ATTENDEE;PARTSTAT=TENTATIVE:mailto:carol@remote.test", "COMMENT:Friday instead?", "END:VEVENT", "END:VCALENDAR", ""}, "\r\n")
	f.service.ProcessDelivered(ctx, "alice", imipMail("mallory@remote.test", "alice@example.com", "COUNTER", []byte(counter)))
	if view := f.service.Scheduling(ctx, f.folder(t, "alice", "Calendar"), organizer); len(view.Proposals) != 1 {
		t.Fatalf("spoofed COUNTER recorded: %+v", view.Proposals)
	}
	raw := imipMail("carol@remote.test", "alice@example.com", "COUNTER", []byte(counter))
	f.service.ProcessDelivered(ctx, "alice", raw)
	if view := f.service.Scheduling(ctx, f.folder(t, "alice", "Calendar"), organizer); len(view.Proposals) != 2 {
		t.Fatalf("external COUNTER not recorded: %+v", view.Proposals)
	}
	inbox := f.folder(t, "alice", "INBOX")
	mail, err := f.space.CreateItem(ctx, alice, inbox.ID, service.ItemInput{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	card, err := f.service.Describe(ctx, alice, inbox.ID, mustCalendarPart(t, raw))
	if err != nil || card.Proposal == nil || !card.CanDecide || card.EventItemID != item.ID || card.Comment != "Friday instead?" {
		t.Fatalf("COUNTER card = %+v err = %v (mail %s)", card, err, mail.ID)
	}

	// Declining carol mails her a DECLINECOUNTER.
	if err := f.service.DecideProposal(ctx, alice, item.ID, "carol@remote.test", false); err != nil {
		t.Fatal(err)
	}
	sent := f.takeSent()
	if len(sent) != 1 || sent[0].To[0] != "carol@remote.test" || !strings.Contains(string(sent[0].Raw), "New time declined") {
		t.Fatalf("decline sent %+v", sent)
	}
	if _, method, _ := mimeCalendar(t, sent[0].Raw); method != "DECLINECOUNTER" {
		t.Fatalf("decline method %q", method)
	}
	if err := f.service.DecideProposal(ctx, alice, item.ID, "carol@remote.test", false); !errors.Is(err, ErrNoProposal) {
		t.Fatalf("second decision err = %v", err)
	}
	// Bob cannot decide on alice's event.
	if err := f.service.DecideProposal(ctx, bob, item.ID, "bob@example.com", true); err == nil {
		t.Fatal("attendee decided the organizer's proposal")
	}

	// Accepting bob's proposal moves the event and re-invites everyone.
	if err := f.service.DecideProposal(ctx, alice, item.ID, "bob@example.com", true); err != nil {
		t.Fatal(err)
	}
	organizer, _ = f.space.GetItem(ctx, alice, item.ID)
	event, _ := calendar.Project(organizer.Data)
	if event.Start != proposedStart.Local().Format(time.RFC3339) && !strings.Contains(string(organizer.Data), "DTSTART:20261106T140000Z") {
		t.Fatalf("event not moved:\n%s", organizer.Data)
	}
	if event.Sequence != 1 || partStat(t, organizer.Data, "bob@example.com") != "ACCEPTED" || partStat(t, organizer.Data, "carol@remote.test") != "NEEDS-ACTION" {
		t.Fatalf("accepted proposal = %+v\n%s", event, organizer.Data)
	}
	if sent := f.takeSent(); len(sent) != 1 || sent[0].To[0] != "carol@remote.test" || !strings.Contains(string(sent[0].Raw), "Updated invitation") {
		t.Fatalf("accepted proposal mailed %+v", sent)
	}
	copyItem, _ = f.service.findEvent(ctx, bob, "bob", "counter-1")
	if !strings.Contains(string(copyItem.Data), "20261106T140000Z") {
		t.Fatalf("bob's copy not moved:\n%s", copyItem.Data)
	}
	if view := f.service.Scheduling(ctx, f.folder(t, "alice", "Calendar"), organizer); len(view.Proposals) != 0 {
		t.Fatalf("decided proposals remain: %+v", view.Proposals)
	}
}

func TestAnswerByMailCarriesCommentAndCounter(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	bob := service.UserAccess("bob", "web")
	raw := imipMail("Zed <zed@remote.test>", "bob@example.com", "REQUEST", requestFromZed("vendor-9"))
	f.service.ProcessDelivered(ctx, "bob", raw)
	message, err := f.space.CreateItem(ctx, bob, f.folder(t, "bob", "INBOX").ID, service.ItemInput{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Answer(ctx, bob, message.ID, Answer{PartStat: "DECLINED", Comment: "On leave"}); err != nil {
		t.Fatal(err)
	}
	sent := f.takeSent()
	if len(sent) != 1 {
		t.Fatalf("sent %+v", sent)
	}
	reply, method, _ := mimeCalendar(t, sent[0].Raw)
	if method != "REPLY" || !strings.Contains(reply, "COMMENT:On leave") || !strings.Contains(reply, "PARTSTAT=DECLINED") {
		t.Fatalf("reply:\n%s", reply)
	}
	start := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	if _, err := f.service.Answer(ctx, bob, message.ID, Answer{ProposedStart: start, ProposedEnd: start.Add(time.Hour), Comment: "Next day?"}); err != nil {
		t.Fatal(err)
	}
	sent = f.takeSent()
	if len(sent) != 1 || sent[0].To[0] != "zed@remote.test" || !strings.Contains(string(sent[0].Raw), "New time proposed") {
		t.Fatalf("counter sent %+v", sent)
	}
	counter, method, _ := mimeCalendar(t, sent[0].Raw)
	if method != "COUNTER" || !strings.Contains(counter, "DTSTART:20261111T090000Z") || !strings.Contains(counter, "COMMENT:Next day?") {
		t.Fatalf("counter:\n%s", counter)
	}
}

// TestLocalAttendeeInvitationReachesInbox checks the Exchange behavior of a
// meeting organized on this server: the local attendee finds the invitation
// in the Inbox as well as the calendar, answers it from the mail, and keeps
// exactly one calendar copy; updates and cancellations arrive the same way.
func TestLocalAttendeeInvitationReachesInbox(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	alice, bob := service.UserAccess("alice", "web"), service.UserAccess("bob", "web")
	item, err := f.space.CreateItem(ctx, alice, f.folder(t, "alice", "Calendar").ID, service.ItemInput{Name: "sync.ics",
		Data: eventICS("inbox-1", "20261105T090000Z", "0", "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:bob@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	local := f.takeLocal()
	if len(local) != 1 || local[0].To[0] != "bob@example.com" || local[0].From != "alice@example.com" || !strings.Contains(string(local[0].Raw), "Subject: Invitation: Planning") {
		t.Fatalf("local invitation mail = %+v", local)
	}
	if _, method, _ := mimeCalendar(t, local[0].Raw); method != "REQUEST" {
		t.Fatalf("invitation method %q", method)
	}
	if sent := f.takeSent(); len(sent) != 0 {
		t.Fatalf("external mail %+v", sent)
	}
	inbox := f.folder(t, "bob", "INBOX")
	messages, err := f.space.ListItems(ctx, bob, inbox.ID, service.ItemQuery{})
	if err != nil || len(messages) != 1 {
		t.Fatalf("bob's inbox = %d items, err %v", len(messages), err)
	}
	countCopies := func() int {
		items, err := f.space.ListItems(ctx, bob, f.folder(t, "bob", "Calendar").ID, service.ItemQuery{})
		if err != nil {
			t.Fatal(err)
		}
		return len(items)
	}
	if copies := countCopies(); copies != 1 {
		t.Fatalf("calendar copies after delivery = %d", copies)
	}
	card, err := f.service.Describe(ctx, bob, inbox.ID, mustCalendarPart(t, messages[0].Data))
	if err != nil || !card.CanRespond || card.Response != "NEEDS-ACTION" {
		t.Fatalf("invitation card = %+v err %v", card, err)
	}
	answered, err := f.service.Answer(ctx, bob, messages[0].ID, Answer{PartStat: "TENTATIVE"})
	if err != nil || answered.Response != "TENTATIVE" {
		t.Fatalf("answer from mail = %+v err %v", answered, err)
	}
	if copies := countCopies(); copies != 1 {
		t.Fatalf("calendar copies after answering = %d", copies)
	}
	organizer, _ := f.space.GetItem(ctx, alice, item.ID)
	if got := partStat(t, organizer.Data, "bob@example.com"); got != "TENTATIVE" {
		t.Fatalf("organizer PARTSTAT = %q", got)
	}

	// A new time is an updated invitation; the stale first mail delivered
	// again changes nothing.
	moved := bytes.Replace(organizer.Data, []byte("DTSTART:20261105T090000Z"), []byte("DTSTART:20261105T130000Z"), 1)
	moved = bytes.Replace(moved, []byte("SEQUENCE:0"), []byte("SEQUENCE:1"), 1)
	if _, err := f.space.UpdateItem(ctx, alice, item.ID, moved, nil); err != nil {
		t.Fatal(err)
	}
	if local := f.takeLocal(); len(local) != 1 || !strings.Contains(string(local[0].Raw), "Subject: Updated invitation: Planning") {
		t.Fatalf("update mail = %+v", local)
	}
	f.service.ProcessDelivered(ctx, "bob", messages[0].Data)
	copyItem, _ := f.service.findEvent(ctx, bob, "bob", "inbox-1")
	if !strings.Contains(string(copyItem.Data), "DTSTART:20261105T130000Z") || countCopies() != 1 {
		t.Fatalf("copy after stale redelivery:\n%s", copyItem.Data)
	}

	// Deleting the meeting sends a cancellation.
	if _, err := f.space.TrashItem(ctx, alice, item.ID); err != nil {
		t.Fatal(err)
	}
	if local := f.takeLocal(); len(local) != 1 || !strings.Contains(string(local[0].Raw), "Subject: Cancelled: Planning") {
		t.Fatalf("cancel mail = %+v", local)
	}
	if messages, _ := f.space.ListItems(ctx, bob, inbox.ID, service.ItemQuery{}); len(messages) != 3 {
		t.Fatalf("bob's inbox holds %d messages, want invitation, update, and cancellation", len(messages))
	}
}

// TestStaleSameSequenceRequestIgnored checks that a REQUEST older than the
// stored copy at the same SEQUENCE leaves the copy alone.
func TestStaleSameSequenceRequestIgnored(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	bob := service.UserAccess("bob", "web")
	newer := requestFromZed("stale-1")
	f.service.ProcessDelivered(ctx, "bob", imipMail("Zed <zed@remote.test>", "bob@example.com", "REQUEST", newer))
	older := bytes.Replace(newer, []byte("SUMMARY:"), []byte("SUMMARY:Old "), 1)
	older = bytes.Replace(older, []byte("DTSTAMP:2026"), []byte("DTSTAMP:2025"), 1)
	if bytes.Equal(older, newer) {
		t.Fatal("fixture request has no DTSTAMP or SUMMARY to age")
	}
	f.service.ProcessDelivered(ctx, "bob", imipMail("Zed <zed@remote.test>", "bob@example.com", "REQUEST", older))
	copyItem, err := f.service.findEvent(ctx, bob, "bob", "stale-1")
	if err != nil || strings.Contains(string(copyItem.Data), "SUMMARY:Old ") {
		t.Fatalf("stale request applied (err %v):\n%s", err, copyItem.Data)
	}
}

func mustCalendarPart(t *testing.T, raw []byte) []byte {
	t.Helper()
	projection, err := service.ProjectMIME(raw)
	if err != nil || len(projection.Calendar) == 0 {
		t.Fatalf("no calendar part: %v", err)
	}
	return projection.Calendar
}
