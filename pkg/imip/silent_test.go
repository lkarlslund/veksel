package imip

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/service"
)

func TestWithoutAttendeeMessagesSchedulesNobody(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	quiet := WithoutAttendeeMessages(ctx)
	alice := service.UserAccess("alice", "ews")
	calendarFolder := f.folder(t, "alice", "Calendar")
	item, err := f.space.CreateItem(quiet, alice, calendarFolder.ID, service.ItemInput{Name: "q.ics", Data: eventICS("quiet-1", "20261102T090000Z", "0", "ATTENDEE:mailto:carol@remote.test")})
	if err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); len(sent) != 0 || f.service.hasState(ctx, item.ID) {
		t.Fatalf("silent create sent %d messages, state=%t", len(sent), f.service.hasState(ctx, item.ID))
	}
	// A later ordinary save catches the attendee up.
	if _, err := f.space.UpdateItem(ctx, alice, item.ID, eventICS("quiet-1", "20261102T100000Z", "1", "ATTENDEE:mailto:carol@remote.test"), nil); err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); len(sent) != 1 || sent[0].To[0] != "carol@remote.test" {
		t.Fatalf("catch-up save sent %+v", sent)
	}
	if err := f.space.DeleteItem(quiet, alice, item.ID); err != nil {
		t.Fatal(err)
	}
	if sent := f.takeSent(); len(sent) != 0 || f.service.hasState(ctx, item.ID) {
		t.Fatalf("silent delete sent %d messages, state=%t", len(sent), f.service.hasState(ctx, item.ID))
	}
}
