package caldav

import (
	"bytes"
	"context"
	"errors"
	"strings"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
)

// ErrSchedulingDisabled is returned by Config.AttendeeReply while calendar
// scheduling messages are turned off.
var ErrSchedulingDisabled = errors.New("calendar scheduling is disabled")

// replyAsAttendee implements the attendee side of implicit scheduling
// (RFC 6638 §3.2.2): when the calendar owner, invited by someone else,
// changes its own PARTSTAT in a PUT, the server sends the REPLY. The DAV
// handler advertises calendar-auto-schedule, so Apple Calendar,
// Thunderbird, and Evolution leave replies to the server; they were never
// sent and the organizer never learned the answer. It reports whether the
// reply rewrote the stored object.
func (h *Handler) replyAsAttendee(ctx context.Context, folder model.Folder, stored model.Item, previous []byte) bool {
	if h.config.AttendeeReply == nil || folder.Type != model.FolderTypeCalendar {
		return false
	}
	actor, _ := ctx.Value(authenticatedUserKey{}).(string)
	if actor == "" || !strings.EqualFold(actor, folder.UserID) {
		return false
	}
	own := map[string]bool{}
	for _, address := range h.calendarUserAddresses(ctx, folder.UserID) {
		if strings.HasPrefix(strings.ToLower(address), "mailto:") {
			own[calendar.MailAddress(address)] = true
		}
	}
	partStat := changedAttendeePartStat(own, previous, stored.Data)
	if partStat == "" {
		return false
	}
	if err := h.config.AttendeeReply(ctx, folder.UserID, stored.ID, partStat); errors.Is(err, ErrSchedulingDisabled) {
		return false
	} else if err != nil {
		log.Warn("caldav: attendee reply", "user", folder.UserID, "item", stored.ID, "partstat", partStat, "error", err)
		return false
	}
	return true
}

// changedAttendeePartStat returns the PARTSTAT one of own's addresses holds
// as an attendee of data's event when it is an answer (ACCEPTED, DECLINED,
// TENTATIVE) that differs from previous; the organizer must be someone else.
func changedAttendeePartStat(own map[string]bool, previous, data []byte) string {
	current := ownPartStat(own, data)
	switch current {
	case calendar.PartStatAccepted, calendar.PartStatDeclined, calendar.PartStatTentative:
	default:
		return ""
	}
	if previous != nil && ownPartStat(own, previous) == current {
		return ""
	}
	return current
}

// ownPartStat is the PARTSTAT of own's attendee entry on the master event,
// or "" when the event is not an invitation from someone else.
func ownPartStat(own map[string]bool, data []byte) string {
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return ""
	}
	master := calendar.MasterEvent(cal.Events())
	organizer := master.Props.Get(ical.PropOrganizer)
	if organizer == nil || own[calendar.MailAddress(organizer.Value)] {
		return ""
	}
	for _, attendee := range master.Props[ical.PropAttendee] {
		if own[calendar.MailAddress(attendee.Value)] {
			partStat := strings.ToUpper(attendee.Params.Get(ical.ParamParticipationStatus))
			if partStat == "" {
				partStat = "NEEDS-ACTION"
			}
			return partStat
		}
	}
	return ""
}
