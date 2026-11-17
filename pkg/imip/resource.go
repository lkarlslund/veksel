package imip

import (
	"context"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const (
	// bookingHorizon bounds how far ahead a recurring booking is checked
	// for conflicts.
	bookingHorizon = 400 * 24 * time.Hour
	// maxBookingOccurrences bounds the occurrences checked per booking.
	maxBookingOccurrences = 500
	protocolBooking       = "resource-booking"
	// ConflictComment is the reply comment of a booking declined for a
	// conflict.
	ConflictComment = "Declined automatically: the resource is already booked at this time."
)

// bookResource answers a request delivered to a resource account by the
// resource's booking policy: a request that overlaps an existing booking is
// declined unless conflicts are allowed, and a free request is accepted, or
// left for a delegate to approve. A request the resource already answered at
// this sequence is left alone.
func (s *Service) bookResource(ctx context.Context, resourceID string, message *calendar.ITIPMessage) {
	if s.cfg.Resource == nil || message == nil || message.Method != calendar.MethodRequest {
		return
	}
	profile := s.cfg.Resource(ctx, resourceID)
	if profile == nil {
		return
	}
	access := service.UserAccess(resourceID, protocolBooking)
	item, err := s.findEvent(ctx, access, resourceID, message.UID)
	if err != nil {
		return
	}
	cal, err := decodeBounded(item.Data)
	if err != nil {
		return
	}
	attendee := s.ownAttendee(ctx, resourceID, message)
	if attendee == "" || eventStatus(calendar.MasterEvent(cal.Events()).Props) == string(ical.EventCancelled) {
		return
	}
	if answered := currentPartStat(cal, attendee); answered != "" && answered != "NEEDS-ACTION" {
		return
	}
	conflict, err := s.bookingConflict(ctx, resourceID, message.UID, item.Data)
	if err != nil {
		logger.Warn("iMIP: check resource availability", "resource", resourceID, "uid", message.UID, "error", err)
		return
	}
	var answer Answer
	switch {
	case conflict && !profile.AllowConflicts:
		answer = Answer{PartStat: calendar.PartStatDeclined, Comment: ConflictComment}
	case profile.Policy == model.BookingApproval:
		logger.Info("iMIP: resource booking awaits delegate approval", "resource", resourceID, "uid", message.UID)
		return
	default:
		answer = Answer{PartStat: calendar.PartStatAccepted}
	}
	if _, err := s.Answer(ctx, access, item.ID, answer); err != nil {
		logger.Warn("iMIP: answer resource booking", "resource", resourceID, "uid", message.UID, "error", err)
		return
	}
	logger.Info("iMIP: answered resource booking", "resource", resourceID, "uid", message.UID, "partstat", answer.PartStat)
}

// bookingConflict reports whether an upcoming occurrence of the event in
// data overlaps another event that occupies resourceID.
func (s *Service) bookingConflict(ctx context.Context, resourceID, uid string, data []byte) (bool, error) {
	if s.cfg.Busy == nil {
		return false, nil
	}
	now := time.Now().UTC()
	occurrences, _, err := calendar.Occurrences(data, now.Add(-24*time.Hour), now.Add(bookingHorizon))
	if err != nil || len(occurrences) == 0 {
		return false, err
	}
	if len(occurrences) > maxBookingOccurrences {
		occurrences = occurrences[:maxBookingOccurrences]
	}
	type interval struct{ start, end time.Time }
	intervals := make([]interval, 0, len(occurrences))
	var first, last time.Time
	for _, occurrence := range occurrences {
		start, end, ok := occurrenceInterval(occurrence.Event)
		if !ok {
			continue
		}
		if first.IsZero() || start.Before(first) {
			first = start
		}
		if end.After(last) {
			last = end
		}
		intervals = append(intervals, interval{start, end})
	}
	if len(intervals) == 0 {
		return false, nil
	}
	busy, err := s.cfg.Busy(ctx, resourceID, first, last)
	if err != nil {
		return false, err
	}
	for _, period := range busy {
		if period.UID == uid {
			continue
		}
		for _, candidate := range intervals {
			if period.Start.Before(candidate.end) && candidate.start.Before(period.End) {
				return true, nil
			}
		}
	}
	return false, nil
}

func occurrenceInterval(event calendar.Event) (time.Time, time.Time, bool) {
	parse := func(value string) (time.Time, error) {
		if event.AllDay {
			return time.ParseInLocation(time.DateOnly, value, time.Local)
		}
		return time.Parse(time.RFC3339, value)
	}
	start, err := parse(event.Start)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	end, err := parse(strings.TrimSpace(event.End))
	if err != nil || !end.After(start) {
		end = start.Add(time.Hour)
	}
	return start, end, true
}
