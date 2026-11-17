package imip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// ErrNoInvitation means a message carries no actionable invitation.
var ErrNoInvitation = errors.New("message has no calendar invitation")

// ErrInvalidResponse rejects an answer other than accept, tentative, or decline.
var ErrInvalidResponse = errors.New("response must be ACCEPTED, TENTATIVE, or DECLINED")

// ErrNotAttendee means none of the account's identities was invited.
var ErrNotAttendee = errors.New("you are not an attendee of this invitation")

var calendarContentType = regexp.MustCompile(`(?i)text/calendar`)

const (
	// maxCalendarScan bounds the items inspected per calendar when looking
	// an event up by UID.
	maxCalendarScan = 20000
	protocolIMIP    = "imip"
)

// incoming is a parsed scheduling message with its verified sender.
type incoming struct {
	message *calendar.ITIPMessage
	cal     *ical.Calendar
	sender  string
}

// parseIncoming extracts the iTIP message of a raw mail. ok is false for
// mail without a usable calendar part.
func parseIncoming(raw []byte) (incoming, bool) {
	if !calendarContentType.Match(raw) {
		return incoming{}, false
	}
	projection, err := service.ProjectMIME(raw)
	if err != nil || len(projection.Calendar) == 0 {
		return incoming{}, false
	}
	cal, err := decodeBounded(projection.Calendar)
	if err != nil {
		return incoming{}, false
	}
	message, err := calendar.ParseITIP(projection.Calendar)
	if err != nil || message.Method == "" {
		return incoming{}, false
	}
	headers := make(map[string]string, len(projection.Headers))
	for name, value := range projection.Headers {
		headers[strings.ToLower(name)] = value
	}
	// A failed DMARC evaluation means the From domain is forged; the
	// trusted Authentication-Results field is the server's own.
	if strings.Contains(strings.ToLower(headers["authentication-results"]), "dmarc=fail") {
		return incoming{}, false
	}
	from, err := mail.ParseAddress(headers["from"])
	if err != nil {
		return incoming{}, false
	}
	return incoming{message: message, cal: cal, sender: strings.ToLower(from.Address)}, true
}

// ProcessDelivered applies the scheduling message in mail just delivered to
// ownerID. Failures are logged; delivery has already succeeded.
func (s *Service) ProcessDelivered(ctx context.Context, ownerID string, raw []byte) {
	if !s.Enabled() {
		return
	}
	in, ok := parseIncoming(raw)
	if !ok {
		return
	}
	var err error
	switch in.message.Method {
	case calendar.MethodReply:
		err = s.applyReply(ctx, ownerID, in)
	case calendar.MethodRequest:
		if err = s.storeInvitation(ctx, ownerID, in, ""); err == nil {
			s.bookResource(ctx, ownerID, in.message)
		}
	case calendar.MethodCancel:
		err = s.applyCancel(ctx, ownerID, in)
	case "REFRESH":
		err = s.answerRefresh(ctx, ownerID, in)
	case calendar.MethodCounter:
		// The proposal waits for the organizer's decision on the event;
		// the mail itself stays in the inbox.
		err = s.recordCounter(ctx, ownerID, in)
	default:
		// A DECLINECOUNTER only informs the attendee; the mail is enough.
		return
	}
	if err != nil && !errors.Is(err, errIgnored) {
		logger.Warn("iMIP: process incoming scheduling message", "method", in.message.Method, "uid", in.message.UID, "owner", ownerID, "error", err)
	} else if errors.Is(err, errIgnored) {
		logger.Info("iMIP: ignored incoming scheduling message", "method", in.message.Method, "uid", in.message.UID, "owner", ownerID, "sender", in.sender)
	}
}

var errIgnored = errors.New("scheduling message does not apply")

// replyPartStats are the answers a VEVENT REPLY may carry (RFC 5546 §3.2.3).
var replyPartStats = map[string]bool{"ACCEPTED": true, "DECLINED": true, "TENTATIVE": true, "DELEGATED": true, "NEEDS-ACTION": true}

// applyReply records an attendee's answer on the event ownerID organizes.
// Only the replying attendee's PARTSTAT changes, and only when the mail comes
// from that attendee's own address.
func (s *Service) applyReply(ctx context.Context, ownerID string, in incoming) error {
	if len(in.message.Attendees) != 1 {
		return errIgnored
	}
	attendee := in.message.Attendees[0]
	address := calendar.MailAddress(attendee.CalendarAddress)
	if address != in.sender || !replyPartStats[attendee.PartStat] {
		return errIgnored
	}
	access := service.UserAccess(ownerID, protocolIMIP)
	item, err := s.findEvent(ctx, access, ownerID, in.message.UID)
	if err != nil {
		return errIgnored
	}
	cal, err := decodeBounded(item.Data)
	if err != nil {
		return errIgnored
	}
	master := calendar.MasterEvent(cal.Events())
	if _, owned := s.ownIdentity(ctx, ownerID, propAddress(master.Props, ical.PropOrganizer)); !owned {
		return errIgnored
	}
	stamp := ""
	if prop := in.message.Event().Props.Get(ical.PropDateTimeStamp); prop != nil {
		stamp = prop.Value
	}
	// The state lock is not held across UpdateItem: the write re-enters
	// ItemWritten, which takes it.
	s.mu.Lock()
	state, err := s.state(ctx, item.ID)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if state != nil && stamp != "" && state.Replies[address] > stamp {
		return errIgnored // an older reply arrived after a newer one
	}
	recurrenceID := ""
	if prop := in.message.Event().Props.Get(ical.PropRecurrenceID); prop != nil {
		recurrenceID = prop.Value
	}
	if !setPartStat(cal, recurrenceID, address, attendee.PartStat) {
		return errIgnored // not an attendee, or an instance without an override
	}
	data, err := encode(cal)
	if err != nil {
		return err
	}
	if _, err := s.cfg.Space.UpdateItem(ctx, access, item.ID, data, item.Headers); err != nil {
		return err
	}
	if state != nil {
		s.mu.Lock()
		state, err = s.state(ctx, item.ID)
		if err == nil && state != nil {
			if stamp != "" {
				if state.Replies == nil {
					state.Replies = make(map[string]string)
				}
				state.Replies[address] = stamp
			}
			if state.Comments == nil {
				state.Comments = make(map[string]string)
			}
			if comment := boundedComment(in.message.Comment); comment != "" {
				state.Comments[address] = comment
			} else {
				delete(state.Comments, address)
			}
			err = s.saveState(ctx, item.ID, state)
		}
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}
	logger.Info("iMIP: applied attendee reply", "uid", in.message.UID, "owner", ownerID, "attendee", address, "partstat", attendee.PartStat)
	return nil
}

// setPartStat sets address's PARTSTAT on the master event, or on the
// override with recurrenceID. It reports whether the attendee was found.
func setPartStat(cal *ical.Calendar, recurrenceID, address, partStat string) bool {
	found := false
	for _, event := range cal.Events() {
		instance := ""
		if prop := event.Props.Get(ical.PropRecurrenceID); prop != nil {
			instance = prop.Value
		}
		if instance != recurrenceID {
			continue
		}
		for index := range event.Props[ical.PropAttendee] {
			attendee := &event.Props[ical.PropAttendee][index]
			if calendar.MailAddress(attendee.Value) == address {
				attendee.Params.Set(ical.ParamParticipationStatus, strings.ToUpper(partStat))
				attendee.Params.Del(ical.ParamRSVP)
				found = true
			}
		}
	}
	return found
}

// storeInvitation files a REQUEST from an external organizer in ownerID's
// calendar. partStat, when set, is the owner's own answer.
func (s *Service) storeInvitation(ctx context.Context, ownerID string, in incoming, partStat string) error {
	organizer := calendar.MailAddress(in.message.Organizer)
	if organizer == "" || (partStat == "" && organizer != in.sender) {
		return errIgnored
	}
	if _, own := s.ownIdentity(ctx, ownerID, organizer); own {
		return errIgnored // the account organizes this event itself
	}
	attendee := s.ownAttendee(ctx, ownerID, in.message)
	if attendee == "" {
		return errIgnored
	}
	access := service.UserAccess(ownerID, protocolIMIP)
	existing, findErr := s.findEvent(ctx, access, ownerID, in.message.UID)
	if findErr != nil && !errors.Is(findErr, store.ErrNotFound) {
		return findErr
	}
	cal := in.cal
	cal.Props.Del(ical.PropMethod)
	if findErr == nil {
		current, err := decodeBounded(existing.Data)
		if err != nil {
			return errIgnored
		}
		master := calendar.MasterEvent(current.Events())
		if propAddress(master.Props, ical.PropOrganizer) != organizer {
			return errIgnored // only the event's own organizer may update it
		}
		if in.message.Seq < sequence(master.Props) {
			return errIgnored
		}
		if partStat == "" && in.message.Seq == sequence(master.Props) {
			// A message older than the copy at the same sequence (such as a
			// queued Inbox copy overtaken by a later edit) changes nothing
			// (RFC 5546 §2.1.5).
			if stamp, currentStamp := dateTimeStamp(calendar.MasterEvent(cal.Events())), dateTimeStamp(master); !stamp.IsZero() && stamp.Before(currentStamp) {
				return errIgnored
			}
			// An unchanged schedule keeps the answer already given.
			partStat = currentPartStat(current, attendee)
		}
	}
	if partStat != "" {
		setPartStat(cal, "", attendee, partStat)
	}
	data, err := encode(cal)
	if err != nil {
		return err
	}
	headers := map[string]string{"UID": in.message.UID, "SUMMARY": strings.TrimSpace(in.message.Summary)}
	if findErr == nil {
		_, err = s.cfg.Space.UpdateItem(ctx, access, existing.ID, data, headers)
		return err
	}
	folder, err := s.defaultCalendar(ctx, access, ownerID)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(in.message.UID))
	_, err = s.cfg.Space.CreateItem(ctx, access, folder.ID, service.ItemInput{
		Name: "imip-" + hex.EncodeToString(digest[:12]) + ".ics", Data: data, Headers: headers, InternalDate: time.Now().UTC(),
	})
	if err == nil {
		logger.Info("iMIP: stored invitation", "uid", in.message.UID, "owner", ownerID, "organizer", organizer)
	}
	return err
}

// applyCancel marks ownerID's copy of an external organizer's event (or one
// instance of it) cancelled.
func (s *Service) applyCancel(ctx context.Context, ownerID string, in incoming) error {
	organizer := calendar.MailAddress(in.message.Organizer)
	if organizer == "" || organizer != in.sender {
		return errIgnored
	}
	access := service.UserAccess(ownerID, protocolIMIP)
	item, err := s.findEvent(ctx, access, ownerID, in.message.UID)
	if err != nil {
		return errIgnored
	}
	cal, err := decodeBounded(item.Data)
	if err != nil {
		return errIgnored
	}
	master := calendar.MasterEvent(cal.Events())
	if propAddress(master.Props, ical.PropOrganizer) != organizer {
		return errIgnored
	}
	if recurrence := in.message.Event().Props.Get(ical.PropRecurrenceID); recurrence != nil {
		exdate := ical.NewProp(ical.PropExceptionDates)
		exdate.Value = recurrence.Value
		if tzid := recurrence.Params.Get(ical.PropTimezoneID); tzid != "" {
			exdate.Params.Set(ical.PropTimezoneID, tzid)
		}
		if recurrence.ValueType() == ical.ValueDate {
			exdate.SetValueType(ical.ValueDate)
		}
		master.Props.Add(exdate)
	} else {
		for _, event := range cal.Events() {
			event.SetStatus(ical.EventCancelled)
		}
	}
	data, err := encode(cal)
	if err != nil {
		return err
	}
	_, err = s.cfg.Space.UpdateItem(ctx, access, item.ID, data, item.Headers)
	return err
}

// answerRefresh resends the current REQUEST to an attendee who asked for it.
func (s *Service) answerRefresh(ctx context.Context, ownerID string, in incoming) error {
	access := service.UserAccess(ownerID, protocolIMIP)
	item, err := s.findEvent(ctx, access, ownerID, in.message.UID)
	if err != nil {
		return errIgnored
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.state(ctx, item.ID)
	if err != nil || state == nil || state.Owner != ownerID {
		return errIgnored
	}
	for _, recipient := range state.Recipients {
		if recipient == in.sender {
			return s.sendRequest(ctx, state, []string{recipient}, false)
		}
	}
	return errIgnored
}

// ownAttendee returns the first ATTENDEE address that is one of ownerID's
// enabled identities.
func (s *Service) ownAttendee(ctx context.Context, ownerID string, message *calendar.ITIPMessage) string {
	for _, attendee := range message.Attendees {
		address := calendar.MailAddress(attendee.CalendarAddress)
		if _, ok := s.ownIdentity(ctx, ownerID, address); ok {
			return address
		}
	}
	return ""
}

func currentPartStat(cal *ical.Calendar, address string) string {
	master := calendar.MasterEvent(cal.Events())
	for _, attendee := range master.Props.Values(ical.PropAttendee) {
		if calendar.MailAddress(attendee.Value) == address {
			return strings.ToUpper(attendee.Params.Get(ical.ParamParticipationStatus))
		}
	}
	return ""
}

// findEvent returns the event with uid from ownerID's own calendars.
func (s *Service) findEvent(ctx context.Context, access service.AccessContext, ownerID, uid string) (model.Item, error) {
	folders, err := s.cfg.Space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return model.Item{}, err
	}
	for _, folder := range folders {
		if folder.Type != model.FolderTypeCalendar || !strings.EqualFold(folder.UserID, ownerID) {
			continue
		}
		items, err := s.cfg.Space.ListItems(ctx, access, folder.ID, service.ItemQuery{MetadataOnly: true, Limit: maxCalendarScan})
		if err != nil {
			return model.Item{}, err
		}
		for _, candidate := range items {
			headerUID := candidate.Headers["UID"]
			if headerUID != "" && headerUID != uid {
				continue
			}
			item, err := s.cfg.Space.GetItem(ctx, access, candidate.ID)
			if err != nil {
				continue
			}
			if headerUID == "" {
				projected, projectErr := calendar.Project(item.Data)
				if projectErr != nil || projected.UID != uid {
					continue
				}
			}
			return item, nil
		}
	}
	return model.Item{}, store.ErrNotFound
}

// defaultCalendar returns ownerID's default calendar, or its first calendar.
func (s *Service) defaultCalendar(ctx context.Context, access service.AccessContext, ownerID string) (model.Folder, error) {
	folders, err := s.cfg.Space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return model.Folder{}, err
	}
	var first *model.Folder
	for index, folder := range folders {
		if folder.Type != model.FolderTypeCalendar || !strings.EqualFold(folder.UserID, ownerID) {
			continue
		}
		if folder.SpecialUse == model.SpecialUseCalendar {
			return folder, nil
		}
		if first == nil {
			first = &folders[index]
		}
	}
	if first == nil {
		return model.Folder{}, fmt.Errorf("account %s has no calendar", ownerID)
	}
	return *first, nil
}
