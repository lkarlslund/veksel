package imip

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// ErrNoProposal means the attendee has no pending new-time proposal.
var ErrNoProposal = errors.New("no pending proposal from this attendee")

// ErrInvalidProposal rejects a proposed time that does not end after it starts.
var ErrInvalidProposal = errors.New("the proposed time must end after it starts")

const maxCommentBytes = 2000

func boundedComment(comment string) string {
	comment = strings.TrimSpace(comment)
	if len(comment) > maxCommentBytes {
		comment = comment[:maxCommentBytes]
	}
	return comment
}

// Invitation is the mail reader's view of a scheduling message.
type Invitation struct {
	// ItemID is the mail item the invitation was read from; set by callers.
	ItemID string         `json:"item_id,omitempty"`
	Method string         `json:"method"`
	Event  calendar.Event `json:"event"`
	// Response is the account's current answer (PARTSTAT) in its calendar
	// copy, or in the message when no copy exists.
	Response string `json:"response,omitempty"`
	// CanRespond is true for a REQUEST that lists one of the account's
	// identities as an attendee.
	CanRespond bool `json:"can_respond"`
	// Comment is the sender's note (REPLY or COUNTER COMMENT).
	Comment string `json:"comment,omitempty"`
	// Proposal is the new time a COUNTER proposes; EventItemID is the
	// organizer's event it applies to, and CanDecide reports that the
	// proposal is still pending for this account to accept or decline.
	Proposal    *Proposal `json:"proposal,omitempty"`
	EventItemID string    `json:"event_item_id,omitempty"`
	CanDecide   bool      `json:"can_decide,omitempty"`
}

// Describe summarizes the calendar part of a mail item in folderID for the
// account that owns that folder.
func (s *Service) Describe(ctx context.Context, access service.AccessContext, folderID string, data []byte) (*Invitation, error) {
	if len(data) == 0 {
		return nil, ErrNoInvitation
	}
	message, err := calendar.ParseITIP(data)
	if err != nil || message.Method == "" {
		return nil, ErrNoInvitation
	}
	event, err := calendar.Project(data)
	if err != nil {
		return nil, ErrNoInvitation
	}
	folder, err := s.cfg.Space.GetFolder(ctx, access, folderID)
	if err != nil {
		return nil, err
	}
	invitation := &Invitation{Method: message.Method, Event: event, Comment: boundedComment(message.Comment)}
	switch message.Method {
	case calendar.MethodCounter:
		s.describeCounter(ctx, access, folder.UserID, message, invitation)
		return invitation, nil
	case calendar.MethodRequest:
	default:
		return invitation, nil
	}
	attendee := s.ownAttendee(ctx, folder.UserID, message)
	if attendee == "" {
		return invitation, nil
	}
	invitation.CanRespond = s.Enabled()
	if cal, err := decodeBounded(data); err == nil {
		invitation.Response = currentPartStat(cal, attendee)
	}
	if item, err := s.findEvent(ctx, access, folder.UserID, message.UID); err == nil {
		if cal, err := decodeBounded(item.Data); err == nil {
			invitation.Response = currentPartStat(cal, attendee)
		}
	}
	return invitation, nil
}

// describeCounter adds the proposal of a COUNTER mail for the organizer.
func (s *Service) describeCounter(ctx context.Context, access service.AccessContext, ownerID string, message *calendar.ITIPMessage, invitation *Invitation) {
	if !message.DTStart.IsZero() && message.DTEnd.After(message.DTStart) {
		invitation.Proposal = &Proposal{Start: message.DTStart, End: message.DTEnd, Comment: invitation.Comment}
		if len(message.Attendees) > 0 {
			invitation.Proposal.Attendee = calendar.MailAddress(message.Attendees[0].CalendarAddress)
		}
	}
	item, err := s.findEvent(ctx, access, ownerID, message.UID)
	if err != nil || invitation.Proposal == nil {
		return
	}
	invitation.EventItemID = item.ID
	s.mu.Lock()
	state, err := s.state(ctx, item.ID)
	s.mu.Unlock()
	if err == nil && state != nil {
		pending, ok := state.Proposals[invitation.Proposal.Attendee]
		invitation.CanDecide = ok && pending.Start.Equal(invitation.Proposal.Start) && pending.End.Equal(invitation.Proposal.End)
	}
}

// Answer is an attendee's response to an invitation: a participation status
// with an optional comment, or, when ProposedStart and ProposedEnd are set, a
// proposal of a new time (iTIP COUNTER).
type Answer struct {
	PartStat      string
	Comment       string
	ProposedStart time.Time
	ProposedEnd   time.Time
}

// Proposing reports whether the answer proposes a new time.
func (a Answer) Proposing() bool { return !a.ProposedStart.IsZero() || !a.ProposedEnd.IsZero() }

// Respond answers the invitation in mail item itemID with partStat.
func (s *Service) Respond(ctx context.Context, access service.AccessContext, itemID, partStat string) (*Invitation, error) {
	return s.Answer(ctx, access, itemID, Answer{PartStat: partStat})
}

// invitationSource is the scheduling message an answer refers to.
type invitationSource struct {
	owner   string
	folder  model.Folder
	message *calendar.ITIPMessage
	cal     *ical.Calendar
	// data is the calendar data Describe is run against after answering.
	data []byte
}

// loadInvitation reads the invitation behind itemID, which is either a mail
// item carrying an iTIP REQUEST or the account's calendar copy of an event
// it is invited to. Only the account owner may answer.
func (s *Service) loadInvitation(ctx context.Context, access service.AccessContext, itemID string) (invitationSource, error) {
	item, err := s.cfg.Space.GetItem(ctx, access, itemID)
	if err != nil {
		return invitationSource{}, err
	}
	folder, err := s.cfg.Space.GetFolder(ctx, access, item.FolderID)
	if err != nil {
		return invitationSource{}, err
	}
	source := invitationSource{owner: folder.UserID, folder: folder}
	if access.Actor.Kind != model.PrincipalUser || !strings.EqualFold(access.Actor.ID, source.owner) {
		return invitationSource{}, fmt.Errorf("only the calendar owner can answer an invitation: %w", service.ErrForbidden)
	}
	switch folder.Type {
	case model.FolderTypeMail:
		projection, err := service.ProjectMIME(item.Data)
		if err != nil || len(projection.Calendar) == 0 {
			return invitationSource{}, ErrNoInvitation
		}
		source.data = projection.Calendar
	case model.FolderTypeCalendar:
		source.data = item.Data
	default:
		return invitationSource{}, ErrNoInvitation
	}
	if source.cal, err = decodeBounded(source.data); err != nil {
		return invitationSource{}, ErrNoInvitation
	}
	source.message, err = calendar.ParseITIP(source.data)
	if err != nil || (folder.Type == model.FolderTypeMail && source.message.Method != calendar.MethodRequest) {
		return invitationSource{}, ErrNoInvitation
	}
	if calendar.MailAddress(source.message.Organizer) == "" {
		return invitationSource{}, ErrNoInvitation
	}
	return source, nil
}

// Answer responds to the invitation in itemID (a mail item or calendar
// copy). A REPLY or COUNTER goes to the organizer: applied directly to a
// local organizer's event, or mailed from the invited identity otherwise. A
// reply also records the answer in the account's calendar copy.
func (s *Service) Answer(ctx context.Context, access service.AccessContext, itemID string, answer Answer) (*Invitation, error) {
	answer.PartStat = strings.ToUpper(strings.TrimSpace(answer.PartStat))
	answer.Comment = strings.TrimSpace(answer.Comment)
	if len(answer.Comment) > maxCommentBytes {
		return nil, fmt.Errorf("comment is longer than %d bytes", maxCommentBytes)
	}
	proposing := answer.Proposing()
	if proposing {
		if !answer.ProposedEnd.After(answer.ProposedStart) {
			return nil, ErrInvalidProposal
		}
		if answer.PartStat == "" {
			answer.PartStat = calendar.PartStatTentative
		}
	}
	if answer.PartStat != calendar.PartStatAccepted && answer.PartStat != calendar.PartStatTentative && answer.PartStat != calendar.PartStatDeclined {
		return nil, ErrInvalidResponse
	}
	if !s.Enabled() {
		return nil, errors.New("calendar invitations are disabled")
	}
	source, err := s.loadInvitation(ctx, access, itemID)
	if err != nil {
		return nil, err
	}
	message := source.message
	organizer := calendar.MailAddress(message.Organizer)
	if _, own := s.ownIdentity(ctx, source.owner, organizer); own {
		return nil, ErrNotAttendee
	}
	attendee := s.ownAttendee(ctx, source.owner, message)
	if attendee == "" {
		return nil, ErrNotAttendee
	}
	var responder calendar.Attendee
	for _, candidate := range message.Attendees {
		if calendar.MailAddress(candidate.CalendarAddress) == attendee {
			responder = candidate
		}
	}
	method := calendar.MethodReply
	var payload []byte
	if proposing {
		method = calendar.MethodCounter
		payload, err = calendar.BuildCounter(message, responder.CalendarAddress, answer.ProposedStart, answer.ProposedEnd)
	} else {
		payload, err = calendar.BuildReply(message, responder.CalendarAddress, answer.PartStat)
	}
	if err == nil {
		payload, err = calendar.WithComment(payload, answer.Comment)
	}
	if err != nil {
		return nil, err
	}
	if err := s.toOrganizer(ctx, method, answer.PartStat, payload, attendee, responder.CommonName, organizer, message); err != nil {
		return nil, err
	}
	in := incoming{message: message, cal: source.cal, sender: organizer}
	if err := s.storeInvitation(ctx, source.owner, in, answer.PartStat); err != nil && !errors.Is(err, errIgnored) {
		return nil, fmt.Errorf("answer sent, but the calendar copy was not updated: %w", err)
	}
	logger.Info("iMIP: answered invitation", "method", method, "uid", message.UID, "attendee", attendee, "partstat", answer.PartStat)
	if source.folder.Type == model.FolderTypeCalendar {
		source.data = nil
		if item, err := s.findEvent(ctx, access, source.owner, message.UID); err == nil {
			source.data = item.Data
		}
		invitation := &Invitation{Method: method, CanRespond: true, Response: answer.PartStat, Comment: answer.Comment}
		if event, err := calendar.Project(source.data); err == nil {
			invitation.Event = event
		}
		return invitation, nil
	}
	return s.Describe(ctx, access, source.folder.ID, source.data)
}

// toOrganizer delivers an attendee's REPLY or COUNTER: directly when the
// organizer is a local account, by mail otherwise.
func (s *Service) toOrganizer(ctx context.Context, method, partStat string, payload []byte, attendee, attendeeName, organizer string, request *calendar.ITIPMessage) error {
	organizerUser, local, err := s.localUser(ctx, organizer)
	if err != nil {
		return err
	}
	if local {
		if organizerUser == "" {
			return fmt.Errorf("the organizer address %s cannot receive scheduling messages", organizer)
		}
		message, err := calendar.ParseITIP(payload)
		if err != nil {
			return err
		}
		cal, err := decodeBounded(payload)
		if err != nil {
			return err
		}
		in := incoming{message: message, cal: cal, sender: attendee}
		if method == calendar.MethodCounter {
			err = s.recordCounter(ctx, organizerUser, in)
		} else {
			err = s.applyReply(ctx, organizerUser, in)
		}
		if errors.Is(err, errIgnored) {
			return errors.New("the organizer's event no longer lists you as an attendee")
		}
		return err
	}
	now := time.Now().UTC()
	intro := map[string]string{
		calendar.PartStatAccepted:  attendee + " has accepted this invitation.",
		calendar.PartStatTentative: attendee + " has tentatively accepted this invitation.",
		calendar.PartStatDeclined:  attendee + " has declined this invitation.",
	}[partStat]
	if method == calendar.MethodCounter {
		intro = attendee + " proposes a new time for this event."
	}
	if parsed, err := calendar.ParseITIP(payload); err == nil && parsed.Comment != "" {
		intro += "\r\n\r\n" + parsed.Comment
	}
	raw, err := buildMail(mailContent{
		From: sender(attendee, attendeeName), To: []string{organizer},
		Subject: subjectFor(method, partStat, false, request.Summary), Text: summaryText(intro, request),
		Method: method, Calendar: payload,
	}, now)
	if err != nil {
		return err
	}
	return s.cfg.Send(ctx, Outgoing{From: attendee, To: []string{organizer}, Raw: raw, UID: request.UID})
}

// recordCounter keeps an attendee's proposed new time on the event ownerID
// organizes until the organizer accepts or declines it. Only the proposing
// attendee may send it, and only for an event that lists them.
func (s *Service) recordCounter(ctx context.Context, ownerID string, in incoming) error {
	var address string
	for _, attendee := range in.message.Attendees {
		if calendar.MailAddress(attendee.CalendarAddress) == in.sender {
			address = in.sender
		}
	}
	if address == "" || in.message.DTStart.IsZero() || !in.message.DTEnd.After(in.message.DTStart) || len(in.message.Raw) > maxCalendarBytes {
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
	if _, owned := s.ownIdentity(ctx, ownerID, propAddress(master.Props, ical.PropOrganizer)); !owned || currentPartStat(cal, address) == "" {
		return errIgnored
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.state(ctx, item.ID)
	if err != nil {
		return err
	}
	if state == nil {
		return errIgnored
	}
	if state.Proposals == nil {
		state.Proposals = make(map[string]Proposal)
	}
	state.Proposals[address] = Proposal{Attendee: address, Start: in.message.DTStart.UTC(), End: in.message.DTEnd.UTC(), Comment: boundedComment(in.message.Comment), Received: time.Now().UTC(), Counter: in.message.Raw}
	if err := s.saveState(ctx, item.ID, state); err != nil {
		return err
	}
	logger.Info("iMIP: recorded proposed new time", "uid", in.message.UID, "owner", ownerID, "attendee", address)
	return nil
}

// EventScheduling is the scheduling view of one calendar event for the
// account whose calendar holds it.
type EventScheduling struct {
	// IsOrganizer reports that the calendar owner organizes the event.
	IsOrganizer bool `json:"is_organizer"`
	// CanRespond reports that the owner is an attendee who may answer.
	CanRespond bool `json:"can_respond"`
	// Response is the owner's own PARTSTAT as an attendee.
	Response string `json:"response,omitempty"`
	// Proposals are pending new-time proposals (organizer only).
	Proposals []Proposal `json:"proposals,omitempty"`
	// Comments are the newest reply comments per attendee (organizer only).
	Comments map[string]string `json:"comments,omitempty"`
}

// Scheduling describes item's scheduling role and pending decisions for the
// owner of its calendar. The caller must already be authorized to read item.
func (s *Service) Scheduling(ctx context.Context, folder model.Folder, item model.Item) EventScheduling {
	var result EventScheduling
	cal, err := decodeBounded(item.Data)
	if err != nil || folder.Type != model.FolderTypeCalendar {
		return result
	}
	master := calendar.MasterEvent(cal.Events())
	organizer := propAddress(master.Props, ical.PropOrganizer)
	if organizer == "" {
		return result
	}
	if _, own := s.ownIdentity(ctx, folder.UserID, organizer); own {
		result.IsOrganizer = true
		s.mu.Lock()
		state, err := s.state(ctx, item.ID)
		s.mu.Unlock()
		if err == nil && state != nil {
			for _, address := range slices.Sorted(maps.Keys(state.Proposals)) {
				proposal := state.Proposals[address]
				proposal.Counter = nil
				result.Proposals = append(result.Proposals, proposal)
			}
			result.Comments = state.Comments
		}
		return result
	}
	message, err := calendar.ParseITIP(item.Data)
	if err != nil {
		return result
	}
	if attendee := s.ownAttendee(ctx, folder.UserID, message); attendee != "" {
		result.CanRespond = s.Enabled()
		result.Response = currentPartStat(cal, attendee)
	}
	return result
}

// DecideProposal accepts or declines attendee's pending new-time proposal on
// the organizer event itemID. Accepting moves the event to the proposed time
// through the FolderSpace as access, which sends the updated REQUEST to every
// attendee; declining sends the proposer a DECLINECOUNTER.
func (s *Service) DecideProposal(ctx context.Context, access service.AccessContext, itemID, attendee string, accept bool) error {
	if !s.Enabled() {
		return errors.New("calendar invitations are disabled")
	}
	attendee = calendar.MailAddress(attendee)
	item, err := s.cfg.Space.GetItem(ctx, access, itemID)
	if err != nil {
		return err
	}
	folder, err := s.cfg.Space.GetFolder(ctx, access, item.FolderID)
	if err != nil {
		return err
	}
	if folder.Type != model.FolderTypeCalendar {
		return ErrNoProposal
	}
	s.mu.Lock()
	state, err := s.state(ctx, item.ID)
	var proposal Proposal
	found := false
	if err == nil && state != nil {
		proposal, found = state.Proposals[attendee]
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if !found || state.Owner != folder.UserID {
		return ErrNoProposal
	}
	if accept {
		data, err := moveEvent(item.Data, proposal)
		if err != nil {
			return err
		}
		if _, err := s.cfg.Space.UpdateItem(ctx, access, item.ID, data, item.Headers); err != nil {
			return err
		}
		return s.dropProposal(ctx, item.ID, attendee)
	}
	counter, err := calendar.ParseITIP(proposal.Counter)
	if err != nil {
		return err
	}
	payload, err := calendar.BuildDeclineCounter(counter, "mailto:"+state.Organizer)
	if err != nil {
		return err
	}
	if _, local, err := s.localUser(ctx, attendee); err != nil {
		return err
	} else if !local {
		if err := s.mailITIP(ctx, state, payload, calendar.MethodDeclineCounter, []string{attendee}, false, time.Now().UTC()); err != nil {
			return err
		}
	}
	return s.dropProposal(ctx, item.ID, attendee)
}

func (s *Service) dropProposal(ctx context.Context, itemID, attendee string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.state(ctx, itemID)
	if err != nil || state == nil {
		return err
	}
	delete(state.Proposals, attendee)
	return s.saveState(ctx, itemID, state)
}

// moveEvent sets the master event to the proposed time in its own time
// zone, bumps SEQUENCE, and asks every attendee to answer again except the
// proposer, who has agreed to the new time.
func moveEvent(data []byte, proposal Proposal) ([]byte, error) {
	cal, err := decodeBounded(data)
	if err != nil {
		return nil, err
	}
	for index := range cal.Children {
		child := cal.Children[index]
		if child.Name != ical.CompEvent || child.Props.Get(ical.PropRecurrenceID) != nil {
			continue
		}
		loc := time.UTC
		if start := child.Props.Get(ical.PropDateTimeStart); start != nil {
			if tzid := start.Params.Get(ical.PropTimezoneID); tzid != "" {
				if zone, err := time.LoadLocation(tzid); err == nil {
					loc = zone
				}
			}
		}
		child.Props.Del(ical.PropDuration)
		child.Props.SetDateTime(ical.PropDateTimeStart, proposal.Start.In(loc))
		child.Props.SetDateTime(ical.PropDateTimeEnd, proposal.End.In(loc))
		seq := ical.NewProp(ical.PropSequence)
		seq.Value = fmt.Sprint(sequence(child.Props) + 1)
		child.Props.Set(seq)
		for i := range child.Props[ical.PropAttendee] {
			prop := &child.Props[ical.PropAttendee][i]
			if calendar.MailAddress(prop.Value) == proposal.Attendee {
				prop.Params.Set(ical.ParamParticipationStatus, calendar.PartStatAccepted)
				prop.Params.Del(ical.ParamRSVP)
			} else {
				prop.Params.Set(ical.ParamParticipationStatus, "NEEDS-ACTION")
				prop.Params.Set(ical.ParamRSVP, "TRUE")
			}
		}
		return encode(cal)
	}
	return nil, ErrNoProposal
}
