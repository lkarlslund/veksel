package imip

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// localDelivery is an iTIP REQUEST or CANCEL for a local attendee's
// calendar. Deliveries run after the state lock is released because the
// attendee copy is written through the observed FolderSpace, which
// re-enters ItemWritten.
type localDelivery struct {
	userID  string
	payload []byte
	method  string
	sender  string
	// senderName is the organizer's CN, shown on the Inbox copy.
	senderName string
	// address is the invited identity, the To of the Inbox copy.
	address string
	// updated marks a REQUEST that revises an invitation already sent.
	updated bool
}

// ItemWritten schedules attendees after a committed calendar write: external
// attendees by mail, local attendees by delivery to their calendars. It
// implements rules.ItemObserver.
func (s *Service) ItemWritten(ctx context.Context, access service.AccessContext, item model.Item) {
	if !s.Enabled() || silent(ctx) || (!mayBeEvent(item.Data) && !s.hasState(ctx, item.ID)) {
		return
	}
	folder, err := s.cfg.Space.GetFolder(ctx, access, item.FolderID)
	if err != nil || folder.Type != model.FolderTypeCalendar {
		return
	}
	s.mu.Lock()
	previous, err := s.state(ctx, item.ID)
	if err != nil {
		s.mu.Unlock()
		logger.Error("iMIP: load scheduling state", "item_id", item.ID, "error", err)
		return
	}
	deliveries, err := s.schedule(ctx, folder.UserID, item, previous)
	s.mu.Unlock()
	if err != nil {
		logger.Error("iMIP: schedule attendees", "item_id", item.ID, "error", err)
	}
	s.deliverLocal(ctx, deliveries)
}

// ItemRemoved cancels the invitations of a deleted or trashed organizer
// event. It implements rules.ItemObserver.
func (s *Service) ItemRemoved(ctx context.Context, _ service.AccessContext, itemID string) {
	if !s.Enabled() || !s.hasState(ctx, itemID) {
		return
	}
	s.mu.Lock()
	previous, err := s.state(ctx, itemID)
	if err != nil || previous == nil {
		s.mu.Unlock()
		return
	}
	var deliveries []localDelivery
	if !silent(ctx) {
		deliveries, err = s.cancelAll(ctx, previous)
	}
	if err == nil {
		err = s.saveState(ctx, itemID, nil)
	}
	s.mu.Unlock()
	if err != nil {
		logger.Error("iMIP: cancel removed event", "item_id", itemID, "error", err)
	}
	s.deliverLocal(ctx, deliveries)
}

// localUser resolves address through the recipient resolver. local reports
// whether the address belongs to this server; userID is the account of a
// terminal identity, empty for aliases and disabled identities.
func (s *Service) localUser(ctx context.Context, address string) (userID string, local bool, err error) {
	route, err := s.cfg.Resolve(ctx, address)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if route.Disabled || !route.Identity.Enabled || route.CatchAll {
		return "", true, nil
	}
	return route.Identity.UserID, true, nil
}

// cancelAll cancels every attendee of a scheduled event; callers hold s.mu.
func (s *Service) cancelAll(ctx context.Context, previous *eventState) ([]localDelivery, error) {
	if err := s.sendCancel(ctx, previous, previous.Recipients); err != nil {
		return nil, err
	}
	return localCancels(previous, slices.Collect(maps.Keys(previous.Local)))
}

// schedule compares an organizer event with what its attendees were last
// sent, mails the external difference, and returns the local deliveries;
// callers hold s.mu.
func (s *Service) schedule(ctx context.Context, owner string, item model.Item, previous *eventState) ([]localDelivery, error) {
	cal, err := decodeBounded(item.Data)
	if err != nil {
		return nil, nil // not a schedulable event; leave any state for a later valid save
	}
	master := calendar.MasterEvent(cal.Events())
	uid, _ := master.Props.Text(ical.PropUID)
	organizer := propAddress(master.Props, ical.PropOrganizer)
	identity, owned := s.ownIdentity(ctx, owner, organizer)
	if uid == "" || !owned {
		if previous != nil && organizer == "" {
			// The organizer turned the meeting back into a private event.
			deliveries, err := s.cancelAll(ctx, previous)
			if err != nil {
				return nil, err
			}
			return deliveries, s.saveState(ctx, item.ID, nil)
		}
		return nil, nil
	}
	var external []string
	local := map[string]string{}
	for _, address := range scheduledAttendees(cal, organizer) {
		userID, isLocal, err := s.localUser(ctx, address)
		if err != nil {
			return nil, err
		}
		switch {
		case !isLocal:
			external = append(external, address)
		case userID != "" && !strings.EqualFold(userID, owner):
			local[address] = userID
		}
	}
	if eventStatus(master.Props) == string(ical.EventCancelled) {
		if previous == nil {
			return nil, nil
		}
		deliveries, err := s.cancelAll(ctx, previous)
		if err != nil {
			return nil, err
		}
		return deliveries, s.saveState(ctx, item.ID, nil)
	}
	next := &eventState{Owner: owner, UID: uid, Organizer: identity.ID, OrganizerName: master.Props.Get(ical.PropOrganizer).Params.Get(ical.ParamCommonName), Sequence: sequence(master.Props), Timing: timing(cal), Content: content(master.Props), Recipients: external, Local: local, Source: item.Data}
	if len(local) == 0 {
		next.Local = nil
	}
	if previous == nil {
		if len(external) == 0 && len(local) == 0 {
			return nil, nil
		}
		if len(external) > 0 {
			if err := s.sendRequest(ctx, next, external, false); err != nil {
				return nil, err
			}
		}
		deliveries, err := localRequests(next, slices.Collect(maps.Keys(local)), nil, false)
		if err != nil {
			return nil, err
		}
		return deliveries, s.saveState(ctx, item.ID, next)
	}
	next.Replies, next.Comments, next.Proposals = previous.Replies, previous.Comments, previous.Proposals
	removed, added := difference(previous.Recipients, external), difference(external, previous.Recipients)
	previousLocal, nextLocal := slices.Sorted(maps.Keys(previous.Local)), slices.Sorted(maps.Keys(local))
	removedLocal, addedLocal := difference(previousLocal, nextLocal), difference(nextLocal, previousLocal)
	if len(removed) > 0 {
		if err := s.sendCancel(ctx, previous, removed); err != nil {
			return nil, err
		}
	}
	deliveries, err := localCancels(previous, removedLocal)
	if err != nil {
		return nil, err
	}
	changed := next.Sequence > previous.Sequence || next.Timing != previous.Timing
	switch {
	case changed && len(external) > 0:
		if err := s.sendRequest(ctx, next, external, true); err != nil {
			return nil, err
		}
	case len(added) > 0:
		if err := s.sendRequest(ctx, next, added, false); err != nil {
			return nil, err
		}
	}
	// Local copies follow schedule and text changes; an attendee answer
	// recorded on the organizer copy does not fan out to every attendee.
	requested := addedLocal
	if changed || next.Content != previous.Content {
		requested = nextLocal
	}
	requests, err := localRequests(next, requested, addedLocal, true)
	if err != nil {
		return nil, err
	}
	deliveries = append(deliveries, requests...)
	for address := range next.Proposals {
		if !slices.Contains(external, address) && local[address] == "" {
			delete(next.Proposals, address)
		}
	}
	if len(external) == 0 && len(local) == 0 {
		return deliveries, s.saveState(ctx, item.ID, nil)
	}
	if len(removed) == 0 && len(added) == 0 && len(removedLocal) == 0 && len(addedLocal) == 0 && !changed && bytes.Equal(previous.Source, item.Data) {
		return deliveries, nil
	}
	return deliveries, s.saveState(ctx, item.ID, next)
}

// difference lists the values of a that are not in b.
func difference(a, b []string) []string {
	var result []string
	for _, value := range a {
		if !slices.Contains(b, value) {
			result = append(result, value)
		}
	}
	return result
}

// localRequests builds REQUEST deliveries for addresses; in a revision, every
// address not in added already holds the invitation and receives an update.
func localRequests(state *eventState, addresses, added []string, revision bool) ([]localDelivery, error) {
	if len(addresses) == 0 {
		return nil, nil
	}
	payload, err := requestCalendar(state.Source, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	deliveries := make([]localDelivery, 0, len(addresses))
	for _, address := range addresses {
		deliveries = append(deliveries, localDelivery{userID: state.Local[address], payload: payload, method: calendar.MethodRequest, sender: state.Organizer,
			senderName: state.OrganizerName, address: address, updated: revision && !slices.Contains(added, address)})
	}
	return deliveries, nil
}

func localCancels(state *eventState, addresses []string) ([]localDelivery, error) {
	deliveries := make([]localDelivery, 0, len(addresses))
	for _, address := range addresses {
		payload, err := cancelCalendar(state.Source, []string{address})
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, localDelivery{userID: state.Local[address], payload: payload, method: calendar.MethodCancel, sender: state.Organizer,
			senderName: state.OrganizerName, address: address})
	}
	return deliveries, nil
}

// deliverLocal applies REQUEST and CANCEL messages to local attendees'
// calendars through the FolderSpace as each attendee, with the same rules
// as an iMIP message from the organizer: only the organizer's own event is
// changed, and an unchanged schedule keeps the attendee's answer. Like
// Exchange, it also mails each person attendee the scheduling message, so
// the invitation (answerable from the mail reader) or cancellation reaches
// their Inbox; the calendar copy is already in place when it arrives.
func (s *Service) deliverLocal(ctx context.Context, deliveries []localDelivery) {
	for _, delivery := range deliveries {
		if delivery.userID == "" {
			continue
		}
		message, err := calendar.ParseITIP(delivery.payload)
		if err != nil {
			continue
		}
		cal, err := decodeBounded(delivery.payload)
		if err != nil {
			continue
		}
		in := incoming{message: message, cal: cal, sender: calendar.MailAddress(delivery.sender)}
		if delivery.method == calendar.MethodCancel {
			err = s.applyCancel(ctx, delivery.userID, in)
		} else {
			err = s.storeInvitation(ctx, delivery.userID, in, "")
		}
		if err != nil && !errors.Is(err, errIgnored) {
			logger.Warn("iMIP: deliver to local attendee", "method", delivery.method, "uid", message.UID, "attendee", delivery.userID, "error", err)
			continue
		}
		logger.Info("iMIP: delivered to local attendee", "method", delivery.method, "uid", message.UID, "attendee", delivery.userID)
		if err != nil {
			continue
		}
		if s.cfg.Resource != nil && s.cfg.Resource(ctx, delivery.userID) != nil {
			s.bookResource(ctx, delivery.userID, message)
			continue
		}
		if err := s.mailLocal(ctx, delivery, message); err != nil {
			logger.Warn("iMIP: mail invitation to local attendee", "method", delivery.method, "uid", message.UID, "attendee", delivery.userID, "error", err)
		}
	}
}

// mailLocal sends a local attendee the Inbox copy of a scheduling message
// already applied to their calendar. Delivery runs the normal local mail
// path; re-applying the message there leaves the calendar copy as it is.
func (s *Service) mailLocal(ctx context.Context, delivery localDelivery, message *calendar.ITIPMessage) error {
	if delivery.address == "" {
		return nil
	}
	intro := "You have been invited to an event."
	switch {
	case delivery.method == calendar.MethodCancel:
		intro = "This event has been cancelled."
	case delivery.updated:
		intro = "This event has been updated."
	}
	raw, err := buildMail(mailContent{
		From: sender(delivery.sender, delivery.senderName), To: []string{delivery.address},
		Subject: subjectFor(delivery.method, "", delivery.updated, message.Summary), Text: summaryText(intro, message),
		Method: delivery.method, Calendar: delivery.payload,
	}, time.Now().UTC())
	if err != nil {
		return err
	}
	return s.cfg.Send(ctx, Outgoing{From: delivery.sender, To: []string{delivery.address}, Raw: raw, UID: message.UID, Local: true})
}

func (s *Service) sendRequest(ctx context.Context, state *eventState, recipients []string, updated bool) error {
	now := time.Now().UTC()
	payload, err := requestCalendar(state.Source, now)
	if err != nil {
		return err
	}
	return s.mailITIP(ctx, state, payload, calendar.MethodRequest, recipients, updated, now)
}

func (s *Service) sendCancel(ctx context.Context, state *eventState, recipients []string) error {
	if len(recipients) == 0 {
		return nil
	}
	payload, err := cancelCalendar(state.Source, recipients)
	if err != nil {
		return err
	}
	return s.mailITIP(ctx, state, payload, calendar.MethodCancel, recipients, false, time.Now().UTC())
}

func (s *Service) mailITIP(ctx context.Context, state *eventState, payload []byte, method string, recipients []string, updated bool, now time.Time) error {
	message, err := calendar.ParseITIP(payload)
	if err != nil {
		return err
	}
	intro := "You have been invited to an event."
	switch {
	case method == calendar.MethodCancel:
		intro = "This event has been cancelled."
	case method == calendar.MethodDeclineCounter:
		intro = "The organizer declined your proposed new time."
	case updated:
		intro = "This event has been updated."
	}
	raw, err := buildMail(mailContent{
		From: sender(state.Organizer, state.OrganizerName), To: recipients,
		Subject: subjectFor(method, "", updated, message.Summary), Text: summaryText(intro, message),
		Method: method, Calendar: payload,
	}, now)
	if err != nil {
		return err
	}
	if err := s.cfg.Send(ctx, Outgoing{From: state.Organizer, To: recipients, Raw: raw, UID: state.UID}); err != nil {
		return err
	}
	logger.Info("iMIP: sent scheduling message", "method", method, "uid", state.UID, "organizer", state.Organizer, "recipients", len(recipients))
	return nil
}
