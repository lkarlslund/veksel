package caldav

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// --- Schedule outbox POST (RFC 6638 §5) ---
//
// Veksel schedules events implicitly: invitations, replies and cancellations
// follow from ordinary calendar writes (pkg/imip), so the outbox accepts
// only free/busy lookups. A client POSTs a VFREEBUSY REQUEST naming the
// attendees and receives one CALDAV:response per recipient.

const (
	// maxScheduleRequestSize bounds a free/busy request body.
	maxScheduleRequestSize = 1 << 20
	// maxFreeBusyRecipients bounds the attendees of one request
	// (CALDAV:max-recipients).
	maxFreeBusyRecipients = 50
	// maxFreeBusyReplyPeriods bounds the busy periods read per recipient.
	maxFreeBusyReplyPeriods = 2000
)

// iTIP request statuses (RFC 5546 §3.6) answered per recipient.
const (
	statusSuccess         = "2.0;Success"
	statusInvalidUser     = "3.7;Invalid calendar user"
	statusNoAuthority     = "3.8;No authority"
	statusUnavailable     = "5.1;Service unavailable"
	statusNoSchedulingFor = "5.3;No scheduling support for user"
)

// scheduleResponse is the CALDAV:schedule-response body of an outbox POST.
type scheduleResponse struct {
	XMLName   xml.Name                `xml:"C:schedule-response"`
	XmlnsD    string                  `xml:"xmlns:d,attr"`
	XmlnsC    string                  `xml:"xmlns:C,attr"`
	Responses []scheduleRecipientResp `xml:"C:response"`
}

type scheduleRecipientResp struct {
	Recipient     davHomeSet `xml:"C:recipient"`
	RequestStatus string     `xml:"C:request-status"`
	CalendarData  string     `xml:"C:calendar-data,omitempty"`
	Description   string     `xml:"d:responsedescription,omitempty"`
}

// freeBusyRequest is a parsed VFREEBUSY REQUEST.
type freeBusyRequest struct {
	uid        string
	organizer  string
	start, end time.Time
	attendees  []string
}

// handlePost serves POST, which DAV defines only on the schedule outbox.
func (h *Handler) handlePost(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) != 1 || parts[0] != model.ScheduleOutboxPath {
		h.respondError(w, r, http.StatusMethodNotAllowed, "bad-method", "POST is only supported on the schedule outbox")
		return
	}
	// Only the owner holds CALDAV:schedule-send on an outbox (RFC 6638
	// §6.2); delegates and sharees act through implicit scheduling.
	actor, _ := r.Context().Value(authenticatedUserKey{}).(string)
	if !strings.EqualFold(actor, username) {
		respondCalDAVPrecondition(w, http.StatusForbidden, "need-privileges", "only the outbox owner can send scheduling requests")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxScheduleRequestSize+1))
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}
	if len(data) > maxScheduleRequestSize {
		respondCalDAVPrecondition(w, http.StatusRequestEntityTooLarge, "max-resource-size", "scheduling request is too large")
		return
	}
	request, status, condition, err := parseFreeBusyRequest(data)
	if err != nil {
		respondCalDAVPrecondition(w, status, condition, err.Error())
		return
	}
	if !h.ownsCalendarAddress(r.Context(), username, request.organizer) {
		respondCalDAVPrecondition(w, http.StatusForbidden, "organizer-allowed", "ORGANIZER is not one of your addresses")
		return
	}
	visible, err := calendarindex.FreeBusyVisibility(r.Context(), h.store.space, h.store.users, davAccess(r.Context(), username))
	if err != nil {
		_ = noteDAVError(r.Context(), err)
		log.Error("caldav: free/busy visibility", "user", username, "error", err)
		h.respondError(w, r, http.StatusInternalServerError, "server-error", "cannot evaluate free/busy visibility")
		return
	}
	now := time.Now().UTC()
	result := scheduleResponse{XmlnsD: NSDAV, XmlnsC: NSSCalDAV, Responses: make([]scheduleRecipientResp, 0, len(request.attendees))}
	for _, attendee := range request.attendees {
		result.Responses = append(result.Responses, h.freeBusyReply(r.Context(), request, attendee, visible, now))
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(result)
}

// freeBusyReply answers one recipient of request.
func (h *Handler) freeBusyReply(ctx context.Context, request freeBusyRequest, attendee string, visible func(model.EmailAddress) bool, now time.Time) scheduleRecipientResp {
	resp := scheduleRecipientResp{Recipient: davHomeSet{Href: attendee}}
	address, ok := mailtoAddress(attendee)
	if !ok {
		resp.RequestStatus = statusInvalidUser
		return resp
	}
	route, err := h.resolveRecipient(ctx, address)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// No remote lookup: an address in a hosted domain that matches
		// nothing is invalid, any other address is beyond this server.
		resp.RequestStatus = statusNoSchedulingFor
		if h.localDomain(ctx, address) {
			resp.RequestStatus = statusInvalidUser
		}
		return resp
	case err != nil:
		log.Error("caldav: resolve free/busy recipient", "error", err)
		resp.RequestStatus = statusUnavailable
		return resp
	}
	// Aliases have no single calendar; disabled identities and catch-all
	// matches are not calendar users.
	identity, err := route.Mailbox()
	if err != nil || !identity.Enabled || route.CatchAll || route.Discard {
		resp.RequestStatus = statusInvalidUser
		return resp
	}
	if !visible(identity) {
		resp.RequestStatus = statusNoAuthority
		return resp
	}
	periods, err := h.calendars.OwnerBusy(ctx, h.store.space, h.store.users, identity.UserID, nil, request.start, request.end, maxFreeBusyReplyPeriods)
	if err != nil {
		_ = noteDAVError(ctx, err)
		log.Error("caldav: free/busy reply", "user", identity.UserID, "error", err)
		resp.RequestStatus = statusUnavailable
		return resp
	}
	resp.RequestStatus = statusSuccess
	resp.CalendarData = string(calendarindex.EncodeVFreeBusyReply(periods, request.start, request.end, now, request.uid, "-//Veksel//CalDAV//EN",
		calendarindex.FreeBusyReply{Organizer: request.organizer, Attendee: attendee}))
	return resp
}

// parseFreeBusyRequest validates an outbox POST body as a VFREEBUSY REQUEST.
// On failure it returns the HTTP status and CALDAV precondition to report.
func parseFreeBusyRequest(data []byte) (freeBusyRequest, int, string, error) {
	var request freeBusyRequest
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return request, http.StatusBadRequest, "valid-calendar-data", fmt.Errorf("invalid iCalendar data: %v", err)
	}
	var freeBusy []*ical.Component
	for _, child := range cal.Children {
		switch child.Name {
		case ical.CompFreeBusy:
			freeBusy = append(freeBusy, child)
		case ical.CompEvent, ical.CompToDo, ical.CompJournal:
			// Invitations, replies and cancellations follow from calendar
			// writes; accepting them here would schedule twice.
			return request, http.StatusForbidden, "valid-scheduling-message",
				errors.New("this server schedules implicitly: save the event in a calendar instead of posting it to the outbox")
		}
	}
	if len(freeBusy) != 1 {
		return request, http.StatusBadRequest, "valid-scheduling-message", errors.New("a free/busy request holds exactly one VFREEBUSY component")
	}
	if method, _ := cal.Props.Text(ical.PropMethod); !strings.EqualFold(strings.TrimSpace(method), "REQUEST") {
		return request, http.StatusBadRequest, "valid-scheduling-message", errors.New("a free/busy request must have METHOD:REQUEST")
	}
	component := freeBusy[0]
	request.uid, _ = component.Props.Text(ical.PropUID)
	if strings.TrimSpace(request.uid) == "" {
		return request, http.StatusBadRequest, "valid-scheduling-message", errors.New("VFREEBUSY requires a UID")
	}
	if organizer := component.Props.Get(ical.PropOrganizer); organizer != nil {
		request.organizer = strings.TrimSpace(organizer.Value)
	}
	if request.organizer == "" {
		return request, http.StatusBadRequest, "valid-scheduling-message", errors.New("VFREEBUSY requires an ORGANIZER")
	}
	seen := map[string]bool{}
	for _, prop := range component.Props.Values(ical.PropAttendee) {
		attendee := strings.TrimSpace(prop.Value)
		key := strings.ToLower(attendee)
		if attendee == "" || seen[key] {
			continue
		}
		seen[key] = true
		request.attendees = append(request.attendees, attendee)
	}
	if len(request.attendees) == 0 {
		return request, http.StatusBadRequest, "valid-scheduling-message", errors.New("VFREEBUSY requires at least one ATTENDEE")
	}
	if len(request.attendees) > maxFreeBusyRecipients {
		return request, http.StatusForbidden, "max-recipients", fmt.Errorf("at most %d attendees can be looked up at once", maxFreeBusyRecipients)
	}
	start, startErr := component.Props.DateTime(ical.PropDateTimeStart, time.UTC)
	end, endErr := component.Props.DateTime(ical.PropDateTimeEnd, time.UTC)
	if startErr != nil || endErr != nil || start.IsZero() || end.IsZero() {
		return request, http.StatusBadRequest, "valid-scheduling-message", errors.New("VFREEBUSY requires a valid DTSTART and DTEND")
	}
	if !end.After(start) || end.Sub(start) > maxFreeBusySpan {
		return request, http.StatusBadRequest, "valid-scheduling-message", errors.New("DTEND must follow DTSTART by at most two years")
	}
	request.start, request.end = start.UTC(), end.UTC()
	return request, 0, "", nil
}

// mailtoAddress returns the mail address of a mailto: calendar user
// address; other URI schemes name no mailbox here.
func mailtoAddress(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 7 || !strings.EqualFold(value[:7], "mailto:") {
		return "", false
	}
	address := calendarcore.MailAddress(value)
	at := strings.LastIndex(address, "@")
	return address, at > 0 && at < len(address)-1
}

// ownsCalendarAddress reports whether value is a mailto: address of one of
// userID's enabled identities.
func (h *Handler) ownsCalendarAddress(ctx context.Context, userID, value string) bool {
	address, ok := mailtoAddress(value)
	if !ok {
		return false
	}
	identity, err := h.store.users.GetEmailAddress(ctx, address)
	return err == nil && identity.Enabled && strings.EqualFold(identity.UserID, userID)
}

// localDomain reports whether address is in a domain this server hosts.
func (h *Handler) localDomain(ctx context.Context, address string) bool {
	if h.domains == nil {
		return false
	}
	_, err := h.domains.Get(ctx, address[strings.LastIndex(address, "@")+1:])
	return err == nil
}

// respondCalDAVPrecondition writes a DAV:error naming a failed CALDAV
// precondition (RFC 6638 §5.1), with msg as its description.
func respondCalDAVPrecondition(w http.ResponseWriter, status int, condition, msg string) {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(msg))
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<d:error xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
 <C:%s/>
 <d:responsedescription>%s</d:responsedescription>
</d:error>`, condition, escaped.String())
}

// ensureScheduleCollection returns username's schedule inbox or outbox,
// creating it on first use.
func (h *Handler) ensureScheduleCollection(ctx context.Context, username, path string) (model.Folder, error) {
	folder, err := h.store.FolderStore().GetByPath(ctx, username, path)
	if err == nil {
		return folder, nil
	}
	folderType := model.FolderTypeScheduleInbox
	if path == model.ScheduleOutboxPath {
		folderType = model.FolderTypeScheduleOutbox
	}
	if err := h.store.FolderStore().Create(ctx, username, path, folderType, ""); err != nil && !errors.Is(err, store.ErrExists) {
		return model.Folder{}, err
	}
	return h.store.FolderStore().GetByPath(ctx, username, path)
}

// calendarUserAddresses lists username's calendar user addresses (RFC 6638
// §2.4.1): the mailto: URI of each enabled identity, primary first, then the
// principal URL.
func (h *Handler) calendarUserAddresses(ctx context.Context, username string) []string {
	identities, err := h.store.users.ListEmailAddressesForUser(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		log.Warn("caldav: list calendar user addresses", "user", username, "error", err)
	}
	hrefs := make([]string, 0, len(identities)+1)
	for _, identity := range identities {
		if identity.Enabled && identity.Primary {
			hrefs = append(hrefs, "mailto:"+identity.ID)
		}
	}
	for _, identity := range identities {
		if identity.Enabled && !identity.Primary {
			hrefs = append(hrefs, "mailto:"+identity.ID)
		}
	}
	return append(hrefs, buildHref(username)+"/")
}

// calendarUserType is username's CALDAV:calendar-user-type (RFC 6638
// §2.4.2): ROOM or RESOURCE for bookable accounts.
func (h *Handler) calendarUserType(ctx context.Context, username string) string {
	user, err := h.store.users.Get(ctx, username)
	if err != nil || user.Resource == nil {
		return "INDIVIDUAL"
	}
	if user.Resource.Kind == model.BookableRoom {
		return "ROOM"
	}
	return "RESOURCE"
}

// schedulePrivileges describes the privileges of a schedule collection
// (RFC 6638 §6): the outbox supports schedule-send and its parts, the inbox
// schedule-deliver and its parts. The owner holds all of them.
func schedulePrivileges(folder model.Folder, owner bool) (*davSupportedPrivilegeSet, *davPrivilegeList) {
	var aggregate davSupportedPrivilege
	var held []davPrivilege
	switch folder.Type {
	case model.FolderTypeScheduleOutbox:
		aggregate = davSupportedPrivilege{Privilege: davPrivilege{ScheduleSend: &empty{}}, Children: []davSupportedPrivilege{
			{Privilege: davPrivilege{ScheduleSendInvite: &empty{}}},
			{Privilege: davPrivilege{ScheduleSendReply: &empty{}}},
			{Privilege: davPrivilege{ScheduleSendFreeBusy: &empty{}}},
		}}
		held = []davPrivilege{{Read: &empty{}}, {ScheduleSend: &empty{}}, {ScheduleSendInvite: &empty{}}, {ScheduleSendReply: &empty{}}, {ScheduleSendFreeBusy: &empty{}}}
	case model.FolderTypeScheduleInbox:
		aggregate = davSupportedPrivilege{Privilege: davPrivilege{ScheduleDeliver: &empty{}}, Children: []davSupportedPrivilege{
			{Privilege: davPrivilege{ScheduleDeliverInvite: &empty{}}},
			{Privilege: davPrivilege{ScheduleDeliverReply: &empty{}}},
			{Privilege: davPrivilege{ScheduleQueryFreeBusy: &empty{}}},
		}}
		held = []davPrivilege{{Read: &empty{}}, {Write: &empty{}}, {ScheduleDeliver: &empty{}}, {ScheduleDeliverInvite: &empty{}}, {ScheduleDeliverReply: &empty{}}, {ScheduleQueryFreeBusy: &empty{}}}
	default:
		return nil, nil
	}
	supported := &davSupportedPrivilegeSet{SupportedPrivilege: []davSupportedPrivilege{{
		Privilege: davPrivilege{All: &empty{}}, Abstract: &empty{},
		Children: []davSupportedPrivilege{{Privilege: davPrivilege{Read: &empty{}}}, {Privilege: davPrivilege{Write: &empty{}}}, aggregate},
	}}}
	if !owner {
		return supported, &davPrivilegeList{}
	}
	return supported, &davPrivilegeList{Privilege: held}
}

// resolveRecipient routes address through the configured recipient
// resolver, or the store's resolver without subaddressing.
func (h *Handler) resolveRecipient(ctx context.Context, address string) (model.RecipientRoute, error) {
	if h.config.ResolveRecipient != nil {
		return h.config.ResolveRecipient(ctx, address)
	}
	if h.typed == nil {
		return model.RecipientRoute{}, store.ErrNotFound
	}
	return h.typed.ResolveRecipient(ctx, address, "")
}
