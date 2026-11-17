package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

var errOrganizerOnly = errors.New("only the organizer can change the attendees of a meeting")

// calendarUpdate maps an editor request to a calendar update for an event in
// folder whose current organizer is existingOrganizer. The folder owner
// organizes a meeting given attendees here; the attendees of a meeting
// someone else organizes cannot be changed from the owner's copy.
func (h *Handler) calendarUpdate(ctx context.Context, request workspaceCalendarEventRequest, folder model.Folder, existingOrganizer string) (calendarcore.Update, error) {
	update := calendarcore.Update{Summary: request.Summary, Description: request.Description, Location: request.Location, Start: request.Start, End: request.End,
		AllDay: request.AllDay, Timezone: request.Timezone, Recurrence: request.Recurrence, Attendees: request.Attendees, Alarms: request.Alarms, Categories: request.Categories}
	owned := existingOrganizer == "" || h.ownsAddress(ctx, folder.UserID, existingOrganizer)
	if request.Attendees != nil && !owned {
		return update, errOrganizerOnly
	}
	update.Organizing = owned
	if request.Attendees != nil && len(*request.Attendees) > 0 && existingOrganizer == "" {
		organizer, err := h.calendarOrganizer(ctx, folder.UserID)
		if err != nil {
			return update, err
		}
		update.Organizer = &organizer
	}
	return update, nil
}

// calendarOrganizer returns the primary enabled identity of userID, with the
// account display name, as a meeting organizer.
func (h *Handler) calendarOrganizer(ctx context.Context, userID string) (calendarcore.AttendeeUpdate, error) {
	identities, err := h.users.ListEmailAddressesForUser(ctx, userID)
	if err != nil {
		return calendarcore.AttendeeUpdate{}, err
	}
	var chosen *model.EmailAddress
	for index, identity := range identities {
		if identity.Enabled && (chosen == nil || identity.Primary && !chosen.Primary) {
			chosen = &identities[index]
		}
	}
	if chosen == nil {
		return calendarcore.AttendeeUpdate{}, errors.New("the calendar owner has no email address to organize meetings from")
	}
	organizer := calendarcore.AttendeeUpdate{Address: chosen.ID}
	if user, err := h.users.Get(ctx, userID); err == nil {
		organizer.Name = user.DisplayName
	}
	return organizer, nil
}

func (h *Handler) ownsAddress(ctx context.Context, userID, address string) bool {
	identity, err := h.users.GetEmailAddress(ctx, calendarcore.MailAddress(address))
	return err == nil && strings.EqualFold(identity.UserID, userID)
}

// invitationAnswerRequest is a reply to an invitation, optionally with a
// comment, or a proposal of a new time when both propose_* are set.
type invitationAnswerRequest struct {
	Response     string `json:"response"`
	Comment      string `json:"comment,omitempty"`
	ProposeStart string `json:"propose_start,omitempty"`
	ProposeEnd   string `json:"propose_end,omitempty"`
}

// answerInvitation answers the invitation behind the {id} item (a mail item
// or a calendar copy) as access and writes any error response.
func (h *Handler) answerInvitation(w http.ResponseWriter, r *http.Request, access service.AccessContext) (*imip.Invitation, bool) {
	var request invitationAnswerRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	if h.scheduling == nil {
		jsonError(w, http.StatusServiceUnavailable, "calendar invitations are unavailable")
		return nil, false
	}
	answer := imip.Answer{PartStat: request.Response, Comment: request.Comment}
	if request.ProposeStart != "" || request.ProposeEnd != "" {
		start, startErr := time.Parse(time.RFC3339, request.ProposeStart)
		end, endErr := time.Parse(time.RFC3339, request.ProposeEnd)
		if startErr != nil || endErr != nil {
			jsonError(w, http.StatusBadRequest, "propose_start and propose_end must be RFC 3339 timestamps")
			return nil, false
		}
		answer.ProposedStart, answer.ProposedEnd = start, end
	}
	invitation, err := h.scheduling.Answer(r.Context(), access, r.PathValue("id"), answer)
	switch {
	case errors.Is(err, imip.ErrNoInvitation), errors.Is(err, imip.ErrNotAttendee):
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return nil, false
	case errors.Is(err, imip.ErrInvalidResponse), errors.Is(err, imip.ErrInvalidProposal):
		jsonError(w, http.StatusBadRequest, err.Error())
		return nil, false
	case err != nil:
		apiError(w, err)
		return nil, false
	}
	h.workspaceChanged(r, "calendar.invitation.answered", r.PathValue("id"), map[string]any{"response": invitation.Response, "method": invitation.Method})
	return invitation, true
}

func (h *Handler) apiWorkspaceCalendarEventRespond(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	folder, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeCalendar)
	if err != nil {
		apiError(w, err)
		return
	}
	access, err := h.calendarAnswerAccess(r, folder)
	if err != nil {
		apiError(w, err)
		return
	}
	if invitation, ok := h.answerInvitation(w, r, access); ok {
		h.workspaceChanged(r, "calendar.event.updated", item.ID, map[string]any{"folder_id": item.FolderID})
		jsonResponse(w, http.StatusOK, invitation)
	}
}

// calendarAnswerAccess returns the access an invitation in folder is
// answered with. The owner answers as themself; a delegate holding
// calendar.schedule on the calendar (for example a resource's booking
// approver) answers on the owner's behalf, which is audited.
func (h *Handler) calendarAnswerAccess(r *http.Request, folder model.Folder) (service.AccessContext, error) {
	actor := currentActor(r)
	if strings.EqualFold(actor.ID, folder.UserID) {
		return webAccess(actor, currentSubject(r), currentActingMode(r)), nil
	}
	capabilities, err := h.workspaceFolderCapabilities(r.Context(), r, folder)
	if err != nil {
		return service.AccessContext{}, err
	}
	if !capabilities.Schedule {
		return service.AccessContext{}, fmt.Errorf("only the calendar owner or a delegate can answer: %w", service.ErrForbidden)
	}
	h.audit.Log(actor.ID, "calendar.invitation.delegate_answer", folder.ID, map[string]string{"owner_id": folder.UserID, "item_id": r.PathValue("id")})
	return service.UserAccess(folder.UserID, "calendar-delegate"), nil
}

// apiWorkspaceCalendarProposal accepts or declines an attendee's proposed
// new time on an event the calendar owner organizes.
func (h *Handler) apiWorkspaceCalendarProposal(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Attendee string `json:"attendee"`
		Decision string `json:"decision"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Decision != "accept" && request.Decision != "decline" {
		jsonError(w, http.StatusBadRequest, "decision must be accept or decline")
		return
	}
	if h.scheduling == nil {
		jsonError(w, http.StatusServiceUnavailable, "calendar invitations are unavailable")
		return
	}
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	folder, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeCalendar)
	if err != nil {
		apiError(w, err)
		return
	}
	// Deciding mails the organizer's answer, so it needs the same authority
	// as answering an invitation: the owner or a scheduling delegate.
	access, err := h.calendarAnswerAccess(r, folder)
	if err != nil {
		apiError(w, err)
		return
	}
	err = h.scheduling.DecideProposal(r.Context(), access, item.ID, request.Attendee, request.Decision == "accept")
	if errors.Is(err, imip.ErrNoProposal) {
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "calendar.event.updated", item.ID, map[string]any{"folder_id": item.FolderID})
	w.WriteHeader(http.StatusNoContent)
}

// freeBusyPeriod is a busy interval; Type is BUSY or BUSY-TENTATIVE (RFC
// 5545 FBTYPE).
type freeBusyPeriod = calendarindex.BusyPeriod

type freeBusyAttendee struct {
	Address string `json:"address"`
	// Status is "known" when busy times are reported, or "unknown" for
	// external addresses and accounts whose availability is not visible.
	Status string           `json:"status"`
	Busy   []freeBusyPeriod `json:"busy"`
}

const (
	maxFreeBusyAttendees = 30
	maxFreeBusyRange     = 42 * 24 * time.Hour
	maxFreeBusyPeriods   = 2000
)

// apiWorkspaceCalendarFreeBusy reports busy times, never event details, for
// attendees over a range. A local account's availability is visible to
// accounts sharing one of its mail domains and to accounts it has shared a
// calendar with; every other address is unknown.
func (h *Handler) apiWorkspaceCalendarFreeBusy(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	start, err := time.Parse(time.RFC3339, query.Get("start"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "start must be an RFC 3339 timestamp")
		return
	}
	end, err := time.Parse(time.RFC3339, query.Get("end"))
	if err != nil || !end.After(start) || end.Sub(start) > maxFreeBusyRange {
		jsonError(w, http.StatusBadRequest, "end must be after start and the range must not exceed 42 days")
		return
	}
	addresses := query["attendee"]
	if len(addresses) == 0 || len(addresses) > maxFreeBusyAttendees {
		jsonError(w, http.StatusBadRequest, "between 1 and 30 attendee values are required")
		return
	}
	visible, err := h.freeBusyVisibility(r)
	if err != nil {
		apiError(w, err)
		return
	}
	result := make([]freeBusyAttendee, 0, len(addresses))
	for _, raw := range addresses {
		address := calendarcore.MailAddress(raw)
		entry := freeBusyAttendee{Address: address, Status: "unknown", Busy: []freeBusyPeriod{}}
		identity, err := h.users.GetEmailAddress(r.Context(), address)
		if err == nil && identity.Enabled && visible(identity) {
			busy, err := h.busyPeriods(r.Context(), identity.UserID, start, end)
			if err != nil {
				apiError(w, err)
				return
			}
			entry.Status, entry.Busy = "known", busy
		}
		result = append(result, entry)
	}
	jsonResponse(w, http.StatusOK, result)
}

// freeBusyVisibility returns whether the session subject may see an
// identity's busy times; calendarindex.FreeBusyVisibility holds the rule
// CalDAV schedule-outbox requests share.
func (h *Handler) freeBusyVisibility(r *http.Request) (func(model.EmailAddress) bool, error) {
	return calendarindex.FreeBusyVisibility(r.Context(), h.folderSpace, h.users, webAccess(currentActor(r), currentSubject(r), currentActingMode(r)))
}

// busyPeriods merges the occupying occurrences of userID's own calendars
// into busy periods.
func (h *Handler) busyPeriods(ctx context.Context, userID string, start, end time.Time) ([]freeBusyPeriod, error) {
	periods, err := h.BusyPeriods(ctx, userID, nil, start, end)
	return calendarindex.MergeBusy(periods), err
}

// BusyPeriods lists, unmerged and with their event UIDs, the opaque,
// non-cancelled, non-declined occurrences of folders, or of every calendar
// userID owns when folders is nil.
func (h *Handler) BusyPeriods(ctx context.Context, userID string, folders []model.Folder, start, end time.Time) ([]calendarindex.BusyPeriod, error) {
	return h.calendarIndex.OwnerBusy(ctx, h.folderSpace, h.users, userID, folders, start, end, maxFreeBusyPeriods)
}

// CalendarIndex is the calendar range index the web app maintains; DAV
// shares it so busy time has one implementation and one sealed projection.
func (h *Handler) CalendarIndex() *calendarindex.Index { return h.calendarIndex }
