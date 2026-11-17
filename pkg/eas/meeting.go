package eas

import (
	"bytes"
	"context"
	"strings"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// Scheduler answers meeting invitations (iTIP REPLY to the organizer and
// the account's calendar copy). It is the server's iMIP service.
type Scheduler interface {
	Respond(ctx context.Context, access service.AccessContext, itemID, partStat string) error
}

// meetingResponse implements MeetingResponse: the request is a meeting
// request in a mail folder, or the invited event in a calendar folder.
func (h *Handler) meetingResponse(command *commandContext) (*Node, error) {
	response := E(8, "MeetingResponse")
	for _, request := range command.request.ChildrenNamed("Request") {
		requestID := childText(request, "RequestId")
		result := E(8, "Result", T(8, "RequestId", requestID))
		partStat := map[string]string{"1": "ACCEPTED", "2": "TENTATIVE", "3": "DECLINED"}[childText(request, "UserResponse")]
		calendarID, status, err := h.answerMeeting(command, requestID, partStat)
		if err != nil {
			return nil, err
		}
		result.Children = append(result.Children, T(8, "Status", status))
		if status == "1" && calendarID != "" && partStat != "DECLINED" {
			result.Children = append(result.Children, T(8, "CalendarId", encodeServerID("i:", calendarID)))
		}
		response.Children = append(response.Children, result)
	}
	return response, nil
}

func (h *Handler) answerMeeting(command *commandContext, requestID, partStat string) (string, string, error) {
	itemID, err := decodeServerID(requestID, "i:")
	if err != nil || partStat == "" {
		return "", "2", nil
	}
	item, err := h.space.GetItem(command.ctx, command.access, itemID)
	if err != nil {
		return "", "2", nil
	}
	folder, err := h.space.GetFolder(command.ctx, command.access, item.FolderID)
	if err != nil {
		return "", "2", nil
	}
	data := item.Data
	if folder.Type == model.FolderTypeMail {
		projection, projectErr := service.ProjectMIME(item.Data)
		if projectErr != nil || len(projection.Calendar) == 0 {
			return "", "2", nil
		}
		data = projection.Calendar
	} else if folder.Type != model.FolderTypeCalendar {
		return "", "2", nil
	}
	event := parseCalendarEvent(data)
	if event == nil {
		return "", "2", nil
	}
	uid, _ := event.master.Props.Text(ical.PropUID)
	if h.scheduler != nil {
		if err := h.scheduler.Respond(command.ctx, command.access, itemID, partStat); err != nil {
			if service.IsTemporarilyUnavailable(err) {
				return "", "", err
			}
			return "", "4", nil
		}
	} else if err := h.recordAnswer(command, folder, item, data, partStat); err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return "", "", err
		}
		return "", "3", nil
	}
	if folder.Type == model.FolderTypeCalendar {
		return item.ID, "1", nil
	}
	calendarItem, found := h.findEventByUID(command, uid)
	if !found {
		return "", "1", nil
	}
	return calendarItem.ID, "1", nil
}

// recordAnswer stores the user's PARTSTAT in the calendar copy when no
// scheduler is configured (no reply is sent in that case).
func (h *Handler) recordAnswer(command *commandContext, folder model.Folder, item model.Item, data []byte, partStat string) error {
	profile := h.profile(command)
	target := item
	if folder.Type == model.FolderTypeMail {
		event := parseCalendarEvent(data)
		uid, _ := event.master.Props.Text(ical.PropUID)
		existing, found := h.findEventByUID(command, uid)
		if !found {
			calendars, err := h.space.ListFolders(command.ctx, command.access, service.FolderQuery{Type: model.FolderTypeCalendar})
			if err != nil {
				return err
			}
			var calendarID string
			for _, candidate := range calendars {
				if candidate.UserID == command.userID && (calendarID == "" || candidate.SpecialUse == model.SpecialUseCalendar) {
					calendarID = candidate.ID
				}
			}
			if calendarID == "" {
				return service.ErrInvalidRequest
			}
			event.cal.Props.Del(ical.PropMethod)
			var buffer bytes.Buffer
			if err := ical.NewEncoder(&buffer).Encode(event.cal); err != nil {
				return err
			}
			summary, _ := event.master.Props.Text(ical.PropSummary)
			created, err := h.space.CreateItem(command.ctx, command.access, calendarID, service.ItemInput{Data: buffer.Bytes(), Headers: map[string]string{"UID": uid, "SUMMARY": summary}})
			if err != nil {
				return err
			}
			existing = created
		}
		target = existing
	}
	event := parseCalendarEvent(target.Data)
	if event == nil {
		return service.ErrInvalidRequest
	}
	for _, component := range append([]*ical.Component{event.master}, event.overrides...) {
		for index := range component.Props[ical.PropAttendee] {
			attendee := &component.Props[ical.PropAttendee][index]
			if profile.owns(calendar.MailAddress(attendee.Value)) {
				attendee.Params.Set(ical.ParamParticipationStatus, partStat)
				attendee.Params.Del(ical.ParamRSVP)
			}
		}
	}
	var buffer bytes.Buffer
	if err := ical.NewEncoder(&buffer).Encode(event.cal); err != nil {
		return err
	}
	_, err := h.space.UpdateItem(command.ctx, command.access, target.ID, buffer.Bytes(), target.Headers)
	return err
}

// findEventByUID finds the user's calendar item for an event UID.
func (h *Handler) findEventByUID(command *commandContext, uid string) (model.Item, bool) {
	if uid == "" {
		return model.Item{}, false
	}
	folders, err := h.space.ListFolders(command.ctx, command.access, service.FolderQuery{Type: model.FolderTypeCalendar})
	if err != nil {
		return model.Item{}, false
	}
	for _, folder := range folders {
		if folder.UserID != command.userID {
			continue
		}
		items, err := h.space.ListItems(command.ctx, command.access, folder.ID, service.ItemQuery{})
		if err != nil {
			continue
		}
		for _, item := range items {
			if strings.EqualFold(item.Headers["UID"], uid) {
				return item, true
			}
			if event := parseCalendarEvent(item.Data); event != nil {
				if candidate, _ := event.master.Props.Text(ical.PropUID); candidate == uid {
					return item, true
				}
			}
		}
	}
	return model.Item{}, false
}
