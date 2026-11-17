package jmap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// JMAP Calendars (draft-ietf-jmap-calendars): Calendar, CalendarEvent and
// ParticipantIdentity over the FolderSpace calendar collections CalDAV
// serves. Event writes pass through the same FolderSpace as every other
// protocol, so the iMIP item observer schedules attendees when an organizer
// saves a meeting.

var (
	queryWindowStart = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	queryWindowEnd   = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
)

func calendarCodec() itemCodec {
	return itemCodec{
		kind:      calendarsKind,
		extension: "ics",
		headers:   map[string]string{"Content-Type": "text/calendar; charset=utf-8"},
		decode: func(item model.Item) (map[string]any, error) {
			cal, err := calendar.Decode(item.Data)
			if err != nil {
				return nil, err
			}
			event, err := decodeCalendarEvent(cal)
			if err != nil {
				return nil, err
			}
			event["isDraft"] = false
			return event, nil
		},
		encode: func(_ context.Context, _ service.AccessContext, object map[string]any, original *model.Item) ([]byte, error) {
			var base *ical.Calendar
			if original != nil {
				var err error
				if base, err = calendar.Decode(original.Data); err != nil {
					return nil, err
				}
			}
			cal, err := encodeCalendarEvent(object, base, time.Now())
			if err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
				return nil, fmt.Errorf("encode iCalendar: %w", err)
			}
			return buf.Bytes(), nil
		},
		newUID:    newUUID,
		match:     matchEvent,
		sortValue: eventSortValue,
	}
}

func matchEvent(event map[string]any, item model.Item, condition map[string]any) (bool, error) {
	after, before := queryWindowStart, queryWindowEnd
	window := false
	for property, value := range condition {
		text, _ := value.(string)
		var ok bool
		switch property {
		case "inCalendar":
			ok = item.FolderID == text
		case "uid":
			ok = event["uid"] == text
		case "after", "before":
			when, valid := utcDate(value)
			if !valid {
				return false, fmt.Errorf("%s must be a UTCDate", property)
			}
			if property == "after" {
				after = when
			} else {
				before = when
			}
			window, ok = true, true
		case "text":
			ok = anyContains(textValues(event), text)
		case "title", "description":
			value, _ := event[property].(string)
			ok = containsFold(value, text)
		case "location":
			ok = anyContains(append(textValues(event["locations"]), textValues(event["virtualLocations"])...), text)
		case "owner", "attendee":
			ok = participantMatches(event, property == "owner", text)
		default:
			return false, fmt.Errorf("%w %s", errUnsupportedFilter, property)
		}
		if !ok {
			return false, nil
		}
	}
	if window {
		occurrences, _, err := calendar.Occurrences(item.Data, after, before)
		if err != nil || len(occurrences) == 0 {
			return false, nil
		}
	}
	return true, nil
}

func participantMatches(event map[string]any, owner bool, needle string) bool {
	participants, _ := event["participants"].(map[string]any)
	for _, raw := range participants {
		p, _ := raw.(map[string]any)
		roles, _ := p["roles"].(map[string]any)
		attending := roles["attendee"] == true || roles["chair"] == true || roles["optional"] == true || roles["informational"] == true
		if (owner && roles["owner"] != true) || (!owner && !attending) {
			continue
		}
		if anyContains(textValues(map[string]any{"email": p["email"], "name": p["name"], "sendTo": p["sendTo"]}), needle) {
			return true
		}
	}
	return false
}

func eventSortValue(event map[string]any, property string) (string, bool) {
	switch property {
	case "start":
		start, _ := event["start"].(string)
		tz, _ := event["timeZone"].(string)
		local, err := time.Parse(localDateTime, start)
		if err != nil {
			return start, true
		}
		return icalTime{local: local, tz: tz}.utc().Format(time.RFC3339), true
	case "uid", "created", "updated":
		value, _ := event[property].(string)
		return value, true
	}
	return "", false
}

func projectCalendar(folder model.Folder, rights collectionRights, owner bool) map[string]any {
	write := rights.create && rights.update && rights.remove
	return map[string]any{"id": folder.ID, "name": folder.Name, "description": nullable(folder.Description), "color": nullable(folder.Color),
		"sortOrder": 0, "isSubscribed": owner || folder.Subscribed, "isVisible": true, "isDefault": folder.SpecialUse == model.SpecialUseCalendar,
		"includeInAvailability": "all", "defaultAlertsWithTime": nil, "defaultAlertsWithoutTime": nil, "timeZone": nil, "shareWith": nil,
		"myRights": map[string]bool{"mayReadFreeBusy": rights.read, "mayReadItems": rights.read, "mayWriteAll": write, "mayWriteOwn": write,
			"mayUpdatePrivate": write, "mayRSVP": rights.update, "mayShare": rights.share, "mayDelete": rights.delete}}
}

// participantIdentityGet lists the account's sending identities as the
// calendar user addresses it may organize or answer events as.
func (h *Handler) participantIdentityGet(ctx context.Context, actor model.User, raw json.RawMessage) (any, *MethodError) {
	var a getArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	var identities []model.EmailAddress
	if access.Subject.ID == a.AccountID {
		var err error
		if identities, err = h.cfg.Directory.ListIdentities(ctx, a.AccountID); err != nil {
			return nil, serverError(err)
		}
	}
	owner, _ := h.cfg.Directory.GetAccount(ctx, a.AccountID)
	wanted := idSet(a.IDs)
	found := map[string]bool{}
	list := []any{}
	for _, identity := range identities {
		id := participantID(identity.ID)
		if !identity.Enabled || (wanted != nil && !wanted[id]) {
			continue
		}
		found[id] = true
		list = append(list, map[string]any{"id": id, "name": owner.DisplayName, "sendTo": map[string]any{"imip": "mailto:" + strings.ToLower(identity.ID)}})
	}
	return map[string]any{"accountId": a.AccountID, "state": shortState(identityIDs(identities)), "list": list, "notFound": nonNil(missing(a.IDs, found))}, nil
}

func (h *Handler) dispatchCalendars(ctx context.Context, actor model.User, name string, raw json.RawMessage, created map[string]string) (any, *MethodError, bool) {
	codec := calendarCodec()
	switch name {
	case "Calendar/get":
		result, err := h.collectionGet(ctx, actor, raw, created, calendarsKind, projectCalendar)
		return result, err, true
	case "Calendar/changes":
		result, err := h.typedChanges(ctx, actor, calendarsKind, service.ChangeObjectFolder, raw)
		return result, err, true
	case "Calendar/set":
		result, err := h.collectionSet(ctx, actor, raw, created, calendarsKind, projectCalendar)
		return result, err, true
	case "CalendarEvent/get":
		result, err := h.itemGet(ctx, actor, raw, created, codec)
		return result, err, true
	case "CalendarEvent/changes":
		result, err := h.typedChanges(ctx, actor, calendarsKind, service.ChangeObjectItem, raw)
		return result, err, true
	case "CalendarEvent/query":
		var options struct {
			ExpandRecurrences bool `json:"expandRecurrences"`
		}
		if json.Unmarshal(raw, &options) == nil && options.ExpandRecurrences {
			return nil, &MethodError{Type: "invalidArguments", Description: "expandRecurrences is not supported"}, true
		}
		result, err := h.itemQuery(ctx, actor, raw, codec)
		return result, err, true
	case "CalendarEvent/queryChanges":
		result, err := h.itemQueryChanges(ctx, actor, raw, codec)
		return result, err, true
	case "CalendarEvent/set":
		result, err := h.itemSet(ctx, actor, raw, created, codec)
		return result, err, true
	case "CalendarEvent/copy":
		result, err := h.itemCopy(ctx, actor, raw, created, codec)
		return result, err, true
	case "ParticipantIdentity/get":
		result, err := h.participantIdentityGet(ctx, actor, raw)
		return result, err, true
	}
	return nil, nil, false
}
