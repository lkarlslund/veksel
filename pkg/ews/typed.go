package ews

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// maxCalendarViewSpan bounds the range one CalendarView may expand.
const maxCalendarViewSpan = 2 * 366 * 24 * time.Hour

// quietScheduling returns the context for a calendar write. The server
// schedules attendees itself when a calendar item is written (implicit
// scheduling through iMIP), so EWS never sends invitations of its own;
// SendToNone asks it to notify nobody.
func quietScheduling(ctx context.Context, mode string) context.Context {
	if strings.EqualFold(strings.TrimSpace(mode), "SendToNone") {
		return imip.WithoutAttendeeMessages(ctx)
	}
	return ctx
}

// defaultFolderFor is the distinguished folder a typed item is saved in
// when CreateItem names none.
func defaultFolderFor(kind itemKind) string {
	switch kind {
	case kindCalendar:
		return "calendar"
	case kindContact:
		return "contacts"
	case kindTask:
		return "tasks"
	}
	return "drafts"
}

func (h *Handler) calendarContext(ctx context.Context, access service.AccessContext, create bool) calendarContext {
	info := requestInfoFrom(ctx)
	profile := h.loadProfile(ctx, access.Actor.ID)
	return calendarContext{info: info, profile: profile, zone: displayZone(info, profile), create: create}
}

// encodeTypedItem builds a new calendar item, contact or task from a
// CreateItem element.
func (h *Handler) encodeTypedItem(ctx context.Context, access service.AccessContext, input *node) ([]byte, map[string]string, error) {
	fields := fieldsOfItem(input)
	scope := h.calendarContext(ctx, access, true)
	switch kindOfTag(input.Name.Local) {
	case kindCalendar:
		event := newEvent(input.descendantText("UID"))
		if err := applyCalendarFields(event, event.master, fields, scope); err != nil {
			return nil, nil, err
		}
		return event.encode()
	case kindContact:
		card := newContact()
		applyContactFields(card, fields)
		return encodeCard(card)
	case kindTask:
		task := newTask()
		if err := applyTaskFields(task, fields, scope); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errEWSInvalidProperty, err)
		}
		return task.encode()
	}
	return nil, nil, fmt.Errorf("%w: unsupported item type %s", errEWSInvalidProperty, input.Name.Local)
}

// createTypedItem stores a CreateItem calendar item, contact or task.
func (h *Handler) createTypedItem(ctx context.Context, access service.AccessContext, op, input *node) (model.Item, error) {
	ids := folderIDs(op.descendant("SavedItemFolderId"))
	folderID := defaultFolderFor(kindOfTag(input.Name.Local))
	if len(ids) > 0 {
		folderID = ids[0]
	}
	folder, err := h.resolveFolder(ctx, access, folderID)
	if err != nil {
		return model.Item{}, err
	}
	data, headers, err := h.encodeTypedItem(ctx, access, input)
	if err != nil {
		if errors.Is(err, errEWSInvalidProperty) || errors.Is(err, errEndBeforeStart) {
			return model.Item{}, err
		}
		return model.Item{}, fmt.Errorf("%w: %v", errEWSInvalidProperty, err)
	}
	return h.space.CreateItem(quietScheduling(ctx, op.attr("SendMeetingInvitations")), access, folder.ID, service.ItemInput{Data: data, Headers: headers})
}

// applyTypedChange applies an ItemChange to a calendar item (or one of its
// occurrences), contact or task.
func (h *Handler) applyTypedChange(ctx context.Context, access service.AccessContext, op *node, identifier *node, current model.Item, key string, updates *node) (model.Item, error) {
	expected := current.ModSeq
	if changeKey := strings.TrimSpace(identifier.attr("ChangeKey")); changeKey != "" && !strings.EqualFold(op.attr("ConflictResolution"), "AlwaysOverwrite") {
		parsed, err := strconv.ParseUint(changeKey, 10, 64)
		if err != nil || parsed == 0 {
			return model.Item{}, fmt.Errorf("%w: invalid item ChangeKey", errEWSInvalidProperty)
		}
		expected = parsed
	}
	fields := fieldsOfUpdates(updates)
	scope := h.calendarContext(ctx, access, false)
	var data []byte
	var headers map[string]string
	var err error
	switch kindOf(current.Data) {
	case kindCalendar:
		event := parseEvent(current.Data)
		if event == nil {
			return model.Item{}, fmt.Errorf("%w: the calendar item cannot be read", errEWSInvalidProperty)
		}
		component := event.master
		if key != "" {
			found, ok := event.occurrenceAt(key, scope.zone)
			if !ok {
				return model.Item{}, errItemNotFound
			}
			component = event.override(found, scope.zone)
		}
		if err := applyCalendarFields(event, component, fields, scope); err != nil {
			return model.Item{}, err
		}
		data, headers, err = event.encode()
	case kindContact:
		card := decodeCard(current.Data)
		if card == nil {
			return model.Item{}, fmt.Errorf("%w: the contact cannot be read", errEWSInvalidProperty)
		}
		applyContactFields(card, fields)
		data, headers, err = encodeCard(card)
	case kindTask:
		task := parseTask(current.Data)
		if task == nil {
			return model.Item{}, fmt.Errorf("%w: the task cannot be read", errEWSInvalidProperty)
		}
		if err := applyTaskFields(task, fields, scope); err != nil {
			return model.Item{}, fmt.Errorf("%w: %v", errEWSInvalidProperty, err)
		}
		data, headers, err = task.encode()
	default:
		return model.Item{}, fmt.Errorf("%w: not a typed item", errEWSInvalidProperty)
	}
	if err != nil {
		return model.Item{}, err
	}
	writeContext := quietScheduling(ctx, op.attr("SendMeetingInvitationsOrCancellations"))
	if updater, ok := h.space.(service.ConditionalItemUpdater); ok {
		return updater.UpdateItemIfModSeq(writeContext, access, current.ID, expected, data, headers)
	}
	return h.space.UpdateItem(writeContext, access, current.ID, data, headers)
}

// deleteOccurrence removes one instance of a recurring calendar item.
func (h *Handler) deleteOccurrence(ctx context.Context, access service.AccessContext, item model.Item, key string) error {
	scope := h.calendarContext(ctx, access, false)
	event := parseEvent(item.Data)
	if event == nil {
		return errItemNotFound
	}
	found, ok := event.occurrenceAt(key, scope.zone)
	if !ok {
		return errItemNotFound
	}
	event.deleteOccurrence(found, scope.zone, scope.profile)
	data, headers, err := event.encode()
	if err != nil {
		return err
	}
	_, err = h.conditionalUpdate(ctx, access, item, data, headers)
	return err
}

// respondToMeeting implements the AcceptItem, TentativelyAcceptItem,
// DeclineItem, CancelCalendarItem and RemoveItem response objects of
// CreateItem. Answers go through the scheduling service, which replies to
// the organizer and updates the calendar copy.
func (h *Handler) respondToMeeting(ctx context.Context, access service.AccessContext, op, input *node) error {
	reference := input.child("ReferenceItemId")
	if reference == nil {
		return fmt.Errorf("%w: ReferenceItemId is required", errEWSInvalidProperty)
	}
	ref, ok := parseItemRef(reference.attr("Id"))
	if !ok {
		return errItemNotFound
	}
	item, err := h.space.GetItem(ctx, access, ref.itemID)
	if err != nil {
		return err
	}
	switch input.Name.Local {
	case "CancelCalendarItem":
		return h.space.DeleteItem(quietScheduling(ctx, op.attr("SendMeetingInvitations")), access, item.ID)
	case "RemoveItem":
		return h.space.DeleteItem(imip.WithoutAttendeeMessages(ctx), access, item.ID)
	}
	partStat := map[string]string{"AcceptItem": "ACCEPTED", "TentativelyAcceptItem": "TENTATIVE", "DeclineItem": "DECLINED"}[input.Name.Local]
	if h.respond != nil {
		return h.respond(ctx, access, item.ID, partStat)
	}
	// Without a scheduling service the answer is only recorded.
	if kindOf(item.Data) != kindCalendar {
		return fmt.Errorf("%w: meeting responses need calendar scheduling", errEWSInvalidProperty)
	}
	event := parseEvent(item.Data)
	if event == nil || !setPartStat(event, h.loadProfile(ctx, access.Actor.ID), partStat) {
		return fmt.Errorf("%w: the user is not an attendee of this meeting", errEWSInvalidProperty)
	}
	data, headers, err := event.encode()
	if err != nil {
		return err
	}
	_, err = h.conditionalUpdate(imip.WithoutAttendeeMessages(ctx), access, item, data, headers)
	return err
}

// calendarView answers FindItem with a CalendarView: every instance that
// overlaps the range, recurring events expanded, sorted by start and cut
// at MaxEntriesReturned.
func (h *Handler) calendarView(ctx context.Context, access service.AccessContext, folder model.Folder, view *node, shape itemShape) (string, error) {
	zone := localZone{location: shape.zone}
	start, okStart := parseDateTime(view.attr("StartDate"), zone)
	end, okEnd := parseDateTime(view.attr("EndDate"), zone)
	if !okStart || !okEnd || !end.After(start) {
		return "", fmt.Errorf("%w: CalendarView requires StartDate before EndDate", errEWSInvalidProperty)
	}
	if end.Sub(start) > maxCalendarViewSpan {
		return "", fmt.Errorf("%w: the CalendarView range is too large", errEWSInvalidProperty)
	}
	limit := 0
	if parsed, err := strconv.Atoi(view.attr("MaxEntriesReturned")); err == nil && parsed > 0 {
		limit = parsed
	}
	items, err := h.space.ListItems(ctx, access, folder.ID, service.ItemQuery{})
	if err != nil {
		return "", err
	}
	type entry struct {
		start  time.Time
		render string
	}
	var entries []entry
	for _, item := range items {
		if kindOf(item.Data) != kindCalendar {
			continue
		}
		event := parseEvent(item.Data)
		if event == nil {
			continue
		}
		for _, found := range event.occurrencesBetween(shape.zone, start, end) {
			instance := masterInstance(item, event, shape.zone)
			if found.key != "" {
				instance = occurrenceInstance(item, event, found, shape.zone)
			}
			entries = append(entries, entry{start: found.start, render: renderCalendarInstance(item, event, instance, shape)})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].start.Before(entries[j].start) })
	complete := true
	if limit > 0 && len(entries) > limit {
		entries, complete = entries[:limit], false
	}
	var out strings.Builder
	for _, entry := range entries {
		out.WriteString(entry.render)
	}
	return response("FindItem", fmt.Sprintf(`<m:RootFolder TotalItemsInView="%d" IncludesLastItemInRange="%t"><t:Items>%s</t:Items></m:RootFolder>`, len(entries), complete, out.String())), nil
}
