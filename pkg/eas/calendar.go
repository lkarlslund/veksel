package eas

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// EAS compact date-time (MS-ASDTYPE 2.3), used by calendar elements.
const easCompactFormat = "20060102T150405Z"

// calendarEvent is one decoded iCalendar resource: the master VEVENT and
// its RECURRENCE-ID overrides.
type calendarEvent struct {
	cal       *ical.Calendar
	master    *ical.Component
	overrides []*ical.Component
}

func parseCalendarEvent(data []byte) *calendarEvent {
	cal, err := calendar.NewDecoder(data).Decode()
	if err != nil {
		return nil
	}
	event := &calendarEvent{cal: cal}
	for _, child := range cal.Children {
		if child.Name != ical.CompEvent {
			continue
		}
		if child.Props.Get(ical.PropRecurrenceID) != nil {
			event.overrides = append(event.overrides, child)
		} else if event.master == nil {
			event.master = child
		}
	}
	if event.master == nil {
		if len(event.overrides) == 0 {
			return nil
		}
		event.master, event.overrides = event.overrides[0], event.overrides[1:]
	}
	return event
}

// propTime reads a DATE or DATE-TIME property. Unknown TZIDs and floating
// times are read in fallback.
func propTime(props ical.Props, name string, fallback *time.Location) (time.Time, bool, *time.Location, bool) {
	prop := props.Get(name)
	if prop == nil {
		return time.Time{}, false, nil, false
	}
	allDay := prop.ValueType() == ical.ValueDate || prop.ValueType() == ical.ValueDefault && len(prop.Value) == 8
	location := fallback
	if allDay {
		value, err := time.ParseInLocation("20060102", prop.Value, fallback)
		return value, true, fallback, err == nil
	}
	if strings.HasSuffix(prop.Value, "Z") {
		location = time.UTC
	} else if tzid := prop.Params.Get(ical.PropTimezoneID); tzid != "" {
		if loaded, err := time.LoadLocation(tzid); err == nil {
			location = loaded
		}
	}
	value, err := time.ParseInLocation("20060102T150405", strings.TrimSuffix(prop.Value, "Z"), location)
	return value, false, location, err == nil
}

func compact(value time.Time) string { return value.UTC().Format(easCompactFormat) }

func parseEASTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{easCompactFormat, easDateFormat, "2006-01-02T15:04:05Z", "20060102T150405"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

// eventTimes resolves an event's start, end and the zone to describe it in.
func eventTimes(component *ical.Component, fallback *time.Location) (start, end time.Time, allDay bool, location *time.Location) {
	start, allDay, location, ok := propTime(component.Props, ical.PropDateTimeStart, fallback)
	if !ok {
		return time.Time{}, time.Time{}, false, fallback
	}
	end, _, _, ok = propTime(component.Props, ical.PropDateTimeEnd, location)
	if !ok {
		if prop := component.Props.Get(ical.PropDuration); prop != nil {
			if duration, err := prop.Duration(); err == nil {
				end, ok = start.Add(duration), true
			}
		}
	}
	if !ok || end.Before(start) {
		end = start
		if allDay {
			end = start.AddDate(0, 0, 1)
		}
	}
	return start, end, allDay, location
}

func (h *Handler) calendarData(command *commandContext, item model.Item, options SyncOptions) *Node {
	event := parseCalendarEvent(item.Data)
	data := E(0, "ApplicationData")
	if event == nil {
		return data
	}
	userLocation := h.userLocation(command)
	profile := h.profile(command)
	master := event.master
	start, end, allDay, location := eventTimes(master, userLocation)
	tz := timeZoneFor(location, start.Year())
	add := func(nodes ...*Node) { data.Children = append(data.Children, nodes...) }
	add(T(4, "TimeZone", tz.encode()))
	stamp := time.Now().UTC()
	if value, _, _, ok := propTime(master.Props, ical.PropDateTimeStamp, time.UTC); ok {
		stamp = value
	}
	add(T(4, "DtStamp", compact(stamp)), T(4, "StartTime", compact(start)))
	summary, _ := master.Props.Text(ical.PropSummary)
	add(T(4, "Subject", summary))
	uid, _ := master.Props.Text(ical.PropUID)
	if !command.version(16, 0) && uid != "" {
		add(T(4, "UID", uid))
	}
	organizer, organizerName := "", ""
	if prop := master.Props.Get(ical.PropOrganizer); prop != nil {
		organizer, organizerName = calendar.MailAddress(prop.Value), prop.Params.Get(ical.ParamCommonName)
	}
	attendees := master.Props.Values(ical.PropAttendee)
	meeting := organizer != "" && len(attendees) > 0
	if meeting {
		if organizerName != "" {
			add(T(4, "OrganizerName", organizerName))
		}
		add(T(4, "OrganizerEmail", organizer))
	}
	locationText, _ := master.Props.Text(ical.PropLocation)
	if command.version(16, 0) {
		if locationText != "" {
			add(E(17, "Location", T(17, "DisplayName", locationText)))
		}
	} else if locationText != "" {
		add(T(4, "Location", locationText))
	}
	add(T(4, "EndTime", compact(end)))
	if rule := master.Props.Get(ical.PropRecurrenceRule); rule != nil {
		if recurrence := recurrenceNode(4, rule.Value, start.In(location)); recurrence != nil {
			add(recurrence)
		}
	}
	add(T(4, "Sensitivity", sensitivity(master.Props)), T(4, "BusyStatus", busyStatus(master.Props)), T(4, "AllDayEvent", boolNumber(allDay)))
	if minutes, ok := reminderMinutes(master); ok {
		add(T(4, "Reminder", strconv.Itoa(minutes)))
	}
	organizing := meeting && profile.owns(organizer)
	add(T(4, "MeetingStatus", meetingStatus(master.Props, meeting, organizing)))
	if len(attendees) > 0 {
		list := E(4, "Attendees")
		for _, attendee := range attendees {
			address := calendar.MailAddress(attendee.Value)
			if address == "" || address == organizer && !organizing {
				continue
			}
			node := E(4, "Attendee", T(4, "Email", address), T(4, "Name", firstNonEmpty(attendee.Params.Get(ical.ParamCommonName), address)))
			node.Children = append(node.Children, T(4, "AttendeeStatus", attendeeStatus(attendee.Params.Get(ical.ParamParticipationStatus))), T(4, "AttendeeType", attendeeType(attendee.Params)))
			list.Children = append(list.Children, node)
		}
		if len(list.Children) > 0 {
			add(list)
		}
	}
	description, _ := master.Props.Text(ical.PropDescription)
	add(textBody(description, options))
	if exceptions := h.exceptionNodes(command, event, location, allDay, options); exceptions != nil {
		add(exceptions)
	}
	if categories := categoriesNode(4, master.Props); categories != nil {
		add(categories)
	}
	if meeting && !organizing {
		add(T(4, "ResponseRequested", "1"))
		if command.version(14, 0) {
			add(T(4, "ResponseType", responseType(attendees, profile)))
		}
	}
	add(T(4, "DisallowNewTimeProposal", "0"))
	if command.version(12, 0) {
		add(T(17, "NativeBodyType", "1"))
	}
	return data
}

// textBody renders a plain-text property as the requested AirSyncBase body.
func textBody(text string, options SyncOptions) *Node {
	preference := chooseBody(options.BodyPreferences, 0, false)
	if preference.Type == bodyHTML && text != "" {
		return bodyNode(bodyHTML, []byte(textToHTML(text)), preference, text)
	}
	if preference.Type == bodyMIME {
		preference.Type = bodyText
	}
	return bodyNode(bodyText, []byte(text), preference, text)
}

func (h *Handler) exceptionNodes(command *commandContext, event *calendarEvent, location *time.Location, allDay bool, options SyncOptions) *Node {
	exceptions := E(4, "Exceptions")
	instanceNode := func(original time.Time) *Node {
		if command.version(16, 0) {
			return T(17, "InstanceId", compact(original))
		}
		return T(4, "ExceptionStartTime", compact(original))
	}
	for _, prop := range event.master.Props.Values(ical.PropExceptionDates) {
		for _, value := range strings.Split(prop.Value, ",") {
			single := prop
			single.Value = value
			props := ical.Props{}
			props.Set(&single)
			original, _, _, ok := propTime(props, ical.PropExceptionDates, location)
			if !ok {
				continue
			}
			exceptions.Children = append(exceptions.Children, E(4, "Exception", T(4, "Deleted", "1"), instanceNode(original)))
		}
	}
	for _, override := range event.overrides {
		original, _, _, ok := propTime(override.Props, ical.PropRecurrenceID, location)
		if !ok {
			continue
		}
		start, end, overrideAllDay, _ := eventTimes(override, location)
		node := E(4, "Exception")
		if status, _ := override.Props.Text(ical.PropStatus); strings.EqualFold(status, "CANCELLED") {
			node.Children = append(node.Children, T(4, "Deleted", "1"), instanceNode(original))
			exceptions.Children = append(exceptions.Children, node)
			continue
		}
		node.Children = append(node.Children, instanceNode(original))
		summary, _ := override.Props.Text(ical.PropSummary)
		node.Children = append(node.Children, T(4, "Subject", summary), T(4, "StartTime", compact(start)), T(4, "EndTime", compact(end)))
		description, _ := override.Props.Text(ical.PropDescription)
		node.Children = append(node.Children, textBody(description, options))
		if locationText, _ := override.Props.Text(ical.PropLocation); locationText != "" {
			if command.version(16, 0) {
				node.Children = append(node.Children, E(17, "Location", T(17, "DisplayName", locationText)))
			} else {
				node.Children = append(node.Children, T(4, "Location", locationText))
			}
		}
		node.Children = append(node.Children, T(4, "Sensitivity", sensitivity(override.Props)), T(4, "BusyStatus", busyStatus(override.Props)), T(4, "AllDayEvent", boolNumber(overrideAllDay || allDay && override.Props.Get(ical.PropDateTimeStart) == nil)))
		if minutes, ok := reminderMinutes(override); ok {
			node.Children = append(node.Children, T(4, "Reminder", strconv.Itoa(minutes)))
		}
		exceptions.Children = append(exceptions.Children, node)
	}
	if len(exceptions.Children) == 0 {
		return nil
	}
	return exceptions
}

func sensitivity(props ical.Props) string {
	value, _ := props.Text(ical.PropClass)
	switch strings.ToUpper(value) {
	case "PRIVATE":
		return "2"
	case "CONFIDENTIAL":
		return "3"
	}
	return "0"
}

func busyStatus(props ical.Props) string {
	if value, _ := props.Text("X-MICROSOFT-CDO-BUSYSTATUS"); value != "" {
		switch strings.ToUpper(value) {
		case "FREE":
			return "0"
		case "TENTATIVE":
			return "1"
		case "OOF":
			return "3"
		case "WORKINGELSEWHERE":
			return "4"
		}
		return "2"
	}
	if value, _ := props.Text(ical.PropTransparency); strings.EqualFold(value, "TRANSPARENT") {
		return "0"
	}
	if value, _ := props.Text(ical.PropStatus); strings.EqualFold(value, "TENTATIVE") {
		return "1"
	}
	return "2"
}

func meetingStatus(props ical.Props, meeting, organizing bool) string {
	cancelled := false
	if value, _ := props.Text(ical.PropStatus); strings.EqualFold(value, "CANCELLED") {
		cancelled = true
	}
	switch {
	case !meeting:
		return "0"
	case organizing && cancelled:
		return "5"
	case organizing:
		return "1"
	case cancelled:
		return "7"
	}
	return "3"
}

func attendeeStatus(partStat string) string {
	switch strings.ToUpper(partStat) {
	case "TENTATIVE":
		return "2"
	case "ACCEPTED":
		return "3"
	case "DECLINED":
		return "4"
	case "NEEDS-ACTION", "":
		return "5"
	}
	return "0"
}

func attendeeType(params ical.Params) string {
	if strings.EqualFold(params.Get(ical.ParamCalendarUserType), "RESOURCE") || strings.EqualFold(params.Get(ical.ParamCalendarUserType), "ROOM") {
		return "3"
	}
	if strings.EqualFold(params.Get(ical.ParamRole), "OPT-PARTICIPANT") {
		return "2"
	}
	return "1"
}

func responseType(attendees []ical.Prop, profile Profile) string {
	for _, attendee := range attendees {
		if profile.owns(calendar.MailAddress(attendee.Value)) {
			switch strings.ToUpper(attendee.Params.Get(ical.ParamParticipationStatus)) {
			case "TENTATIVE":
				return "2"
			case "ACCEPTED":
				return "3"
			case "DECLINED":
				return "4"
			}
			return "5"
		}
	}
	return "0"
}

func reminderMinutes(component *ical.Component) (int, bool) {
	for _, child := range component.Children {
		if child.Name != ical.CompAlarm {
			continue
		}
		trigger := child.Props.Get(ical.PropTrigger)
		if trigger == nil || trigger.ValueType() == ical.ValueDateTime || strings.EqualFold(trigger.Params.Get(ical.ParamRelated), "END") {
			continue
		}
		if duration, err := trigger.Duration(); err == nil && duration <= 0 {
			return int(-duration / time.Minute), true
		}
	}
	return 0, false
}

func categoriesNode(page byte, props ical.Props) *Node {
	var values []string
	for _, prop := range props.Values(ical.PropCategories) {
		list, _ := prop.TextList()
		values = append(values, list...)
	}
	if len(values) == 0 {
		return nil
	}
	node := E(page, "Categories")
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			node.Children = append(node.Children, T(page, "Category", value))
		}
	}
	return node
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// meetingRequestNode renders the MS-ASEMAIL MeetingRequest of an iMIP
// invitation, which lets clients offer Accept, Tentative and Decline.
func meetingRequestNode(event *calendarEvent, userLocation *time.Location) *Node {
	master := event.master
	start, end, allDay, location := eventTimes(master, userLocation)
	stamp := time.Now().UTC()
	if value, _, _, ok := propTime(master.Props, ical.PropDateTimeStamp, time.UTC); ok {
		stamp = value
	}
	node := E(2, "MeetingRequest",
		T(2, "AllDayEvent", boolNumber(allDay)),
		T(2, "StartTime", start.UTC().Format(easDateFormat)),
		T(2, "DtStamp", stamp.UTC().Format(easDateFormat)),
		T(2, "EndTime", end.UTC().Format(easDateFormat)),
		T(2, "InstanceType", "0"),
	)
	if master.Props.Get(ical.PropRecurrenceRule) != nil {
		node.Children[4].Text = "1"
	}
	if locationText, _ := master.Props.Text(ical.PropLocation); locationText != "" {
		node.Children = append(node.Children, T(2, "Location", locationText))
	}
	if prop := master.Props.Get(ical.PropOrganizer); prop != nil {
		organizer := calendar.MailAddress(prop.Value)
		if name := prop.Params.Get(ical.ParamCommonName); name != "" {
			organizer = `"` + name + `" <` + organizer + `>`
		}
		node.Children = append(node.Children, T(2, "Organizer", organizer))
	}
	if prop := master.Props.Get(ical.PropRecurrenceID); prop != nil {
		if original, _, _, ok := propTime(master.Props, ical.PropRecurrenceID, location); ok {
			node.Children = append(node.Children, T(2, "RecurrenceId", original.UTC().Format(easDateFormat)))
		}
	}
	if minutes, ok := reminderMinutes(master); ok {
		node.Children = append(node.Children, T(2, "Reminder", strconv.Itoa(minutes*60)))
	}
	node.Children = append(node.Children, T(2, "ResponseRequested", "1"))
	if rule := master.Props.Get(ical.PropRecurrenceRule); rule != nil {
		if recurrence := recurrenceNode(2, rule.Value, start.In(location)); recurrence != nil {
			node.Children = append(node.Children, E(2, "Recurrences", recurrence))
		}
	}
	uid, _ := master.Props.Text(ical.PropUID)
	node.Children = append(node.Children,
		T(2, "Sensitivity", sensitivity(master.Props)),
		T(2, "BusyStatus", busyStatus(master.Props)),
		T(2, "TimeZone", timeZoneFor(location, start.Year()).encode()),
		T(2, "GlobalObjId", globalObjectID(uid)),
	)
	return node
}

// calendarFromEAS builds or updates an iCalendar resource from calendar
// ApplicationData. Properties EAS does not model (sequence, custom X-
// properties, attendee parameters) are preserved from existing.
func (h *Handler) calendarFromEAS(command *commandContext, existing []byte, data *Node) ([]byte, map[string]string, error) {
	userLocation := h.userLocation(command)
	profile := h.profile(command)
	var event *calendarEvent
	if existing != nil {
		event = parseCalendarEvent(existing)
	}
	if event == nil {
		cal := ical.NewCalendar()
		cal.Props.SetText(ical.PropVersion, "2.0")
		cal.Props.SetText(ical.PropProductID, "-//Veksel//ActiveSync//EN")
		master := ical.NewEvent()
		uid := firstNonEmpty(childText(data, "UID"), childText(data, "ClientUid"))
		if uid == "" {
			uid = newUID()
		}
		master.Props.SetText(ical.PropUID, uid)
		cal.Children = append(cal.Children, master.Component)
		event = &calendarEvent{cal: cal, master: master.Component}
	}
	master := event.master
	before := significantEAS(master.Props)
	tz, hasTZ := decodeTimeZone(childText(data, "TimeZone"))
	if !hasTZ {
		tz = timeZoneFor(userLocation, time.Now().Year())
	}
	start, okStart := parseEASTime(childText(data, "StartTime"))
	end, okEnd := parseEASTime(childText(data, "EndTime"))
	if !okStart {
		if existing == nil {
			return nil, nil, errors.New("calendar item has no StartTime")
		}
		start, end, _, _ = eventTimes(master, userLocation)
		okEnd = true
	}
	if !okEnd || end.Before(start) {
		end = start
	}
	allDay := childText(data, "AllDayEvent") == "1"
	location := matchLocation(tz, start.Year(), userLocation)
	setEventTimes(master.Props, start, end, allDay, tz, location)
	master.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
	setText(master.Props, ical.PropSummary, childText(data, "Subject"))
	locationText := childText(data, "Location")
	if locationNode := data.Child("Location"); locationNode != nil && locationNode.Page == 17 {
		locationText = childText(locationNode, "DisplayName")
	}
	setText(master.Props, ical.PropLocation, locationText)
	if body := data.Child("Body"); body != nil {
		setText(master.Props, ical.PropDescription, clientBodyText(body))
	}
	setSensitivity(master.Props, childText(data, "Sensitivity"))
	setBusyStatus(master.Props, childText(data, "BusyStatus"))
	setReminder(master, childText(data, "Reminder"))
	if categories := data.Child("Categories"); categories != nil {
		setCategoryList(master.Props, categories)
	}
	if recurrence := data.Child("Recurrence"); recurrence != nil {
		reference := start
		if location != nil {
			reference = start.In(location)
		}
		_ = reference
		if rule := ruleFromEAS(recurrence, allDay, tz); rule != "" {
			prop := ical.NewProp(ical.PropRecurrenceRule)
			prop.Value = rule
			master.Props.Set(prop)
		}
	} else if existing == nil || data.Child("StartTime") != nil {
		master.Props.Del(ical.PropRecurrenceRule)
	}
	if exceptions := data.Child("Exceptions"); exceptions != nil {
		applyExceptions(event, exceptions, tz, location, allDay)
	}
	h.applyAttendees(master, data, profile)
	if after := significantEAS(master.Props); before != "" && after != before && master.Props.Get(ical.PropOrganizer) != nil && profile.owns(calendar.MailAddress(master.Props.Get(ical.PropOrganizer).Value)) {
		sequence := ical.NewProp(ical.PropSequence)
		current := 0
		if prop := master.Props.Get(ical.PropSequence); prop != nil {
			current, _ = prop.Int()
		}
		sequence.Value = strconv.Itoa(current + 1)
		master.Props.Set(sequence)
	}
	calendar.AddMissingTimezones(event.cal)
	var buffer bytes.Buffer
	if err := ical.NewEncoder(&buffer).Encode(event.cal); err != nil {
		return nil, nil, err
	}
	uid, _ := master.Props.Text(ical.PropUID)
	summary, _ := master.Props.Text(ical.PropSummary)
	return buffer.Bytes(), map[string]string{"UID": uid, "SUMMARY": summary}, nil
}

func significantEAS(props ical.Props) string {
	var parts []string
	for _, name := range []string{ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropLocation, ical.PropRecurrenceRule} {
		if prop := props.Get(name); prop != nil {
			parts = append(parts, prop.Value)
		} else {
			parts = append(parts, "")
		}
	}
	return strings.Join(parts, "|")
}

// setEventTimes writes DTSTART/DTEND. All-day events use the dates local
// to the client's zone; timed events use a matching IANA zone so
// recurrences follow daylight saving time, or UTC when none matches.
func setEventTimes(props ical.Props, start, end time.Time, allDay bool, tz easTimeZone, location *time.Location) {
	props.Del(ical.PropDuration)
	if allDay {
		localStart := start.Add(time.Duration(tz.offset(start)) * time.Second)
		localEnd := end.Add(time.Duration(tz.offset(end)) * time.Second)
		startDate := time.Date(localStart.Year(), localStart.Month(), localStart.Day(), 0, 0, 0, 0, time.UTC)
		endDate := time.Date(localEnd.Year(), localEnd.Month(), localEnd.Day(), 0, 0, 0, 0, time.UTC)
		if !endDate.After(startDate) {
			endDate = startDate.AddDate(0, 0, 1)
		}
		props.SetDate(ical.PropDateTimeStart, startDate)
		props.SetDate(ical.PropDateTimeEnd, endDate)
		return
	}
	if location == nil {
		location = time.UTC
	}
	props.SetDateTime(ical.PropDateTimeStart, start.In(location))
	props.SetDateTime(ical.PropDateTimeEnd, end.In(location))
}

func setText(props ical.Props, name, value string) {
	if strings.TrimSpace(value) == "" {
		props.Del(name)
		return
	}
	props.SetText(name, value)
}

// bodyText extracts plain text from an AirSyncBase Body sent by a client.
func clientBodyText(body *Node) string {
	text := nodeValue(body.Child("Data"))
	if childText(body, "Type") == "2" {
		return service.HTMLToText(text)
	}
	return strings.ReplaceAll(text, "\r\n", "\n")
}

func setSensitivity(props ical.Props, value string) {
	switch value {
	case "":
		return
	case "2":
		props.SetText(ical.PropClass, "PRIVATE")
	case "3":
		props.SetText(ical.PropClass, "CONFIDENTIAL")
	default:
		props.Del(ical.PropClass)
	}
}

func setBusyStatus(props ical.Props, value string) {
	names := map[string]string{"0": "FREE", "1": "TENTATIVE", "2": "BUSY", "3": "OOF", "4": "WORKINGELSEWHERE"}
	name, ok := names[value]
	if !ok {
		return
	}
	props.SetText("X-MICROSOFT-CDO-BUSYSTATUS", name)
	if value == "0" {
		props.SetText(ical.PropTransparency, "TRANSPARENT")
	} else {
		props.SetText(ical.PropTransparency, "OPAQUE")
	}
}

func setReminder(component *ical.Component, value string) {
	component.Children = slices.DeleteFunc(component.Children, func(child *ical.Component) bool { return child.Name == ical.CompAlarm })
	minutes, err := strconv.Atoi(strings.TrimSpace(value))
	if value == "" || err != nil || minutes < 0 {
		return
	}
	alarm := ical.NewComponent(ical.CompAlarm)
	alarm.Props.SetText(ical.PropAction, "DISPLAY")
	alarm.Props.SetText(ical.PropDescription, "Reminder")
	trigger := ical.NewProp(ical.PropTrigger)
	trigger.Value = "-PT" + strconv.Itoa(minutes) + "M"
	if minutes == 0 {
		trigger.Value = "PT0S"
	}
	alarm.Props.Set(trigger)
	component.Children = append(component.Children, alarm)
}

func setCategoryList(props ical.Props, categories *Node) {
	props.Del(ical.PropCategories)
	var values []string
	for _, category := range categories.Children {
		if value := strings.TrimSpace(nodeValue(category)); value != "" {
			values = append(values, value)
		}
	}
	if len(values) > 0 {
		prop := ical.NewProp(ical.PropCategories)
		prop.SetTextList(values)
		props.Set(prop)
	}
}

// applyExceptions replaces the overrides and EXDATEs with the client's
// complete exception list.
func applyExceptions(event *calendarEvent, exceptions *Node, tz easTimeZone, location *time.Location, allDay bool) {
	master := event.master
	master.Props.Del(ical.PropExceptionDates)
	existing := map[string]*ical.Component{}
	for _, override := range event.overrides {
		if original, _, _, ok := propTime(override.Props, ical.PropRecurrenceID, location); ok {
			existing[compact(original)] = override
		}
	}
	keep := map[*ical.Component]bool{}
	var deleted []time.Time
	for _, exception := range exceptions.ChildrenNamed("Exception") {
		originalText := firstNonEmpty(childText(exception, "ExceptionStartTime"), childText(exception, "InstanceId"))
		original, ok := parseEASTime(originalText)
		if !ok {
			continue
		}
		if childText(exception, "Deleted") == "1" {
			deleted = append(deleted, original)
			continue
		}
		override := existing[compact(original)]
		if override == nil {
			clone := ical.NewEvent()
			clone.Props = calendar.CloneProps(master.Props)
			clone.Props.Del(ical.PropRecurrenceRule)
			clone.Props.Del(ical.PropExceptionDates)
			clone.Props.Del(ical.PropRecurrenceDates)
			recurrence := ical.NewProp(ical.PropRecurrenceID)
			if allDay {
				local := original.Add(time.Duration(tz.offset(original)) * time.Second)
				recurrence.SetDate(local)
			} else if location != nil {
				recurrence.SetDateTime(original.In(location))
			} else {
				recurrence.SetDateTime(original)
			}
			clone.Props.Set(recurrence)
			override = clone.Component
			event.cal.Children = append(event.cal.Children, override)
		}
		keep[override] = true
		start, okStart := parseEASTime(childText(exception, "StartTime"))
		end, okEnd := parseEASTime(childText(exception, "EndTime"))
		if okStart && okEnd {
			setEventTimes(override.Props, start, end, childText(exception, "AllDayEvent") == "1" || allDay && exception.Child("AllDayEvent") == nil, tz, location)
		}
		if exception.Child("Subject") != nil {
			setText(override.Props, ical.PropSummary, childText(exception, "Subject"))
		}
		if exception.Child("Location") != nil {
			setText(override.Props, ical.PropLocation, firstNonEmpty(childText(exception.Child("Location"), "DisplayName"), childText(exception, "Location")))
		}
		if body := exception.Child("Body"); body != nil {
			setText(override.Props, ical.PropDescription, clientBodyText(body))
		}
		setSensitivity(override.Props, childText(exception, "Sensitivity"))
		setBusyStatus(override.Props, childText(exception, "BusyStatus"))
		if exception.Child("Reminder") != nil {
			setReminder(override, childText(exception, "Reminder"))
		}
	}
	event.cal.Children = slices.DeleteFunc(event.cal.Children, func(child *ical.Component) bool {
		return child.Name == ical.CompEvent && child != master && !keep[child]
	})
	for _, original := range deleted {
		prop := ical.NewProp(ical.PropExceptionDates)
		if allDay {
			prop.SetDate(original.Add(time.Duration(tz.offset(original)) * time.Second))
		} else if location != nil {
			prop.SetDateTime(original.In(location))
		} else {
			prop.SetDateTime(original)
		}
		master.Props.Add(prop)
	}
}

// applyAttendees writes the client's attendee list. A client may only
// change the attendees of meetings the user organizes (or new ones); for
// received meetings the organizer's list is authoritative.
func (h *Handler) applyAttendees(master *ical.Component, data *Node, profile Profile) {
	attendees := data.Child("Attendees")
	organizerProp := master.Props.Get(ical.PropOrganizer)
	if organizerProp != nil && !profile.owns(calendar.MailAddress(organizerProp.Value)) {
		return
	}
	if attendees == nil {
		if data.Child("MeetingStatus") != nil && childText(data, "MeetingStatus") == "0" {
			master.Props.Del(ical.PropAttendee)
			master.Props.Del(ical.PropOrganizer)
		}
		return
	}
	previous := map[string]ical.Prop{}
	for _, attendee := range master.Props.Values(ical.PropAttendee) {
		previous[calendar.MailAddress(attendee.Value)] = attendee
	}
	master.Props.Del(ical.PropAttendee)
	added := 0
	for _, attendee := range attendees.ChildrenNamed("Attendee") {
		address := strings.ToLower(strings.TrimSpace(childText(attendee, "Email")))
		if address == "" {
			continue
		}
		prop, ok := previous[address]
		if !ok {
			prop = *ical.NewProp(ical.PropAttendee)
			prop.Value = "mailto:" + address
			prop.Params.Set(ical.ParamParticipationStatus, "NEEDS-ACTION")
			prop.Params.Set(ical.ParamRSVP, "TRUE")
		}
		if name := strings.TrimSpace(childText(attendee, "Name")); name != "" && name != address {
			prop.Params.Set(ical.ParamCommonName, name)
		}
		switch childText(attendee, "AttendeeType") {
		case "2":
			prop.Params.Set(ical.ParamRole, "OPT-PARTICIPANT")
		case "3":
			prop.Params.Set(ical.ParamCalendarUserType, "RESOURCE")
			prop.Params.Set(ical.ParamRole, "NON-PARTICIPANT")
		default:
			prop.Params.Set(ical.ParamRole, "REQ-PARTICIPANT")
		}
		master.Props.Add(&prop)
		added++
	}
	if added == 0 {
		master.Props.Del(ical.PropOrganizer)
		return
	}
	if organizerProp == nil && profile.primary() != "" {
		organizer := ical.NewProp(ical.PropOrganizer)
		organizer.Value = "mailto:" + profile.primary()
		if profile.DisplayName != "" {
			organizer.Params.Set(ical.ParamCommonName, profile.DisplayName)
		}
		master.Props.Set(organizer)
	}
}

func newUID() string {
	value := make([]byte, 16)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value) + "@veksel"
}
