// Package calendar provides storage-independent iCalendar projections for
// workspace consumers. Protocol and web adapters pass item payloads through
// this package; it has no knowledge of a concrete storage backend.
package calendar

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
)

const maxOccurrencesPerItem = 2000

type Event struct {
	UID         string   `json:"uid"`
	Summary     string   `json:"summary"`
	Description string   `json:"description,omitempty"`
	Location    string   `json:"location,omitempty"`
	Organizer   string   `json:"organizer,omitempty"`
	Attendees   []string `json:"attendees,omitempty"`
	// Participants carries each attendee's address and participation status
	// (RFC 5545 PARTSTAT) in Attendees order.
	Participants []Participant `json:"participants,omitempty"`
	Categories   []string      `json:"categories,omitempty"`
	Status       string        `json:"status,omitempty"`
	URL          string        `json:"url,omitempty"`
	Start        string        `json:"start"`
	End          string        `json:"end,omitempty"`
	AllDay       bool          `json:"all_day"`
	Timezone     string        `json:"timezone,omitempty"`
	Recurrence   string        `json:"recurrence"`
	// RRule is the master event's raw RRULE value, so editors can
	// round-trip rules the presets do not cover.
	RRule string `json:"rrule,omitempty"`
	// OrganizerAddress is the bare organizer address without its CN.
	OrganizerAddress string  `json:"organizer_address,omitempty"`
	Sequence         int     `json:"sequence,omitempty"`
	Transparent      bool    `json:"transparent,omitempty"`
	Alarms           []Alarm `json:"alarms,omitempty"`
}

// Participant is one ATTENDEE with its participation status.
type Participant struct {
	Address  string `json:"address"`
	Name     string `json:"name,omitempty"`
	PartStat string `json:"partstat,omitempty"`
	// Role is the RFC 5545 ROLE (REQ-PARTICIPANT when absent).
	Role string `json:"role,omitempty"`
}

// Alarm is one VALARM. MinutesBefore is set for triggers relative to the
// event start; other triggers (absolute or end-relative) are reported with
// their raw value only and are preserved unless alarms are replaced.
type Alarm struct {
	Trigger       string `json:"trigger"`
	MinutesBefore *int   `json:"minutes_before,omitempty"`
	Action        string `json:"action,omitempty"`
}

// AttendeeUpdate is one attendee written by an editor.
type AttendeeUpdate struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	// Role is REQ-PARTICIPANT, OPT-PARTICIPANT, NON-PARTICIPANT, or CHAIR.
	Role string `json:"role,omitempty"`
}

// maxAlarmMinutes bounds a reminder to four weeks before the start.
const maxAlarmMinutes = 4 * 7 * 24 * 60

// maxAttendees bounds the attendees an editor may write to one event.
const maxAttendees = 200

type Occurrence struct {
	Event
	RecurrenceID string `json:"recurrence_id,omitempty"`
}

type Update struct {
	Summary     string
	Description string
	Location    string
	Start       string
	End         string
	AllDay      bool
	Timezone    string
	// Recurrence is nil when an existing rule must be preserved. An empty
	// value explicitly removes recurrence; supported presets replace it, and
	// a raw RRULE value ("FREQ=WEEKLY;BYDAY=MO,WE") is validated and stored.
	Recurrence *string
	// Attendees, when non-nil, replaces the attendee list. Existing
	// attendees keep their PARTSTAT and parameters; an empty list turns the
	// meeting back into a private event and drops the organizer.
	Attendees *[]AttendeeUpdate
	// Organizer is set as ORGANIZER when the event has attendees and no
	// organizer yet.
	Organizer *AttendeeUpdate
	// Alarms, when non-nil, replaces every VALARM with display reminders
	// the given minutes before the start.
	Alarms *[]int
	// Categories, when non-nil, replaces CATEGORIES.
	Categories *[]string
	// Organizing reports that the writer organizes the event: a changed
	// time, place, or rule then bumps SEQUENCE and asks attendees again.
	Organizing bool
}

func Decode(data []byte) (*ical.Calendar, error) {
	cal, err := NewDecoder(data).Decode()
	if err != nil {
		return nil, fmt.Errorf("decode iCalendar: %w", err)
	}
	if len(cal.Events()) == 0 {
		return nil, errors.New("iCalendar item contains no event")
	}
	return cal, nil
}

func Project(data []byte) (Event, error) {
	cal, err := Decode(data)
	if err != nil {
		return Event{}, err
	}
	return projectEvent(MasterEvent(cal.Events()))
}

// MasterEvent returns the event without a RECURRENCE-ID, falling back to the
// first event when the payload only carries recurrence overrides.
func MasterEvent(events []ical.Event) ical.Event {
	for _, event := range events {
		if event.Props.Get(ical.PropRecurrenceID) == nil {
			return event
		}
	}
	return events[0]
}

func projectEvent(event ical.Event) (Event, error) {
	startProp := event.Props.Get(ical.PropDateTimeStart)
	if startProp == nil {
		return Event{}, errors.New("event has no DTSTART")
	}
	allDay := startProp.ValueType() == ical.ValueDate
	start, err := event.DateTimeStart(time.Local)
	if err != nil {
		return Event{}, fmt.Errorf("parse DTSTART: %w", err)
	}
	end, err := event.DateTimeEnd(time.Local)
	if err != nil {
		return Event{}, fmt.Errorf("parse DTEND: %w", err)
	}
	uid, _ := event.Props.Text(ical.PropUID)
	summary, _ := event.Props.Text(ical.PropSummary)
	description, _ := event.Props.Text(ical.PropDescription)
	location, _ := event.Props.Text(ical.PropLocation)
	organizer := calendarAddress(event.Props.Get(ical.PropOrganizer))
	organizerAddress := ""
	if prop := event.Props.Get(ical.PropOrganizer); prop != nil {
		organizerAddress = MailAddress(prop.Value)
	}
	attendees := make([]string, 0, len(event.Props.Values(ical.PropAttendee)))
	var participants []Participant
	for _, attendee := range event.Props.Values(ical.PropAttendee) {
		attendees = append(attendees, calendarAddress(&attendee))
		partStat := strings.ToUpper(strings.TrimSpace(attendee.Params.Get(ical.ParamParticipationStatus)))
		if partStat == "" {
			partStat = "NEEDS-ACTION"
		}
		participants = append(participants, Participant{Address: MailAddress(attendee.Value), Name: strings.TrimSpace(attendee.Params.Get(ical.ParamCommonName)), PartStat: partStat, Role: strings.ToUpper(strings.TrimSpace(attendee.Params.Get(ical.ParamRole)))})
	}
	var categories []string
	for _, category := range event.Props.Values(ical.PropCategories) {
		values, _ := category.TextList()
		categories = append(categories, values...)
	}
	status := ""
	if prop := event.Props.Get(ical.PropStatus); prop != nil {
		status = prop.Value
	}
	url := ""
	if prop := event.Props.Get(ical.PropURL); prop != nil {
		url = prop.Value
	}
	tzid := startProp.Params.Get(ical.PropTimezoneID)
	recurrence, rrule := "none", ""
	if rule := event.Props.Get(ical.PropRecurrenceRule); rule != nil {
		rrule = rule.Value
		switch strings.ToUpper(rule.Value) {
		case "FREQ=DAILY":
			recurrence = "daily"
		case "FREQ=WEEKLY":
			recurrence = "weekly"
		case "FREQ=MONTHLY":
			recurrence = "monthly"
		case "FREQ=YEARLY":
			recurrence = "yearly"
		default:
			recurrence = "custom"
		}
	}
	return Event{UID: uid, Summary: summary, Description: description, Location: location, Organizer: organizer, Attendees: attendees, Participants: participants, Categories: categories, Status: status, URL: url,
		Start: formatTime(start, allDay), End: formatTime(end, allDay), AllDay: allDay,
		Timezone: tzid, Recurrence: recurrence, RRule: rrule, OrganizerAddress: organizerAddress, Sequence: eventSequence(event.Props),
		Transparent: transparent(event.Props), Alarms: projectAlarms(event.Children)}, nil
}

func eventSequence(props ical.Props) int {
	if prop := props.Get(ical.PropSequence); prop != nil {
		if value, err := prop.Int(); err == nil {
			return value
		}
	}
	return 0
}

func transparent(props ical.Props) bool {
	prop := props.Get(ical.PropTransparency)
	return prop != nil && strings.EqualFold(strings.TrimSpace(prop.Value), "TRANSPARENT")
}

func projectAlarms(children []*ical.Component) []Alarm {
	var alarms []Alarm
	for _, child := range children {
		if child.Name != ical.CompAlarm {
			continue
		}
		trigger := child.Props.Get(ical.PropTrigger)
		if trigger == nil {
			continue
		}
		alarm := Alarm{Trigger: trigger.Value}
		if prop := child.Props.Get(ical.PropAction); prop != nil {
			alarm.Action = strings.ToUpper(prop.Value)
		}
		if trigger.ValueType() == ical.ValueDuration && !strings.EqualFold(trigger.Params.Get(ical.ParamRelated), "END") {
			if duration, err := trigger.Duration(); err == nil && duration <= 0 {
				minutes := int(-duration / time.Minute)
				alarm.MinutesBefore = &minutes
			}
		}
		alarms = append(alarms, alarm)
	}
	return alarms
}

// MailAddress returns the lower-cased email address of a calendar user
// address, dropping a mailto: scheme in any case.
func MailAddress(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 7 && strings.EqualFold(value[:7], "mailto:") {
		value = value[7:]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func calendarAddress(prop *ical.Prop) string {
	if prop == nil {
		return ""
	}
	address := strings.TrimPrefix(strings.TrimSpace(prop.Value), "mailto:")
	if name := strings.TrimSpace(prop.Params.Get("CN")); name != "" {
		return name + " <" + address + ">"
	}
	return address
}

func Occurrences(data []byte, rangeStart, rangeEnd time.Time) ([]Occurrence, bool, error) {
	cal, err := Decode(data)
	if err != nil {
		return nil, false, err
	}
	master := MasterEvent(cal.Events())
	base, err := projectEvent(master)
	if err != nil {
		return nil, false, err
	}
	start, err := master.DateTimeStart(time.Local)
	if err != nil {
		return nil, false, err
	}
	end, err := master.DateTimeEnd(time.Local)
	if err != nil {
		return nil, false, err
	}
	duration := end.Sub(start)
	if duration <= 0 {
		duration = time.Hour
	}
	starts := []time.Time{start}
	if set, setErr := master.Component.RecurrenceSet(time.Local); setErr != nil {
		return nil, false, setErr
	} else if set != nil {
		// Include occurrences that start before the range but overlap it.
		starts = set.Between(rangeStart.Add(-duration), rangeEnd, true)
	}
	truncated := len(starts) > maxOccurrencesPerItem
	if truncated {
		starts = starts[:maxOccurrencesPerItem]
	}
	exceptions := make(map[string]Occurrence)
	for _, event := range cal.Events() {
		recurrenceID := event.Props.Get(ical.PropRecurrenceID)
		if recurrenceID == nil {
			continue
		}
		originalStart, recurrenceErr := recurrenceID.DateTime(time.Local)
		if recurrenceErr != nil {
			return nil, false, fmt.Errorf("parse RECURRENCE-ID: %w", recurrenceErr)
		}
		projected, projectionErr := projectEvent(event)
		if projectionErr != nil {
			return nil, false, projectionErr
		}
		projected.Recurrence = base.Recurrence
		exceptions[occurrenceKey(originalStart)] = Occurrence{Event: projected, RecurrenceID: occurrenceKey(originalStart)}
	}
	result := make([]Occurrence, 0, len(starts))
	for _, occurrenceStart := range starts {
		key := occurrenceKey(occurrenceStart)
		if exception, ok := exceptions[key]; ok {
			delete(exceptions, key)
			exceptionStart, exceptionEnd := parseOccurrenceRange(exception)
			if exceptionStart.Before(rangeEnd) && exceptionEnd.After(rangeStart) {
				result = append(result, exception)
			}
			continue
		}
		occurrenceEnd := occurrenceStart.Add(duration)
		if !occurrenceStart.Before(rangeEnd) || !occurrenceEnd.After(rangeStart) {
			continue
		}
		value := base
		value.Start = formatTime(occurrenceStart, base.AllDay)
		value.End = formatTime(occurrenceEnd, base.AllDay)
		result = append(result, Occurrence{Event: value, RecurrenceID: key})
	}
	for _, exception := range exceptions {
		exceptionStart, exceptionEnd := parseOccurrenceRange(exception)
		if exceptionStart.Before(rangeEnd) && exceptionEnd.After(rangeStart) {
			result = append(result, exception)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Start < result[j].Start })
	return result, truncated, nil
}

func occurrenceKey(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseOccurrenceRange(occurrence Occurrence) (time.Time, time.Time) {
	start, _ := time.Parse(time.RFC3339, occurrence.Start)
	if occurrence.AllDay {
		start, _ = time.ParseInLocation(time.DateOnly, occurrence.Start, time.Local)
	}
	end, err := time.Parse(time.RFC3339, occurrence.End)
	if occurrence.AllDay {
		end, err = time.ParseInLocation(time.DateOnly, occurrence.End, time.Local)
	}
	if err != nil || !end.After(start) {
		end = start.Add(time.Hour)
	}
	return start, end
}

func Create(update Update, uid string, now time.Time) ([]byte, error) {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//Veksel//Workspace//EN")
	event := ical.NewEvent()
	event.Props.SetText(ical.PropUID, uid)
	event.Props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	cal.Children = append(cal.Children, event.Component)
	return applyAndEncode(cal, event, update)
}

func UpdateExisting(data []byte, update Update) ([]byte, error) {
	cal, err := Decode(data)
	if err != nil {
		return nil, err
	}
	events := cal.Events()
	master := MasterEvent(events)
	return applyAndEncode(cal, &master, update)
}

// UpdateOccurrence creates or replaces one recurrence exception while leaving
// the master event and every other occurrence unchanged.
func UpdateOccurrence(data []byte, recurrenceID string, update Update) ([]byte, error) {
	originalStart, err := time.Parse(time.RFC3339, recurrenceID)
	if err != nil {
		return nil, errors.New("recurrence ID must be an RFC 3339 timestamp")
	}
	cal, err := Decode(data)
	if err != nil {
		return nil, err
	}
	events := cal.Events()
	master := MasterEvent(events)
	if master.Props.Get(ical.PropRecurrenceRule) == nil && master.Props.Get(ical.PropRecurrenceDates) == nil {
		return nil, errors.New("event is not recurring")
	}
	var target *ical.Event
	for _, candidate := range events {
		prop := candidate.Props.Get(ical.PropRecurrenceID)
		if prop == nil {
			continue
		}
		value, parseErr := prop.DateTime(time.Local)
		if parseErr == nil && occurrenceKey(value) == occurrenceKey(originalStart) {
			target = &candidate
			break
		}
	}
	if target == nil {
		exception := ical.NewEvent()
		exception.Props = CloneProps(master.Props)
		exception.Children = cloneComponents(master.Children)
		exception.Props.Del(ical.PropRecurrenceRule)
		exception.Props.Del(ical.PropRecurrenceDates)
		exception.Props.Del(ical.PropExceptionDates)
		recurrence := ical.NewProp(ical.PropRecurrenceID)
		if start := master.Props.Get(ical.PropDateTimeStart); start != nil && start.ValueType() == ical.ValueDate {
			recurrence.SetDate(originalStart.In(time.Local))
		} else {
			recurrence.SetDateTime(originalStart.UTC())
		}
		exception.Props.Set(recurrence)
		cal.Children = append(cal.Children, exception.Component)
		target = exception
	}
	update.Recurrence = nil
	return applyAndEncode(cal, target, update)
}

func cloneComponents(source []*ical.Component) []*ical.Component {
	cloned := make([]*ical.Component, 0, len(source))
	for _, component := range source {
		copy := ical.NewComponent(component.Name)
		copy.Props = CloneProps(component.Props)
		copy.Children = cloneComponents(component.Children)
		cloned = append(cloned, copy)
	}
	return cloned
}

// CloneProps deep-copies properties so callers can modify parameters without
// mutating the decoded source.
func CloneProps(source ical.Props) ical.Props {
	cloned := make(ical.Props, len(source))
	for name, values := range source {
		cloned[name] = make([]ical.Prop, len(values))
		for index, value := range values {
			cloned[name][index] = value
			cloned[name][index].Params = make(ical.Params, len(value.Params))
			for param, paramValues := range value.Params {
				cloned[name][index].Params[param] = append([]string(nil), paramValues...)
			}
		}
	}
	return cloned
}

func applyAndEncode(cal *ical.Calendar, event *ical.Event, update Update) ([]byte, error) {
	update.Summary = strings.TrimSpace(update.Summary)
	if update.Summary == "" || update.Start == "" {
		return nil, errors.New("summary and start are required")
	}
	start, end, loc, err := parseUpdateTimes(update)
	if err != nil {
		return nil, err
	}
	before := significant(event.Props)
	event.Props.SetText(ical.PropSummary, update.Summary)
	setOptionalText(event.Props, ical.PropDescription, update.Description)
	setOptionalText(event.Props, ical.PropLocation, update.Location)
	event.Props.Del(ical.PropDuration)
	if update.AllDay {
		event.Props.SetDate(ical.PropDateTimeStart, start)
		event.Props.SetDate(ical.PropDateTimeEnd, end)
	} else {
		start, end = start.In(loc), end.In(loc)
		event.Props.SetDateTime(ical.PropDateTimeStart, start)
		event.Props.SetDateTime(ical.PropDateTimeEnd, end)
	}
	if update.Recurrence != nil {
		preset := strings.ToLower(strings.TrimSpace(*update.Recurrence))
		switch preset {
		case "", "none":
			event.Props.Del(ical.PropRecurrenceRule)
		case "daily", "weekly", "monthly", "yearly":
			prop := ical.NewProp(ical.PropRecurrenceRule)
			prop.Value = "FREQ=" + strings.ToUpper(preset)
			event.Props.Set(prop)
		default:
			rule, err := normalizeRRule(*update.Recurrence)
			if err != nil {
				return nil, err
			}
			prop := ical.NewProp(ical.PropRecurrenceRule)
			prop.Value = rule
			event.Props.Set(prop)
		}
	}
	if update.Categories != nil {
		setCategories(event.Props, *update.Categories)
	}
	if update.Alarms != nil {
		if err := setAlarms(event, *update.Alarms); err != nil {
			return nil, err
		}
	}
	if update.Attendees != nil {
		if err := setAttendees(event.Props, *update.Attendees, update.Organizer); err != nil {
			return nil, err
		}
	}
	// Attendees treat a changed time, place, or rule as a new revision of
	// the meeting (RFC 5546 §2.1.4), so their answers are asked for again.
	if update.Organizing && len(event.Props.Values(ical.PropAttendee)) > 0 && event.Props.Get(ical.PropOrganizer) != nil && before != "" && significant(event.Props) != before {
		sequence := ical.NewProp(ical.PropSequence)
		sequence.Value = strconv.Itoa(eventSequence(event.Props) + 1)
		event.Props.Set(sequence)
		organizer := MailAddress(event.Props.Get(ical.PropOrganizer).Value)
		for index := range event.Props[ical.PropAttendee] {
			attendee := &event.Props[ical.PropAttendee][index]
			if MailAddress(attendee.Value) != organizer {
				attendee.Params.Set(ical.ParamParticipationStatus, "NEEDS-ACTION")
				attendee.Params.Set(ical.ParamRSVP, "TRUE")
			}
		}
	}
	AddMissingTimezones(cal)
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, fmt.Errorf("encode iCalendar: %w", err)
	}
	return buf.Bytes(), nil
}

func parseUpdateTimes(update Update) (time.Time, time.Time, *time.Location, error) {
	loc := time.UTC
	if update.Timezone != "" {
		var err error
		loc, err = time.LoadLocation(update.Timezone)
		if err != nil {
			return time.Time{}, time.Time{}, nil, errors.New("timezone is not recognized")
		}
	}
	if update.AllDay {
		start, err := time.ParseInLocation(time.DateOnly, update.Start, loc)
		if err != nil {
			return time.Time{}, time.Time{}, nil, errors.New("all-day start must use YYYY-MM-DD")
		}
		end := start.AddDate(0, 0, 1)
		if update.End != "" {
			end, err = time.ParseInLocation(time.DateOnly, update.End, loc)
		}
		if err != nil || !end.After(start) {
			return time.Time{}, time.Time{}, nil, errors.New("all-day end must be after start")
		}
		return start, end, loc, nil
	}
	start, err := time.Parse(time.RFC3339, update.Start)
	if err != nil {
		return time.Time{}, time.Time{}, nil, errors.New("start must be an RFC 3339 timestamp")
	}
	end := start.Add(time.Hour)
	if update.End != "" {
		end, err = time.Parse(time.RFC3339, update.End)
	}
	if err != nil || !end.After(start) {
		return time.Time{}, time.Time{}, nil, errors.New("end must be after start")
	}
	return start, end, loc, nil
}

func setOptionalText(props ical.Props, name, value string) {
	if value == "" {
		props.Del(name)
	} else {
		props.SetText(name, value)
	}
}

func formatTime(value time.Time, allDay bool) string {
	if value.IsZero() {
		return ""
	}
	if allDay {
		return value.Format(time.DateOnly)
	}
	return value.Format(time.RFC3339)
}

// significant digests the properties whose change makes a scheduled
// meeting a new revision. It is empty for an event that has no time yet.
func significant(props ical.Props) string {
	if props.Get(ical.PropDateTimeStart) == nil {
		return ""
	}
	var parts []string
	for _, name := range []string{ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDuration, ical.PropRecurrenceRule, ical.PropLocation} {
		for _, prop := range props.Values(name) {
			parts = append(parts, name+";"+prop.Params.Get(ical.PropTimezoneID)+":"+prop.Value)
		}
	}
	return strings.Join(parts, "\n")
}

// normalizeRRule validates a raw RRULE value and returns it upper-cased
// with an optional "RRULE:" prefix removed.
func normalizeRRule(value string) (string, error) {
	rule := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(value)), "RRULE:")
	if rule == "" || len(rule) > 512 || (!strings.HasPrefix(rule, "FREQ=") && !strings.Contains(rule, ";FREQ=")) {
		return "", errors.New("recurrence must be none, daily, weekly, monthly, yearly, or an RRULE value")
	}
	props := make(ical.Props)
	prop := ical.NewProp(ical.PropRecurrenceRule)
	prop.Value = rule
	props.Set(prop)
	option, err := props.RecurrenceRule()
	if err != nil || option == nil {
		return "", errors.New("recurrence rule is not valid")
	}
	if option.Interval < 0 || option.Interval > 1000 || option.Count < 0 || option.Count > 5000 {
		return "", errors.New("recurrence interval or count is out of range")
	}
	return rule, nil
}

func setCategories(props ical.Props, values []string) {
	props.Del(ical.PropCategories)
	var categories []string
	for _, category := range values {
		category = strings.TrimSpace(category)
		if category != "" && len(category) <= 64 && len(categories) < 20 && !containsFold(categories, category) {
			categories = append(categories, category)
		}
	}
	if len(categories) > 0 {
		prop := ical.NewProp(ical.PropCategories)
		prop.SetTextList(categories)
		props.Set(prop)
	}
}

func setAlarms(event *ical.Event, minutes []int) error {
	if len(minutes) > 10 {
		return errors.New("an event may have at most 10 reminders")
	}
	children := event.Children[:0]
	for _, child := range event.Children {
		if child.Name != ical.CompAlarm {
			children = append(children, child)
		}
	}
	event.Children = children
	seen := make(map[int]bool, len(minutes))
	for _, value := range minutes {
		if value < 0 || value > maxAlarmMinutes {
			return errors.New("reminders must be between the start time and four weeks before")
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		alarm := ical.NewComponent(ical.CompAlarm)
		alarm.Props.SetText(ical.PropAction, "DISPLAY")
		trigger := ical.NewProp(ical.PropTrigger)
		trigger.SetValueType(ical.ValueDuration)
		trigger.Value = alarmTrigger(value)
		alarm.Props.Set(trigger)
		alarm.Props.SetText(ical.PropDescription, "Reminder")
		event.Children = append(event.Children, alarm)
	}
	return nil
}

// alarmTrigger formats a start-relative reminder in its most readable unit.
func alarmTrigger(minutes int) string {
	switch {
	case minutes == 0:
		return "PT0S"
	case minutes%(24*60) == 0:
		return "-P" + strconv.Itoa(minutes/(24*60)) + "D"
	case minutes%60 == 0:
		return "-PT" + strconv.Itoa(minutes/60) + "H"
	default:
		return "-PT" + strconv.Itoa(minutes) + "M"
	}
}

var attendeeRoles = map[string]bool{"REQ-PARTICIPANT": true, "OPT-PARTICIPANT": true, "NON-PARTICIPANT": true, "CHAIR": true}

// setAttendees replaces the ATTENDEE list. Remaining attendees keep their
// parameters (PARTSTAT, CN, SCHEDULE-*) with the role updated; new ones are
// asked to reply.
func setAttendees(props ical.Props, attendees []AttendeeUpdate, organizer *AttendeeUpdate) error {
	if len(attendees) > maxAttendees {
		return fmt.Errorf("an event may have at most %d attendees", maxAttendees)
	}
	existing := props.Values(ical.PropAttendee)
	var next []ical.Prop
	seen := map[string]bool{}
	for _, attendee := range attendees {
		address, err := validAddress(attendee.Address)
		if err != nil {
			return err
		}
		if seen[address] {
			continue
		}
		seen[address] = true
		role := strings.ToUpper(strings.TrimSpace(attendee.Role))
		if role == "" {
			role = "REQ-PARTICIPANT"
		}
		if !attendeeRoles[role] {
			return errors.New("attendee role must be REQ-PARTICIPANT, OPT-PARTICIPANT, NON-PARTICIPANT, or CHAIR")
		}
		var prop *ical.Prop
		for index := range existing {
			if MailAddress(existing[index].Value) == address {
				prop = &existing[index]
				break
			}
		}
		if prop == nil {
			prop = ical.NewProp(ical.PropAttendee)
			prop.Value = "mailto:" + address
			prop.Params.Set(ical.ParamParticipationStatus, "NEEDS-ACTION")
			prop.Params.Set(ical.ParamRSVP, "TRUE")
		}
		prop.Params.Set(ical.ParamRole, role)
		if name := cleanName(attendee.Name); name != "" {
			prop.Params.Set(ical.ParamCommonName, name)
		}
		next = append(next, *prop)
	}
	if len(next) == 0 {
		props.Del(ical.PropAttendee)
		props.Del(ical.PropOrganizer)
		return nil
	}
	props[ical.PropAttendee] = next
	if props.Get(ical.PropOrganizer) == nil {
		if organizer == nil {
			return errors.New("an event with attendees needs an organizer")
		}
		address, err := validAddress(organizer.Address)
		if err != nil {
			return err
		}
		prop := ical.NewProp(ical.PropOrganizer)
		prop.Value = "mailto:" + address
		if name := cleanName(organizer.Name); name != "" {
			prop.Params.Set(ical.ParamCommonName, name)
		}
		props.Set(prop)
	}
	return nil
}

// validAddress accepts a bare address, a mailto: URI, or "Name <address>"
// and returns the lower-cased address.
func validAddress(value string) (string, error) {
	parsed, err := mail.ParseAddress(MailAddress(value))
	if err != nil {
		parsed, err = mail.ParseAddress(strings.TrimSpace(value))
	}
	if err != nil || len(parsed.Address) > 254 || !strings.Contains(parsed.Address, "@") {
		return "", fmt.Errorf("attendee address %q is not valid", value)
	}
	return strings.ToLower(parsed.Address), nil
}

func cleanName(value string) string {
	value = strings.Join(strings.Fields(strings.ReplaceAll(value, `"`, "")), " ")
	if len(value) > 120 {
		value = value[:120]
	}
	return value
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}
