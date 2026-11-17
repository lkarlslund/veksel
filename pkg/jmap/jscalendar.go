package jmap

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
)

// JSCalendar (RFC 8984) ↔ iCalendar (RFC 5545) conversion for the commonly
// used event properties, following draft-ietf-calext-jscalendar-icalendar.
// iCalendar properties, parameters and components the converter does not
// own stay in the stored object across JMAP writes.

const localDateTime = "2006-01-02T15:04:05"

const calendarProductID = "-//Veksel//JMAP Calendars//EN"

// ownedEventProps are the VEVENT properties rewritten from JSCalendar.
var ownedEventProps = []string{
	ical.PropSummary, ical.PropDescription, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDuration,
	ical.PropStatus, ical.PropTransparency, ical.PropClass, ical.PropPriority, ical.PropColor, ical.PropSequence,
	ical.PropCreated, ical.PropLastModified, ical.PropDateTimeStamp, ical.PropCategories, ical.PropLocation,
	ical.PropConference, ical.PropURL, ical.PropRecurrenceRule, ical.PropExceptionDates, ical.PropRecurrenceDates,
	ical.PropOrganizer, ical.PropAttendee, ical.PropRecurrenceID,
}

// overrideIgnored are JSCalendar properties never carried in a recurrence
// override patch.
var overrideIgnored = map[string]bool{"@type": true, "uid": true, "recurrenceRules": true, "recurrenceOverrides": true,
	"excludedRecurrenceRules": true, "created": true, "updated": true, "id": true, "calendarIds": true, "isDraft": true}

// icalTime is a DATE or DATE-TIME as wall-clock time in a named zone: tz is
// empty for floating time and "Etc/UTC" for UTC values.
type icalTime struct {
	local time.Time // wall clock, carried in time.UTC
	tz    string
	date  bool
}

func parseICalValue(value, tzid string, date bool) (icalTime, error) {
	value = strings.TrimSpace(value)
	if date || len(value) == 8 {
		local, err := time.Parse("20060102", value)
		return icalTime{local: local, date: true}, err
	}
	t := icalTime{tz: tzid}
	if strings.HasSuffix(value, "Z") {
		value, t.tz = strings.TrimSuffix(value, "Z"), "Etc/UTC"
	}
	local, err := time.Parse("20060102T150405", value)
	t.local = local
	return t, err
}

func parseICalProp(prop *ical.Prop) (icalTime, error) {
	return parseICalValue(prop.Value, prop.Params.Get(ical.PropTimezoneID), prop.ValueType() == ical.ValueDate)
}

// in converts the time to wall-clock time in zone tz when both zones are
// known; floating and date values keep their wall clock.
func (t icalTime) in(tz string) icalTime {
	if t.date || t.tz == "" || tz == "" || t.tz == tz {
		return icalTime{local: t.local, tz: tz, date: t.date}
	}
	from, err1 := time.LoadLocation(t.tz)
	to, err2 := time.LoadLocation(tz)
	if err1 != nil || err2 != nil {
		return icalTime{local: t.local, tz: tz}
	}
	absolute := time.Date(t.local.Year(), t.local.Month(), t.local.Day(), t.local.Hour(), t.local.Minute(), t.local.Second(), 0, from)
	wall := absolute.In(to)
	return icalTime{local: time.Date(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), wall.Second(), 0, time.UTC), tz: tz}
}

// utc returns the absolute instant; floating time is read as UTC.
func (t icalTime) utc() time.Time {
	if t.tz == "" || t.date {
		return t.local
	}
	location, err := time.LoadLocation(t.tz)
	if err != nil {
		return t.local
	}
	return time.Date(t.local.Year(), t.local.Month(), t.local.Day(), t.local.Hour(), t.local.Minute(), t.local.Second(), 0, location).UTC()
}

// setOn writes the time into prop, replacing its value type and TZID.
func (t icalTime) setOn(prop *ical.Prop) {
	prop.Params.Del(ical.PropTimezoneID)
	prop.Params.Del(ical.ParamValue)
	switch {
	case t.date:
		prop.Params.Set(ical.ParamValue, string(ical.ValueDate))
		prop.Value = t.local.Format("20060102")
	case t.tz == "Etc/UTC" || t.tz == "UTC":
		prop.Value = t.local.Format("20060102T150405") + "Z"
	case t.tz != "":
		prop.Params.Set(ical.PropTimezoneID, t.tz)
		prop.Value = t.local.Format("20060102T150405")
	default:
		prop.Value = t.local.Format("20060102T150405")
	}
}

// duration is a nominal JSCalendar/iCalendar duration.
type duration struct {
	negative bool
	days     int
	seconds  int
}

func parseDuration(value string) (duration, error) {
	var d duration
	value = strings.ToUpper(strings.TrimSpace(value))
	if strings.HasPrefix(value, "-") {
		d.negative, value = true, value[1:]
	} else {
		value = strings.TrimPrefix(value, "+")
	}
	if !strings.HasPrefix(value, "P") || len(value) < 3 {
		return d, fmt.Errorf("invalid duration %q", value)
	}
	inTime, number := false, ""
	for _, r := range value[1:] {
		switch {
		case r >= '0' && r <= '9':
			number += string(r)
		case r == 'T':
			inTime = true
		default:
			n, err := strconv.Atoi(number)
			if err != nil {
				return d, fmt.Errorf("invalid duration %q", value)
			}
			number = ""
			switch {
			case r == 'W' && !inTime:
				d.days += 7 * n
			case r == 'D' && !inTime:
				d.days += n
			case r == 'H' && inTime:
				d.seconds += 3600 * n
			case r == 'M' && inTime:
				d.seconds += 60 * n
			case r == 'S' && inTime:
				d.seconds += n
			default:
				return d, fmt.Errorf("invalid duration %q", value)
			}
		}
	}
	if number != "" {
		return d, fmt.Errorf("invalid duration %q", value)
	}
	return d, nil
}

func (d duration) String() string {
	var b strings.Builder
	if d.negative {
		b.WriteByte('-')
	}
	b.WriteByte('P')
	if d.days > 0 {
		b.WriteString(strconv.Itoa(d.days) + "D")
	}
	if d.seconds > 0 || d.days == 0 {
		b.WriteByte('T')
		h, m, s := d.seconds/3600, d.seconds/60%60, d.seconds%60
		if h > 0 {
			b.WriteString(strconv.Itoa(h) + "H")
		}
		if m > 0 {
			b.WriteString(strconv.Itoa(m) + "M")
		}
		if s > 0 || d.seconds == 0 {
			b.WriteString(strconv.Itoa(s) + "S")
		}
	}
	return b.String()
}

func (d duration) addTo(t time.Time) time.Time {
	sign := 1
	if d.negative {
		sign = -1
	}
	return t.AddDate(0, 0, sign*d.days).Add(time.Duration(sign*d.seconds) * time.Second)
}

func nominalDuration(start, end time.Time) duration {
	if end.Before(start) {
		return duration{}
	}
	days := 0
	for !start.AddDate(0, 0, days+1).After(end) {
		days++
	}
	return duration{days: days, seconds: int(end.Sub(start.AddDate(0, 0, days)) / time.Second)}
}

// decodeCalendarEvent projects the master event of an iCalendar object, its
// overrides, exclusions and extra dates into one JSCalendar Event.
func decodeCalendarEvent(cal *ical.Calendar) (map[string]any, error) {
	events := cal.Events()
	if len(events) == 0 {
		return nil, errors.New("calendar object contains no event")
	}
	master := calendar.MasterEvent(events)
	if master.Props.Get(ical.PropRecurrenceID) != nil {
		return nil, errors.New("calendar object contains only recurrence overrides")
	}
	event, start, err := eventObject(master.Component)
	if err != nil {
		return nil, err
	}
	tz, _ := event["timeZone"].(string)
	overrides := map[string]any{}
	for _, name := range []string{ical.PropExceptionDates, ical.PropRecurrenceDates} {
		for _, prop := range master.Props.Values(name) {
			if strings.EqualFold(prop.Params.Get(ical.ParamValue), "PERIOD") {
				continue
			}
			for _, value := range strings.Split(prop.Value, ",") {
				t, err := parseICalValue(value, prop.Params.Get(ical.PropTimezoneID), prop.ValueType() == ical.ValueDate || start.date)
				if err != nil {
					continue
				}
				key := t.in(tz).local.Format(localDateTime)
				if name == ical.PropExceptionDates {
					overrides[key] = map[string]any{"excluded": true}
				} else {
					overrides[key] = map[string]any{}
				}
			}
		}
	}
	base := cloneJSON(event).(map[string]any)
	masterUID, _ := master.Props.Text(ical.PropUID)
	for _, other := range events {
		ridProp := other.Props.Get(ical.PropRecurrenceID)
		if otherUID, _ := other.Props.Text(ical.PropUID); ridProp == nil || otherUID != masterUID {
			continue
		}
		rid, err := parseICalProp(ridProp)
		if err != nil {
			continue
		}
		key := rid.in(tz).local.Format(localDateTime)
		override, _, err := eventObject(other.Component)
		if err != nil {
			continue
		}
		base["start"] = key
		overrides[key] = overridePatch(base, override)
	}
	if len(overrides) > 0 {
		event["recurrenceOverrides"] = overrides
	}
	return event, nil
}

// overridePatch is the PatchObject that turns the master (with start moved
// to the recurrence id) into the override.
func overridePatch(base, override map[string]any) map[string]any {
	patch := map[string]any{}
	for key, value := range override {
		if !overrideIgnored[key] && !reflect.DeepEqual(normalizeJSON(base[key]), normalizeJSON(value)) {
			patch[key] = value
		}
	}
	for key := range base {
		if _, ok := override[key]; !ok && !overrideIgnored[key] {
			patch[key] = nil
		}
	}
	return patch
}

// eventObject converts one VEVENT without its recurrence overrides.
func eventObject(component *ical.Component) (map[string]any, icalTime, error) {
	props := component.Props
	event := map[string]any{"@type": "Event"}
	text := func(name string) string {
		value, _ := props.Text(name)
		return value
	}
	if uid := text(ical.PropUID); uid != "" {
		event["uid"] = uid
	}
	startProp := props.Get(ical.PropDateTimeStart)
	if startProp == nil {
		return nil, icalTime{}, errors.New("event has no DTSTART")
	}
	start, err := parseICalProp(startProp)
	if err != nil {
		return nil, icalTime{}, fmt.Errorf("parse DTSTART: %w", err)
	}
	event["start"] = start.local.Format(localDateTime)
	if start.date {
		event["showWithoutTime"] = true
	}
	if start.tz != "" {
		event["timeZone"] = start.tz
	}
	if prop := props.Get(ical.PropDuration); prop != nil {
		if d, err := parseDuration(prop.Value); err == nil {
			event["duration"] = d.String()
		}
	} else if prop := props.Get(ical.PropDateTimeEnd); prop != nil {
		if end, err := parseICalProp(prop); err == nil {
			if d := nominalDuration(start.local, end.in(start.tz).local); d.days > 0 || d.seconds > 0 {
				event["duration"] = d.String()
			}
		}
	} else if start.date {
		event["duration"] = "P1D"
	}
	for name, property := range map[string]string{ical.PropSummary: "title", ical.PropDescription: "description", ical.PropColor: "color"} {
		if value := text(name); value != "" {
			event[property] = value
		}
	}
	if value := strings.ToLower(text(ical.PropStatus)); value == "confirmed" || value == "tentative" || value == "cancelled" {
		event["status"] = value
	}
	switch strings.ToUpper(text(ical.PropTransparency)) {
	case "TRANSPARENT":
		event["freeBusyStatus"] = "free"
	case "OPAQUE":
		event["freeBusyStatus"] = "busy"
	}
	switch strings.ToUpper(text(ical.PropClass)) {
	case "PUBLIC":
		event["privacy"] = "public"
	case "PRIVATE":
		event["privacy"] = "private"
	case "CONFIDENTIAL":
		event["privacy"] = "secret"
	}
	for name, property := range map[string]string{ical.PropPriority: "priority", ical.PropSequence: "sequence"} {
		if prop := props.Get(name); prop != nil {
			if n, err := prop.Int(); err == nil {
				event[property] = n
			}
		}
	}
	if stamp, ok := utcStamp(props, ical.PropCreated); ok {
		event["created"] = stamp
	}
	if stamp, ok := utcStamp(props, ical.PropLastModified); ok {
		event["updated"] = stamp
	} else if stamp, ok := utcStamp(props, ical.PropDateTimeStamp); ok {
		event["updated"] = stamp
	}
	keywords := map[string]any{}
	for _, prop := range props.Values(ical.PropCategories) {
		values, _ := prop.TextList()
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				keywords[value] = true
			}
		}
	}
	if len(keywords) > 0 {
		event["keywords"] = keywords
	}
	if location := text(ical.PropLocation); location != "" {
		event["locations"] = map[string]any{"1": map[string]any{"@type": "Location", "name": location}}
	}
	virtual := map[string]any{}
	for index, prop := range props.Values(ical.PropConference) {
		entry := map[string]any{"@type": "VirtualLocation", "uri": prop.Value}
		if label := prop.Params.Get("LABEL"); label != "" {
			entry["name"] = label
		}
		virtual["v"+strconv.Itoa(index+1)] = entry
	}
	if len(virtual) > 0 {
		event["virtualLocations"] = virtual
	}
	if prop := props.Get(ical.PropURL); prop != nil && prop.Value != "" {
		event["links"] = map[string]any{"1": map[string]any{"@type": "Link", "href": prop.Value}}
	}
	var rules []any
	for _, prop := range props.Values(ical.PropRecurrenceRule) {
		if rule, err := decodeRecurrenceRule(prop.Value, start); err == nil {
			rules = append(rules, rule)
		}
	}
	if len(rules) > 0 {
		event["recurrenceRules"] = rules
	}
	if participants, replyTo := decodeParticipants(props); len(participants) > 0 {
		event["participants"] = participants
		if replyTo != "" {
			event["replyTo"] = map[string]any{"imip": replyTo}
		}
	}
	if alerts := decodeAlerts(component.Children); len(alerts) > 0 {
		event["alerts"] = alerts
	}
	return event, start, nil
}

func utcStamp(props ical.Props, name string) (string, bool) {
	prop := props.Get(name)
	if prop == nil {
		return "", false
	}
	when, err := prop.DateTime(time.UTC)
	if err != nil {
		return "", false
	}
	return when.UTC().Format(time.RFC3339), true
}

var weekdays = []string{"MO", "TU", "WE", "TH", "FR", "SA", "SU"}

func decodeRecurrenceRule(value string, start icalTime) (map[string]any, error) {
	rule := map[string]any{"@type": "RecurrenceRule"}
	numbers := func(list string) ([]any, error) {
		var out []any
		for _, part := range strings.Split(list, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(strings.ToUpper(value), "RRULE:"), ";") {
		name, raw, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch name {
		case "FREQ":
			rule["frequency"] = strings.ToLower(raw)
		case "INTERVAL", "COUNT":
			n, err := strconv.Atoi(raw)
			if err != nil {
				return nil, err
			}
			rule[strings.ToLower(name)] = n
		case "UNTIL":
			until, err := parseICalValue(raw, "", false)
			if err != nil {
				return nil, err
			}
			rule["until"] = until.in(start.tz).local.Format(localDateTime)
		case "WKST":
			rule["firstDayOfWeek"] = strings.ToLower(raw)
		case "RSCALE":
			rule["rscale"] = strings.ToLower(raw)
		case "SKIP":
			rule["skip"] = strings.ToLower(raw)
		case "BYDAY":
			var days []any
			for _, day := range strings.Split(raw, ",") {
				if len(day) < 2 || indexOf(weekdays, day[len(day)-2:]) < 0 {
					return nil, fmt.Errorf("invalid BYDAY %q", day)
				}
				nday := map[string]any{"@type": "NDay", "day": strings.ToLower(day[len(day)-2:])}
				if prefix := day[:len(day)-2]; prefix != "" {
					n, err := strconv.Atoi(prefix)
					if err != nil {
						return nil, err
					}
					nday["nthOfPeriod"] = n
				}
				days = append(days, nday)
			}
			rule["byDay"] = days
		case "BYMONTH":
			var months []any
			for _, month := range strings.Split(raw, ",") {
				months = append(months, strings.ToUpper(month))
			}
			rule["byMonth"] = months
		case "BYMONTHDAY", "BYYEARDAY", "BYWEEKNO", "BYHOUR", "BYMINUTE", "BYSECOND", "BYSETPOS":
			list, err := numbers(raw)
			if err != nil {
				return nil, err
			}
			property := map[string]string{"BYMONTHDAY": "byMonthDay", "BYYEARDAY": "byYearDay", "BYWEEKNO": "byWeekNo", "BYHOUR": "byHour",
				"BYMINUTE": "byMinute", "BYSECOND": "bySecond", "BYSETPOS": "bySetPosition"}[name]
			rule[property] = list
		}
	}
	if _, ok := rule["frequency"]; !ok {
		return nil, errors.New("RRULE without FREQ")
	}
	return rule, nil
}

func encodeRecurrenceRule(raw any, start icalTime) (string, error) {
	rule, _ := raw.(map[string]any)
	frequency, _ := rule["frequency"].(string)
	if !containsString([]string{"yearly", "monthly", "weekly", "daily", "hourly", "minutely", "secondly"}, frequency) {
		return "", fmt.Errorf("invalid recurrence frequency %q", frequency)
	}
	parts := []string{"FREQ=" + strings.ToUpper(frequency)}
	if v, ok := rule["rscale"].(string); ok {
		parts = append(parts, "RSCALE="+strings.ToUpper(v))
	}
	if v, ok := rule["skip"].(string); ok {
		parts = append(parts, "SKIP="+strings.ToUpper(v))
	}
	if n, ok := jsonInt(rule["interval"]); ok && n > 0 {
		parts = append(parts, "INTERVAL="+strconv.Itoa(n))
	}
	if n, ok := jsonInt(rule["count"]); ok {
		parts = append(parts, "COUNT="+strconv.Itoa(n))
	}
	if until, ok := rule["until"].(string); ok {
		local, err := time.Parse(localDateTime, until)
		if err != nil {
			return "", errors.New("invalid recurrence until")
		}
		t := icalTime{local: local, tz: start.tz, date: start.date}
		switch {
		case t.date:
			parts = append(parts, "UNTIL="+local.Format("20060102"))
		case t.tz != "":
			parts = append(parts, "UNTIL="+t.utc().Format("20060102T150405Z"))
		default:
			parts = append(parts, "UNTIL="+local.Format("20060102T150405"))
		}
	}
	if days, ok := rule["byDay"].([]any); ok && len(days) > 0 {
		var values []string
		for _, rawDay := range days {
			nday, _ := rawDay.(map[string]any)
			day, _ := nday["day"].(string)
			if indexOf(weekdays, strings.ToUpper(day)) < 0 {
				return "", fmt.Errorf("invalid byDay day %q", day)
			}
			prefix := ""
			if n, ok := jsonInt(nday["nthOfPeriod"]); ok && n != 0 {
				prefix = strconv.Itoa(n)
			}
			values = append(values, prefix+strings.ToUpper(day))
		}
		parts = append(parts, "BYDAY="+strings.Join(values, ","))
	}
	if months, ok := rule["byMonth"].([]any); ok && len(months) > 0 {
		var values []string
		for _, month := range months {
			values = append(values, fmt.Sprint(month))
		}
		parts = append(parts, "BYMONTH="+strings.Join(values, ","))
	}
	for _, field := range [][2]string{{"byMonthDay", "BYMONTHDAY"}, {"byYearDay", "BYYEARDAY"}, {"byWeekNo", "BYWEEKNO"}, {"byHour", "BYHOUR"},
		{"byMinute", "BYMINUTE"}, {"bySecond", "BYSECOND"}, {"bySetPosition", "BYSETPOS"}} {
		list, _ := rule[field[0]].([]any)
		if len(list) == 0 {
			continue
		}
		var values []string
		for _, item := range list {
			n, ok := jsonInt(item)
			if !ok {
				return "", fmt.Errorf("invalid %s", field[0])
			}
			values = append(values, strconv.Itoa(n))
		}
		parts = append(parts, field[1]+"="+strings.Join(values, ","))
	}
	if v, ok := rule["firstDayOfWeek"].(string); ok && v != "" {
		parts = append(parts, "WKST="+strings.ToUpper(v))
	}
	return strings.Join(parts, ";"), nil
}

func jsonInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case float64:
		return int(v), v == float64(int(v))
	case int:
		return v, true
	}
	return 0, false
}

// participantID derives a stable participant id from its address.
func participantID(address string) string {
	sum := sha256Bytes(strings.ToLower(address))
	return fmt.Sprintf("%x", sum[:6])
}

var (
	participationStatuses = []string{"needs-action", "accepted", "declined", "tentative", "delegated"}
	calendarUserTypes     = map[string]string{"INDIVIDUAL": "individual", "GROUP": "group", "RESOURCE": "resource", "ROOM": "location"}
)

func decodeParticipants(props ical.Props) (map[string]any, string) {
	participants := map[string]any{}
	participant := func(prop ical.Prop) map[string]any {
		address := calendar.MailAddress(prop.Value)
		id := participantID(address)
		p, ok := participants[id].(map[string]any)
		if !ok {
			p = map[string]any{"@type": "Participant", "roles": map[string]any{}, "sendTo": map[string]any{"imip": prop.Value}}
			if address != "" && strings.Contains(address, "@") {
				p["email"] = address
			}
			participants[id] = p
		}
		if name := prop.Params.Get(ical.ParamCommonName); name != "" {
			p["name"] = name
		}
		return p
	}
	replyTo := ""
	if organizer := props.Get(ical.PropOrganizer); organizer != nil {
		replyTo = organizer.Value
		p := participant(*organizer)
		p["roles"].(map[string]any)["owner"] = true
	}
	for _, attendee := range props.Values(ical.PropAttendee) {
		p := participant(attendee)
		roles := p["roles"].(map[string]any)
		switch strings.ToUpper(attendee.Params.Get(ical.ParamRole)) {
		case "CHAIR":
			roles["attendee"], roles["chair"] = true, true
		case "OPT-PARTICIPANT":
			roles["attendee"], roles["optional"] = true, true
		case "NON-PARTICIPANT":
			roles["informational"] = true
		default:
			roles["attendee"] = true
		}
		status := strings.ToLower(attendee.Params.Get(ical.ParamParticipationStatus))
		if status == "" || indexOf(participationStatuses, status) < 0 {
			status = "needs-action"
		}
		p["participationStatus"] = status
		if strings.EqualFold(attendee.Params.Get(ical.ParamRSVP), "TRUE") {
			p["expectReply"] = true
		}
		if kind, ok := calendarUserTypes[strings.ToUpper(attendee.Params.Get(ical.ParamCalendarUserType))]; ok {
			p["kind"] = kind
		}
		if agent := strings.ToLower(attendee.Params.Get("SCHEDULE-AGENT")); agent != "" {
			p["scheduleAgent"] = agent
		}
	}
	return participants, replyTo
}

func decodeAlerts(children []*ical.Component) map[string]any {
	alerts := map[string]any{}
	position := 0
	for _, child := range children {
		if child.Name != ical.CompAlarm {
			continue
		}
		position++
		trigger := child.Props.Get(ical.PropTrigger)
		if trigger == nil {
			continue
		}
		alert := map[string]any{"@type": "Alert", "action": "display"}
		if action := child.Props.Get(ical.PropAction); action != nil && strings.EqualFold(action.Value, "EMAIL") {
			alert["action"] = "email"
		}
		if strings.EqualFold(trigger.Params.Get(ical.ParamValue), "DATE-TIME") || strings.HasSuffix(trigger.Value, "Z") {
			when, err := trigger.DateTime(time.UTC)
			if err != nil {
				continue
			}
			alert["trigger"] = map[string]any{"@type": "AbsoluteTrigger", "when": when.UTC().Format(time.RFC3339)}
		} else {
			d, err := parseDuration(trigger.Value)
			if err != nil {
				continue
			}
			offset := map[string]any{"@type": "OffsetTrigger", "offset": d.String()}
			if strings.EqualFold(trigger.Params.Get(ical.ParamRelated), "END") {
				offset["relativeTo"] = "end"
			}
			alert["trigger"] = offset
		}
		alerts[alertKey(child, position)] = alert
	}
	return alerts
}

func alertKey(alarm *ical.Component, position int) string {
	if uid, _ := alarm.Props.Text(ical.PropUID); uid != "" {
		return uid
	}
	return "a" + strconv.Itoa(position)
}

// encodeCalendarEvent writes a JSCalendar Event into an iCalendar object.
// With an original, components and properties the converter does not own
// are kept, including those of existing recurrence overrides.
func encodeCalendarEvent(event map[string]any, original *ical.Calendar, now time.Time) (*ical.Calendar, error) {
	if t, ok := event["@type"]; ok && t != "Event" {
		return nil, errors.New("@type must be Event")
	}
	uid, _ := event["uid"].(string)
	if uid == "" {
		return nil, errors.New("uid is required")
	}
	cal := ical.NewCalendar()
	var masterBase *ical.Component
	overrideBases := map[string]*ical.Component{}
	if original != nil {
		cal.Props = original.Props
		var master *ical.Component
		for _, child := range original.Children {
			if child.Name == ical.CompEvent {
				if child.Props.Get(ical.PropRecurrenceID) == nil && master == nil {
					master = child
				}
			}
		}
		for _, child := range original.Children {
			if child.Name != ical.CompEvent {
				cal.Children = append(cal.Children, child)
				continue
			}
			if child == master {
				masterBase = child
				continue
			}
			if rid := child.Props.Get(ical.PropRecurrenceID); rid != nil && master != nil {
				if t, err := parseICalProp(rid); err == nil {
					masterStart, _ := parseICalProp(master.Props.Get(ical.PropDateTimeStart))
					overrideBases[t.in(masterStart.tz).local.Format(localDateTime)] = child
					continue
				}
			}
			cal.Children = append(cal.Children, child)
		}
	}
	if cal.Props.Get(ical.PropVersion) == nil {
		cal.Props.SetText(ical.PropVersion, "2.0")
	}
	if cal.Props.Get(ical.PropProductID) == nil {
		cal.Props.SetText(ical.PropProductID, calendarProductID)
	}
	master, start, err := buildEvent(event, uid, masterBase, now)
	if err != nil {
		return nil, err
	}
	if masterBase != nil {
		bumpSequence(masterBase, master, event)
	}
	cal.Children = append(cal.Children, master)
	overrides, _ := event["recurrenceOverrides"].(map[string]any)
	base := cloneJSON(event).(map[string]any)
	for key := range overrideIgnored {
		if key != "uid" && key != "@type" {
			delete(base, key)
		}
	}
	for _, key := range sortedKeys(overrides) {
		local, err := time.Parse(localDateTime, key)
		if err != nil {
			return nil, fmt.Errorf("recurrenceOverrides key %q is not a LocalDateTime", key)
		}
		rid := icalTime{local: local, tz: start.tz, date: start.date}
		patch, ok := overrides[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("recurrenceOverrides/%s must be an object", key)
		}
		if patch["excluded"] == true {
			prop := ical.NewProp(ical.PropExceptionDates)
			rid.setOn(prop)
			master.Props.Add(prop)
			continue
		}
		if len(patch) == 0 {
			prop := ical.NewProp(ical.PropRecurrenceDates)
			rid.setOn(prop)
			master.Props.Add(prop)
			continue
		}
		instance := cloneJSON(base).(map[string]any)
		instance["start"] = key
		if err := applyPatch(instance, patch); err != nil {
			return nil, fmt.Errorf("recurrenceOverrides/%s: %w", key, err)
		}
		override, _, err := buildEvent(instance, uid, overrideBases[key], now)
		if err != nil {
			return nil, fmt.Errorf("recurrenceOverrides/%s: %w", key, err)
		}
		prop := ical.NewProp(ical.PropRecurrenceID)
		rid.setOn(prop)
		override.Props.Set(prop)
		cal.Children = append(cal.Children, override)
	}
	return cal, nil
}

// bumpSequence raises SEQUENCE when an organizer changes the time, rule or
// place of a scheduled meeting without raising it itself, so attendees treat
// the update as a new revision (RFC 5546 §2.1.4).
func bumpSequence(before, after *ical.Component, event map[string]any) {
	if after.Props.Get(ical.PropOrganizer) == nil || len(after.Props.Values(ical.PropAttendee)) == 0 {
		return
	}
	digest := func(c *ical.Component) string {
		var parts []string
		for _, name := range []string{ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDuration, ical.PropRecurrenceRule, ical.PropLocation} {
			for _, prop := range c.Props.Values(name) {
				value := prop.Value
				if name == ical.PropRecurrenceRule {
					rule := strings.Split(strings.ToUpper(value), ";")
					slices.Sort(rule)
					value = strings.Join(rule, ";")
				}
				parts = append(parts, name+prop.Params.Get(ical.PropTimezoneID)+":"+value)
			}
		}
		return strings.Join(parts, "\n")
	}
	old := 0
	if prop := before.Props.Get(ical.PropSequence); prop != nil {
		old, _ = prop.Int()
	}
	requested, _ := jsonInt(event["sequence"])
	if digest(before) != digest(after) && requested <= old {
		prop := ical.NewProp(ical.PropSequence)
		prop.Value = strconv.Itoa(old + 1)
		after.Props.Set(prop)
	}
}

// buildEvent writes the JSCalendar properties into a VEVENT, starting from
// a copy of base so properties the converter does not own survive.
func buildEvent(event map[string]any, uid string, base *ical.Component, now time.Time) (*ical.Component, icalTime, error) {
	component := ical.NewComponent(ical.CompEvent)
	var baseAlarms []*ical.Component
	if base != nil {
		for name, values := range base.Props {
			component.Props[name] = append([]ical.Prop(nil), values...)
		}
		for _, child := range base.Children {
			if child.Name == ical.CompAlarm {
				baseAlarms = append(baseAlarms, child)
			} else {
				component.Children = append(component.Children, child)
			}
		}
	}
	for _, name := range ownedEventProps {
		component.Props.Del(name)
	}
	props := component.Props
	props.SetText(ical.PropUID, uid)
	props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	str := func(name string) string { value, _ := event[name].(string); return value }
	startText := str("start")
	local, err := time.Parse(localDateTime, startText)
	if err != nil {
		return nil, icalTime{}, errors.New("start must be a LocalDateTime")
	}
	start := icalTime{local: local, tz: str("timeZone"), date: event["showWithoutTime"] == true}
	if start.date {
		start.tz = ""
	} else if start.tz != "" && start.tz != "Etc/UTC" && start.tz != "UTC" {
		if _, err := time.LoadLocation(start.tz); err != nil {
			return nil, icalTime{}, fmt.Errorf("unknown timeZone %q", start.tz)
		}
	}
	prop := ical.NewProp(ical.PropDateTimeStart)
	start.setOn(prop)
	props.Set(prop)
	if text := str("duration"); text != "" {
		d, err := parseDuration(text)
		if err != nil || d.negative {
			return nil, icalTime{}, errors.New("duration must be a positive Duration")
		}
		if d.days > 0 || d.seconds > 0 {
			end := start
			end.local = d.addTo(start.local)
			if start.date && d.seconds != 0 {
				return nil, icalTime{}, errors.New("duration of an event without time must be whole days")
			}
			prop := ical.NewProp(ical.PropDateTimeEnd)
			end.setOn(prop)
			props.Set(prop)
		}
	}
	setText := func(name, value string) {
		if value != "" {
			props.SetText(name, value)
		}
	}
	setText(ical.PropSummary, str("title"))
	setText(ical.PropDescription, str("description"))
	setText(ical.PropColor, str("color"))
	if status := str("status"); status != "" {
		if !containsString([]string{"confirmed", "tentative", "cancelled"}, status) {
			return nil, icalTime{}, fmt.Errorf("invalid status %q", status)
		}
		props.SetText(ical.PropStatus, strings.ToUpper(status))
	}
	switch str("freeBusyStatus") {
	case "free":
		props.SetText(ical.PropTransparency, "TRANSPARENT")
	case "busy":
		props.SetText(ical.PropTransparency, "OPAQUE")
	}
	switch str("privacy") {
	case "public":
		props.SetText(ical.PropClass, "PUBLIC")
	case "private":
		props.SetText(ical.PropClass, "PRIVATE")
	case "secret":
		props.SetText(ical.PropClass, "CONFIDENTIAL")
	}
	for property, name := range map[string]string{"priority": ical.PropPriority, "sequence": ical.PropSequence} {
		if n, ok := jsonInt(event[property]); ok {
			prop := ical.NewProp(name)
			prop.Value = strconv.Itoa(n)
			props.Set(prop)
		}
	}
	if created, ok := event["created"].(string); ok {
		if when, err := time.Parse(time.RFC3339, created); err == nil {
			props.SetDateTime(ical.PropCreated, when.UTC())
		}
	}
	props.SetDateTime(ical.PropLastModified, now.UTC())
	if keywords := trueKeys(event["keywords"]); len(keywords) > 0 {
		prop := ical.NewProp(ical.PropCategories)
		prop.SetTextList(keywords)
		props.Set(prop)
	}
	locations, _ := event["locations"].(map[string]any)
	for _, key := range sortedKeys(locations) {
		location, _ := locations[key].(map[string]any)
		if name, _ := location["name"].(string); name != "" {
			props.SetText(ical.PropLocation, name)
			break
		}
	}
	virtual, _ := event["virtualLocations"].(map[string]any)
	for _, key := range sortedKeys(virtual) {
		location, _ := virtual[key].(map[string]any)
		uri, _ := location["uri"].(string)
		if uri == "" {
			return nil, icalTime{}, fmt.Errorf("virtualLocations/%s needs a uri", key)
		}
		prop := ical.NewProp(ical.PropConference)
		prop.SetValueType(ical.ValueURI)
		prop.Value = uri
		if name, _ := location["name"].(string); name != "" {
			prop.Params.Set("LABEL", name)
		}
		props.Add(prop)
	}
	links, _ := event["links"].(map[string]any)
	for _, key := range sortedKeys(links) {
		link, _ := links[key].(map[string]any)
		if href, _ := link["href"].(string); href != "" {
			prop := ical.NewProp(ical.PropURL)
			prop.SetValueType(ical.ValueURI)
			prop.Value = href
			props.Set(prop)
			break
		}
	}
	rules, _ := event["recurrenceRules"].([]any)
	for _, raw := range rules {
		value, err := encodeRecurrenceRule(raw, start)
		if err != nil {
			return nil, icalTime{}, err
		}
		prop := ical.NewProp(ical.PropRecurrenceRule)
		prop.Value = value
		props.Add(prop)
	}
	var baseProps ical.Props
	if base != nil {
		baseProps = base.Props
	}
	if err := encodeParticipants(props, event, baseProps); err != nil {
		return nil, icalTime{}, err
	}
	alarms, err := encodeAlerts(event["alerts"], baseAlarms, str("title"))
	if err != nil {
		return nil, icalTime{}, err
	}
	component.Children = append(component.Children, alarms...)
	return component, start, nil
}

func encodeParticipants(props ical.Props, event map[string]any, base ical.Props) error {
	participants, _ := event["participants"].(map[string]any)
	existing := func(name, address string) *ical.Prop {
		for _, prop := range base.Values(name) {
			if calendar.MailAddress(prop.Value) == calendar.MailAddress(address) {
				clone := ical.Prop{Name: prop.Name, Value: prop.Value, Params: ical.Params{}}
				for k, v := range prop.Params {
					clone.Params[k] = append([]string(nil), v...)
				}
				return &clone
			}
		}
		prop := ical.NewProp(name)
		return prop
	}
	organizerSet := false
	for _, key := range sortedKeys(participants) {
		p, ok := participants[key].(map[string]any)
		if !ok {
			return fmt.Errorf("participants/%s must be an object", key)
		}
		sendTo, _ := p["sendTo"].(map[string]any)
		address, _ := sendTo["imip"].(string)
		if address == "" {
			if email, _ := p["email"].(string); email != "" {
				address = "mailto:" + email
			}
		}
		if address == "" {
			return fmt.Errorf("participants/%s needs sendTo/imip or email", key)
		}
		roles, _ := p["roles"].(map[string]any)
		name, _ := p["name"].(string)
		if roles["owner"] == true && !organizerSet {
			organizer := existing(ical.PropOrganizer, address)
			organizer.Value = address
			setParam(organizer, ical.ParamCommonName, name)
			props.Set(organizer)
			organizerSet = true
		}
		attending := roles["attendee"] == true || roles["chair"] == true || roles["optional"] == true || roles["informational"] == true || roles["owner"] != true
		if !attending {
			continue
		}
		attendee := existing(ical.PropAttendee, address)
		attendee.Value = address
		setParam(attendee, ical.ParamCommonName, name)
		role := "REQ-PARTICIPANT"
		switch {
		case roles["chair"] == true:
			role = "CHAIR"
		case roles["informational"] == true:
			role = "NON-PARTICIPANT"
		case roles["optional"] == true:
			role = "OPT-PARTICIPANT"
		}
		setParam(attendee, ical.ParamRole, role)
		status, _ := p["participationStatus"].(string)
		if status == "" {
			status = "needs-action"
		}
		if indexOf(participationStatuses, status) < 0 {
			return fmt.Errorf("participants/%s has an invalid participationStatus", key)
		}
		setParam(attendee, ical.ParamParticipationStatus, strings.ToUpper(status))
		rsvp := ""
		if p["expectReply"] == true {
			rsvp = "TRUE"
		}
		setParam(attendee, ical.ParamRSVP, rsvp)
		cutype := ""
		if kind, _ := p["kind"].(string); kind != "" {
			for ical, js := range calendarUserTypes {
				if js == kind {
					cutype = ical
				}
			}
		}
		setParam(attendee, ical.ParamCalendarUserType, cutype)
		agent, _ := p["scheduleAgent"].(string)
		setParam(attendee, "SCHEDULE-AGENT", strings.ToUpper(agent))
		props.Add(attendee)
	}
	if !organizerSet {
		if replyTo, _ := event["replyTo"].(map[string]any); replyTo != nil && len(participants) > 0 {
			if address, _ := replyTo["imip"].(string); address != "" {
				organizer := existing(ical.PropOrganizer, address)
				organizer.Value = address
				props.Set(organizer)
			}
		}
	}
	return nil
}

func setParam(prop *ical.Prop, name, value string) {
	if value == "" {
		prop.Params.Del(name)
		return
	}
	prop.Params.Set(name, value)
}

func encodeAlerts(raw any, base []*ical.Component, title string) ([]*ical.Component, error) {
	alerts, _ := raw.(map[string]any)
	byKey := map[string]*ical.Component{}
	for index, alarm := range base {
		byKey[alertKey(alarm, index+1)] = alarm
	}
	var out []*ical.Component
	for position, key := range sortedKeys(alerts) {
		alert, ok := alerts[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("alerts/%s must be an object", key)
		}
		alarm := ical.NewComponent(ical.CompAlarm)
		if existing, ok := byKey[key]; ok {
			for name, values := range existing.Props {
				alarm.Props[name] = append([]ical.Prop(nil), values...)
			}
			alarm.Children = existing.Children
		}
		alarm.Props.Del(ical.PropUID)
		if key != "a"+strconv.Itoa(position+1) {
			alarm.Props.SetText(ical.PropUID, key)
		}
		action := "DISPLAY"
		if a, _ := alert["action"].(string); a == "email" {
			action = "EMAIL"
		}
		alarm.Props.SetText(ical.PropAction, action)
		trigger, _ := alert["trigger"].(map[string]any)
		prop := ical.NewProp(ical.PropTrigger)
		switch {
		case trigger["when"] != nil:
			when, err := time.Parse(time.RFC3339, fmt.Sprint(trigger["when"]))
			if err != nil {
				return nil, fmt.Errorf("alerts/%s has an invalid trigger time", key)
			}
			prop.SetDateTime(when.UTC())
		case trigger["offset"] != nil:
			d, err := parseDuration(fmt.Sprint(trigger["offset"]))
			if err != nil {
				return nil, fmt.Errorf("alerts/%s has an invalid trigger offset", key)
			}
			prop.Value = d.String()
			if trigger["relativeTo"] == "end" {
				prop.Params.Set(ical.ParamRelated, "END")
			}
		default:
			return nil, fmt.Errorf("alerts/%s needs an offset or absolute trigger", key)
		}
		alarm.Props.Set(prop)
		if alarm.Props.Get(ical.PropDescription) == nil {
			description := title
			if description == "" {
				description = "Reminder"
			}
			alarm.Props.SetText(ical.PropDescription, description)
		}
		if action == "EMAIL" && alarm.Props.Get(ical.PropSummary) == nil {
			alarm.Props.SetText(ical.PropSummary, alarm.Props.Get(ical.PropDescription).Value)
		}
		out = append(out, alarm)
	}
	return out, nil
}
