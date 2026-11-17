package caldav

import (
	"bytes"
	"encoding/xml"
	"errors"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

// maxExpandedInstances bounds the instances one object contributes to an
// expanded calendar-query or multiget reply.
const maxExpandedInstances = 1000

// calendarDataRequest captures the CALDAV:calendar-data element of a
// calendar-query or calendar-multiget prop, whose expand child asks for
// recurrence instances instead of the stored object (RFC 4791 §9.6.5).
type calendarDataRequest struct {
	Prop struct {
		CalendarData *struct {
			Expand *timeRange `xml:"urn:ietf:params:xml:ns:caldav expand"`
		} `xml:"urn:ietf:params:xml:ns:caldav calendar-data"`
	} `xml:"DAV: prop"`
}

// expandRange returns the expand range of a REPORT body, if it has one.
func expandRange(body []byte) (start, end time.Time, ok bool, err error) {
	var request calendarDataRequest
	if xml.Unmarshal(body, &request) != nil || request.Prop.CalendarData == nil || request.Prop.CalendarData.Expand == nil {
		return time.Time{}, time.Time{}, false, nil
	}
	expand := request.Prop.CalendarData.Expand
	if start, err = parseCalDAVTime(expand.Start); err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	if end, err = parseCalDAVTime(expand.End); err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	return start, end, true, nil
}

// expandedCalendarData returns data with its recurring component replaced
// by the instances overlapping [start, end), as RFC 4791 §9.6.5 requires:
// one VCALENDAR in which every instance carries a RECURRENCE-ID, has no
// RRULE, RDATE, or EXDATE, and uses UTC date-times, overridden instances
// taking the place of the ones they replace. Data that cannot be expanded is
// returned unchanged.
func expandedCalendarData(data []byte, start, end time.Time) []byte {
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return data
	}
	instances, err := expandInstances(cal, start, end)
	if err != nil {
		return data
	}
	out := ical.NewCalendar()
	for _, name := range []string{ical.PropVersion, ical.PropProductID, ical.PropCalendarScale} {
		if prop := cal.Props.Get(name); prop != nil {
			out.Props.Set(prop)
		}
	}
	if out.Props.Get(ical.PropVersion) == nil {
		out.Props.SetText(ical.PropVersion, "2.0")
	}
	if out.Props.Get(ical.PropProductID) == nil {
		out.Props.SetText(ical.PropProductID, "-//Veksel//CalDAV//EN")
	}
	for _, instance := range instances {
		// The encoder requires DTSTAMP, which some stored objects lack.
		if instance.Props.Get(ical.PropDateTimeStamp) == nil {
			instance.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
		}
	}
	out.Children = instances
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(out); err != nil {
		return data
	}
	return buf.Bytes()
}

// objectOverlaps reports whether any instance of a recurring calendar
// object overlaps [start, end); ok is false when it cannot be decided.
func objectOverlaps(data []byte, start, end time.Time) (overlaps, ok bool) {
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return false, false
	}
	instances, err := expandInstances(cal, start, end)
	if err != nil {
		return false, false
	}
	return len(instances) > 0, true
}

// expandInstances lists the events and tasks of cal overlapping
// [start, end), expanding the recurring master into instances.
func expandInstances(cal *ical.Calendar, start, end time.Time) ([]*ical.Component, error) {
	var master *ical.Component
	overrides := map[time.Time]*ical.Component{}
	var standalone []*ical.Component
	for _, child := range cal.Children {
		if child.Name != ical.CompEvent && child.Name != ical.CompToDo {
			continue
		}
		recurrenceID := child.Props.Get(ical.PropRecurrenceID)
		switch {
		case recurrenceID != nil:
			at, err := recurrenceID.DateTime(time.UTC)
			if err != nil {
				return nil, err
			}
			overrides[at.UTC()] = child
		case master == nil && child.Props.Get(ical.PropRecurrenceRule) != nil:
			master = child
		default:
			standalone = append(standalone, child)
		}
	}
	var result []*ical.Component
	for _, component := range standalone {
		if component.Props.Get(ical.PropDateTimeStart) != nil {
			// A start that cannot be placed leaves the decision to the caller.
			if _, _, _, err := componentSpan(component); err != nil {
				return nil, err
			}
		}
		if overlapsRange(component, start, end) {
			result = append(result, utcComponent(component))
		}
	}
	if master != nil {
		set, err := recurrenceSet(master)
		if err != nil {
			return nil, err
		}
		_, duration, allDay, err := componentSpan(master)
		if err != nil {
			return nil, err
		}
		for count, at := range set.Between(start.Add(-duration), end, true) {
			if count >= maxExpandedInstances {
				break
			}
			if override, found := overrides[at.UTC()]; found {
				delete(overrides, at.UTC())
				if overlapsRange(override, start, end) {
					result = append(result, utcComponent(override))
				}
				continue
			}
			instanceEnd := at.Add(duration)
			if !at.Before(end) || (duration > 0 && !instanceEnd.After(start)) || (duration == 0 && at.Before(start)) {
				continue
			}
			result = append(result, masterInstance(master, at, duration, allDay))
		}
	}
	for _, override := range overrides {
		if overlapsRange(override, start, end) {
			result = append(result, utcComponent(override))
		}
	}
	return result, nil
}

// recurrenceSet is the master's RRULE with its RDATE and EXDATE values.
// Unlike go-ical's RecurrenceSet it accepts the comma-separated value lists
// RFC 5545 allows (EXDATE:20250103T100000Z,20250105T100000Z).
func recurrenceSet(master *ical.Component) (*rrule.Set, error) {
	option, err := master.Props.RecurrenceRule()
	if err != nil {
		return nil, err
	}
	startProp := master.Props.Get(ical.PropDateTimeStart)
	if option == nil || startProp == nil {
		return nil, errNoStart
	}
	start, err := startProp.DateTime(time.UTC)
	if err != nil {
		return nil, err
	}
	rule, err := rrule.NewRRule(*option)
	if err != nil {
		return nil, err
	}
	set := &rrule.Set{}
	set.RRule(rule)
	set.DTStart(start)
	for _, name := range []string{ical.PropExceptionDates, ical.PropRecurrenceDates} {
		for _, prop := range master.Props[name] {
			for value := range strings.SplitSeq(prop.Value, ",") {
				single := prop
				single.Value = strings.TrimSpace(value)
				at, err := single.DateTime(time.UTC)
				if err != nil {
					return nil, err
				}
				if name == ical.PropExceptionDates {
					set.ExDate(at)
				} else {
					set.RDate(at)
				}
			}
		}
	}
	return set, nil
}

// componentSpan returns a component's start, its duration (DTEND, DUE, or
// DURATION; a day for an all-day event without an end), and whether it is
// an all-day (DATE-valued) component.
func componentSpan(component *ical.Component) (time.Time, time.Duration, bool, error) {
	startProp := component.Props.Get(ical.PropDateTimeStart)
	if startProp == nil {
		return time.Time{}, 0, false, errNoStart
	}
	start, err := startProp.DateTime(time.UTC)
	if err != nil {
		return time.Time{}, 0, false, err
	}
	allDay := startProp.ValueType() == ical.ValueDate || len(startProp.Value) == len("20060102")
	var finish time.Time
	if component.Name == ical.CompEvent {
		finish, err = (&ical.Event{Component: component}).DateTimeEnd(time.UTC)
		if err != nil {
			return time.Time{}, 0, false, err
		}
	} else if due := component.Props.Get(ical.PropDue); due != nil {
		if finish, err = due.DateTime(time.UTC); err != nil {
			return time.Time{}, 0, false, err
		}
	} else {
		finish = start
		if prop := component.Props.Get(ical.PropDuration); prop != nil {
			if duration, durationErr := prop.Duration(); durationErr == nil {
				finish = start.Add(duration)
			}
		}
	}
	if finish.Before(start) {
		finish = start
	}
	return start, finish.Sub(start), allDay, nil
}

var errNoStart = errors.New("component has no DTSTART")

// overlapsRange applies the RFC 4791 §9.9 overlap test to one component;
// a component without DTSTART overlaps every range.
func overlapsRange(component *ical.Component, start, end time.Time) bool {
	from, duration, _, err := componentSpan(component)
	if err != nil {
		return true
	}
	if duration == 0 {
		return !from.Before(start) && from.Before(end)
	}
	return from.Before(end) && from.Add(duration).After(start)
}

// masterInstance builds one instance of the recurring master starting at.
func masterInstance(master *ical.Component, at time.Time, duration time.Duration, allDay bool) *ical.Component {
	instance := ical.NewComponent(master.Name)
	for name, props := range master.Props {
		switch name {
		case ical.PropRecurrenceRule, ical.PropRecurrenceDates, ical.PropExceptionDates, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDue:
			continue
		}
		instance.Props[name] = append([]ical.Prop(nil), props...)
	}
	instance.Children = master.Children
	setInstanceTime(instance, ical.PropDateTimeStart, at, allDay)
	setInstanceTime(instance, ical.PropRecurrenceID, at, allDay)
	if master.Props.Get(ical.PropDuration) == nil {
		switch {
		case master.Props.Get(ical.PropDateTimeEnd) != nil:
			setInstanceTime(instance, ical.PropDateTimeEnd, at.Add(duration), allDay)
		case master.Props.Get(ical.PropDue) != nil:
			setInstanceTime(instance, ical.PropDue, at.Add(duration), allDay)
		}
	}
	return instance
}

func setInstanceTime(component *ical.Component, name string, at time.Time, allDay bool) {
	prop := ical.NewProp(name)
	if allDay {
		prop.SetDate(at)
	} else {
		prop.SetDateTime(at.UTC())
	}
	component.Props.Set(prop)
}

// utcComponent returns a copy of component with its date-times in UTC, so
// an expanded reply needs no VTIMEZONE.
func utcComponent(component *ical.Component) *ical.Component {
	copied := ical.NewComponent(component.Name)
	for name, props := range component.Props {
		copied.Props[name] = append([]ical.Prop(nil), props...)
	}
	copied.Children = component.Children
	for _, name := range []string{ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDue, ical.PropRecurrenceID} {
		prop := copied.Props.Get(name)
		if prop == nil || prop.ValueType() == ical.ValueDate || len(prop.Value) == len("20060102") || strings.HasSuffix(prop.Value, "Z") {
			continue
		}
		if at, err := prop.DateTime(time.UTC); err == nil {
			copied.Props.SetDateTime(name, at.UTC())
		}
	}
	return copied
}
