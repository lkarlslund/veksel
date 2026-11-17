package calendar

import (
	"fmt"
	"time"

	"github.com/emersion/go-ical"
)

// TimezoneComponent builds a VTIMEZONE for an IANA zone from the Go time
// zone database: one observance per offset change in year, each with the
// yearly rule (for example last Sunday of March) when the following year
// repeats it. RFC 5545 requires one for every TZID a document references.
func TimezoneComponent(tzid string, year int) (*ical.Component, bool) {
	if tzid == "" || tzid == "Local" || tzid == "UTC" {
		return nil, false
	}
	loc, err := time.LoadLocation(tzid)
	if err != nil {
		return nil, false
	}
	component := ical.NewComponent(ical.CompTimezone)
	component.Props.SetText(ical.PropTimezoneID, tzid)
	transitions := zoneTransitions(loc, year)
	if len(transitions) == 0 {
		name, offset := time.Date(year, time.January, 1, 0, 0, 0, 0, loc).Zone()
		component.Children = append(component.Children, observance(ical.CompTimezoneStandard, "19700101T000000", offset, offset, name, ""))
		return component, true
	}
	for _, transition := range transitions {
		kind := ical.CompTimezoneStandard
		if transition.at.In(loc).IsDST() {
			kind = ical.CompTimezoneDaylight
		}
		wall := transition.at.Add(time.Duration(transition.from) * time.Second).UTC()
		rule := ""
		if repeatsNextYear(loc, wall, transition) {
			rule = fmt.Sprintf("FREQ=YEARLY;BYMONTH=%d;BYDAY=%s", int(wall.Month()), weekdayOrdinal(wall))
		}
		name, _ := transition.at.In(loc).Zone()
		component.Children = append(component.Children, observance(kind, wall.Format("20060102T150405"), transition.from, transition.to, name, rule))
	}
	return component, true
}

// AddMissingTimezones appends a VTIMEZONE for every TZID the calendar's
// components reference without defining, so readers that do not know IANA
// names still place the times correctly.
func AddMissingTimezones(cal *ical.Calendar) {
	defined := map[string]bool{}
	for _, child := range cal.Children {
		if child.Name == ical.CompTimezone {
			if tzid, err := child.Props.Text(ical.PropTimezoneID); err == nil {
				defined[tzid] = true
			}
		}
	}
	year := time.Now().Year()
	var added []*ical.Component
	var visit func(components []*ical.Component)
	visit = func(components []*ical.Component) {
		for _, component := range components {
			if component.Name == ical.CompTimezone {
				continue
			}
			for _, values := range component.Props {
				for _, prop := range values {
					tzid := prop.Params.Get(ical.PropTimezoneID)
					if tzid == "" || defined[tzid] {
						continue
					}
					defined[tzid] = true
					if timezone, ok := TimezoneComponent(tzid, year); ok {
						added = append(added, timezone)
					}
				}
			}
			visit(component.Children)
		}
	}
	visit(cal.Children)
	// Time zones lead the document so readers see them first.
	cal.Children = append(added, cal.Children...)
}

// ZoneChange is one offset change of a time zone: at the instant At the
// UTC offset changes From seconds To seconds east of UTC.
type ZoneChange struct {
	At       time.Time
	From, To int
}

// ZoneChanges lists the instants in year when loc changes offset, for
// protocols that describe zones as yearly transition rules.
func ZoneChanges(loc *time.Location, year int) []ZoneChange {
	transitions := zoneTransitions(loc, year)
	changes := make([]ZoneChange, 0, len(transitions))
	for _, transition := range transitions {
		changes = append(changes, ZoneChange{At: transition.at, From: transition.from, To: transition.to})
	}
	return changes
}

type zoneTransition struct {
	at       time.Time
	from, to int
}

// zoneTransitions finds the instants in year when loc changes offset.
func zoneTransitions(loc *time.Location, year int) []zoneTransition {
	var result []zoneTransition
	day := time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC)
	end := day.AddDate(1, 0, 0)
	_, previous := day.In(loc).Zone()
	for day.Before(end) {
		next := day.Add(24 * time.Hour)
		if _, offset := next.In(loc).Zone(); offset != previous {
			low, high := day, next
			for high.Sub(low) > time.Second {
				middle := low.Add(high.Sub(low) / 2)
				if _, value := middle.In(loc).Zone(); value == previous {
					low = middle
				} else {
					high = middle
				}
			}
			result = append(result, zoneTransition{at: high, from: previous, to: offset})
			previous = offset
		}
		day = next
	}
	return result
}

// repeatsNextYear reports whether the same weekday rule changes the offset
// the same way one year later.
func repeatsNextYear(loc *time.Location, wall time.Time, transition zoneTransition) bool {
	for _, candidate := range zoneTransitions(loc, wall.Year()+1) {
		next := candidate.at.Add(time.Duration(candidate.from) * time.Second).UTC()
		if candidate.from == transition.from && candidate.to == transition.to && next.Month() == wall.Month() &&
			next.Weekday() == wall.Weekday() && weekdayOrdinal(next) == weekdayOrdinal(wall) && next.Hour() == wall.Hour() && next.Minute() == wall.Minute() {
			return true
		}
	}
	return false
}

// weekdayOrdinal names the date's weekday within its month as an RRULE
// BYDAY value: -1SU for the last Sunday, 2SU for the second.
func weekdayOrdinal(date time.Time) string {
	days := [...]string{"SU", "MO", "TU", "WE", "TH", "FR", "SA"}
	lastDay := time.Date(date.Year(), date.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if date.Day()+7 > lastDay {
		return "-1" + days[date.Weekday()]
	}
	return fmt.Sprintf("%d%s", (date.Day()-1)/7+1, days[date.Weekday()])
}

func observance(kind, start string, from, to int, name, rule string) *ical.Component {
	component := ical.NewComponent(kind)
	set := func(name, value string) {
		prop := ical.NewProp(name)
		prop.Value = value
		component.Props.Set(prop)
	}
	set(ical.PropDateTimeStart, start)
	set(ical.PropTimezoneOffsetFrom, utcOffset(from))
	set(ical.PropTimezoneOffsetTo, utcOffset(to))
	if name != "" {
		set(ical.PropTimezoneName, name)
	}
	if rule != "" {
		set(ical.PropRecurrenceRule, rule)
	}
	return component
}

func utcOffset(seconds int) string {
	sign := '+'
	if seconds < 0 {
		sign, seconds = '-', -seconds
	}
	return fmt.Sprintf("%c%02d%02d", sign, seconds/3600, seconds/60%60)
}
