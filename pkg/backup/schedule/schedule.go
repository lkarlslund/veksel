// Package schedule parses and evaluates the wall-clock schedule of scheduled
// installation backups. It has no project dependencies so configuration
// validation and the backup scheduler share one definition.
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Default wall-clock time used by the "daily" and "weekly" shorthands.
const (
	defaultHour    = 3
	defaultWeekday = time.Sunday
)

// Schedule is a daily or weekly wall-clock slot. The zero value is disabled.
type Schedule struct {
	Enabled bool
	Weekly  bool
	Weekday time.Weekday
	Hour    int
	Minute  int
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "sunday": time.Sunday, "mon": time.Monday, "monday": time.Monday,
	"tue": time.Tuesday, "tuesday": time.Tuesday, "wed": time.Wednesday, "wednesday": time.Wednesday,
	"thu": time.Thursday, "thursday": time.Thursday, "fri": time.Friday, "friday": time.Friday,
	"sat": time.Saturday, "saturday": time.Saturday,
}

// Parse accepts, case-insensitively:
//
//	off | (empty)            disabled
//	daily | daily HH:MM | HH:MM
//	weekly | weekly DAY | weekly DAY HH:MM | DAY HH:MM
//
// DAY is a weekday name or its three-letter abbreviation. The shorthands run
// at 03:00, weekly on Sunday.
func Parse(value string) (Schedule, error) {
	fields := strings.Fields(strings.ToLower(value))
	if len(fields) == 0 || (len(fields) == 1 && fields[0] == "off") {
		return Schedule{}, nil
	}
	result := Schedule{Enabled: true, Weekday: defaultWeekday, Hour: defaultHour}
	switch fields[0] {
	case "daily":
		fields = fields[1:]
	case "weekly":
		result.Weekly = true
		fields = fields[1:]
		if len(fields) == 0 {
			return result, nil
		}
		fallthrough
	default:
		if day, ok := weekdays[fields[0]]; ok {
			result.Weekly, result.Weekday = true, day
			fields = fields[1:]
		}
	}
	switch len(fields) {
	case 0:
		return result, nil
	case 1:
		hour, minute, err := parseClock(fields[0])
		if err != nil {
			return Schedule{}, err
		}
		result.Hour, result.Minute = hour, minute
		return result, nil
	default:
		return Schedule{}, fmt.Errorf("invalid backup schedule %q: use off, daily, weekly, HH:MM, or DAY HH:MM", value)
	}
}

func parseClock(value string) (int, int, error) {
	hourText, minuteText, ok := strings.Cut(value, ":")
	hour, hourErr := strconv.Atoi(hourText)
	minute, minuteErr := strconv.Atoi(minuteText)
	if !ok || hourErr != nil || minuteErr != nil || len(minuteText) != 2 || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("invalid time of day %q: use HH:MM in 24-hour form", value)
	}
	return hour, minute, nil
}

// String renders the canonical form accepted by Parse.
func (s Schedule) String() string {
	switch {
	case !s.Enabled:
		return "off"
	case s.Weekly:
		return fmt.Sprintf("weekly %s %02d:%02d", strings.ToLower(s.Weekday.String()[:3]), s.Hour, s.Minute)
	default:
		return fmt.Sprintf("daily %02d:%02d", s.Hour, s.Minute)
	}
}

// Period is the nominal time between two slots.
func (s Schedule) Period() time.Duration {
	if s.Weekly {
		return 7 * 24 * time.Hour
	}
	return 24 * time.Hour
}

// Previous returns the latest slot at or before at, in at's location. A
// disabled schedule has no slots and returns the zero time.
func (s Schedule) Previous(at time.Time) time.Time {
	if !s.Enabled {
		return time.Time{}
	}
	slot := time.Date(at.Year(), at.Month(), at.Day(), s.Hour, s.Minute, 0, 0, at.Location())
	for slot.After(at) || (s.Weekly && slot.Weekday() != s.Weekday) {
		slot = slot.AddDate(0, 0, -1)
		slot = time.Date(slot.Year(), slot.Month(), slot.Day(), s.Hour, s.Minute, 0, 0, at.Location())
	}
	return slot
}

// Next returns the first slot strictly after after, in after's location.
func (s Schedule) Next(after time.Time) time.Time {
	if !s.Enabled {
		return time.Time{}
	}
	slot := time.Date(after.Year(), after.Month(), after.Day(), s.Hour, s.Minute, 0, 0, after.Location())
	for !slot.After(after) || (s.Weekly && slot.Weekday() != s.Weekday) {
		slot = slot.AddDate(0, 0, 1)
		slot = time.Date(slot.Year(), slot.Month(), slot.Day(), s.Hour, s.Minute, 0, 0, after.Location())
	}
	return slot
}

// Due reports whether a run should start at now: a slot has passed since the
// later of the last attempt and the baseline (when this schedule took
// effect). After downtime spanning several slots it is due exactly once,
// because the attempt it triggers moves past every missed slot.
func (s Schedule) Due(lastAttempt, baseline, now time.Time) bool {
	if !s.Enabled {
		return false
	}
	reference := lastAttempt
	if baseline.After(reference) {
		reference = baseline
	}
	return s.Previous(now).After(reference)
}

// NextRun is when the next run becomes due: now when one is already due,
// otherwise the first slot after the reference time.
func (s Schedule) NextRun(lastAttempt, baseline, now time.Time) time.Time {
	if !s.Enabled {
		return time.Time{}
	}
	if s.Due(lastAttempt, baseline, now) {
		return now
	}
	return s.Next(now)
}
