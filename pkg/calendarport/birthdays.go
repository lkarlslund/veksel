package calendarport

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendar"
)

// Birthday is a contact's date of birth. Year is zero when the vCard gives
// only month and day (BDAY:--0315).
type Birthday struct {
	ContactID string
	Name      string
	Year      int
	Month     time.Month
	Day       int
}

// ParseBirthday reads an RFC 6350 / RFC 2426 BDAY value: 19850315,
// 1985-03-15, --0315, --03-15, optionally followed by a time.
func ParseBirthday(value string) (year int, month time.Month, day int, ok bool) {
	value = strings.TrimSpace(value)
	if index := strings.IndexAny(value, "Tt"); index > 0 {
		value = value[:index]
	}
	value = strings.ReplaceAll(value, "-", "")
	if len(value) == 4 {
		value = "0000" + value // --MMDD
	}
	if len(value) != 8 {
		return 0, 0, 0, false
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, 0, 0, false
	}
	year, month, day = number/10000, time.Month(number/100%100), number%100
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return 0, 0, 0, false
	}
	if year != 0 && (year < 1800 || year > 9999) {
		year = 0
	}
	if day > daysIn(month, 2000) { // 2000 is a leap year, so 29 February is valid
		return 0, 0, 0, false
	}
	return year, month, day, true
}

func daysIn(month time.Month, year int) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// BirthdayEvents projects birthdays as all-day events in [start, end). A
// 29 February birthday falls on 28 February in common years.
func BirthdayEvents(birthdays []Birthday, start, end time.Time) []calendar.Occurrence {
	var result []calendar.Occurrence
	for _, birthday := range birthdays {
		for year := start.Year() - 1; year <= end.Year(); year++ {
			day := min(birthday.Day, daysIn(birthday.Month, year))
			date := time.Date(year, birthday.Month, day, 0, 0, 0, 0, start.Location())
			next := date.AddDate(0, 0, 1)
			if !date.Before(end) || !next.After(start) {
				continue
			}
			summary := birthday.Name + "’s birthday"
			if birthday.Year != 0 && year > birthday.Year {
				summary = fmt.Sprintf("%s (%d)", summary, year-birthday.Year)
			}
			event := calendar.Event{UID: "birthday-" + birthday.ContactID, Summary: summary, Start: date.Format(time.DateOnly), End: next.Format(time.DateOnly), AllDay: true, Recurrence: "yearly", Transparent: true, Categories: []string{"Birthday"}}
			result = append(result, calendar.Occurrence{Event: event, RecurrenceID: date.Format(time.DateOnly)})
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Start < result[j].Start })
	return result
}
