package caldav

import (
	"bufio"
	"fmt"
	"slices"
	"strings"
	"time"
)

// RRule represents a parsed iCalendar RRULE property (RFC 5545).
type RRule struct {
	Freq       RecurFreq // Required: DAILY, WEEKLY, MONTHLY, YEARLY
	Interval   int       // Default 1
	Count      *int      // Optional: number of occurrences
	Until      time.Time // Optional: end of recurrence
	ByDay      []string  // e.g. ["MO", "WE", "FR"]
	ByMonthDay []int     // e.g. [1, 15]
	ByMonth    []int     // e.g. [6, 12]
	ByWeekNo   []int     // e.g. [1, 2]
}

// RecurFreq is the frequency of recurrence.
type RecurFreq int

const (
	FreqDaily RecurFreq = iota + 1
	FreqWeekly
	FreqMonthly
	FreqYearly
)

// parseRRule parses an RRULE value string into an RRule struct.
// Format: FREQ=DAILY;INTERVAL=2;COUNT=10
func parseRRule(value string) (*RRule, error) {
	r := &RRule{Interval: 1}
	pairs := strings.Split(value, ";")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToUpper(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "FREQ":
			switch val {
			case "DAILY":
				r.Freq = FreqDaily
			case "WEEKLY":
				r.Freq = FreqWeekly
			case "MONTHLY":
				r.Freq = FreqMonthly
			case "YEARLY":
				r.Freq = FreqYearly
			default:
				return nil, fmt.Errorf("unknown RRULE FREQ: %s", val)
			}
		case "INTERVAL":
			fmt.Sscanf(val, "%d", &r.Interval)
			if r.Interval < 1 {
				r.Interval = 1
			}
		case "COUNT":
			var count int
			fmt.Sscanf(val, "%d", &count)
			if count > 0 {
				r.Count = &count
			}
		case "UNTIL":
			t, err := parseCalDAVTime(val)
			if err == nil {
				r.Until = t
			}
		case "BYDAY":
			// One entry per weekday is enough: entries naming the same day
			// expand to the same occurrences, and an unbounded list would
			// multiply every expanded week.
			seen := make(map[int]bool)
			for _, day := range strings.Split(val, ",") {
				if weekday := parseDayOfWeek(day); !seen[weekday] {
					seen[weekday] = true
					r.ByDay = append(r.ByDay, day)
				}
			}
		case "BYMONTHDAY":
			for _, s := range strings.Split(val, ",") {
				var d int
				fmt.Sscanf(strings.TrimSpace(s), "%d", &d)
				if d != 0 && d >= -31 && d <= 31 && !slices.Contains(r.ByMonthDay, d) {
					r.ByMonthDay = append(r.ByMonthDay, d)
				}
			}
		case "BYMONTH":
			for _, s := range strings.Split(val, ",") {
				var m int
				fmt.Sscanf(strings.TrimSpace(s), "%d", &m)
				if m > 0 && m <= 12 && !slices.Contains(r.ByMonth, m) {
					r.ByMonth = append(r.ByMonth, m)
				}
			}
		case "BYWEEKNO":
			for _, s := range strings.Split(val, ",") {
				var w int
				fmt.Sscanf(strings.TrimSpace(s), "%d", &w)
				if w != 0 && w >= -53 && w <= 53 && !slices.Contains(r.ByWeekNo, w) {
					r.ByWeekNo = append(r.ByWeekNo, w)
				}
			}
		}
	}
	if r.Freq == 0 {
		return nil, fmt.Errorf("RRULE must have FREQ")
	}
	return r, nil
}

// expandRecurrence generates occurrence times for a recurring event within the
// given query range. It returns a slice of time.Time representing each occurrence
// start time that falls within [rangeStart, rangeEnd].
//
// dtStart is the original event start time.
// duration is the event duration (DTEND - DTSTART), used for clamping.
// exDates are exception dates to exclude.
// rDates are additional recurrence dates to include.
func expandRecurrence(rrule *RRule, dtStart time.Time, duration time.Duration, rangeStart, rangeEnd time.Time, exDates map[time.Time]struct{}, rDates []time.Time) []time.Time {
	if rrule == nil {
		return nil
	}

	// Limit to prevent infinite loops on malformed rules
	maxIterations := 10000

	// Determine the effective end for expansion
	expandEnd := rangeEnd

	// If UNTIL is set and before rangeEnd, use UNTIL
	if !rrule.Until.IsZero() && rrule.Until.Before(rangeEnd) {
		expandEnd = rrule.Until
	}

	// Generate occurrences based on frequency
	var occurrences []time.Time
	switch rrule.Freq {
	case FreqDaily:
		occurrences = expandDaily(rrule, dtStart, rangeStart, expandEnd, maxIterations)
	case FreqWeekly:
		occurrences = expandWeekly(rrule, dtStart, rangeStart, expandEnd, maxIterations)
	case FreqMonthly:
		occurrences = expandMonthly(rrule, dtStart, rangeStart, expandEnd, maxIterations)
	case FreqYearly:
		occurrences = expandYearly(rrule, dtStart, rangeStart, expandEnd, maxIterations)
	}

	// Apply COUNT limit. Like the range expansion above, at most
	// maxIterations periods are generated: COUNT comes from the client and
	// must not size allocations or loops.
	if rrule.Count != nil {
		count := min(*rrule.Count, maxIterations)
		// For MONTHLY with BYMONTHDAY or YEARLY with BYMONTH, COUNT applies to
		// the number of periods (months/years), not individual occurrences.
		// Generate the base periods and expand with BY* rules.
		switch rrule.Freq {
		case FreqMonthly:
			if len(rrule.ByMonthDay) > 0 {
				// COUNT = number of months, each month produces BYMONTHDAY occurrences
				counted := make([]time.Time, 0)
				for i := 0; i < count; i++ {
					baseMonth := dtStart.AddDate(0, i*rrule.Interval, 0)
					for _, md := range rrule.ByMonthDay {
						monthLen := daysInMonth(baseMonth.Year(), baseMonth.Month())
						if md > monthLen {
							md = monthLen
						}
						candidate := time.Date(baseMonth.Year(), baseMonth.Month(), md,
							dtStart.Hour(), dtStart.Minute(), dtStart.Second(), 0, dtStart.Location())
						counted = append(counted, candidate)
					}
				}
				// Filter to range
				countedInRange := make([]time.Time, 0)
				for _, o := range counted {
					if !o.Before(rangeStart) && !o.After(rangeEnd) {
						countedInRange = append(countedInRange, o)
					}
				}
				occurrences = countedInRange
			} else {
				// Simple monthly: COUNT = number of occurrences
				// Clamp day to month length (handles Feb 29 -> Feb 28)
				counted := make([]time.Time, 0, count)
				for i := 0; i < count; i++ {
					baseMonth := dtStart.AddDate(0, i*rrule.Interval, 0)
					monthLen := daysInMonth(baseMonth.Year(), baseMonth.Month())
					clampedDay := dtStart.Day()
					if clampedDay > monthLen {
						clampedDay = monthLen
					}
					candidate := time.Date(baseMonth.Year(), baseMonth.Month(), clampedDay,
						dtStart.Hour(), dtStart.Minute(), dtStart.Second(), 0, dtStart.Location())
					counted = append(counted, candidate)
				}
				countedInRange := make([]time.Time, 0)
				for _, o := range counted {
					if !o.Before(rangeStart) && !o.After(rangeEnd) {
						countedInRange = append(countedInRange, o)
					}
				}
				occurrences = countedInRange
			}
		case FreqYearly:
			if len(rrule.ByMonth) > 0 {
				// COUNT = number of years, each year produces BYMONTH occurrences
				counted := make([]time.Time, 0)
				for i := 0; i < count; i++ {
					baseYear := dtStart.AddDate(i*rrule.Interval, 0, 0)
					for _, m := range rrule.ByMonth {
						day := dtStart.Day()
						if m == 2 && day > 28 && !isLeapYear(baseYear.Year()) {
							day = 28
						}
						candidate := time.Date(baseYear.Year(), time.Month(m), day,
							dtStart.Hour(), dtStart.Minute(), dtStart.Second(), 0, dtStart.Location())
						counted = append(counted, candidate)
					}
				}
				countedInRange := make([]time.Time, 0)
				for _, o := range counted {
					if !o.Before(rangeStart) && !o.After(rangeEnd) {
						countedInRange = append(countedInRange, o)
					}
				}
				occurrences = countedInRange
			} else {
				counted := make([]time.Time, 0, count)
				for i := 0; i < count; i++ {
					candidate := dtStart.AddDate(i*rrule.Interval, 0, 0)
					counted = append(counted, candidate)
				}
				countedInRange := make([]time.Time, 0)
				for _, o := range counted {
					if !o.Before(rangeStart) && !o.After(rangeEnd) {
						countedInRange = append(countedInRange, o)
					}
				}
				occurrences = countedInRange
			}
		case FreqDaily:
			counted := make([]time.Time, 0, count)
			for i := 0; i < count; i++ {
				candidate := dtStart.AddDate(0, 0, i*rrule.Interval)
				counted = append(counted, candidate)
			}
			countedInRange := make([]time.Time, 0)
			for _, o := range counted {
				if !o.Before(rangeStart) && !o.After(rangeEnd) {
					countedInRange = append(countedInRange, o)
				}
			}
			occurrences = countedInRange
		case FreqWeekly:
			counted := make([]time.Time, 0, count)
			for i := 0; i < count; i++ {
				candidate := dtStart.AddDate(0, 0, i*rrule.Interval*7)
				counted = append(counted, candidate)
			}
			countedInRange := make([]time.Time, 0)
			for _, o := range counted {
				if !o.Before(rangeStart) && !o.After(rangeEnd) {
					countedInRange = append(countedInRange, o)
				}
			}
			occurrences = countedInRange
		}
	}

	// Filter out occurrences past expandEnd (for UNTIL)
	if !rrule.Until.IsZero() {
		filtered := make([]time.Time, 0, len(occurrences))
		for _, o := range occurrences {
			if !o.After(rrule.Until) {
				filtered = append(filtered, o)
			}
		}
		occurrences = filtered
	}

	// Filter to range
	filtered := make([]time.Time, 0, len(occurrences))
	for _, o := range occurrences {
		if !o.Before(rangeStart) && !o.After(rangeEnd) {
			filtered = append(filtered, o)
		}
	}
	occurrences = filtered

	// Remove exdates
	if len(exDates) > 0 {
		filtered := make([]time.Time, 0, len(occurrences))
		for _, o := range occurrences {
			if _, excluded := exDates[o]; !excluded {
				// Also check date-only match for all-day events
				dateKey := time.Date(o.Year(), o.Month(), o.Day(), 0, 0, 0, 0, o.Location())
				if _, excluded := exDates[dateKey]; !excluded {
					filtered = append(filtered, o)
				}
			}
		}
		occurrences = filtered
	}

	// Add RDATEs that fall within the range
	for _, rd := range rDates {
		if !rd.Before(rangeStart) && !rd.After(rangeEnd) {
			occurrences = append(occurrences, rd)
		}
	}

	return occurrences
}

func expandDaily(r *RRule, dtStart, rangeStart, rangeEnd time.Time, maxIter int) []time.Time {
	if dtStart.After(rangeEnd) {
		return nil
	}

	// Calculate starting point
	start := dtStart
	if start.Before(rangeStart) {
		// Skip ahead to the range
		days := int(rangeStart.Sub(start).Hours()/24) / r.Interval
		if days > 0 {
			start = start.AddDate(0, 0, days*r.Interval)
			// Make sure we didn't skip past rangeStart
			if start.Before(rangeStart) {
				start = start.AddDate(0, 0, r.Interval)
			}
		}
	}

	occurrences := make([]time.Time, 0)
	iter := 0
	for !start.After(rangeEnd) && iter < maxIter {
		if !start.Before(rangeStart) {
			occurrences = append(occurrences, start)
		}
		start = start.AddDate(0, 0, r.Interval)
		iter++
	}
	return occurrences
}

func expandWeekly(r *RRule, dtStart, rangeStart, rangeEnd time.Time, maxIter int) []time.Time {
	if dtStart.After(rangeEnd) {
		return nil
	}

	start := dtStart
	if start.Before(rangeStart) {
		weeks := int(rangeStart.Sub(start).Hours()/(24*7)) / r.Interval
		if weeks > 0 {
			start = start.AddDate(0, 0, weeks*r.Interval*7)
			if start.Before(rangeStart) {
				start = start.AddDate(0, 0, r.Interval*7)
			}
		}
	}

	occurrences := make([]time.Time, 0)
	iter := 0
	for !start.After(rangeEnd) && iter < maxIter {
		if !start.Before(rangeStart) {
			// Apply BYDAY filtering if present
			if len(r.ByDay) > 0 {
				occurrences = append(occurrences, applyByDay(start, r.ByDay)...)
			} else {
				occurrences = append(occurrences, start)
			}
		}
		start = start.AddDate(0, 0, r.Interval*7)
		iter++
	}
	return occurrences
}

func expandMonthly(r *RRule, dtStart, rangeStart, rangeEnd time.Time, maxIter int) []time.Time {
	if dtStart.After(rangeEnd) {
		return nil
	}

	// Start from the month of dtStart
	startMonth := dtStart
	if dtStart.Before(rangeStart) {
		// Calculate months to skip
		months := (rangeStart.Year()-dtStart.Year())*12 + int(rangeStart.Month()-dtStart.Month())
		if months > 0 {
			months = (months / r.Interval) * r.Interval
			startMonth = dtStart.AddDate(0, months, 0)
			if startMonth.Before(rangeStart) {
				startMonth = startMonth.AddDate(0, r.Interval, 0)
			}
		}
	}

	day := dtStart.Day()
	occurrences := make([]time.Time, 0)
	iter := 0
	for !startMonth.After(rangeEnd) && iter < maxIter {
		if !startMonth.Before(rangeStart) {
			// Apply BYMONTHDAY if present
			if len(r.ByMonthDay) > 0 {
				for _, md := range r.ByMonthDay {
					// Clamp day to month length
					monthLen := daysInMonth(startMonth.Year(), startMonth.Month())
					if md > monthLen {
						md = monthLen
					}
					candidate := time.Date(startMonth.Year(), startMonth.Month(), md,
						dtStart.Hour(), dtStart.Minute(), dtStart.Second(), 0, dtStart.Location())
					if !candidate.Before(rangeStart) && !candidate.After(rangeEnd) {
						occurrences = append(occurrences, candidate)
					}
				}
			} else {
				// Clamp day to month length (handles Feb 29 -> Feb 28)
				monthLen := daysInMonth(startMonth.Year(), startMonth.Month())
				clampedDay := day
				if clampedDay > monthLen {
					clampedDay = monthLen
				}
				candidate := time.Date(startMonth.Year(), startMonth.Month(), clampedDay,
					dtStart.Hour(), dtStart.Minute(), dtStart.Second(), 0, dtStart.Location())
				if !candidate.Before(rangeStart) && !candidate.After(rangeEnd) {
					occurrences = append(occurrences, candidate)
				}
			}
		}
		startMonth = startMonth.AddDate(0, r.Interval, 0)
		iter++
	}
	return occurrences
}

func expandYearly(r *RRule, dtStart, rangeStart, rangeEnd time.Time, maxIter int) []time.Time {
	if dtStart.After(rangeEnd) {
		return nil
	}

	startYear := dtStart
	if dtStart.Before(rangeStart) {
		years := rangeStart.Year() - dtStart.Year()
		if years > 0 {
			years = (years / r.Interval) * r.Interval
			startYear = dtStart.AddDate(years, 0, 0)
			if startYear.Before(rangeStart) {
				startYear = startYear.AddDate(r.Interval, 0, 0)
			}
		}
	}

	occurrences := make([]time.Time, 0)
	iter := 0
	for !startYear.After(rangeEnd) && iter < maxIter {
		if !startYear.Before(rangeStart) {
			// Apply BYMONTH if present
			months := r.ByMonth
			if len(months) == 0 {
				months = []int{int(dtStart.Month())}
			}
			for _, m := range months {
				// Handle Feb 29 on non-leap years
				day := dtStart.Day()
				if m == 2 && day > 28 {
					if !isLeapYear(startYear.Year()) {
						day = 28
					}
				}
				candidate := time.Date(startYear.Year(), time.Month(m), day,
					dtStart.Hour(), dtStart.Minute(), dtStart.Second(), 0, dtStart.Location())
				if !candidate.Before(rangeStart) && !candidate.After(rangeEnd) {
					occurrences = append(occurrences, candidate)
				}
			}
		}
		startYear = startYear.AddDate(r.Interval, 0, 0)
		iter++
	}
	return occurrences
}

// applyByDay generates occurrences for each BYDAY value within the week starting at weekStart.
func applyByDay(weekStart time.Time, byDays []string) []time.Time {
	var results []time.Time
	for _, bd := range byDays {
		dayOfWeek := parseDayOfWeek(bd)
		if dayOfWeek < 0 {
			continue
		}
		// Find the target day in this week
		currentDow := int(weekStart.Weekday())
		diff := dayOfWeek - currentDow
		if diff < 0 {
			diff += 7
		}
		occurrence := weekStart.AddDate(0, 0, diff)
		results = append(results, occurrence)
	}
	return results
}

// parseDayOfWeek parses a BYDAY value like "MO", "TU", "WE", "TH", "FR", "SA", "SU".
// Returns 0=Sunday through 6=Saturday, or -1 on error.
func parseDayOfWeek(s string) int {
	s = strings.ToUpper(strings.TrimSpace(s))
	// Handle nth occurrence like "2MO" (second Monday) — just use the day part
	if len(s) >= 2 {
		dayPart := s[len(s)-2:]
		switch dayPart {
		case "MO":
			return 1
		case "TU":
			return 2
		case "WE":
			return 3
		case "TH":
			return 4
		case "FR":
			return 5
		case "SA":
			return 6
		case "SU":
			return 0
		}
	}
	return -1
}

func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func isLeapYear(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

// --- Extraction helpers for recurrence properties ---

// extractRRule extracts the RRULE property from iCalendar data.
func extractRRule(data []byte) string {
	scanner := bufio.NewScanner(bytesReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "RRULE:") {
			idx := strings.Index(line, ":")
			if idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

// extractRDateTimes extracts all RDATE properties from iCalendar data.
func extractRDateTimes(data []byte) []time.Time {
	scanner := bufio.NewScanner(bytesReader(data))
	var dates []time.Time
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "RDATE:") {
			idx := strings.Index(line, ":")
			if idx < 0 {
				continue
			}
			val := strings.TrimSpace(line[idx+1:])
			// RDATE can contain comma-separated values
			for _, s := range strings.Split(val, ",") {
				s = strings.TrimSpace(s)
				if t, err := parseCalDAVTime(s); err == nil {
					dates = append(dates, t)
				}
			}
		}
	}
	return dates
}

// extractExDateMap extracts all EXDATE properties from iCalendar data
// and returns them as a map for fast lookup.
func extractExDateMap(data []byte) map[time.Time]struct{} {
	scanner := bufio.NewScanner(bytesReader(data))
	exDates := make(map[time.Time]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "EXDATE:") {
			idx := strings.Index(line, ":")
			if idx < 0 {
				continue
			}
			val := strings.TrimSpace(line[idx+1:])
			// EXDATE can contain comma-separated values
			for _, s := range strings.Split(val, ",") {
				s = strings.TrimSpace(s)
				if t, err := parseCalDAVTime(s); err == nil {
					exDates[t] = struct{}{}
					// Also add date-only key for all-day matching
					dateKey := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
					exDates[dateKey] = struct{}{}
				}
			}
		}
	}
	return exDates
}

// hasRecurrence checks if the event data contains RRULE or RDATE properties.
func hasRecurrence(data []byte) bool {
	return extractRRule(data) != "" || len(extractRDateTimes(data)) > 0
}

// getEventOccurrences returns all occurrence start times for an event within
// the given time range. For non-recurring events, it returns the single DTSTART
// if it falls within the range. For recurring events, it expands the recurrence.
func getEventOccurrences(data []byte, rangeStart, rangeEnd time.Time) []time.Time {
	dtStart := extractDTStart(data)
	dtEnd := extractDTEnd(data)

	if dtStart.IsZero() {
		// No start time — can't expand
		return nil
	}

	// Check for recurrence
	rruleStr := extractRRule(data)
	if rruleStr == "" {
		// Non-recurring event — check if it falls in range
		if !dtStart.Before(rangeStart) && !dtStart.After(rangeEnd) {
			return []time.Time{dtStart}
		}
		// Also check if event overlaps the range (event spans into range)
		if dtEnd.IsZero() {
			dtEnd = dtStart
		}
		if !dtStart.After(rangeEnd) && !dtEnd.Before(rangeStart) {
			return []time.Time{dtStart}
		}
		return nil
	}

	// Parse RRULE
	rrule, err := parseRRule(rruleStr)
	if err != nil {
		// If we can't parse the rule, fall back to the base event
		if !dtStart.Before(rangeStart) && !dtStart.After(rangeEnd) {
			return []time.Time{dtStart}
		}
		return nil
	}

	// Calculate event duration
	duration := time.Duration(0)
	if !dtEnd.IsZero() {
		duration = dtEnd.Sub(dtStart)
	}

	// Extract EXDATEs and RDATEs
	exDates := extractExDateMap(data)
	rDates := extractRDateTimes(data)

	occurrences := expandRecurrence(rrule, dtStart, duration, rangeStart, rangeEnd, exDates, rDates)

	// If no occurrences from RRULE but we have RDATEs in range, return those
	if len(occurrences) == 0 && len(rDates) > 0 {
		for _, rd := range rDates {
			if !rd.Before(rangeStart) && !rd.After(rangeEnd) {
				occurrences = append(occurrences, rd)
			}
		}
	}

	return occurrences
}

// generateOccurrenceICal creates an iCalendar VEVENT for a specific occurrence
// of a recurring event. It modifies DTSTART/DTEND to the occurrence time and
// adds the RECURRENCE-ID property.
func generateOccurrenceICal(originalData []byte, occurrenceTime time.Time) []byte {
	return generateOccurrenceICalWithTZ(originalData, occurrenceTime, "")
}

// generateOccurrenceICalWithTZ creates an iCalendar VEVENT for a specific occurrence
// with timezone-aware DTSTART/DTEND. If tzID is non-empty, the times are formatted
// with the TZID parameter instead of UTC.
func generateOccurrenceICalWithTZ(originalData []byte, occurrenceTime time.Time, tzID string) []byte {
	// Parse the original event and replace DTSTART/DTEND
	lines := splitICalLines(originalData)
	var result []string
	inVEVENT := false
	replacedStart := false
	replacedEnd := false

	// Check if original is all-day
	isAllDay := extractIsAllDay(originalData)

	// Format occurrence time
	var occurrenceStr string
	var recurrenceIDPrefix string
	if isAllDay {
		occurrenceStr = occurrenceTime.UTC().Format("20060102")
		recurrenceIDPrefix = "RECURRENCE-ID;VALUE=DATE:"
	} else if tzID != "" {
		occurrenceStr = occurrenceTime.Format("20060102T150405")
		recurrenceIDPrefix = "RECURRENCE-ID;TZID=" + tzID + ":"
	} else {
		occurrenceStr = occurrenceTime.UTC().Format("20060102T150405Z")
		recurrenceIDPrefix = "RECURRENCE-ID:"
	}

	// Extract original DTSTART prefix (with TZID parameter if present)
	var origDTStartPrefix string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "DTSTART") {
			colonIdx := strings.Index(trimmed, ":")
			if colonIdx >= 0 {
				origDTStartPrefix = trimmed[:colonIdx+1]
			}
			break
		}
	}

	// Extract original DTEND prefix
	var origDTEndPrefix string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "DTEND") {
			colonIdx := strings.Index(trimmed, ":")
			if colonIdx >= 0 {
				origDTEndPrefix = trimmed[:colonIdx+1]
			}
			break
		}
	}

	// Get original times for duration calculation
	origStart, origStartTZID := extractDTStartWithTZ(originalData)
	origEnd, _ := extractDTEndWithTZ(originalData)

	for _, line := range lines {
		upper := strings.ToUpper(strings.TrimSpace(line))
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(upper, "BEGIN:VEVENT") {
			inVEVENT = true
			result = append(result, line)
			continue
		}
		if strings.HasPrefix(upper, "END:VEVENT") {
			// Add RECURRENCE-ID before END:VEVENT
			recurrenceID := recurrenceIDPrefix + occurrenceStr
			result = append(result, recurrenceID)
			result = append(result, line)
			inVEVENT = false
			continue
		}

		if inVEVENT {
			if !replacedStart && strings.HasPrefix(upper, "DTSTART") {
				// Build the new DTSTART line
				var newLine string
				if tzID != "" {
					newLine = fmt.Sprintf("DTSTART;TZID=%s:%s", tzID, occurrenceStr)
				} else if origDTStartPrefix != "" {
					// Preserve original prefix (e.g., DTSTART;VALUE=DATE:)
					newLine = origDTStartPrefix + occurrenceStr
				} else {
					colonIdx := strings.Index(trimmed, ":")
					if colonIdx >= 0 {
						newLine = trimmed[:colonIdx+1] + occurrenceStr
					} else {
						newLine = line
					}
				}
				result = append(result, newLine)
				replacedStart = true
				continue
			}
			if !replacedEnd && strings.HasPrefix(upper, "DTEND") {
				// Calculate new DTEND based on original duration
				var duration time.Duration
				if !origStart.IsZero() && !origEnd.IsZero() {
					duration = origEnd.Sub(origStart)
				}
				newEnd := occurrenceTime.Add(duration)
				var endStr string
				if isAllDay {
					endStr = newEnd.UTC().Format("20060102")
				} else if tzID != "" {
					endStr = newEnd.Format("20060102T150405")
				} else {
					endStr = newEnd.UTC().Format("20060102T150405Z")
				}

				var newLine string
				if tzID != "" && origStartTZID != "" {
					newLine = fmt.Sprintf("DTEND;TZID=%s:%s", tzID, endStr)
				} else if origDTEndPrefix != "" {
					newLine = origDTEndPrefix + endStr
				} else {
					colonIdx := strings.Index(trimmed, ":")
					if colonIdx >= 0 {
						newLine = trimmed[:colonIdx+1] + endStr
					} else {
						newLine = line
					}
				}
				result = append(result, newLine)
				replacedEnd = true
				continue
			}
		}

		result = append(result, line)
	}

	return []byte(strings.Join(result, "\r\n") + "\r\n")
}

// splitICalLines splits iCalendar data into lines, handling line folding (RFC 5545).
func splitICalLines(data []byte) []string {
	text := string(data)
	// Unfold lines (lines starting with space or tab are continuations)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	var unfolded []string
	var current strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			current.WriteString(line[1:])
		} else {
			if current.Len() > 0 {
				unfolded = append(unfolded, current.String())
			}
			current.Reset()
			current.WriteString(line)
		}
	}
	if current.Len() > 0 {
		unfolded = append(unfolded, current.String())
	}

	return unfolded
}

// bytesReader returns a strings.Reader for the given bytes.
func bytesReader(b []byte) *strings.Reader {
	return strings.NewReader(string(b))
}
