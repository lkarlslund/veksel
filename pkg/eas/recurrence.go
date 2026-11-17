package eas

import (
	"strconv"
	"strings"
	"time"
)

// EAS recurrence types (MS-ASCAL 2.2.2.38).
const (
	recurDaily          = "0"
	recurWeekly         = "1"
	recurMonthly        = "2"
	recurMonthlyNth     = "3"
	recurYearly         = "5"
	recurYearlyNth      = "6"
	dayOfWeekLastDay    = 127
	weekOfMonthLastWeek = 5
)

var weekdayCodes = []string{"SU", "MO", "TU", "WE", "TH", "FR", "SA"}

type recurrenceRule map[string]string

func parseRule(value string) recurrenceRule {
	rule := recurrenceRule{}
	for _, part := range strings.Split(value, ";") {
		key, val, ok := strings.Cut(part, "=")
		if ok {
			rule[strings.ToUpper(strings.TrimSpace(key))] = strings.ToUpper(strings.TrimSpace(val))
		}
	}
	return rule
}

// byDay splits BYDAY into an EAS weekday mask and an ordinal (0 when absent).
func byDay(value string) (mask int, ordinal int) {
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if len(entry) < 2 {
			continue
		}
		code := entry[len(entry)-2:]
		if prefix := entry[:len(entry)-2]; prefix != "" {
			ordinal, _ = strconv.Atoi(prefix)
		}
		for index, candidate := range weekdayCodes {
			if candidate == code {
				mask |= 1 << index
			}
		}
	}
	return mask, ordinal
}

// recurrenceNode maps an RRULE to EAS Recurrence on the given code page
// (4 calendar, 2 email meeting request, 9 tasks). localStart is the first
// occurrence in the event's own zone. Rules EAS cannot express (several
// month days, BYHOUR, ...) are approximated by their frequency.
func recurrenceNode(page byte, value string, localStart time.Time) *Node {
	rule := parseRule(value)
	kind := ""
	mask, ordinal := byDay(rule["BYDAY"])
	if position, err := strconv.Atoi(rule["BYSETPOS"]); err == nil && ordinal == 0 {
		ordinal = position
	}
	switch rule["FREQ"] {
	case "DAILY":
		kind = recurDaily
		if mask != 0 {
			kind = recurWeekly
		}
	case "WEEKLY":
		kind = recurWeekly
		if mask == 0 {
			mask = 1 << int(localStart.Weekday())
		}
	case "MONTHLY":
		kind = recurMonthly
		if mask != 0 && ordinal != 0 {
			kind = recurMonthlyNth
		}
	case "YEARLY":
		kind = recurYearly
		if mask != 0 && ordinal != 0 {
			kind = recurYearlyNth
		}
	default:
		return nil
	}
	node := E(page, "Recurrence", T(page, "Type", kind))
	add := func(tag, text string) { node.Children = append(node.Children, T(page, tag, text)) }
	if count := rule["COUNT"]; count != "" {
		add("Occurrences", count)
	}
	interval := rule["INTERVAL"]
	if interval == "" {
		interval = "1"
	}
	add("Interval", interval)
	week := ordinal
	if week < 0 || week > 4 {
		week = weekOfMonthLastWeek
	}
	switch kind {
	case recurWeekly:
		add("DayOfWeek", strconv.Itoa(mask))
	case recurMonthlyNth:
		add("WeekOfMonth", strconv.Itoa(week))
		add("DayOfWeek", strconv.Itoa(mask))
	case recurYearlyNth:
		add("WeekOfMonth", strconv.Itoa(week))
		add("DayOfWeek", strconv.Itoa(mask))
		add("MonthOfYear", monthOf(rule, localStart))
	case recurYearly:
		add("MonthOfYear", monthOf(rule, localStart))
	}
	if until := rule["UNTIL"]; until != "" {
		if parsed, ok := parseRuleUntil(until, localStart.Location()); ok {
			add("Until", compact(parsed))
		}
	}
	switch kind {
	case recurMonthly, recurYearly:
		day := rule["BYMONTHDAY"]
		if day == "" || strings.Contains(day, ",") {
			day = strconv.Itoa(localStart.Day())
		}
		if day == "-1" {
			day = "31"
		}
		add("DayOfMonth", day)
	}
	if page == 4 {
		add("CalendarType", "0")
		if first := rule["WKST"]; first != "" {
			for index, code := range weekdayCodes {
				if code == first {
					add("FirstDayOfWeek", strconv.Itoa(index))
				}
			}
		}
	}
	return node
}

func monthOf(rule recurrenceRule, localStart time.Time) string {
	if month := rule["BYMONTH"]; month != "" && !strings.Contains(month, ",") {
		return month
	}
	return strconv.Itoa(int(localStart.Month()))
}

func parseRuleUntil(value string, location *time.Location) (time.Time, bool) {
	if location == nil {
		location = time.UTC
	}
	for _, layout := range []string{"20060102T150405Z", "20060102T150405"} {
		if parsed, err := time.ParseInLocation(layout, value, location); err == nil {
			if strings.HasSuffix(value, "Z") {
				parsed, _ = time.Parse(layout, value)
			}
			return parsed, true
		}
	}
	if parsed, err := time.ParseInLocation("20060102", value, location); err == nil {
		return parsed.Add(24*time.Hour - time.Second), true
	}
	return time.Time{}, false
}

// ruleFromEAS maps EAS Recurrence back to an RRULE value.
func ruleFromEAS(recurrence *Node, allDay bool, tz easTimeZone) string {
	kind := childText(recurrence, "Type")
	parts := []string{}
	mask, _ := strconv.Atoi(childText(recurrence, "DayOfWeek"))
	days := func() string {
		var codes []string
		for index, code := range weekdayCodes {
			if mask&(1<<index) != 0 {
				codes = append(codes, code)
			}
		}
		return strings.Join(codes, ",")
	}
	week, _ := strconv.Atoi(childText(recurrence, "WeekOfMonth"))
	if week == weekOfMonthLastWeek {
		week = -1
	}
	switch kind {
	case recurDaily:
		parts = append(parts, "FREQ=DAILY")
		if mask != 0 && mask != dayOfWeekLastDay {
			parts = append(parts, "BYDAY="+days())
		}
	case recurWeekly:
		parts = append(parts, "FREQ=WEEKLY")
		if mask != 0 {
			parts = append(parts, "BYDAY="+days())
		}
	case recurMonthly:
		parts = append(parts, "FREQ=MONTHLY")
		if day := childText(recurrence, "DayOfMonth"); day != "" {
			parts = append(parts, "BYMONTHDAY="+day)
		}
	case recurMonthlyNth:
		parts = append(parts, "FREQ=MONTHLY")
		if mask == dayOfWeekLastDay {
			parts = append(parts, "BYMONTHDAY=-1")
		} else {
			parts = append(parts, "BYDAY="+days(), "BYSETPOS="+strconv.Itoa(week))
		}
	case recurYearly:
		parts = append(parts, "FREQ=YEARLY")
		if month := childText(recurrence, "MonthOfYear"); month != "" {
			parts = append(parts, "BYMONTH="+month)
		}
		if day := childText(recurrence, "DayOfMonth"); day != "" {
			parts = append(parts, "BYMONTHDAY="+day)
		}
	case recurYearlyNth:
		parts = append(parts, "FREQ=YEARLY")
		if month := childText(recurrence, "MonthOfYear"); month != "" {
			parts = append(parts, "BYMONTH="+month)
		}
		parts = append(parts, "BYDAY="+days(), "BYSETPOS="+strconv.Itoa(week))
	default:
		return ""
	}
	if interval, _ := strconv.Atoi(childText(recurrence, "Interval")); interval > 1 {
		parts = append(parts, "INTERVAL="+strconv.Itoa(interval))
	}
	if count, _ := strconv.Atoi(childText(recurrence, "Occurrences")); count > 0 {
		parts = append(parts, "COUNT="+strconv.Itoa(count))
	} else if until, ok := parseEASTime(childText(recurrence, "Until")); ok {
		if allDay {
			// UNTIL takes the DTSTART value type (RFC 5545 3.3.10).
			local := until.Add(time.Duration(tz.offset(until)) * time.Second)
			parts = append(parts, "UNTIL="+local.Format("20060102"))
		} else {
			parts = append(parts, "UNTIL="+until.UTC().Format("20060102T150405Z"))
		}
	}
	if first := childText(recurrence, "FirstDayOfWeek"); first != "" {
		if index, err := strconv.Atoi(first); err == nil && index >= 0 && index < 7 {
			parts = append(parts, "WKST="+weekdayCodes[index])
		}
	}
	return strings.Join(parts, ";")
}
