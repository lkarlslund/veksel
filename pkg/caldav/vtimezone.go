package caldav

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
)

// VTimezone represents a parsed VTIMEZONE component (RFC 5545).
type VTimezone struct {
	TzID     string
	Daylight []tzSubcomponent
	Standard []tzSubcomponent
}

// tzSubcomponent represents a DAYLIGHT or STANDARD sub-component within VTIMEZONE.
type tzSubcomponent struct {
	Name         string // "DAYLIGHT" or "STANDARD"
	DtStart      time.Time
	TzOffsetFrom time.Duration // e.g. -0500 = -5h
	TzOffsetTo   time.Duration // e.g. -0400 = -4h
	RRule        *RRule
}

// parseVTimezone parses a VTIMEZONE component from iCalendar data.
// It extracts the TZID and all DAYLIGHT/STANDARD sub-components.
func parseVTimezone(data []byte) (*VTimezone, error) {
	lines := splitICalLines(data)

	// Find the VTIMEZONE boundaries
	var tzID string
	var subComponents []tzSubcomponent
	inVTimezone := false
	inSubcomponent := false
	currentSub := tzSubcomponent{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		if strings.HasPrefix(upper, "BEGIN:VTIMEZONE") {
			inVTimezone = true
			continue
		}
		if !inVTimezone {
			continue
		}

		if strings.HasPrefix(upper, "END:VTIMEZONE") {
			break
		}

		// Extract TZID from BEGIN:VTIMEZONE or TZID property
		if !inSubcomponent && strings.HasPrefix(upper, "TZID:") {
			colonIdx := strings.Index(trimmed, ":")
			if colonIdx >= 0 {
				tzID = strings.TrimSpace(trimmed[colonIdx+1:])
			}
			continue
		}

		// Check for DAYLIGHT/STANDARD sub-component
		if strings.HasPrefix(upper, "BEGIN:DAYLIGHT") || strings.HasPrefix(upper, "BEGIN:STANDARD") {
			inSubcomponent = true
			currentSub = tzSubcomponent{Name: strings.TrimPrefix(upper, "BEGIN:")}
			continue
		}

		if inSubcomponent && strings.HasPrefix(upper, "END:DAYLIGHT") || inSubcomponent && strings.HasPrefix(upper, "END:STANDARD") {
			inSubcomponent = false
			subComponents = append(subComponents, currentSub)
			currentSub = tzSubcomponent{}
			continue
		}

		if inSubcomponent {
			parseSubcomponentLine(&currentSub, trimmed, upper)
		}
	}

	if tzID == "" {
		return nil, fmt.Errorf("VTIMEZONE missing TZID")
	}

	vtz := &VTimezone{TzID: tzID}
	for _, sc := range subComponents {
		if sc.Name == "DAYLIGHT" {
			vtz.Daylight = append(vtz.Daylight, sc)
		} else {
			vtz.Standard = append(vtz.Standard, sc)
		}
	}

	return vtz, nil
}

func parseSubcomponentLine(sc *tzSubcomponent, trimmed, upper string) {
	if strings.HasPrefix(upper, "DTSTART:") || strings.HasPrefix(upper, "DTSTART;") {
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx >= 0 {
			val := strings.TrimSpace(trimmed[colonIdx+1:])
			if t, err := parseCalDAVTime(val); err == nil {
				sc.DtStart = t
			}
		}
	} else if strings.HasPrefix(upper, "TZOFFSETFROM:") {
		sc.TzOffsetFrom = parseTZOffset(upper[len("TZOFFSETFROM:"):])
	} else if strings.HasPrefix(upper, "TZOFFSETTO:") {
		sc.TzOffsetTo = parseTZOffset(upper[len("TZOFFSETTO:"):])
	} else if strings.HasPrefix(upper, "RRULE:") {
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx >= 0 {
			val := strings.TrimSpace(trimmed[colonIdx+1:])
			if r, err := parseRRule(val); err == nil {
				sc.RRule = r
			}
		}
	}
}

// parseTZOffset parses a TZOFFSET value like "-0500" or "+0100" into a duration.
func parseTZOffset(s string) time.Duration {
	// Accept the extended format "+01:00" too. An empty value (a bare
	// "TZOFFSETFROM:" line) has no offset.
	s = strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	if s == "" {
		return 0
	}
	sign := time.Duration(1)
	if s[0] == '-' {
		sign = -1
		s = s[1:]
	} else if s[0] == '+' {
		s = s[1:]
	}

	hours := 0
	minutes := 0
	if len(s) >= 4 {
		fmt.Sscanf(s[:2], "%d", &hours)
		fmt.Sscanf(s[2:4], "%d", &minutes)
	} else if len(s) >= 2 {
		fmt.Sscanf(s, "%d", &hours)
	}

	return sign * (time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute)
}

// formatTZOffset formats a duration as a TZOFFSET string like "-0500".
func formatTZOffset(offset time.Duration) string {
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	hours := int(offset.Hours())
	minutes := int(offset.Minutes()) % 60
	return fmt.Sprintf("%s%02d%02d", sign, hours, minutes)
}

// generateVTimezone returns the VTIMEZONE component for an IANA zone, built
// by calendar.TimezoneComponent from the zone's own transitions (the last
// Sunday rules of Europe, the US second/first Sunday rules, southern
// hemisphere order) rather than one fixed rule for every zone.
func generateVTimezone(tzName string) (string, error) {
	component, ok := calendar.TimezoneComponent(tzName, time.Now().Year())
	if !ok {
		return "", fmt.Errorf("unknown timezone: %s", tzName)
	}
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//Veksel//Timezone//EN")
	cal.Children = append(cal.Children, component)
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return "", err
	}
	text := buf.String()
	start, end := strings.Index(text, "BEGIN:VTIMEZONE"), strings.LastIndex(text, "END:VTIMEZONE")
	if start < 0 || end < 0 {
		return "", fmt.Errorf("encode timezone %s", tzName)
	}
	return text[start:end+len("END:VTIMEZONE")] + "\r\n", nil
}

// --- Timezone-aware datetime extraction ---

// tzIDFromLine extracts the TZID parameter from an iCalendar property line.
// Returns the TZID with original case preserved, or empty string if not present.
// The original line is needed to preserve case; upperLine is used for detection.
func tzIDFromLine(original, upperLine string) string {
	// Look for TZID= in the uppercased property line before the colon
	colonIdx := strings.Index(upperLine, ":")
	if colonIdx < 0 {
		return ""
	}
	propPart := upperLine[:colonIdx]
	// Look for TZID= in the property part
	tzIDIdx := strings.Index(propPart, "TZID=")
	if tzIDIdx < 0 {
		return ""
	}
	// Extract the value from the ORIGINAL line to preserve case
	origColonIdx := strings.Index(original, ":")
	if origColonIdx < 0 {
		return ""
	}
	origPropPart := original[:origColonIdx]
	origTZIDIdx, _ := model.IndexFold(origPropPart, "TZID=")
	if origTZIDIdx < 0 {
		return ""
	}
	// Extract the value after TZID=
	start := origTZIDIdx + 5 // len("TZID=")
	end := len(origPropPart)
	// Value might be quoted
	if start < end && origPropPart[start] == '"' {
		start++
		end = strings.Index(origPropPart[start:], "\"")
		if end < 0 {
			// Unterminated quote: the value runs to the end of the parameters.
			end = len(origPropPart)
		} else {
			end += start
		}
	}
	return origPropPart[start:end]
}

// extractDTStartWithTZ extracts DTSTART along with its TZID parameter.
func extractDTStartWithTZ(data []byte) (time.Time, string) {
	return extractDateTimeWithTZ(data, "DTSTART")
}

// extractDTEndWithTZ extracts DTEND along with its TZID parameter.
func extractDTEndWithTZ(data []byte) (time.Time, string) {
	return extractDateTimeWithTZ(data, "DTEND")
}

// extractDateTimeWithTZ extracts a datetime property and its TZID parameter.
func extractDateTimeWithTZ(data []byte, prop string) (time.Time, string) {
	scanner := bufio.NewScanner(bytesReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		upperLine := strings.ToUpper(line)

		// The colon is located in line itself: upper-casing can change byte
		// lengths, so an index into upperLine may not fit line.
		colonIdx := -1
		for i := 0; i < len(line)-1; i++ {
			if line[i] == ':' {
				colonIdx = i
				break
			}
		}
		if colonIdx < 0 {
			continue
		}

		propName := strings.ToUpper(line[:colonIdx])
		semiIdx := strings.Index(propName, ";")
		if semiIdx >= 0 {
			propName = propName[:semiIdx]
		}
		if propName != prop {
			continue
		}

		// Extract TZID (preserving original case)
		tzID := tzIDFromLine(line, upperLine)

		val := strings.TrimSpace(line[colonIdx+1:])
		t, err := parseCalDAVTime(val)
		if err == nil {
			return t, tzID
		}
	}
	return time.Time{}, ""
}

// convertToLocalTime converts a time from its source timezone to the target timezone.
// If the source time has a TZID, it's interpreted in that timezone.
// If the target TZID is empty, UTC is used.
func convertToLocalTime(t time.Time, sourceTZID, targetTZID string) time.Time {
	if sourceTZID == "" {
		// No source timezone — assume UTC
		if targetTZID == "" {
			return t
		}
		loc, err := time.LoadLocation(targetTZID)
		if err != nil {
			return t.UTC()
		}
		return t.In(loc)
	}

	// Load source location
	srcLoc, err := time.LoadLocation(sourceTZID)
	if err != nil {
		// Unknown timezone, treat as UTC
		if targetTZID != "" {
			loc, loadErr := time.LoadLocation(targetTZID)
			if loadErr == nil {
				return t.UTC().In(loc)
			}
		}
		return t.UTC()
	}

	// Interpret the time in the source timezone
	// The parsed time values (year, month, day, hour, min, sec) represent local time in sourceTZID
	localT := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, srcLoc)

	if targetTZID == "" {
		return localT.UTC()
	}

	// Convert to target timezone
	targetLoc, err := time.LoadLocation(targetTZID)
	if err != nil {
		return localT.UTC()
	}
	return localT.In(targetLoc)
}

// convertEventToTimezone converts event DTSTART/DTEND from their original timezone
// to the target timezone and returns the converted times.
func convertEventToTimezone(data []byte, targetTZID string) (dtStart, dtEnd time.Time, isAllDay bool) {
	dtStart, sourceTZID := extractDTStartWithTZ(data)
	dtEnd, _ = extractDTEndWithTZ(data)
	isAllDay = extractIsAllDay(data)

	if dtStart.IsZero() {
		return time.Time{}, time.Time{}, false
	}

	// Convert start time
	dtStart = convertToLocalTime(dtStart, sourceTZID, targetTZID)
	if !dtEnd.IsZero() {
		dtEnd = convertToLocalTime(dtEnd, sourceTZID, targetTZID)
	}

	return dtStart, dtEnd, isAllDay
}

// formatICalTime formats a time as an iCalendar DATE-TIME value in the given timezone.
// If tzID is empty, it formats as UTC (with Z suffix).
func formatICalTime(t time.Time, tzID string) string {
	if tzID == "" {
		return t.UTC().Format("20060102T150405Z")
	}
	return t.Format("20060102T150405")
}

// getEventLocalTimes returns the event start/end times in the requested timezone.
// This is used for calendar-query responses when the client requests timezone expansion.
func getEventLocalTimes(data []byte, targetTZID string) (start, end time.Time) {
	start, end, _ = convertEventToTimezone(data, targetTZID)
	return
}

// extractVTimezoneFromICal extracts the VTIMEZONE component from a full iCalendar document.
// Some clients include VTIMEZONE alongside VEVENT in the same .ics file.
func extractVTimezoneFromICal(data []byte) (*VTimezone, error) {
	lines := splitICalLines(data)

	// Find VTIMEZONE start and end
	var vtzLines []string
	inVTimezone := false
	depth := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		if strings.HasPrefix(upper, "BEGIN:VTIMEZONE") {
			inVTimezone = true
			depth = 1
		}

		if inVTimezone {
			vtzLines = append(vtzLines, trimmed)
			if strings.HasPrefix(upper, "BEGIN:") {
				depth++
			}
			if strings.HasPrefix(upper, "END:") {
				depth--
				if depth == 0 {
					break
				}
			}
		}
	}

	if len(vtzLines) == 0 {
		return nil, fmt.Errorf("no VTIMEZONE found in data")
	}

	return parseVTimezone([]byte(strings.Join(vtzLines, "\n")))
}

// collectTimezonesFromEvent extracts all unique TZID values referenced in an event.
func collectTimezonesFromEvent(data []byte) []string {
	scanner := bufio.NewScanner(bytesReader(data))
	tzIDs := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		upper := strings.ToUpper(line)

		// Check for TZID= in any property
		idx := strings.Index(upper, "TZID=")
		if idx < 0 {
			continue
		}

		colonIdx := strings.Index(upper, ":")
		if colonIdx < 0 || idx > colonIdx {
			continue
		}

		start := idx + 5
		end := colonIdx
		if start >= end {
			continue
		}

		tzID := upper[start:end]
		// Handle quoted values
		tzID = strings.Trim(tzID, "\"")
		if tzID != "" && tzID != "UTC" {
			tzIDs[tzID] = struct{}{}
		}
	}

	result := make([]string, 0, len(tzIDs))
	for tz := range tzIDs {
		result = append(result, tz)
	}
	return result
}

// isFixedOffset checks if a timezone has a fixed offset (no DST).
func isFixedOffset(tzName string) bool {
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		return true // Unknown, assume fixed
	}

	// Check if the offset differs between January and July
	winter := time.Date(2024, 1, 15, 12, 0, 0, 0, loc)
	summer := time.Date(2024, 7, 15, 12, 0, 0, 0, loc)

	_, winterOff := winter.Zone()
	_, summerOff := summer.Zone()

	return winterOff == summerOff
}

// roundDuration rounds a duration to the nearest minute.
func roundDuration(d time.Duration) time.Duration {
	minutes := int64(math.Round(float64(d) / float64(time.Minute)))
	return time.Duration(minutes) * time.Minute
}
