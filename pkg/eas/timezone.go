package eas

import (
	"encoding/base64"
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// easTimeZone is the MS-ASDTYPE 2.6.4 TimeZone value: a base64 Windows
// TIME_ZONE_INFORMATION structure. Bias values are minutes west of UTC.
type easTimeZone struct {
	Bias         int32
	StandardName string
	Standard     systemTime
	StandardBias int32
	DaylightName string
	Daylight     systemTime
	DaylightBias int32
}

// systemTime is a SYSTEMTIME transition rule. With Year 0, Day is the
// week of the month (1-4, 5 for the last) and DayOfWeek the weekday.
type systemTime struct {
	Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds uint16
}

const timeZoneSize = 172

func (tz easTimeZone) encode() string {
	buffer := make([]byte, timeZoneSize)
	binary.LittleEndian.PutUint32(buffer[0:], uint32(tz.Bias))
	putUTF16(buffer[4:68], tz.StandardName)
	tz.Standard.put(buffer[68:84])
	binary.LittleEndian.PutUint32(buffer[84:], uint32(tz.StandardBias))
	putUTF16(buffer[88:152], tz.DaylightName)
	tz.Daylight.put(buffer[152:168])
	binary.LittleEndian.PutUint32(buffer[168:], uint32(tz.DaylightBias))
	return base64.StdEncoding.EncodeToString(buffer)
}

func decodeTimeZone(value string) (easTimeZone, bool) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) < timeZoneSize {
		return easTimeZone{}, false
	}
	return easTimeZone{
		Bias:         int32(binary.LittleEndian.Uint32(data[0:])),
		StandardName: getUTF16(data[4:68]),
		Standard:     getSystemTime(data[68:84]),
		StandardBias: int32(binary.LittleEndian.Uint32(data[84:])),
		DaylightName: getUTF16(data[88:152]),
		Daylight:     getSystemTime(data[152:168]),
		DaylightBias: int32(binary.LittleEndian.Uint32(data[168:])),
	}, true
}

func putUTF16(destination []byte, value string) {
	encoded := utf16.Encode([]rune(value))
	for index := 0; index < len(encoded) && index < len(destination)/2-1; index++ {
		binary.LittleEndian.PutUint16(destination[index*2:], encoded[index])
	}
}

func getUTF16(data []byte) string {
	values := make([]uint16, 0, len(data)/2)
	for index := 0; index+1 < len(data); index += 2 {
		value := binary.LittleEndian.Uint16(data[index:])
		if value == 0 {
			break
		}
		values = append(values, value)
	}
	return string(utf16.Decode(values))
}

func (s systemTime) put(destination []byte) {
	for index, value := range []uint16{s.Year, s.Month, s.DayOfWeek, s.Day, s.Hour, s.Minute, s.Second, s.Milliseconds} {
		binary.LittleEndian.PutUint16(destination[index*2:], value)
	}
}

func getSystemTime(data []byte) systemTime {
	value := func(index int) uint16 { return binary.LittleEndian.Uint16(data[index*2:]) }
	return systemTime{value(0), value(1), value(2), value(3), value(4), value(5), value(6), value(7)}
}

// utcTimeZone is the zero-bias zone without daylight saving time.
var utcTimeZone = easTimeZone{StandardName: "UTC", DaylightName: "UTC"}

// timeZoneFor describes location's rules in the given year. Transitions are
// found by scanning the year, so any IANA zone with at most two yearly
// changes is represented exactly; others are approximated by their
// standard offset.
func timeZoneFor(location *time.Location, year int) easTimeZone {
	if location == nil || location == time.UTC {
		return utcTimeZone
	}
	january := time.Date(year, time.January, 1, 0, 0, 0, 0, location)
	july := time.Date(year, time.July, 1, 0, 0, 0, 0, location)
	_, januaryOffset := january.Zone()
	_, julyOffset := july.Zone()
	name := location.String()
	if januaryOffset == julyOffset {
		return easTimeZone{Bias: int32(-januaryOffset / 60), StandardName: name, DaylightName: name}
	}
	standardOffset, daylightOffset := min(januaryOffset, julyOffset), max(januaryOffset, julyOffset)
	tz := easTimeZone{
		Bias: int32(-standardOffset / 60), StandardName: name, DaylightName: name,
		DaylightBias: int32(-(daylightOffset - standardOffset) / 60),
	}
	start := time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(1, 0, 0)
	previous := offsetAt(start, location)
	for day := start; day.Before(end); day = day.Add(24 * time.Hour) {
		next := day.Add(24 * time.Hour)
		if offset := offsetAt(next, location); offset != previous {
			low, high := day, next
			for high.Sub(low) > time.Minute {
				middle := low.Add(high.Sub(low) / 2)
				if offsetAt(middle, location) == previous {
					low = middle
				} else {
					high = middle
				}
			}
			// The rule is expressed in local time before the change.
			local := high.Add(time.Duration(previous) * time.Second)
			rule := transitionRule(local)
			if offset == daylightOffset {
				tz.Daylight = rule
			} else {
				tz.Standard = rule
			}
			previous = offset
		}
	}
	return tz
}

func offsetAt(instant time.Time, location *time.Location) int {
	_, offset := instant.In(location).Zone()
	return offset
}

func transitionRule(local time.Time) systemTime {
	week := (local.Day()-1)/7 + 1
	if local.Day()+7 > daysIn(local.Month(), local.Year()) {
		week = 5
	}
	return systemTime{
		Month: uint16(local.Month()), DayOfWeek: uint16(local.Weekday()), Day: uint16(week),
		Hour: uint16(local.Hour()), Minute: uint16(local.Minute()),
	}
}

func daysIn(month time.Month, year int) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// hasDaylight reports whether the zone defines daylight saving time.
func (tz easTimeZone) hasDaylight() bool {
	return tz.Daylight.Month != 0 && tz.Standard.Month != 0 && tz.DaylightBias != 0
}

// offset returns the UTC offset in seconds at instant under tz's rules.
func (tz easTimeZone) offset(instant time.Time) int {
	standard := -int(tz.Bias+tz.StandardBias) * 60
	if !tz.hasDaylight() {
		return -int(tz.Bias) * 60
	}
	daylight := -int(tz.Bias+tz.DaylightBias) * 60
	year := instant.UTC().Year()
	// Transition instants in UTC: daylight starts at the rule's local
	// standard time and ends at the rule's local daylight time.
	daylightStart := tz.Daylight.instant(year).Add(-time.Duration(standard) * time.Second)
	daylightEnd := tz.Standard.instant(year).Add(-time.Duration(daylight) * time.Second)
	in := false
	if daylightStart.Before(daylightEnd) {
		in = !instant.Before(daylightStart) && instant.Before(daylightEnd)
	} else {
		in = !instant.Before(daylightStart) || instant.Before(daylightEnd)
	}
	if in {
		return daylight
	}
	return standard
}

// instant resolves the rule in year as a wall-clock time labeled UTC.
func (s systemTime) instant(year int) time.Time {
	if s.Year != 0 {
		return time.Date(int(s.Year), time.Month(s.Month), int(s.Day), int(s.Hour), int(s.Minute), int(s.Second), 0, time.UTC)
	}
	first := time.Date(year, time.Month(s.Month), 1, int(s.Hour), int(s.Minute), int(s.Second), 0, time.UTC)
	shift := (int(s.DayOfWeek) - int(first.Weekday()) + 7) % 7
	day := 1 + shift + (int(s.Day)-1)*7
	for day > daysIn(time.Month(s.Month), year) {
		day -= 7
	}
	return first.AddDate(0, 0, day-1)
}

// candidateZones are matched against client time zones, which carry rules
// and display names but no IANA identifier.
var candidateZones = []string{
	"Europe/London", "Europe/Dublin", "Europe/Lisbon", "Europe/Copenhagen", "Europe/Berlin", "Europe/Paris",
	"Europe/Amsterdam", "Europe/Brussels", "Europe/Stockholm", "Europe/Oslo", "Europe/Madrid", "Europe/Rome",
	"Europe/Vienna", "Europe/Zurich", "Europe/Warsaw", "Europe/Prague", "Europe/Budapest", "Europe/Helsinki",
	"Europe/Athens", "Europe/Bucharest", "Europe/Kiev", "Europe/Istanbul", "Europe/Moscow", "Atlantic/Reykjavik",
	"America/New_York", "America/Chicago", "America/Denver", "America/Phoenix", "America/Los_Angeles",
	"America/Anchorage", "Pacific/Honolulu", "America/Halifax", "America/St_Johns", "America/Toronto",
	"America/Vancouver", "America/Mexico_City", "America/Sao_Paulo", "America/Argentina/Buenos_Aires",
	"America/Santiago", "America/Bogota", "America/Lima", "Africa/Johannesburg", "Africa/Cairo", "Africa/Lagos",
	"Africa/Nairobi", "Asia/Dubai", "Asia/Karachi", "Asia/Kolkata", "Asia/Dhaka", "Asia/Bangkok", "Asia/Jakarta",
	"Asia/Singapore", "Asia/Hong_Kong", "Asia/Shanghai", "Asia/Taipei", "Asia/Seoul", "Asia/Tokyo",
	"Asia/Jerusalem", "Asia/Tehran", "Australia/Perth", "Australia/Adelaide", "Australia/Darwin",
	"Australia/Brisbane", "Australia/Sydney", "Australia/Melbourne", "Australia/Hobart", "Pacific/Auckland",
}

// matchLocation finds an IANA zone whose rules equal tz's in year, so
// recurring events keep their wall-clock time across daylight changes.
// The preferred zone (the user's own) wins ties between equal zones.
func matchLocation(tz easTimeZone, year int, preferred *time.Location) *time.Location {
	if tz.Bias == 0 && !tz.hasDaylight() {
		return time.UTC
	}
	candidates := make([]*time.Location, 0, len(candidateZones)+1)
	if preferred != nil {
		candidates = append(candidates, preferred)
	}
	for _, name := range candidateZones {
		if location, err := time.LoadLocation(name); err == nil {
			candidates = append(candidates, location)
		}
	}
	for _, location := range candidates {
		if sameRules(timeZoneFor(location, year), tz) {
			return location
		}
	}
	return nil
}

func sameRules(a, b easTimeZone) bool {
	if a.Bias != b.Bias || a.hasDaylight() != b.hasDaylight() {
		return false
	}
	if !a.hasDaylight() {
		return true
	}
	same := func(x, y systemTime) bool {
		return x.Month == y.Month && x.DayOfWeek == y.DayOfWeek && x.Day == y.Day && x.Hour == y.Hour && x.Minute == y.Minute
	}
	return a.DaylightBias == b.DaylightBias && same(a.Daylight, b.Daylight) && same(a.Standard, b.Standard)
}
