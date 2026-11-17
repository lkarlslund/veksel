package ews

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendar"
)

// windowsZones maps the Windows time zone IDs EWS clients send in
// StartTimeZone, MeetingTimeZone and TimeZoneContext to IANA zones. The
// first entry for an IANA zone is the name rendered back to clients.
var windowsZones = [][2]string{
	{"UTC", "UTC"},
	{"GMT Standard Time", "Europe/London"},
	{"Greenwich Standard Time", "Atlantic/Reykjavik"},
	{"W. Europe Standard Time", "Europe/Berlin"},
	{"W. Europe Standard Time", "Europe/Amsterdam"},
	{"W. Europe Standard Time", "Europe/Stockholm"},
	{"W. Europe Standard Time", "Europe/Oslo"},
	{"W. Europe Standard Time", "Europe/Rome"},
	{"W. Europe Standard Time", "Europe/Vienna"},
	{"W. Europe Standard Time", "Europe/Zurich"},
	{"Romance Standard Time", "Europe/Paris"},
	{"Romance Standard Time", "Europe/Copenhagen"},
	{"Romance Standard Time", "Europe/Brussels"},
	{"Romance Standard Time", "Europe/Madrid"},
	{"Central Europe Standard Time", "Europe/Budapest"},
	{"Central Europe Standard Time", "Europe/Prague"},
	{"Central European Standard Time", "Europe/Warsaw"},
	{"E. Europe Standard Time", "Europe/Chisinau"},
	{"FLE Standard Time", "Europe/Kiev"},
	{"FLE Standard Time", "Europe/Kyiv"},
	{"FLE Standard Time", "Europe/Helsinki"},
	{"FLE Standard Time", "Europe/Riga"},
	{"FLE Standard Time", "Europe/Tallinn"},
	{"FLE Standard Time", "Europe/Vilnius"},
	{"GTB Standard Time", "Europe/Bucharest"},
	{"GTB Standard Time", "Europe/Athens"},
	{"Kaliningrad Standard Time", "Europe/Kaliningrad"},
	{"Belarus Standard Time", "Europe/Minsk"},
	{"Russian Standard Time", "Europe/Moscow"},
	{"Turkey Standard Time", "Europe/Istanbul"},
	{"Israel Standard Time", "Asia/Jerusalem"},
	{"Jordan Standard Time", "Asia/Amman"},
	{"Middle East Standard Time", "Asia/Beirut"},
	{"Egypt Standard Time", "Africa/Cairo"},
	{"South Africa Standard Time", "Africa/Johannesburg"},
	{"W. Central Africa Standard Time", "Africa/Lagos"},
	{"E. Africa Standard Time", "Africa/Nairobi"},
	{"Morocco Standard Time", "Africa/Casablanca"},
	{"Arabic Standard Time", "Asia/Baghdad"},
	{"Arab Standard Time", "Asia/Riyadh"},
	{"Arabian Standard Time", "Asia/Dubai"},
	{"Iran Standard Time", "Asia/Tehran"},
	{"Georgian Standard Time", "Asia/Tbilisi"},
	{"Caucasus Standard Time", "Asia/Yerevan"},
	{"Afghanistan Standard Time", "Asia/Kabul"},
	{"Pakistan Standard Time", "Asia/Karachi"},
	{"West Asia Standard Time", "Asia/Tashkent"},
	{"Ekaterinburg Standard Time", "Asia/Yekaterinburg"},
	{"India Standard Time", "Asia/Kolkata"},
	{"India Standard Time", "Asia/Calcutta"},
	{"Sri Lanka Standard Time", "Asia/Colombo"},
	{"Nepal Standard Time", "Asia/Kathmandu"},
	{"Bangladesh Standard Time", "Asia/Dhaka"},
	{"Myanmar Standard Time", "Asia/Yangon"},
	{"SE Asia Standard Time", "Asia/Bangkok"},
	{"SE Asia Standard Time", "Asia/Jakarta"},
	{"N. Central Asia Standard Time", "Asia/Novosibirsk"},
	{"North Asia Standard Time", "Asia/Krasnoyarsk"},
	{"China Standard Time", "Asia/Shanghai"},
	{"China Standard Time", "Asia/Hong_Kong"},
	{"North Asia East Standard Time", "Asia/Irkutsk"},
	{"Singapore Standard Time", "Asia/Singapore"},
	{"Singapore Standard Time", "Asia/Kuala_Lumpur"},
	{"Taipei Standard Time", "Asia/Taipei"},
	{"W. Australia Standard Time", "Australia/Perth"},
	{"Tokyo Standard Time", "Asia/Tokyo"},
	{"Korea Standard Time", "Asia/Seoul"},
	{"Yakutsk Standard Time", "Asia/Yakutsk"},
	{"Cen. Australia Standard Time", "Australia/Adelaide"},
	{"AUS Central Standard Time", "Australia/Darwin"},
	{"E. Australia Standard Time", "Australia/Brisbane"},
	{"AUS Eastern Standard Time", "Australia/Sydney"},
	{"AUS Eastern Standard Time", "Australia/Melbourne"},
	{"Tasmania Standard Time", "Australia/Hobart"},
	{"West Pacific Standard Time", "Pacific/Port_Moresby"},
	{"Vladivostok Standard Time", "Asia/Vladivostok"},
	{"New Zealand Standard Time", "Pacific/Auckland"},
	{"Fiji Standard Time", "Pacific/Fiji"},
	{"Tonga Standard Time", "Pacific/Tongatapu"},
	{"Samoa Standard Time", "Pacific/Apia"},
	{"Azores Standard Time", "Atlantic/Azores"},
	{"Cape Verde Standard Time", "Atlantic/Cape_Verde"},
	{"Greenland Standard Time", "America/Nuuk"},
	{"Greenland Standard Time", "America/Godthab"},
	{"E. South America Standard Time", "America/Sao_Paulo"},
	{"Argentina Standard Time", "America/Argentina/Buenos_Aires"},
	{"Argentina Standard Time", "America/Buenos_Aires"},
	{"Montevideo Standard Time", "America/Montevideo"},
	{"SA Eastern Standard Time", "America/Cayenne"},
	{"Newfoundland Standard Time", "America/St_Johns"},
	{"Atlantic Standard Time", "America/Halifax"},
	{"Paraguay Standard Time", "America/Asuncion"},
	{"Pacific SA Standard Time", "America/Santiago"},
	{"SA Western Standard Time", "America/La_Paz"},
	{"Venezuela Standard Time", "America/Caracas"},
	{"Eastern Standard Time", "America/New_York"},
	{"Eastern Standard Time", "America/Toronto"},
	{"US Eastern Standard Time", "America/Indiana/Indianapolis"},
	{"Cuba Standard Time", "America/Havana"},
	{"SA Pacific Standard Time", "America/Bogota"},
	{"SA Pacific Standard Time", "America/Lima"},
	{"Eastern Standard Time (Mexico)", "America/Cancun"},
	{"Central Standard Time", "America/Chicago"},
	{"Central Standard Time (Mexico)", "America/Mexico_City"},
	{"Canada Central Standard Time", "America/Regina"},
	{"Central America Standard Time", "America/Guatemala"},
	{"Mountain Standard Time", "America/Denver"},
	{"Mountain Standard Time", "America/Edmonton"},
	{"US Mountain Standard Time", "America/Phoenix"},
	{"Mountain Standard Time (Mexico)", "America/Mazatlan"},
	{"Pacific Standard Time", "America/Los_Angeles"},
	{"Pacific Standard Time", "America/Vancouver"},
	{"Pacific Standard Time (Mexico)", "America/Tijuana"},
	{"Alaskan Standard Time", "America/Anchorage"},
	{"Hawaiian Standard Time", "Pacific/Honolulu"},
	{"UTC-11", "Etc/GMT+11"},
	{"Dateline Standard Time", "Etc/GMT+12"},
	{"UTC+12", "Etc/GMT-12"},
}

// requestInfo is what the SOAP header says about the client: the schema
// version it was written against and the zone of its local times.
type requestInfo struct {
	version string
	// zone is the TimeZoneContext; nil when the request carries none.
	zone *time.Location
}

type requestInfoKey struct{}

func withRequestInfo(ctx context.Context, info requestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

func requestInfoFrom(ctx context.Context) requestInfo {
	info, _ := ctx.Value(requestInfoKey{}).(requestInfo)
	return info
}

// exchange2007 reports whether the client speaks the Exchange 2007 schema,
// which describes time zones with MeetingTimeZone instead of
// StartTimeZone and EndTimeZone.
func (r requestInfo) exchange2007() bool {
	return strings.HasPrefix(strings.ToLower(r.version), "exchange2007")
}

func parseRequestInfo(header *node) requestInfo {
	info := requestInfo{}
	if header == nil {
		return info
	}
	if version := header.child("RequestServerVersion"); version != nil {
		info.version = version.attr("Version")
	}
	if zoneContext := header.child("TimeZoneContext"); zoneContext != nil {
		info.zone = definitionLocation(zoneContext.child("TimeZoneDefinition"))
	}
	return info
}

// zoneLocation resolves a Windows or IANA zone ID.
func zoneLocation(id string) *time.Location {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for _, entry := range windowsZones {
		if strings.EqualFold(entry[0], id) {
			if location, err := time.LoadLocation(entry[1]); err == nil {
				return location
			}
		}
	}
	if location, err := time.LoadLocation(id); err == nil {
		return location
	}
	return nil
}

// windowsZone names a zone by its Windows ID: the table entry for the IANA
// name, else the first entry with the same offsets in January and July of
// year, else UTC.
func windowsZone(location *time.Location, year int) string {
	if location == nil {
		return "UTC"
	}
	for _, entry := range windowsZones {
		if entry[1] == location.String() {
			return entry[0]
		}
	}
	offsets := func(candidate *time.Location) [2]int {
		_, january := time.Date(year, time.January, 15, 12, 0, 0, 0, candidate).Zone()
		_, july := time.Date(year, time.July, 15, 12, 0, 0, 0, candidate).Zone()
		return [2]int{january, july}
	}
	want := offsets(location)
	for _, entry := range windowsZones {
		if candidate, err := time.LoadLocation(entry[1]); err == nil && offsets(candidate) == want {
			return entry[0]
		}
	}
	return "UTC"
}

// definitionLocation resolves a TimeZoneDefinition (StartTimeZone,
// EndTimeZone or TimeZoneContext) by its ID, or by the bias of its
// standard period when the ID is unknown.
func definitionLocation(definition *node) *time.Location {
	if definition == nil {
		return nil
	}
	if location := zoneLocation(definition.attr("Id")); location != nil {
		return location
	}
	for _, period := range definition.descendant("Periods").ChildrenNamed("Period") {
		if !strings.Contains(strings.ToLower(period.attr("Name")+period.attr("Id")), "standard") && !strings.Contains(period.attr("Id"), "Std") {
			continue
		}
		if bias, ok := parseXSDuration(period.attr("Bias")); ok {
			return time.FixedZone(definition.attr("Id"), -int(bias/time.Second))
		}
	}
	return nil
}

// localZone converts client wall times to instants: by an IANA location,
// or by the Exchange 2007 MeetingTimeZone transition rules.
type localZone struct {
	location *time.Location
	rules    *ewsTimeZone
}

func (z localZone) known() bool { return z.location != nil || z.rules != nil }

// instant interprets wall (a wall-clock time labeled UTC) in the zone.
func (z localZone) instant(wall time.Time) time.Time {
	switch {
	case z.location != nil:
		return time.Date(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), wall.Second(), 0, z.location).UTC()
	case z.rules != nil:
		return z.rules.toUTC(wall)
	}
	return wall
}

// meetingTimeZone parses an Exchange 2007 MeetingTimeZone.
func meetingTimeZone(zone *node) localZone {
	if zone == nil {
		return localZone{}
	}
	if location := zoneLocation(zone.attr("TimeZoneName")); location != nil {
		return localZone{location: location}
	}
	base, ok := parseXSDuration(zone.descendantText("BaseOffset"))
	if !ok {
		return localZone{}
	}
	rules := &ewsTimeZone{bias: int(base / time.Minute)}
	parse := func(element *node) (*zoneTransition, int) {
		if element == nil {
			return nil, 0
		}
		offset, _ := parseXSDuration(element.child("Offset").textOrEmpty())
		recurrence := element.child("RelativeYearlyRecurrence")
		clock, err := time.Parse("15:04:05", strings.TrimSpace(element.child("Time").textOrEmpty()))
		weekday, okDay := weekdays[strings.ToLower(recurrence.descendantText("DaysOfWeek"))]
		month := monthNumber(recurrence.descendantText("Month"))
		order := dayIndexNumber(recurrence.descendantText("DayOfWeekIndex"))
		if recurrence == nil || err != nil || !okDay || month == 0 || order == 0 {
			return nil, int(offset / time.Minute)
		}
		if order < 0 {
			order = 5
		}
		return &zoneTransition{month: month, order: order, hour: clock.Hour(), minute: clock.Minute(), weekday: weekday}, int(offset / time.Minute)
	}
	rules.standard, rules.standardBias = parse(zone.child("Standard"))
	rules.daylight, rules.daylightBias = parse(zone.child("Daylight"))
	return localZone{rules: rules}
}

// parseXSDuration parses an xs:duration such as -PT1H, PT30M or P1DT2H.
func parseXSDuration(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	negative := strings.HasPrefix(value, "-")
	value = strings.TrimPrefix(value, "-")
	if !strings.HasPrefix(value, "P") || len(value) < 3 {
		return 0, false
	}
	value = value[1:]
	var total time.Duration
	inTime := false
	number := ""
	for _, r := range value {
		switch {
		case r == 'T':
			inTime = true
		case r >= '0' && r <= '9' || r == '.':
			number += string(r)
		default:
			amount, err := strconv.ParseFloat(number, 64)
			if err != nil {
				return 0, false
			}
			number = ""
			unit := map[rune]time.Duration{'D': 24 * time.Hour, 'W': 7 * 24 * time.Hour}[r]
			if inTime {
				unit = map[rune]time.Duration{'H': time.Hour, 'M': time.Minute, 'S': time.Second}[r]
			}
			if unit == 0 {
				return 0, false
			}
			total += time.Duration(amount * float64(unit))
		}
	}
	if number != "" {
		return 0, false
	}
	if negative {
		total = -total
	}
	return total, true
}

// formatXSDuration renders a duration as xs:duration.
func formatXSDuration(value time.Duration) string {
	sign := ""
	if value < 0 {
		sign, value = "-", -value
	}
	days := value / (24 * time.Hour)
	value -= days * 24 * time.Hour
	out := sign + "P"
	if days > 0 {
		out += strconv.Itoa(int(days)) + "D"
	}
	if value > 0 || days == 0 {
		out += "T"
		if hours := value / time.Hour; hours > 0 {
			out += strconv.Itoa(int(hours)) + "H"
			value -= hours * time.Hour
		}
		if minutes := value / time.Minute; minutes > 0 {
			out += strconv.Itoa(int(minutes)) + "M"
			value -= minutes * time.Minute
		}
		if seconds := value / time.Second; seconds > 0 || strings.HasSuffix(out, "T") {
			out += strconv.Itoa(int(seconds)) + "S"
		}
	}
	return out
}

var monthNames = []string{"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}

func monthNumber(name string) int {
	for index, candidate := range monthNames {
		if strings.EqualFold(candidate, strings.TrimSpace(name)) {
			return index + 1
		}
	}
	return 0
}

var dayIndexNames = map[string]int{"first": 1, "second": 2, "third": 3, "fourth": 4, "last": -1}

func dayIndexNumber(name string) int { return dayIndexNames[strings.ToLower(strings.TrimSpace(name))] }

func dayIndexName(order int) string {
	switch order {
	case 1:
		return "First"
	case 2:
		return "Second"
	case 3:
		return "Third"
	case 4:
		return "Fourth"
	}
	return "Last"
}

var weekdayNames = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

// timeZoneElements renders the zone of an event for the client's schema:
// MeetingTimeZone for Exchange 2007, StartTimeZone and EndTimeZone after.
func timeZoneElements(info requestInfo, location *time.Location, year int) string {
	name := windowsZone(location, year)
	if !info.exchange2007() {
		return `<t:StartTimeZone Id="` + escape(name) + `" Name="` + escape(name) + `"/><t:EndTimeZone Id="` + escape(name) + `" Name="` + escape(name) + `"/>`
	}
	if location == nil {
		location = time.UTC
	}
	var out strings.Builder
	out.WriteString(`<t:MeetingTimeZone TimeZoneName="` + escape(name) + `">`)
	changes := calendar.ZoneChanges(location, year)
	_, standardOffset := time.Date(year, time.January, 1, 0, 0, 0, 0, location).Zone()
	var standard, daylight *calendar.ZoneChange
	for index := range changes {
		change := &changes[index]
		if change.At.In(location).IsDST() {
			daylight = change
		} else {
			standard = change
			standardOffset = change.To
		}
	}
	out.WriteString(`<t:BaseOffset>` + formatXSDuration(-time.Duration(standardOffset)*time.Second) + `</t:BaseOffset>`)
	if standard != nil && daylight != nil {
		rule := func(tag string, change *calendar.ZoneChange, offset int) {
			wall := change.At.Add(time.Duration(change.From) * time.Second).UTC()
			order := (wall.Day()-1)/7 + 1
			if wall.Day()+7 > time.Date(wall.Year(), wall.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day() {
				order = -1
			}
			out.WriteString(`<t:` + tag + `><t:Offset>` + formatXSDuration(-time.Duration(offset)*time.Second) + `</t:Offset><t:RelativeYearlyRecurrence><t:DaysOfWeek>` + weekdayNames[wall.Weekday()] + `</t:DaysOfWeek><t:DayOfWeekIndex>` + dayIndexName(order) + `</t:DayOfWeekIndex><t:Month>` + monthNames[wall.Month()-1] + `</t:Month></t:RelativeYearlyRecurrence><t:Time>` + wall.Format("15:04:05") + `</t:Time></t:` + tag + `>`)
		}
		rule("Standard", standard, 0)
		rule("Daylight", daylight, daylight.To-standardOffset)
	}
	out.WriteString(`</t:MeetingTimeZone>`)
	return out.String()
}

// parseDateTime parses an xs:dateTime. Values without a zone designator
// are wall times in zone.
func parseDateTime(value string, zone localZone) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z07:00"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), true
		}
	}
	for _, layout := range []string{"2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return zone.instant(parsed), true
		}
	}
	return time.Time{}, false
}

func formatDateTime(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05Z") }
