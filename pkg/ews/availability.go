package ews

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// BusyPeriod is one busy interval of a mailbox.
type BusyPeriod struct {
	Start, End time.Time
	Tentative  bool
}

// DirectoryEntry is one global address list match for ResolveNames.
type DirectoryEntry struct {
	Name    string
	Address string
}

const (
	maxAvailabilityMailboxes = 100
	maxAvailabilityWindow    = 42 * 24 * time.Hour
	maxResolutions           = 100
)

// ewsTimeZone is the SerializableTimeZone of GetUserAvailabilityRequest.
// Bias values are minutes west of UTC, as in Windows TIME_ZONE_INFORMATION.
type ewsTimeZone struct {
	bias, standardBias, daylightBias int
	standard, daylight               *zoneTransition
}

type zoneTransition struct {
	month, order, hour, minute int
	weekday                    time.Weekday
}

var weekdays = map[string]time.Weekday{"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday, "wednesday": time.Wednesday, "thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday}

func parseTimeZone(zone *node) ewsTimeZone {
	result := ewsTimeZone{}
	if zone == nil {
		return result
	}
	result.bias, _ = strconv.Atoi(strings.TrimSpace(zone.child("Bias").textOrEmpty()))
	parse := func(element *node) (*zoneTransition, int) {
		if element == nil {
			return nil, 0
		}
		bias, _ := strconv.Atoi(element.descendantText("Bias"))
		month, _ := strconv.Atoi(element.descendantText("Month"))
		order, _ := strconv.Atoi(element.descendantText("DayOrder"))
		clock, _ := time.Parse("15:04:05", element.descendantText("Time"))
		weekday, ok := weekdays[strings.ToLower(element.descendantText("DayOfWeek"))]
		if month < 1 || month > 12 || order < 1 || order > 5 || !ok {
			return nil, bias
		}
		return &zoneTransition{month: month, order: order, hour: clock.Hour(), minute: clock.Minute(), weekday: weekday}, bias
	}
	result.standard, result.standardBias = parse(zone.child("StandardTime"))
	result.daylight, result.daylightBias = parse(zone.child("DaylightTime"))
	return result
}

func (n *node) textOrEmpty() string {
	if n == nil {
		return ""
	}
	return n.Text
}

// at resolves the transition in year as a wall-clock time labeled UTC.
func (t zoneTransition) at(year int) time.Time {
	first := time.Date(year, time.Month(t.month), 1, t.hour, t.minute, 0, 0, time.UTC)
	day := 1 + (int(t.weekday)-int(first.Weekday())+7)%7 + (t.order-1)*7
	last := time.Date(year, time.Month(t.month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
	for day > last {
		day -= 7
	}
	return first.AddDate(0, 0, day-1)
}

// offset returns the zone's UTC offset in minutes east at instant.
func (z ewsTimeZone) offset(instant time.Time) int {
	standard := -(z.bias + z.standardBias)
	if z.standard == nil || z.daylight == nil || z.daylightBias == z.standardBias {
		return standard
	}
	daylight := -(z.bias + z.daylightBias)
	year := instant.UTC().Year()
	start := z.daylight.at(year).Add(-time.Duration(standard) * time.Minute)
	end := z.standard.at(year).Add(-time.Duration(daylight) * time.Minute)
	inside := !instant.Before(start) && instant.Before(end)
	if start.After(end) {
		inside = !instant.Before(start) || instant.Before(end)
	}
	if inside {
		return daylight
	}
	return standard
}

func (z ewsTimeZone) toUTC(local time.Time) time.Time {
	guess := local.Add(-time.Duration(z.offset(local)) * time.Minute)
	return local.Add(-time.Duration(z.offset(guess)) * time.Minute)
}

func (z ewsTimeZone) toLocal(instant time.Time) time.Time {
	return instant.UTC().Add(time.Duration(z.offset(instant)) * time.Minute)
}

func parseLocalTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04:05.0000000", time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, layout != time.RFC3339
		}
	}
	return time.Time{}, false
}

// getUserAvailability implements GetUserAvailability for free/busy views,
// which Outlook for Mac and the macOS Calendar use for the scheduling
// assistant. Details (subjects, locations) are never disclosed.
func (h *Handler) getUserAvailability(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	zone := parseTimeZone(op.child("TimeZone"))
	options := op.descendant("FreeBusyViewOptions")
	window := options.descendant("TimeWindow")
	startText, endText := window.descendantText("StartTime"), window.descendantText("EndTime")
	start, startLocal := parseLocalTime(startText)
	end, endLocal := parseLocalTime(endText)
	if start.IsZero() || end.IsZero() {
		return "", fmt.Errorf("%w: FreeBusyViewOptions TimeWindow is required", errEWSInvalidProperty)
	}
	if startLocal {
		start = zone.toUTC(start)
	}
	if endLocal {
		end = zone.toUTC(end)
	}
	if !end.After(start) || end.Sub(start) > maxAvailabilityWindow {
		return "", fmt.Errorf("%w: the time window must be positive and at most 42 days", errEWSInvalidProperty)
	}
	interval := 30
	if value, err := strconv.Atoi(options.descendantText("MergedFreeBusyIntervalInMinutes")); err == nil && value >= 5 && value <= 1440 {
		interval = value
	}
	view := options.descendantText("RequestedView")
	merged := strings.Contains(strings.ToLower(view), "merged")
	events := !strings.EqualFold(view, "MergedOnly")
	viewType := "FreeBusy"
	switch {
	case merged && events:
		viewType = "FreeBusyMerged"
	case merged:
		viewType = "MergedOnly"
	}
	mailboxes := op.descendant("MailboxDataArray").ChildrenNamed("MailboxData")
	if len(mailboxes) == 0 || len(mailboxes) > maxAvailabilityMailboxes {
		return "", fmt.Errorf("%w: between 1 and %d mailboxes are required", errEWSInvalidProperty, maxAvailabilityMailboxes)
	}
	var out strings.Builder
	out.WriteString(`<m:GetUserAvailabilityResponse><m:FreeBusyResponseArray>`)
	for _, mailbox := range mailboxes {
		address := mailbox.descendantText("Address")
		var periods []BusyPeriod
		known := false
		var err error
		if h.freeBusy != nil {
			periods, known, err = h.freeBusy(ctx, access, address, start, end)
		}
		if err != nil || !known {
			code := "ErrorNoFreeBusyAccess"
			if err != nil {
				code = "ErrorFreeBusyGenerationFailed"
			}
			out.WriteString(`<m:FreeBusyResponse><m:ResponseMessage ResponseClass="Error"><m:MessageText>Free/busy information is not available for ` + escape(address) + `.</m:MessageText><m:ResponseCode>` + code + `</m:ResponseCode><m:DescriptiveLinkKey>0</m:DescriptiveLinkKey></m:ResponseMessage><m:FreeBusyView><t:FreeBusyViewType>None</t:FreeBusyViewType></m:FreeBusyView></m:FreeBusyResponse>`)
			continue
		}
		out.WriteString(`<m:FreeBusyResponse><m:ResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode></m:ResponseMessage><m:FreeBusyView><t:FreeBusyViewType>` + viewType + `</t:FreeBusyViewType>`)
		if merged {
			out.WriteString(`<t:MergedFreeBusy>` + mergedFreeBusy(periods, start, end, time.Duration(interval)*time.Minute) + `</t:MergedFreeBusy>`)
		}
		if events {
			out.WriteString(`<t:CalendarEventArray>`)
			for _, period := range periods {
				busyType := "Busy"
				if period.Tentative {
					busyType = "Tentative"
				}
				out.WriteString(`<t:CalendarEvent><t:StartTime>` + zone.toLocal(period.Start).Format("2006-01-02T15:04:05") + `</t:StartTime><t:EndTime>` + zone.toLocal(period.End).Format("2006-01-02T15:04:05") + `</t:EndTime><t:BusyType>` + busyType + `</t:BusyType></t:CalendarEvent>`)
			}
			out.WriteString(`</t:CalendarEventArray>`)
		}
		out.WriteString(`</m:FreeBusyView></m:FreeBusyResponse>`)
	}
	out.WriteString(`</m:FreeBusyResponseArray></m:GetUserAvailabilityResponse>`)
	return out.String(), nil
}

// mergedFreeBusy renders one digit per interval: 0 free, 1 tentative,
// 2 busy.
func mergedFreeBusy(periods []BusyPeriod, start, end time.Time, interval time.Duration) string {
	slots := int((end.Sub(start) + interval - 1) / interval)
	merged := []byte(strings.Repeat("0", slots))
	for _, period := range periods {
		for slot := range merged {
			from := start.Add(time.Duration(slot) * interval)
			if period.Start.Before(from.Add(interval)) && period.End.After(from) {
				value := byte('2')
				if period.Tentative {
					value = '1'
				}
				merged[slot] = max(merged[slot], value)
			}
		}
	}
	return string(merged)
}

// resolveNames implements ResolveNames over the global address list and the
// user's contacts, which Mac Mail and Outlook use to complete recipients.
func (h *Handler) resolveNames(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	query := strings.TrimSpace(op.descendantText("UnresolvedEntry"))
	query = strings.TrimPrefix(strings.TrimPrefix(query, "SMTP:"), "smtp:")
	if query == "" {
		return "", fmt.Errorf("%w: UnresolvedEntry is required", errEWSInvalidProperty)
	}
	type resolution struct{ name, address, kind string }
	var found []resolution
	seen := map[string]bool{}
	scope := strings.ToLower(op.attr("SearchScope"))
	if h.directory != nil && scope != "contacts" {
		entries, err := h.directory(ctx, access.Actor.ID, query, maxResolutions)
		if err == nil {
			for _, entry := range entries {
				if address := strings.ToLower(entry.Address); address != "" && !seen[address] {
					seen[address] = true
					found = append(found, resolution{name: entry.Name, address: address, kind: "Mailbox"})
				}
			}
		}
	}
	if scope != "activedirectory" {
		folders, err := h.space.ListFolders(ctx, access, service.FolderQuery{Type: model.FolderTypeContacts})
		if err != nil {
			return "", err
		}
		needle := strings.ToLower(query)
		for _, folder := range folders {
			if folder.SpecialUse == model.SpecialUseRecentRecipients {
				continue
			}
			items, err := h.space.ListItems(ctx, access, folder.ID, service.ItemQuery{})
			if err != nil {
				continue
			}
			for _, item := range items {
				contact := model.ParseVCard(item.Data)
				for _, address := range contact.Emails {
					address = strings.ToLower(strings.TrimSpace(address))
					if address == "" || seen[address] || len(found) >= maxResolutions {
						continue
					}
					if strings.Contains(address, needle) || strings.Contains(strings.ToLower(contact.FN), needle) {
						seen[address] = true
						found = append(found, resolution{name: contact.FN, address: address, kind: "Contact"})
					}
				}
			}
		}
	}
	if len(found) == 0 {
		return `<m:ResolveNamesResponse><m:ResponseMessages><m:ResolveNamesResponseMessage ResponseClass="Error"><m:MessageText>No results were found.</m:MessageText><m:ResponseCode>ErrorNameResolutionNoResults</m:ResponseCode><m:DescriptiveLinkKey>0</m:DescriptiveLinkKey></m:ResolveNamesResponseMessage></m:ResponseMessages></m:ResolveNamesResponse>`, nil
	}
	class, code := "Success", "NoError"
	if len(found) > 1 {
		class, code = "Warning", "ErrorNameResolutionMultipleResults"
	}
	var out strings.Builder
	out.WriteString(`<m:ResolveNamesResponse><m:ResponseMessages><m:ResolveNamesResponseMessage ResponseClass="` + class + `">`)
	if class == "Warning" {
		out.WriteString(`<m:MessageText>Multiple results were found.</m:MessageText>`)
	}
	out.WriteString(`<m:ResponseCode>` + code + `</m:ResponseCode><m:ResolutionSet TotalItemsInView="` + strconv.Itoa(len(found)) + `" IncludesLastItemInRange="true">`)
	for _, entry := range found {
		name := entry.name
		if name == "" {
			name = entry.address
		}
		out.WriteString(`<t:Resolution><t:Mailbox><t:Name>` + escape(name) + `</t:Name><t:EmailAddress>` + escape(entry.address) + `</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>` + entry.kind + `</t:MailboxType></t:Mailbox></t:Resolution>`)
	}
	out.WriteString(`</m:ResolutionSet></m:ResolveNamesResponseMessage></m:ResponseMessages></m:ResolveNamesResponse>`)
	return out.String(), nil
}
