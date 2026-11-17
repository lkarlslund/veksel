package calendarindex

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Busy types are RFC 5545 FBTYPE values.
const (
	BusyType          = "BUSY"
	BusyTentativeType = "BUSY-TENTATIVE"
)

// BusyPeriod is an interval during which an event occupies a calendar's
// owner. UID names the event so a booking can ignore its own earlier copy.
type BusyPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Type  string    `json:"type"`
	UID   string    `json:"-"`
}

// Busy returns the busy periods of the occupying occurrences in folders over
// [start, end): opaque, not cancelled, and not declined by any address in
// own (the owner's identities). At most limit periods are returned (0 means
// unlimited); periods are clipped to the range and not merged.
func (i *Index) Busy(ctx context.Context, space service.FolderSpace, access service.AccessContext, folders []model.Folder, own []string, start, end time.Time, limit int) ([]BusyPeriod, error) {
	var periods []BusyPeriod
	for _, folder := range folders {
		results, err := i.Query(ctx, space, access, folder, start, end)
		if err != nil {
			return nil, err
		}
		for _, result := range results {
			event := result.Occurrence.Event
			if event.Transparent || strings.EqualFold(event.Status, "CANCELLED") {
				continue
			}
			kind := BusyType
			if strings.EqualFold(event.Status, "TENTATIVE") {
				kind = BusyTentativeType
			}
			declined := false
			for _, participant := range event.Participants {
				if slices.Contains(own, participant.Address) {
					switch participant.PartStat {
					case "DECLINED":
						declined = true
					case "TENTATIVE", "NEEDS-ACTION":
						kind = BusyTentativeType
					}
				}
			}
			from, until, ok := OccupiedBounds(event)
			if declined || !ok || !until.After(start) || !from.Before(end) {
				continue
			}
			periods = append(periods, BusyPeriod{Start: later(from, start).UTC(), End: earlier(until, end).UTC(), Type: kind, UID: event.UID})
			if limit > 0 && len(periods) >= limit {
				return periods, nil
			}
		}
	}
	return periods, nil
}

// OwnerBusy returns, unmerged and with their event UIDs, the busy periods
// of folders as seen by their owner ownerID, or of every calendar ownerID
// owns when folders is nil. Occurrences ownerID's identities declined do
// not count. Callers must already have authorized the requester to see
// ownerID's free/busy time: the folders are read with the owner's access so
// a free/busy-only sharee learns busy times and nothing else.
func (i *Index) OwnerBusy(ctx context.Context, space service.FolderSpace, users *model.UserStore, ownerID string, folders []model.Folder, start, end time.Time, limit int) ([]BusyPeriod, error) {
	access := service.UserAccess(ownerID, "freebusy")
	if folders == nil {
		listed, err := space.ListFolders(ctx, access, service.FolderQuery{Type: model.FolderTypeCalendar})
		if err != nil {
			return nil, err
		}
		for _, folder := range listed {
			if folder.Type == model.FolderTypeCalendar && strings.EqualFold(folder.UserID, ownerID) {
				folders = append(folders, folder)
			}
		}
	}
	// An account without addresses has no identities to decline with.
	identities, err := users.ListEmailAddressesForUser(ctx, ownerID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	own := make([]string, 0, len(identities))
	for _, identity := range identities {
		own = append(own, strings.ToLower(identity.ID))
	}
	return i.Busy(ctx, space, access, folders, own, start, end, limit)
}

// FreeBusyVisibility returns whether the subject of access may see an
// identity's busy times: its own, one in a mail domain the subject has an
// enabled identity in, or one whose owner has shared a calendar the subject
// can see. Every free/busy surface that looks up colleagues by address (the
// web scheduling assistant, CalDAV schedule-outbox requests) applies it.
func FreeBusyVisibility(ctx context.Context, space service.FolderSpace, users *model.UserStore, access service.AccessContext) (func(model.EmailAddress) bool, error) {
	subject := strings.ToLower(access.Subject.ID)
	identities, err := users.ListEmailAddressesForUser(ctx, subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	domains := make(map[string]bool, len(identities))
	for _, identity := range identities {
		if identity.Enabled {
			domains[strings.ToLower(identity.DomainID)] = true
		}
	}
	folders, err := space.ListFolders(ctx, access, service.FolderQuery{Type: model.FolderTypeCalendar})
	if err != nil {
		return nil, err
	}
	sharing := map[string]bool{}
	for _, folder := range folders {
		if folder.Type == model.FolderTypeCalendar {
			sharing[strings.ToLower(folder.UserID)] = true
		}
	}
	return func(identity model.EmailAddress) bool {
		owner := strings.ToLower(identity.UserID)
		return owner == subject || domains[strings.ToLower(identity.DomainID)] || sharing[owner]
	}, nil
}

// MergeBusy sorts periods and joins touching or overlapping periods of the
// same type.
func MergeBusy(periods []BusyPeriod) []BusyPeriod {
	sort.Slice(periods, func(a, b int) bool { return periods[a].Start.Before(periods[b].Start) })
	merged := make([]BusyPeriod, 0, len(periods))
	for _, period := range periods {
		period.UID = ""
		if last := len(merged) - 1; last >= 0 && !period.Start.After(merged[last].End) && period.Type == merged[last].Type {
			if period.End.After(merged[last].End) {
				merged[last].End = period.End
			}
			continue
		}
		merged = append(merged, period)
	}
	return merged
}

// EncodeVFreeBusy renders periods as an iCalendar object holding one
// VFREEBUSY component (RFC 5545 §3.6.4) covering [start, end): the range as
// DTSTART/DTEND and each busy interval as a UTC FREEBUSY period typed by
// FBTYPE. Periods are clipped to the range, sorted, and merged.
func EncodeVFreeBusy(periods []BusyPeriod, start, end, stamp time.Time, uid, prodID string) []byte {
	return encodeVFreeBusy(periods, start, end, stamp, uid, prodID, FreeBusyReply{})
}

// FreeBusyReply names the parties of an iTIP VFREEBUSY REPLY (RFC 5546
// §3.3.3): the requesting organizer and the one attendee whose busy time
// the reply carries, both calendar user addresses such as mailto: URIs.
type FreeBusyReply struct {
	Organizer string
	Attendee  string
}

// EncodeVFreeBusyReply renders periods like EncodeVFreeBusy as an iTIP
// METHOD:REPLY answering a VFREEBUSY REQUEST: uid is the request's UID and
// the VFREEBUSY names reply's organizer and attendee.
func EncodeVFreeBusyReply(periods []BusyPeriod, start, end, stamp time.Time, uid, prodID string, reply FreeBusyReply) []byte {
	return encodeVFreeBusy(periods, start, end, stamp, uid, prodID, reply)
}

func encodeVFreeBusy(periods []BusyPeriod, start, end, stamp time.Time, uid, prodID string, reply FreeBusyReply) []byte {
	const layout = "20060102T150405Z"
	start, end = start.UTC(), end.UTC()
	clipped := make([]BusyPeriod, 0, len(periods))
	for _, period := range periods {
		if !period.End.After(start) || !period.Start.Before(end) || !period.End.After(period.Start) {
			continue
		}
		period.Start, period.End = later(period.Start, start).UTC(), earlier(period.End, end).UTC()
		if period.Type != BusyTentativeType {
			period.Type = BusyType
		}
		clipped = append(clipped, period)
	}
	var b strings.Builder
	line := func(format string, args ...any) {
		writeFolded(&b, fmt.Sprintf(format, args...))
	}
	itip := reply != FreeBusyReply{}
	line("BEGIN:VCALENDAR")
	line("VERSION:2.0")
	line("PRODID:%s", prodID)
	if itip {
		line("METHOD:REPLY")
	}
	line("BEGIN:VFREEBUSY")
	line("UID:%s", escapeText(uid))
	line("DTSTAMP:%s", stamp.UTC().Format(layout))
	line("DTSTART:%s", start.Format(layout))
	line("DTEND:%s", end.Format(layout))
	if itip {
		line("ORGANIZER:%s", stripControls(reply.Organizer))
		line("ATTENDEE:%s", stripControls(reply.Attendee))
	}
	// One period per property keeps every line far below the 75-octet
	// folding limit.
	for _, period := range MergeBusy(clipped) {
		line("FREEBUSY;FBTYPE=%s:%s/%s", period.Type, period.Start.Format(layout), period.End.Format(layout))
	}
	line("END:VFREEBUSY")
	line("END:VCALENDAR")
	return []byte(b.String())
}

// writeFolded writes one content line, folded at 75 octets without
// splitting a UTF-8 sequence (RFC 5545 §3.1), and its CRLF.
func writeFolded(b *strings.Builder, line string) {
	limit := 75
	for len(line) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(line[cut]) {
			cut--
		}
		b.WriteString(line[:cut])
		b.WriteString("\r\n ")
		line = line[cut:]
		limit = 74 // the leading space counts toward the next line
	}
	b.WriteString(line)
	b.WriteString("\r\n")
}

// escapeText escapes an RFC 5545 TEXT value.
func escapeText(value string) string {
	return strings.NewReplacer(`\`, `\\`, ";", `\;`, ",", `\,`, "\n", `\n`, "\r", "").Replace(value)
}

// stripControls drops control characters a URI value cannot carry, so a
// caller-supplied address cannot inject content lines.
func stripControls(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

// OccupiedBounds returns an occurrence's interval; a missing or inverted end
// occupies an hour, or the whole day for an all-day event.
func OccupiedBounds(event calendarcore.Event) (time.Time, time.Time, bool) {
	parse := func(value string) (time.Time, error) {
		if event.AllDay {
			return time.ParseInLocation(time.DateOnly, value, time.Local)
		}
		return time.Parse(time.RFC3339, value)
	}
	from, err := parse(event.Start)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	until, err := parse(event.End)
	if err != nil || !until.After(from) {
		until = from.Add(time.Hour)
		if event.AllDay {
			until = from.AddDate(0, 0, 1)
		}
	}
	return from, until, true
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
