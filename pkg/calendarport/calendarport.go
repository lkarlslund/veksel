// Package calendarport converts between whole iCalendar documents (.ics files
// and feeds) and Veksel calendar objects, which hold one UID each: the master
// event, its recurrence exceptions, and the VTIMEZONE definitions they use.
// Import, export, subscriptions, and published calendars share it.
package calendarport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
)

const (
	// MaxDocumentBytes bounds one imported or subscribed document.
	MaxDocumentBytes = 16 << 20
	// MaxObjects bounds the calendar objects (distinct UIDs) of a document.
	MaxObjects = 10000
	// MaxObjectBytes bounds one encoded calendar object.
	MaxObjectBytes = 1 << 20
	// MaxProblems bounds the problems reported for one document.
	MaxProblems = 50

	importProductID = "-//Veksel//Calendar Import//EN"
	exportProductID = "-//Veksel//Calendar Export//EN"
)

// Object is one calendar object: every component of one UID.
type Object struct {
	UID     string
	Summary string
	Data    []byte
	// Events counts the VEVENTs (master plus exceptions) it holds.
	Events int
}

// Problem is one component that could not be imported.
type Problem struct {
	UID     string `json:"uid,omitempty"`
	Message string `json:"message"`
}

// Document is a parsed iCalendar document.
type Document struct {
	Objects  []Object
	Problems []Problem
	// Skipped counts components other than events and time zones (to-dos,
	// journals, free/busy) that a calendar of events does not hold.
	Skipped int
	// Name is the document's X-WR-CALNAME, when present.
	Name string
}

func (d *Document) problem(uid, format string, values ...any) {
	if len(d.Problems) < MaxProblems {
		d.Problems = append(d.Problems, Problem{UID: uid, Message: fmt.Sprintf(format, values...)})
	}
}

// Parse splits an iCalendar document, possibly holding several VCALENDARs,
// into calendar objects grouped by UID. Events without a UID get a stable
// UID derived from their content so a repeated import replaces them. Each
// object carries the VTIMEZONE definitions its events reference.
func Parse(data []byte) Document {
	var document Document
	if len(data) > MaxDocumentBytes {
		document.problem("", "the calendar is larger than %d MiB", MaxDocumentBytes>>20)
		return document
	}
	timezones := map[string]*ical.Component{}
	groups := map[string][]*ical.Component{}
	var order []string
	decoder := calendar.NewDecoder(data)
	parsed := 0
	for {
		cal, err := decoder.Decode()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if parsed == 0 {
				document.problem("", "not a valid iCalendar document: %v", err)
			} else {
				document.problem("", "the document ends with invalid data: %v", err)
			}
			break
		}
		parsed++
		if name, err := cal.Props.Text("X-WR-CALNAME"); err == nil && document.Name == "" {
			document.Name = strings.TrimSpace(name)
		}
		for _, child := range cal.Children {
			switch child.Name {
			case ical.CompTimezone:
				if tzid, err := child.Props.Text(ical.PropTimezoneID); err == nil && tzid != "" {
					timezones[tzid] = child
				}
			case ical.CompEvent:
				uid, _ := child.Props.Text(ical.PropUID)
				uid = strings.TrimSpace(uid)
				if uid == "" {
					uid = derivedUID(child)
					child.Props.SetText(ical.PropUID, uid)
				}
				if _, seen := groups[uid]; !seen {
					if len(order) >= MaxObjects {
						document.problem(uid, "the calendar has more than %d events; the rest were not read", MaxObjects)
						continue
					}
					order = append(order, uid)
				}
				groups[uid] = append(groups[uid], child)
			default:
				document.Skipped++
			}
		}
	}
	for _, uid := range order {
		object, err := buildObject(uid, groups[uid], timezones, importProductID)
		if err != nil {
			document.problem(uid, "%v", err)
			continue
		}
		document.Objects = append(document.Objects, object)
	}
	return document
}

// derivedUID names an event without a UID by its identifying content.
func derivedUID(event *ical.Component) string {
	hash := sha256.New()
	for _, name := range []string{ical.PropSummary, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropRecurrenceRule, ical.PropRecurrenceID, ical.PropLocation} {
		if prop := event.Props.Get(name); prop != nil {
			_, _ = io.WriteString(hash, prop.Value)
		}
		_, _ = hash.Write([]byte{0})
	}
	return "import-" + hex.EncodeToString(hash.Sum(nil)[:16])
}

// buildObject assembles one UID's events, master first, with the time zones
// they reference, and checks that the result is a usable calendar object.
func buildObject(uid string, events []*ical.Component, timezones map[string]*ical.Component, productID string) (Object, error) {
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Props.Get(ical.PropRecurrenceID) == nil && events[j].Props.Get(ical.PropRecurrenceID) != nil
	})
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, productID)
	for _, tzid := range referencedTimezones(events) {
		if component, ok := timezones[tzid]; ok {
			cal.Children = append(cal.Children, component)
		}
	}
	cal.Children = append(cal.Children, events...)
	for _, event := range events {
		if event.Props.Get(ical.PropDateTimeStamp) == nil {
			event.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
		}
	}
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return Object{}, fmt.Errorf("event cannot be stored: %w", err)
	}
	if buf.Len() > MaxObjectBytes {
		return Object{}, fmt.Errorf("event is larger than %d KiB", MaxObjectBytes>>10)
	}
	projected, err := calendar.Project(buf.Bytes())
	if err != nil {
		return Object{}, fmt.Errorf("event cannot be read: %w", err)
	}
	return Object{UID: uid, Summary: projected.Summary, Data: buf.Bytes(), Events: len(events)}, nil
}

func referencedTimezones(components []*ical.Component) []string {
	seen := map[string]bool{}
	var result []string
	for _, component := range components {
		for _, values := range component.Props {
			for _, prop := range values {
				if tzid := prop.Params.Get(ical.PropTimezoneID); tzid != "" && !seen[tzid] {
					seen[tzid] = true
					result = append(result, tzid)
				}
			}
		}
	}
	sort.Strings(result)
	return result
}

// Exporter gathers calendar objects into one iCalendar document.
type Exporter struct {
	// Public prepares events for an anonymous published feed: private and
	// confidential events become busy blocks, and every event loses its
	// attendees, organizer, alarms, attachments, and extension properties.
	Public bool

	cal       *ical.Calendar
	timezones map[string]bool
	events    int
	bytes     int
	maxBytes  int
}

// NewExporter starts a document named name. maxBytes bounds the stored
// objects it accepts (0 means MaxDocumentBytes * 4).
func NewExporter(name string, maxBytes int) *Exporter {
	if maxBytes <= 0 {
		maxBytes = MaxDocumentBytes * 4
	}
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, exportProductID)
	cal.Props.SetText("CALSCALE", "GREGORIAN")
	if name = strings.TrimSpace(name); name != "" {
		prop := ical.NewProp("X-WR-CALNAME")
		prop.SetText(name)
		prop.Params.Del(ical.ParamValue) // readers expect the bare form
		cal.Props.Set(prop)
	}
	return &Exporter{cal: cal, timezones: map[string]bool{}, maxBytes: maxBytes}
}

// ErrTooLarge means an export exceeded its size bound.
var ErrTooLarge = errors.New("the calendar is too large to export")

// Add appends the events and time zones of one stored calendar object.
func (e *Exporter) Add(data []byte) error {
	e.bytes += len(data)
	if e.bytes > e.maxBytes {
		return ErrTooLarge
	}
	cal, err := calendar.Decode(data)
	if err != nil {
		return nil // not an event object; a calendar may hold other items
	}
	for _, child := range cal.Children {
		switch child.Name {
		case ical.CompTimezone:
			tzid, _ := child.Props.Text(ical.PropTimezoneID)
			if tzid == "" || e.timezones[tzid] {
				continue
			}
			e.timezones[tzid] = true
			// Time zones lead the document so readers see them first.
			e.cal.Children = append([]*ical.Component{child}, e.cal.Children...)
		case ical.CompEvent:
			if e.Public {
				publicEvent(child)
			}
			e.cal.Children = append(e.cal.Children, child)
			e.events++
		}
	}
	return nil
}

// publicTimeProps survive when a private event is reduced to a busy block.
var publicTimeProps = []string{
	ical.PropDateTimeStamp, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDuration,
	ical.PropRecurrenceRule, ical.PropRecurrenceDates, ical.PropExceptionDates, ical.PropRecurrenceID,
	ical.PropStatus, ical.PropTransparency, ical.PropSequence,
}

// publicEvent strips event in place for an anonymous feed; see
// Exporter.Public.
func publicEvent(event *ical.Component) {
	class, _ := event.Props.Text(ical.PropClass)
	if class = strings.ToUpper(strings.TrimSpace(class)); class == "PRIVATE" || class == "CONFIDENTIAL" {
		uid, _ := event.Props.Text(ical.PropUID)
		kept := make(ical.Props, len(publicTimeProps)+3)
		for _, name := range publicTimeProps {
			if values, ok := event.Props[name]; ok {
				kept[name] = values
			}
		}
		event.Props = kept
		// A derived UID keeps recurrence exceptions grouped without
		// revealing the event's own UID.
		hash := sha256.Sum256([]byte(uid))
		event.Props.SetText(ical.PropUID, "busy-"+hex.EncodeToString(hash[:12]))
		event.Props.SetText(ical.PropSummary, "Busy")
		event.Props.SetText(ical.PropClass, "PRIVATE")
		event.Children = nil
		return
	}
	for name := range event.Props {
		if name == ical.PropAttendee || name == ical.PropOrganizer || name == ical.PropAttach || strings.HasPrefix(name, "X-") {
			delete(event.Props, name)
		}
	}
	event.Children = slices.DeleteFunc(event.Children, func(child *ical.Component) bool { return child.Name == ical.CompAlarm })
}

// AddComponent appends a synthesized event.
func (e *Exporter) AddComponent(event *ical.Component) {
	e.cal.Children = append(e.cal.Children, event)
	e.events++
}

// Events reports the events added so far.
func (e *Exporter) Events() int { return e.events }

// Encode writes the document, defining any time zone that stored events
// reference without a VTIMEZONE of their own.
func (e *Exporter) Encode(w io.Writer) error {
	calendar.AddMissingTimezones(e.cal)
	return ical.NewEncoder(w).Encode(e.cal)
}

// Overlaps reports whether any occurrence of the calendar object overlaps
// [start, end). Objects that cannot be expanded are kept.
func Overlaps(data []byte, start, end time.Time) bool {
	occurrences, _, err := calendar.Occurrences(data, start, end)
	return err != nil || len(occurrences) > 0
}

// BusyEvent builds an opaque VEVENT that reveals only a busy interval, as
// published availability-only calendars carry. tentative marks a period the
// owner has not confirmed.
func BusyEvent(start, end time.Time, tentative bool, stamp time.Time) *ical.Component {
	event := ical.NewEvent()
	hash := sha256.Sum256([]byte(start.UTC().Format(time.RFC3339) + "/" + end.UTC().Format(time.RFC3339)))
	event.Props.SetText(ical.PropUID, "busy-"+hex.EncodeToString(hash[:12]))
	event.Props.SetDateTime(ical.PropDateTimeStamp, stamp.UTC())
	event.Props.SetDateTime(ical.PropDateTimeStart, start.UTC())
	event.Props.SetDateTime(ical.PropDateTimeEnd, end.UTC())
	summary := "Busy"
	if tentative {
		summary = "Tentative"
		event.Props.SetText(ical.PropStatus, "TENTATIVE")
	}
	event.Props.SetText(ical.PropSummary, summary)
	event.Props.SetText(ical.PropClass, "PRIVATE")
	event.Props.SetText(ical.PropTransparency, "OPAQUE")
	return event.Component
}
