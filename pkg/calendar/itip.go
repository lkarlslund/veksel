package calendar

// iTIP (iCalendar Transport-Independent Messaging) codec shared by CalDAV
// scheduling and iMIP (RFC 6047). Implements the RFC 5546 REQUEST, REPLY,
// CANCEL, COUNTER, and DECLINECOUNTER messages.

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
)

// iTIP method types (RFC 5546).
const (
	MethodRequest        = "REQUEST"
	MethodReply          = "REPLY"
	MethodCancel         = "CANCEL"
	MethodCounter        = "COUNTER"
	MethodDeclineCounter = "DECLINECOUNTER"
)

// Participation status values used in scheduling responses (RFC 5545 §3.2.12).
const (
	PartStatAccepted  = "ACCEPTED"
	PartStatDeclined  = "DECLINED"
	PartStatTentative = "TENTATIVE"
)

const itipProductID = "-//Veksel//CalDAV//EN"

// ITIPMessage represents a parsed iTIP scheduling message.
type ITIPMessage struct {
	// Method is the upper-cased iTIP method (REQUEST, REPLY, CANCEL, ...).
	Method string

	// UID is the event UID from the VEVENT component.
	UID string

	// Seq is the sequence number (SEQUENCE property).
	Seq int

	// Organizer is the organizer's calendar address.
	Organizer string

	// Attendees are the ATTENDEE properties with their parameters.
	Attendees []Attendee

	// Summary, Description and Location are the unescaped event texts.
	Summary     string
	Description string
	Location    string

	// Comment is the sender's COMMENT, such as a note sent with a reply.
	Comment string

	// DTStart and DTEnd are the event start and end times.
	DTStart time.Time
	DTEnd   time.Time

	// Raw is the raw iCalendar data.
	Raw []byte

	// cal and event retain the decoded message so responses can copy
	// properties (with their parameters) and VTIMEZONE definitions verbatim.
	cal   *ical.Calendar
	event ical.Event
}

// Event returns the decoded event the message describes, for properties the
// parsed fields do not carry (DTSTAMP, RECURRENCE-ID parameters). Callers must
// not modify it.
func (m *ITIPMessage) Event() ical.Event { return m.event }

// Attendee represents an ATTENDEE property in an iTIP message.
type Attendee struct {
	CalendarAddress string
	CommonName      string
	PartStat        string
	Rsvp            bool
	Role            string
	DelegatedTo     []string
	DelegatedFrom   []string
}

// ParseITIP parses an iTIP scheduling message from raw iCalendar data.
// Recurrence overrides are ignored in favour of the master event.
func ParseITIP(data []byte) (*ITIPMessage, error) {
	cal, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("iTIP: %w", err)
	}
	event := MasterEvent(cal.Events())
	msg := &ITIPMessage{Raw: data, cal: cal, event: event}

	if method := cal.Props.Get(ical.PropMethod); method != nil {
		msg.Method = strings.ToUpper(strings.TrimSpace(method.Value))
	}
	msg.UID, _ = event.Props.Text(ical.PropUID)
	if msg.UID == "" {
		return nil, fmt.Errorf("iTIP: missing UID in VEVENT")
	}
	if seq := event.Props.Get(ical.PropSequence); seq != nil {
		if msg.Seq, err = seq.Int(); err != nil {
			return nil, fmt.Errorf("iTIP: invalid SEQUENCE: %w", err)
		}
	}
	if organizer := event.Props.Get(ical.PropOrganizer); organizer != nil {
		msg.Organizer = strings.TrimSpace(organizer.Value)
	}
	msg.Summary, _ = event.Props.Text(ical.PropSummary)
	msg.Description, _ = event.Props.Text(ical.PropDescription)
	msg.Location, _ = event.Props.Text(ical.PropLocation)
	msg.Comment, _ = event.Props.Text(ical.PropComment)
	msg.DTStart, _ = event.DateTimeStart(time.UTC)
	msg.DTEnd, _ = event.DateTimeEnd(time.UTC)

	for _, prop := range event.Props.Values(ical.PropAttendee) {
		msg.Attendees = append(msg.Attendees, Attendee{
			CalendarAddress: strings.TrimSpace(prop.Value),
			CommonName:      prop.Params.Get(ical.ParamCommonName),
			PartStat:        strings.ToUpper(prop.Params.Get(ical.ParamParticipationStatus)),
			Rsvp:            strings.EqualFold(prop.Params.Get(ical.ParamRSVP), "TRUE"),
			Role:            strings.ToUpper(prop.Params.Get(ical.ParamRole)),
			DelegatedTo:     prop.Params.Values(ical.ParamDelegatedTo),
			DelegatedFrom:   prop.Params.Values(ical.ParamDelegatedFrom),
		})
	}
	return msg, nil
}

// BuildReply builds a REPLY (RFC 5546 §3.2.3) for the given REQUEST. The
// reply carries exactly one ATTENDEE: the responder, with partStat set.
func BuildReply(request *ITIPMessage, responderAddress string, partStat string) ([]byte, error) {
	cal, event, source := newiTIPResponse(request, MethodReply, request.Seq)
	copyProps(event.Props, source, ical.PropOrganizer, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDuration, ical.PropSummary)
	event.Props.Add(respondingAttendee(source, responderAddress, partStat))
	return encodeiTIP(cal)
}

// BuildCancel builds a CANCEL (RFC 5546 §3.2.5) for the whole event from the
// organizer, bumping SEQUENCE and listing every attendee being removed.
func BuildCancel(request *ITIPMessage) ([]byte, error) {
	cal, event, source := newiTIPResponse(request, MethodCancel, request.Seq+1)
	copyProps(event.Props, source, ical.PropOrganizer, ical.PropAttendee, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDuration, ical.PropSummary)
	event.SetStatus(ical.EventCancelled)
	return encodeiTIP(cal)
}

// BuildCounter builds a COUNTER (RFC 5546 §3.2.7) in which the responding
// attendee proposes new start and end times. ORGANIZER and SEQUENCE are those
// of the original request.
func BuildCounter(request *ITIPMessage, responderAddress string, newStart, newEnd time.Time) ([]byte, error) {
	cal, event, source := newiTIPResponse(request, MethodCounter, request.Seq)
	copyProps(event.Props, source, ical.PropOrganizer, ical.PropSummary, ical.PropDescription, ical.PropLocation)
	event.Props.SetDateTime(ical.PropDateTimeStart, newStart.UTC())
	event.Props.SetDateTime(ical.PropDateTimeEnd, newEnd.UTC())
	event.Props.Add(respondingAttendee(source, responderAddress, PartStatTentative))
	for _, attendee := range source.Values(ical.PropAttendee) {
		if !SameCalAddress(attendee.Value, responderAddress) {
			event.Props.Add(&attendee)
		}
	}
	return encodeiTIP(cal)
}

// BuildDeclineCounter builds a DECLINECOUNTER (RFC 5546 §3.2.8) from the
// organizer rejecting a COUNTER. It echoes the counter's attendees, which
// include the attendee that proposed the change.
func BuildDeclineCounter(counter *ITIPMessage, organizerAddress string) ([]byte, error) {
	cal, event, source := newiTIPResponse(counter, MethodDeclineCounter, counter.Seq)
	organizer := source.Get(ical.PropOrganizer)
	if organizer == nil || !SameCalAddress(organizer.Value, organizerAddress) {
		organizer = ical.NewProp(ical.PropOrganizer)
		organizer.Value = organizerAddress
	}
	event.Props.Set(organizer)
	copyProps(event.Props, source, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDuration, ical.PropSummary)
	for _, attendee := range source.Values(ical.PropAttendee) {
		if !SameCalAddress(attendee.Value, organizerAddress) {
			event.Props.Add(&attendee)
		}
	}
	return encodeiTIP(cal)
}

// WithComment adds a COMMENT (RFC 5545 §3.8.1.4) to the event of an encoded
// iTIP message, such as the note an attendee sends with a REPLY or COUNTER.
// An empty comment returns data unchanged.
func WithComment(data []byte, comment string) ([]byte, error) {
	comment = strings.TrimSpace(comment)
	if comment == "" {
		return data, nil
	}
	if len(comment) > 2000 {
		return nil, fmt.Errorf("iTIP: comment is longer than 2000 bytes")
	}
	cal, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("iTIP: %w", err)
	}
	for _, event := range cal.Events() {
		event.Props.SetText(ical.PropComment, comment)
	}
	return encodeiTIP(cal)
}

// newiTIPResponse starts a response calendar for msg with the given method
// and sequence. It returns the new event and a private copy of the source
// event's properties that the caller may move into the response.
func newiTIPResponse(msg *ITIPMessage, method string, seq int) (*ical.Calendar, *ical.Event, ical.Props) {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, itipProductID)
	cal.Props.SetText(ical.PropMethod, method)
	// Copied DTSTART/DTEND/RECURRENCE-ID values may reference a TZID.
	for _, child := range msg.cal.Children {
		if child.Name == ical.CompTimezone {
			cal.Children = append(cal.Children, child)
		}
	}

	source := CloneProps(msg.event.Props)
	event := ical.NewEvent()
	event.Props.SetText(ical.PropUID, msg.UID)
	event.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
	sequence := ical.NewProp(ical.PropSequence)
	sequence.Value = strconv.Itoa(seq)
	event.Props.Set(sequence)
	copyProps(event.Props, source, ical.PropRecurrenceID)
	cal.Children = append(cal.Children, event.Component)
	return cal, event, source
}

// copyProps moves every instance of the named properties from source to dst.
func copyProps(dst, source ical.Props, names ...string) {
	for _, name := range names {
		if values := source[name]; len(values) > 0 {
			dst[name] = values
		}
	}
}

// respondingAttendee returns the responder's ATTENDEE property from source,
// preserving parameters such as CN and ROLE, or a new one if the responder was
// not invited. PARTSTAT is replaced and the RSVP request is dropped.
func respondingAttendee(source ical.Props, address, partStat string) *ical.Prop {
	var attendee *ical.Prop
	for _, candidate := range source.Values(ical.PropAttendee) {
		if SameCalAddress(candidate.Value, address) {
			attendee = &candidate
			break
		}
	}
	if attendee == nil {
		attendee = ical.NewProp(ical.PropAttendee)
		attendee.Value = address
	}
	attendee.Params.Set(ical.ParamParticipationStatus, partStat)
	attendee.Params.Del(ical.ParamRSVP)
	return attendee
}

// SameCalAddress compares calendar user addresses; the mailto scheme and mail
// domains are case-insensitive and clients commonly vary local-part case.
func SameCalAddress(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func encodeiTIP(cal *ical.Calendar) ([]byte, error) {
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, fmt.Errorf("iTIP: encode: %w", err)
	}
	return buf.Bytes(), nil
}
