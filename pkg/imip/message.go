package imip

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"slices"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/mailidentity"
)

const (
	// maxCalendarBytes bounds every calendar object iMIP parses or keeps.
	maxCalendarBytes = 256 << 10
	// maxCalendarComponents bounds the VEVENTs (master plus overrides) of
	// one scheduled object.
	maxCalendarComponents = 200

	productID = "-//Veksel//iMIP//EN"

	paramScheduleAgent     = "SCHEDULE-AGENT"
	paramScheduleStatus    = "SCHEDULE-STATUS"
	paramScheduleForceSend = "SCHEDULE-FORCE-SEND"
)

// decodeBounded decodes a calendar object within the iMIP size limits.
func decodeBounded(data []byte) (*ical.Calendar, error) {
	if len(data) > maxCalendarBytes {
		return nil, errors.New("calendar object is too large")
	}
	cal, err := calendar.Decode(data)
	if err != nil {
		return nil, err
	}
	if len(cal.Events()) > maxCalendarComponents {
		return nil, errors.New("calendar object has too many events")
	}
	return cal, nil
}

func encode(cal *ical.Calendar) ([]byte, error) {
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, fmt.Errorf("encode iCalendar: %w", err)
	}
	return buf.Bytes(), nil
}

func propAddress(props ical.Props, name string) string {
	if prop := props.Get(name); prop != nil {
		return calendar.MailAddress(prop.Value)
	}
	return ""
}

func sequence(props ical.Props) int {
	if prop := props.Get(ical.PropSequence); prop != nil {
		if value, err := prop.Int(); err == nil {
			return value
		}
	}
	return 0
}

// dateTimeStamp is an event's DTSTAMP, zero when absent or invalid.
func dateTimeStamp(event ical.Event) time.Time {
	stamp, err := event.Props.DateTime(ical.PropDateTimeStamp, time.UTC)
	if err != nil {
		return time.Time{}
	}
	return stamp
}

func eventStatus(props ical.Props) string {
	if prop := props.Get(ical.PropStatus); prop != nil {
		return strings.ToUpper(strings.TrimSpace(prop.Value))
	}
	return ""
}

// timing digests every property that decides when an event happens, across
// the master event and its overrides, so a schedule change is detected even
// when the client did not bump SEQUENCE.
func timing(cal *ical.Calendar) string {
	var parts []string
	for _, event := range cal.Events() {
		for _, name := range []string{ical.PropRecurrenceID, ical.PropDateTimeStart, ical.PropDateTimeEnd, ical.PropDuration, ical.PropRecurrenceRule, ical.PropRecurrenceDates, ical.PropExceptionDates} {
			for _, prop := range event.Props.Values(name) {
				parts = append(parts, name+";"+prop.Params.Get(ical.PropTimezoneID)+":"+prop.Value)
			}
		}
		parts = append(parts, "|")
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(digest[:])
}

// content digests the master event texts that local attendee copies follow.
func content(props ical.Props) string {
	var parts []string
	for _, name := range []string{ical.PropSummary, ical.PropDescription, ical.PropLocation, ical.PropStatus, ical.PropURL} {
		if prop := props.Get(name); prop != nil {
			parts = append(parts, name+":"+prop.Value)
		}
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(digest[:12])
}

// scheduledAttendees lists the attendee addresses the server schedules for:
// every ATTENDEE except the organizer and those whose client handles
// scheduling itself (SCHEDULE-AGENT=CLIENT or NONE, RFC 6638 §7.1).
func scheduledAttendees(cal *ical.Calendar, organizer string) []string {
	var addresses []string
	for _, event := range cal.Events() {
		for _, attendee := range event.Props.Values(ical.PropAttendee) {
			agent := strings.ToUpper(strings.TrimSpace(attendee.Params.Get(paramScheduleAgent)))
			if agent != "" && agent != "SERVER" {
				continue
			}
			address := calendar.MailAddress(attendee.Value)
			if !strings.Contains(address, "@") || address == organizer || slices.Contains(addresses, address) {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	return addresses
}

// stripScheduling removes the CalDAV-only scheduling parameters and private
// alarms that never travel in an iTIP message (RFC 6638 §7.1–7.3).
func stripScheduling(cal *ical.Calendar) {
	for _, child := range cal.Children {
		if child.Name != ical.CompEvent {
			continue
		}
		children := child.Children[:0]
		for _, nested := range child.Children {
			if nested.Name != ical.CompAlarm {
				children = append(children, nested)
			}
		}
		child.Children = children
		for _, name := range []string{ical.PropOrganizer, ical.PropAttendee} {
			for index := range child.Props[name] {
				params := child.Props[name][index].Params
				params.Del(paramScheduleAgent)
				params.Del(paramScheduleStatus)
				params.Del(paramScheduleForceSend)
			}
		}
	}
}

// requestCalendar turns an organizer's stored calendar object into an iTIP
// REQUEST carrying every event component.
func requestCalendar(source []byte, now time.Time) ([]byte, error) {
	cal, err := decodeBounded(source)
	if err != nil {
		return nil, err
	}
	stripScheduling(cal)
	cal.Props.SetText(ical.PropProductID, productID)
	cal.Props.SetText(ical.PropMethod, calendar.MethodRequest)
	for _, event := range cal.Events() {
		event.Props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	}
	return encode(cal)
}

// cancelCalendar builds an iTIP CANCEL from the last scheduled source for the
// given attendees only, so removed attendees learn they were uninvited while
// the others keep their invitation.
func cancelCalendar(source []byte, attendees []string) ([]byte, error) {
	cal, err := decodeBounded(source)
	if err != nil {
		return nil, err
	}
	stripScheduling(cal)
	for _, event := range cal.Events() {
		kept := event.Props[ical.PropAttendee][:0]
		for _, attendee := range event.Props[ical.PropAttendee] {
			if slices.Contains(attendees, calendar.MailAddress(attendee.Value)) {
				kept = append(kept, attendee)
			}
		}
		event.Props[ical.PropAttendee] = kept
	}
	filtered, err := encode(cal)
	if err != nil {
		return nil, err
	}
	message, err := calendar.ParseITIP(filtered)
	if err != nil {
		return nil, err
	}
	return calendar.BuildCancel(message)
}

// mailContent is the human-readable side of an iMIP message.
type mailContent struct {
	From     *mail.Address
	To       []string
	Subject  string
	Text     string
	Method   string
	Calendar []byte
}

// summaryText describes an event in the text/plain alternative.
func summaryText(intro string, message *calendar.ITIPMessage) string {
	var text strings.Builder
	text.WriteString(intro + "\r\n\r\n")
	title := message.Summary
	if title == "" {
		title = "(untitled event)"
	}
	fmt.Fprintf(&text, "Event:     %s\r\n", title)
	if !message.DTStart.IsZero() {
		when := message.DTStart.UTC().Format("Mon 2 Jan 2006 15:04 MST")
		if !message.DTEnd.IsZero() {
			when += " – " + message.DTEnd.UTC().Format("Mon 2 Jan 2006 15:04 MST")
		}
		fmt.Fprintf(&text, "When:      %s\r\n", when)
	}
	if message.Location != "" {
		fmt.Fprintf(&text, "Where:     %s\r\n", message.Location)
	}
	if message.Organizer != "" {
		fmt.Fprintf(&text, "Organizer: %s\r\n", calendar.MailAddress(message.Organizer))
	}
	if message.Description != "" {
		text.WriteString("\r\n" + message.Description + "\r\n")
	}
	return text.String()
}

// buildMail assembles an RFC 6047 message: a multipart/alternative of the
// text summary and the text/calendar part with its METHOD, plus the same
// calendar as an application/ics attachment for clients (notably Outlook)
// that only act on attachments.
func buildMail(content mailContent, now time.Time) ([]byte, error) {
	if content.From == nil || len(content.To) == 0 {
		return nil, errors.New("iMIP message requires a sender and recipients")
	}
	var body bytes.Buffer
	mixed := multipart.NewWriter(&body)
	var alternative bytes.Buffer
	inner := multipart.NewWriter(&alternative)

	textPart, err := inner.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/plain; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	qp := quotedprintable.NewWriter(textPart)
	if _, err := qp.Write([]byte(content.Text)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	calendarType := mime.FormatMediaType("text/calendar", map[string]string{"method": content.Method, "charset": "utf-8"})
	calendarPart, err := inner.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {calendarType},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	writeBase64(calendarPart, content.Calendar)
	if err := inner.Close(); err != nil {
		return nil, err
	}

	alternativePart, err := mixed.CreatePart(textproto.MIMEHeader{
		"Content-Type": {mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": inner.Boundary()})},
	})
	if err != nil {
		return nil, err
	}
	if _, err := alternativePart.Write(alternative.Bytes()); err != nil {
		return nil, err
	}
	name := strings.ToLower(content.Method) + ".ics"
	attachment, err := mixed.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {mime.FormatMediaType("application/ics", map[string]string{"name": name})},
		"Content-Disposition":       {mime.FormatMediaType("attachment", map[string]string{"filename": name})},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	writeBase64(attachment, content.Calendar)
	if err := mixed.Close(); err != nil {
		return nil, err
	}

	domain := mailidentity.MessageIDDomain(content.From.Address, "")
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	var message bytes.Buffer
	header := func(name, value string) { message.WriteString(name + ": " + value + "\r\n") }
	header("From", content.From.String())
	header("To", strings.Join(content.To, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", content.Subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<imip-"+hex.EncodeToString(token)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": mixed.Boundary()}))
	message.WriteString("\r\n")
	message.Write(body.Bytes())
	return message.Bytes(), nil
}

func writeBase64(w interface{ Write([]byte) (int, error) }, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 76 {
		_, _ = w.Write([]byte(encoded[:76] + "\r\n"))
		encoded = encoded[76:]
	}
	_, _ = w.Write([]byte(encoded + "\r\n"))
}

// sender formats the organizer or attendee identity with its calendar CN.
func sender(address, name string) *mail.Address {
	return &mail.Address{Name: strings.TrimSpace(name), Address: address}
}

// subjectFor labels an iMIP message the way common clients do.
func subjectFor(method, partStat string, updated bool, summary string) string {
	if summary == "" {
		summary = "(untitled event)"
	}
	switch method {
	case calendar.MethodCancel:
		return "Cancelled: " + summary
	case calendar.MethodCounter:
		return "New time proposed: " + summary
	case calendar.MethodDeclineCounter:
		return "New time declined: " + summary
	case calendar.MethodReply:
		switch partStat {
		case calendar.PartStatAccepted:
			return "Accepted: " + summary
		case calendar.PartStatDeclined:
			return "Declined: " + summary
		default:
			return "Tentative: " + summary
		}
	}
	if updated {
		return "Updated invitation: " + summary
	}
	return "Invitation: " + summary
}
