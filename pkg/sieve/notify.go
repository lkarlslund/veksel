package sieve

import (
	"errors"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
)

// maxNotifications bounds the notify actions one script run may perform.
const (
	maxNotifications    = 8
	maxNotifyRecipients = 10
)

// mailtoNotification is a parsed RFC 5436 mailto notification URI.
type mailtoNotification struct {
	recipients []string
	subject    string
	body       string
}

// parseMailtoURI parses a mailto URI (RFC 6068) for the enotify mailto
// method. Recipients come from the path and the to, cc, and bcc header
// fields; subject and body are kept; RFC 5436 section 2.4 has every other
// header field ignored.
func parseMailtoURI(uri string) (mailtoNotification, error) {
	var n mailtoNotification
	scheme, rest, ok := strings.Cut(uri, ":")
	if !ok || !strings.EqualFold(scheme, "mailto") {
		return n, errors.New("unsupported notification method")
	}
	path, query, _ := strings.Cut(rest, "?")
	addRecipients := func(list string) error {
		for _, part := range strings.Split(list, ",") {
			decoded, err := url.PathUnescape(part)
			if err != nil {
				return err
			}
			if decoded = strings.TrimSpace(decoded); decoded == "" {
				continue
			}
			address, err := mail.ParseAddress(decoded)
			if err != nil {
				return err
			}
			n.recipients = append(n.recipients, address.Address)
		}
		return nil
	}
	if err := addRecipients(path); err != nil {
		return n, err
	}
	for field := range strings.SplitSeq(query, "&") {
		name, value, _ := strings.Cut(field, "=")
		decoded, err := url.PathUnescape(value)
		if err != nil {
			return n, err
		}
		switch strings.ToLower(name) {
		case "to", "cc", "bcc":
			if err := addRecipients(value); err != nil {
				return n, err
			}
		case "subject":
			n.subject = decoded
		case "body":
			n.body = decoded
		}
	}
	if len(n.recipients) == 0 {
		return n, errors.New("mailto URI without recipients")
	}
	return n, nil
}

func validImportance(importance string) bool {
	return importance == "1" || importance == "2" || importance == "3"
}

// encodeURL percent-encodes every character outside the RFC 3986
// unreserved set (the RFC 5435 :encodeurl set modifier).
func encodeURL(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(strconv.FormatUint(uint64(c)>>4, 16)+strconv.FormatUint(uint64(c)&15, 16)))
	}
	return b.String()
}

func (i *Interpreter) executeNotify(c *NotifyCommand) error {
	method := i.expand(c.Method)
	target, err := parseMailtoURI(method)
	if err != nil {
		return &RuntimeError{Msg: "invalid notification method " + strconv.Quote(method)}
	}
	importance := i.expand(c.Importance)
	if importance == "" || !validImportance(importance) {
		importance = "2"
	}
	from := i.expand(c.From)
	if from != "" {
		if _, err := mail.ParseAddress(from); err != nil {
			from = ""
		}
	}
	message := i.expand(c.Message)
	if message == "" {
		// RFC 5435 section 3.5 leaves the default to the implementation.
		message = "New mail from " + i.firstHeader("from") + ": " + i.firstHeader("subject")
	}
	// RFC 5436 section 2.7: never notify about an automatically
	// submitted message, so notifications cannot loop.
	if auto := strings.TrimSpace(i.firstRawHeader("auto-submitted")); auto != "" && !strings.EqualFold(auto, "no") {
		return nil
	}
	for _, existing := range i.notifications {
		if existing.Method == method {
			return nil // RFC 5435 section 3.10: no duplicate notifications
		}
	}
	if len(i.notifications) >= maxNotifications {
		return &RuntimeError{Msg: "too many notifications"}
	}
	if len(target.recipients) > maxNotifyRecipients {
		return &RuntimeError{Msg: "too many notification recipients"}
	}
	subject, body := target.subject, target.body
	if subject == "" {
		subject = message
	}
	if body == "" {
		body = message
	}
	i.notifications = append(i.notifications, NotifyResult{
		Method: method, To: target.recipients, From: from, Subject: truncateUTF8(subject, 256),
		Message: body, Importance: importance,
	})
	return nil
}

// notifyCapability answers notify_method_capability for a mailto URI: the
// only capability defined, "online", is "maybe" (RFC 5436 section 2.6).
func notifyCapability(uri, capability string) (string, bool) {
	if _, err := parseMailtoURI(uri); err != nil || !strings.EqualFold(capability, "online") {
		return "", false
	}
	return "maybe", true
}
