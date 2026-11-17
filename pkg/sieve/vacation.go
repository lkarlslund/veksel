package sieve

import (
	"crypto/sha256"
	"encoding/hex"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// Vacation response periods (RFC 5230 section 4.1, RFC 6131): :days
// defaults to 7 and is at least 1; :seconds may be 0, meaning always reply.
const (
	defaultVacationDays = 7
	maxVacationPeriod   = 365 * 24 * time.Hour
)

// vacationRecipientHeaders are searched for the user's address before
// replying (RFC 5230 section 4.5).
var vacationRecipientHeaders = []string{"to", "cc", "bcc", "resent-to", "resent-cc", "resent-bcc"}

var listHeaders = []string{"list-id", "list-help", "list-subscribe", "list-unsubscribe", "list-post", "list-owner", "list-archive"}

func (i *Interpreter) executeVacation(c *VacationCommand) error {
	if i.vacationRan {
		return &RuntimeError{Msg: "vacation executed more than once"}
	}
	i.vacationRan = true
	subject, from, reason, handle := i.expand(c.Subject), i.expand(c.From), i.expand(c.Reason), i.expand(c.Handle)
	if handle == "" {
		// RFC 5230 section 4.2: without :handle, replies that differ in
		// their arguments are tracked separately.
		sum := sha256.Sum256([]byte(strings.Join([]string{subject, from, strconv.FormatBool(c.Mime), reason}, "\x00")))
		handle = hex.EncodeToString(sum[:16])
	}
	if from != "" {
		if _, err := mail.ParseAddress(from); err != nil {
			from = ""
		}
	}
	if from == "" {
		from = strings.Trim(strings.TrimSpace(i.msg.EnvelopeTo), "<>")
	}
	sender := strings.Trim(strings.TrimSpace(i.msg.EnvelopeFrom), "<>")
	if !i.vacationAllowed(sender, i.expandAll(c.Addresses)) {
		log.Debug("sieve: vacation suppressed", "sender", sender)
		return nil
	}
	if subject == "" {
		if original := i.firstHeader("subject"); original != "" {
			subject = "Auto: " + original
		} else {
			subject = "Automatic reply"
		}
	}
	messageID := strings.TrimSpace(i.firstRawHeader("message-id"))
	references := ""
	if messageID != "" {
		references = strings.TrimSpace(strings.Join(strings.Fields(i.firstRawHeader("references")+" "+messageID), " "))
	}
	i.vacation = &VacationResult{
		Subject: subject, Body: reason, Mime: c.Mime, From: from, To: sender,
		MessageID: messageID, References: references, Handle: handle, Period: vacationPeriod(c),
	}
	return nil
}

func vacationPeriod(c *VacationCommand) time.Duration {
	if c.HasSeconds {
		return time.Duration(min(c.Seconds, int64(maxVacationPeriod/time.Second))) * time.Second
	}
	days := int64(defaultVacationDays)
	if c.HasDays {
		days = max(1, min(c.Days, int64(maxVacationPeriod/(24*time.Hour))))
	}
	return time.Duration(days) * 24 * time.Hour
}

func (i *Interpreter) firstRawHeader(name string) string {
	if values := i.msg.Headers[name]; len(values) > 0 {
		return values[0]
	}
	return ""
}

func (i *Interpreter) firstHeader(name string) string { return decodeHeader(i.firstRawHeader(name)) }

// vacationAllowed applies the RFC 5230 section 4.5 and 4.6 rules: no reply
// to the null sender, to automated or list mail, to the user's own
// addresses, or to mail that does not name the user as a recipient.
func (i *Interpreter) vacationAllowed(sender string, addresses []string) bool {
	if sender == "" {
		return false
	}
	if auto := strings.TrimSpace(i.firstRawHeader("auto-submitted")); auto != "" && !strings.EqualFold(auto, "no") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(i.firstRawHeader("precedence"))) {
	case "bulk", "list", "junk":
		return false
	}
	for _, name := range listHeaders {
		if len(i.msg.Headers[name]) > 0 {
			return false
		}
	}
	local, _, _ := splitAddress(strings.ToLower(sender))
	if strings.HasPrefix(local, "owner-") || strings.HasSuffix(local, "-request") || strings.HasSuffix(local, "-owner") ||
		local == "mailer-daemon" || local == "listserv" || local == "majordomo" {
		return false
	}
	own := append([]string(nil), addresses...)
	if to := strings.Trim(strings.TrimSpace(i.msg.EnvelopeTo), "<>"); to != "" {
		own = append(own, to)
	}
	for index, address := range own {
		if parsed, err := mail.ParseAddress(address); err == nil {
			own[index] = parsed.Address
		}
	}
	if i.ownAddress(own, sender) {
		return false
	}
	for _, name := range vacationRecipientHeaders {
		for _, value := range i.msg.Headers[name] {
			for _, recipient := range parseAddressList(value) {
				if i.ownAddress(own, recipient) {
					return true
				}
			}
		}
	}
	return false
}

// ownAddress reports that address is one of own, ignoring case and any
// subaddress detail.
func (i *Interpreter) ownAddress(own []string, address string) bool {
	base := func(address string) string {
		local, domain, _ := splitAddress(strings.ToLower(address))
		user, _, _ := model.SplitSubaddress(local, i.msg.SubaddressDelimiters)
		return user + "@" + domain
	}
	for _, candidate := range own {
		if strings.EqualFold(candidate, address) || base(candidate) == base(address) {
			return true
		}
	}
	return false
}
