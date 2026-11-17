package smtp

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"mime"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/sieve"
)

// sieveScriptError is a script that cannot be parsed or run. Delivery falls
// back to the default mailbox for it, and only for it: an error applying the
// script's actions comes after some of them may already have been applied.
type sieveScriptError struct{ err error }

func (e sieveScriptError) Error() string { return e.err.Error() }
func (e sieveScriptError) Unwrap() error { return e.err }

// runSieve executes a Sieve script and applies the result.
func (s *Session) runSieve(script string, fullMsg []byte, userID, defaultFolderID string, headers map[string]string, body []byte) (*sieve.Result, error) {
	msg := sieve.NewMessage(fullMsg)
	msg.EnvelopeFrom, msg.EnvelopeTo = s.envelopeSender, s.deliveryRecipient
	if s.cfg.Delivery.RecipientDelimiters != nil {
		msg.SubaddressDelimiters = s.cfg.Delivery.RecipientDelimiters()
	}
	if s.cfg.Delivery.GetFolderIDByPath != nil {
		// mailboxexists (RFC 5490): only the recipient's own folders are
		// fileinto targets, so resolving the path is the permission check.
		msg.MailboxExists = func(name string) bool {
			_, err := s.cfg.Delivery.GetFolderIDByPath(s.ctx, userID, name)
			return err == nil
		}
	}

	ast, err := sieve.Parse(script)
	if err != nil {
		return nil, sieveScriptError{fmt.Errorf("parse sieve: %w", err)}
	}
	result, err := sieve.NewInterpreter(msg).Run(ast)
	if err != nil {
		return nil, sieveScriptError{fmt.Errorf("run sieve: %w", err)}
	}

	// reject and ereject (RFC 5429) refuse the message in the SMTP dialogue;
	// the interpreter has already refused to combine them with delivery.
	if result.RejectReason != "" {
		return nil, &PolicyRejectError{Reason: sieveRejectReason(result.RejectReason)}
	}

	// Redirects are ordinary outbound queue jobs in the same SMTP batch. This
	// makes redirect-only and :copy atomic with any retained local copy.
	if len(result.RedirectAddresses) > 0 {
		redirectedMessage, redirectHeaders, ok := prepareForwardedMessage(userID, fullMsg, headers)
		if !ok {
			// A forwarding loop must not lose the message: file it locally
			// when the script delivers it nowhere else.
			if len(result.FileIntoFolders) == 0 {
				result.Kept = true
			}
		} else {
			redirectSender := s.forwardSender(s.envelopeSender)
			redirectedMessage = s.forwardSealer(s.deliveryRecipient)(redirectedMessage)
			for index, redirectAddr := range result.RedirectAddresses {
				if err := validateEmailAddress(redirectAddr); err != nil {
					return nil, &FilterTemporaryError{Stage: "Sieve redirect", Err: err}
				}
				if s.cfg.Delivery.MailQueue == nil {
					return nil, &FilterTemporaryError{Stage: "Sieve redirect", Err: errors.New("mail queue is unavailable")}
				}
				if err := s.enqueueDelivery(&MailMessage{ID: fmt.Sprintf("smtp-redirect-%d-%d-%d", s.id, time.Now().UnixNano(), index+1), EnvelopeSender: redirectSender, Recipient: redirectAddr, Headers: redirectHeaders, Content: redirectedMessage, Outbound: true}); err != nil {
					return nil, &FilterTemporaryError{Stage: "Sieve redirect queue", Err: err}
				}
				logger.Info("smtp: sieve redirect staged", "user", userID, "to", redirectAddr, "kept", result.Kept)
			}
		}
	}

	// Notifications (RFC 5435 enotify, RFC 5436 mailto) join the batch.
	for _, notify := range result.NotifyRequests {
		notifyCopy, headerCopy := notify, cloneSMTPHeaders(headers)
		notifyCopy.To = append([]string(nil), notify.To...)
		correlation := s.deliveryCorrelationID
		if s.stagingDelivery && s.cfg.Delivery.PrepareDerived != nil {
			if err := s.handleSieveNotify(notifyCopy, userID, headerCopy, "", correlation); err != nil {
				return nil, &FilterTemporaryError{Stage: "Sieve notify queue", Err: err}
			}
		} else {
			s.afterDeliveryCommit(func() { _ = s.handleSieveNotify(notifyCopy, userID, headerCopy, "", correlation) })
		}
	}

	// Handle vacation auto-reply (RFC 5230)
	if result.VacationReply != nil {
		vacationCopy, headerCopy := *result.VacationReply, cloneSMTPHeaders(headers)
		correlation := s.deliveryCorrelationID
		if s.stagingDelivery && s.cfg.Delivery.PrepareDerived != nil {
			if err := s.stageSieveVacation(&vacationCopy, userID, headerCopy, "", correlation); err != nil {
				return nil, &FilterTemporaryError{Stage: "Sieve vacation queue", Err: err}
			}
		} else {
			s.afterDeliveryCommit(func() { s.handleSieveVacation(&vacationCopy, userID, headerCopy, "", correlation) })
		}
	}

	if s.cfg.Delivery.MailQueue == nil && s.cfg.Delivery.AppendFolderItem == nil && s.cfg.Delivery.AppendMessage == nil {
		return result, nil
	}
	modifiedMsg := s.composeMessage(headers, body)
	delivered := make(map[string]bool)
	deliver := func(folderID string) error {
		if delivered[folderID] {
			return nil // RFC 5228 section 2.10.3: one copy per mailbox
		}
		delivered[folderID] = true
		_, err := s.appendFolderItem(userID, folderID, modifiedMsg, headers)
		if err == nil && s.cfg.Delivery.NotifyIMAPIdle != nil {
			s.afterDeliveryCommit(func() { s.cfg.Delivery.NotifyIMAPIdle(folderID) })
		}
		return err
	}
	for _, folder := range result.FileIntoFolders {
		targetFolderID, unresolvedPath := s.resolveSieveFolder(userID, folder)
		if unresolvedPath != "" {
			if delivered["path:"+unresolvedPath] {
				continue
			}
			delivered["path:"+unresolvedPath] = true
			message := &MailMessage{ID: fmt.Sprintf("smtp-fileinto-%d-%d-%d", s.id, time.Now().UnixNano(), len(s.stagedDeliveries)+1), EnvelopeSender: s.envelopeSender, Headers: headers, Content: modifiedMsg, TargetFolderPath: unresolvedPath, TargetOwnerID: userID}
			if err := s.enqueueDelivery(message); err != nil {
				return result, err
			}
			continue
		}
		if err := deliver(targetFolderID); err != nil {
			return result, err
		}
	}
	if result.Kept {
		if err := deliver(defaultFolderID); err != nil {
			return result, err
		}
	}
	return result, nil
}

// resolveSieveFolder maps a fileinto mailbox name to a folder ID. With a
// mail queue an unknown path is returned as unresolved so the queue creates
// it atomically with the delivery; otherwise it is created here. This is the
// RFC 5490 fileinto :create behaviour (Result.CreateFolders); Veksel applies
// it to plain fileinto as well, which RFC 5228 section 4.1 permits, so a
// missing mailbox never silently diverts mail to the implicit keep.
func (s *Session) resolveSieveFolder(userID, path string) (folderID, unresolvedPath string) {
	if s.cfg.Delivery.GetFolderIDByPath == nil {
		return path, ""
	}
	resolved, err := s.cfg.Delivery.GetFolderIDByPath(s.ctx, userID, path)
	switch {
	case err == nil:
		return resolved, ""
	case s.cfg.Delivery.MailQueue != nil:
		return "", path
	case s.cfg.Delivery.CreateFolder != nil:
		if err := s.cfg.Delivery.CreateFolder(s.ctx, userID, path, "mail", ""); err == nil {
			if resolved, err := s.cfg.Delivery.GetFolderIDByPath(s.ctx, userID, path); err == nil {
				return resolved, ""
			}
		}
	}
	return path, ""
}

// sieveRejectReason makes a reject reason safe for one SMTP reply line:
// line breaks and control characters become spaces and the text is capped.
func sieveRejectReason(reason string) string {
	reason = strings.Join(strings.FieldsFunc(reason, func(r rune) bool { return r < 0x20 || r == 0x7f || r == ' ' }), " ")
	if len(reason) > 200 {
		cut := 200
		for cut > 0 && !utf8.RuneStart(reason[cut]) {
			cut--
		}
		reason = reason[:cut]
	}
	if reason == "" {
		return "Message rejected"
	}
	return reason
}

// handleForwarding checks if the user has mail forwarding enabled and
// sends a copy of the message to the forwarding address.
const maxForwardHops = 10

// seal ARC-seals the forwarded bytes; nil forwards them unsealed.
func (s *Session) handleForwarding(userID, envelopeSender string, fullMsg []byte, headers map[string]string, parentID, correlationID string, seal func([]byte) []byte) error {
	if (s.cfg.Delivery.ResolveForwardTo == nil && s.cfg.Delivery.GetForwardTo == nil) || (s.cfg.Delivery.PrepareDerived == nil && s.cfg.Delivery.SendDerived == nil && s.cfg.Delivery.SendForward == nil) {
		return nil
	}

	forwardTo := ""
	if s.cfg.Delivery.ResolveForwardTo != nil {
		var err error
		forwardTo, err = s.cfg.Delivery.ResolveForwardTo(context.Background(), userID)
		if err != nil {
			return fmt.Errorf("resolve forwarding policy: %w", err)
		}
	} else {
		forwardTo = s.cfg.Delivery.GetForwardTo(context.Background(), userID)
	}
	if forwardTo == "" {
		return nil
	}

	forwardedMessage, _, ok := prepareForwardedMessage(userID, fullMsg, headers)
	if !ok {
		logger.Warn("smtp: forwarding loop suppressed", "user", userID, "to", forwardTo)
		return nil
	}
	if seal != nil {
		forwardedMessage = seal(forwardedMessage)
	}
	if err := s.sendDerivedMessage(DerivedMessage{Kind: "forward", Recipient: forwardTo, EnvelopeSender: s.forwardSender(envelopeSender), FullMessage: forwardedMessage, ParentID: parentID, CorrelationID: correlationID}); err != nil {
		logger.Error("smtp: forwarding failed", "user", userID, "to", forwardTo, "error", err)
		return err
	} else {
		logger.Info("smtp: message forwarded", "user", userID, "to", forwardTo)
	}
	return nil
}

// forwardSender is the envelope sender for a forward or redirect of mail
// from sender (SRS when configured).
func (s *Session) forwardSender(sender string) string {
	if s.cfg.Delivery.RewriteForwardSender == nil {
		return sender
	}
	return s.cfg.Delivery.RewriteForwardSender(context.Background(), sender)
}

func prepareForwardedMessage(userID string, fullMsg []byte, headers map[string]string) ([]byte, map[string]string, bool) {
	forwardedUsers := splitForwardedUsers(smtpHeaderValue(headers, "X-Veksel-Forwarded-By"))
	if slices.ContainsFunc(forwardedUsers, func(value string) bool { return strings.EqualFold(value, userID) }) {
		return nil, nil, false
	}
	hops, _ := strconv.Atoi(strings.TrimSpace(smtpHeaderValue(headers, "X-Veksel-Forward-Hop")))
	if hops >= maxForwardHops {
		return nil, nil, false
	}
	forwardHeaders := cloneSMTPHeaders(headers)
	forwardedUsers = append(forwardedUsers, userID)
	forwardHeaders["X-Veksel-Forwarded-By"] = strings.Join(forwardedUsers, ", ")
	forwardHeaders["X-Veksel-Forward-Hop"] = strconv.Itoa(hops + 1)
	_, body := model.ParseMessageHeaders(fullMsg)
	return model.RebuildMessage(fullMsg, forwardHeaders, body), forwardHeaders, true
}

func splitForwardedUsers(value string) []string {
	var users []string
	for _, user := range strings.Split(value, ",") {
		if user = strings.TrimSpace(user); user != "" {
			users = append(users, user)
		}
	}
	return users
}

// handleVacationReply checks if the user has vacation auto-reply enabled
// and sends a reply to the message sender if rate limits allow.
func (s *Session) handleVacationReply(userID, recipient, envelopeSender string, headers map[string]string, parentID, correlationID string) {
	if s.cfg.Delivery.VacationActive == nil || s.cfg.Delivery.VacationReply == nil || (s.cfg.Delivery.SendDerived == nil && s.cfg.Delivery.SendForward == nil) {
		return
	}
	if suppressAutomaticReply(envelopeSender, recipient, headers) {
		return
	}

	// Check if vacation is active
	if !s.cfg.Delivery.VacationActive(s.ctx, userID) {
		return
	}

	// Get the sender from the message
	sender := envelopeSender
	if sender == "" {
		return
	}

	// Check rate limiting
	reservation, allowed := s.reserveVacationReply(userID, sender)
	if !allowed {
		return
	}

	// Get vacation reply content
	subject, message := s.cfg.Delivery.VacationReply(s.ctx, userID)
	if subject == "" {
		subject = "Automatic reply"
	}

	// Build the auto-reply message
	replyHeaders := map[string]string{
		"From":           headers["To"], // Reply from the recipient
		"To":             sender,
		"Subject":        subject,
		"Date":           time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID":     generateMessageID(headers["To"], s.cfg.ServerName),
		"Auto-Submitted": "auto-replied",
		"Precedence":     "bulk",
	}

	if origMsgID := headers["Message-ID"]; origMsgID != "" {
		replyHeaders["In-Reply-To"] = origMsgID
		replyHeaders["References"] = origMsgID
	}

	replyBody := []byte(message)
	replyMsg := buildMessage(replyHeaders, replyBody)

	// Send the vacation reply
	if err := s.sendDerivedMessage(DerivedMessage{Kind: "vacation", Recipient: sender, FullMessage: replyMsg, ParentID: parentID, CorrelationID: correlationID, DKIM: s.originatedDKIM(userID, replyHeaders["From"])}); err != nil {
		s.finishVacationReply(userID, sender, reservation, false)
		logger.Error("smtp: vacation reply failed", "user", userID, "to", sender, "error", err)
		return
	}
	logger.Info("smtp: vacation reply sent", "user", userID, "to", sender)
	s.finishVacationReply(userID, sender, reservation, true)
}

func (s *Session) stageVacationReply(userID, recipient, envelopeSender string, headers map[string]string, parentID, correlationID string) error {
	if suppressAutomaticReply(envelopeSender, recipient, headers) {
		return nil
	}
	active, subject, message := false, "", ""
	if s.cfg.Delivery.ResolveVacation != nil {
		var err error
		active, subject, message, err = s.cfg.Delivery.ResolveVacation(context.Background(), userID)
		if err != nil {
			return fmt.Errorf("resolve vacation policy: %w", err)
		}
	} else if s.cfg.Delivery.VacationActive != nil && s.cfg.Delivery.VacationReply != nil {
		active = s.cfg.Delivery.VacationActive(context.Background(), userID)
		subject, message = s.cfg.Delivery.VacationReply(context.Background(), userID)
	}
	if !active {
		return nil
	}
	sender := strings.Trim(strings.TrimSpace(envelopeSender), "<>")
	if sender == "" {
		return nil
	}
	if subject == "" {
		subject = "Automatic reply"
	}
	replyHeaders := map[string]string{"From": headers["To"], "To": sender, "Subject": subject,
		"Date": time.Now().UTC().Format(time.RFC1123Z), "Message-ID": generateMessageID(headers["To"], s.cfg.ServerName), "Auto-Submitted": "auto-replied", "Precedence": "bulk"}
	if originalID := smtpHeaderValue(headers, "Message-ID"); originalID != "" {
		replyHeaders["In-Reply-To"], replyHeaders["References"] = originalID, originalID
	}
	return s.stageVacationIntent("vacation", userID, sender, replyHeaders, []byte(message), parentID, correlationID, nil)
}

func (s *Session) stageVacationIntent(kind, userID, sender string, replyHeaders map[string]string, body []byte, parentID, correlationID string, extra map[string]string) error {
	id := fmt.Sprintf("vacation-intent-%s-%s", correlationID, userID)
	for _, staged := range s.stagedDeliveries {
		if staged.ID == id {
			return nil
		}
	}
	attributes := map[string]string{"derived_kind": kind, "user_id": userID, "sender": sender}
	maps.Copy(attributes, extra)
	if s.originatedDKIM(userID, replyHeaders["From"]) != nil {
		attributes[AttributeDKIMSign] = "true"
	}
	return s.enqueueDelivery(&MailMessage{ID: id, Kind: MailTaskVacation, Attributes: attributes, Recipient: sender,
		Content: buildMessage(replyHeaders, body), ParentID: parentID, CorrelationID: correlationID})
}

// originatedDKIM requests a DKIM signature for mail the server writes for
// userID (vacation replies, Sieve notifications) only when from is an
// identity the user may send as. A Sieve :from, or a vacation reply's From
// copied from the incoming To header, is otherwise unvouched and stays
// unsigned.
func (s *Session) originatedDKIM(userID, from string) *dkim.Request {
	authorize := s.cfg.Delivery.AuthorizeSubmission
	address, err := mail.ParseAddress(from)
	if authorize == nil || err != nil || authorize(context.Background(), userID, address.Address, from, "") != nil {
		return nil
	}
	return &dkim.Request{}
}

func (s *Session) reserveVacationReply(userID, sender string) (string, bool) {
	delivery := s.cfg.Delivery
	if delivery.ReserveVacationReply != nil {
		token, ok, err := delivery.ReserveVacationReply(context.Background(), userID, sender)
		if err != nil {
			logger.Error("smtp: vacation reservation failed", "user", userID, "sender", sender, "error", err)
			return "", false
		}
		return token, ok
	}
	if delivery.ShouldVacationReply != nil && !delivery.ShouldVacationReply(context.Background(), userID, sender) {
		return "", false
	}
	return "", true
}

func (s *Session) finishVacationReply(userID, sender, token string, sent bool) {
	delivery := s.cfg.Delivery
	var err error
	if token != "" {
		if sent && delivery.CompleteVacationReply != nil {
			err = delivery.CompleteVacationReply(context.Background(), userID, sender, token)
		} else if !sent && delivery.CancelVacationReply != nil {
			err = delivery.CancelVacationReply(context.Background(), userID, sender, token)
		}
	} else if sent && delivery.RecordVacationReply != nil {
		err = delivery.RecordVacationReply(context.Background(), userID, sender)
	}
	if err != nil {
		logger.Error("smtp: update vacation rate limit failed", "user", userID, "sender", sender, "sent", sent, "error", err)
	}
}

func suppressAutomaticReply(envelopeSender, recipient string, headers map[string]string) bool {
	sender := strings.Trim(strings.TrimSpace(envelopeSender), "<>")
	if sender == "" || strings.EqualFold(sender, strings.Trim(strings.TrimSpace(recipient), "<>")) {
		return true
	}
	if value := strings.TrimSpace(smtpHeaderValue(headers, "Auto-Submitted")); value != "" && !strings.EqualFold(value, "no") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(smtpHeaderValue(headers, "Precedence"))) {
	case "bulk", "list", "junk":
		return true
	}
	return strings.TrimSpace(smtpHeaderValue(headers, "List-Id")) != "" || strings.TrimSpace(smtpHeaderValue(headers, "List-Unsubscribe")) != ""
}

func smtpHeaderValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// handleSieveNotify sends a Sieve mailto notification (RFC 5436). It is
// marked Auto-Submitted: auto-notified so that it cannot trigger further
// notifications or vacation replies.
func (s *Session) handleSieveNotify(notify sieve.NotifyResult, userID string, headers map[string]string, parentID, correlationID string) error {
	if s.cfg.Delivery.PrepareDerived == nil && s.cfg.Delivery.SendDerived == nil && s.cfg.Delivery.SendForward == nil {
		return nil
	}
	from := notify.From
	if from == "" {
		from = s.deliveryRecipient
		if from == "" {
			from = fmt.Sprintf("<%s>", userID)
		}
	}
	envelopeSender := from
	if address, err := mail.ParseAddress(from); err == nil {
		envelopeSender = address.Address
	}
	notifyHeaders := map[string]string{
		"From":                      from,
		"To":                        strings.Join(notify.To, ", "),
		"Subject":                   mime.QEncoding.Encode("utf-8", notify.Subject),
		"Date":                      time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID":                generateMessageID(from, s.cfg.ServerName),
		"Auto-Submitted":            "auto-notified",
		"MIME-Version":              "1.0",
		"Content-Type":              "text/plain; charset=utf-8",
		"Content-Transfer-Encoding": "8bit",
	}
	switch notify.Importance {
	case "1":
		notifyHeaders["Importance"] = "high"
	case "3":
		notifyHeaders["Importance"] = "low"
	}
	if origFrom := smtpHeaderValue(headers, "From"); origFrom != "" {
		notifyHeaders["X-Original-From"] = origFrom
	}
	notifyMsg := buildMessage(notifyHeaders, []byte(notify.Message))
	for _, recipient := range notify.To {
		if err := validateEmailAddress(recipient); err != nil {
			return fmt.Errorf("invalid notification recipient %q: %w", recipient, err)
		}
		if err := s.sendDerivedMessage(DerivedMessage{Kind: "sieve-notify", Recipient: recipient, EnvelopeSender: envelopeSender, FullMessage: notifyMsg, ParentID: parentID, CorrelationID: correlationID, DKIM: s.originatedDKIM(userID, from)}); err != nil {
			logger.Error("smtp: sieve notify failed", "user", userID, "to", recipient, "error", err)
			return err
		}
		logger.Info("smtp: sieve notification sent", "user", userID, "to", recipient)
	}
	return nil
}

// sieveVacationReply builds the auto-reply for a Sieve vacation action
// (RFC 5230 section 5). ok is false when the reply must not be sent.
func (s *Session) sieveVacationReply(vacation *sieve.VacationResult, userID string, headers map[string]string) (sender string, replyHeaders map[string]string, body []byte, ok bool) {
	sender = strings.Trim(strings.TrimSpace(vacation.To), "<>")
	if sender == "" || suppressAutomaticReply(sender, s.deliveryRecipient, headers) {
		return "", nil, nil, false
	}
	from := vacation.From
	if from == "" {
		from = headers["To"]
		if from == "" {
			from = fmt.Sprintf("<%s>", userID)
		}
	}
	replyHeaders, body = vacation.ContentHeaders()
	replyHeaders["From"], replyHeaders["To"] = from, sender
	replyHeaders["Subject"] = mime.QEncoding.Encode("utf-8", vacation.Subject)
	replyHeaders["Date"] = time.Now().UTC().Format(time.RFC1123Z)
	replyHeaders["Message-ID"] = generateMessageID(from, s.cfg.ServerName)
	replyHeaders["Auto-Submitted"], replyHeaders["Precedence"] = "auto-replied", "bulk"
	if vacation.MessageID != "" {
		replyHeaders["In-Reply-To"], replyHeaders["References"] = vacation.MessageID, vacation.References
	}
	return sender, replyHeaders, body, true
}

// handleSieveVacation sends an auto-reply based on a Sieve vacation action
// (RFC 5230), tracked per sender and :handle.
func (s *Session) handleSieveVacation(vacation *sieve.VacationResult, userID string, headers map[string]string, parentID, correlationID string) {
	if s.cfg.Delivery.SendDerived == nil && s.cfg.Delivery.SendForward == nil {
		return
	}
	sender, replyHeaders, body, ok := s.sieveVacationReply(vacation, userID, headers)
	if !ok {
		return
	}
	trackingKey := vacation.TrackingKey()
	reservation, allowed := s.reserveVacationReply(userID, trackingKey)
	if !allowed {
		logger.Debug("smtp: sieve vacation reply rate-limited", "user", userID, "sender", sender)
		return
	}
	replyMsg := buildMessage(replyHeaders, body)
	if err := s.sendDerivedMessage(DerivedMessage{Kind: "sieve-vacation", Recipient: sender, FullMessage: replyMsg, ParentID: parentID, CorrelationID: correlationID, DKIM: s.originatedDKIM(userID, replyHeaders["From"])}); err != nil {
		s.finishVacationReply(userID, trackingKey, reservation, false)
		logger.Error("smtp: sieve vacation reply failed", "user", userID, "to", sender, "error", err)
		return
	}
	logger.Info("smtp: sieve vacation reply sent", "user", userID, "to", sender)
	s.finishVacationReply(userID, trackingKey, reservation, true)
}

func (s *Session) stageSieveVacation(vacation *sieve.VacationResult, userID string, headers map[string]string, parentID, correlationID string) error {
	sender, replyHeaders, body, ok := s.sieveVacationReply(vacation, userID, headers)
	if !ok {
		return nil
	}
	return s.stageVacationIntent("sieve-vacation", userID, sender, replyHeaders, body, parentID, correlationID, map[string]string{
		AttributeVacationKey: vacation.TrackingKey(), AttributeVacationPeriod: strconv.FormatInt(int64(vacation.Period/time.Second), 10)})
}
