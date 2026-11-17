package smtp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/mailidentity"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/virus"
)

var errDeliveryHandled = errors.New("delivery handled by policy")

func (s *Session) acceptMessage(msgData []byte) {
	if s.cfg.MaxReceivedHeaders > 0 && countHeaderFields(msgData, "received") > s.cfg.MaxReceivedHeaders {
		s.send(554, "5.4.6 Too many hops; probable mail routing loop")
		s.resetTransaction()
		return
	}
	// Verify DKIM against the exact bytes supplied by the peer. Rebuilding or
	// adding local headers before this point would invalidate valid signatures.
	s.dkimResult = s.runDKIMVerification(msgData)
	if s.dkimResult != nil && s.dkimResult.ShouldReject {
		s.send(s.dkimResult.RejectionCode, s.dkimResult.RejectionText)
		s.resetTransaction()
		return
	}
	s.arcResult = s.runARCVerification(msgData)

	// Every accepted message gets this hop's trace field above the peer's
	// fields before scoring, delivery, queue admission, or DKIM signing.
	transactionID := fmt.Sprintf("smtp-transaction-%d-%d", time.Now().UnixNano(), s.id)
	msgData = model.PrependHeaderField(msgData, s.receivedField(transactionID, time.Now()))
	s.messageHead, _ = model.SplitHeaderBody(msgData)
	headers, body := model.ParseMessageHeaders(msgData)
	if !s.requireTLS {
		count := countHeaderFields(msgData, "tls-required")
		value := strings.TrimSpace(smtpHeaderValue(headers, "TLS-Required"))
		if count > 1 || count == 1 && !strings.EqualFold(value, "No") {
			s.send(550, "5.7.1 Invalid TLS-Required header")
			s.resetTransaction()
			return
		}
		s.tlsOptional = count == 1
	}
	// RFC 5322 3.6 allows one From and at most one Sender field. A second
	// field, or a second spelling of the name, would let identity checks and
	// the recipient's client read different values.
	for _, field := range []string{"from", "sender"} {
		if countHeaderFields(msgData, field) > 1 {
			s.send(550, "5.6.0 Message has more than one "+field+" header field")
			s.resetTransaction()
			return
		}
	}

	// Generate Message-ID if missing; spam scoring still sees it as missing.
	_, peerMessageID := headers["Message-ID"]
	if !peerMessageID {
		headers["Message-ID"] = generateMessageID("", s.cfg.ServerName)
	}

	// Add X-HELO-Status header to flagged messages
	if s.cfg.HeloPolicy != nil && s.heloHostname != "" {
		result := s.heloResult
		if result == nil {
			result = s.evaluateHeloPolicy(s.heloHostname)
		}
		headers["X-HELO-Status"] = heloStatusHeader(result)
	}

	// Run DMARC evaluation after SPF and DKIM checks
	s.dmarcResult = s.runDMARCEvaluation(headers)
	s.applyARCOverride()
	s.recordDMARCAggregate()

	// Check DMARC policy — reject if required
	if s.dmarcResult != nil && s.dmarcResult.ShouldReject {
		s.send(s.dmarcResult.RejectionCode, s.dmarcResult.RejectionText)
		s.resetTransaction()
		return
	}
	spoofResult, err := s.evaluateLocalIdentity(context.Background(), headers)
	if err != nil {
		logger.Error("smtp: local identity policy unavailable", "session", s.id, "error", err)
		s.send(451, "4.3.0 Local identity policy unavailable")
		s.resetTransaction()
		return
	}
	s.spoofResult = spoofResult
	if spoofResult != nil && spoofResult.Reject {
		s.send(550, "5.7.1 Unauthenticated use of a local sender identity")
		s.resetTransaction()
		return
	}
	// Replace peer-supplied authentication claims and legacy per-check fields
	// with one bounded field owned by this Veksel authentication service.
	replaceSMTPHeader(headers, "Authentication-Results", "")
	replaceSMTPHeader(headers, "Received-SPF", "")
	replaceSMTPHeader(headers, "DKIM-Verification-Result", "")
	replaceSMTPHeader(headers, "DMARC-Verification-Result", "")
	if !s.authenticated {
		for _, name := range spam.PeerHeaders {
			replaceSMTPHeader(headers, name, "")
		}
	}
	// Drop the peer's copies before adding Veksel' own, so the new
	// Authentication-Results lands at the top rather than in their place.
	headers, body = s.commitHeaders(headers, body)
	authenticationResults, err := s.authenticationResultsHeader(headers)
	if err != nil {
		logger.Error("smtp: build authentication results", "session", s.id, "error", err)
		s.send(451, "4.3.0 Authentication processing unavailable")
		s.resetTransaction()
		return
	}
	replaceSMTPHeader(headers, "Authentication-Results", authenticationResults)
	headers, body = s.commitHeaders(headers, body)

	if s.authenticated && s.cfg.Delivery != nil {
		if s.cfg.Delivery.AuthorizeSubmission != nil {
			if err := s.cfg.Delivery.AuthorizeSubmission(context.Background(), s.authUserID, s.envelopeSender, smtpHeaderValue(headers, "From"), smtpHeaderValue(headers, "Sender")); err != nil {
				logger.Warn("smtp: submission identity rejected", "session", s.id, "actor", s.authUserID, "error", err)
				s.send(550, "5.7.1 Submission identity is not authorized")
				s.resetTransaction()
				return
			}
		}
		// Only an authorized submission originates here; relayed mail keeps
		// its original signatures.
		s.originated = true
	}
	if s.enforceAttachmentPolicy(headers, body) {
		return
	}
	if !s.authenticated && s.scoreSpam(headers, body, peerMessageID) {
		return
	}
	s.markSpamtrapHit()

	// Deliver to each recipient

	s.stagingDelivery = s.cfg.Delivery != nil && s.cfg.Delivery.MailQueue != nil
	s.stagedDeliveries = nil
	s.postCommitActions = nil
	s.deliveryCorrelationID = transactionID
	spamtrapAction, spamtrapHit := s.spamtrapAction(headers, body)
	deliveryErrors := 0
	deliveredTargets := make(map[string]struct{})
	for _, addr := range s.recipients {
		// Spamtrap copies are dropped silently: no delivery, no DSN.
		if s.spamtrapRecipient(addr) {
			continue
		}
		targets := s.recipientExpansions[addr]
		if len(targets) == 0 {
			targets = []string{addr}
		}
		for _, target := range targets {
			canonicalTarget := strings.ToLower(target)
			if _, duplicate := deliveredTargets[canonicalTarget]; duplicate {
				continue
			}
			deliveredTargets[canonicalTarget] = struct{}{}
			if options, present := s.dsnRecipients[addr]; present {
				s.dsnRecipients[canonicalTarget] = options
			}
			if err := s.deliverMessage(target, headers, body); err != nil {
				// Check for virus detection error
				if vErr, ok := err.(*virus.ErrVirusDetected); ok {
					s.send(550, fmt.Sprintf("5.7.1 Message rejected: virus detected (%s)", vErr.VirusName))
					s.resetTransaction()
					return
				}
				var filterErr *FilterTemporaryError
				if errors.As(err, &filterErr) {
					logger.Warn("smtp: filter evaluation deferred transaction", "session", s.id, "addr", addr, "stage", filterErr.Stage, "error", filterErr.Err)
					deliveryErrors++
					continue
				}
				var rejectErr *PolicyRejectError
				if errors.As(err, &rejectErr) {
					s.send(550, "5.7.1 "+rejectErr.Reason)
					s.resetTransaction()
					return
				}

				logger.Error("smtp: delivery failed", "session", s.id, "addr", target, "alias", addr, "error", err)

				// If a mail queue is configured and this is a temporary failure,
				// enqueue for retry instead of failing immediately.
				if s.cfg.Delivery.MailQueue != nil && isTemporaryError(err) {
					if qErr := s.enqueueDelivery(&MailMessage{
						EnvelopeSender: s.envelopeSender,
						Recipient:      target,
						Headers:        headers,
						Content:        s.composeMessage(headers, body),
						DKIM:           s.submissionDKIM(),
					}); qErr != nil {
						logger.Error("smtp: failed to enqueue message for retry", "addr", addr, "error", qErr)
					} else {
						logger.Info("smtp: message enqueued for retry", "addr", addr)
						continue // Accept the message — it will be retried
					}
				}

				deliveryErrors++
			}
		}
	}
	if deliveryErrors == 0 && s.stagingDelivery && len(s.stagedDeliveries) > 0 {
		if err := s.cfg.Delivery.MailQueue.EnqueueBatch(s.stagedDeliveries); err != nil {
			var rejection *mailpolicy.RejectionError
			if errors.As(err, &rejection) {
				code := rejection.EnhancedStatusCode
				if code == "" {
					code = "5.7.1"
				}
				s.send(550, code+" "+rejection.Reason)
				s.resetTransaction()
				return
			}
			var temporary TemporaryRejection
			if errors.As(err, &temporary) {
				code, reason := temporary.TemporaryRejection()
				logger.Info("smtp: delivery batch deferred", "session", s.id, "actor", s.authUserID, "reason", reason)
				s.send(451, code+" "+reason)
				s.resetTransaction()
				return
			}
			logger.Error("smtp: failed to commit delivery batch", "session", s.id, "recipients", len(s.stagedDeliveries), "error", err)
			deliveryErrors = len(s.recipients)
		}
	}
	actions := append([]func(){}, s.postCommitActions...)
	if spamtrapHit {
		actions = append(actions, spamtrapAction)
	}
	if deliveryErrors == 0 && s.authenticated && s.authUserID != "" && s.cfg.Delivery != nil && s.cfg.Delivery.RecordRecentRecipients != nil {
		userID := s.authUserID
		recipients := append([]string(nil), s.recipients...)
		record := s.cfg.Delivery.RecordRecentRecipients
		actions = append(actions, func() {
			if err := record(context.Background(), userID, recipients); err != nil {
				logger.Warn("smtp: record recent recipients", "session", s.id, "user", userID, "error", err)
			}
		})
	}
	s.stagingDelivery = false
	s.stagedDeliveries = nil
	s.postCommitActions = nil
	s.deliveryCorrelationID = ""

	if deliveryErrors > 0 {
		s.send(451, fmt.Sprintf("Delivery failed for %d recipient(s)", deliveryErrors))
	} else {
		// The durable batch is authoritative. A slow or faulty notification,
		// forwarding, or vacation hook must not make the client retry an already
		// accepted transaction.
		s.send(250, "Message accepted")
		s.junkCommands = 0
	}

	s.resetTransaction()
	if deliveryErrors == 0 {
		s.runPostCommitActions(actions)
	}
}

// deliverMessage routes a message to a single recipient, running spam filtering
// and Sieve filtering before delivery.
func (s *Session) deliverMessage(addr string, headers map[string]string, body []byte) error {
	previousRecipient := s.deliveryRecipient
	previousTranscript := s.deliveryScanTranscript
	previousSpamResult := s.deliverySpamResult
	s.deliveryRecipient = addr
	s.deliveryScanTranscript = ""
	s.deliverySpamResult = nil
	defer func() {
		s.deliveryRecipient = previousRecipient
		s.deliveryScanTranscript = previousTranscript
		s.deliverySpamResult = previousSpamResult
	}()
	if s.cfg.Delivery == nil || s.cfg.Delivery.ResolveRecipient == nil {
		return fmt.Errorf("delivery not configured")
	}

	if original, ok := s.srsReturns[addr]; ok {
		return s.relayMessage(addr, original, headers, body)
	}
	folderID, userID, err := s.cfg.Delivery.ResolveRecipient(s.ctx, addr)
	if errors.Is(err, ErrRecipientDiscarded) {
		logger.Info("smtp: recipient discards mail", "recipient", addr)
		return nil
	}
	if err != nil {
		if s.canRelay(addr) || s.routedRecipients[strings.ToLower(addr)] {
			return s.relayMessage(addr, addr, headers, body)
		}
		return fmt.Errorf("resolve recipient: %w", err)
	}

	// Filters may add recipient-specific headers, so never mutate the map shared
	// by the other recipients in this SMTP transaction.
	headers = cloneSMTPHeaders(headers)
	if s.dmarcResult != nil && s.dmarcResult.PolicyApplied && s.dmarcResult.Disposition == "quarantine" && s.cfg.DmarcPolicy != nil && s.cfg.DmarcPolicy.Mode == DmarcPolicyReject && !s.authenticated {
		fullMsg := s.composeMessage(headers, body)
		if err := s.stageDMARCQuarantine(addr, userID, headers, fullMsg); err != nil {
			return err
		}
		return nil
	}

	// Apply the account's spam policy to the transaction's score.
	targetFolderID, filterErr := s.runSpamFilter(userID, folderID, headers)
	if filterErr != nil {
		return filterErr
	}

	// Reconstruct full message with headers (may have been modified by spam filter)
	fullMsg := s.composeMessage(headers, body)

	// Run the generic content pipeline after account allow/block policy. An
	// external spam verdict uses the same Junk target as the built-in scorer.
	externalSpam, scanErr := s.runContentScan(addr, userID, true, headers, fullMsg)
	if scanErr != nil {
		if errors.Is(scanErr, errDeliveryHandled) {
			return nil
		}
		return scanErr
	}
	if externalSpam && s.cfg.Delivery.GetJunkFolderID != nil {
		junkFolderID, err := s.cfg.Delivery.GetJunkFolderID(s.ctx, userID)
		if err != nil {
			return &FilterTemporaryError{Stage: "spam destination", Err: err}
		}
		targetFolderID = junkFolderID
	}
	// Scanner headers are part of the durable message, not side metadata only.
	fullMsg = s.composeMessage(headers, body)

	// Run Sieve filtering if configured
	if s.cfg.Delivery.GetSieveScript != nil && userID != "" {
		script, active, err := s.cfg.Delivery.GetSieveScript(s.ctx, userID)
		if err != nil {
			return &FilterTemporaryError{Stage: "Sieve policy", Err: err}
		}
		if active && script != "" {
			if result, err := s.runSieve(script, fullMsg, userID, targetFolderID, headers, body); err != nil {
				var rejectErr *PolicyRejectError
				if errors.As(err, &rejectErr) {
					return rejectErr
				}
				var temporaryErr *FilterTemporaryError
				if errors.As(err, &temporaryErr) {
					return temporaryErr
				}
				var scriptErr sieveScriptError
				if !errors.As(err, &scriptErr) {
					// Applying the actions failed, possibly after some were
					// applied: falling back to the default mailbox would
					// accept the message and lose the failed copy.
					return fmt.Errorf("apply sieve actions: %w", err)
				}
				// A broken script delivers to the default mailbox.
				logger.Error("smtp: sieve script error", "user", userID, "error", err)
			} else if result != nil {
				// Sieve handled the message — return early
				return nil
			}
		}
	}

	if s.cfg.Delivery.MailQueue == nil && s.cfg.Delivery.AppendFolderItem == nil && s.cfg.Delivery.AppendMessage == nil {
		return fmt.Errorf("append not configured")
	}

	deliveryID, err := s.appendFolderItem(userID, targetFolderID, fullMsg, headers)

	// Notify IMAP IDLE clients about the new message
	if err == nil && s.cfg.Delivery.NotifyIMAPIdle != nil {
		s.afterDeliveryCommit(func() { s.cfg.Delivery.NotifyIMAPIdle(targetFolderID) })
	}

	// Derived forwards join the same durable batch as the local delivery. Older
	// callback-only integrations retain the post-commit behavior.
	if userID != "" {
		messageCopy, headerCopy, sender, correlation := append([]byte(nil), fullMsg...), cloneSMTPHeaders(headers), s.envelopeSender, s.deliveryCorrelationID
		seal := s.forwardSealer(addr)
		if s.stagingDelivery && s.cfg.Delivery.PrepareDerived != nil {
			if forwardErr := s.handleForwarding(userID, sender, messageCopy, headerCopy, deliveryID, correlation, seal); forwardErr != nil {
				return &FilterTemporaryError{Stage: "forward queue", Err: forwardErr}
			}
		} else {
			s.afterDeliveryCommit(func() {
				_ = s.handleForwarding(userID, sender, messageCopy, headerCopy, deliveryID, correlation, seal)
			})
		}
		if s.stagingDelivery && s.cfg.Delivery.PrepareDerived != nil {
			if vacationErr := s.stageVacationReply(userID, addr, sender, headerCopy, deliveryID, correlation); vacationErr != nil {
				return &FilterTemporaryError{Stage: "vacation queue", Err: vacationErr}
			}
		} else {
			s.afterDeliveryCommit(func() { s.handleVacationReply(userID, addr, sender, headerCopy, deliveryID, correlation) })
		}
	}

	return err
}

// relayMessage content-scans a message accepted for addr and queues it for
// outbound delivery to recipient.
func (s *Session) relayMessage(addr, recipient string, headers map[string]string, body []byte) error {
	headers = cloneSMTPHeaders(headers)
	fullMsg := s.composeMessage(headers, body)
	if _, scanErr := s.runContentScan(addr, "", false, headers, fullMsg); scanErr != nil {
		if errors.Is(scanErr, errDeliveryHandled) {
			return nil
		}
		return scanErr
	}
	// Scanner headers are part of the relayed message.
	message := &MailMessage{
		EnvelopeSender: s.envelopeSender, Recipient: recipient, Headers: headers, Content: s.composeMessage(headers, body), Outbound: true, DKIM: s.submissionDKIM(),
	}
	if s.deliveryScanTranscript != "" {
		message.Attributes = map[string]string{"scan_transcript": s.deliveryScanTranscript, "scan_summary": smtpHeaderValue(headers, "X-Veksel-Content-Scan")}
	}
	if err := s.enqueueDelivery(message); err != nil {
		return fmt.Errorf("4.3.0 persist outbound delivery: %w", err)
	}
	return nil
}

// submissionDKIM requests a DKIM signature for copies of an authorized
// submission; relayed mail gets none.
func (s *Session) submissionDKIM() *dkim.Request {
	if !s.originated {
		return nil
	}
	return &dkim.Request{}
}

func (s *Session) appendFolderItem(userID, folderID string, data []byte, headers map[string]string) (string, error) {
	if s.cfg.Delivery != nil && s.cfg.Delivery.MailQueue != nil {
		message := &MailMessage{
			ID:             fmt.Sprintf("smtp-%d-%d-%d", s.id, time.Now().UnixNano(), len(s.stagedDeliveries)+1),
			EnvelopeSender: s.envelopeSender,
			Recipient:      s.deliveryRecipient,
			Headers:        headers,
			Content:        data,
			TargetFolderID: folderID,
			TargetOwnerID:  userID,
		}
		if s.deliveryScanTranscript != "" {
			message.Attributes = map[string]string{"scan_transcript": s.deliveryScanTranscript, "scan_summary": smtpHeaderValue(headers, "X-Veksel-Content-Scan")}
		}
		if err := s.enqueueDelivery(message); err != nil {
			return "", err
		}
		return message.ID, nil
	}
	if s.cfg.Delivery.AppendFolderItem != nil {
		return s.cfg.Delivery.AppendFolderItem(s.ctx, userID, folderID, data, headers)
	}
	return s.cfg.Delivery.AppendMessage(s.ctx, folderID, data, headers)
}

func (s *Session) enqueueDelivery(message *MailMessage) error {
	if s.cfg.Delivery == nil || s.cfg.Delivery.MailQueue == nil {
		return errors.New("mail queue is not configured")
	}
	copyMessage := *message
	if copyMessage.CorrelationID == "" {
		copyMessage.CorrelationID = s.deliveryCorrelationID
	}
	if copyMessage.AuthenticatedActor == "" && s.authenticated {
		copyMessage.AuthenticatedActor = s.authUserID
	}
	if copyMessage.SourceIP == "" && s.conn != nil {
		copyMessage.SourceIP = extractRemoteIP(s.conn)
	}
	copyMessage.Body = append([]byte(nil), message.Body...)
	copyMessage.Content = append([]byte(nil), message.Content...)
	copyMessage.Headers = make(map[string]string, len(message.Headers))
	for key, value := range message.Headers {
		copyMessage.Headers[key] = value
	}
	copyMessage.Attributes = make(map[string]string, len(message.Attributes))
	for key, value := range message.Attributes {
		copyMessage.Attributes[key] = value
	}
	recipient := copyMessage.Recipient
	if recipient == "" {
		recipient = s.deliveryRecipient
	}
	if s.dsnReturn != "" {
		copyMessage.Attributes["dsn_return"] = s.dsnReturn
	}
	if s.dsnEnvelopeID != "" {
		copyMessage.Attributes["dsn_envelope_id"] = s.dsnEnvelopeID
	}
	if s.requireTLS {
		copyMessage.Attributes[AttributeRequireTLS] = "true"
		delete(copyMessage.Attributes, AttributeTLSOptional)
	} else if s.tlsOptional {
		copyMessage.Attributes[AttributeTLSOptional] = "true"
		delete(copyMessage.Attributes, AttributeRequireTLS)
	}
	if options, ok := s.dsnRecipients[strings.ToLower(recipient)]; ok {
		if options.notify != "" {
			copyMessage.Attributes["dsn_notify"] = options.notify
		}
		if options.orcpt != "" {
			copyMessage.Attributes["dsn_original_recipient"] = options.orcpt
		}
	}
	if s.stagingDelivery {
		s.stagedDeliveries = append(s.stagedDeliveries, &copyMessage)
		return nil
	}
	return s.cfg.Delivery.MailQueue.Enqueue(&copyMessage)
}

func cloneSMTPHeaders(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for name, value := range headers {
		cloned[name] = value
	}
	return cloned
}

func (s *Session) afterDeliveryCommit(action func()) {
	if s.stagingDelivery {
		s.postCommitActions = append(s.postCommitActions, action)
		return
	}
	action()
}

func (s *Session) runPostCommitActions(actions []func()) {
	for _, action := range actions {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("smtp: post-commit action panicked", "session", s.id, "panic", recovered)
				}
			}()
			action()
		}()
	}
}

func messageBody(message []byte) []byte {
	_, body := model.ParseMessageHeaders(message)
	return body
}

// queueDSN records rejection metadata only. SMTP has already reported the
// failure to the connected client, so a bounce here would be backscatter for
// a message Veksel never accepted.
func (s *Session) queueDSN(addr string, status DSNStatus, diagnostic string) {
	s.failedRecipients = append(s.failedRecipients, addr)
	logger.Info("smtp: recipient rejected before acceptance", "addr", addr, "status", status.Code, "diagnostic", diagnostic)
}

// buildMessage serializes a message Veksel generates from headers and body.
// The accepted transaction message uses composeMessage instead.
func buildMessage(headers map[string]string, body []byte) []byte {
	return model.BuildMessage(headers, body)
}

// composeMessage serializes the transaction message from its edited header
// map, keeping the arrival order and repeated fields (Received above all) of
// s.messageHead; see model.RebuildMessage.
func (s *Session) composeMessage(headers map[string]string, body []byte) []byte {
	return model.RebuildMessage(s.messageHead, headers, body)
}

// commitHeaders makes the edited header map the transaction's message head
// and returns the map and body parsed back from it.
func (s *Session) commitHeaders(headers map[string]string, body []byte) (map[string]string, []byte) {
	message := s.composeMessage(headers, body)
	s.messageHead, _ = model.SplitHeaderBody(message)
	return model.ParseMessageHeaders(message)
}

// generateMessageID creates a RFC 5322 compliant Message-ID in the domain of
// the from address, falling back to the server name (see
// mailidentity.MessageIDDomain).
func generateMessageID(from, serverName string) string {
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	return fmt.Sprintf("<%s.%s@%s>", ts, fmt.Sprintf("%06d", time.Now().UnixNano()%1000000), mailidentity.MessageIDDomain(from, serverName))
}

func (s *Session) sendDerivedMessage(derived DerivedMessage) error {
	if s.stagingDelivery && s.cfg.Delivery.MailQueue != nil && s.cfg.Delivery.PrepareDerived != nil {
		message, err := s.cfg.Delivery.PrepareDerived(context.Background(), derived)
		if err != nil {
			return err
		}
		if message == nil {
			return errors.New("derived message preparation returned no queue message")
		}
		if message.ParentID == "" {
			message.ParentID = derived.ParentID
		}
		if message.CorrelationID == "" {
			message.CorrelationID = derived.CorrelationID
		}
		return s.enqueueDelivery(message)
	}
	if s.cfg.Delivery.SendDerived != nil {
		return s.cfg.Delivery.SendDerived(context.Background(), derived)
	}
	return s.cfg.Delivery.SendForward(context.Background(), derived.Recipient, derived.FullMessage)
}

// isTemporaryError checks if the error represents a temporary (retryable) failure.
// It looks for DSN 4.x.x status codes or common network error patterns.
func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Check for DSN 4.x.x pattern
	for i := 0; i < len(msg)-3; i++ {
		if msg[i] == '4' && msg[i+1] == '.' {
			return true
		}
	}
	// Common network errors
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "connection refused") {
		return true
	}
	if strings.Contains(lower, "i/o timeout") {
		return true
	}
	if strings.Contains(lower, "network is unreachable") {
		return true
	}
	if strings.Contains(lower, "context deadline exceeded") {
		return true
	}
	if strings.Contains(lower, "context canceled") {
		return true
	}
	return false
}
