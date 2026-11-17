package smtp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/attachment"
	"github.com/lkarlslund/veksel/pkg/contentscan"
	"github.com/lkarlslund/veksel/pkg/dmarc"
	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/virus"
)

// scoreSpam scores the transaction once and applies its transaction-level
// actions. It returns true when it answered the transaction: rejected at
// the reject threshold, or deferred by score-triggered greylisting. A sender
// on any recipient's allow list is never rejected or greylisted. A
// Message-ID Veksel generated is hidden from scoring unless peerMessageID.
func (s *Session) scoreSpam(headers map[string]string, body []byte, peerMessageID bool) bool {
	if s.cfg.Spam == nil {
		return false
	}
	scored := headers
	if !peerMessageID {
		scored = cloneSMTPHeaders(headers)
		delete(scored, "Message-ID")
	}
	message := spam.Message{
		Content: s.composeMessage(headers, body), Headers: scored, RemoteIP: extractRemoteIP(s.conn),
		Helo: s.heloHostname, EnvelopeFrom: s.envelopeSender, Attachments: s.attachments.Findings,
		Connection: s.connectionFindings(),
	}
	if s.spfResult != nil {
		message.SPF = s.spfResult.Result
	}
	if s.dkimResult != nil {
		message.DKIM = s.dkimResult.Result
		if s.dkimResult.Testing && message.DKIM != "pass" {
			// A failure under a t=y key counts as unsigned (RFC 6376).
			message.DKIM = "none"
		}
	}
	if s.dmarcResult != nil {
		message.DMARC = s.dmarcResult.Result
		if s.dmarcResult.OverrideReason != "" {
			// A trusted forwarder vouched for the original authentication.
			message.DMARC = "none"
		}
	}
	_, message.AuthDomain, _ = s.senderAuth(headers).Sender()
	result, ok := s.cfg.Spam.Check(s.ctx, message)
	if !ok {
		return false
	}
	spam.StampReputation(headers, result)
	if s.cfg.Classifier != nil {
		// Only a shared model may influence the transaction-level actions;
		// account models judge each recipient in runSpamFilter.
		sample := spam.NewSample(message.Content)
		s.spamSample = &sample
		if symbol, ok := s.cfg.Classifier.Classify(s.ctx, "", sample.Tokens); ok {
			result = result.WithBayes(symbol)
		}
	}
	s.spamResult = &result
	greylisting := result.Greylist() && s.cfg.Greylist != nil && greylistActive(s.cfg.Greylist) && greylistScoreTriggered(s.cfg.Greylist)
	if result.Action != spam.ActionReject && !greylisting || s.onlySpamtraps() || s.senderAllowlisted(headers) {
		return false
	}
	if result.Action == spam.ActionReject {
		logger.Info("smtp: message rejected as spam", "session", s.id, "score", result.Score, "symbols", spamSymbolNames(result))
		s.send(550, "5.7.1 Message rejected as spam")
		s.resetTransaction()
		return true
	}
	// Record every recipient's triplet before answering, so one retry can
	// pass them all.
	var retry time.Duration
	for _, recipient := range s.recipients {
		decision, err := s.cfg.Greylist.Check(s.ctx, s.greylistTriplet(message.RemoteIP, recipient))
		if err != nil {
			s.send(451, "4.3.0 Temporary greylisting service failure")
			s.resetTransaction()
			return true
		}
		if decision.Action == greylist.ActionDefer {
			retry = max(retry, decision.RetryAfter, time.Second)
		}
	}
	if retry == 0 {
		return false
	}
	logger.Info("smtp: message greylisted by spam score", "session", s.id, "score", result.Score)
	s.send(451, "4.7.1 Greylisting in effect; retry after "+retry.Round(time.Second).String())
	s.resetTransaction()
	return true
}

// attachmentPolicy returns the live policy, or nil when inspection is not
// configured.
func (s *Session) attachmentPolicy() *attachment.Policy {
	if s.cfg.Attachments == nil {
		return nil
	}
	return s.cfg.Attachments.Load()
}

// enforceAttachmentPolicy inspects the transaction's attachments once and
// applies the reject policy to dangerous executables, returning true when it
// answered the transaction. Quarantine applies per recipient in
// runContentScan; submissions have no quarantine and are rejected.
func (s *Session) enforceAttachmentPolicy(headers map[string]string, body []byte) bool {
	policy := s.attachmentPolicy()
	if !policy.Applies(s.authenticated) {
		return false
	}
	s.attachments = policy.Analyze(s.composeMessage(headers, body))
	hard := s.attachments.Hard()
	if len(hard) == 0 || policy.Mode() == attachment.ModeScore || (policy.Mode() == attachment.ModeQuarantine && !s.authenticated) {
		return false
	}
	logger.Info("smtp: message rejected by attachment policy", "session", s.id, "authenticated", s.authenticated, "reason", s.attachments.Reason())
	s.send(550, "5.7.1 Message rejected: blocked attachment ("+hard[0].Symbol+")")
	s.resetTransaction()
	return true
}

// attachmentScanResult is the attachment policy's content-scan evidence,
// present when the policy quarantines this transaction.
func (s *Session) attachmentScanResult() (contentscan.Result, bool) {
	policy := s.attachmentPolicy()
	if s.authenticated || policy == nil || policy.Mode() != attachment.ModeQuarantine || len(s.attachments.Hard()) == 0 {
		return contentscan.Result{}, false
	}
	result := contentscan.Result{Engine: "attachments", Verdict: contentscan.VerdictClean}
	for _, finding := range s.attachments.Findings {
		result.Symbols = append(result.Symbols, contentscan.Symbol{Name: finding.Symbol, Description: finding.Detail})
	}
	return result, true
}

func spamSymbolNames(result spam.Result) []string {
	names := make([]string, 0, len(result.Symbols))
	for _, symbol := range result.Symbols {
		names = append(names, symbol.Name)
	}
	return names
}

// spamPolicySender is the identity personal allow and block lists match:
// the From header, else the envelope sender.
func (s *Session) spamPolicySender(headers map[string]string) string {
	if from := headers["From"]; from != "" {
		return from
	}
	return s.envelopeSender
}

// senderAllowlisted reports whether any local recipient allow-lists the
// sender. An unreadable list counts as allowing: delivery to that account
// then defers on the same read instead of the transaction being rejected.
func (s *Session) senderAllowlisted(headers map[string]string) bool {
	delivery := s.cfg.Delivery
	sender := s.spamPolicySender(headers)
	if delivery == nil || delivery.ResolveRecipient == nil || delivery.GetSpamWhitelist == nil || sender == "" {
		return false
	}
	for _, recipient := range s.recipients {
		targets := s.recipientExpansions[recipient]
		if len(targets) == 0 {
			targets = []string{recipient}
		}
		for _, target := range targets {
			_, userID, err := delivery.ResolveRecipient(s.ctx, target)
			if err != nil || userID == "" {
				continue
			}
			allowed, err := delivery.GetSpamWhitelist(s.ctx, userID)
			if err != nil || spam.ListMatches(allowed, sender) {
				return true
			}
		}
	}
	return false
}

// runSpamFilter applies one account's spam policy to the transaction's
// score: the account's classifier symbol, the personal allow and block
// lists, the account's Junk threshold (zero uses the server's), and the
// X-Spam-* headers clients and Sieve see.
// Accounts with spam filtering off still get headers judged against the
// server threshold, but their mail is never moved. It returns the target
// folder.
func (s *Session) runSpamFilter(userID, defaultFolderID string, headers map[string]string) (string, error) {
	delivery := s.cfg.Delivery
	if delivery == nil || delivery.GetSpamConfig == nil {
		return defaultFolderID, nil
	}
	enabled, threshold, err := delivery.GetSpamConfig(s.ctx, userID)
	if err != nil {
		return "", &FilterTemporaryError{Stage: "spam policy", Err: err}
	}
	sender := s.spamPolicySender(headers)
	allowed, blocked := false, false
	if enabled && sender != "" {
		if delivery.GetSpamWhitelist != nil {
			list, err := delivery.GetSpamWhitelist(s.ctx, userID)
			if err != nil {
				return "", &FilterTemporaryError{Stage: "spam allow-list", Err: err}
			}
			allowed = spam.ListMatches(list, sender)
		}
		if !allowed && delivery.GetSpamBlacklist != nil {
			list, err := delivery.GetSpamBlacklist(s.ctx, userID)
			if err != nil {
				return "", &FilterTemporaryError{Stage: "spam block-list", Err: err}
			}
			blocked = spam.ListMatches(list, sender)
		}
	}
	if s.spamResult == nil && !blocked {
		return defaultFolderID, nil
	}
	result := spam.Result{Thresholds: spam.DefaultThresholds()}
	if s.spamResult != nil {
		result = *s.spamResult
		if s.spamSample != nil {
			if symbol, ok := s.cfg.Classifier.Classify(s.ctx, userID, s.spamSample.Tokens); ok {
				result = result.WithBayes(symbol)
			}
			if !allowed && !blocked {
				symbol, known, err := s.knownCorrespondent(userID, headers)
				if err != nil {
					return "", &FilterTemporaryError{Stage: "known correspondents", Err: err}
				}
				if known {
					result = result.WithSymbol(symbol)
				}
			}
			s.deliverySpamResult = &result
			s.autolearn(userID, result, allowed)
		}
	}
	required := result.Thresholds.Junk
	if enabled && threshold != 0 {
		required = threshold
	}
	isSpam := !allowed && (blocked || result.Score >= required)
	switch {
	case allowed:
		result.Symbols = append(slices.Clone(result.Symbols), spam.Symbol{Name: "USER_ALLOWLIST"})
	case blocked:
		result.Symbols = append(slices.Clone(result.Symbols), spam.Symbol{Name: "USER_BLOCKLIST"})
	}
	spam.AddHeaders(headers, result, required, isSpam)
	if !enabled || !isSpam || delivery.GetJunkFolderID == nil {
		return defaultFolderID, nil
	}
	logger.Info("smtp: message filed as spam", "user", userID, "score", result.Score, "blocked", blocked)
	junkFolderID, err := delivery.GetJunkFolderID(s.ctx, userID)
	if err != nil {
		return "", &FilterTemporaryError{Stage: "Junk folder policy", Err: err}
	}
	return junkFolderID, nil
}

// autolearn offers the account's final result to the classifier once the
// delivery is durable. Only an allow-listed sender whose DKIM or DMARC
// passed is trusted as ham.
func (s *Session) autolearn(userID string, result spam.Result, allowed bool) {
	trusted := allowed && (s.dkimResult != nil && s.dkimResult.Result == "pass" || s.dmarcResult != nil && s.dmarcResult.Result == "pass")
	classifier, sample := s.cfg.Classifier, *s.spamSample
	s.afterDeliveryCommit(func() { classifier.Autolearn(context.Background(), userID, sample, result, trusted) })
}

func (s *Session) stageDMARCQuarantine(recipient, ownerID string, headers map[string]string, fullMsg []byte) error {
	reason := "DMARC policy quarantine"
	if s.cfg.Delivery != nil && s.cfg.Delivery.MailQueue != nil {
		attributes := map[string]string{
			"subject": smtpHeaderValue(headers, "Subject"), "virus_name": reason, "scanner": "dmarc",
			"date": time.Now().UTC().Format(time.RFC3339), "reason_type": "dmarc", "reason": reason,
			"dmarc_disposition":      s.dmarcResult.Disposition,
			"authentication_results": smtpHeaderValue(headers, "Authentication-Results"),
		}
		if err := s.enqueueDelivery(&MailMessage{
			ID:   fmt.Sprintf("smtp-quarantine-%d-%d-%d", s.id, time.Now().UnixNano(), len(s.stagedDeliveries)+1),
			Kind: MailTaskQuarantine, EnvelopeSender: s.envelopeSender, Recipient: recipient,
			Headers: headers, Content: fullMsg, TargetOwnerID: ownerID, Attributes: attributes,
		}); err != nil {
			return &FilterTemporaryError{Stage: "DMARC quarantine queue", Err: err}
		}
		return nil
	}
	if s.cfg.Delivery != nil && s.cfg.Delivery.QuarantineMessage != nil {
		if _, err := s.cfg.Delivery.QuarantineMessage(context.Background(), s.envelopeSender, recipient, smtpHeaderValue(headers, "Subject"), headers, fullMsg, reason); err != nil {
			return &FilterTemporaryError{Stage: "DMARC quarantine", Err: err}
		}
		return nil
	}
	return &FilterTemporaryError{Stage: "DMARC quarantine", Err: errors.New("quarantine storage is unavailable")}
}

// runContentScan applies the generic typed pipeline and records its evidence
// together with the transaction's spam score.
func (s *Session) runContentScan(recipient, ownerID string, applyDomainPolicy bool, headers map[string]string, fullMsg []byte) (bool, error) {
	report, scanned, err := s.scanContent(recipient, applyDomainPolicy, headers, fullMsg)
	if err != nil {
		return false, err
	}
	attachmentResult, quarantineAttachments := s.attachmentScanResult()
	spamResult := s.spamResult
	if s.deliverySpamResult != nil {
		spamResult = s.deliverySpamResult
	}
	if !scanned && spamResult == nil && !quarantineAttachments {
		return false, nil
	}
	// The built-in score is evidence beside the engines, not an external
	// verdict: its Junk filing is per-account policy in runSpamFilter.
	if quarantineAttachments {
		report.Results = append(report.Results, attachmentResult)
		report.Decision = max(report.Decision, contentscan.DecisionQuarantine)
	}
	malwareNames, scannerNames, externalSpam := contentScanEvidence(report)
	if spamResult != nil {
		report.Results = append([]contentscan.Result{spamResult.ScanResult()}, report.Results...)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return false, &FilterTemporaryError{Stage: "content scanner evidence", Err: err}
	}
	s.deliveryScanTranscript = string(encoded)
	headers["X-Veksel-Content-Scan"] = contentScanSummary(report)
	if !scanned && !quarantineAttachments {
		return false, nil
	}
	if scanned {
		virus.AddVirusHeaders(headers, strings.Join(malwareNames, ","), len(malwareNames) > 0)
	}
	if externalSpam {
		for _, result := range report.Results {
			if result.Verdict == contentscan.VerdictSpam && result.Engine != spam.EngineName {
				symbols := make([]spam.Symbol, 0, len(result.Symbols))
				for _, symbol := range result.Symbols {
					symbols = append(symbols, spam.Symbol{Name: symbol.Name, Score: symbol.Score})
				}
				spam.AddHeaders(headers, spam.Result{Score: result.Score, Symbols: symbols}, result.RequiredScore, true)
				break
			}
		}
	}
	return s.applyContentScanDecision(recipient, ownerID, report, headers, fullMsg, malwareNames, scannerNames, externalSpam)
}

// scanContent runs the content pipeline when scanning applies to recipient,
// retaining the legacy virus callback for embedded integrations that have
// not migrated yet. It reports whether a scan ran.
func (s *Session) scanContent(recipient string, applyDomainPolicy bool, headers map[string]string, fullMsg []byte) (contentscan.Report, bool, error) {
	if s.cfg.Delivery == nil || (s.cfg.Delivery.ContentScan == nil && s.cfg.Delivery.VirusScan == nil) {
		return contentscan.Report{}, false, nil
	}
	if s.cfg.Delivery.GetVirusScanEnabled == nil || !s.cfg.Delivery.GetVirusScanEnabled() {
		return contentscan.Report{}, false, nil
	}
	if applyDomainPolicy && s.cfg.Delivery.GetVirusScanEnabledForDomain != nil {
		if atIdx := strings.LastIndex(recipient, "@"); atIdx >= 0 {
			enabled, err := s.cfg.Delivery.GetVirusScanEnabledForDomain(s.ctx, recipient[atIdx+1:])
			if err != nil {
				return contentscan.Report{}, false, &FilterTemporaryError{Stage: "content scanner policy", Err: err}
			}
			if !enabled {
				return contentscan.Report{}, false, nil
			}
		}
	}
	var report contentscan.Report
	if s.cfg.Delivery.ContentScan != nil {
		report = s.cfg.Delivery.ContentScan(context.Background(), contentscan.Message{
			Content: fullMsg, Headers: headers, EnvelopeFrom: s.envelopeSender,
			Recipient: recipient, RemoteIP: extractRemoteIP(s.conn),
		})
	} else {
		virusName, infected, err := s.cfg.Delivery.VirusScan(fullMsg)
		if err != nil {
			return contentscan.Report{}, false, &FilterTemporaryError{Stage: "virus scanner", Err: err}
		}
		verdict := contentscan.VerdictClean
		var names []string
		if infected {
			verdict, names = contentscan.VerdictMalware, []string{virusName}
		}
		report = contentscan.Report{Results: []contentscan.Result{{Engine: "legacy", Verdict: verdict, MalwareNames: names}}}
		if infected {
			report.Decision = contentscan.DecisionQuarantine
		}
	}
	return report, true, nil
}

// applyContentScanDecision enforces the pipeline decision: deferral,
// malware rejection, or quarantine with the retained evidence.
func (s *Session) applyContentScanDecision(recipient, ownerID string, report contentscan.Report, headers map[string]string, fullMsg []byte, malwareNames, scannerNames []string, externalSpam bool) (bool, error) {
	infected := len(malwareNames) > 0
	virusName := strings.Join(malwareNames, ",")
	if report.Decision == contentscan.DecisionDefer {
		return false, &FilterTemporaryError{Stage: "content scanner", Err: errors.New("scanner policy requested temporary deferral")}
	}
	if infected && !s.authenticated {
		logger.Info("smtp: message rejected (malware detected)", "malware", virusName, "recipient", recipient, "scanners", scannerNames)
		return false, &virus.ErrVirusDetected{VirusName: virusName, Scanner: strings.Join(scannerNames, ",")}
	}
	if report.Decision != contentscan.DecisionQuarantine {
		return externalSpam, nil
	}
	reason := virusName
	if _, quarantined := s.attachmentScanResult(); reason == "" && quarantined {
		reason = s.attachments.Reason()
	}
	if reason == "" {
		reason = "Content scanner policy quarantine"
	}
	if ownerID == "" {
		ownerID = s.authUserID
	}
	if s.cfg.Delivery.MailQueue != nil {
		quarantineContent := s.composeMessage(headers, messageBody(fullMsg))
		if err := s.enqueueDelivery(&MailMessage{
			ID: fmt.Sprintf("smtp-quarantine-%d-%d-%d", s.id, time.Now().UnixNano(), len(s.stagedDeliveries)+1), Kind: MailTaskQuarantine,
			EnvelopeSender: s.envelopeSender, Recipient: recipient, Headers: headers, Content: quarantineContent, TargetOwnerID: ownerID,
			Attributes: map[string]string{
				"subject": smtpHeaderValue(headers, "Subject"), "virus_name": reason, "scanner": strings.Join(scannerNames, ","), "date": time.Now().UTC().Format(time.RFC3339),
				"reason_type": "content_scan", "reason": reason, "scan_transcript": s.deliveryScanTranscript, "scan_summary": smtpHeaderValue(headers, "X-Veksel-Content-Scan"),
			},
		}); err != nil {
			return false, &FilterTemporaryError{Stage: "quarantine queue", Err: err}
		}
		return false, errDeliveryHandled
	}
	if s.cfg.Delivery.QuarantineMessage != nil {
		quarantineContent := s.composeMessage(headers, messageBody(fullMsg))
		if _, err := s.cfg.Delivery.QuarantineMessage(s.ctx, s.envelopeSender, recipient, smtpHeaderValue(headers, "Subject"), headers, quarantineContent, reason); err != nil {
			return false, &FilterTemporaryError{Stage: "quarantine", Err: err}
		}
		return false, errDeliveryHandled
	}
	return false, &FilterTemporaryError{Stage: "quarantine", Err: errors.New("quarantine storage is unavailable")}
}

func contentScanEvidence(report contentscan.Report) (malwareNames, scannerNames []string, spamDetected bool) {
	for _, result := range report.Results {
		scannerNames = append(scannerNames, result.Engine)
		malwareNames = append(malwareNames, result.MalwareNames...)
		spamDetected = spamDetected || result.Verdict == contentscan.VerdictSpam
	}
	return malwareNames, scannerNames, spamDetected
}

func contentScanSummary(report contentscan.Report) string {
	parts := make([]string, 0, len(report.Results))
	for _, result := range report.Results {
		value := result.Verdict.String()
		if result.ErrorCode != "" {
			value = "error(" + result.ErrorCode + ")"
		}
		parts = append(parts, result.Engine+"="+value)
	}
	value := strings.Join(parts, ",")
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

// evaluateHeloPolicy runs the HELO policy checks against the provided hostname.
// Returns a HeloResult describing the outcome.
func (s *Session) evaluateHeloPolicy(heloHostname string) *HeloResult {
	if s.cfg.HeloPolicy == nil {
		return &HeloResult{Pass: true, HeaderValue: "off"}
	}

	clientIP := extractRemoteIP(s.conn)
	return s.cfg.HeloPolicy.Evaluate(heloHostname, clientIP)
}

// runSPFCheck performs SPF validation for the current envelope sender.
// The result is stored in s.spfResult for use during RCPT TO and DATA.
func (s *Session) runSPFCheck() {
	if s.cfg.SpfPolicy == nil {
		return
	}

	clientIP := extractRemoteIP(s.conn)
	s.spfResult = EvaluateSPF(s.ctx, s.cfg.SpfPolicy, s.envelopeSender, s.heloHostname, clientIP)
}

// greylistTriplet is the greylisting input for recipient in the current
// transaction. It names the envelope domain when SPF passed for it, which
// lets greylisting skip the sender or key the triplet on its sending pool.
func (s *Session) greylistTriplet(remoteIP, recipient string) greylist.Triplet {
	triplet := greylist.Triplet{RemoteIP: remoteIP, EnvelopeFrom: s.envelopeSender, Recipient: recipient}
	if s.envelopeSender != "" && s.spfResult != nil && s.spfResult.Result == "pass" {
		triplet.SPFPassDomain = s.spfResult.SenderDomain
	}
	return triplet
}

// runDKIMVerification performs DKIM verification on the message data.
// The result is stored in s.dkimResult for use during DATA processing.
func (s *Session) runDKIMVerification(msgData []byte) *DkimResult {
	if s.cfg.DkimPolicy == nil {
		return nil
	}

	result := EvaluateDKIM(s.cfg.DkimPolicy, msgData)
	s.dkimResult = result
	return result
}

// runDMARCEvaluation performs DMARC evaluation using SPF and DKIM results.
// The result is stored in s.dmarcResult for use during DATA processing.
func (s *Session) runDMARCEvaluation(headers map[string]string) *DmarcResult {
	if s.cfg.DmarcPolicy == nil {
		return nil
	}

	// Every From field counts, whatever the case of its name: the header
	// map keeps one value per spelling, so a second From field or a "FROM:"
	// spelling would otherwise pick, or hide, the domain DMARC checks while
	// the recipient's client shows another.
	values := s.headerFromValues(headers)
	if len(values) == 0 {
		return &DmarcResult{Result: "none", Pass: true, HeaderValue: "none; reason=no-from-header"}
	}
	fromDomains := headerFromDomains(values)
	if len(fromDomains) == 0 {
		return &DmarcResult{Result: "none", Pass: true, HeaderValue: "none; reason=invalid-from-header"}
	}

	// SPF authenticates the MAIL FROM domain, or the HELO domain for a null
	// sender (RFC 7489 section 3.1.2 with RFC 7208 section 2.4).
	spfDomain := ""
	spfPass := false
	if s.spfResult != nil {
		spfDomain = s.spfResult.SenderDomain
		spfPass = s.spfResult.Result == "pass"
	}

	// Every passing signature is a DKIM identifier DMARC may align with.
	dkimDomains := s.dkimResult.PassingDomains()

	results := make([]*DmarcResult, 0, len(fromDomains))
	for _, domain := range fromDomains {
		results = append(results, EvaluateDMARC(s.cfg.DmarcPolicy, domain, spfDomain, spfPass, dkimDomains, len(dkimDomains) > 0))
	}
	result := combineDMARC(results)
	s.dmarcResult = result
	return result
}

// maxDMARCFromDomains bounds the From domains one message has evaluated.
const maxDMARCFromDomains = 4

// headerFromValues returns the value of every From field of the
// transaction's message, falling back to headers when no message head was
// recorded.
func (s *Session) headerFromValues(headers map[string]string) []string {
	var values []string
	for name, fieldValues := range model.ParseHeaderValues(s.messageHead) {
		if strings.EqualFold(name, "from") {
			values = append(values, fieldValues...)
		}
	}
	if len(values) == 0 {
		if value := smtpHeaderValue(headers, "From"); value != "" {
			values = []string{value}
		}
	}
	return values
}

// headerFromDomains returns the distinct domains of the From field values,
// in order, cut to maxDMARCFromDomains.
func headerFromDomains(values []string) []string {
	var domains []string
	for _, value := range values {
		for _, domain := range headerIdentityDomains(value) {
			domain = strings.TrimSuffix(domain, ".")
			if domain != "" && !slices.Contains(domains, domain) {
				domains = append(domains, domain)
			}
		}
	}
	if len(domains) > maxDMARCFromDomains {
		domains = domains[:maxDMARCFromDomains]
	}
	return domains
}

// combineDMARC merges the evaluations of several From domains, as RFC 7489
// section 6.6.1 permits, into the strictest: a failure wins (a rejecting
// one first, then a quarantining one), then temperror, permerror, and none.
// The message passes only when every From domain passed, so an aligned
// domain the sender controls cannot cover a forged one beside it.
func combineDMARC(results []*DmarcResult) *DmarcResult {
	rank := func(result *DmarcResult) int {
		switch {
		case result.Result == "fail" && result.ShouldReject:
			return 0
		case result.Result == "fail" && result.PolicyApplied && result.Disposition == "quarantine":
			return 1
		case result.Result == "fail":
			return 2
		case result.Result == "temperror":
			return 3
		case result.Result == "permerror":
			return 4
		case result.Result == "pass" || result.Result == "skip":
			return 6
		default:
			return 5
		}
	}
	decisive := results[0]
	for _, result := range results[1:] {
		if rank(result) < rank(decisive) {
			decisive = result
		}
	}
	return decisive
}

func (s *Session) recordDMARCAggregate() {
	if s.cfg.DMARCAggregates == nil || s.dmarcResult == nil || s.dmarcResult.Reporting == nil || len(s.dmarcResult.Reporting.RUA) == 0 {
		return
	}
	observation := dmarc.AggregateObservation{Time: time.Now().UTC(), SourceIP: extractRemoteIP(s.conn),
		HeaderFrom: s.dmarcResult.Domain, EnvelopeFrom: extractDomainFromAddress(s.envelopeSender),
		Disposition: s.dmarcResult.Disposition, DKIMAligned: s.dmarcResult.DkimPass,
		SPFAligned: s.dmarcResult.SpfPass, Policy: *s.dmarcResult.Reporting}
	if s.spfResult != nil {
		observation.SPF = dmarc.AggregateAuthResult{Domain: s.spfResult.SenderDomain, Result: s.spfResult.Result}
	}
	if s.dkimResult != nil {
		for _, signature := range s.dkimResult.Signatures {
			observation.DKIM = append(observation.DKIM, dmarc.AggregateAuthResult{Domain: signature.Domain, Selector: signature.Selector, Result: signature.Status})
		}
		if len(s.dkimResult.Signatures) == 0 && s.dkimResult.Domain != "" {
			observation.DKIM = []dmarc.AggregateAuthResult{{Domain: s.dkimResult.Domain, Selector: s.dkimResult.Selector, Result: s.dkimResult.Result}}
		}
	}
	if err := s.cfg.DMARCAggregates.Record(context.Background(), observation); err != nil {
		logger.Error("smtp: record DMARC aggregate observation", "session", s.id, "error", err)
		if s.cfg.DMARCAggregateError != nil {
			s.cfg.DMARCAggregateError(err)
		}
	}
}
