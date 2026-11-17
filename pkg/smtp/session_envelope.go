package smtp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// cmdMail handles MAIL FROM (RFC 5321).
// Supports BODY=8BITMIME (RFC 1652), SMTPUTF8 (RFC 6531), and SIZE parameters.
func (s *Session) cmdMail(cmd string, arg string) {
	if s.curState < statePostEHLO || s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	if s.cfg.AuthRequired && !s.authenticated {
		s.send(530, "Authentication required")
		return
	}

	// Parse "FROM:<addr> [SP parameters]"
	arg = strings.TrimSpace(arg)
	if !strings.HasPrefix(strings.ToUpper(arg), "FROM:") {
		s.send(501, "Syntax: MAIL FROM:<address>")
		return
	}

	rest := strings.TrimPrefix(arg[5:], " ")
	rest = strings.TrimSpace(rest)

	addr, parameters, err := splitSMTPPathParameters(rest)
	if err != nil {
		s.send(501, err.Error())
		return
	}
	if len(parameters) > 0 && !s.ehloGiven {
		s.send(555, "MAIL parameters require EHLO")
		return
	}
	returnMode, envelopeID, requireTLS, err := parseMailParameters(parameters, s.cfg.MaxMessageSize)
	if err != nil {
		code := 555
		if strings.Contains(err.Error(), "exceeds limit") {
			code = 552
		} else if !strings.Contains(err.Error(), "unsupported") {
			code = 501
		}
		s.send(code, err.Error())
		return
	}
	if requireTLS && !s.tlsDone {
		s.send(530, "5.7.10 Encryption needed for REQUIRETLS")
		return
	}

	if addr == "" || addr == "<>" {
		// Null sender (bounce/DSN)
		s.envelopeSender = ""
	} else {
		// Validate address format — use lenient validation for SMTPUTF8
		if err := validateEmailAddress(addr); err != nil {
			s.send(501, "Invalid address syntax")
			return
		}
		// Strip angle brackets for consistent internal representation
		addr = strings.Trim(addr, "<>")
		s.envelopeSender = strings.ToLower(addr)
	}

	s.recipients = nil
	s.recipientExpansions = make(map[string][]string)
	s.srsReturns = make(map[string]string)
	s.routedRecipients = nil
	s.spamtraps = nil
	s.dsnReturn = returnMode
	s.dsnEnvelopeID = envelopeID
	s.requireTLS = requireTLS
	s.tlsOptional = false
	s.dsnRecipients = make(map[string]dsnRecipientOptions)
	s.curState = stateHasMAIL

	// Run SPF check for the envelope sender
	s.runSPFCheck()

	s.send(250, "OK")
}

// cmdRCPT handles RCPT TO (RFC 5321).
func (s *Session) cmdRCPT(arg string) {
	s.tarpit()
	if s.curState < stateHasMAIL || s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	// Check SPF result — reject if policy requires
	if s.spfResult != nil && s.spfResult.ShouldReject {
		s.send(s.spfResult.RejectionCode, s.spfResult.RejectionText)
		return
	}

	arg = strings.TrimSpace(arg)
	if !strings.HasPrefix(strings.ToUpper(arg), "TO:") {
		s.send(501, "Syntax: RCPT TO:<address>")
		return
	}

	addr := strings.TrimSpace(arg[3:])

	// Strip leading colon if present (TO:<addr> vs TO: <addr>)
	if len(addr) > 0 && addr[0] == ':' {
		addr = strings.TrimSpace(addr[1:])
	}

	path, parameters, err := splitSMTPPathParameters(addr)
	if err != nil {
		s.send(501, "Syntax: RCPT TO:<address>")
		return
	}
	options, err := parseRecipientParameters(parameters)
	if err != nil {
		code := 501
		if strings.Contains(err.Error(), "unsupported") {
			code = 555
		}
		s.send(code, err.Error())
		return
	}
	if len(parameters) > 0 && !s.ehloGiven {
		s.send(555, "RCPT parameters require EHLO")
		return
	}
	addr = path

	// Validate address format — use lenient validation for SMTPUTF8
	if err := validateEmailAddress(addr); err != nil {
		s.send(501, "Invalid address syntax")
		return
	}

	addr = strings.ToLower(addr)

	// Strip angle brackets if present
	addr = strings.Trim(addr, "<>")

	// A bounce to an SRS address this server issued returns to the original
	// sender through the outbound queue; it is never a local mailbox.
	srsReturn := ""
	if s.cfg.Delivery != nil && s.cfg.Delivery.ReverseSRS != nil {
		original, isSRS, err := s.cfg.Delivery.ReverseSRS(context.Background(), addr)
		if isSRS && err != nil {
			s.send(550, "5.1.1 Invalid or expired SRS address")
			return
		}
		if isSRS {
			srsReturn = original
		}
	}
	// Bounces must return to a signed return path (BATV); a valid tag is
	// removed before routing. SRS returns carry their own signature.
	if srsReturn == "" && s.cfg.Delivery != nil && s.cfg.Delivery.CheckReturnPath != nil {
		recipient, err := s.cfg.Delivery.CheckReturnPath(context.Background(), addr, s.envelopeSender == "" && !s.authenticated)
		switch {
		case errors.Is(err, ErrBackscatter):
			s.send(550, "5.7.1 Bounce to an address this server did not sign; rejected as backscatter")
			return
		case err != nil:
			s.send(451, "4.3.0 Recipient validation is temporarily unavailable")
			return
		}
		addr = recipient
	}
	// Inbound address rewriting (masquerading) replaces the recipient itself
	// before alias expansion and resolution.
	if srsReturn == "" && s.cfg.Delivery != nil && s.cfg.Delivery.RewriteRecipient != nil {
		recipient, err := s.cfg.Delivery.RewriteRecipient(context.Background(), addr)
		if err != nil {
			s.send(451, "4.3.0 Recipient rewriting is temporarily unavailable")
			return
		}
		addr = recipient
	}

	// A spamtrap is accepted like a mailbox so the sender cannot tell it
	// apart; it is never expanded, resolved, greylisted, or delivered.
	trap := false
	if srsReturn == "" {
		if trap, err = s.isSpamtrap(addr); err != nil {
			s.send(451, "4.3.0 Recipient validation is temporarily unavailable")
			return
		}
	}

	targets := []string{addr}
	if !trap && srsReturn == "" && s.cfg.Delivery != nil && s.cfg.Delivery.ExpandRecipient != nil {
		expandedTargets, expanded, err := s.cfg.Delivery.ExpandRecipient(context.Background(), addr)
		if err != nil {
			s.send(451, "4.3.0 Recipient alias is temporarily unavailable")
			return
		}
		if expanded {
			if len(expandedTargets) == 0 {
				s.send(550, "5.1.1 Recipient alias has no targets")
				return
			}
			targets = expandedTargets
		}
	}
	terminal := make(map[string]struct{})
	for _, recipient := range s.recipients {
		expanded := s.recipientExpansions[recipient]
		if len(expanded) == 0 {
			expanded = []string{recipient}
		}
		for _, target := range expanded {
			terminal[strings.ToLower(target)] = struct{}{}
		}
	}
	for _, target := range targets {
		terminal[strings.ToLower(target)] = struct{}{}
	}
	if s.cfg.MaxRecipients > 0 && len(terminal) > s.cfg.MaxRecipients {
		s.send(452, "Too many expanded recipients")
		return
	}

	// Resolve the recipient before greylisting so an invalid address cannot
	// consume durable triplet capacity or be used for account enumeration.
	if !trap && srsReturn == "" && s.cfg.Delivery != nil && s.cfg.Delivery.ResolveRecipient != nil {
		for _, target := range targets {
			_, _, err := s.cfg.Delivery.ResolveRecipient(s.ctx, target)
			if err == nil || errors.Is(err, ErrRecipientDiscarded) {
				continue
			}
			if len(targets) == 1 && s.canRelay(target) {
				// A configured outbound route is a valid recipient destination.
				continue
			}
			routed, routeErr := s.routeUnknownRecipient(target)
			if routeErr != nil {
				logger.Warn("smtp: split delivery check failed", "session", s.id, "recipient", target, "error", routeErr)
				s.send(451, "4.4.3 Recipient verification is temporarily unavailable")
				return
			}
			if routed {
				if s.routedRecipients == nil {
					s.routedRecipients = make(map[string]bool)
				}
				s.routedRecipients[strings.ToLower(target)] = true
			} else {
				// Queue a DSN bounce to the sender for this failed recipient
				s.queueDSN(addr, DSNUserUnknown, "User unknown: "+addr)
				s.reportAbuse(ban.TriggerRecipient)
				s.unknownRecipient()
				s.send(550, "User unknown")
				return
			}
		}
	}
	if !trap && s.cfg.Greylist != nil && !s.authenticated && greylistActive(s.cfg.Greylist) && !greylistScoreTriggered(s.cfg.Greylist) {
		decision, err := s.cfg.Greylist.Check(context.Background(), s.greylistTriplet(extractRemoteIP(s.conn), addr))
		if err != nil {
			s.send(451, "4.3.0 Temporary greylisting service failure")
			return
		}
		if decision.Action == greylist.ActionDefer {
			retry := max(time.Second, decision.RetryAfter).Round(time.Second)
			s.send(451, "4.7.1 Greylisting in effect; retry after "+retry.String())
			return
		}
	}

	s.recipients = append(s.recipients, addr)
	if trap {
		if s.spamtraps == nil {
			s.spamtraps = make(map[string]struct{})
		}
		s.spamtraps[addr] = struct{}{}
	}
	if srsReturn != "" {
		if s.srsReturns == nil {
			s.srsReturns = make(map[string]string)
		}
		s.srsReturns[addr] = srsReturn
	}
	if len(targets) > 1 || targets[0] != addr {
		s.recipientExpansions[addr] = append([]string(nil), targets...)
	}
	s.dsnRecipients[addr] = options
	s.curState = stateHasRCPT
	s.send(250, "OK")
}

// cmdDATA handles the DATA command (RFC 5321).
func (s *Session) cmdDATA() {
	if s.curState < stateHasRCPT || s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	if len(s.recipients) == 0 {
		s.send(503, "No recipients specified")
		return
	}
	if s.bdatActive {
		s.send(503, "BDAT transaction in progress")
		return
	}

	// Send the 354 response immediately — the client won't send the DATA
	// body until it receives this response, even under pipelining.
	s.send(354, "Send message data; end with <CRLF>.<CRLF>")
	// Flush queued responses so the client gets the 354 before we read the body
	if s.pipelining && len(s.cmdResponses) > 0 {
		s.sendQueuedResponses()
		s.cmdResponses = s.cmdResponses[:0]
	}

	s.curState = stateData

	// Read message body until \r\n.\r\n
	msgData, err := s.readDataBody()
	switch {
	case errors.Is(err, errDataTooLarge):
		s.send(552, "Message size exceeds fixed maximum message size")
		s.resetTransaction()
		return
	case errors.Is(err, errDataBareLFDot):
		if s.violation(spam.SymbolProtocolViolation, "bare LF around end of data", false) {
			return
		}
		s.send(554, "Bare LF is not permitted around the end-of-data marker")
		s.resetTransaction()
		return
	case err != nil:
		s.send(451, "Failed to read message data")
		s.resetTransaction()
		return
	}
	s.acceptMessage(msgData)
}

// cmdBDAT handles RFC 3030 message chunks. Unlike DATA, chunk bytes are read
// exactly and are not dot-unescaped. The completed message enters the same
// policy and durable queue path as DATA.
func (s *Session) cmdBDAT(arg string) {
	size, last, err := parseBDATArgument(arg)
	if err != nil {
		s.send(501, err.Error())
		return
	}
	if !s.ehloGiven || s.curState < stateHasRCPT || s.curState == stateData || s.curState == stateQuit || len(s.recipients) == 0 {
		if discardErr := s.discardBDATChunk(size); discardErr != nil {
			s.send(451, "Failed to read message chunk")
			return
		}
		s.send(503, "Bad sequence of commands")
		return
	}
	currentSize := int64(len(s.bdatData))
	maxInt := int64(^uint(0) >> 1)
	if size > maxInt || currentSize > maxInt-size || (s.cfg.MaxMessageSize > 0 && currentSize+size > s.cfg.MaxMessageSize) {
		if discardErr := s.discardBDATChunk(size); discardErr != nil {
			s.send(451, "Failed to read message chunk")
		} else {
			s.send(552, "Message size exceeds fixed maximum message size")
		}
		s.resetTransaction()
		return
	}
	chunk := make([]byte, int(size))
	if _, err := io.ReadFull(s.rw.Reader, chunk); err != nil {
		s.send(451, "Failed to read message chunk")
		s.resetTransaction()
		return
	}
	s.bdatData = append(s.bdatData, chunk...)
	s.bdatActive = !last
	s.dataBytes.Store(int64(len(s.bdatData)))
	if !last {
		s.send(250, "Chunk accepted")
		return
	}
	message := s.bdatData
	s.bdatData = nil
	s.bdatActive = false
	s.acceptMessage(message)
}

func parseBDATArgument(arg string) (int64, bool, error) {
	fields := strings.Fields(arg)
	if len(fields) < 1 || len(fields) > 2 {
		return 0, false, errors.New("Syntax: BDAT chunk-size [LAST]")
	}
	size, err := strconv.ParseUint(fields[0], 10, 63)
	if err != nil {
		return 0, false, errors.New("Invalid BDAT chunk size")
	}
	last := len(fields) == 2
	if last && !strings.EqualFold(fields[1], "LAST") {
		return 0, false, errors.New("Syntax: BDAT chunk-size [LAST]")
	}
	return int64(size), last, nil
}

func (s *Session) discardBDATChunk(size int64) error {
	_, err := io.CopyN(io.Discard, s.rw.Reader, size)
	return err
}

func countHeaderFields(message []byte, target string) int {
	lines := strings.Split(strings.ReplaceAll(string(message), "\r\n", "\n"), "\n")
	count := 0
	for _, line := range lines {
		if line == "" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, _, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), target) {
			count++
		}
	}
	return count
}

// readDataBody reads the DATA body until the terminating dot line.
var (
	// errDataTooLarge reports a DATA body over the size limit; the body was
	// still read to its terminator so no message bytes become commands.
	errDataTooLarge = errors.New("message size exceeds limit")
	// errDataBareLFDot reports a "." line next to a bare LF, the pattern
	// SMTP smuggling uses to make a downstream hop end the message early.
	errDataBareLFDot = errors.New("bare LF around end-of-data marker")
)

// readDataBody reads a DATA body up to the RFC 5321 terminator <CRLF>.<CRLF>
// and returns it with dot-stuffing removed and every line ending in CRLF.
// Only a "." line ending in CRLF after a CRLF-terminated line ends the body;
// a lone bare LF ends a line and is normalized to CRLF. Oversized and
// smuggling-shaped bodies are drained to the terminator before the error is
// returned so the session stays in sync with the client.
func (s *Session) readDataBody() ([]byte, error) {
	var body, line []byte
	var dataErr error
	prevCRLF := true
	for {
		chunk, err := s.rw.Reader.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
		s.dataBytes.Add(int64(len(chunk)))
		if dataErr == nil && s.cfg.MaxMessageSize > 0 && s.dataBytes.Load() > s.cfg.MaxMessageSize {
			dataErr, body = errDataTooLarge, nil
		}
		// Past an error only the first bytes of a line matter: whether it
		// is the terminator.
		if dataErr == nil || len(line) < 4 {
			line = append(line, chunk...)
		}
		if err != nil {
			continue
		}
		crlf := len(chunk) >= 2 && chunk[len(chunk)-2] == '\r' || len(chunk) == 1 && len(line) >= 2 && line[len(line)-2] == '\r'
		switch {
		case prevCRLF && string(line) == ".\r\n":
			return body, dataErr
		case string(line) == ".\n" || string(line) == ".\r\n":
			dataErr, body = errDataBareLFDot, nil
		case dataErr == nil:
			content := line[:len(line)-1]
			if crlf {
				content = content[:len(content)-1]
			}
			content = bytes.TrimPrefix(content, []byte("."))
			body = append(append(body, content...), '\r', '\n')
		}
		prevCRLF = crlf
		line = line[:0]
	}
}

// routeUnknownRecipient asks the split-delivery policy about a recipient no
// local identity hosts.
func (s *Session) routeUnknownRecipient(recipient string) (bool, error) {
	if s.cfg.Delivery == nil || s.cfg.Delivery.RouteUnknownRecipient == nil || s.cfg.Delivery.MailQueue == nil {
		return false, nil
	}
	return s.cfg.Delivery.RouteUnknownRecipient(s.ctx, recipient, extractRemoteIP(s.conn))
}

func (s *Session) canRelay(recipient string) bool {
	if !s.authenticated || s.cfg.Delivery == nil || s.cfg.Delivery.MailQueue == nil {
		return false
	}
	if s.cfg.Delivery.CanRelayRecipient != nil {
		return s.cfg.Delivery.CanRelayRecipient(context.Background(), recipient)
	}
	return s.cfg.Delivery.AllowAuthenticatedRelay
}

// extractDomainFromAddress extracts the domain part from an email address.
// Handles formats like "Name <user@domain.com>" and "user@domain.com".
func extractDomainFromAddress(addr string) string {
	addr = strings.TrimSpace(addr)

	// Look for angle brackets
	if end := strings.LastIndex(addr, ">"); end > 0 {
		start := strings.LastIndex(addr, "<")
		if start >= 0 && start < end {
			addr = addr[start+1 : end]
		}
	}

	// Extract domain after @
	if atIdx := strings.LastIndex(addr, "@"); atIdx >= 0 {
		return strings.ToLower(addr[atIdx+1:])
	}

	return ""
}

// validateEmailAddress validates an email address for SMTP envelope use.
// It accepts both ASCII addresses (RFC 5321) and internationalized addresses
// with non-ASCII characters (RFC 6531 SMTPUTF8). The address may be wrapped
// in angle brackets.
func validateEmailAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	addr = strings.Trim(addr, "<>")

	if addr == "" {
		return fmt.Errorf("empty address")
	}

	// Find the @ separator
	atIdx := strings.LastIndex(addr, "@")
	if atIdx < 1 {
		return fmt.Errorf("missing @ in address")
	}

	local := addr[:atIdx]
	domain := addr[atIdx+1:]

	if local == "" || domain == "" {
		return fmt.Errorf("empty local or domain part")
	}

	// For SMTPUTF8, allow any non-whitespace characters in local and domain
	// RFC 6531: local part can contain UTF8, domain can contain internationalized domain names
	for _, r := range local {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return fmt.Errorf("whitespace in local part")
		}
	}
	for _, r := range domain {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return fmt.Errorf("whitespace in domain part")
		}
	}

	return nil
}
