package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/attachment"
	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// SMTP session states following RFC 5321 command sequencing.
type state int

const (
	stateGreeting state = iota
	statePostEHLO
	stateHasMAIL
	stateHasRCPT
	stateData
	stateQuit
)

func (s state) String() string {
	switch s {
	case stateGreeting:
		return "greeting"
	case statePostEHLO:
		return "post-EHLO"
	case stateHasMAIL:
		return "has-MAIL"
	case stateHasRCPT:
		return "has-RCPT"
	case stateData:
		return "data"
	case stateQuit:
		return "quit"
	default:
		return "unknown"
	}
}

// Session represents one SMTP connection.
type Session struct {
	id      uint64
	cfg     *Config
	conn    net.Conn
	rw      *bufio.ReadWriter
	tracked *proto.Session // shutdown tracking; nil outside an accept loop
	// ctx carries the client IP so credential checks share the failed-login
	// throttle with the other protocols.
	ctx context.Context

	curState state

	// Negotiated features
	heloGiven    bool
	ehloGiven    bool
	heloHostname string // hostname sent in HELO/EHLO
	pipelining   bool   // client announced PIPELINING support
	// heloResult is the HELO policy outcome for heloHostname, reused for the
	// X-HELO-Status and Received fields instead of repeating its DNS lookup.
	heloResult *HeloResult

	// TLS state
	tlsConn *tls.Conn
	tlsDone bool

	// Authentication
	authenticated bool
	authUserID    string
	ntlmCtx       *auth.NtlmContext // NTLM state machine

	// Transaction state
	envelopeSender      string
	recipients          []string
	recipientExpansions map[string][]string
	srsReturns          map[string]string // accepted SRS recipient -> verified return address
	routedRecipients    map[string]bool   // targets accepted for split delivery to another server
	dsnReturn           string
	dsnEnvelopeID       string
	dsnRecipients       map[string]dsnRecipientOptions
	requireTLS          bool
	tlsOptional         bool
	deliveryRecipient   string
	// failedRecipients tracks recipients rejected at RCPT TO time (for DSN)
	failedRecipients []string
	dataBytes        atomic.Int64
	bdatData         []byte
	bdatActive       bool
	// messageHead is the transaction message's header block in arrival order,
	// topped by this hop's Received field. Header-map edits are serialized
	// against it so repeated fields such as Received keep their order.
	messageHead []byte

	// SPF result from checking the envelope sender domain against the client IP
	spfResult *SpfResult

	// DKIM result from verifying the message signature
	dkimResult *DkimResult

	// DMARC result from evaluating policy
	dmarcResult *DmarcResult
	spoofResult *SpoofResult
	// arcResult is the inbound ARC chain validation, nil when not verified.
	arcResult *dkim.ARCResult
	// spamtraps are the transaction's recipients that are spamtraps.
	spamtraps map[string]struct{}
	// spamResult is the transaction's spam score, nil when unscored.
	spamResult *spam.Result
	// attachments is the transaction's attachment inspection.
	attachments attachment.Report
	// spamSample is the transaction's classifier view, nil without a
	// classifier.
	spamSample *spam.Sample
	// deliverySpamResult is the current recipient's score after its own
	// classifier symbol, reported as that delivery's evidence.
	deliverySpamResult *spam.Result

	// Pipelining support (RFC 2920)
	cmdQueue     []string   // buffered commands from pipelining client
	cmdResponses [][]string // accumulated responses: each entry is [code, text]

	// Rate limiting
	cmdLimiter  *ratelimit.Limiter // per-connection command limiter
	authLimiter *ratelimit.Limiter // per-IP auth attempt limiter

	// stagedDeliveries holds one SMTP DATA transaction until every recipient
	// has passed policy processing. The queue commits the slice atomically.
	stagedDeliveries       []*MailMessage
	postCommitActions      []func()
	stagingDelivery        bool
	deliveryCorrelationID  string
	deliveryScanTranscript string
	// originated marks an authorized authenticated submission, whose copies
	// leaving this server are DKIM-signed at queue admission.
	originated bool

	// Connection screening (see screening.go). findings are the session's
	// connection-stage facts for spam evaluation; they survive RSET.
	screenExempt bool
	findings     []spam.ConnectionFinding
	violations   int
	bareLFSeen   bool
	junkCommands int
	unknownRcpts int
	rdnsChecked  bool
	rdnsFindings []spam.ConnectionFinding
}

func newSession(id uint64, cfg *Config, conn net.Conn, cmdLimiter, authLimiter *ratelimit.Limiter) *Session {
	ip := extractRemoteIP(conn)
	return &Session{
		id:           id,
		cfg:          cfg,
		ctx:          ratelimit.WithClientIP(context.Background(), ip),
		conn:         conn,
		rw:           bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		cmdLimiter:   cmdLimiter,
		authLimiter:  authLimiter,
		screenExempt: cfg.Screening.exempt(ip),
	}
}

// run executes the SMTP protocol loop for this session.
func (s *Session) run() {
	defer s.conn.Close()

	// Apply implicit TLS if configured
	if s.cfg.TLSConfig != nil && s.cfg.ImplicitTLS {
		s.tlsConn = tls.Server(s.conn, s.cfg.TLSConfig)
		if err := s.tlsConn.Handshake(); err != nil {
			logger.Error("smtp: TLS handshake failed", "session", s.id, "error", err)
			return
		}
		s.conn = s.tlsConn
		s.rw = bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
		s.tlsDone = true
	}

	s.curState = stateGreeting
	if !s.greet() {
		return
	}

	// Read commands with a timeout
	for {
		s.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		// When pipelining is enabled, try to read multiple commands
		// before processing. We use a short timeout to detect additional
		// commands in the pipeline.
		s.tracked.SetIdle(true)
		err := s.readPipelineCommands()
		s.tracked.SetIdle(false)
		if err != nil {
			if err != io.EOF {
				logger.Error("smtp: read error", "session", s.id, "error", err)
			}
			return
		}
		if s.curState == stateQuit {
			return
		}
		if len(s.cmdQueue) == 0 {
			continue
		}

		// Per-connection command rate limiting
		if s.cmdLimiter != nil {
			key := fmt.Sprintf("smtp-cmd-%d", s.id)
			if !s.cmdLimiter.Allow(key) {
				logger.Warn("smtp: command rate limit exceeded", "session", s.id)
				s.send(421, "Too many commands, try again later")
				return
			}
		}

		// Process all queued commands
		s.flushCommandQueue()

		if s.curState == stateQuit {
			return
		}
	}
}

// readPipelineCommands reads commands from the connection, accumulating
// them into cmdQueue. It reads the first command with the full timeout,
// then, when PIPELINING was negotiated, checks if more data is already
// available in the buffer (pipelined commands sent by the client before
// reading any response). It returns the error that ended the first read;
// the session must end on it. A line longer than maxLineLength is queued
// as overlongLine. A screening violation that ends the session returns with
// curState stateQuit.
func (s *Session) readPipelineCommands() error {
	// Read the first command with the full timeout
	line, err := s.readCommand()
	if err != nil || line == "" || !s.queueCommand(line) || !s.pipelining {
		return err
	}

	// Check if more data is already buffered (pipelined commands).
	// We use Peek to see if there's data already in the buffer without
	// blocking. If the buffer is empty, no pipelined commands are available.
	for s.rw.Reader.Buffered() > 0 {
		// Set a very short deadline — we only want data that's already here
		s.conn.SetReadDeadline(time.Now().Add(time.Millisecond))
		line, err = s.readCommand()
		if err != nil || s.curState == stateQuit {
			break
		}
		if line != "" && !s.queueCommand(line) {
			break
		}
	}

	// Restore the full timeout for processing
	s.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	return nil
}

func commandStartsMessageData(line string) bool {
	command, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	return strings.EqualFold(command, "DATA") || strings.EqualFold(command, "BDAT")
}

// flushCommandQueue processes all queued commands and sends accumulated responses.
func (s *Session) flushCommandQueue() {
	s.cmdResponses = s.cmdResponses[:0]

	for len(s.cmdQueue) > 0 {
		line := s.cmdQueue[0]
		s.cmdQueue = s.cmdQueue[1:]

		// Parse command and argument
		cmd, arg := s.parseCommand(line)

		// Dispatch based on command
		logger.Debug("smtp: dispatch", "session", s.id, "command", cmd)
		upperCommand := strings.ToUpper(cmd)
		if line == overlongLine || upperCommand != "AUTH" && len(line) > maxCommandLength {
			if s.violation(spam.SymbolProtocolViolation, "overlong command line", false) {
				return
			}
			s.send(500, "5.5.2 Line too long")
			continue
		}
		if s.bdatActive && upperCommand != "BDAT" && upperCommand != "RSET" && upperCommand != "QUIT" {
			s.send(503, "BDAT transaction in progress")
			continue
		}
		switch upperCommand {
		case "EHLO":
			s.cmdEHLO(arg)
		case "HELO":
			s.cmdHELO(arg)
		case "MAIL", "SEND", "SOML", "SAML":
			s.cmdMail(cmd, arg)
		case "RCPT":
			s.cmdRCPT(arg)
		case "DATA":
			s.cmdDATA()
		case "BDAT":
			s.cmdBDAT(arg)
		case "RSET":
			if s.junkCommand(upperCommand) {
				return
			}
			s.cmdRSET()
		case "NOOP":
			if s.junkCommand(upperCommand) {
				return
			}
			s.cmdNOOP()
		case "QUIT":
			s.cmdQUIT()
		case "STARTTLS":
			s.cmdSTARTTLS()
		case "AUTH":
			s.cmdAUTH(arg)
		case "VRFY":
			if s.junkCommand(upperCommand) {
				return
			}
			s.cmdVRFY(arg)
		case "EXPN":
			if s.junkCommand(upperCommand) {
				return
			}
			s.cmdEXPN(arg)
		default:
			if s.violation(spam.SymbolProtocolViolation, "unknown command", false) {
				return
			}
			// send queues while pipelining and answers at once otherwise,
			// so an unknown command before EHLO is answered too.
			s.send(502, "Command not implemented")
		}

		// If we entered DATA state or quit, stop processing the queue
		// DATA requires reading the body synchronously
		if s.curState == stateData || s.curState == stateQuit {
			// Send any accumulated responses before reading DATA body
			if s.pipelining && len(s.cmdResponses) > 0 {
				s.sendQueuedResponses()
			}
			return
		}
	}

	// Send all accumulated responses
	if s.pipelining && len(s.cmdResponses) > 0 {
		s.sendQueuedResponses()
	}
}

// sendQueuedResponses sends all accumulated responses at once.
func (s *Session) sendQueuedResponses() {
	for _, resp := range s.cmdResponses {
		// Multi-line continuation codes (e.g. "250-") already include the
		// hyphen and should not have a space inserted between code and text.
		code, text := resp[0], resp[1]
		if strings.HasSuffix(code, "-") {
			s.rw.WriteString(fmt.Sprintf("%s%s\r\n", code, text))
		} else {
			s.rw.WriteString(fmt.Sprintf("%s %s\r\n", code, text))
		}
	}
	s.rw.Flush()
}

// parseCommand splits "EHLO foo" into ("EHLO", "foo").
func (s *Session) parseCommand(line string) (cmd, arg string) {
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		return strings.TrimSpace(line), ""
	}
	return line[:idx], strings.TrimSpace(line[idx+1:])
}

// readLine reads a single line of at most maxLineLength octets, handling
// both \r\n and \n. A longer line is discarded and reported as
// errLineTooLong.
func (s *Session) readLine() (string, error) {
	line, err := s.readRawLine()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (s *Session) readRawLine() (string, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := s.rw.Reader.ReadSlice('\n')
		if !tooLong && len(line)+len(chunk) <= maxLineLength {
			line = append(line, chunk...)
		} else {
			tooLong, line = true, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return "", err
		}
		if tooLong {
			return "", errLineTooLong
		}
		return string(line), nil
	}
}

// overlongLine stands in the command queue for a line longer than
// maxLineLength. No client line can equal it: lines end at their first LF.
const overlongLine = "\n"

// readCommand reads one command line, counting its syntax violations, and
// returns it trimmed, or overlongLine for a discarded overlong line.
func (s *Session) readCommand() (string, error) {
	raw, err := s.readRawLine()
	if errors.Is(err, errLineTooLong) {
		return overlongLine, nil
	}
	if err != nil {
		return "", err
	}
	if s.inspectLine(raw) {
		return "", nil
	}
	return strings.TrimSpace(raw), nil
}

// send formats and sends an SMTP reply.
// When pipelining is active and responses are being queued, this enqueues
// the response instead of sending immediately.
func (s *Session) send(code int, text string) {
	if code >= 500 && code <= 504 {
		s.reportAbuse(ban.TriggerProtocol)
	}
	text = s.enhancedReply(code, text)
	// During DATA body read or STARTTLS/AUTH multi-step, don't queue
	if s.curState == stateData {
		msg := fmt.Sprintf("%d %s\r\n", code, text)
		if _, err := s.rw.WriteString(msg); err != nil {
			logger.Error("smtp: write error", "session", s.id, "error", err)
			return
		}
		s.rw.Flush()
		return
	}

	if s.pipelining {
		s.enqueueResponse(code, text)
		return
	}
	msg := fmt.Sprintf("%d %s\r\n", code, text)
	if _, err := s.rw.WriteString(msg); err != nil {
		logger.Error("smtp: write error", "session", s.id, "error", err)
		return
	}
	s.rw.Flush()
}

// reportAbuse strikes the client address with the abuse ban engine.
// Authenticated sessions are never struck. Connection-stage protocol checks
// (early talkers, pipelining violations) report through it too.
func (s *Session) reportAbuse(trigger ban.Trigger) {
	if s.cfg.Abuse != nil && !s.authenticated {
		s.cfg.Abuse.Strike(extractRemoteIP(s.conn), trigger)
	}
}

// enqueueResponse adds a response to the queue for pipelined delivery.
func (s *Session) enqueueResponse(code int, text string) {
	s.cmdResponses = append(s.cmdResponses, []string{fmt.Sprintf("%d", code), s.enhancedReply(code, text)})
}

// sendImmediate sends a response immediately, bypassing the pipelining queue.
// Used for interactive multi-step exchanges (AUTH challenges, STARTTLS, DATA).
func (s *Session) sendImmediate(code int, text string) {
	text = s.enhancedReply(code, text)
	msg := fmt.Sprintf("%d %s\r\n", code, text)
	if _, err := s.rw.WriteString(msg); err != nil {
		logger.Error("smtp: write error", "session", s.id, "error", err)
		return
	}
	s.rw.Flush()
}

// enhancedReply applies RFC 2034 after an EHLO client has negotiated the
// extension. Greeting/EHLO responses and 3xx challenges intentionally remain
// unchanged. Command handlers can provide a more specific enhanced code; this
// fallback only fills a missing one.
func (s *Session) enhancedReply(code int, text string) string {
	if !s.ehloGiven || hasEnhancedStatusCode(text) {
		return text
	}
	enhanced := map[int]string{
		211: "2.0.0", 214: "2.0.0", 220: "2.0.0", 221: "2.0.0", 235: "2.7.0",
		250: "2.0.0", 251: "2.1.5", 252: "2.1.5",
		421: "4.3.2", 450: "4.2.0", 451: "4.3.0", 452: "4.3.1", 454: "4.7.0",
		500: "5.5.2", 501: "5.5.2", 502: "5.5.1", 503: "5.5.1", 504: "5.5.4",
		530: "5.7.0", 534: "5.7.9", 535: "5.7.8", 538: "5.7.11",
		550: "5.0.0", 551: "5.1.6", 552: "5.3.4", 553: "5.1.3", 554: "5.0.0", 555: "5.5.4",
	}[code]
	if enhanced == "" {
		return text
	}
	return enhanced + " " + text
}

// hasEnhancedStatusCode reports whether text starts with an RFC 3463 status
// code: class "." subject "." detail, where subject and detail have one to
// three digits (5.7.11, 5.7.30, 4.7.112).
func hasEnhancedStatusCode(text string) bool {
	code, _, _ := strings.Cut(text, " ")
	parts := strings.Split(code, ".")
	if len(parts) != 3 || len(parts[0]) != 1 || !strings.Contains("245", parts[0]) {
		return false
	}
	for _, part := range parts[1:] {
		if len(part) < 1 || len(part) > 3 {
			return false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
		}
	}
	return true
}

// sendMulti sends a multi-line SMTP reply (code- for continuation, code for final).
func (s *Session) sendMulti(code int, lines []string) {
	// The last line carries the final text: an EHLO reply ends with its last
	// keyword, never a filler line clients would parse as an extension.
	if s.pipelining {
		for index, line := range lines {
			separator := "-"
			if index == len(lines)-1 {
				separator = ""
			}
			s.cmdResponses = append(s.cmdResponses, []string{fmt.Sprintf("%d%s", code, separator), line})
		}
		return
	}

	for index, line := range lines {
		separator := "-"
		if index == len(lines)-1 {
			separator = " "
		}
		s.rw.WriteString(fmt.Sprintf("%d%s%s\r\n", code, separator, line))
	}
	s.rw.Flush()
}

// cmdEHLO handles the EHLO command (RFC 5321).
func (s *Session) cmdEHLO(arg string) {
	if s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	// Evaluate HELO policy
	result := s.evaluateHeloPolicy(arg)
	if !result.Pass {
		if s.cfg.HeloPolicy.Mode == HeloPolicyReject {
			s.send(result.RejectionCode, result.RejectionText)
			return
		}
		// Warn mode: log the warning but allow the connection
		logger.Warn("smtp: HELO policy warning", "session", s.id, "helo", arg, "warnings", result.Warnings)
	}

	s.heloGiven = true
	s.ehloGiven = true
	s.heloHostname = arg
	s.heloResult = result
	s.pipelining = true
	s.curState = statePostEHLO

	// Build extension list
	ext := []string{s.cfg.ServerName}

	if s.cfg.TLSConfig != nil && !s.tlsDone {
		ext = append(ext, "STARTTLS")
	}

	if mechanisms := s.allowedAuthMechanisms(); len(mechanisms) > 0 && (!s.cfg.RequireTLSForAuth || s.tlsDone) {
		ext = append(ext, "AUTH "+strings.Join(mechanisms, " "))
	}

	ext = append(ext, "PIPELINING")
	ext = append(ext, "8BITMIME")
	ext = append(ext, "SMTPUTF8")
	ext = append(ext, "CHUNKING")
	ext = append(ext, "ENHANCEDSTATUSCODES")
	ext = append(ext, "DSN")
	// RFC 8689 permits REQUIRETLS only on a TLS-protected session. Advertising
	// it after STARTTLS also promises that onward delivery will preserve it.
	if s.tlsDone {
		ext = append(ext, "REQUIRETLS")
	}
	if s.cfg.SaslIrEnabled {
		ext = append(ext, "SASLIR")
	}
	if s.cfg.MaxMessageSize > 0 {
		ext = append(ext, fmt.Sprintf("SIZE %d", s.cfg.MaxMessageSize))
	} else {
		ext = append(ext, "SIZE")
	}
	if s.cfg.MaxRecipients > 0 {
		// RFC 9422 LIMITS lets clients split large recipient lists up front.
		ext = append(ext, fmt.Sprintf("LIMITS RCPTMAX=%d", s.cfg.MaxRecipients))
	}
	if s.cfg.VrfyEnabled {
		ext = append(ext, "VRFY")
	}
	if s.cfg.ExpnEnabled {
		ext = append(ext, "EXPN")
	}

	s.sendMulti(250, ext)
}

// cmdHELO handles the HELO fallback (RFC 5321).
func (s *Session) cmdHELO(arg string) {
	if s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	// Evaluate HELO policy
	result := s.evaluateHeloPolicy(arg)
	if !result.Pass {
		if s.cfg.HeloPolicy.Mode == HeloPolicyReject {
			s.send(result.RejectionCode, result.RejectionText)
			return
		}
		// Warn mode: log the warning but allow the connection
		logger.Warn("smtp: HELO policy warning", "session", s.id, "helo", arg, "warnings", result.Warnings)
	}

	s.heloGiven = true
	s.ehloGiven = false
	s.heloHostname = arg
	s.heloResult = result
	s.pipelining = false // HELO does not support extensions
	s.curState = statePostEHLO
	s.send(250, fmt.Sprintf("%s", s.cfg.ServerName))
}

// resetTransaction clears the current transaction state (MAIL/RCPT).
func (s *Session) resetTransaction() {
	s.envelopeSender = ""
	s.recipients = nil
	s.recipientExpansions = nil
	s.srsReturns = nil
	s.routedRecipients = nil
	s.dsnReturn = ""
	s.dsnEnvelopeID = ""
	s.requireTLS = false
	s.tlsOptional = false
	s.dsnRecipients = nil
	s.deliveryRecipient = ""
	s.failedRecipients = nil
	s.dataBytes.Store(0)
	s.bdatData = nil
	s.bdatActive = false
	s.messageHead = nil
	s.spfResult = nil
	s.dkimResult = nil
	s.dmarcResult = nil
	s.spoofResult = nil
	s.arcResult = nil
	s.spamtraps = nil
	s.spamResult = nil
	s.attachments = attachment.Report{}
	s.spamSample = nil
	s.stagingDelivery = false
	s.stagedDeliveries = nil
	s.postCommitActions = nil
	s.deliveryCorrelationID = ""
	s.originated = false
	if s.curState == stateData || s.curState == stateHasRCPT || s.curState == stateHasMAIL {
		s.curState = statePostEHLO
	}
}

// cmdRSET handles the RSET command (RFC 5321).
func (s *Session) cmdRSET() {
	if s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	s.resetTransaction()
	s.send(250, "OK")
}

// cmdNOOP handles the NOOP command (RFC 5321).
func (s *Session) cmdNOOP() {
	s.send(250, "OK")
}

// cmdQUIT handles the QUIT command (RFC 5321).
func (s *Session) cmdQUIT() {
	s.send(221, fmt.Sprintf("%s closing connection", s.cfg.ServerName))
	s.curState = stateQuit
}

// cmdVRFY handles the VRFY command (RFC 5321 Section 4.1.1.1).
// Verifies that the given address is recognized by the server.
// Returns 250 if the address is valid, 550 if not.
// This command is disabled by default due to user enumeration risk.
func (s *Session) cmdVRFY(arg string) {
	if !s.cfg.VrfyEnabled {
		s.send(502, "VRFY command not implemented")
		return
	}

	if s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	arg = strings.TrimSpace(arg)
	if arg == "" {
		s.send(501, "Syntax: VRFY <string>")
		return
	}

	// Strip angle brackets if present
	addr := strings.Trim(arg, "<>")
	addr = strings.ToLower(addr)

	// If we have a delivery resolver, try to look up the address
	if s.cfg.Delivery != nil && s.cfg.Delivery.ResolveRecipient != nil {
		_, _, err := s.cfg.Delivery.ResolveRecipient(s.ctx, addr)
		if err != nil && !errors.Is(err, ErrRecipientDiscarded) {
			s.reportAbuse(ban.TriggerRecipient)
			s.send(550, "User unknown")
			return
		}
		s.send(250, fmt.Sprintf("%s is a valid address", addr))
		return
	}

	// No resolver available — cannot verify
	s.send(502, "VRFY not available")
}

// cmdEXPN handles the EXPN command (RFC 5321 Section 4.1.1.2).
// Expands a mailing list name into its member addresses.
// Returns 502 not implemented by default; this command is disabled
// by default due to mailing-list enumeration risk.
func (s *Session) cmdEXPN(arg string) {
	if !s.cfg.ExpnEnabled {
		s.send(502, "EXPN command not implemented")
		return
	}

	if s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	arg = strings.TrimSpace(arg)
	if arg == "" {
		s.send(501, "Syntax: EXPN <list-name>")
		return
	}

	// Mailing list expansion is not offered (RFC 5321 section 3.5.2).
	s.send(502, "EXPN not implemented")
}
