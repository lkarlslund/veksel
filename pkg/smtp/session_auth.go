package smtp

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// cmdSTARTTLS handles the STARTTLS command (RFC 3207).
func (s *Session) cmdSTARTTLS() {
	if s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}

	if s.cfg.TLSConfig == nil || s.tlsDone {
		s.send(502, "STARTTLS not available")
		return
	}

	// STARTTLS must end a pipelined group (RFC 3207 section 4.2). Anything
	// after it was sent in cleartext and must not run as if it had arrived
	// under TLS (CVE-2011-0411 class command injection).
	if len(s.cmdQueue) > 0 || s.rw.Reader.Buffered() > 0 {
		logger.Warn("smtp: commands pipelined after STARTTLS", "session", s.id)
		s.cmdQueue = nil
		s.send(421, "Commands pipelined after STARTTLS refused, closing connection")
		s.curState = stateQuit
		return
	}

	s.send(220, "Ready to start TLS")
	// Flush immediately — client needs the 220 before upgrading to TLS
	if s.pipelining && len(s.cmdResponses) > 0 {
		s.sendQueuedResponses()
		s.cmdResponses = s.cmdResponses[:0]
	}

	// Upgrade connection to TLS
	s.tlsConn = tls.Server(s.conn, s.cfg.TLSConfig)
	if err := s.tlsConn.Handshake(); err != nil {
		logger.Error("smtp: STARTTLS handshake failed", "session", s.id, "error", err)
		s.send(454, "TLS handshake failed")
		return
	}

	s.conn = s.tlsConn
	s.rw = bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
	s.tlsDone = true

	// Reset state to force EHLO after TLS
	s.curState = stateGreeting
	s.ehloGiven = false
	s.heloGiven = false
	s.pipelining = false
}

// cmdAUTH handles the AUTH command (RFC 4954).
func (s *Session) cmdAUTH(arg string) {
	// Credentials offered in cleartext to the inbound relay listener are
	// probing, never a legitimate submission.
	if !s.tlsDone && !s.cfg.AuthRequired && s.violation(spam.SymbolProtocolViolation, "AUTH without TLS", false) {
		return
	}
	if s.curState < statePostEHLO || s.curState == stateData || s.curState == stateQuit {
		s.send(503, "Bad sequence of commands")
		return
	}
	// RFC 4954 4: AUTH is not allowed once a session is authenticated.
	if s.authenticated {
		s.send(503, "5.5.1 Already authenticated")
		return
	}

	if s.cfg.AuthValidator == nil {
		s.send(502, "AUTH not available")
		return
	}
	if s.cfg.RequireTLSForAuth && !s.tlsDone {
		s.send(538, "Encryption required for requested authentication mechanism")
		return
	}

	// Per-IP auth attempt rate limiting
	if s.authLimiter != nil {
		ip := extractRemoteIP(s.conn)
		if !s.authLimiter.Allow(ip) {
			logger.Warn("smtp: auth rate limit exceeded", "session", s.id, "ip", ip)
			s.send(421, "Too many authentication attempts, try again later")
			return
		}
	}

	arg = strings.TrimSpace(arg)
	parts := strings.Fields(arg)
	if len(parts) == 0 {
		s.send(502, "5.5.1 Send AUTH mechanism")
		return
	}

	mechanism := strings.ToUpper(parts[0])
	if !s.authMechanismAllowed(mechanism) {
		s.send(504, "Unsupported AUTH mechanism")
		return
	}

	switch mechanism {
	case "PLAIN", "LOGIN":
		initial := ""
		if len(parts) > 1 && s.cfg.SaslIrEnabled {
			initial = parts[1] // RFC 4954 initial response
		}
		s.authPassword(mechanism, initial)
	case "XOAUTH2":
		s.authXOAUTH2(arg)
	case "NTLM":
		s.authNTLM(arg)
	default:
		s.send(504, "Unsupported AUTH mechanism")
	}
}

func (s *Session) allowedAuthMechanisms() []string {
	result := make([]string, 0, len(s.cfg.AuthMechanisms))
	seen := make(map[string]struct{}, len(s.cfg.AuthMechanisms))
	for _, configured := range s.cfg.AuthMechanisms {
		mechanism := strings.ToUpper(strings.TrimSpace(configured))
		if mechanism == "" {
			continue
		}
		if mechanism == "XOAUTH2" && s.cfg.OAuth2Validator == nil {
			continue
		}
		if mechanism == "NTLM" && !s.cfg.NtlmEnabled {
			continue
		}
		if _, exists := seen[mechanism]; exists {
			continue
		}
		seen[mechanism] = struct{}{}
		result = append(result, mechanism)
	}
	return result
}

func (s *Session) authMechanismAllowed(mechanism string) bool {
	for _, allowed := range s.allowedAuthMechanisms() {
		if allowed == mechanism {
			return true
		}
	}
	return false
}

// authPassword handles AUTH PLAIN (RFC 4616) and AUTH LOGIN through the shared
// SASL exchange; this method only frames 334 challenges and replies.
func (s *Session) authPassword(mechanism, initial string) {
	username, password, err := auth.RunPasswordExchange(mechanism, initial, func(challenge string) (string, error) {
		s.sendImmediate(334, challenge)
		return s.readLine()
	})
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrSASLCanceled):
		s.send(501, "Authentication canceled")
		return
	case errors.Is(err, auth.ErrSASLEncoding):
		s.send(501, "Invalid base64")
		return
	case errors.Is(err, auth.ErrSASLMalformed):
		s.send(501, fmt.Sprintf("Invalid %s credentials", mechanism))
		return
	case errors.Is(err, auth.ErrSASLAuthzid):
		s.send(535, "Authentication failed")
		return
	default: // connection read failure
		s.send(501, "Auth failed")
		return
	}

	userID, err := s.cfg.AuthValidator(s.ctx, username, password)
	if err != nil {
		s.sendAuthFailure(err)
		return
	}
	s.refundAuthAttempt()
	s.authenticated = true
	s.authUserID = userID
	s.send(235, "Authentication successful")
}

// sendAuthFailure replies to a rejected credential. Throttling is a temporary
// failure (RFC 4954 454) so clients retry later instead of prompting for a new
// password; it reveals nothing about the account.
func (s *Session) sendAuthFailure(err error) {
	if errors.Is(err, ratelimit.ErrAuthThrottled) {
		s.send(454, "Temporary authentication failure; retry later")
		return
	}
	s.send(535, "Authentication failed")
}

// authXOAUTH2 handles AUTH XOAUTH2 (RFC 7628).
func (s *Session) authXOAUTH2(arg string) {
	if s.cfg.OAuth2Validator == nil {
		s.send(504, "XOAUTH2 not available")
		return
	}

	parts := strings.Fields(arg)
	if len(parts) < 2 || !s.cfg.SaslIrEnabled {
		s.send(501, "Invalid XOAUTH2 response")
		return
	}

	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		s.send(501, "Invalid base64")
		return
	}

	email, token, err := auth.ParseXOAUTH2Response(data)
	if err != nil {
		s.send(535, "Authentication failed")
		return
	}

	userID, err := s.cfg.OAuth2Validator(s.ctx, email, token)
	if err != nil {
		s.send(535, "Authentication failed")
		return
	}

	s.refundAuthAttempt()
	s.authenticated = true
	s.authUserID = userID
	s.send(235, "Authentication successful")
}

// authNTLM handles AUTH NTLM (NTLMSSP three-message exchange).
// The NTLM protocol uses base64-encoded binary messages:
// 1. Client sends AUTH NTLM <base64-type1>
// 2. Server responds with 334 <base64-type2>
// 3. Client sends <base64-type3>
// 4. Server responds with 235 on success
func (s *Session) authNTLM(arg string) {
	if !s.cfg.NtlmEnabled {
		s.send(504, "NTLM not available")
		return
	}

	parts := strings.Fields(arg)
	if len(parts) < 2 {
		s.send(501, "NTLM requires initial response")
		return
	}

	// Decode Type-1 message
	type1Data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		s.send(501, "Invalid base64")
		return
	}

	// Initialize NTLM context and process Type-1
	if s.ntlmCtx == nil {
		s.ntlmCtx = auth.NewNtlmContext()
	}
	type2Data, err := s.ntlmCtx.ProcessType1(type1Data)
	if err != nil {
		s.send(535, fmt.Sprintf("NTLM failed: %v", err))
		return
	}

	// Send Type-2 challenge (334 response with base64-encoded challenge)
	s.sendImmediate(334, base64.StdEncoding.EncodeToString(type2Data))

	// Read Type-3 response
	line, err := s.readLine()
	if err != nil {
		s.send(535, "NTLM failed")
		return
	}

	type3Data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		s.send(501, "Invalid base64")
		return
	}

	// Process Type-3
	if err := s.ntlmCtx.ProcessType3(type3Data); err != nil {
		s.send(535, fmt.Sprintf("NTLM failed: %v", err))
		return
	}

	// Validate credentials
	if s.cfg.AuthValidator == nil {
		s.send(535, "Authentication disabled")
		return
	}

	userID, err := s.cfg.AuthValidator(s.ctx, s.ntlmCtx.Username, "")
	if err != nil {
		s.sendAuthFailure(err)
		return
	}

	s.refundAuthAttempt()
	s.authenticated = true
	s.authUserID = userID
	s.send(235, "Authentication successful")
}

// refundAuthAttempt returns the per-IP attempt token consumed when
// authentication began. The limiter exists to slow guessing, so only failed
// attempts may count: clients legitimately open many authenticated connections
// at once (a mail app per folder, several devices behind one NAT address).
func (s *Session) refundAuthAttempt() {
	if s.authLimiter != nil {
		s.authLimiter.Refund(extractRemoteIP(s.conn))
	}
}
