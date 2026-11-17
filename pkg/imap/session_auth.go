package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
)

// cmdStartTLS handles the STARTTLS command (RFC 2595).
func (s *Session) cmdStartTLS(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "STARTTLS does not accept arguments")
		return
	}
	if s.cfg.TLSConfig == nil || s.tlsDone {
		s.sendNO(tag, "STARTTLS not available")
		return
	}

	// The client must wait for the tagged response before starting the
	// handshake (RFC 9051 section 6.2.1). Bytes it sent early were read in
	// cleartext and would otherwise be lost, or executed as if they had
	// arrived under TLS (CVE-2011-0411 class command injection).
	if s.rw.Reader.Buffered() > 0 {
		logger.Warn("imap: data pipelined after STARTTLS", "session", s.id)
		s.sendUntagged("* BYE Data received after STARTTLS before TLS negotiation")
		s.curState = stateLogout
		return
	}

	s.sendOK(tag, "Begin TLS negotiation")

	tlsConn := tls.Server(s.conn, serverTLSConfig(s.cfg.TLSConfig))
	if err := handshakeTLS(tlsConn); err != nil {
		// The stream is neither cleartext nor TLS now, so nothing more can
		// be said to the client.
		logger.Error("imap: STARTTLS handshake failed", "session", s.id, "error", err)
		s.curState = stateLogout
		return
	}

	s.conn = tlsConn
	s.rw = bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
	s.tlsDone = true
}

// tlsHandshakeTimeout bounds a TLS handshake so a client that stops
// mid-negotiation cannot hold the session for the full command timeout.
const tlsHandshakeTimeout = 30 * time.Second

// handshakeTLS completes the server handshake on conn within
// tlsHandshakeTimeout.
func handshakeTLS(conn *tls.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
	defer cancel()
	return conn.HandshakeContext(ctx)
}

// serverTLSConfig returns the IMAP handshake configuration derived from
// config, including any per-client configuration it selects: at least TLS 1.2
// and no session tickets.
//
// Go sends its TLS 1.3 session ticket in the same flight as the server
// Finished. imaplib2 (used by OfflineIMAP) reads that ticket in its reader
// thread while its writer thread sends the next command on the same OpenSSL
// connection, which OpenSSL does not support; in roughly one handshake in
// twelve the command never reaches the server and the client waits forever.
// IMAP connections are long-lived, so session resumption saves little.
func serverTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}
	secure := imapTLSPolicy(config)
	if selectConfig := config.GetConfigForClient; selectConfig != nil {
		secure.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := selectConfig(hello)
			if err != nil || selected == nil {
				return selected, err
			}
			return imapTLSPolicy(selected), nil
		}
	}
	return secure
}

// imapTLSPolicy returns a copy of config with the IMAP TLS policy applied.
func imapTLSPolicy(config *tls.Config) *tls.Config {
	secure := config.Clone()
	secure.MinVersion = max(secure.MinVersion, tls.VersionTLS12)
	secure.SessionTicketsDisabled = true
	return secure
}

// plaintextAuthPermitted reports whether credentials may be sent in the clear
// on this connection: either TLS is active or the listener opted out.
func (s *Session) plaintextAuthPermitted() bool {
	return !s.cfg.RequireTLSForAuth || s.tlsDone
}

// sendPrivacyRequired refuses authentication on a cleartext connection
// (RFC 9051 section 7.1) without consulting any credential validator.
func (s *Session) sendPrivacyRequired(tag string) {
	s.sendNO(tag, "[PRIVACYREQUIRED] TLS is required for authentication")
}

// cmdLogin handles the LOGIN command (RFC 3501).
func (s *Session) cmdLogin(tag string, args []string) {
	if len(args) != 2 {
		s.sendBAD(tag, "Expected: LOGIN username password")
		return
	}
	if !s.plaintextAuthPermitted() {
		s.sendPrivacyRequired(tag)
		return
	}

	// Per-IP auth attempt rate limiting
	if s.authLimiter != nil {
		ip := extractRemoteIP(s.conn)
		if !s.authLimiter.Allow(ip) {
			logger.Warn("imap: auth rate limit exceeded", "session", s.id, "ip", ip)
			s.sendNO(tag, "Too many authentication attempts, try again later")
			return
		}
	}

	username := args[0]
	password := args[1]

	if s.cfg.AuthValidator == nil {
		s.sendNO(tag, "Login disabled")
		return
	}

	userID, err := s.cfg.AuthValidator(*s.ctx, username, password)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	s.refundAuthAttempt()
	s.authenticated = true
	s.userID = userID
	s.curState = stateAuthenticated
	s.sendOK(tag, "LOGIN completed")
}

// cmdAuthenticate handles the AUTHENTICATE command (RFC 3501, RFC 4616).
func (s *Session) cmdAuthenticate(tag string, args []string) {
	if len(args) < 1 {
		s.sendBAD(tag, "Expected: AUTHENTICATE mechanism")
		return
	}

	// Per-IP auth attempt rate limiting
	if s.authLimiter != nil {
		ip := extractRemoteIP(s.conn)
		if !s.authLimiter.Allow(ip) {
			logger.Warn("imap: auth rate limit exceeded", "session", s.id, "ip", ip)
			s.sendNO(tag, "Too many authentication attempts, try again later")
			return
		}
	}

	mechanism := strings.ToUpper(args[0])
	switch mechanism {
	case "PLAIN", "LOGIN", "XOAUTH2":
		if !s.plaintextAuthPermitted() {
			s.sendPrivacyRequired(tag)
			return
		}
	}
	switch mechanism {
	case "PLAIN", "LOGIN":
		s.authPassword(tag, mechanism, args)
	case "XOAUTH2":
		s.authXOAUTH2(tag, args)
	case "NTLM":
		s.authNTLM(tag, args)
	default:
		s.sendNO(tag, fmt.Sprintf("SASL mechanism %s not supported", mechanism))
	}
}

// authPassword handles AUTHENTICATE PLAIN (RFC 4616) and LOGIN through the
// shared SASL exchange; this method only frames continuations and replies.
func (s *Session) authPassword(tag, mechanism string, args []string) {
	if s.cfg.AuthValidator == nil {
		s.sendNO(tag, "Authentication disabled")
		return
	}
	initial := ""
	if len(args) >= 2 && s.cfg.SaslIrEnabled {
		initial = args[1] // SASL-IR (RFC 4959)
	}
	username, password, err := auth.RunPasswordExchange(mechanism, initial, func(challenge string) (string, error) {
		s.sendContinuation(challenge)
		return s.readLine()
	})
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrSASLCanceled):
		s.sendBAD(tag, "Authentication canceled")
		return
	case errors.Is(err, auth.ErrSASLEncoding):
		s.sendBAD(tag, "Invalid base64")
		return
	case errors.Is(err, auth.ErrSASLMalformed):
		s.sendBAD(tag, fmt.Sprintf("Invalid %s credentials", mechanism))
		return
	case errors.Is(err, auth.ErrSASLAuthzid):
		s.sendNO(tag, "[AUTHORIZATIONFAILED] Authorization identity is not supported")
		return
	default: // connection read failure
		s.sendNO(tag, "Auth failed")
		return
	}

	userID, err := s.cfg.AuthValidator(*s.ctx, username, password)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	s.refundAuthAttempt()
	s.authenticated = true
	s.userID = userID
	s.curState = stateAuthenticated
	s.sendOK(tag, fmt.Sprintf("AUTHENTICATE %s completed", mechanism))
}

// authXOAUTH2 handles AUTHENTICATE XOAUTH2 (RFC 7628).
func (s *Session) authXOAUTH2(tag string, args []string) {
	if s.cfg.OAuth2Validator == nil {
		s.sendNO(tag, "XOAUTH2 not available")
		return
	}

	var data []byte
	var err error

	if len(args) >= 2 && s.cfg.SaslIrEnabled {
		// Initial response provided (SASL-IR, RFC 8305)
		data, err = base64.StdEncoding.DecodeString(args[1])
	} else {
		// Challenge-response
		s.sendContinuation("")
		line, readErr := s.readLine()
		if readErr != nil {
			s.sendNO(tag, "Auth failed")
			return
		}
		data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	}

	if err != nil {
		s.sendBAD(tag, "Invalid base64")
		return
	}

	// Parse the XOAUTH2 response to get email and token
	email, token, parseErr := auth.ParseXOAUTH2Response(data)
	if parseErr != nil {
		s.sendNO(tag, fmt.Sprintf("Authentication failed: invalid XOAUTH2 response"))
		return
	}

	userID, err := s.cfg.OAuth2Validator(*s.ctx, email, token)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	s.refundAuthAttempt()
	s.authenticated = true
	s.userID = userID
	s.curState = stateAuthenticated
	s.sendOK(tag, "AUTHENTICATE XOAUTH2 completed")
}

// authNTLM handles AUTHENTICATE NTLM (NTLMSSP three-message exchange).
// The NTLM protocol uses base64-encoded binary messages:
// 1. Client sends AUTHENTICATE NTLM <base64-type1>
// 2. Server responds with + <base64-type2>
// 3. Client sends <base64-type3>
// 4. Server responds with tagged OK on success
func (s *Session) authNTLM(tag string, args []string) {
	if !s.cfg.NtlmEnabled {
		s.sendNO(tag, "NTLM not available")
		return
	}

	var type1Data []byte
	var err error

	if len(args) >= 2 && s.cfg.SaslIrEnabled {
		// Initial response provided (SASL-IR, RFC 8305)
		type1Data, err = base64.StdEncoding.DecodeString(args[1])
	} else {
		// Challenge-response
		s.sendContinuation("")
		line, readErr := s.readLine()
		if readErr != nil {
			s.sendNO(tag, "NTLM failed")
			return
		}
		type1Data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	}

	if err != nil {
		s.sendBAD(tag, "Invalid base64")
		return
	}

	// Initialize NTLM context and process Type-1
	if s.ntlmCtx == nil {
		s.ntlmCtx = auth.NewNtlmContext()
	}
	type2Data, err := s.ntlmCtx.ProcessType1(type1Data)
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("NTLM failed: %v", err))
		return
	}

	// Send Type-2 challenge (continuation response with base64-encoded challenge)
	s.sendContinuation(base64.StdEncoding.EncodeToString(type2Data))

	// Read Type-3 response
	line, err := s.readLine()
	if err != nil {
		s.sendNO(tag, "NTLM failed")
		return
	}

	type3Data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		s.sendBAD(tag, "Invalid base64")
		return
	}

	// Process Type-3
	if err := s.ntlmCtx.ProcessType3(type3Data); err != nil {
		s.sendNO(tag, fmt.Sprintf("NTLM failed: %v", err))
		return
	}

	// Validate credentials
	if s.cfg.AuthValidator == nil {
		s.sendNO(tag, "Authentication disabled")
		return
	}

	userID, err := s.cfg.AuthValidator(*s.ctx, s.ntlmCtx.Username, "")
	if err != nil {
		s.sendNO(tag, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	s.refundAuthAttempt()
	s.authenticated = true
	s.userID = userID
	s.curState = stateAuthenticated
	s.sendOK(tag, "AUTHENTICATE NTLM completed")
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
