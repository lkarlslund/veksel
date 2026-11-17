package smtp

import (
	"crypto/tls"
	"net"
	"strings"
	"time"
)

// receivedField returns the trace field this hop prepends to every accepted
// message (RFC 5321 section 4.4), folded one clause per line:
//
//	Received: from client.example.org (mail.example.org [192.0.2.10])
//		by mx.example.com (Veksel) with ESMTPS id smtp-transaction-1-2
//		(using TLSv1.3 with cipher TLS_AES_128_GCM_SHA256)
//		for <bob@example.com>; Mon, 02 Jan 2026 15:04:05 +0000
//
// The client address is the effective one, so a PROXY protocol relayed
// address appears instead of the load balancer's. The reverse DNS name comes
// from the HELO policy check and is omitted when that check found none. The
// for clause names the recipient only when there is exactly one, so a
// multi-recipient message does not disclose its other recipients. With
// SubmissionReceivedPrivacy an authenticated submission carries no client
// address or reverse DNS name.
func (s *Session) receivedField(id string, now time.Time) string {
	literal := addressLiteral(extractRemoteIP(s.conn))
	var b strings.Builder
	b.WriteString("Received: from ")
	switch helo := traceToken(s.heloHostname); {
	case helo != "":
		b.WriteString(helo)
	case literal != "":
		b.WriteString(literal)
	default:
		b.WriteString("unknown")
	}
	if literal != "" && !(s.authenticated && s.cfg.SubmissionReceivedPrivacy) {
		b.WriteString(" (")
		if s.heloResult != nil {
			if name := traceToken(s.heloResult.ReverseDNS); name != "" {
				b.WriteString(name)
				b.WriteByte(' ')
			}
		}
		b.WriteString(literal)
		b.WriteByte(')')
	}
	serverName := traceToken(s.cfg.ServerName)
	if serverName == "" {
		serverName = "localhost"
	}
	b.WriteString("\r\n\tby ")
	b.WriteString(serverName)
	b.WriteString(" (Veksel) with ")
	b.WriteString(s.receivedProtocol())
	b.WriteString(" id ")
	b.WriteString(id)
	if s.tlsConn != nil {
		state := s.tlsConn.ConnectionState()
		b.WriteString("\r\n\t(using ")
		b.WriteString(tlsVersionName(state.Version))
		b.WriteString(" with cipher ")
		b.WriteString(tls.CipherSuiteName(state.CipherSuite))
		b.WriteByte(')')
	}
	if len(s.recipients) == 1 {
		if recipient := traceToken(s.recipients[0]); recipient != "" {
			b.WriteString("\r\n\tfor <")
			b.WriteString(recipient)
			b.WriteByte('>')
		}
	}
	b.WriteString("; ")
	b.WriteString(now.Format(time.RFC1123Z))
	return b.String()
}

// receivedProtocol returns the RFC 3848 "with" keyword for the session:
// SMTP after HELO, otherwise ESMTP with S for TLS and A for authentication.
func (s *Session) receivedProtocol() string {
	if !s.ehloGiven {
		return "SMTP"
	}
	protocol := "ESMTP"
	if s.tlsDone {
		protocol += "S"
	}
	if s.authenticated {
		protocol += "A"
	}
	return protocol
}

// addressLiteral formats ip as an RFC 5321 address literal: [192.0.2.1] or
// [IPv6:2001:db8::1]. It returns "" for a value that is not an IP address.
func addressLiteral(ip string) string {
	parsed := net.ParseIP(ip)
	switch {
	case parsed == nil:
		return ""
	case parsed.To4() != nil:
		return "[" + parsed.To4().String() + "]"
	default:
		return "[IPv6:" + parsed.String() + "]"
	}
}

// tlsVersionName returns the conventional trace name of a TLS version.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return strings.ReplaceAll(tls.VersionName(version), " ", "")
	}
}

// traceToken bounds a client-supplied value for a Received clause: it keeps
// printable characters other than the comment and clause delimiters, so a
// HELO argument cannot open a comment, end the field early, or fold it.
func traceToken(value string) string {
	value = strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("();\\<>", r) {
			return -1
		}
		return r
	}, value)
	if len(value) > 255 {
		value = strings.ToValidUTF8(value[:255], "")
	}
	return value
}
