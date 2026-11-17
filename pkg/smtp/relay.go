// Package smtp provides an outbound SMTP relay client for delivering mail
// to external domains.
//
// The relay client connects to remote MTAs, negotiates TLS via STARTTLS,
// optionally authenticates, and delivers messages following RFC 5321.
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/dane"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/tlsrpt"
)

// MTASTSPolicyResolver is the discovery capability consumed by outbound SMTP.
// The interface keeps DNS/HTTPS/cache ownership outside the relay client.
type MTASTSPolicyResolver interface {
	Resolve(context.Context, string) (mtasts.Result, error)
}

// DANEPolicyResolver is the DNSSEC-validated TLSA capability consumed by
// direct MX delivery (RFC 7672). Resolver trust and DNS ownership stay
// outside the relay client.
type DANEPolicyResolver interface {
	Active() bool
	MX(context.Context, string) dane.MXResult
	HostPolicy(context.Context, string, int) dane.HostPolicy
}

// TLSReportRecorder is the non-blocking reporting sink consumed by outbound
// SMTP. Recorder failures never alter message delivery.
type TLSReportRecorder interface {
	Record(context.Context, tlsrpt.Event) error
}

// RelayConfig holds configuration for the outbound SMTP relay client.
type RelayConfig struct {
	// Host is the relay SMTP server hostname. When empty, the relay client
	// performs DNS MX lookups to find the mail server for the recipient domain.
	Host string

	// Port is the relay SMTP server port. Default is 587 (submission).
	Port int

	// ServerName is the hostname sent in the EHLO command.
	// When empty, it defaults to "localhost".
	ServerName string

	// Username and Password are used for SMTP AUTH (PLAIN mechanism).
	// When both are empty, no authentication is performed.
	Username string
	Password string

	// LocalName is the reverse DNS name used in EHLO (same as ServerName).
	LocalName string

	// DialTimeout controls how long dialing can take. Default 10s.
	DialTimeout time.Duration

	// Dialer is an optional custom dialer for outgoing connections.
	// When nil, a default net.Dialer with DialTimeout is used.
	Dialer *net.Dialer

	// TLSConfig is an optional custom TLS configuration for STARTTLS.
	// When nil, a default config with InsecureSkipVerify=false is used.
	TLSConfig *tls.Config

	// TLSSkipVerify skips TLS certificate verification.
	// Only use this for testing or self-signed certificates.
	TLSSkipVerify bool

	// RequireTLS forces the connection to use TLS via STARTTLS.
	// If the server does not support STARTTLS, delivery fails.
	RequireTLS bool

	// ConnectTimeout controls how long the full SMTP handshake can take.
	// Default is 30 seconds.
	ConnectTimeout time.Duration

	// LookupMX and LookupHost make DNS routing deterministic in tests. The
	// system resolver is used when they are nil.
	LookupMX   func(context.Context, string) ([]*net.MX, error)
	LookupHost func(context.Context, string) ([]string, error)
	// DialContext, when set, replaces Dialer so tests can reach MX host
	// names without DNS.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// MTASTS discovers and caches RFC 8461 transport policy. When nil,
	// delivery retains its explicitly configured TLS behavior.
	MTASTS MTASTSPolicyResolver

	// DANE applies RFC 7672 to direct MX delivery. When nil or inactive,
	// delivery falls back to MTA-STS and opportunistic TLS.
	DANE DANEPolicyResolver

	// TLSPolicyEvidence receives a short transport-security outcome per
	// delivery target, such as "dane-verified", for the delivery trace.
	TLSPolicyEvidence func(context.Context, string)

	// TLSReporter receives privacy-bounded RFC 8460 session outcomes.
	TLSReporter TLSReportRecorder
	// TLSReportError observes recorder outages without coupling them to SMTP.
	TLSReportError func(error)
}

// RelayClient delivers mail to external SMTP servers.
type RelayClient struct {
	cfg *RelayConfig
}

// DSNEnvelopeOptions carries RFC 3461 preferences between durable queue work
// and a downstream server that advertises DSN.
type DSNEnvelopeOptions struct {
	Return            string
	EnvelopeID        string
	Notify            string
	OriginalRecipient string
	RequireTLS        bool
	TLSOptional       bool
}

// UncertainDeliveryError means the remote server may have accepted DATA but
// its final acknowledgement could not be observed. Retrying can duplicate the
// message, so callers must retain and expose that uncertainty.
type UncertainDeliveryError struct{ Err error }

func (e *UncertainDeliveryError) Error() string { return e.Err.Error() }
func (e *UncertainDeliveryError) Unwrap() error { return e.Err }

func IsDeliveryUncertain(err error) bool {
	var uncertain *UncertainDeliveryError
	return errors.As(err, &uncertain)
}

// NewRelayClient creates a new outbound relay client.
func NewRelayClient(cfg *RelayConfig) *RelayClient {
	return &RelayClient{cfg: cfg}
}

// Deliver sends a message to the specified recipient via SMTP.
// It resolves the destination server, establishes a connection,
// negotiates TLS, authenticates if configured, and transfers the message.
func (rc *RelayClient) Deliver(ctx context.Context, sender, recipient string, headers map[string]string, body []byte) error {
	return rc.DeliverWithOptions(ctx, sender, recipient, headers, body, DSNEnvelopeOptions{})
}

func (rc *RelayClient) DeliverWithOptions(ctx context.Context, sender, recipient string, headers map[string]string, body []byte, options DSNEnvelopeOptions) error {
	return rc.DeliverMessage(ctx, sender, recipient, model.BuildMessage(headers, body), options)
}

// DeliverMessage relays message, the exact RFC 5322 bytes, to recipient.
func (rc *RelayClient) DeliverMessage(ctx context.Context, sender, recipient string, message []byte, options DSNEnvelopeOptions) error {
	targets, err := rc.resolveTargets(ctx, recipient)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", recipient, err)
	}
	policyDomain := rc.transportPolicyDomain(recipient)
	policyResult := mtasts.Result{Source: mtasts.SourceNone}
	if !options.TLSOptional {
		policyDomain, policyResult, err = rc.resolveTransportPolicy(ctx, recipient)
		if err != nil {
			return fmt.Errorf("4.7.5 MTA-STS policy cache unavailable: %w", err)
		}
	}
	policy := policyResult.Policy
	daneDomain := extractDomain(recipient)
	daneSecure := false
	if rc.daneApplies(options) {
		var daneErr error
		targets, daneSecure, daneErr = rc.daneTargets(ctx, daneDomain, targets)
		if daneErr != nil {
			return daneErr
		}
	}
	if options.RequireTLS && rc.cfg.Host == "" && !daneSecure && (policy == nil || policy.Mode != mtasts.ModeEnforce) {
		// The standard also permits DNSSEC-authenticated MX evidence. The Go
		// resolver does not expose DNSSEC validation, so direct MX delivery must
		// use Veksel' existing enforcing MTA-STS path rather than claim evidence
		// it cannot prove.
		if policyResult.Failure != nil {
			return fmt.Errorf("4.7.5 REQUIRETLS recipient transport policy is temporarily unavailable: %s", policyResult.Failure.Type)
		}
		return errors.New("5.7.30 REQUIRETLS support required: recipient MX path is not authenticated by enforcing MTA-STS")
	}
	appliedPolicy := reportPolicy(policyDomain, policy)
	if policyResult.Failure != nil {
		resultType := tlsrpt.ResultSTSPolicyFetchError
		if policyResult.Failure.Type == mtasts.FailurePolicy || policyResult.Failure.Type == mtasts.FailureTXTInvalid {
			resultType = tlsrpt.ResultSTSPolicyInvalid
		}
		rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ResultType: resultType, FailureReasonCode: policyResult.Failure.Type})
	}
	var failures []error
	for _, target := range targets {
		if daneSecure {
			hostPolicy := rc.cfg.DANE.HostPolicy(ctx, target.Host, target.Port)
			if hostPolicy.State != dane.StateNone {
				err := rc.deliverDANETarget(ctx, daneDomain, target, hostPolicy, sender, recipient, message, options)
				if err == nil {
					return nil
				}
				if IsDeliveryUncertain(err) {
					return fmt.Errorf("delivery to %s:%d is uncertain: %w", target.Host, target.Port, err)
				}
				failures = append(failures, err)
				continue
			}
			rc.recordTLSPolicy(ctx, "no-dane mx="+target.Host+": "+hostPolicy.Reason)
			if options.RequireTLS && (policy == nil || policy.Mode != mtasts.ModeEnforce) {
				failures = append(failures, fmt.Errorf("5.7.30 REQUIRETLS support required: MX %s is not authenticated by DANE or enforcing MTA-STS", target.Host))
				continue
			}
		}
		if policy != nil && policy.Mode == mtasts.ModeEnforce && !policy.MatchesMX(target.Host) {
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: target.Host,
				ResultType: tlsrpt.ResultValidationFailure, FailureReasonCode: "mx-not-authorized-by-sts-policy"})
			failures = append(failures, fmt.Errorf("4.7.5 MTA-STS policy %s for %s does not authorize MX %s", policy.PolicyID, policy.PolicyDomain, target.Host))
			continue
		}
		security := relaySecurity{}
		if policy != nil && policy.Mode == mtasts.ModeEnforce {
			security.requireTLS = true
			security.verifyTLS = true
		}
		if options.RequireTLS {
			security.requireTLS = true
			security.verifyTLS = true
			security.requirePeerCapability = true
		}
		if err := rc.deliverTarget(ctx, target.Host, target.Port, sender, recipient, message, options, security, appliedPolicy); err == nil {
			return nil
		} else {
			if IsDeliveryUncertain(err) {
				// Trying another MX after an ambiguous final DATA response can
				// create a second accepted copy in the same queue attempt.
				return fmt.Errorf("delivery to %s:%d is uncertain: %w", target.Host, target.Port, err)
			}
			failures = append(failures, err)
		}
	}
	return fmt.Errorf("all delivery targets failed: %w", errors.Join(failures...))
}

type relaySecurity struct {
	requireTLS            bool
	verifyTLS             bool
	requirePeerCapability bool
	// dane, when set, replaces WebPKI verification with RFC 7672 matching.
	dane *dane.HostPolicy
}

// daneApplies reports whether RFC 7672 governs this delivery: DANE is
// active and the message goes directly to recipient MX hosts. Smart hosts
// and explicit routes are operator-chosen next hops, and TLS-Required: No
// (RFC 8689) waives recipient transport policy.
func (rc *RelayClient) daneApplies(options DSNEnvelopeOptions) bool {
	return rc.cfg.DANE != nil && rc.cfg.Host == "" && !options.TLSOptional && rc.cfg.DANE.Active()
}

// daneTargets authenticates the MX RRset. A secure RRset becomes the target
// list, since only DNSSEC-authenticated MX names may anchor TLSA lookups. An
// insecure RRset leaves DANE out of this delivery; a bogus one defers it.
func (rc *RelayClient) daneTargets(ctx context.Context, domain string, targets []mxResult) ([]mxResult, bool, error) {
	result := rc.cfg.DANE.MX(ctx, domain)
	switch result.Security {
	case dane.Bogus:
		reason := "MX lookup failed"
		if result.Err != nil {
			reason = result.Err.Error()
		}
		rc.recordTLS(ctx, tlsrpt.Event{Policy: tlsrpt.AppliedPolicy{Type: tlsrpt.PolicyTypeTLSA, Domain: domain},
			ResultType: tlsrpt.ResultDNSSECInvalid, FailureReasonCode: "mx-dnssec-lookup-failed"})
		rc.recordTLSPolicy(ctx, "dane-failed: "+reason)
		return nil, false, fmt.Errorf("4.7.5 DANE: DNSSEC MX lookup for %s failed: %s", domain, reason)
	case dane.Secure:
		secure := make([]mxResult, 0, len(result.Hosts))
		for _, host := range result.Hosts {
			if host.Host != "" {
				secure = append(secure, mxResult{Host: host.Host, Port: 25, Preference: host.Preference})
			}
		}
		if len(result.Hosts) == 0 {
			secure = append(secure, mxResult{Host: domain, Port: 25})
		}
		if len(secure) > 0 {
			targets = secure
		}
		return targets, true, nil
	}
	rc.recordTLSPolicy(ctx, "no-dane: MX records of "+domain+" are not DNSSEC-signed")
	return targets, false, nil
}

// deliverDANETarget delivers to one MX host that has a secure TLSA RRset.
// DANE takes precedence over MTA-STS for the host (RFC 8461 section 2):
// STARTTLS is mandatory and usable records authenticate the certificate.
// Every DANE failure is temporary (RFC 7672 section 2.2).
func (rc *RelayClient) deliverDANETarget(ctx context.Context, domain string, target mxResult, hostPolicy dane.HostPolicy, sender, recipient string, message []byte, options DSNEnvelopeOptions) error {
	applied := tlsaReportPolicy(domain, hostPolicy)
	if hostPolicy.State == dane.StateFailed {
		rc.recordTLS(ctx, tlsrpt.Event{Policy: applied, ReceivingMX: target.Host, ResultType: tlsrpt.ResultDNSSECInvalid, FailureReasonCode: "tlsa-dnssec-lookup-failed"})
		rc.recordTLSPolicy(ctx, "dane-failed mx="+target.Host+": "+hostPolicy.Reason)
		return fmt.Errorf("4.7.5 DANE: TLSA lookup for MX %s failed: %s", target.Host, hostPolicy.Reason)
	}
	if options.RequireTLS && hostPolicy.State != dane.StateUsable {
		rc.recordTLSPolicy(ctx, "dane-failed mx="+target.Host+": "+hostPolicy.Reason)
		return fmt.Errorf("5.7.30 REQUIRETLS support required: MX %s publishes no usable TLSA record", target.Host)
	}
	security := relaySecurity{requireTLS: true, requirePeerCapability: options.RequireTLS, dane: &hostPolicy}
	err := rc.deliverTarget(ctx, target.Host, target.Port, sender, recipient, message, options, security, applied)
	if err != nil && !IsDeliveryUncertain(err) {
		rc.recordTLSPolicy(ctx, "dane-failed mx="+target.Host+": "+err.Error())
	}
	return err
}

func tlsaReportPolicy(domain string, hostPolicy dane.HostPolicy) tlsrpt.AppliedPolicy {
	records := make([]string, 0, len(hostPolicy.Records))
	for _, record := range hostPolicy.Records {
		records = append(records, record.String())
	}
	return tlsrpt.AppliedPolicy{Type: tlsrpt.PolicyTypeTLSA, Strings: records, Domain: domain, MX: []string{hostPolicy.Host}}
}

func (rc *RelayClient) recordTLSPolicy(ctx context.Context, outcome string) {
	if rc.cfg.TLSPolicyEvidence != nil {
		rc.cfg.TLSPolicyEvidence(ctx, outcome)
	}
}

func (rc *RelayClient) deliverTarget(ctx context.Context, host string, port int, sender, recipient string, message []byte, options DSNEnvelopeOptions, security relaySecurity, appliedPolicy tlsrpt.AppliedPolicy) error {
	conn, err := rc.dial(ctx, host, port)
	if err != nil {
		return fmt.Errorf("dial %s:%d: %w", host, port, err)
	}
	defer conn.Close()

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	// Read greeting
	line, err := rc.readLine(conn, rw)
	if err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	code, _ := parseReply(line)
	if code/100 != 2 {
		return fmt.Errorf("greeting: %s", line)
	}

	// EHLO
	serverName := rc.cfg.ServerName
	if serverName == "" {
		serverName = "localhost"
	}
	if _, err := rc.sendCommand(conn, rw, "EHLO "+serverName); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	replies, err := rc.readMultiReply(conn, rw)
	if err != nil {
		return fmt.Errorf("EHLO reply: %w", err)
	}
	if replies[0].code/100 != 2 {
		return newReplyError("EHLO", replies)
	}
	extensions := parseEHLO(replies)
	receivingHELO := replies[0].text
	sendingIP, receivingIP := connectionIPs(conn)

	// STARTTLS if available
	starttlsSupported := containsExtension(extensions, "STARTTLS")

	requireTLS := rc.cfg.RequireTLS || security.requireTLS
	if starttlsSupported || requireTLS {
		if !starttlsSupported && requireTLS {
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
				SendingMTAIP: sendingIP, ReceivingIP: receivingIP, ResultType: tlsrpt.ResultSTARTTLSNotSupported})
			if security.requirePeerCapability {
				return errors.New("5.7.10 Encryption needed: STARTTLS not supported by next-hop server")
			}
			if security.dane != nil {
				return fmt.Errorf("4.7.5 DANE: MX %s publishes TLSA records but does not offer STARTTLS", host)
			}
			return errors.New("4.7.5 STARTTLS required but not supported by server")
		}

		if _, err := rc.sendCommand(conn, rw, "STARTTLS"); err != nil {
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
				SendingMTAIP: sendingIP, ReceivingIP: receivingIP, ResultType: tlsrpt.ResultValidationFailure, FailureReasonCode: "starttls-command-failed"})
			return fmt.Errorf("STARTTLS command: %w", err)
		}
		replies, err = rc.readMultiReply(conn, rw)
		if err != nil {
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
				SendingMTAIP: sendingIP, ReceivingIP: receivingIP, ResultType: tlsrpt.ResultValidationFailure, FailureReasonCode: "starttls-reply-failed"})
			return fmt.Errorf("STARTTLS reply: %w", err)
		}
		if replies[0].code/100 != 2 {
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
				SendingMTAIP: sendingIP, ReceivingIP: receivingIP, ResultType: tlsrpt.ResultValidationFailure, FailureReasonCode: "starttls-rejected"})
			return newReplyError("STARTTLS", replies)
		}

		// Upgrade to TLS
		tlsConn, unverified, err := rc.doTLS(conn, host, requireTLS, security)
		if err != nil {
			resultType, reason := classifyTLSError(err)
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
				SendingMTAIP: sendingIP, ReceivingIP: receivingIP, ResultType: resultType, FailureReasonCode: reason})
			if security.requirePeerCapability {
				return fmt.Errorf("5.7.10 Encryption needed: TLS authentication failed: %w", err)
			}
			if security.dane != nil {
				return fmt.Errorf("4.7.5 DANE TLS authentication failed for MX %s: %w", host, err)
			}
			if security.verifyTLS {
				return fmt.Errorf("4.7.5 MTA-STS TLS handshake: %w", err)
			}
			return fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tlsConn
		if security.dane != nil && security.dane.State == dane.StateUnusable {
			// The session is encrypted, but the published TLSA RRset could not
			// be applied, which RFC 8460 reports as a policy failure.
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
				SendingMTAIP: sendingIP, ReceivingIP: receivingIP, ResultType: tlsrpt.ResultTLSAInvalid, FailureReasonCode: "tlsa-records-unusable"})
			rc.recordTLSPolicy(ctx, "dane-unauthenticated mx="+host+": "+security.dane.Reason+"; mandatory TLS without authentication")
		} else if unverified != nil {
			// Opportunistic TLS (RFC 7435): the session is encrypted but the
			// certificate does not authenticate the host, which a testing
			// MTA-STS policy still wants reported.
			resultType, reason := classifyTLSError(unverified)
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
				SendingMTAIP: sendingIP, ReceivingIP: receivingIP, ResultType: resultType, FailureReasonCode: reason})
			rc.recordTLSPolicy(ctx, "tls-unverified mx="+host+": "+unverified.Error())
			logger.Info("relay: TLS without certificate verification", "host", host, "reason", unverified)
		} else {
			rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
				SendingMTAIP: sendingIP, ReceivingIP: receivingIP, Success: true})
			if security.dane != nil {
				rc.recordTLSPolicy(ctx, "dane-verified mx="+host+" tlsa="+security.dane.TLSAName)
			}
		}
		rw = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

		// Re-issue EHLO after TLS
		if _, err := rc.sendCommand(conn, rw, "EHLO "+serverName); err != nil {
			return fmt.Errorf("EHLO after TLS: %w", err)
		}
		replies, err = rc.readMultiReply(conn, rw)
		if err != nil {
			return fmt.Errorf("EHLO after TLS reply: %w", err)
		}
		if replies[0].code/100 != 2 {
			return newReplyError("EHLO after TLS", replies)
		}
		extensions = parseEHLO(replies)
		if security.requirePeerCapability && !containsExtension(extensions, "REQUIRETLS") {
			return errors.New("5.7.30 REQUIRETLS support required by next-hop server")
		}
	} else {
		rc.recordTLS(ctx, tlsrpt.Event{Policy: appliedPolicy, ReceivingMX: host, ReceivingMXHELO: receivingHELO,
			SendingMTAIP: sendingIP, ReceivingIP: receivingIP, ResultType: tlsrpt.ResultSTARTTLSNotSupported})
	}

	// AUTH PLAIN if credentials configured
	if rc.cfg.Username != "" && rc.cfg.Password != "" {
		authSupported := false
		for _, ext := range extensions {
			if strings.HasPrefix(strings.ToUpper(ext), "AUTH ") {
				authSupported = true
				break
			}
		}

		if !authSupported {
			return errors.New("AUTH required but not supported by server")
		}

		// PLAIN: \x00<username>\x00<password>
		authData := "\x00" + rc.cfg.Username + "\x00" + rc.cfg.Password
		authB64 := base64.StdEncoding.EncodeToString([]byte(authData))

		if _, err := rc.sendCommand(conn, rw, "AUTH PLAIN "+authB64); err != nil {
			return fmt.Errorf("AUTH command: %w", err)
		}
		replies, err = rc.readMultiReply(conn, rw)
		if err != nil {
			return fmt.Errorf("AUTH reply: %w", err)
		}
		if replies[0].code/100 != 2 {
			return newReplyError("AUTH", replies)
		}
	}

	// MAIL FROM
	mailFrom := "MAIL FROM:<" + sender + ">"
	if containsExtension(extensions, "DSN") {
		if options.Return != "" {
			mailFrom += " RET=" + strings.ToUpper(options.Return)
		}
		if options.EnvelopeID != "" {
			mailFrom += " ENVID=" + options.EnvelopeID
		}
	}
	if options.RequireTLS {
		mailFrom += " REQUIRETLS"
	}
	if _, err := rc.sendCommand(conn, rw, mailFrom); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	replies, err = rc.readMultiReply(conn, rw)
	if err != nil {
		return fmt.Errorf("MAIL FROM reply: %w", err)
	}
	if replies[0].code/100 != 2 {
		return newReplyError("MAIL FROM", replies)
	}

	// RCPT TO
	rcptTo := "RCPT TO:<" + recipient + ">"
	if containsExtension(extensions, "DSN") {
		if options.Notify != "" {
			rcptTo += " NOTIFY=" + strings.ToUpper(options.Notify)
		}
		if options.OriginalRecipient != "" {
			rcptTo += " ORCPT=" + options.OriginalRecipient
		}
	}
	if _, err := rc.sendCommand(conn, rw, rcptTo); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	replies, err = rc.readMultiReply(conn, rw)
	if err != nil {
		return fmt.Errorf("RCPT TO reply: %w", err)
	}
	if replies[0].code/100 != 2 {
		return newReplyError("RCPT TO", replies)
	}

	// DATA
	if _, err := rc.sendCommand(conn, rw, "DATA"); err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	replies, err = rc.readMultiReply(conn, rw)
	if err != nil {
		return fmt.Errorf("DATA reply: %w", err)
	}
	if replies[0].code != 354 {
		return newReplyError("DATA", replies)
	}

	// Build and send the message content
	msgData := dotStuff(message)
	if err := writeFull(conn, msgData); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	// Terminating dot. The CRLF of a complete last line is the first half of
	// the terminator (RFC 5321 section 4.1.1.4); adding another would append
	// an empty line to the body at every hop.
	terminator := "\r\n.\r\n"
	if bytes.HasSuffix(msgData, []byte("\r\n")) {
		terminator = ".\r\n"
	}
	if err := writeFull(conn, []byte(terminator)); err != nil {
		return &UncertainDeliveryError{Err: fmt.Errorf("write DATA terminator: %w", err)}
	}
	rw.Flush()

	// Read DATA response
	line, err = rc.readLine(conn, rw)
	if err != nil {
		return &UncertainDeliveryError{Err: fmt.Errorf("read final DATA response: %w", err)}
	}
	code, text := parseReply(line)
	if code/100 != 2 {
		return &ReplyError{Command: "DATA", Code: code, Text: fmt.Sprintf("%d %s", code, text)}
	}

	// QUIT
	rc.sendCommand(conn, rw, "QUIT")

	return nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[written:]
	}
	return nil
}

// smtpReply holds a single SMTP reply line.
type smtpReply struct {
	code int
	text string
	raw  string
}

// dotStuff applies SMTP dot-stuffing (RFC 5321 section 4.5.2).
// Lines starting with '.' get an extra '.' prepended.
func dotStuff(data []byte) []byte {
	var out []byte
	atLineStart := true

	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			atLineStart = true
			out = append(out, data[i])
			continue
		}
		if atLineStart && data[i] == '.' {
			// Duplicate the dot
			out = append(out, '.', data[i])
		} else {
			out = append(out, data[i])
		}
		if data[i] == '\r' {
			// \r\n is the line ending; next char starts a new line
		} else {
			atLineStart = false
		}
	}
	return out
}

// sendCommand writes an SMTP command and flushes the buffer.
func (rc *RelayClient) sendCommand(conn net.Conn, rw *bufio.ReadWriter, cmd string) (int, error) {
	data := cmd + "\r\n"
	n, err := rw.WriteString(data)
	if err != nil {
		return n, err
	}
	return n, rw.Flush()
}

// Remote servers are untrusted: a reply line is capped well above the
// RFC 5321 limit of 512 octets, and a multi-line reply at a line count far
// beyond any real EHLO response, so a hostile MX cannot stream an endless
// reply into memory.
const (
	maxRelayReplyLineLength = 8 << 10
	maxRelayReplyLines      = 512
)

// readLine reads a single SMTP reply line.
func (rc *RelayClient) readLine(conn net.Conn, rw *bufio.ReadWriter) (string, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := proto.ReadBoundedLine(rw.Reader, maxRelayReplyLineLength)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readMultiReply reads a multi-line SMTP reply and returns structured replies.
func (rc *RelayClient) readMultiReply(conn net.Conn, rw *bufio.ReadWriter) ([]smtpReply, error) {
	var replies []smtpReply
	for {
		line, err := rc.readLine(conn, rw)
		if err != nil {
			return replies, err
		}
		code, text := parseReply(line)
		replies = append(replies, smtpReply{code: code, text: text, raw: line})
		if len(replies) > maxRelayReplyLines {
			return replies, fmt.Errorf("SMTP reply exceeds %d lines", maxRelayReplyLines)
		}
		// Reply is complete when the 4th character is a space (not '-')
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
		// Single-line reply (no continuation)
		if len(line) < 4 {
			break
		}
	}
	return replies, nil
}

// parseReply extracts the status code and text from an SMTP reply line.
func parseReply(line string) (int, string) {
	code := 0
	if len(line) >= 3 {
		for i := 0; i < 3; i++ {
			if line[i] >= '0' && line[i] <= '9' {
				code = code*10 + int(line[i]-'0')
			}
		}
	}
	text := ""
	if len(line) > 4 {
		text = strings.TrimSpace(line[4:])
	}
	return code, text
}

// parseEHLO extracts extension tokens from EHLO multi-line reply.
// Each reply line after the first is an extension advertisement.
func parseEHLO(replies []smtpReply) []string {
	var extensions []string
	for _, r := range replies {
		extensions = append(extensions, r.text)
	}
	return extensions
}

// containsExtension checks if a list of EHLO extensions contains the given token.
func containsExtension(extensions []string, token string) bool {
	token = strings.ToUpper(token)
	for _, ext := range extensions {
		if strings.ToUpper(ext) == token {
			return true
		}
	}
	return false
}

// dial creates a TCP connection to the target server.
func (rc *RelayClient) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if rc.cfg.DialContext != nil {
		return rc.cfg.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	dialer := rc.cfg.Dialer
	if dialer == nil {
		timeout := rc.cfg.DialTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		dialer = &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}
	}
	return dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
}

// doTLS performs a TLS handshake on the connection. When TLS is required,
// verified by policy, or governed by DANE, a certificate that does not
// authenticate the host fails the handshake. Otherwise TLS is opportunistic
// (RFC 7435): the handshake completes, and unverified reports why the
// certificate did not authenticate the host.
func (rc *RelayClient) doTLS(conn net.Conn, host string, requireTLS bool, security relaySecurity) (tlsConn net.Conn, unverified error, err error) {
	forceVerify := security.verifyTLS
	tlsCfg := rc.cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: rc.cfg.TLSSkipVerify && !forceVerify,
			MinVersion:         tls.VersionTLS12,
		}
	} else {
		// Clone to set ServerName
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = host
		if forceVerify {
			tlsCfg.InsecureSkipVerify = false
		}
	}
	if policy := security.dane; policy != nil {
		// RFC 7672 replaces WebPKI: SNI names the TLSA base domain, and only
		// usable TLSA records (none, for an unusable RRset) authenticate.
		if len(policy.Names) > 0 {
			tlsCfg.ServerName = policy.Names[0]
		}
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = nil
		if records := policy.Usable(); len(records) > 0 {
			names := policy.Names
			tlsCfg.VerifyConnection = func(state tls.ConnectionState) error {
				return dane.Verify(state.PeerCertificates, records, names, time.Now())
			}
		}
	} else if !requireTLS && !forceVerify && !tlsCfg.InsecureSkipVerify {
		roots, name := tlsCfg.RootCAs, host
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(state tls.ConnectionState) error {
			unverified = verifyPeer(state.PeerCertificates, roots, name)
			return nil
		}
	}

	client := tls.Client(conn, tlsCfg)
	if err := client.Handshake(); err != nil {
		client.Close()
		return nil, nil, err
	}
	return client, unverified, nil
}

// verifyPeer checks a certificate chain the way crypto/tls would.
func verifyPeer(chain []*x509.Certificate, roots *x509.CertPool, name string) error {
	if len(chain) == 0 {
		return errors.New("tls: server presented no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates})
	if err != nil {
		return &tls.CertificateVerificationError{UnverifiedCertificates: chain, Err: err}
	}
	return nil
}

func (rc *RelayClient) resolveTransportPolicy(ctx context.Context, recipient string) (string, mtasts.Result, error) {
	domain := rc.transportPolicyDomain(recipient)
	canonical, canonicalErr := mtasts.CanonicalDomain(domain)
	if canonicalErr != nil {
		return "", mtasts.Result{Source: mtasts.SourceNone}, nil
	}
	if tlsrpt.IsSuppressed(ctx) {
		return canonical, mtasts.Result{Source: mtasts.SourceNone}, nil
	}
	if rc.cfg.MTASTS == nil {
		return canonical, mtasts.Result{Source: mtasts.SourceNone}, nil
	}
	result, err := rc.cfg.MTASTS.Resolve(ctx, canonical)
	return canonical, result, err
}

func (rc *RelayClient) transportPolicyDomain(recipient string) string {
	if rc.cfg.Host != "" {
		return rc.cfg.Host
	}
	return extractDomain(recipient)
}

func reportPolicy(domain string, policy *mtasts.Policy) tlsrpt.AppliedPolicy {
	if policy == nil {
		return tlsrpt.AppliedPolicy{Type: tlsrpt.PolicyTypeNoPolicyFound, Domain: domain}
	}
	strings := []string{"version: STSv1", "mode: " + policy.Mode}
	for _, pattern := range policy.MX {
		strings = append(strings, "mx: "+pattern)
	}
	strings = append(strings, fmt.Sprintf("max_age: %d", policy.MaxAge))
	return tlsrpt.AppliedPolicy{Type: tlsrpt.PolicyTypeSTS, Strings: strings, Domain: policy.PolicyDomain, MX: append([]string(nil), policy.MX...)}
}

func (rc *RelayClient) recordTLS(ctx context.Context, event tlsrpt.Event) {
	if rc.cfg.TLSReporter == nil || event.Policy.Domain == "" || tlsrpt.IsSuppressed(ctx) {
		return
	}
	event.AttemptID = tlsrpt.AttemptID(ctx)
	if err := rc.cfg.TLSReporter.Record(ctx, event); err != nil && rc.cfg.TLSReportError != nil {
		rc.cfg.TLSReportError(err)
	}
}

func connectionIPs(conn net.Conn) (string, string) {
	addressIP := func(address net.Addr) string {
		host, _, err := net.SplitHostPort(address.String())
		if err != nil {
			return ""
		}
		return host
	}
	return addressIP(conn.LocalAddr()), addressIP(conn.RemoteAddr())
}

func classifyTLSError(err error) (string, string) {
	if verifyErr, ok := dane.IsVerifyError(err); ok {
		switch verifyErr.Kind {
		case dane.FailureNameMismatch:
			return tlsrpt.ResultCertificateHostMismatch, verifyErr.Kind
		case dane.FailureChainInvalid:
			return tlsrpt.ResultCertificateNotTrusted, verifyErr.Kind
		}
		return tlsrpt.ResultTLSAInvalid, verifyErr.Kind
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return tlsrpt.ResultCertificateHostMismatch, "certificate-host-mismatch"
	}
	var invalidError x509.CertificateInvalidError
	if errors.As(err, &invalidError) {
		if invalidError.Reason == x509.Expired {
			return tlsrpt.ResultCertificateExpired, "certificate-expired-or-not-yet-valid"
		}
		return tlsrpt.ResultCertificateNotTrusted, "certificate-chain-invalid"
	}
	var authorityError x509.UnknownAuthorityError
	if errors.As(err, &authorityError) {
		return tlsrpt.ResultCertificateNotTrusted, "unknown-certificate-authority"
	}
	return tlsrpt.ResultValidationFailure, "tls-handshake-failed"
}

// resolve determines the target host and port for a recipient address.
// It first checks for a configured relay host, then falls back to DNS MX lookup.
func (rc *RelayClient) resolve(ctx context.Context, recipient string) (string, int, error) {
	targets, err := rc.resolveTargets(ctx, recipient)
	if err != nil {
		return "", 0, err
	}
	return targets[0].Host, targets[0].Port, nil
}

func (rc *RelayClient) resolveTargets(ctx context.Context, recipient string) ([]mxResult, error) {
	// If a relay host is configured, use it for all deliveries
	if rc.cfg.Host != "" {
		port := rc.cfg.Port
		if port == 0 {
			port = 587
		}
		return []mxResult{{Host: rc.cfg.Host, Port: port}}, nil
	}

	// Extract domain from recipient
	domain := extractDomain(recipient)
	if domain == "" {
		return nil, fmt.Errorf("cannot extract domain from %s", recipient)
	}

	// Perform DNS MX lookup
	return mxLookupAll(ctx, domain, rc.cfg.LookupMX, rc.cfg.LookupHost)
}

// extractDomain returns the domain part of an email address.
func extractDomain(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.Trim(addr, "<>")
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

// repliesStr formats a slice of reply codes into a readable string.
// ReplyError is a refusal from the next hop. Its code decides whether the
// delivery is retried (4xx, e.g. greylisting "450 try later" without an
// enhanced status code) or bounced (5xx), per RFC 5321 section 4.2.1.
type ReplyError struct {
	Command string
	Code    int
	Text    string // the reply lines, "450 text, 450 more"
}

func newReplyError(command string, replies []smtpReply) *ReplyError {
	code := 0
	if len(replies) > 0 {
		code = replies[0].code
	}
	return &ReplyError{Command: command, Code: code, Text: repliesStr(replies)}
}

func (e *ReplyError) Error() string { return e.Command + ": " + e.Text }

// SMTPReplyCode is the three-digit reply code.
func (e *ReplyError) SMTPReplyCode() int { return e.Code }

func repliesStr(replies []smtpReply) string {
	parts := make([]string, len(replies))
	for i, r := range replies {
		parts[i] = fmt.Sprintf("%d %s", r.code, r.text)
	}
	return strings.Join(parts, ", ")
}
