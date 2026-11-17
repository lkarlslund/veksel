package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"

	"github.com/lkarlslund/veksel/pkg/attachment"
	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/contentscan"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dmarc"
	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/spam"
)

var logger = log.For(log.ModuleSMTP)

// ErrBackscatter marks a recipient refused by Delivery.CheckReturnPath: a
// bounce to a local address that does not carry a valid signed return path.
var ErrBackscatter = errors.New("bounce to an unsigned return path")

// ErrRecipientDiscarded is returned by Delivery.ResolveRecipient for an
// address that accepts mail and drops it (an inactive temporary alias set to
// discard). The recipient is valid at RCPT and delivers nothing.
var ErrRecipientDiscarded = errors.New("recipient discards mail")

// Server handles incoming SMTP connections.
type Server struct {
	// cfg is replaced by SetConfig; each session keeps the one it started with.
	cfg         atomic.Pointer[Config]
	connections *metrics.ConnectionGauge

	// session counter for logging
	sessionID atomic.Uint64

	// listeners and active sessions for shutdown
	sessions proto.Sessions

	// Rate limiters
	connGate    *ratelimit.ConnectionGate // per-IP connection admission
	cmdLimiter  *ratelimit.Limiter        // per-connection command limiter
	authLimiter *ratelimit.Limiter        // per-IP auth attempt limiter
}

// Config holds SMTP server configuration.
type Config struct {
	// ServerName is used in the greeting banner and Message-ID generation.
	ServerName string

	// TLSConfig, when non-nil, is used for STARTTLS and/or implicit TLS.
	TLSConfig *tls.Config
	// ImplicitTLS forces all connections to upgrade to TLS immediately.
	// When false, TLS is only available via STARTTLS.
	ImplicitTLS bool

	// AuthRequired forces clients to authenticate before sending mail.
	// Typically true for submission (port 587), false for SMTP (port 25).
	AuthRequired bool
	// RequireTLSForAuth prevents credential exchange until STARTTLS or implicit
	// TLS has completed. Submission listeners should always enable it.
	RequireTLSForAuth bool

	// AuthMechanisms is a list of allowed authentication mechanisms.
	// e.g. []string{"PLAIN", "LOGIN"}.
	AuthMechanisms []string

	// MaxRecipients limits the number of RCPT TO per message.
	MaxRecipients int

	// MaxMessageSize limits DATA body size in bytes. 0 means unlimited.
	MaxMessageSize int64
	// MaxReceivedHeaders rejects probable transport loops before acceptance.
	// A value of zero disables this safeguard.
	MaxReceivedHeaders int
	// SubmissionReceivedPrivacy leaves the client address and reverse DNS
	// name out of the Received field of authenticated submissions.
	SubmissionReceivedPrivacy bool

	// AuthValidator is called during AUTH to verify credentials.
	// Return the userID on success, or an error on failure.
	AuthValidator protocolauth.AuthenticateFunc

	// OAuth2Validator is called during AUTH XOAUTH2 to verify the token.
	// Return the userID on success, or an error on failure.
	OAuth2Validator func(ctx context.Context, email, token string) (string, error)

	// Delivery targets for received mail.
	Delivery *Delivery

	// Metrics is the optional metrics collector.
	Metrics *metrics.Metrics

	// Connections is shared by every listener variant of this protocol.
	Connections *metrics.ConnectionGauge

	// RateLimitConnections enables per-IP connection admission: a
	// connection flood guard plus ConnectionPolicy.
	RateLimitConnections bool
	// ConnectionPolicy caps concurrent connections per client address and
	// lists exempt client prefixes. It applies to connections accepted after
	// SetConfig.
	ConnectionPolicy ratelimit.ConnectionPolicy

	// Abuse receives strikes for unauthenticated abuse: unknown recipients
	// (directory harvesting) and 5xx command errors. Connections from banned
	// clients are refused before the session starts, by the listener.
	Abuse ban.Reporter

	// RateLimitCommands enables per-connection command rate limiting.
	// When true, the server limits commands per session.
	RateLimitCommands bool

	// RateLimitAuth enables per-IP authentication attempt rate limiting.
	// When true, the server limits AUTH attempts per IP.
	RateLimitAuth bool

	// Screening is the connection-stage protection of the inbound listener:
	// the early-talker greeting test, protocol violation limits, recipient
	// tarpitting, and FCrDNS and HELO scoring. The zero value screens
	// nothing.
	Screening Screening

	// HeloPolicy controls HELO/EHLO validation and reverse DNS checking.
	// When nil, no HELO policy is enforced.
	HeloPolicy *HeloPolicy

	// SpfPolicy controls SPF checking for incoming mail.
	// When nil, SPF checking is disabled.
	SpfPolicy *SpfPolicy

	// DkimPolicy controls DKIM verification for incoming mail.
	// When nil, DKIM verification is disabled.
	DkimPolicy *DkimPolicy

	// DmarcPolicy controls DMARC evaluation for incoming mail.
	// When nil, DMARC evaluation is disabled.
	DmarcPolicy *DmarcPolicy

	// DMARCAggregates receives one privacy-bounded observation per SMTP DATA
	// transaction after evaluation and before subsequent policy filtering.
	// ARC validates inbound ARC chains and seals forwarded mail; nil
	// disables both.
	ARC *ARCPolicy

	DMARCAggregates DMARCAggregateRecorder
	// DMARCAggregateError observes recorder failures without changing SMTP
	// acceptance; reporting storage is not part of message delivery durability.
	DMARCAggregateError func(error)

	// LocalDomainSpoofPolicy protects locally hosted identities arriving over
	// unauthenticated SMTP. Authenticated submission uses AuthorizeSubmission.
	LocalDomainSpoofPolicy SpoofPolicyMode

	// Greylist evaluates resolved recipients on unauthenticated inbound SMTP.
	// Submission listeners should leave it nil.
	Greylist GreylistChecker

	// Spam scores each unauthenticated message once per transaction. The
	// result drives rejection, score-triggered greylisting, per-account Junk
	// filing, X-Spam-* headers, and content-scan evidence. Nil disables
	// scoring.
	Spam SpamChecker

	// Attachments inspects attachments once per transaction. Its findings
	// are scored by Spam, and its policy rejects or quarantines dangerous
	// executables. Authenticated submissions are inspected only when the
	// policy opts in; there, quarantine rejects, since submitted mail has no
	// recipient quarantine. Nil disables inspection.
	Attachments *attachment.Switch
	// Classifier contributes the statistical BAYES_* symbol: the shared
	// model's at the transaction stage, and each recipient's own model's
	// when filing it. It also auto-learns from committed deliveries. Nil
	// disables it.
	Classifier SpamClassifier

	// VrfyEnabled controls whether the VRFY command is accepted (RFC 5321).
	// Default false — enabling VRFY allows user enumeration.
	VrfyEnabled bool

	// ExpnEnabled controls whether the EXPN command is accepted (RFC 5321).
	// Default false — enabling EXPN allows mailing-list enumeration.
	ExpnEnabled bool

	// NtlmEnabled controls whether the NTLM SASL mechanism is available.
	// Default false — NTLM is disabled unless explicitly enabled.
	NtlmEnabled bool

	// SaslIrEnabled controls whether SASL-IR (Initial Response) is allowed.
	// When true, clients may send the initial SASL response inline with
	// the AUTH command, avoiding a round-trip (RFC 8305).
	// Default true — SASL-IR is enabled unless explicitly disabled.
	SaslIrEnabled bool
}

// DMARCAggregateRecorder is the narrow inbound SMTP reporting boundary.
type DMARCAggregateRecorder interface {
	Record(context.Context, dmarc.AggregateObservation) error
}

// GreylistChecker is the narrow SMTP-facing boundary for durable greylisting.
type GreylistChecker interface {
	Check(context.Context, greylist.Triplet) (greylist.Decision, error)
}

// SpamChecker is the narrow SMTP-facing boundary of the spam engine.
type SpamChecker interface {
	Check(context.Context, spam.Message) (spam.Result, bool)
}

// SpamClassifier is the SMTP-facing boundary of the statistical classifier.
type SpamClassifier interface {
	// Classify returns userID's classifier symbol for tokens; an empty
	// userID consults only the shared model. False means no model scored.
	Classify(ctx context.Context, userID string, tokens []string) (spam.Symbol, bool)
	// Autolearn may train userID's model from a delivered message's final
	// result; trustedSender marks an allow-listed, authenticated sender.
	Autolearn(ctx context.Context, userID string, sample spam.Sample, result spam.Result, trustedSender bool)
}

// greylistScoreTriggered reports whether checker greylists only messages
// whose spam score reaches the greylist threshold, after DATA, instead of
// every unfamiliar triplet at RCPT.
func greylistScoreTriggered(checker GreylistChecker) bool {
	mode, ok := checker.(interface{ ScoreTriggered() bool })
	return ok && mode.ScoreTriggered()
}

// greylistActive reports whether checker currently greylists. A checker that
// can be switched off at runtime implements Enabled; while it is off, checks
// are skipped entirely, as if no checker were configured.
func greylistActive(checker GreylistChecker) bool {
	toggle, ok := checker.(interface{ Enabled() bool })
	return !ok || toggle.Enabled()
}

// Delivery routes received mail to user mailboxes.
type Delivery struct {
	// RecordRecentRecipients runs after an authenticated submission has been
	// durably accepted. Errors are logged and never change the SMTP result.
	RecordRecentRecipients func(ctx context.Context, userID string, recipients []string) error

	// ResolveRecipient looks up an email address and returns the target
	// folder ID and any required routing info. Returns an error if the
	// address is not found.
	ResolveRecipient func(ctx context.Context, addr string) (folderID string, userID string, err error)
	// ExpandRecipient resolves a configured one-level local alias to terminal
	// local identities. expanded=false means addr is not an alias.
	ExpandRecipient func(ctx context.Context, addr string) (targets []string, expanded bool, err error)
	// IsSpamtrap reports whether addr is an admin-defined spamtrap that is
	// not a real identity. Unauthenticated mail to a trap is accepted at
	// RCPT, like mail to any mailbox, but never delivered or bounced.
	IsSpamtrap func(ctx context.Context, addr string) (bool, error)
	// RecordSpamtrap learns from an accepted transaction that addressed
	// spamtraps; it runs after the transaction is committed.
	RecordSpamtrap func(ctx context.Context, hit SpamtrapHit)

	// AppendMessage stores the message in the target folder.
	AppendMessage func(ctx context.Context, folderID string, data []byte, headers map[string]string) (itemID string, err error)
	// AppendFolderItem is the owner-aware form used by the generic folder
	// boundary. It takes precedence over AppendMessage when configured.
	AppendFolderItem func(ctx context.Context, userID, folderID string, data []byte, headers map[string]string) (itemID string, err error)

	// NotifyIMAPIdle, when set, is called after a successful message append
	// to notify any IMAP IDLE clients watching the folder. The folderID is
	// the folder that received the new message. It must be safe to call
	// from any goroutine.
	NotifyIMAPIdle func(folderID string)

	// ResolveSender looks up the envelope sender and returns the target
	// folder ID (INBOX) for delivering bounce messages. Returns an error
	// if the sender address is not a managed user. Used for DSN bounce delivery.
	ResolveSender func(ctx context.Context, addr string) (folderID string, userID string, err error)

	// GetSieveScript returns the user's Sieve script and active flag.
	// Used for server-side mail filtering (RFC 5228).
	GetSieveScript func(ctx context.Context, userID string) (script string, active bool, err error)

	// AuthorizeSubmission validates the authenticated actor's envelope and
	// RFC 5322 From/Sender identities. It is called after DATA headers have
	// been parsed and must fail closed when authorization state is unavailable.
	AuthorizeSubmission func(ctx context.Context, actorID, envelopeSender, from, sender string) error

	// IsLocalDomain reports whether a canonical domain belongs to this server.
	// Store failures must be returned so identity protection fails closed.
	IsLocalDomain func(context.Context, string) (bool, error)

	// GetFolderIDByPath resolves a folder path for a user to a folder ID.
	// Used by Sieve fileinto to find the target folder.
	GetFolderIDByPath func(ctx context.Context, userID, path string) (folderID string, err error)

	// CreateFolder creates a new folder for a user if it doesn't exist.
	// Used by Sieve fileinto to auto-create folders.
	CreateFolder func(ctx context.Context, userID, path string, folderType string, parentID string) error

	// RewriteForwardSender returns the envelope sender for mail forwarded or
	// redirected on behalf of a local recipient, applying the Sender
	// Rewriting Scheme. Nil keeps the original sender.
	RewriteForwardSender func(ctx context.Context, sender string) string
	// ReverseSRS reports whether addr is an SRS address of this server and,
	// when it verifies, where mail sent to it returns. A forged or expired
	// address reports isSRS with an error.
	ReverseSRS func(ctx context.Context, addr string) (original string, isSRS bool, err error)
	// CheckReturnPath applies backscatter protection (BATV) to a recipient
	// and returns it with any valid signed-return-path tag removed. bounce
	// marks a null-sender transaction from an unauthenticated client. An
	// error wrapping ErrBackscatter rejects the recipient; any other error
	// defers it.
	CheckReturnPath func(ctx context.Context, addr string, bounce bool) (string, error)
	// RewriteRecipient applies inbound address rewriting to a recipient at
	// RCPT and returns the address to accept instead. Nil keeps it.
	RewriteRecipient func(ctx context.Context, addr string) (string, error)
	// RecipientDelimiters returns the current subaddress delimiters exposed
	// to Sieve's subaddress extension (RFC 5233).
	RecipientDelimiters func() string

	// GetForwardTo returns the forwarding address for a user.
	// Returns empty string if forwarding is not configured.
	GetForwardTo func(ctx context.Context, userID string) (addr string)
	// ResolveForwardTo is the fail-closed form of GetForwardTo. It takes
	// precedence and reports configuration/backend lookup failures.
	ResolveForwardTo func(ctx context.Context, userID string) (addr string, err error)

	// SendForward sends a forwarded message to an external address.
	// The headers and body are the original message.
	SendForward func(ctx context.Context, toAddr string, fullMsg []byte) error
	// SendDerived is the trace-aware form for forwards, notifications, and
	// automatic replies. It takes precedence over SendForward.
	SendDerived func(ctx context.Context, message DerivedMessage) error
	// PrepareDerived converts a derived message into protocol-neutral queue
	// work, including local-recipient resolution. During SMTP DATA processing it
	// lets the derived delivery join the original atomic queue batch.
	PrepareDerived func(ctx context.Context, message DerivedMessage) (*MailMessage, error)

	// VacationActive returns true if the user's vacation auto-reply is active.
	VacationActive func(ctx context.Context, userID string) (active bool)

	// VacationReply returns the subject and body for a vacation auto-reply.
	VacationReply func(ctx context.Context, userID string) (subject, message string)
	// ResolveVacation is the fail-closed form used during durable SMTP
	// admission. It reports account/configuration lookup failures.
	ResolveVacation func(ctx context.Context, userID string) (active bool, subject, message string, err error)

	// ShouldVacationReply returns true if a vacation reply should be sent
	// to this sender (rate-limited to once per 24h).
	ShouldVacationReply func(ctx context.Context, userID, sender string) (ok bool)

	// RecordVacationReply records that a vacation reply was sent to this sender.
	RecordVacationReply func(ctx context.Context, userID, sender string) error
	// ReserveVacationReply atomically claims a short-lived rate-limit lease.
	// Complete commits the 24-hour suppression timestamp after queue acceptance;
	// Cancel releases a claim when the derived message was not accepted.
	ReserveVacationReply  func(ctx context.Context, userID, sender string) (token string, ok bool, err error)
	CompleteVacationReply func(ctx context.Context, userID, sender, token string) error
	CancelVacationReply   func(ctx context.Context, userID, sender, token string) error

	// GetSpamConfig returns the user's spam filtering configuration.
	// Returns (enabled, threshold) — defaults to (true, 5.0).
	GetSpamConfig func(ctx context.Context, userID string) (enabled bool, threshold float64, err error)

	// GetSpamWhitelist returns the list of whitelisted senders for a user.
	// Whitelisted senders are never flagged as spam.
	GetSpamWhitelist func(ctx context.Context, userID string) ([]string, error)

	// GetSpamBlacklist returns the list of blacklisted senders for a user.
	// Blacklisted senders are always rejected.
	GetSpamBlacklist func(ctx context.Context, userID string) ([]string, error)

	// KnownCorrespondent returns the KNOWN_CORRESPONDENT symbol when sender,
	// whose From address authenticated, is someone userID has written to;
	// false when the feature is off or the sender is unknown.
	KnownCorrespondent func(ctx context.Context, userID, sender string) (spam.Symbol, bool, error)

	// GetJunkFolderID returns the folder ID for the user's Junk folder.
	GetJunkFolderID func(ctx context.Context, userID string) (folderID string, err error)

	// MailQueue is an optional delivery queue for retrying failed messages.
	// When set, messages that fail with a temporary error are enqueued
	// for retry instead of failing immediately.
	MailQueue MailQueue

	// AllowAuthenticatedRelay permits authenticated sessions to address
	// non-local recipients. Their messages are accepted into MailQueue and are
	// never relayed synchronously from the SMTP session.
	AllowAuthenticatedRelay bool
	// CanRelayRecipient optionally applies destination-specific relay policy.
	// When set, it supersedes AllowAuthenticatedRelay for authenticated SMTP.
	CanRelayRecipient func(context.Context, string) bool
	// RouteUnknownRecipient decides split delivery for an address no local
	// identity hosts: true when its domain routes unknown recipients to
	// another server and that server accepts the address. peerIP is the
	// connecting client, so mail is never routed back to where it came from.
	// An error is temporary (451).
	RouteUnknownRecipient func(ctx context.Context, recipient, peerIP string) (bool, error)
	// TrustedDomainRelay reports whether peerIP is a server that shares the
	// hosted domain (its split-delivery server), whose mail may carry the
	// domain's identities without SPF or DMARC passing here.
	TrustedDomainRelay func(ctx context.Context, domain, peerIP string) (bool, error)

	// VirusScanEnabled returns whether virus scanning is enabled globally.
	GetVirusScanEnabled func() bool

	// VirusScanEnabledForDomain returns whether virus scanning is enabled
	// for the given domain. Returns (true, nil) if enabled or not configured,
	// (false, nil) if explicitly disabled, or an error on lookup failure.
	GetVirusScanEnabledForDomain func(ctx context.Context, domainID string) (bool, error)

	// VirusScan runs the message through the virus scanner.
	// Returns (virusName, infected, error). If the scanner is unavailable,
	// err is set and the caller should decide whether to reject or allow.
	VirusScan func(data []byte) (virusName string, infected bool, err error)

	// ContentScan is the typed scanner pipeline. It supersedes VirusScan when
	// configured; the legacy callback remains for embedders during migration.
	ContentScan func(context.Context, contentscan.Message) contentscan.Report

	// QuarantineMessage stores an infected message in the virus quarantine.
	// Returns the quarantine entry ID, or an error.
	QuarantineMessage func(ctx context.Context, sender, recipient, subject string, headers map[string]string, body []byte, virusName string) (string, error)
}

type DerivedMessage struct {
	Kind           string
	Recipient      string
	EnvelopeSender string
	FullMessage    []byte
	ParentID       string
	CorrelationID  string
	// DKIM marks mail the server writes itself for signing when it leaves
	// the server; forwards and redirects of received mail carry none.
	DKIM *dkim.Request
}

// FilterTemporaryError means delivery policy could not be evaluated. SMTP
// must defer the entire transaction instead of queueing an unfiltered copy.
type FilterTemporaryError struct {
	Stage string
	Err   error
}

func (e *FilterTemporaryError) Error() string {
	return "4.7.0 " + e.Stage + " unavailable: " + e.Err.Error()
}

func (e *FilterTemporaryError) Unwrap() error { return e.Err }

// PolicyRejectError rejects an SMTP DATA transaction before acceptance.
type PolicyRejectError struct{ Reason string }

func (e *PolicyRejectError) Error() string { return e.Reason }

// MailMessage represents a message to be delivered by the queue.
type MailMessage struct {
	ID                 string
	Kind               string
	Attributes         map[string]string
	CorrelationID      string
	ParentID           string
	EnvelopeSender     string
	Recipient          string
	Headers            map[string]string
	Body               []byte
	Content            []byte
	TargetFolderID     string
	TargetFolderPath   string
	TargetOwnerID      string
	Outbound           bool
	Held               bool
	Policy             mailpolicy.Result
	PolicyRoute        string
	AuthenticatedActor string
	SourceIP           string
	// DKIM marks locally originated mail for signing at queue admission.
	DKIM *dkim.Request
}

// Durable transport-security attributes are carried through the generic
// system queue so every onward relay and mediated copy keeps RFC 8689 state.
const (
	AttributeRequireTLS  = "require_tls"
	AttributeTLSOptional = "tls_optional"
	// AttributeDKIMSign on a vacation intent marks its reply as written for
	// an identity the user may send as, so the reply is DKIM-signed.
	AttributeDKIMSign = "dkim_sign"
	// AttributeVacationKey and AttributeVacationPeriod (seconds) carry a
	// Sieve vacation's response-tracking key and period (RFC 5230).
	AttributeVacationKey    = "vacation_key"
	AttributeVacationPeriod = "vacation_period"
)

const (
	MailTaskQuarantine = "quarantine"
	MailTaskVacation   = "vacation"
)

// MailQueue is the interface for the delivery retry queue.
type MailQueue interface {
	// Enqueue adds a message to the delivery queue for retry.
	Enqueue(msg *MailMessage) error
	// EnqueueBatch durably accepts all messages or none. SMTP DATA and BDAT use
	// this boundary so a multi-recipient transaction cannot be partially accepted.
	EnqueueBatch(messages []*MailMessage) error
}

// TemporaryRejection is implemented by queue admission errors that ask the
// client to retry later, such as an exhausted per-account sending limit. SMTP
// answers 451 with the enhanced status code and the user-visible reason.
type TemporaryRejection interface {
	error
	TemporaryRejection() (enhancedCode, reason string)
}

// New creates a new SMTP server with the given config.
func New(cfg *Config) *Server {
	connections := cfg.Connections
	if connections == nil {
		connections = metrics.NewConnectionGauge(cfg.Metrics, "smtp_active_connections")
	}
	s := &Server{connections: connections}
	s.SetConfig(cfg)
	if cfg.RateLimitConnections {
		s.connGate = ratelimit.NewConnectionGate()
	}
	if cfg.RateLimitCommands {
		s.cmdLimiter = ratelimit.NewSMTPCommandLimiter()
	}
	if cfg.RateLimitAuth {
		s.authLimiter = ratelimit.NewAuthLimiter()
	}
	return s
}

// SetConfig replaces the configuration used by sessions accepted afterwards;
// established sessions keep theirs. Connection gauges and rate limiters are
// fixed when the server is created.
func (s *Server) SetConfig(cfg *Config) {
	s.cfg.Store(cfg)
}

// ActiveSessions reports how many accepted sessions are still running.
func (s *Server) ActiveSessions() int {
	return s.sessions.Active()
}

// Listen creates a TCP listener on the given address.
// Call Listen once for each port (e.g. :25 and :587).
func (s *Server) Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.sessions.AddListener(ln)
	logger.Info("smtp: listening", "addr", addr)
	return ln, nil
}

// Accept starts accepting connections from ln in a loop until ctx is done.
// Each connection spawns a session handled in a goroutine.
func (s *Server) Accept(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			select {
			case <-ctx.Done():
				break
			default:
				logger.Error("smtp: accept error", "error", err)
				continue
			}
			break
		}

		cfg := s.cfg.Load()
		releaseAdmission := func() {}
		if s.connGate != nil {
			release, ok := s.connGate.Admit(conn.RemoteAddr().String(), cfg.ConnectionPolicy)
			if !ok {
				logger.Warn("smtp: connection limit exceeded", "remote", conn.RemoteAddr().String())
				proto.Refuse(conn, "421 4.7.0 Too many connections from your address")
				continue
			}
			releaseAdmission = release
		}

		tracked := s.sessions.Track(conn)
		if tracked == nil {
			releaseAdmission()
			continue
		}
		releaseConnection := s.connections.Open()
		id := s.sessionID.Add(1)
		sess := newSession(id, cfg, conn, s.cmdLimiter, s.authLimiter)
		sess.tracked = tracked
		if cfg.Metrics != nil {
			cfg.Metrics.IncrementCounter("smtp_connections_total", nil)
		}
		go func() {
			defer tracked.Done()
			defer releaseConnection()
			defer releaseAdmission()
			sess.run()
			if cfg.Metrics != nil {
				cfg.Metrics.IncrementCounter("smtp_connections_closed_total", nil)
			}
		}()
	}
}

// extractRemoteIP returns the IP portion of conn.RemoteAddr.
func extractRemoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// Close shuts down all listeners. Active sessions keep running.
func (s *Server) Close() error {
	return s.sessions.CloseListeners()
}

// Shutdown closes all listeners and waits for active sessions to finish.
// Sessions waiting for a client command are closed immediately; busy
// sessions are closed once their current command completes. When ctx ends
// first, remaining connections are closed and ctx.Err() is returned.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.sessions.Shutdown(ctx)
}
