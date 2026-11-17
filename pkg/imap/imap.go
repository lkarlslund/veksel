// Package imap implements an IMAP4rev1 server (RFC 3501).
//
// It provides a TCP listener, session management, state machine,
// authentication (LOGIN, AUTHENTICATE PLAIN), mailbox commands,
// item access (FETCH, STORE, COPY, APPEND), SEARCH, EXPUNGE,
// and IDLE with real-time notifications.
package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/service"
)

var logger = log.For(log.ModuleIMAP)

// Server handles incoming IMAP connections.
type Server struct {
	// cfg is replaced by SetConfig; each session keeps the one it started with.
	cfg         atomic.Pointer[Config]
	connections *metrics.ConnectionGauge

	// session counter for logging
	sessionID atomic.Uint64

	// listeners and active sessions for shutdown
	sessions proto.Sessions

	// wakes signals IDLE and NOTIFY sessions when their folders change
	// (see wake.go).
	wakes wakeIndex
	// unfollow removes the commit listener, which is installed on the folder
	// space only while a session is registered in wakes.
	followMu sync.Mutex
	unfollow func()

	// Rate limiters
	connGate    *ratelimit.ConnectionGate // per-IP connection admission
	cmdLimiter  *ratelimit.Limiter        // per-connection command limiter
	authLimiter *ratelimit.Limiter        // per-IP auth attempt limiter
}

// Config holds IMAP server configuration.
type Config struct {
	// ServerName is used in the greeting banner.
	ServerName string

	// Version is the server version string (used in ID responses).
	Version string

	// TLSConfig, when non-nil, enables STARTTLS.
	TLSConfig *tls.Config

	// ImplicitTLS forces all connections to upgrade to TLS immediately.
	ImplicitTLS bool

	// RequireTLSForAuth prevents LOGIN and plaintext SASL mechanisms on
	// cleartext connections (RFC 9051 LOGINDISABLED). It should normally be
	// enabled for network listeners.
	RequireTLSForAuth bool

	// AuthMechanisms is a list of allowed authentication mechanisms.
	AuthMechanisms []string

	// AuthValidator is called during LOGIN/AUTHENTICATE to verify credentials.
	// Return the userID on success, or an error on failure.
	AuthValidator protocolauth.AuthenticateFunc

	// OAuth2Validator is called during AUTHENTICATE XOAUTH2 to verify the token.
	// Return the userID on success, or an error on failure.
	OAuth2Validator func(ctx context.Context, email, token string) (string, error)

	// TypedStore gives access to the model layer.
	TypedStore *model.TypedStore

	// FolderSpace is the protocol-neutral, authorized storage boundary.
	FolderSpace service.FolderSpace

	// Search is the optional account-wide derived index. When absent, SEARCH
	// retains the compatibility scanner used by embedded callers.
	Search service.SearchReader

	// MailIndex supplies stored message previews for FETCH PREVIEW. Without
	// it previews are computed from the message.
	MailIndex *mailindex.Index

	// Authorizer enables canonical folder policy for shared mailbox access.
	// Nil retains legacy ACL behavior for compatibility in embedded callers.
	Authorizer *authz.Engine

	// Metrics is the optional metrics collector.
	Metrics *metrics.Metrics

	// Connections is shared by every listener variant of this protocol.
	Connections *metrics.ConnectionGauge

	// CommandObserver receives normalized command names without tags,
	// arguments, literals, or credentials. It is intended for diagnostics and
	// compatibility evidence and must return promptly.
	CommandObserver func(string)

	// RateLimitConnections enables per-IP connection admission: a
	// connection flood guard plus ConnectionPolicy.
	RateLimitConnections bool
	// ConnectionPolicy caps concurrent connections per client address and
	// lists exempt client prefixes. It applies to connections accepted after
	// SetConfig.
	ConnectionPolicy ratelimit.ConnectionPolicy

	// RateLimitCommands enables per-connection command rate limiting.
	RateLimitCommands bool
	// RateLimitAuth enables per-IP authentication attempt rate limiting.
	// When true, the server limits AUTH attempts per IP.
	RateLimitAuth bool

	// NtlmEnabled controls whether the NTLM SASL mechanism is available.
	// Default false — NTLM is disabled unless explicitly enabled.
	NtlmEnabled bool

	// SaslIrEnabled controls whether SASL-IR (Initial Response) is allowed.
	// When true, clients may send the initial SASL response inline with
	// the AUTHENTICATE command, avoiding a round-trip (RFC 8305).
	// Default true — SASL-IR is enabled unless explicitly disabled.
	SaslIrEnabled bool

	// MaxLiteralSize bounds both one APPEND literal and the cumulative payload
	// of an atomic MULTIAPPEND command. Zero uses DefaultMaxLiteralSize.
	MaxLiteralSize int64
}

const DefaultMaxLiteralSize int64 = 50 * 1024 * 1024

// New creates a new IMAP server with the given config.
func New(cfg *Config) *Server {
	s := &Server{
		connections: cfg.Connections,
	}
	s.SetConfig(cfg)
	if s.connections == nil {
		s.connections = metrics.NewConnectionGauge(cfg.Metrics, "imap_active_connections")
	}
	if cfg.RateLimitConnections {
		s.connGate = ratelimit.NewConnectionGate()
	}
	if cfg.RateLimitCommands {
		s.cmdLimiter = ratelimit.NewIMAPCommandLimiter()
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
	if cfg.MaxLiteralSize <= 0 {
		cfg.MaxLiteralSize = DefaultMaxLiteralSize
	}
	configureFolderSpace(cfg)
	s.cfg.Store(cfg)
	s.followCommits(true)
}

// ActiveSessions reports how many accepted sessions are still running.
func (s *Server) ActiveSessions() int {
	return s.sessions.Active()
}

func configureFolderSpace(cfg *Config) {
	if cfg == nil || cfg.TypedStore == nil {
		return
	}
	if cfg.Authorizer == nil {
		cfg.Authorizer = authz.New(cfg.TypedStore)
	}
	if cfg.FolderSpace == nil {
		cfg.FolderSpace = service.NewFolderSpace(cfg.TypedStore, cfg.Authorizer)
	}
}

// Listen creates a TCP listener on the given address.
func (s *Server) Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.sessions.AddListener(ln)
	logger.Info("imap: listening", "addr", addr)
	return ln, nil
}

// Accept starts accepting connections from ln in a loop until ctx is done.
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
				logger.Error("imap: accept error", "error", err)
				continue
			}
			break
		}

		cfg := s.cfg.Load()
		releaseAdmission := func() {}
		if s.connGate != nil {
			release, ok := s.connGate.Admit(conn.RemoteAddr().String(), cfg.ConnectionPolicy)
			if !ok {
				logger.Warn("imap: connection limit exceeded", "remote", conn.RemoteAddr().String())
				proto.Refuse(conn, "* BYE [UNAVAILABLE] Too many connections from your address")
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
		sess := newSession(id, cfg, conn, s, s.cmdLimiter, s.authLimiter)
		sess.tracked = tracked
		if cfg.Metrics != nil {
			cfg.Metrics.IncrementCounter("imap_connections_total", nil)
		}
		go func() {
			defer tracked.Done()
			defer releaseConnection()
			defer releaseAdmission()
			sess.run()
			if cfg.Metrics != nil {
				cfg.Metrics.IncrementCounter("imap_connections_closed_total", nil)
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
	err := s.sessions.Shutdown(ctx)
	s.followCommits(false)
	return err
}

// NotifyExists wakes the IDLE and NOTIFY sessions watching folderID. Writers
// that go through a folder space announcing its commits need not call it; it
// serves those that write to the store directly.
func (s *Server) NotifyExists(folderID string) {
	s.wakes.changed("", []string{folderID})
}

// runtimeGOOS returns the OS from runtime.GOOS for use in ID responses.
func runtimeGOOS() string {
	return runtime.GOOS
}
