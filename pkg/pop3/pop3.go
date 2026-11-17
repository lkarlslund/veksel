// Package pop3 implements a POP3 server (RFC 1939).
//
// It provides a TCP listener, session management, state machine
// (Authorization → Transaction → Update), authentication via USER/PASS
// and AUTH (RFC 1734), core commands (STAT, LIST, RETR, DELE, RSET, QUIT),
// TOP (RFC 2449), UIDL, and TLS support (implicit TLS + STLS).
package pop3

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/service"
)

// DefaultIdleTimeout is the RFC 1939 section 3 minimum autologout timer.
const DefaultIdleTimeout = 10 * time.Minute

var logger = log.For(log.ModulePOP3)

// Server handles incoming POP3 connections.
type Server struct {
	// cfg is replaced by SetConfig; each session keeps the one it started with.
	cfg         atomic.Pointer[Config]
	connections *metrics.ConnectionGauge
	connGate    *ratelimit.ConnectionGate // per-IP connection admission

	// session counter for logging
	sessionID atomic.Uint64

	// listeners and active sessions for shutdown
	sessions proto.Sessions
}

// Config holds POP3 server configuration.
type Config struct {
	// ServerName is used in the greeting banner.
	ServerName string

	// TLSConfig, when non-nil, enables STLS.
	TLSConfig *tls.Config

	// ImplicitTLS forces all connections to upgrade to TLS immediately.
	ImplicitTLS bool

	// RequireTLSForAuth prevents password authentication on cleartext
	// connections. It should normally be enabled for network listeners.
	RequireTLSForAuth bool

	// AuthMechanisms is a list of allowed authentication mechanisms
	// for the AUTH command (RFC 1734). e.g. []string{"PLAIN", "LOGIN"}.
	AuthMechanisms []string

	// AuthValidator is called during USER/PASS or AUTH to verify credentials.
	// Return the userID on success, or an error on failure.
	AuthValidator protocolauth.AuthenticateFunc

	// TypedStore is retained for compatibility with embedded callers. New
	// integrations should provide FolderSpace.
	TypedStore *model.TypedStore

	// FolderSpace is the protocol-neutral, authorized storage boundary.
	FolderSpace service.FolderSpace

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

	// IdleTimeout closes a connection when the client sends no command for
	// this long, and bounds each response write. Zero uses DefaultIdleTimeout.
	IdleTimeout time.Duration
}

// New creates a new POP3 server with the given config.
func New(cfg *Config) *Server {
	connections := cfg.Connections
	if connections == nil {
		connections = metrics.NewConnectionGauge(cfg.Metrics, "pop3_active_connections")
	}
	s := &Server{connections: connections}
	s.SetConfig(cfg)
	if cfg.RateLimitConnections {
		s.connGate = ratelimit.NewConnectionGate()
	}
	return s
}

// SetConfig replaces the configuration used by sessions accepted afterwards;
// established sessions keep theirs. Connection gauges and rate limiters are
// fixed when the server is created.
func (s *Server) SetConfig(cfg *Config) {
	if cfg.FolderSpace == nil && cfg.TypedStore != nil {
		cfg.FolderSpace = service.NewFolderSpace(cfg.TypedStore, authz.New(cfg.TypedStore))
	}
	s.cfg.Store(cfg)
}

// ActiveSessions reports how many accepted sessions are still running.
func (s *Server) ActiveSessions() int {
	return s.sessions.Active()
}

// Listen creates a TCP listener on the given address.
func (s *Server) Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.sessions.AddListener(ln)
	logger.Info("pop3: listening", "addr", addr)
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
				logger.Error("pop3: accept error", "error", err)
				continue
			}
			break
		}

		cfg := s.cfg.Load()
		releaseAdmission := func() {}
		if s.connGate != nil {
			release, ok := s.connGate.Admit(conn.RemoteAddr().String(), cfg.ConnectionPolicy)
			if !ok {
				logger.Warn("pop3: connection limit exceeded", "remote", conn.RemoteAddr().String())
				proto.Refuse(conn, "-ERR [SYS/TEMP] Too many connections from your address")
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
		sess := newSession(id, cfg, conn)
		sess.tracked = tracked
		if cfg.Metrics != nil {
			cfg.Metrics.IncrementCounter("pop3_connections_total", nil)
		}
		go func() {
			defer tracked.Done()
			defer releaseConnection()
			defer releaseAdmission()
			sess.run()
			if cfg.Metrics != nil {
				cfg.Metrics.IncrementCounter("pop3_connections_closed_total", nil)
			}
		}()
	}
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
