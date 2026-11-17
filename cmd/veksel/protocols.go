package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/certificates"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/smtp"
	webapp "github.com/lkarlslund/veksel/pkg/web/app"
	"github.com/lkarlslund/veksel/pkg/webhook"
)

// protocolServer is a running protocol server. Close stops accepting while
// established sessions continue; Shutdown drains them.
type protocolServer interface {
	Close() error
	Shutdown(context.Context) error
	ActiveSessions() int
}

// activeListener is a bound listener and the server accepting on it.
type activeListener struct {
	name     string // identifies the listener across reconfigurations, e.g. "IMAPS"
	addr     string // configured address
	listener net.Listener
	proxy    *proto.ProxyListener // under listener; relays PROXY protocol client addresses
	server   protocolServer
	cancel   context.CancelFunc
}

// protocolState tracks the runtime state of a single protocol server group.
type protocolState struct {
	mu     sync.Mutex
	active []activeListener
	// retired servers no longer accept connections; their sessions finish
	// undisturbed, still receive notifications, and are drained at shutdown.
	retired     []protocolServer
	certificate liveCertificate
	connections *metrics.ConnectionGauge
	// stopped records an administrator stop; configuration changes are
	// validated but leave the protocol stopped until it is started again.
	stopped   bool
	lastError string
	attempt   uint64
	attemptAt time.Time
}

func (p *protocolState) isRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active) > 0
}

func (p *protocolState) status() webapp.ProtocolRuntimeStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	listeners := make([]string, 0, len(p.active))
	for _, active := range p.active {
		listeners = append(listeners, active.listener.Addr().String())
	}
	return webapp.ProtocolRuntimeStatus{Running: len(p.active) > 0, Listeners: listeners, Error: p.lastError, Attempt: p.attempt, AttemptedAt: p.attemptAt}
}

// recordAttemptLocked starts a new status attempt that reports problems.
func (p *protocolState) recordAttemptLocked(problems []error) {
	p.attempt++
	p.attemptAt = time.Now().UTC()
	messages := make([]string, 0, len(problems))
	for _, problem := range problems {
		messages = append(messages, problem.Error())
	}
	p.lastError = strings.Join(messages, "; ")
}

// retireLocked stops accepting on every active listener for which keep
// returns false. Its server is retired rather than discarded so established
// sessions continue; retired servers without sessions are forgotten.
func (p *protocolState) retireLocked(keep func(activeListener) bool) {
	p.retired = slices.DeleteFunc(p.retired, func(server protocolServer) bool { return server.ActiveSessions() == 0 })
	p.active = slices.DeleteFunc(p.active, func(active activeListener) bool {
		if keep(active) {
			return false
		}
		active.cancel()
		_ = active.listener.Close()
		_ = active.server.Close()
		p.retired = append(p.retired, active.server)
		return true
	})
}

// stop stops accepting connections until the protocol is started again.
func (p *protocolState) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retireLocked(func(activeListener) bool { return false })
	p.stopped = true
}

// beginShutdown stops accepting and returns drain targets that wait for the
// active sessions of every current and retired server.
func (p *protocolState) beginShutdown(name string) []drainTarget {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retireLocked(func(activeListener) bool { return false })
	p.stopped = true
	targets := make([]drainTarget, 0, len(p.retired))
	for _, server := range p.retired {
		targets = append(targets, drainTarget{name: name, shutdown: server.Shutdown})
	}
	p.retired = nil
	return targets
}

// liveCertificate gives every listener and session of a protocol one TLS
// configuration that resolves the currently assigned certificate at each
// handshake, so a new assignment applies without rebinding listeners.
type liveCertificate struct {
	once    sync.Once
	server  *tls.Config
	current atomic.Pointer[tls.Config]
}

// serverConfig returns the protocol's handshake configuration.
func (l *liveCertificate) serverConfig() *tls.Config {
	l.once.Do(func() {
		l.server = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return l.current.Load(), nil
		}}
	})
	return l.server
}

// protocolControllers holds the stop/start state for each protocol.
type protocolControllers struct {
	mu          sync.Mutex
	imap        protocolState
	smtp        protocolState
	pop3        protocolState
	managesieve protocolState
	// cfg is the latest accepted configuration; guarded by mu.
	cfg *config.Config
	// Dependencies for starting servers
	ts          *model.TypedStore
	met         *metrics.Metrics
	webhookDisp *webhook.Dispatcher
	mailQueue   *queue.Queue
	folderSpace service.FolderSpace
	search      service.SearchReader
	// mailIndex gives IMAP the stored message previews of the mail list.
	mailIndex    *mailindex.Index
	sieveScripts *service.SieveRepository
	certificates *certificates.Provider
	protocolAuth *protocolauth.Service
	// bans refuses banned clients at accept and receives SMTP abuse strikes.
	bans *ban.Service
	// screenCache remembers SMTP clients that passed connection screening
	// and their reverse DNS outcomes across configuration changes.
	screenCache smtp.ScreenCache
	// smtpDeps is set once the mail services exist; guarded by mu.
	smtpDeps smtpDependencies
}

// config returns the latest accepted configuration.
func (c *protocolControllers) config() *config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

// reconfigure applies a changed configuration to the listeners of protos.
// Later starts use cfg even when applying it fails.
func (c *protocolControllers) reconfigure(cfg *config.Config, protos ...*protocolDefinition) error {
	c.mu.Lock()
	c.cfg = cfg
	c.mu.Unlock()
	var errs []error
	for _, proto := range protos {
		if err := c.applyProtocol(context.Background(), proto, cfg, true); err != nil && !errors.Is(err, errSMTPNotReady) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// start starts proto from the latest configuration for startup and admin
// starts, recording rather than returning listener problems.
func (c *protocolControllers) start(ctx context.Context, proto *protocolDefinition) {
	_ = c.applyProtocol(ctx, proto, c.config(), false)
}

// beginShutdown stops accepting on every protocol and returns the drain
// targets for their active sessions.
func (c *protocolControllers) beginShutdown() []drainTarget {
	var targets []drainTarget
	targets = append(targets, c.smtp.beginShutdown("smtp")...)
	targets = append(targets, c.imap.beginShutdown("imap")...)
	targets = append(targets, c.pop3.beginShutdown("pop3")...)
	targets = append(targets, c.managesieve.beginShutdown("managesieve")...)
	return targets
}

// protocolSettings groups the live mail protocol settings by the protocols
// that read them; each group reconfigures only those protocols.
var protocolSettings = []struct {
	protos []*protocolDefinition
	keys   []string
}{
	{[]*protocolDefinition{&smtpProtocol}, []string{"smtp_enabled", "smtp_listen", "smtp_submission_enabled", "smtp_submission_listen",
		"smtp_implicit_tls_enabled", "smtp_tls_listen", "smtp_server_name", "smtp_certificate", "smtp_auth_mechanisms",
		"smtp_max_recipients", "smtp_max_received_headers", "smtp_submission_received_privacy", "smtp_vrfy_enabled", "smtp_expn_enabled",
		"helo_policy", "spf_policy", "dkim_verify_policy", "dmarc_policy", "local_domain_spoof_policy",
		"arc_verify", "arc_seal_forwards", "arc_trusted_sealers",
		"smtp_greet_delay_ms", "smtp_pregreet_action", "smtp_protocol_violation_limit", "smtp_tarpit_after_unknown_rcpts", "smtp_fcrdns_check"}},
	{[]*protocolDefinition{&imapProtocol}, []string{"imap_enabled", "imap_listen", "imap_tls_enabled", "imap_tls_listen",
		"imap_server_name", "imap_require_tls_auth", "imap_certificate", "imap_max_literal_size"}},
	{[]*protocolDefinition{&pop3Protocol}, []string{"pop3_enabled", "pop3_listen", "pop3_tls_enabled", "pop3_tls_listen",
		"pop3_server_name", "pop3_certificate", "pop3_require_tls_auth"}},
	{[]*protocolDefinition{&manageSieveProtocol}, []string{"managesieve_enabled", "managesieve_listen", "managesieve_tls_enabled",
		"managesieve_tls_listen", "managesieve_certificate", "managesieve_require_tls_auth"}},
	{[]*protocolDefinition{&imapProtocol, &smtpProtocol}, []string{"ntlm_enabled", "sasl_ir_enabled"}},
	{[]*protocolDefinition{&smtpProtocol, &imapProtocol, &pop3Protocol}, []string{"mail_max_connections_per_ip", "mail_connection_limit_exempt"}},
	{[]*protocolDefinition{&smtpProtocol, &imapProtocol, &pop3Protocol, &manageSieveProtocol}, []string{"mail_proxy_protocol", "mail_proxy_protocol_trusted"}},
}

// registerProtocolSettings makes every mail protocol setting live.
func (s *server) registerProtocolSettings() error {
	controllers := s.protocolControl.controllers
	for _, group := range protocolSettings {
		apply := func(cfg *config.Config) error {
			if err := controllers.reconfigure(cfg, group.protos...); err != nil {
				return err
			}
			if slices.Contains(group.keys, "smtp_server_name") {
				s.warnSMTPIdentity(cfg)
			}
			// The mail connection limit exemptions also exempt from bans.
			if slices.Contains(group.keys, "mail_connection_limit_exempt") && s.bans != nil {
				s.bans.Configure(banPolicy(cfg))
			}
			return nil
		}
		if err := s.cfgService.RegisterApplier(apply, group.keys...); err != nil {
			return startupError("register protocol settings", err)
		}
	}
	// The public address only feeds the mail identity check.
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		s.warnSMTPIdentity(cfg)
		return nil
	}, "smtp_public_address"); err != nil {
		return startupError("register protocol settings", err)
	}
	return nil
}

// warnSMTPIdentity logs why the configured SMTP server name is unlikely to
// be accepted by receiving servers.
func (s *server) warnSMTPIdentity(cfg *config.Config) {
	s.background.Go(func(ctx context.Context) {
		for _, problem := range smtpIdentityProblems(ctx, cfg.SmtpServerName, cfg.SmtpPublicAddress, net.DefaultResolver) {
			log.Warn("mail identity: " + problem)
		}
	})
}

func authenticateProtocolUser(ctx context.Context, service *protocolauth.Service, protocol, username, password string) (string, error) {
	result, err := service.Authenticate(ctx, username, password, protocol)
	if err != nil {
		return "", err
	}
	return result.User.ID, nil
}

// protocolControlImpl implements app.ProtocolControl.
type protocolControlImpl struct {
	controllers *protocolControllers
}

// --- ProtocolControl interface implementation ---

func (p *protocolControlImpl) IsIMAPRunning() bool {
	return p.controllers.imap.isRunning()
}

func (p *protocolControlImpl) StopIMAP() {
	p.controllers.imap.stop()
	log.Info("imap: stopped via admin settings")
}

func (p *protocolControlImpl) StartIMAP() {
	p.controllers.start(context.Background(), &imapProtocol)
	log.Info("imap: started via admin settings")
}

func (p *protocolControlImpl) IsSMTPRunning() bool {
	return p.controllers.smtp.isRunning()
}

func (p *protocolControlImpl) ProtocolRuntimeStatus(protocol string) webapp.ProtocolRuntimeStatus {
	switch protocol {
	case "smtp":
		return p.controllers.smtp.status()
	case "imap":
		return p.controllers.imap.status()
	case "pop3":
		return p.controllers.pop3.status()
	case "managesieve":
		return p.controllers.managesieve.status()
	default:
		return webapp.ProtocolRuntimeStatus{}
	}
}

func (p *protocolControlImpl) StopSMTP() {
	p.controllers.smtp.stop()
	log.Info("smtp: stopped via admin settings")
}

func (p *protocolControlImpl) StartSMTP() {
	p.controllers.start(context.Background(), &smtpProtocol)
	log.Info("smtp: started via admin settings")
}

func (p *protocolControlImpl) IsPOP3Running() bool {
	return p.controllers.pop3.isRunning()
}

func (p *protocolControlImpl) StopPOP3() {
	p.controllers.pop3.stop()
	log.Info("pop3: stopped via admin settings")
}

func (p *protocolControlImpl) StartPOP3() {
	p.controllers.start(context.Background(), &pop3Protocol)
	log.Info("pop3: started via admin settings")
}

func (p *protocolControlImpl) GetMailQueue() *queue.Queue {
	p.controllers.mu.Lock()
	defer p.controllers.mu.Unlock()
	return p.controllers.mailQueue
}
