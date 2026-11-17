package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/attachment"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/imap"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/managesieve"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/pop3"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

// protocolDefinition describes how one protocol turns configuration into
// listeners.
type protocolDefinition struct {
	name        string // status and log name, e.g. "imap"
	label       string // error label, e.g. "IMAP"
	state       func(*protocolControllers) *protocolState
	certificate func(*config.Config) (assignment, certFile, keyFile string)
	// listeners plans the listeners for cfg. serverTLS is the protocol's
	// live handshake configuration, nil when no certificate is assigned.
	// Problems name listeners skipped for a missing certificate; an error
	// means the protocol cannot start at all.
	listeners func(c *protocolControllers, cfg *config.Config, serverTLS *tls.Config, connections *metrics.ConnectionGauge) (plans []listenerPlan, problems []error, err error)
}

// listenerPlan is one listener a protocol runs for a configuration.
type listenerPlan struct {
	name string // identifies the listener across reconfigurations, e.g. "IMAPS"
	addr string
	// implicitTLS, when set, wraps the bound listener in TLS.
	implicitTLS *tls.Config
	// serve starts a server accepting on a newly bound listener.
	serve func(context.Context, net.Listener) protocolServer
	// update gives the server already accepting on addr the plan's settings
	// for its next sessions.
	update func(protocolServer)
}

// configurableServer is a protocol server whose configuration can be
// replaced for the sessions it accepts next.
type configurableServer[C any] interface {
	protocolServer
	Accept(context.Context, net.Listener)
	SetConfig(*C)
}

// servedBy plans a listener served by servers built with newServer from cfg.
func servedBy[C any, S configurableServer[C]](name, addr string, cfg *C, newServer func(*C) S) listenerPlan {
	return listenerPlan{
		name: name,
		addr: addr,
		serve: func(ctx context.Context, ln net.Listener) protocolServer {
			server := newServer(cfg)
			go server.Accept(ctx, ln)
			return server
		},
		update: func(server protocolServer) { server.(S).SetConfig(cfg) },
	}
}

var (
	imapProtocol = protocolDefinition{
		name: "imap", label: "IMAP",
		state: func(c *protocolControllers) *protocolState { return &c.imap },
		certificate: func(cfg *config.Config) (string, string, string) {
			return cfg.ImapCertificate, cfg.ImapTlsCert, cfg.ImapTlsKey
		},
		listeners: (*protocolControllers).imapListeners,
	}
	pop3Protocol = protocolDefinition{
		name: "pop3", label: "POP3",
		state: func(c *protocolControllers) *protocolState { return &c.pop3 },
		certificate: func(cfg *config.Config) (string, string, string) {
			return cfg.Pop3Certificate, cfg.Pop3TlsCert, cfg.Pop3TlsKey
		},
		listeners: (*protocolControllers).pop3Listeners,
	}
	smtpProtocol = protocolDefinition{
		name: "smtp", label: "SMTP",
		state: func(c *protocolControllers) *protocolState { return &c.smtp },
		certificate: func(cfg *config.Config) (string, string, string) {
			return cfg.SmtpCertificate, cfg.SmtpTlsCert, cfg.SmtpTlsKey
		},
		listeners: (*protocolControllers).smtpListeners,
	}
	manageSieveProtocol = protocolDefinition{
		name: "managesieve", label: "ManageSieve",
		state: func(c *protocolControllers) *protocolState { return &c.managesieve },
		certificate: func(cfg *config.Config) (string, string, string) {
			return cfg.ManageSieveCertificate, "", ""
		},
		listeners: (*protocolControllers).manageSieveListeners,
	}
)

// applyProtocol makes protocol's listeners match cfg. A listener whose address
// is unchanged keeps accepting and gives its next sessions the new settings;
// moved and added listeners are bound and started before removed ones stop,
// and stopped servers are retired so their established sessions finish
// undisturbed. A certificate assignment applies to the next handshake on
// every listener.
//
// A strict application (a live configuration change) loads the certificate
// and binds every new address before changing anything, returning an error
// that leaves the running listeners untouched; an administrator-stopped
// protocol is only validated. Otherwise (startup and admin starts) problems
// are recorded in the protocol status and the remaining listeners start.
func (c *protocolControllers) applyProtocol(ctx context.Context, protocol *protocolDefinition, cfg *config.Config, strict bool) error {
	state := protocol.state(c)
	state.mu.Lock()
	defer state.mu.Unlock()

	var problems []error
	assignment, certFile, keyFile := protocol.certificate(cfg)
	certificate, err := c.certificates.TLSConfig(ctx, assignment, certFile, keyFile)
	if err != nil {
		err = fmt.Errorf("%s certificate: %w", protocol.label, err)
		if strict {
			return err
		}
		log.Error(protocol.name+": failed to load assigned TLS certificate", "error", err)
		problems = append(problems, err)
		certificate = nil
	}
	var serverTLS *tls.Config
	if certificate != nil {
		serverTLS = state.certificate.serverConfig()
	}
	if state.connections == nil {
		state.connections = metrics.NewConnectionGauge(c.met, protocol.name+"_active_connections")
	}
	plans, planProblems, err := protocol.listeners(c, cfg, serverTLS, state.connections)
	if err != nil {
		if !strict {
			state.recordAttemptLocked([]error{err})
		}
		return err
	}
	problems = append(problems, planProblems...)

	// Bind every new address first so a strict change can still back out.
	bound := make([]net.Listener, len(plans))
	proxies := make([]*proto.ProxyListener, len(plans))
	proxyPolicies := make([]*proto.ProxyPolicy, len(plans))
	for i, plan := range plans {
		proxyPolicies[i] = mailProxyPolicy(cfg, protocol.name, plan.name)
	}
	closeBound := func() {
		for _, ln := range bound {
			if ln != nil {
				_ = ln.Close()
			}
		}
	}
	for i, plan := range plans {
		if _, running := state.activeAt(plan.name, plan.addr); running {
			continue
		}
		ln, err := net.Listen("tcp", plan.addr)
		if err != nil {
			err = fmt.Errorf("%s %s: %w", plan.name, plan.addr, err)
			if strict {
				closeBound()
				return err
			}
			problems = append(problems, err)
			continue
		}
		// The PROXY header precedes the TLS handshake, and banned clients
		// (by their relayed address) are closed before either.
		proxies[i] = proto.NewProxyListener(ln, proxyPolicies[i])
		ln = c.bans.Listener(proxies[i], protocol.name)
		if plan.implicitTLS != nil {
			ln = tls.NewListener(ln, plan.implicitTLS)
		}
		bound[i] = ln
	}
	if strict && state.stopped {
		closeBound()
		return nil
	}

	state.certificate.current.Store(certificate)
	next := make([]activeListener, 0, len(plans))
	for i, plan := range plans {
		if active, running := state.activeAt(plan.name, plan.addr); running {
			active.proxy.SetPolicy(proxyPolicies[i])
			plan.update(active.server)
			next = append(next, active)
			continue
		}
		if bound[i] == nil {
			continue
		}
		serveCtx, cancel := context.WithCancel(context.Background())
		next = append(next, activeListener{name: plan.name, addr: plan.addr, listener: bound[i], proxy: proxies[i], server: plan.serve(serveCtx, bound[i]), cancel: cancel})
		log.Info(protocol.name+": listening", "listener", plan.name, "addr", bound[i].Addr().String())
	}
	state.retireLocked(func(active activeListener) bool {
		_, kept := activeAt(next, active.name, active.addr)
		return kept
	})
	state.active = next
	state.stopped = false
	for _, problem := range problems {
		log.Warn(protocol.name+": listener problem", "error", problem)
	}
	state.recordAttemptLocked(problems)
	return nil
}

// activeAt returns the listener named name that is bound to addr.
func activeAt(active []activeListener, name, addr string) (activeListener, bool) {
	for _, listener := range active {
		if listener.name == name && listener.addr == addr {
			return listener, true
		}
	}
	return activeListener{}, false
}

func (p *protocolState) activeAt(name, addr string) (activeListener, bool) {
	return activeAt(p.active, name, addr)
}

// protocolAuthValidator authenticates protocol logins and counts attempts,
// failures, and successes under the "<prefix>_auth_*" metrics.
func (c *protocolControllers) protocolAuthValidator(protocol, prefix string) func(context.Context, string, string) (string, error) {
	met := c.met
	return func(ctx context.Context, username, password string) (string, error) {
		met.IncrementCounter(prefix+"_auth_attempts_total", nil)
		userID, err := authenticateProtocolUser(ctx, c.protocolAuth, protocol, username, password)
		if err != nil {
			met.IncrementCounter(prefix+"_auth_failures_total", nil)
			return "", err
		}
		met.IncrementCounter(prefix+"_auth_successes_total", nil)
		return userID, nil
	}
}

// abortProtocols stops every protocol listener when startup fails after
// listeners have started.
func (s *server) abortProtocols() {
	controllers := s.protocolControl.controllers
	controllers.smtp.stop()
	controllers.imap.stop()
	controllers.pop3.stop()
	controllers.managesieve.stop()
}

// startManageSieve starts the enabled ManageSieve listeners.
func (s *server) startManageSieve() error {
	s.cleanup.pushAbort(s.abortProtocols)
	controllers := s.protocolControl.controllers
	controllers.sieveScripts = s.sieveScripts
	controllers.start(s.ctx, &manageSieveProtocol)
	return nil
}

// manageSieveListeners plans the ManageSieve STARTTLS and implicit-TLS
// listeners.
func (c *protocolControllers) manageSieveListeners(cfg *config.Config, serverTLS *tls.Config, _ *metrics.ConnectionGauge) ([]listenerPlan, []error, error) {
	authenticate := func(authCtx context.Context, username, password string) (string, error) {
		return authenticateProtocolUser(authCtx, c.protocolAuth, model.AppProtocolManageSieve, username, password)
	}
	listener := func(name, addr string, implicitTLS *tls.Config) listenerPlan {
		return listenerPlan{
			name: name, addr: addr, implicitTLS: implicitTLS,
			serve: func(_ context.Context, ln net.Listener) protocolServer {
				server := &managesieve.Server{Repository: c.sieveScripts, Authenticate: authenticate, TLSConfig: serverTLS,
					RequireTLSForAuth: cfg.ManageSieveRequireTLSAuth, ReadTimeout: 5 * time.Minute, WriteTimeout: time.Minute}
				go func() { _ = server.Serve(ln) }()
				return server
			},
			update: func(server protocolServer) {
				server.(*managesieve.Server).Reconfigure(serverTLS, cfg.ManageSieveRequireTLSAuth)
			},
		}
	}
	var plans []listenerPlan
	var problems []error
	if cfg.ManageSieveEnabled {
		if cfg.ManageSieveRequireTLSAuth && serverTLS == nil {
			problems = append(problems, errors.New("ManageSieve requires TLS authentication but has no assigned certificate"))
		}
		plans = append(plans, listener("ManageSieve", cfg.ManageSieveListen, nil))
	}
	if cfg.ManageSieveTLSEnabled {
		if serverTLS == nil {
			problems = append(problems, errors.New("implicit TLS ManageSieve has no assigned certificate"))
		} else {
			plans = append(plans, listener("ManageSieve TLS", cfg.ManageSieveTLSListen, serverTLS))
		}
	}
	return plans, problems, nil
}

// startIMAP starts the enabled IMAP listeners. It runs before SMTP so queued
// deliveries can notify IMAP IDLE sessions.
func (s *server) startIMAP() error {
	s.protocolControl.controllers.start(s.ctx, &imapProtocol)
	return nil
}

// imapListeners plans the IMAP (STARTTLS) and IMAPS listeners.
func (c *protocolControllers) imapListeners(cfg *config.Config, serverTLS *tls.Config, connections *metrics.ConnectionGauge) ([]listenerPlan, []error, error) {
	authValidator := c.protocolAuthValidator(model.AppProtocolIMAP, "imap")
	var plans []listenerPlan
	var problems []error
	if cfg.ImapEnabled {
		plans = append(plans, servedBy("IMAP", cfg.ImapListen, c.imapConfig(cfg, serverTLS, false, authValidator, connections), imap.New))
		if serverTLS == nil {
			problems = append(problems, plaintextOnly("IMAP", cfg.ImapRequireTLSAuth))
		}
	}
	if cfg.ImapTLSEnabled && serverTLS != nil {
		plans = append(plans, servedBy("IMAPS", cfg.ImapTlsListen, c.imapConfig(cfg, serverTLS, true, authValidator, connections), imap.New))
	} else if cfg.ImapTLSEnabled && cfg.ImapTlsListen != "" {
		problems = append(problems, errors.New("IMAPS has no assigned certificate"))
	}
	return plans, problems, nil
}

// plaintextOnly describes a client listener running without a certificate.
func plaintextOnly(protocol string, requireTLSAuth bool) error {
	if requireTLSAuth {
		return fmt.Errorf("%s has no assigned certificate, so STARTTLS is unavailable and clients cannot sign in (TLS is required for authentication)", protocol)
	}
	return fmt.Errorf("%s has no assigned certificate, so STARTTLS is unavailable and clients sign in and read mail unencrypted", protocol)
}

// imapConfig returns the IMAP server configuration shared by the STARTTLS and
// implicit-TLS listeners.
func (c *protocolControllers) imapConfig(cfg *config.Config, tlsConfig *tls.Config, implicitTLS bool, authValidator func(context.Context, string, string) (string, error), connections *metrics.ConnectionGauge) *imap.Config {
	return &imap.Config{
		ServerName:           cfg.ImapServerName,
		AuthMechanisms:       []string{"PLAIN", "LOGIN"},
		TLSConfig:            tlsConfig,
		ImplicitTLS:          implicitTLS,
		RequireTLSForAuth:    cfg.ImapRequireTLSAuth,
		AuthValidator:        authValidator,
		TypedStore:           c.ts,
		FolderSpace:          c.folderSpace,
		Search:               c.search,
		MailIndex:            c.mailIndex,
		Authorizer:           authz.New(c.ts),
		Metrics:              c.met,
		Connections:          connections,
		RateLimitConnections: true,
		ConnectionPolicy:     mailConnectionPolicy(cfg),
		RateLimitCommands:    true,
		RateLimitAuth:        true,
		NtlmEnabled:          cfg.NtlmEnabled,
		SaslIrEnabled:        cfg.SaslIrEnabled,
		MaxLiteralSize:       cfg.ImapMaxLiteralSize,
	}
}

// startPOP3 starts the enabled POP3 listeners.
func (s *server) startPOP3() error {
	s.protocolControl.controllers.start(s.ctx, &pop3Protocol)
	return nil
}

// pop3Listeners plans the POP3 (STLS) and POP3S listeners.
func (c *protocolControllers) pop3Listeners(cfg *config.Config, serverTLS *tls.Config, connections *metrics.ConnectionGauge) ([]listenerPlan, []error, error) {
	authValidator := c.protocolAuthValidator(model.AppProtocolPOP3, "pop3")
	var plans []listenerPlan
	var problems []error
	if cfg.Pop3Enabled {
		plans = append(plans, servedBy("POP3", cfg.Pop3Listen, c.pop3Config(cfg, serverTLS, false, authValidator, connections), pop3.New))
		if serverTLS == nil {
			problems = append(problems, plaintextOnly("POP3", cfg.Pop3RequireTLSAuth))
		}
	}
	if cfg.Pop3TLSEnabled && serverTLS != nil {
		plans = append(plans, servedBy("POP3S", cfg.Pop3TlsListen, c.pop3Config(cfg, serverTLS, true, authValidator, connections), pop3.New))
	} else if cfg.Pop3TLSEnabled && cfg.Pop3TlsListen != "" {
		problems = append(problems, errors.New("POP3S has no assigned certificate"))
	}
	return plans, problems, nil
}

// pop3Config returns the POP3 server configuration shared by the STLS and
// implicit-TLS listeners.
func (c *protocolControllers) pop3Config(cfg *config.Config, tlsConfig *tls.Config, implicitTLS bool, authValidator func(context.Context, string, string) (string, error), connections *metrics.ConnectionGauge) *pop3.Config {
	return &pop3.Config{
		ServerName:           cfg.Pop3ServerName,
		TLSConfig:            tlsConfig,
		ImplicitTLS:          implicitTLS,
		RequireTLSForAuth:    cfg.Pop3RequireTLSAuth,
		AuthMechanisms:       []string{"PLAIN", "LOGIN"},
		AuthValidator:        authValidator,
		TypedStore:           c.ts,
		FolderSpace:          c.folderSpace,
		Metrics:              c.met,
		Connections:          connections,
		RateLimitConnections: true,
		ConnectionPolicy:     mailConnectionPolicy(cfg),
	}
}

// startSMTP starts the enabled SMTP relay, submission, and implicit-TLS
// submission listeners on top of the delivery chain.
func (s *server) startSMTP() error {
	controllers := s.protocolControl.controllers
	var classifier smtp.SpamClassifier
	if s.spamClassifier != nil {
		classifier = s.spamClassifier
	}
	controllers.setSMTPDependencies(smtpDependencies{
		delivery:        s.smtpDelivery(),
		greylist:        s.greylisting,
		spam:            &s.delivery.spam,
		attachments:     &s.delivery.attachments,
		classifier:      classifier,
		dmarcAggregates: s.dmarcAggregateSink,
	})
	controllers.start(s.ctx, &smtpProtocol)
	return nil
}

// smtpDependencies are the mail services SMTP servers deliver into. They exist
// only once the mail services are built, after the admin UI is reachable.
type smtpDependencies struct {
	delivery        *smtp.Delivery
	greylist        smtp.GreylistChecker
	spam            smtp.SpamChecker
	attachments     *attachment.Switch
	classifier      smtp.SpamClassifier
	dmarcAggregates smtp.DMARCAggregateRecorder
}

func (c *protocolControllers) setSMTPDependencies(deps smtpDependencies) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.smtpDeps = deps
}

// heloPolicy builds the inbound HELO/EHLO policy for mode. Off disables the
// check entirely. The policy validates the announced name (not empty, not an
// address literal or localhost, and fully qualified); it does not require the
// name to match reverse DNS, which legitimate senders frequently fail.
func heloPolicy(mode string) *smtp.HeloPolicy {
	switch smtp.HeloPolicyMode(mode) {
	case smtp.HeloPolicyWarn, smtp.HeloPolicyReject:
		return &smtp.HeloPolicy{Mode: smtp.HeloPolicyMode(mode), RequireHelo: true, MinDomainParts: 2}
	default:
		return nil
	}
}

// loopbackPrefixes are never screened: local MTAs, health checks, and
// tooling connect from them.
var loopbackPrefixes = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// smtpScreening builds the inbound listener's connection screening. The
// mail connection limit exemptions and loopback are exempt.
func (c *protocolControllers) smtpScreening(cfg *config.Config) smtp.Screening {
	return smtp.Screening{
		GreetDelay:              time.Duration(cfg.SmtpGreetDelayMs) * time.Millisecond,
		Pregreet:                smtp.PregreetAction(cfg.SmtpPregreetAction),
		ViolationLimit:          cfg.SmtpProtocolViolationLimit,
		TarpitAfterUnknownRcpts: cfg.SmtpTarpitAfterUnknownRcpts,
		FCrDNS:                  cfg.SmtpFcrdnsCheck,
		Exempt:                  append(slices.Clone(loopbackPrefixes), mailConnectionPolicy(cfg).Exempt...),
		Cache:                   &c.screenCache,
	}
}

// errSMTPNotReady reports that SMTP cannot start before its delivery chain
// exists; startup starts it from the latest configuration once it does.
var errSMTPNotReady = errors.New("SMTP delivery is not initialized yet")

// smtpListeners plans the SMTP relay, submission, and implicit-TLS
// submission listeners.
func (c *protocolControllers) smtpListeners(cfg *config.Config, serverTLS *tls.Config, connections *metrics.ConnectionGauge) ([]listenerPlan, []error, error) {
	c.mu.Lock()
	deps := c.smtpDeps
	c.mu.Unlock()
	if deps.delivery == nil {
		return nil, nil, errSMTPNotReady
	}
	authValidator := c.protocolAuthValidator(model.AppProtocolSMTP, "smtp")

	// SMTP listener on port 25 (STARTTLS, no implicit TLS)
	smtpCfg := &smtp.Config{
		ServerName:                cfg.SmtpServerName,
		MaxRecipients:             cfg.SmtpMaxRecipients,
		MaxMessageSize:            cfg.SmtpMaxMessageSize,
		MaxReceivedHeaders:        cfg.SmtpMaxReceivedHeaders,
		TLSConfig:                 serverTLS,
		Delivery:                  deps.delivery,
		Metrics:                   c.met,
		Connections:               connections,
		RateLimitConnections:      true,
		ConnectionPolicy:          mailConnectionPolicy(cfg),
		RateLimitCommands:         true,
		RateLimitAuth:             true,
		VrfyEnabled:               cfg.SmtpVrfyEnabled,
		ExpnEnabled:               cfg.SmtpExpnEnabled,
		HeloPolicy:                heloPolicy(cfg.HeloPolicy),
		Screening:                 c.smtpScreening(cfg),
		SpfPolicy:                 &smtp.SpfPolicy{Mode: smtp.SpfPolicyMode(cfg.SpfPolicy)},
		DkimPolicy:                &smtp.DkimPolicy{Mode: smtp.DkimPolicyMode(cfg.DkimVerifyPolicy)},
		DmarcPolicy:               &smtp.DmarcPolicy{Mode: smtp.DmarcPolicyMode(cfg.DmarcPolicy)},
		ARC:                       arcPolicy(cfg, c.ts),
		DMARCAggregates:           deps.dmarcAggregates,
		DMARCAggregateError:       dmarcAggregateError,
		LocalDomainSpoofPolicy:    smtp.SpoofPolicyMode(cfg.LocalDomainSpoofPolicy),
		Greylist:                  deps.greylist, // skipped while greylisting is disabled
		Spam:                      deps.spam,     // scores nothing while spam scoring is disabled
		Attachments:               deps.attachments,
		Classifier:                deps.classifier,
		NtlmEnabled:               cfg.NtlmEnabled,
		SaslIrEnabled:             cfg.SaslIrEnabled,
		SubmissionReceivedPrivacy: cfg.SmtpSubmissionReceivedPrivacy,
		Abuse:                     c.bans,
	}
	// authenticated derives the submission variants, which require TLS
	// authentication and skip greylisting and spam scoring.
	authenticated := func(implicitTLS bool) *smtp.Config {
		submissionCfg := *smtpCfg
		submissionCfg.AuthRequired = true
		submissionCfg.RequireTLSForAuth = true
		submissionCfg.AuthMechanisms = strings.Split(cfg.SmtpAuthMechanisms, ",")
		submissionCfg.AuthValidator = authValidator
		submissionCfg.Greylist = nil
		submissionCfg.Spam = nil
		submissionCfg.Classifier = nil
		// Authenticated clients are identified by their credentials, and
		// end-user devices rarely announce a resolvable host name.
		submissionCfg.HeloPolicy = nil
		submissionCfg.Screening = smtp.Screening{}
		submissionCfg.ImplicitTLS = implicitTLS
		return &submissionCfg
	}

	var plans []listenerPlan
	var problems []error
	if cfg.SmtpEnabled {
		plans = append(plans, servedBy("SMTP", cfg.SmtpListen, smtpCfg, smtp.New))
		if serverTLS == nil {
			// The listener works, but plaintext-only: health degrades so an
			// administrator sees it.
			problems = append(problems, errors.New("SMTP has no assigned certificate, so STARTTLS is unavailable: inbound mail arrives unencrypted and senders that enforce MTA-STS or DANE cannot deliver"))
		}
	}
	// Submission on port 587 uses STARTTLS and can be disabled independently.
	if cfg.SmtpSubmissionEnabled && serverTLS != nil {
		submissionCfg := authenticated(false)
		// Authenticated submissions are not inbound DMARC evaluations.
		submissionCfg.DMARCAggregates, submissionCfg.DMARCAggregateError = nil, nil
		plans = append(plans, servedBy("submission", cfg.SmtpSubmissionListen, submissionCfg, smtp.New))
	} else if cfg.SmtpSubmissionEnabled {
		problems = append(problems, errors.New("submission is enabled but no certificate is assigned"))
	}
	// Port 465 is the implicit-TLS secure submission variant.
	if cfg.SmtpImplicitTLSEnabled && serverTLS != nil {
		plans = append(plans, servedBy("SMTPS", cfg.SmtpTLSListen, authenticated(true), smtp.New))
	} else if cfg.SmtpImplicitTLSEnabled {
		problems = append(problems, errors.New("SMTPS is enabled but no certificate is assigned"))
	}
	return plans, problems, nil
}

// mailConnectionPolicy returns the connection admission policy shared by the
// SMTP, IMAP, and POP3 listeners. The exemptions were validated when the
// configuration was accepted.
func mailConnectionPolicy(cfg *config.Config) ratelimit.ConnectionPolicy {
	exempt, _ := config.ParseAddressPrefixes("mail_connection_limit_exempt", cfg.MailConnectionLimitExempt)
	return ratelimit.ConnectionPolicy{MaxPerIP: cfg.MailMaxConnectionsPerIP, Exempt: exempt}
}

// proxyListenerNames names each mail listener in mail_proxy_protocol.
var proxyListenerNames = map[string]string{
	"SMTP": "smtp-relay", "submission": "submission", "SMTPS": "smtps",
	"IMAP": "imap-starttls", "IMAPS": "imaps",
	"POP3": "pop3-starttls", "POP3S": "pop3s",
	"ManageSieve": "managesieve-starttls", "ManageSieve TLS": "managesieve-tls",
}

// mailProxyPolicy returns the PROXY protocol policy of the listener of
// protocol, nil when the listener takes direct connections only. The trusted
// proxies were validated when the configuration was accepted.
func mailProxyPolicy(cfg *config.Config, protocol, listener string) *proto.ProxyPolicy {
	if !config.MailProxyProtocolEnabled(cfg.MailProxyProtocol, protocol, proxyListenerNames[listener]) {
		return nil
	}
	trusted, _ := config.ParseAddressPrefixes("mail_proxy_protocol_trusted", cfg.MailProxyProtocolTrusted)
	return &proto.ProxyPolicy{Trusted: trusted}
}
