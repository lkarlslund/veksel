package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/autodiscover"
	"github.com/lkarlslund/veksel/pkg/caldav"
	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/diagnostics"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/httpservice"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/static"
	webapp "github.com/lkarlslund/veksel/pkg/web/app"
)

func extractConfiguredPort(address string, fallback int) int {
	_, value, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fallback
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fallback
	}
	return port
}

// buildHTTP registers every HTTP route on the shared mux: health and metrics,
// the unified web app, DAV, autodiscover, and the Exchange protocols. HTTP
// settings are registered as live appliers.
func (s *server) buildHTTP() error {
	s.applyHTTPServiceState(s.cfg)
	s.registerHealthRoutes()
	if err := s.buildAppHandler(); err != nil {
		return err
	}
	s.registerDAV()
	s.registerAutodiscover()
	if err := s.registerOpenPGP(); err != nil {
		return startupError("register OpenPGP key discovery", err)
	}
	if err := s.registerExchange(); err != nil {
		return err
	}
	if err := s.registerHTTPLiveSettings(); err != nil {
		return startupError("register live HTTP settings", err)
	}
	return nil
}

func (s *server) registerHealthRoutes() {
	mux := s.mux
	// Legacy health check — anonymous status for load balancers. Build and
	// listener details are served to API-key callers of /api/v1/health and by the
	// administration health APIs.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		s.refreshHealth(r.Context())
		snapshot := s.healthRegistry.Snapshot(time.Now())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":%q}`, snapshot.Status)
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"alive"}`))
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		s.refreshHealth(r.Context())
		snapshot := s.healthRegistry.Snapshot(time.Now())
		status := http.StatusOK
		if snapshot.Status == health.StatusUnavailable {
			status = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"status":%q}`, snapshot.Status)
	})
	// Prometheus scrape endpoint — requires the metrics_token bearer
	// credential and is absent when no token is configured.
	mux.Handle("GET /metrics", s.met.ScrapeHandler(func() string { return *s.metricsToken.Load() }))
	// The unified workspace is the canonical web interface.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusFound)
	})
	mux.HandleFunc("GET /web", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/mail", http.StatusPermanentRedirect)
	})
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/admin", http.StatusPermanentRedirect)
	})
	// Serve embedded static assets.
	// The embed root contains css/, js/, fonts/ so we strip /static/ prefix.
	mux.Handle("/static/", http.StripPrefix("/static", static.Handler()))
}

// buildAppHandler configures and registers the unified user/admin web app
// and logs the setup link while no system owner exists.
func (s *server) buildAppHandler() error {
	cfg, ctx := s.cfg, s.ctx
	appHandler, err := webapp.New(s.ts)
	if err != nil {
		return startupError("initialize unified web app", err)
	}
	s.appHandler = appHandler
	appHandler.ConfigureBackground(s.background)
	s.routeSecrets = appHandler.SecretSealer()
	// ACME DNS-01 publishes challenge records through the same DNS provider
	// zones the Domains view manages.
	if s.certificates != nil {
		s.certificates.SetDNSChallenger(appHandler.DNSZones())
	}
	appHandler.ConfigureAdministration(cfg, s.protocolControl)
	appHandler.ConfigureMobileConfig(func() autodiscover.Config {
		return s.newAutodiscover(s.cfgService.Current().Config).Config()
	}, s.mobileConfigSigner)
	s.trustedProxies, err = httpservice.NewTrustedProxies(cfg.HTTPTrustedProxies)
	if err == nil {
		err = s.trustedProxies.SetHeader(cfg.HTTPForwardedHeader)
	}
	if err != nil {
		return startupError("configure trusted proxies", err)
	}
	appHandler.ConfigureTrustedProxies(s.trustedProxies)
	// Trusted reverse proxies are never banned, following live changes.
	s.bans.SetExemptCheck(s.trustedProxies.Trusts)
	appHandler.ConfigureBans(s.bans)
	appHandler.ConfigureLoginThrottle(s.protocolAuth.Throttle())
	appHandler.ConfigurePasswordVerifier(s.protocolAuth)
	if s.directory != nil {
		appHandler.ConfigureDirectory(s.directory)
	}
	if err := appHandler.ConfigureManagedConfiguration(s.cfgService); err != nil {
		return startupError("register live settings", err)
	}
	// IMAP previews and the web share one mail index, and so one background
	// build queue and snapshot cache.
	appHandler.ConfigureMailIndex(s.protocolControl.controllers.mailIndex)
	appHandler.ConfigureAccountStorage(s.accountManager)
	appHandler.ConfigureAccountVerification(s.accountVerification)
	appHandler.ConfigureBackupScheduler(s.backupScheduler)
	appHandler.ConfigureSearch(s.search)
	appHandler.ConfigureRuntimeHealth(s.healthRegistry, s.refreshHealth)
	appHandler.ConfigureMetrics(s.met)
	appHandler.ConfigureHealthAlerts(s.healthAlerts)
	appHandler.ConfigureAlertNotifier(s.alertNotifier)
	appHandler.ConfigureWebhooks(s.webhooks)
	if err := s.registerOutboundHTTP(); err != nil {
		return startupError("register outbound HTTP policy", err)
	}
	if err := s.registerSyncNetwork(); err != nil {
		return startupError("register sync source network policy", err)
	}
	if err := s.registerProtocolPasswordPolicy(); err != nil {
		return startupError("register protocol password policy", err)
	}
	if err := s.registerMTASTSPolicy(); err != nil {
		return startupError("register MTA-STS policy", err)
	}
	appHandler.ConfigureMailPolicies(s.mailPolicies)
	appHandler.ConfigureAutomation(s.automation)
	appHandler.ConfigureGreylisting(s.greylisting)
	s.search.SetEventPublisher(appHandler.EventPublisher())
	appHandler.SetFolderCache(s.folderCache)
	appHandler.ConfigureCapabilities(map[string]bool{"jmap": true, "ews": ewsCompiled, "eas": easCompiled, "greylisting": true})
	appHandler.ConfigureCompliance(s.compliance, s.retention)
	appHandler.ConfigureMigrations(s.folderSpace, migrationSourceFactories())
	appHandler.ConfigureCalendarScheduling(s.imip)
	// Calendar subscriptions refresh in the background on their own
	// hourly or daily schedules.
	s.background.Go(func(ctx context.Context) { appHandler.CalendarFeeds().Run(ctx, time.Minute) })
	appHandler.ConfigureBuildInfo(webapp.BuildInfo{
		Version: buildVersion, Commit: buildCommit, BuildTime: buildTime,
		StoreType: string(cfg.StoreBackend), ListenAddr: cfg.ListenAddr,
		IMAPPort: cfg.ImapListen, SMTPPort: cfg.SmtpListen, StartTime: time.Now(),
	})
	// Administrators can drain and exit the process over the API.
	s.shutdownCh = make(chan struct{}, 1)
	s.restartCh = make(chan struct{}, 1)
	notify := func(ch chan struct{}) func() {
		return func() {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	appHandler.ConfigureServerControl(notify(s.restartCh), notify(s.shutdownCh))
	appHandler.Register(s.mux)
	s.warnSMTPIdentity(cfg)
	if token, err := appHandler.SetupToken(ctx); err != nil {
		log.Error("read setup state", "error", err)
	} else if token != "" {
		// The log redacts secrets, so the usable link goes to stderr (and
		// therefore the journal) once, never to the rotating log files.
		log.Warn("setup pending: the setup link is printed to standard error")
		fmt.Fprintf(os.Stderr, "setup pending: open this link to create the system owner: %s\n", setupURL(cfg.HTTPListeners, token))
	}
	return nil
}

// registerDAV mounts CalDAV, CardDAV, and WebDAV under /dav/, protected by
// HTTP Basic auth. The service gate answers while dav_enabled is off.
func (s *server) registerDAV() {
	cfg, met := s.cfg, s.met
	s.dav = caldav.NewWithFolderSpace(s.ts, s.folderSpace, &caldav.Config{
		ServerName:        cfg.ListenAddr,
		Metrics:           met,
		MaxWebdavFileSize: cfg.WebdavMaxFileSize,
		Authorizer:        authz.New(s.ts),
		CalendarIndex:     s.appHandler.CalendarIndex(),
		ResolveRecipient:  s.resolveRecipient,
		AttendeeReply:     s.davAttendeeReply,
	})
	s.mux.Handle("/dav/", http.HandlerFunc(s.serveDAV))
	s.mux.HandleFunc("PROPFIND /{$}", redirectToDAVRoot)
}

// davAttendeeReply answers an invitation through the scheduling service
// when an attendee changes its PARTSTAT over CalDAV.
func (s *server) davAttendeeReply(ctx context.Context, ownerID, itemID, partStat string) error {
	if !s.imip.Enabled() {
		return caldav.ErrSchedulingDisabled
	}
	_, err := s.imip.Respond(ctx, service.UserAccess(ownerID, "dav"), itemID, partStat)
	return err
}

// davChallenge is the Basic challenge for DAV clients; charset tells them
// to send UTF-8 credentials (RFC 7617 §2.1).
const davChallenge = `Basic realm="CalDAV", charset="UTF-8"`

// serveDAV authenticates a DAV request with HTTP Basic credentials and
// hands it to the DAV handler.
func (s *server) serveDAV(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s.met.IncrementCounter("http_requests_total", map[string]string{"handler": "caldav"})
	defer func() {
		s.met.ObserveHistogram("http_request_duration_seconds", time.Since(start).Seconds(), map[string]string{"handler": "caldav"})
	}()

	// HTTP Basic auth
	user, pass, ok := r.BasicAuth()
	if !ok {
		if r.Method == http.MethodOptions {
			// Capability discovery reveals nothing about accounts; iOS
			// and Evolution probe OPTIONS before they send credentials.
			s.dav.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", davChallenge)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Validate credentials against user store
	userID, err := authenticateProtocolUser(r.Context(), s.protocolAuth, model.AppProtocolDAV, user, pass)
	if errors.Is(err, ratelimit.ErrAuthThrottled) {
		ratelimit.WriteRetryAfter(w, err)
		http.Error(w, "too many failed authentication attempts", http.StatusTooManyRequests)
		return
	}
	if err != nil {
		w.Header().Set("WWW-Authenticate", davChallenge)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s.dav.ServeHTTP(w, caldav.WithAuthenticatedUser(r, userID))
}

// redirectToDAVRoot points a PROPFIND on "/" at the DAV root, as
// /.well-known/caldav does (RFC 6764 §5): python caldav, Thunderbird, and
// DAVx5 given only the server URL PROPFIND it for current-user-principal,
// which the web application answered with 405.
func redirectToDAVRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dav/", http.StatusMovedPermanently)
}

// registerAutodiscover serves email client auto-configuration: Microsoft
// Autodiscover POX, Apple .well-known/autoconfig/mail, and Thunderbird
// autoconfig. The handler is rebuilt when an advertised service changes.
func (s *server) registerAutodiscover() {
	s.autodiscover.Store(s.newAutodiscover(s.cfg))
	handle := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.autodiscover.Load().Handle(w, r) })
	for _, prefix := range []string{"/autodiscover/", "/Autodiscover/", "/.well-known/", "/mail/", "/browser/"} {
		s.mux.Handle(prefix, handle)
	}
}

func (s *server) newAutodiscover(cfg *config.Config) *autodiscover.Handler {
	smtpTLSAvailable := cfg.SmtpCertificate != "" || (cfg.SmtpTlsCert != "" && cfg.SmtpTlsKey != "")
	imapTLSAvailable := cfg.ImapCertificate != "" || (cfg.ImapTlsCert != "" && cfg.ImapTlsKey != "")
	pop3TLSAvailable := cfg.Pop3Certificate != "" || (cfg.Pop3TlsCert != "" && cfg.Pop3TlsKey != "")
	davPort, davTLS := davListener(cfg)
	return autodiscover.New(s.ts.UserStore(), autodiscover.Config{
		MTASTSPolicy:           s.mtaSTSPolicy,
		DavPort:                davPort,
		DavTLS:                 davTLS,
		ServerName:             cfg.SmtpServerName,
		ImapServerName:         cfg.ImapServerName,
		Pop3ServerName:         cfg.Pop3ServerName,
		ListenAddr:             cfg.ListenAddr,
		SmtpPort:               extractConfiguredPort(cfg.SmtpSubmissionListen, 587),
		SmtpTlsPort:            extractConfiguredPort(cfg.SmtpTLSListen, 465),
		ImapPort:               extractConfiguredPort(cfg.ImapListen, 143),
		ImapTlsPort:            extractConfiguredPort(cfg.ImapTlsListen, 993),
		Pop3Port:               extractConfiguredPort(cfg.Pop3Listen, 110),
		Pop3TlsPort:            extractConfiguredPort(cfg.Pop3TlsListen, 995),
		DavPath:                "/dav/",
		EwsEnabled:             ewsCompiled && cfg.EwsEnabled,
		EasEnabled:             easCompiled && cfg.EasEnabled,
		ImapTlsEnabled:         cfg.ImapTLSEnabled && imapTLSAvailable,
		Pop3TlsEnabled:         cfg.Pop3TLSEnabled && pop3TLSAvailable,
		SmtpSubmissionEnabled:  cfg.SmtpSubmissionEnabled && smtpTLSAvailable,
		SmtpImplicitTLSEnabled: cfg.SmtpImplicitTLSEnabled && smtpTLSAvailable,
		ImapEnabled:            cfg.ImapEnabled,
		ImapStartTLSEnabled:    cfg.ImapEnabled && imapTLSAvailable,
		Pop3Enabled:            cfg.Pop3Enabled,
		Pop3StartTLSEnabled:    cfg.Pop3Enabled && pop3TLSAvailable,
	}, func(ctx context.Context, username, password string) (string, error) {
		return authenticateProtocolUser(ctx, s.protocolAuth, model.AppProtocolEWS, username, password)
	})
}

// davListener finds the enabled HTTP listener serving the DAV service,
// preferring an HTTPS one. The port is zero when no listener serves DAV.
func davListener(cfg *config.Config) (port int, tls bool) {
	for _, listener := range cfg.HTTPListeners {
		if !listener.Enabled || !slices.Contains(listener.Services, "dav") {
			continue
		}
		secure := listener.Transport == config.HTTPSTransport
		if candidate := extractConfiguredPort(listener.Address, 0); candidate != 0 && (port == 0 || secure && !tls) {
			port, tls = candidate, secure
		}
	}
	return port, tls
}

// mobileConfigSigner loads the certificate assigned to the first enabled
// HTTPS listener so Apple configuration profiles show as verified. It
// returns a nil key when no certificate is assigned.
func (s *server) mobileConfigSigner(ctx context.Context) ([]*x509.Certificate, crypto.Signer, error) {
	cfg := s.cfgService.Current().Config
	for _, listener := range cfg.HTTPListeners {
		if !listener.Enabled || listener.Transport != config.HTTPSTransport || listener.Certificate == "" {
			continue
		}
		tlsConfig, err := s.certificates.TLSConfig(ctx, listener.Certificate, "", "")
		if err != nil || tlsConfig == nil {
			return nil, nil, err
		}
		var pair *tls.Certificate
		if tlsConfig.GetCertificate != nil {
			pair, err = tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: cfg.SmtpServerName})
			if err != nil {
				return nil, nil, err
			}
		} else if len(tlsConfig.Certificates) > 0 {
			pair = &tlsConfig.Certificates[0]
		}
		if pair == nil {
			return nil, nil, nil
		}
		signer, ok := pair.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, nil, errors.New("certificate key cannot sign")
		}
		chain := make([]*x509.Certificate, 0, len(pair.Certificate))
		for _, der := range pair.Certificate {
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, nil, err
			}
			chain = append(chain, certificate)
		}
		return chain, signer, nil
	}
	return nil, nil, nil
}

// registerExchange mounts EWS and EAS when compiled in; the service gate
// follows ews_enabled and eas_enabled. Their message submission waits for
// the mail stack, which starts later.
func (s *server) registerExchange() error {
	exchangeDeps := newExchangeDependencies(s.mux, s.ts, s.folderSpace, s.protocolAuth, s.appHandler.ConfigureEASDeviceInventory)
	exchangeDeps.ctx = s.longPolls
	exchangeDeps.submit = func(ctx context.Context, userID string, raw []byte) error {
		exchangeMail := s.exchangeMail
		if exchangeMail == nil {
			return fmt.Errorf("mail submission is not ready")
		}
		_, err := exchangeMail.SubmitRaw(ctx, model.PrincipalRef{Kind: model.PrincipalUser, ID: userID}, raw)
		return err
	}
	exchangeDeps.search = func() service.SearchReader { return s.search }
	exchangeDeps.respond = func(ctx context.Context, access service.AccessContext, itemID, partStat string) error {
		if s.imip == nil {
			return fmt.Errorf("calendar scheduling is not ready")
		}
		_, err := s.imip.Respond(ctx, access, itemID, partStat)
		return err
	}
	exchangeDeps.freeBusy = func(ctx context.Context, access service.AccessContext, address string, start, end time.Time) ([]calendarindex.BusyPeriod, bool, error) {
		if s.appHandler == nil {
			return nil, false, fmt.Errorf("calendar availability is starting")
		}
		identity, err := s.ts.UserStore().GetEmailAddress(ctx, calendar.MailAddress(address))
		if err != nil || !identity.Enabled {
			return nil, false, nil
		}
		visible, err := calendarindex.FreeBusyVisibility(ctx, s.folderSpace, s.ts.UserStore(), access)
		if err != nil || !visible(identity) {
			return nil, false, err
		}
		periods, err := s.appHandler.BusyPeriods(ctx, identity.UserID, nil, start, end)
		return calendarindex.MergeBusy(periods), err == nil, err
	}
	if err := registerEWS(exchangeDeps); err != nil {
		return startupError("initialize EWS", err)
	}
	if err := registerEAS(exchangeDeps); err != nil {
		return startupError("initialize EAS", err)
	}
	return nil
}

// bindHTTPListeners binds every enabled HTTP(S) listener and the optional
// pprof listener. Any failure closes the listeners bound so far. Later
// http_listeners and pprof_listen changes are reconciled live by the
// running sets.
func (s *server) bindHTTPListeners() error {
	gated := s.services.Handler(s.mux)
	s.httpListeners = httpservice.NewListenerSet(func(listener config.HTTPListener) http.Handler {
		return s.trustedProxies.Handler(s.bans.Handler(httpservice.Handler(listener, gated)))
	}, func(listener config.HTTPListener) (*tls.Config, error) {
		return s.certificates.TLSConfig(s.ctx, listener.Certificate, "", "")
	}, httpservice.DefaultTimeouts)
	if err := s.httpListeners.Apply(s.cfg.HTTPListeners); err != nil {
		log.Error("http listener: failed to start", "error", err)
		return fmt.Errorf("http listener: %w", err)
	}
	s.cleanup.pushAbort(s.httpListeners.Close)
	pprofHandler := diagnostics.NewPprofServer("").Handler
	s.pprofListener = httpservice.NewListenerSet(func(config.HTTPListener) http.Handler { return pprofHandler },
		nil, httpservice.Timeouts{ReadHeader: 5 * time.Second, Idle: time.Minute})
	if err := s.pprofListener.Apply(pprofListeners(s.cfg.PprofListenAddr)); err != nil {
		log.Error("pprof: failed to listen", "addr", s.cfg.PprofListenAddr, "error", err)
		return fmt.Errorf("pprof: failed to listen: %w", err)
	}
	s.cleanup.pushAbort(s.pprofListener.Close)
	return nil
}

// watchSignals starts the graceful shutdown on SIGINT / SIGTERM.
func (s *server) watchSignals() error {
	s.signalCtx, s.stopSignals = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	s.cleanup.push(s.stopSignals)
	return nil
}

// startHTTP starts the app sync scheduler, background mail indexing, the
// optional pprof listener, and serving on every bound HTTP listener.
func (s *server) startHTTP() error {
	s.appHandler.StartSyncScheduler()
	s.appHandler.StartMailIndexing()
	s.pprofListener.Serve()
	s.httpListeners.Serve()
	return nil
}

// pprofListeners describes the optional profiling listener as a listener
// set entry; an empty address disables it.
func pprofListeners(address string) []config.HTTPListener {
	if address = strings.TrimSpace(address); address == "" {
		return nil
	}
	return []config.HTTPListener{{ID: "pprof", Name: "Go profiling", Enabled: true, Transport: config.HTTPTransport, Address: address}}
}
