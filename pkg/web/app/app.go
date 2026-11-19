// Package app serves the unified Veksel web application.
package app

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/accountverify"
	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/background"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/calendarfeed"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/contentscan"
	"github.com/lkarlslund/veksel/pkg/dane"
	"github.com/lkarlslund/veksel/pkg/dmarc"
	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/dnsserver"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/httpservice"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/mailstate"
	"github.com/lkarlslund/veksel/pkg/messagetemplate"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/savedsearch"
	"github.com/lkarlslund/veksel/pkg/scheduledsend"
	"github.com/lkarlslund/veksel/pkg/sendguard"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/sharing"
	staticassets "github.com/lkarlslund/veksel/pkg/static"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/virus"
)

const (
	sessionCookie = "veksel_session"
	csrfCookie    = "veksel_csrf"
)

type sessionContextKey struct{}

//go:embed templates/*.gohtml
var templateFS embed.FS

// Handler serves setup, authentication, and the unified application shell.
type Handler struct {
	ts               *model.TypedStore
	users            *model.UserStore
	recipientMailbox func(context.Context, string) (model.EmailAddress, error)
	scheduling       *imip.Service
	apiKeys          *model.APIKeyStore
	apiRoutes        []apiRoute
	build            BuildInfo
	restartServer    func()
	shutdownServer   func()
	referenceOnce    sync.Once
	reference        []byte
	referenceErr     error
	appPasswords     *model.AppPasswordStore
	sendGuard        *sendguard.Guard
	// domainLimitMu serializes checking a domain limit with the create or
	// update it admits, so concurrent requests cannot jointly exceed it.
	domainLimitMu       sync.Mutex
	secondFactors       *model.SecondFactorStore
	twoFactorPolicy     atomic.Pointer[string]
	webAuthn            webAuthnCeremonies
	bootstrap           *authz.Bootstrap
	authorizer          *authz.Engine
	sessions            *sessionStore
	authorization       *service.Authorization
	mail                *service.Mail
	scheduledMail       *scheduledsend.Service
	mailState           *mailstate.Service
	workspace           *workspaceFacade
	folderSpace         service.FolderSpace
	compliance          *service.Compliance
	retention           *service.RetentionJob
	compliancePolicy    atomic.Pointer[compliancePolicy]
	calendarIndex       *calendarindex.Index
	mailIndex           *mailindex.Index
	mailIndexWarm       atomic.Bool // set once StartMailIndexing runs background builds
	mimeReader          *service.MIMEReader
	search              service.SearchReader
	savedSearches       *savedsearch.Store
	peopleDirectory     peopleDirectoryCache
	messageTemplates    *messagetemplate.Store
	migrationJobs       *migration.Store
	migrationRunner     *migration.Runner
	background          *background.Group // sync runs and scheduler; see ConfigureBackground
	migrationSources    map[string]migration.SourceFactory
	capabilities        map[string]bool
	audit               *audit.Logger
	events              *events.Hub
	cfg                 *config.Config
	userAliases         atomic.Pointer[userAliasPolicy]
	configService       *config.Service
	accountManager      *account.Manager
	accountVerification *accountverify.Scheduler
	backupScheduler     *backup.Scheduler
	protocols           ProtocolControl
	systemQueue         SystemQueue
	messageTrace        *messagetrace.Store
	loginThrottle       *ratelimit.AuthThrottle
	passwords           PasswordVerifier
	directory           DirectoryControl
	trustedProxies      *httpservice.TrustedProxies
	folderCache         *service.CachedFolderSpace
	runtimeHealth       *health.Registry
	metrics             *metrics.Metrics
	refreshHealth       func(context.Context)
	healthAlerts        *health.AlertStore
	alertNotifier       AlertNotifier
	webhooks            *model.WebhookStore
	webhookDeliveries   *model.WebhookDeliveryStore
	webhookTester       WebhookTester
	mailPolicies        *mailpolicy.Service
	automation          *rules.Engine
	greylisting         *greylist.Service
	bans                *ban.Service
	contentScanning     ContentScanner
	contentTrainer      contentscan.Trainer
	spamFiltering       SpamFiltering
	spamBlocklists      SpamBlocklists
	spamReputation      SpamReputation
	spamClassifier      SpamClassifier
	quarantine          *virus.QuarantineStore
	quarantineActions   *virus.QuarantineActionService
	quarantineDigests   atomic.Pointer[virus.QuarantineDigestService]
	shareLinks          *sharing.Service
	calendarFeeds       *calendarfeed.Service
	birthdayCache       sync.Map // contacts folder ID -> cachedBirthdays
	mtaSTSAdmin         MTASTSAdministration
	tlsReportAdmin      TLSReportAdministration
	tlsReportRunning    bool
	daneStatus          func() dane.Status
	dmarcAggregateAdmin interface {
		Days(context.Context) ([]string, error)
		Jobs(context.Context) ([]dmarc.AggregateReportJob, error)
	}
	dmarcAggregateRunner interface {
		ProcessDay(context.Context, string) ([]dmarc.AggregateReportJob, error)
	}
	dmarcAggregateRunning bool
	easDevices            EASDeviceInventory
	mobileConfig          *mobileConfigSource
	clientManifest        clientManifest
	dnsResolver           DNSResolver
	dnsZones              *dnsprovider.Zones
	dnsServer             *dnsserver.Server
	setupChecklist        setupChecklistCache
	port25Dial            func(ctx context.Context, network, address string) (net.Conn, error)
	deliverabilityLimiter *ratelimit.Limiter
	templates             *template.Template

	// changeRetentionObservers follow change history retention, which
	// other runtime owners (JMAP submission history) share.
	changeRetentionMu        sync.Mutex
	changeRetentionObservers []func(days, maxEntries int)
}

func (h *Handler) ConfigureDMARCAggregates(admin interface {
	Days(context.Context) ([]string, error)
	Jobs(context.Context) ([]dmarc.AggregateReportJob, error)
}, runner interface {
	ProcessDay(context.Context, string) ([]dmarc.AggregateReportJob, error)
}, running bool) {
	h.dmarcAggregateAdmin = admin
	h.dmarcAggregateRunner = runner
	h.dmarcAggregateRunning = running
}

// dmarcReportingRunning reports whether aggregate report delivery runs; a
// runner that can be reconfigured live reports its own state.
func (h *Handler) dmarcReportingRunning() bool {
	if live, ok := h.dmarcAggregateRunner.(interface{ Running() bool }); ok {
		return live.Running()
	}
	return h.dmarcAggregateRunning
}

// ConfigureAdministration connects the unified admin surface to runtime
// configuration and protocol lifecycle controls.
func (h *Handler) ConfigureAdministration(cfg *config.Config, protocols ProtocolControl) {
	h.cfg, h.protocols = cfg, protocols
	if cfg != nil {
		h.userAliases.Store(userAliasPolicyFromConfig(cfg))
		h.setTwoFactorPolicy(cfg.WebTwoFactorRequired)
		h.calendarFeeds.SetAllowPrivateNetworks(cfg.CalendarSubscriptionAllowPrivateNetworks)
		h.compliancePolicy.Store(compliancePolicyFromConfig(cfg))
		h.workspace.SetTrashRetentionDays(cfg.TrashRetentionDays)
		h.setChangeRetention(cfg.ChangeHistoryRetentionDays, cfg.ChangeHistoryMaxEntries)
	}
}

// ObserveChangeRetention calls fn with the change history retention now,
// when administration is configured, and whenever the setting changes.
func (h *Handler) ObserveChangeRetention(fn func(days, maxEntries int)) {
	h.changeRetentionMu.Lock()
	h.changeRetentionObservers = append(h.changeRetentionObservers, fn)
	h.changeRetentionMu.Unlock()
	if h.cfg != nil {
		fn(h.cfg.ChangeHistoryRetentionDays, h.cfg.ChangeHistoryMaxEntries)
	}
}

// setChangeRetention applies change history retention to the folder space
// and every observer.
func (h *Handler) setChangeRetention(days, maxEntries int) {
	h.workspace.SetChangeRetention(days, maxEntries)
	h.changeRetentionMu.Lock()
	observers := slices.Clone(h.changeRetentionObservers)
	h.changeRetentionMu.Unlock()
	for _, observe := range observers {
		observe(days, maxEntries)
	}
}

// ConfigureManagedConfiguration installs the file-backed, revisioned source
// used by the canonical configuration REST API.
func (h *Handler) ConfigureManagedConfiguration(service *config.Service) error {
	h.configService = service
	if service == nil {
		return nil
	}
	return h.registerLiveSettings()
}

// ConfigureAccountStorage installs account discovery and engine lifecycle.
func (h *Handler) ConfigureAccountStorage(manager *account.Manager) {
	h.accountManager = manager
	if manager != nil && h.cfg != nil {
		manager.SetRetainedCleanupDays(h.cfg.AccountRetainedCleanupDays)
	}
	if manager != nil {
		// List and calendar projections of encrypted accounts are sealed.
		h.mailIndex.SetSealer(manager)
		h.calendarIndex.SetSealer(manager)
	}
}

// ConfigureAccountVerification installs recurring, read-only account checks.
func (h *Handler) ConfigureAccountVerification(scheduler *accountverify.Scheduler) {
	h.accountVerification = scheduler
}

func (h *Handler) SetSystemQueue(systemQueue SystemQueue)          { h.systemQueue = systemQueue }
func (h *Handler) SetFolderCache(cache *service.CachedFolderSpace) { h.folderCache = cache }

// ConfigureSearch installs the shared account index used by UI and protocols.
func (h *Handler) ConfigureSearch(search service.SearchReader) { h.search = search }

// ConfigureRuntimeHealth installs the canonical detailed health projection
// used by the authenticated administration API.
func (h *Handler) ConfigureRuntimeHealth(registry *health.Registry, refresh func(context.Context)) {
	h.runtimeHealth, h.refreshHealth = registry, refresh
}

// ConfigureMetrics installs the shared runtime collector used by protocol
// servers and the privacy-bounded administration projection.
func (h *Handler) ConfigureMetrics(collector *metrics.Metrics) { h.metrics = collector }

// ConfigureHealthAlerts installs durable operator-owned alert state.
func (h *Handler) ConfigureHealthAlerts(alerts *health.AlertStore) { h.healthAlerts = alerts }

// AlertNotifier delivers alert transitions through the configured channels.
type AlertNotifier interface {
	SetPolicy(alertnotify.Policy)
	Status(context.Context) (alertnotify.Status, error)
	Test(context.Context) []alertnotify.ChannelResult
}

// ConfigureAlertNotifier installs alert channel delivery and its live policy.
func (h *Handler) ConfigureAlertNotifier(notifier AlertNotifier) { h.alertNotifier = notifier }

// WebhookTester sends an immediate diagnostic delivery for one subscription.
type WebhookTester interface {
	Test(context.Context, string) (*model.WebhookDelivery, error)
}

// ConfigureWebhooks installs the runtime dispatcher used by test actions.
func (h *Handler) ConfigureWebhooks(tester WebhookTester) { h.webhookTester = tester }

// ConfigureMailPolicies installs the same live policy snapshot used by queue
// admission so administration never edits a disconnected configuration copy.
func (h *Handler) ConfigureMailPolicies(policies *mailpolicy.Service) { h.mailPolicies = policies }

// ConfigureAutomation installs the rule engine shared by every FolderSpace
// protocol adapter and the user settings API.
func (h *Handler) ConfigureAutomation(automation *rules.Engine) { h.automation = automation }

// ConfigureGreylisting installs the same durable service used by inbound SMTP.
func (h *Handler) ConfigureGreylisting(service *greylist.Service) { h.greylisting = service }

// ContentScanner is the content scanning boundary shared with SMTP. A
// scanner reporting no engines is treated as unavailable.
type ContentScanner interface {
	Scan(context.Context, contentscan.Message) contentscan.Report
	Status() []contentscan.EngineStatus
}

// ConfigureContentScanning installs the same live scanner used by SMTP.
func (h *Handler) ConfigureContentScanning(scanner ContentScanner) {
	h.contentScanning = scanner
}

// ConfigureContentTrainer installs an optional explicit spam/ham learning
// target. Training remains independent from scanning and release actions.
func (h *Handler) ConfigureContentTrainer(trainer contentscan.Trainer) {
	h.contentTrainer = trainer
}

// trainingAvailable reports whether explicit training currently has a
// target; a switchable trainer reports its own availability.
func (h *Handler) trainingAvailable() bool {
	if h.contentTrainer == nil {
		return false
	}
	if switchable, ok := h.contentTrainer.(interface{ TrainingAvailable() bool }); ok {
		return switchable.TrainingAvailable()
	}
	return true
}

// ConfigureQuarantine installs the same policy-aware store used by SMTP and
// the cleanup owner. Tests and offline handlers retain an unbounded fallback.
// ConfigureCalendarScheduling installs the iMIP service that describes and
// answers calendar invitations in the mail reader.
func (h *Handler) ConfigureCalendarScheduling(scheduling *imip.Service) {
	h.scheduling = scheduling
}

// ConfigureRecipientMailbox installs the server's recipient resolver, which
// maps subaddressed and catch-all recipients to the identity receiving them.
func (h *Handler) ConfigureRecipientMailbox(resolve func(context.Context, string) (model.EmailAddress, error)) {
	h.recipientMailbox = resolve
}

// mailboxForRecipient returns the identity receiving mail for recipient.
func (h *Handler) mailboxForRecipient(ctx context.Context, recipient string) (model.EmailAddress, error) {
	if h.recipientMailbox != nil {
		return h.recipientMailbox(ctx, recipient)
	}
	return h.users.GetEmailAddress(ctx, recipient)
}

func (h *Handler) ConfigureQuarantine(quarantine *virus.QuarantineStore) {
	h.quarantine = quarantine
}

func (h *Handler) ConfigureQuarantineActions(actions *virus.QuarantineActionService) {
	h.quarantineActions = actions
}

func (h *Handler) ConfigureQuarantineDigests(digests *virus.QuarantineDigestService) {
	h.quarantineDigests.Store(digests)
}

// EventPublisher lets process-level services publish to authenticated clients.
func (h *Handler) EventPublisher() events.Publisher { return h.events }

// PublishAdminEvent resolves current administrators at transition time so a
// role grant or revocation takes effect without restarting background owners.
func (h *Handler) PublishAdminEvent(ctx context.Context, event events.Event) error {
	users, err := h.users.List(ctx)
	if err != nil {
		return err
	}
	for _, user := range users {
		if user.Enabled && h.isAdmin(ctx, user.ID) {
			event.Recipients = append(event.Recipients, user.ID)
		}
	}
	h.events.Publish(event)
	return nil
}

// SetMessageTrace exposes the persistent metadata-only delivery trace to admins.
func (h *Handler) SetMessageTrace(messageTrace *messagetrace.Store) { h.messageTrace = messageTrace }

func New(ts *model.TypedStore) (*Handler, error) {
	templates, err := template.New("").Funcs(template.FuncMap{"asset": staticassets.AssetURL}).ParseFS(templateFS, "templates/*.gohtml")
	if err != nil {
		return nil, fmt.Errorf("parse app templates: %w", err)
	}
	manifest, err := buildClientManifest()
	if err != nil {
		return nil, fmt.Errorf("build client manifest: %w", err)
	}
	engine := authz.New(ts)
	eventHub := events.NewHub()
	authorization := service.NewAuthorization(ts, engine)
	authorization.SetEventPublisher(eventHub)
	migrationJobs, err := migration.NewStore(context.Background(), ts.Store())
	if err != nil {
		return nil, fmt.Errorf("initialize migration jobs: %w", err)
	}
	if err := migrationJobs.MarkInterrupted(context.Background()); err != nil {
		return nil, fmt.Errorf("recover migration jobs: %w", err)
	}
	if err := ts.EnsureNamespace(context.Background(), model.NSSecondFactors); err != nil && !errors.Is(err, store.ErrExists) {
		return nil, fmt.Errorf("initialize second factors: %w", err)
	}
	space := service.NewFolderSpace(ts, engine)
	compliance, err := service.NewCompliance(context.Background(), ts)
	if err != nil {
		return nil, fmt.Errorf("initialize compliance: %w", err)
	}
	space.SetLegalHolds(compliance)
	shareLinks, err := sharing.New(context.Background(), ts, space, engine)
	if err != nil {
		return nil, fmt.Errorf("initialize share links: %w", err)
	}
	calendarFeeds, err := calendarfeed.New(context.Background(), ts.Store())
	if err != nil {
		return nil, err
	}
	auditLog := audit.New(ts)
	// DNS provider credentials share the stored-credential keys, so key
	// rotation covers them.
	dnsZones, err := dnsprovider.NewZones(context.Background(), ts, migrationJobs, auditLog)
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		ts: ts, users: model.NewUserStore(ts), apiKeys: model.NewAPIKeyStore(ts), appPasswords: model.NewAppPasswordStore(ts), secondFactors: model.NewSecondFactorStore(ts), bootstrap: authz.NewBootstrap(ts),
		authorizer: engine, authorization: authorization,
		workspace: newWorkspaceFacade(space), folderSpace: space, compliance: compliance, calendarIndex: calendarindex.New(ts.Store()), mailIndex: mailindex.New(ts.Store()), sessions: newSessionStore(ts),
		mimeReader: service.NewMIMEReader(space), savedSearches: savedsearch.New(space), messageTemplates: messagetemplate.New(space),
		templates: templates, audit: auditLog, events: eventHub, clientManifest: manifest, dnsZones: dnsZones,
		migrationJobs: migrationJobs, migrationSources: make(map[string]migration.SourceFactory),
		capabilities: map[string]bool{"caldav": true, "carddav": true, "webdav": true},
		shareLinks:   shareLinks, calendarFeeds: calendarFeeds,
		loginThrottle: ratelimit.NewAuthThrottle(), passwords: protocolauth.New(ts),
		deliverabilityLimiter: ratelimit.NewLimiter(deliverabilityBurst, deliverabilityRefillPerSecond),
		webhooks:              model.NewWebhookStore(ts), webhookDeliveries: model.NewWebhookDeliveryStore(ts),
	}
	handler.migrationRunner = migration.NewRunner(migrationJobs, space)
	handler.background = background.New(context.Background())
	return handler, nil
}

// ConfigureBackground runs the handler's background jobs, such as sync runs
// and the sync scheduler, on group. The server passes its own group so
// shutdown stops them before the stores close.
func (h *Handler) ConfigureBackground(group *background.Group) {
	h.background = group
}

// ConfigureCapabilities publishes compile-time features without coupling the
// web package to executable build tags.
func (h *Handler) ConfigureCapabilities(capabilities map[string]bool) {
	for name, enabled := range capabilities {
		h.capabilities[name] = enabled
	}
}

// ConfigureMigrations installs the same durable folder space used by wire
// protocols and the source factories compiled into this binary.
func (h *Handler) ConfigureMigrations(space service.FolderSpace, sources map[string]migration.SourceFactory) {
	if space != nil {
		service.ConfigureLegalHolds(space, h.compliance)
		h.folderSpace = space
		h.savedSearches.SetFolderSpace(space)
		h.messageTemplates.SetFolderSpace(space)
		h.mimeReader = service.NewMIMEReader(space)
		h.workspace.SetFolderSpace(space)
		h.shareLinks.SetFolderSpace(space)
		h.migrationRunner = migration.NewRunner(h.migrationJobs, space)
	}
	h.migrationSources = make(map[string]migration.SourceFactory, len(sources))
	for name, factory := range sources {
		h.migrationSources[name] = factory
	}
}

// SetMailQueue enables authenticated mail submission after the server's
// delivery queue has been initialized.
func (h *Handler) SetMailQueue(mailQueue service.MailQueue) {
	h.mail = service.NewMailWithFolderSpace(h.ts, h.authorizer, mailQueue, h.folderSpace)
	h.mail.SetEventPublisher(h.events)
}

// ConfigureScheduledSubmissions installs future-send jobs on the same
// authorized Mail and FolderSpace instances used by immediate submission.
func (h *Handler) ConfigureScheduledSubmissions(ctx context.Context, cfg scheduledsend.Config) (*scheduledsend.Service, error) {
	if h.mail == nil {
		return nil, errors.New("mail submission is unavailable")
	}
	scheduler, err := scheduledsend.New(ctx, h.ts, h.folderSpace, h.mail, cfg)
	if err != nil {
		return nil, err
	}
	h.scheduledMail = scheduler
	return scheduler, nil
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /favicon.ico", staticassets.ServeFavicon)
	// The installable web app files are public: the browser fetches the
	// manifest and update-checks the worker without a session.
	mux.HandleFunc("GET "+staticassets.ManifestPath, staticassets.ServeManifest)
	mux.HandleFunc("GET "+staticassets.ServiceWorkerPath, staticassets.ServeServiceWorker)
	mux.HandleFunc("GET "+staticassets.OfflinePath, staticassets.ServeOfflinePage)
	mux.HandleFunc("GET /app/setup", h.handleSetup)
	mux.HandleFunc("POST /app/setup", h.handleSetupPost)
	mux.HandleFunc("GET /app/login", h.handleLogin)
	mux.HandleFunc("POST /app/login", h.handleLoginPost)
	mux.HandleFunc("GET /quarantine/action", h.quarantineActionConfirmation)
	mux.HandleFunc("POST /quarantine/action", h.quarantineActionExecute)

	protected := http.NewServeMux()
	protected.HandleFunc("GET /", h.handleHome)
	protected.HandleFunc("GET /{page}", h.handlePage)
	protected.HandleFunc("GET /settings/{section}", h.handleUserSettings)
	protected.HandleFunc("GET /admin/{section}", h.handleAdminSection)
	protected.HandleFunc("GET /admin/protocols/{protocol}", h.handleAdminProtocol)
	protected.HandleFunc("GET /admin/operations/{operation}", h.handleAdminOperation)
	protected.HandleFunc("POST /logout", h.handleLogout)
	mux.Handle("/app/", http.StripPrefix("/app", h.requireSession(protected)))
	h.registerAPI(apiRouter{h: h, mux: mux})
	h.registerTwoFactorRoutes(mux, apiRouter{h: h, mux: mux})
	h.registerSendGuardRoutes(apiRouter{h: h, mux: mux})
	h.registerDomainAdminRoutes(apiRouter{h: h, mux: mux})
	h.registerUserAliasRoutes(apiRouter{h: h, mux: mux})
	h.registerPGPKeyRoutes(apiRouter{h: h, mux: mux})
}

func (h *Handler) handleAdminSection(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionFromContext(r.Context())
	scope := h.adminScopeFor(r.Context(), session.ActorID)
	section := r.PathValue("section")
	if !scope.system && !(scope.any() && domainAdminSections[section]) {
		if scope.any() && validAdminSection(section) {
			h.renderAdminDenied(w, r, scope, section, "", "")
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !validAdminSection(section) {
		http.NotFound(w, r)
		return
	}
	if section == "protocols" {
		http.Redirect(w, r, "/app/admin/protocols/smtp", http.StatusSeeOther)
		return
	}
	if section == "operations" {
		http.Redirect(w, r, "/app/admin/operations/overview", http.StatusSeeOther)
		return
	}
	h.renderAdminPage(w, r, scope, section, "")
}

func (h *Handler) handleAdminOperation(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionFromContext(r.Context())
	scope := h.adminScopeFor(r.Context(), session.ActorID)
	operation := r.PathValue("operation")
	if !scope.system && !(scope.any() && domainAdminOperations[operation]) {
		if scope.any() && validAdminOperation(operation) {
			h.renderAdminDenied(w, r, scope, "operations", operation, "")
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !validAdminOperation(operation) {
		http.NotFound(w, r)
		return
	}
	h.renderAdminOperation(w, r, scope, operation)
}

func (h *Handler) handleAdminProtocol(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionFromContext(r.Context())
	if !h.isAdmin(r.Context(), session.ActorID) {
		if scope := h.adminScopeFor(r.Context(), session.ActorID); scope.any() && validAdminProtocol(r.PathValue("protocol")) {
			h.renderAdminDenied(w, r, scope, "protocols", "", r.PathValue("protocol"))
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	protocol := r.PathValue("protocol")
	if !validAdminProtocol(protocol) {
		http.NotFound(w, r)
		return
	}
	h.renderAdminPage(w, r, adminScope{system: true}, "protocols", protocol)
}

func (h *Handler) handleSetup(w http.ResponseWriter, r *http.Request) {
	state, err := h.bootstrap.State(r.Context())
	if err != nil {
		h.render(w, "setup.gohtml", map[string]any{"Error": err.Error(), "Blocked": true, "CSRF": h.ensureCSRF(w, r)}, http.StatusInternalServerError)
		return
	}
	if state == authz.SetupComplete {
		http.Redirect(w, r, "/app/login", http.StatusFound)
		return
	}
	blocked := state == authz.SetupBlocked
	errorMessage := ""
	if blocked {
		errorMessage = "This store contains users but no system owner. Automatic upgrade is disabled; start with a clean store."
	}
	h.render(w, "setup.gohtml", map[string]any{
		"Blocked": blocked, "Error": errorMessage, "CSRF": h.ensureCSRF(w, r), "Token": r.URL.Query().Get("token"), "HostName": h.setupDefaultHostName(),
	}, http.StatusOK)
}

// SetupToken returns the one-time first-owner token while setup is pending.
func (h *Handler) SetupToken(ctx context.Context) (string, error) {
	return h.bootstrap.SetupToken(ctx)
}

func (h *Handler) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	if !h.validPublicCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	password, token := r.FormValue("password"), r.FormValue("token")
	hostForm := r.FormValue("host_name")
	setupError := func(message string, status int) {
		h.render(w, "setup.gohtml", map[string]any{"Error": message, "CSRF": h.ensureCSRF(w, r), "Token": token, "HostName": hostForm}, status)
	}
	if password != r.FormValue("confirm") {
		setupError("Passwords do not match", http.StatusBadRequest)
		return
	}
	hostName, err := h.setupHostNameChange(hostForm)
	if err != nil {
		setupError("Public mail host name: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.bootstrap.CreateOwner(r.Context(), token, r.FormValue("username"), r.FormValue("display_name"), password); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, authz.ErrSetupToken) {
			status = http.StatusForbidden
		}
		setupError(err.Error(), status)
		return
	}
	h.persistSetupHostName(r.Context(), hostName)
	if err := h.syncAccountManifest(r.Context(), r.FormValue("username")); err != nil {
		h.render(w, "setup.gohtml", map[string]any{"Error": err.Error(), "CSRF": h.ensureCSRF(w, r)}, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/app/login?setup=complete", http.StatusFound)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := h.bootstrap.State(r.Context())
	if err != nil {
		http.Error(w, "setup state unavailable", http.StatusInternalServerError)
		return
	}
	if state != authz.SetupComplete {
		http.Redirect(w, r, "/app/setup", http.StatusFound)
		return
	}
	h.render(w, "login.gohtml", map[string]any{
		"CSRF": h.ensureCSRF(w, r), "Error": r.URL.Query().Get("error"),
		"SetupComplete": r.URL.Query().Get("setup") == "complete",
	}, http.StatusOK)
}

func (h *Handler) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if !h.validPublicCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	user, err := h.authenticateLogin(r, r.FormValue("username"), r.FormValue("password"))
	if errors.Is(err, ratelimit.ErrAuthThrottled) {
		ratelimit.WriteRetryAfter(w, err)
		h.render(w, "login.gohtml", map[string]any{
			"CSRF": h.ensureCSRF(w, r), "Error": "Too many failed sign-in attempts. Try again later.",
		}, http.StatusTooManyRequests)
		return
	}
	if err != nil {
		http.Redirect(w, r, "/app/login?error=Invalid+username+or+password", http.StatusFound)
		return
	}
	csrf, err := r.Cookie(csrfCookie)
	if err != nil {
		http.Error(w, "missing CSRF cookie", http.StatusForbidden)
		return
	}
	state, err := h.beginSignIn(w, r, user.ID, csrf.Value)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	if state != "" {
		http.Redirect(w, r, "/app/login/second-factor", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/app/", http.StatusFound)
}

// startSession records a browser session for the resolved client and sets its
// cookie. The cookie is Secure whenever the client connection is HTTPS, either
// directly or as reported by a trusted TLS-terminating proxy.
func (h *Handler) startSession(w http.ResponseWriter, r *http.Request, userID, csrf string) error {
	client := httpservice.RequestClient(r)
	token, err := h.sessions.Create(r.Context(), userID, csrf, client.IP, r.UserAgent())
	if err != nil {
		return err
	}
	if h.sendGuard != nil {
		h.sendGuard.RecordLogin(r.Context(), userID, client.IP)
	}
	if h.mailIndexWarm.Load() {
		go h.warmAccount(context.WithoutCancel(r.Context()), userID)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: client.HTTPS, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionLifetime.Seconds())})
	return nil
}

var errInvalidLogin = errors.New("invalid username or password")

// authenticateLogin verifies browser credentials. Repeated failures from one
// client are refused by the shared throttle before any password hash is
// compared. The client address honours forwarding headers only from
// configured trusted proxies.
func (h *Handler) authenticateLogin(r *http.Request, username, password string) (user model.User, err error) {
	username = strings.ToLower(strings.TrimSpace(username))
	ip := httpservice.RequestClient(r).IP
	if err := h.loginThrottle.Begin(ip, username); err != nil {
		return model.User{}, err
	}
	defer func() { h.loginThrottle.End(ip, username, err == nil) }()
	user, err = h.passwords.VerifyPassword(r.Context(), username, password)
	if err != nil {
		return model.User{}, errInvalidLogin
	}
	return user, nil
}

// PasswordVerifier checks an account's primary password: a local hash for
// local accounts, the directory for directory accounts. Protocol logins use
// the same check, so web and protocol sign-in cannot diverge.
type PasswordVerifier interface {
	VerifyPassword(ctx context.Context, username, password string) (model.User, error)
}

// confirmPassword re-verifies the signed-in account's own primary password
// before a sensitive action.
func (h *Handler) confirmPassword(ctx context.Context, userID, password string) bool {
	user, err := h.passwords.VerifyPassword(ctx, userID, password)
	return err == nil && user.ID == userID
}

// ConfigureLoginThrottle shares the failed-authentication throttle used by
// protocol credentials so one client has a single budget across surfaces.
func (h *Handler) ConfigureLoginThrottle(throttle *ratelimit.AuthThrottle) {
	h.loginThrottle = throttle
}

// ConfigurePasswordVerifier installs the primary password check shared with
// protocol logins, including directory accounts.
func (h *Handler) ConfigurePasswordVerifier(verifier PasswordVerifier) {
	h.passwords = verifier
}

// ConfigureTrustedProxies installs the shared forwarded-header resolver so
// http_trusted_proxies changes apply live.
func (h *Handler) ConfigureTrustedProxies(proxies *httpservice.TrustedProxies) {
	h.trustedProxies = proxies
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionFromContext(r.Context())
	if !ok || !h.validSessionCSRF(r, session) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = h.sessions.Delete(r.Context(), cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", HttpOnly: true, Expires: time.Unix(1, 0), MaxAge: -1})
	http.Redirect(w, r, "/app/login", http.StatusFound)
}

func (h *Handler) handleHome(w http.ResponseWriter, r *http.Request) {
	h.renderApp(w, r, "home")
}

func (h *Handler) handlePage(w http.ResponseWriter, r *http.Request) {
	page := r.PathValue("page")
	switch page {
	case "mail", "calendar", "tasks", "contacts", "files", "search", "trash", "account", "sharing", "quarantine":
		if page == "account" {
			http.Redirect(w, r, "/app/settings/profile", http.StatusSeeOther)
			return
		}
		if page == "sharing" {
			http.Redirect(w, r, "/app/settings/access", http.StatusSeeOther)
			return
		}
		h.renderApp(w, r, page)
	case "settings":
		http.Redirect(w, r, "/app/settings/profile", http.StatusSeeOther)
	case "admin":
		session, _ := sessionFromContext(r.Context())
		switch scope := h.adminScopeFor(r.Context(), session.ActorID); {
		case scope.system:
			h.renderAdminPage(w, r, scope, "overview", "")
		case scope.any():
			http.Redirect(w, r, "/app/admin/domains", http.StatusSeeOther)
		default:
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) renderAdminPage(w http.ResponseWriter, r *http.Request, scope adminScope, section, protocol string) {
	session, _ := sessionFromContext(r.Context())
	h.render(w, "app.gohtml", map[string]any{
		"Page": "admin", "AdminSection": section, "AdminProtocol": protocol, "AdminScope": scope.name(),
		"Session": session, "IsAdmin": scope.system, "DomainAdmin": !scope.system, "CSRF": h.csrfValue(r),
	}, http.StatusOK)
}

// renderAdminDenied answers a domain administrator who opens a system-only
// administration page with the administration shell and an in-app "not
// available for your role" view, instead of a bare error page.
func (h *Handler) renderAdminDenied(w http.ResponseWriter, r *http.Request, scope adminScope, section, operation, protocol string) {
	session, _ := sessionFromContext(r.Context())
	h.render(w, "app.gohtml", map[string]any{
		"Page": "admin", "AdminSection": section, "AdminOperation": operation, "AdminProtocol": protocol, "AdminScope": scope.name(), "AdminDenied": true,
		"Session": session, "IsAdmin": scope.system, "DomainAdmin": !scope.system, "CSRF": h.csrfValue(r),
	}, http.StatusForbidden)
}

func (h *Handler) renderAdminOperation(w http.ResponseWriter, r *http.Request, scope adminScope, operation string) {
	session, _ := sessionFromContext(r.Context())
	h.render(w, "app.gohtml", map[string]any{
		"Page": "admin", "AdminSection": "operations", "AdminOperation": operation, "AdminScope": scope.name(),
		"Session": session, "IsAdmin": scope.system, "DomainAdmin": !scope.system, "CSRF": h.csrfValue(r),
	}, http.StatusOK)
}

func (h *Handler) renderApp(w http.ResponseWriter, r *http.Request, page string) {
	session, _ := sessionFromContext(r.Context())
	scope := h.adminScopeFor(r.Context(), session.ActorID)
	h.render(w, "app.gohtml", map[string]any{
		"Page": page, "Session": session, "IsAdmin": scope.system, "DomainAdmin": !scope.system && scope.any(),
		"CSRF": h.csrfValue(r),
	}, http.StatusOK)
}

// displayName returns the user's profile display name, or the account ID when
// none is set.
func (h *Handler) displayName(userID string) string {
	if user, err := h.users.Get(context.Background(), userID); err == nil && strings.TrimSpace(user.DisplayName) != "" {
		return user.DisplayName
	}
	return userID
}

// isAdmin reports system administration: system.owner, system.admin, or a
// custom system role holding system.manage. authorization.roles.read keeps
// admitting custom roles written before system.manage existed.
func (h *Handler) isAdmin(ctx context.Context, userID string) bool {
	return h.systemAllowed(ctx, userID, authz.SystemManage) || h.systemAllowed(ctx, userID, authz.AuthorizationRolesRead)
}

// isOwner reports owner authority: the right to assign roles, which
// system.admin lacks. Operations that could make their caller an owner
// (backup restore, raw configuration, the directory's administrator role)
// require it.
func (h *Handler) isOwner(ctx context.Context, userID string) bool {
	return h.systemAllowed(ctx, userID, authz.AuthorizationRolesWrite)
}

func (h *Handler) systemAllowed(ctx context.Context, userID string, action authz.Action) bool {
	decision, err := h.authorizer.Check(ctx, authz.Request{
		Actor:    model.PrincipalRef{Kind: model.PrincipalUser, ID: userID},
		Action:   action,
		Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
	})
	return err == nil && decision.Allowed
}

func (h *Handler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Redirect(w, r, "/app/login", http.StatusFound)
			return
		}
		session, err := h.sessions.Get(r.Context(), cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/app/login", http.StatusFound)
			return
		}
		user, err := h.users.Get(r.Context(), session.ActorID)
		if err != nil || !user.Enabled {
			_ = h.sessions.Delete(r.Context(), cookie.Value)
			http.Redirect(w, r, "/app/login", http.StatusFound)
			return
		}
		session, err = h.revalidateActing(r.Context(), cookie.Value, session)
		if err != nil {
			http.Error(w, "authorization state unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handler) revalidateActing(ctx context.Context, token string, session model.Session) (model.Session, error) {
	if session.SubjectID == "" || session.SubjectID == session.ActorID {
		if session.SubjectID != session.ActorID || session.ActingMode != "" {
			return h.clearActing(ctx, token, session, "invalid_state")
		}
		return session, nil
	}
	subject, err := h.users.Get(ctx, session.SubjectID)
	if err != nil || !subject.Enabled {
		return h.clearActing(ctx, token, session, "subject_unavailable")
	}
	var action authz.Action
	switch authz.ActingMode(session.ActingMode) {
	case authz.ActingDelegation:
		action = authz.AccountDelegate
	case authz.ActingImpersonation:
		if session.ActingExpiresAt.IsZero() || !session.ActingExpiresAt.After(time.Now().UTC()) {
			return h.clearActing(ctx, token, session, "expired")
		}
		action = authz.AccountImpersonate
	default:
		return h.clearActing(ctx, token, session, "invalid_mode")
	}
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: session.ActorID}
	decision, err := h.authorizer.Check(ctx, authz.Request{
		Actor: actor, Subject: actor, Action: action,
		Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: session.SubjectID},
	})
	if err != nil {
		return model.Session{}, err
	}
	if !decision.Allowed {
		return h.clearActing(ctx, token, session, "permission_revoked")
	}
	return session, nil
}

func (h *Handler) clearActing(ctx context.Context, token string, session model.Session, cause string) (model.Session, error) {
	cleared, err := h.sessions.SetActing(ctx, token, "", "", "", time.Time{})
	if err == nil {
		h.audit.Log(session.ActorID, "session."+session.ActingMode+".cleared", session.SubjectID, map[string]string{"cause": cause, "reason": session.ActingReason})
	}
	return cleared, err
}

func sessionFromContext(ctx context.Context) (model.Session, bool) {
	session, ok := ctx.Value(sessionContextKey{}).(model.Session)
	return session, ok
}

func (h *Handler) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(csrfCookie); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	token, err := randomToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: token, Path: "/", Secure: httpservice.RequestClient(r).HTTPS, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionLifetime.Seconds())})
	return token
}

func (h *Handler) validPublicCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	provided := submittedCSRF(r)
	return len(cookie.Value) == len(provided) && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(provided)) == 1
}

func (h *Handler) validSessionCSRF(r *http.Request, session model.Session) bool {
	return h.sessions.ValidCSRF(session, submittedCSRF(r))
}

// submittedCSRF returns the token the client sent explicitly. The CSRF cookie
// is never accepted here: a cross-site request carries it automatically.
func submittedCSRF(r *http.Request) string {
	if value := r.Header.Get("X-CSRF-Token"); value != "" {
		return value
	}
	return r.FormValue("_csrf")
}

// csrfValue returns the token to embed in rendered pages.
func (h *Handler) csrfValue(r *http.Request) string {
	if value := submittedCSRF(r); value != "" {
		return value
	}
	if cookie, err := r.Cookie(csrfCookie); err == nil {
		return cookie.Value
	}
	return ""
}

func (h *Handler) render(w http.ResponseWriter, name string, data map[string]any, status int) {
	data["ClientManifest"] = h.clientManifest
	if session, ok := data["Session"].(model.Session); ok {
		data["ActorName"], data["SubjectName"] = h.displayName(session.ActorID), h.displayName(session.SubjectID)
		if name == "app.gohtml" {
			owner := session.ActorID
			if session.ActingMode == string(authz.ActingImpersonation) && session.SubjectID != "" {
				// Support access shows the supported account's preferences,
				// the ones its settings pages change.
				owner = session.SubjectID
			}
			data["Preferences"] = h.clientPreferences(context.Background(), owner)
		}
	}
	var body bytes.Buffer
	if err := h.templates.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "template rendering failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setPageSecurityHeaders(w.Header())
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}

// appPagePolicy confines the application, sign-in and setup pages to their
// own scripts: an injected element can neither run inline script nor load
// one from elsewhere, and no other site may frame the sign-in form. Inline
// style attributes stay allowed, since the templates and the client use
// them for layout; message HTML is shown in a separately sandboxed frame.
const appPagePolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
	"font-src 'self'; connect-src 'self'; media-src 'self' blob:; frame-src 'self' blob:; worker-src 'self'; manifest-src 'self'; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// setPageSecurityHeaders adds the page policy unless the handler already set
// a stricter one (public share pages do).
func setPageSecurityHeaders(header http.Header) {
	if header.Get("Content-Security-Policy") == "" {
		header.Set("Content-Security-Policy", appPagePolicy)
	}
	if header.Get("X-Frame-Options") == "" {
		header.Set("X-Frame-Options", "DENY")
	}
	header.Set("X-Content-Type-Options", "nosniff")
	if header.Get("Referrer-Policy") == "" {
		header.Set("Referrer-Policy", "same-origin")
	}
}

// SecretSealer returns the installation's stored-credential sealer, which
// opens the credentials administrators store through this handler.
func (h *Handler) SecretSealer() *migration.Store { return h.migrationJobs }
