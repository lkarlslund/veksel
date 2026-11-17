package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/accountverify"
	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/autodiscover"
	"github.com/lkarlslund/veksel/pkg/background"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/bayes"
	"github.com/lkarlslund/veksel/pkg/caldav"
	"github.com/lkarlslund/veksel/pkg/certificates"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/directory"
	"github.com/lkarlslund/veksel/pkg/dmarc"
	"github.com/lkarlslund/veksel/pkg/dnsserver"
	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/httpservice"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/rules"
	searchindex "github.com/lkarlslund/veksel/pkg/search"
	"github.com/lkarlslund/veksel/pkg/sendguard"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/tlsrpt"
	"github.com/lkarlslund/veksel/pkg/virus"
	webapp "github.com/lkarlslund/veksel/pkg/web/app"
	"github.com/lkarlslund/veksel/pkg/webhook"
)

// server carries the long-lived components that run wires together. Each
// startup phase fills in the fields later phases depend on and registers the
// matching cleanup, so an early failure releases exactly what was opened.
type server struct {
	// callout caches split-delivery recipient callouts (see recipientCallout).
	calloutOnce sync.Once
	callout     *smtp.RecipientCallout
	cleanup     cleanupStack
	// drained is set once the graceful shutdown sequence has run; abort-only
	// cleanups are skipped after that.
	drained bool

	cfgService *config.Service
	cfg        *config.Config
	store      store.Store
	ts         *model.TypedStore
	met        *metrics.Metrics

	// background runs every long-lived background job, and ctx is its
	// context. Shutdown stops the group (cancel and wait) only after protocol
	// sessions and HTTP requests have drained, and always before the stores
	// close, so no job reaches a closed store.
	background *background.Group
	ctx        context.Context
	// longPolls ends when shutdown begins, before requests drain, so long
	// polls such as ActiveSync Ping answer at once instead of holding the
	// drain until its deadline.
	longPolls     context.Context
	stopLongPolls context.CancelFunc

	// Accounts and system services.
	protocolAuth        *protocolauth.Service
	directory           *directory.Service
	accountManager      *account.Manager
	accountVerification *accountverify.Scheduler
	backupScheduler     *backup.Scheduler
	capacityCollector   *health.CapacityCollector
	certificates        *certificates.Provider
	mailPolicies        *mailpolicy.Service
	greylisting         *greylist.Service
	bans                *ban.Service
	webhooks            *webhook.Dispatcher
	// dnsServer is the optional built-in authoritative DNS server.
	dnsServer *dnsserver.Server
	// protocolControl backs live protocol start/stop from the admin UI.
	protocolControl *protocolControlImpl

	// Folder storage stack.
	folderSpace service.FolderSpace
	folderCache *service.CachedFolderSpace
	search      *searchindex.Manager
	automation  *rules.Engine
	// compliance owns legal holds and retention policies; retention applies
	// the policies in the background.
	compliance   *service.Compliance
	retention    *service.RetentionJob
	imip         *imip.Service
	sieveScripts *service.SieveRepository
	// spamClassifier learns from Junk moves and scores per recipient.
	spamClassifier *bayes.Service

	// Runtime health.
	healthRegistry    *health.Registry
	healthAlerts      *health.AlertStore
	healthEvaluator   *health.Evaluator
	healthReady       atomic.Bool
	latestQueueStats  atomic.Pointer[queue.Stats]
	certificateHealth certificateHealthCache
	alertNotifier     *alertnotify.Notifier
	quotaWatcher      *alertnotify.QuotaWatcher
	// sendGuard enforces outbound sending limits and holds the mail of
	// suspected compromised accounts.
	sendGuard         *sendguard.Guard
	alertDeliveryBusy atomic.Bool
	quotaScanBusy     atomic.Bool

	// HTTP.
	mux            *http.ServeMux
	appHandler     *webapp.Handler
	trustedProxies *httpservice.TrustedProxies
	shutdownCh     chan struct{}
	restartCh      chan struct{}
	// httpListeners and pprofListener reconcile their servers with
	// configuration changes; services, autodiscover and metricsToken are
	// swapped by live appliers (http_live.go).
	httpListeners *httpservice.ListenerSet
	pprofListener *httpservice.ListenerSet
	services      httpservice.ServiceGate
	dav           *caldav.Handler
	autodiscover  atomic.Pointer[autodiscover.Handler]
	metricsToken  atomic.Pointer[string]
	signalCtx     context.Context
	stopSignals   context.CancelFunc

	// Mail transport.
	messageTrace       *messagetrace.Store
	mtaSTS             *mtasts.Service
	dane               daneRuntime
	tlsReporter        *tlsrpt.Recorder
	dmarcAggregates    *dmarc.AggregateRecorder
	dmarcAggregateSink smtp.DMARCAggregateRecorder
	quarantineStore    *virus.QuarantineStore
	quarantineActions  *virus.QuarantineActionService
	vacationProcessor  service.VacationIntentProcessor
	mailQueue          *queue.Queue
	smtpQueueAdapter   *queue.SMTPAdapter
	routeSecrets       secretOpener // opens sealed sender route credentials
	openpgp            openpgpSettings
	stopScheduledMail  func()
	exchangeMail       *service.Mail
	recipientHistory   *service.RecipientHistory
	// delivery holds the outbound routes, scanners, and reporting state
	// that managed configuration replaces live.
	delivery deliveryRuntime
}

// certificateHealthCache rate-limits stored certificate inspection during
// runtime health refreshes.
type certificateHealthCache struct {
	mu           sync.Mutex
	at           time.Time
	signature    string
	observations []health.Observation
}

// cleanupStack releases resources in reverse order of acquisition.
type cleanupStack struct {
	entries []cleanupEntry
}

type cleanupEntry struct {
	fn func()
	// abortOnly entries release resources that the graceful shutdown
	// sequence otherwise stops explicitly and in its own order.
	abortOnly bool
}

// push registers fn to run when run returns.
func (c *cleanupStack) push(fn func()) {
	c.entries = append(c.entries, cleanupEntry{fn: fn})
}

// pushAbort registers fn to run only when startup fails before the graceful
// shutdown sequence.
func (c *cleanupStack) pushAbort(fn func()) {
	c.entries = append(c.entries, cleanupEntry{fn: fn, abortOnly: true})
}

// run calls the registered cleanups in reverse order.
func (c *cleanupStack) run(aborted bool) {
	for i := len(c.entries) - 1; i >= 0; i-- {
		if entry := c.entries[i]; aborted || !entry.abortOnly {
			entry.fn()
		}
	}
	c.entries = nil
}

// startupError logs a fatal startup failure and returns it wrapped with the
// same message.
func startupError(message string, err error) error {
	log.Error(message, "error", err)
	return fmt.Errorf("%s: %w", message, err)
}

// spawn runs fn once on the background group; it is skipped once shutdown
// has stopped the group.
func (s *server) spawn(fn func()) {
	s.background.Go(func(context.Context) { fn() })
}

// everyAdjustable runs fn every interval on group until it stops. The
// returned function changes the interval while running: the ticker is reset
// and the new period governs from then on.
func everyAdjustable(group *background.Group, interval time.Duration, fn func()) func(time.Duration) {
	resets := make(chan time.Duration, 1)
	var mu sync.Mutex
	group.Go(func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case next := <-resets:
				ticker.Reset(next)
			case <-ticker.C:
				fn()
			}
		}
	})
	return func(next time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		select {
		case <-resets:
		default:
		}
		resets <- next
	}
}

// openRuntime loads the managed configuration, sets up logging, and opens and
// initializes the system store.
func (s *server) openRuntime(dataDir string) error {
	cfgService, err := config.Open(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open configuration: %v\n", err)
		return fmt.Errorf("open configuration: %w", err)
	}
	s.cfgService = cfgService
	s.cfg = cfgService.Current().Config
	cfg := s.cfg

	// Setup structured logging with dual output
	log.SetFileRetention(cfg.LogFileRetentionDays, cfg.LogFileMaxFiles)
	if err := log.Setup(cfg.LogDir, cfg.LogFormat,
		log.ParseLevel(cfg.LogConsoleLevel), log.ParseLevel(cfg.LogFileLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "log setup warning: %v (continuing with console only)\n", err)
	}
	s.cleanup.push(func() { log.Close() })
	if err := log.ConfigureModules(cfg.LogModuleLevels); err != nil {
		fmt.Fprintf(os.Stderr, "log module configuration warning: %v (using info defaults)\n", err)
	}

	log.Info("veksel starting", "version", buildVersion, "commit", buildCommit, "built", buildTime)

	s.store, err = cfg.OpenStore()
	if err != nil {
		return startupError("open store", err)
	}
	s.cleanup.push(func() { s.store.Close() })
	s.ts = model.NewTypedStore(s.store, cfg.StoreBackend)
	s.met = metrics.New(s.store)
	s.cleanup.push(s.met.Close)

	// Registered after the store, so every background job has returned
	// before the store and metrics close, on shutdown and on aborted startup.
	s.background = background.New(context.Background())
	s.ctx = s.background.Context()
	s.longPolls, s.stopLongPolls = context.WithCancel(s.ctx)
	s.cleanup.push(s.background.Stop)
	// Ensure all model namespaces exist.
	if err := model.InitializeSystemStore(s.ctx, s.ts); err != nil {
		return startupError("initialize system store", err)
	}
	return nil
}
