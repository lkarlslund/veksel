package main

import (
	"context"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/log"
)

// buildHealth creates the runtime health registry, its durable alert store,
// and the evaluator that turns health changes into alert transitions.
func (s *server) buildHealth() error {
	s.healthRegistry = health.New()
	var err error
	s.healthAlerts, err = health.NewAlertStore(s.ctx, s.ts.Store())
	if err != nil {
		return startupError("initialize health alerts", err)
	}
	s.healthEvaluator, err = health.NewEvaluator(s.healthRegistry, s.healthAlerts, s.refreshHealth)
	if err != nil {
		return startupError("initialize health evaluator", err)
	}
	return s.buildAlertDelivery()
}

// refreshHealth refreshes runtime health observations once every component
// they observe has started; until then it leaves the registry untouched.
func (s *server) refreshHealth(ctx context.Context) {
	if s.healthReady.Load() {
		s.refreshRuntimeHealth(ctx)
	}
}

// currentConfig returns the latest managed configuration and its revision.
func (s *server) currentConfig() (*config.Config, string) {
	if s.cfgService != nil {
		current := s.cfgService.Current()
		return current.Config, current.Revision
	}
	return s.cfg, "startup"
}

func (s *server) refreshRuntimeHealth(refreshCtx context.Context) {
	effective, configRevision := s.currentConfig()
	controllers := s.protocolControl.controllers
	now := time.Now().UTC()
	policy := health.Policy{
		QueueWarningAge: time.Duration(effective.AlertQueueWarningMinutes) * time.Minute, QueueCriticalAge: time.Duration(effective.AlertQueueCriticalMinutes) * time.Minute,
		WebhookWarningAge: time.Duration(effective.AlertWebhookWarningMinutes) * time.Minute, WebhookCriticalAge: time.Duration(effective.AlertWebhookCriticalMinutes) * time.Minute,
		StorageWarningFreePercent: effective.AlertStorageWarningFreePercent, StorageCriticalFreePercent: effective.AlertStorageCriticalFreePercent,
		CertWarningAge: time.Duration(effective.AlertCertWarningDays) * 24 * time.Hour, CertCriticalAge: time.Duration(effective.AlertCertCriticalDays) * 24 * time.Hour,
	}
	observations := []health.Observation{
		{ID: "http", Label: "HTTP application", Kind: "listener", Desired: true, Required: true, State: health.StateHealthy, Details: map[string]string{"address": effective.ListenAddr}},
		protocolHealthObservation("imap", "IMAP", effective.ImapEnabled || effective.ImapTLSEnabled, controllers.imap.status()),
		protocolHealthObservation("pop3", "POP3", effective.Pop3Enabled || effective.Pop3TLSEnabled, controllers.pop3.status()),
		protocolHealthObservation("smtp", "SMTP and submission", effective.SmtpEnabled || effective.SmtpSubmissionEnabled || effective.SmtpImplicitTLSEnabled, controllers.smtp.status()),
		protocolHealthObservation("managesieve", "ManageSieve", effective.ManageSieveEnabled || effective.ManageSieveTLSEnabled, controllers.managesieve.status()),
		sharedHTTPHealthObservation("caldav", "CalDAV, CardDAV, and WebDAV", effective.DavEnabled, true),
		sharedHTTPHealthObservation("jmap", "JMAP", effective.JmapEnabled, true),
		sharedHTTPHealthObservation("ews", "Exchange Web Services (EWS)", effective.EwsEnabled, ewsCompiled),
		sharedHTTPHealthObservation("eas", "Exchange ActiveSync (EAS)", effective.EasEnabled, easCompiled),
	}
	storeObservation := health.Observation{ID: "system-store", Label: "System store", Kind: "dependency", Desired: true, Required: true, State: health.StateHealthy, Details: map[string]string{"backend": string(effective.StoreBackend)}}
	if _, storeErr := s.ts.ListNamespaces(refreshCtx); storeErr != nil {
		storeObservation.State = health.StateUnavailable
		storeObservation.Reason = "system store cannot list namespaces"
	}
	observations = append(observations, storeObservation)
	observations = append(observations, s.accountVerification.Observation(refreshCtx, now))
	observations = append(observations, s.backupScheduler.Observation(now))
	observations = append(observations, s.bans.Observation())
	queueObservation := policy.QueueObservation(0, 0)
	if s.mailQueue == nil {
		queueObservation.State = health.StateUnavailable
		queueObservation.Severity = health.SeverityCritical
		queueObservation.Reason = "durable queue is not initialized"
	} else {
		depth, oldestAge := s.mailQueue.Size(), time.Duration(0)
		if stats := s.latestQueueStats.Load(); stats != nil {
			depth = stats.Size
			oldestAge = time.Duration(stats.OldestAgeSeconds * float64(time.Second))
		}
		queueObservation = policy.QueueObservation(depth, oldestAge)
	}
	observations = append(observations, queueObservation)
	webhookStats := s.webhooks.Snapshot(now)
	observations = append(observations, policy.WebhookObservation(now,
		webhookStats.Pending, webhookStats.InFlight, webhookStats.Retrying, webhookStats.TerminalFailed,
		time.Duration(webhookStats.OldestPendingAgeSeconds*float64(time.Second)), webhookStats.LastSuccessAt,
		webhookStats.LastFailureAt, webhookStats.LastTerminalFailureAt, webhookStats.Error))
	observations = append(observations, s.spamHealthObservation(effective))
	observations = append(observations, s.quotaWatcher.Observation())
	if s.sendGuard != nil {
		observations = append(observations, s.sendGuard.Observations()...)
	}
	if s.appHandler != nil {
		observations = append(observations, s.appHandler.DNSZones().Observation(refreshCtx))
	}
	if s.dnsServer != nil {
		observations = append(observations, s.dnsServer.Observation())
	}
	observations = append(observations, policy.CapacityObservations(s.capacityCollector.Snapshot(now, s.capacityTargetList()))...)
	if assignments := storedCertificateAssignments(effective); len(assignments) > 0 {
		observations = append(observations, s.certificateObservations(refreshCtx, now, configRevision, policy, assignments)...)
	}
	if healthErr := s.healthRegistry.Replace(now, observations); healthErr != nil {
		log.Error("refresh runtime health", "error", healthErr)
	}
}

// certificateObservations inspects stored certificate metadata at most once
// a minute, or sooner when the configuration revision changes.
func (s *server) certificateObservations(ctx context.Context, now time.Time, configRevision string, policy health.Policy, assignments map[string][]string) []health.Observation {
	cache := &s.certificateHealth
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if configRevision != cache.signature || now.Sub(cache.at) >= time.Minute {
		metadata, metadataErr := s.ts.TLSCertStore().ListMetadata(ctx)
		if metadataErr != nil {
			cache.observations = []health.Observation{{ID: "certificate-inventory", Label: "Certificate inventory", Kind: "certificate", Desired: true, Required: true, State: health.StateUnavailable, Severity: health.SeverityCritical, Reason: "stored certificate metadata is unavailable"}}
		} else {
			cache.observations = policy.CertificateObservations(now, metadata, assignments)
		}
		cache.at, cache.signature = now, configRevision
	}
	return cache.observations
}

// startHealthMonitoring enables runtime health refreshes, publishes the
// initial alert transitions, and evaluates health periodically.
func (s *server) startHealthMonitoring() error {
	ctx := s.ctx
	s.healthReady.Store(true)
	s.refreshRuntimeHealth(ctx)
	s.evaluateHealth()
	s.scanQuotaWarnings()
	s.background.Go(func(ctx context.Context) {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		effective, _ := s.currentConfig()
		nextEvaluation := time.Now().Add(time.Duration(effective.AlertEvaluationSeconds) * time.Second)
		nextQuotaScan := time.Now().Add(quotaScanInterval)
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if !now.Before(nextQuotaScan) {
					nextQuotaScan = now.Add(quotaScanInterval)
					s.scanQuotaWarnings()
				}
				if now.Before(nextEvaluation) {
					continue
				}
				effective, _ := s.currentConfig()
				nextEvaluation = now.Add(time.Duration(effective.AlertEvaluationSeconds) * time.Second)
				s.evaluateHealth()
			}
		}
	})
	return nil
}

// evaluateHealth evaluates alert rules, publishes resulting transitions to
// signed-in administrators, and delivers pending transitions through the
// configured channels. Channel delivery runs even without new transitions so
// deferred, retried, and digest notifications go out on schedule.
func (s *server) evaluateHealth() {
	transitions, evaluateErr := s.healthEvaluator.Evaluate(s.ctx)
	if evaluateErr != nil {
		log.Error("evaluate runtime health", "error", evaluateErr)
		return
	}
	effective, _ := s.currentConfig()
	published := publishHealthTransitions(time.Now().UTC(), effective.AlertNotificationsEnabled, transitions,
		func(event events.Event) error { return s.appHandler.PublishAdminEvent(s.ctx, event) })
	if published > 0 {
		log.Info("published runtime health transitions", "count", published)
	}
	s.processAlertNotifications()
}
