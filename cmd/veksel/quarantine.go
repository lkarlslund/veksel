package main

import (
	"context"
	"net/mail"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/virus"
)

func quarantinePolicy(cfg *config.Config) virus.QuarantinePolicy {
	return virus.QuarantinePolicy{
		Retention:  time.Duration(cfg.QuarantineRetentionDays) * 24 * time.Hour,
		MaxEntries: cfg.QuarantineMaxEntries,
		MaxBytes:   cfg.QuarantineMaxBytes,
	}
}

// openQuarantine opens the quarantine store and its action tokens, schedules
// expiry cleanup, and makes the quarantine settings live.
func (s *server) openQuarantine() error {
	cfg, ts, ctx := s.cfg, s.ts, s.ctx
	s.quarantineStore = virus.NewQuarantineStore(ts, quarantinePolicy(cfg))
	s.quarantineStore.SetOwnerResolver(func(ownerCtx context.Context, recipient string) (string, error) {
		identity, ownerErr := s.recipientMailbox(ownerCtx, recipient)
		return identity.UserID, ownerErr
	})
	s.appHandler.ConfigureQuarantine(s.quarantineStore)
	var err error
	s.quarantineActions, err = virus.NewQuarantineActionService(ctx, ts, time.Duration(cfg.QuarantineActionTTLHours)*time.Hour)
	if err != nil {
		return startupError("initialize quarantine actions", err)
	}
	s.appHandler.ConfigureQuarantineActions(s.quarantineActions)
	var batchSize atomic.Int64
	batchSize.Store(int64(cfg.QuarantineCleanupBatchSize))
	cleanup := func() { s.cleanupQuarantine(int(batchSize.Load())) }
	cleanup()
	setInterval := everyAdjustable(s.background, time.Duration(cfg.QuarantineCleanupMinutes)*time.Minute, cleanup)
	return s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		if err := s.quarantineStore.SetPolicy(quarantinePolicy(cfg)); err != nil {
			return err
		}
		if err := s.quarantineActions.SetTTL(time.Duration(cfg.QuarantineActionTTLHours) * time.Hour); err != nil {
			return err
		}
		batchSize.Store(int64(cfg.QuarantineCleanupBatchSize))
		setInterval(time.Duration(cfg.QuarantineCleanupMinutes) * time.Minute)
		return nil
	}, "quarantine_retention_days", "quarantine_max_entries", "quarantine_max_bytes", "quarantine_action_ttl_hours",
		"quarantine_cleanup_minutes", "quarantine_cleanup_batch_size")
}

func (s *server) cleanupQuarantine(batchSize int) {
	ctx := s.ctx
	cleanup, cleanupErr := s.quarantineStore.CleanupExpired(ctx, time.Now().UTC(), batchSize)
	if cleanupErr != nil {
		log.Error("cleanup quarantine", "error", cleanupErr)
	} else if cleanup.Removed > 0 {
		log.Info("quarantine: removed expired messages", "removed", cleanup.Removed, "bytes", cleanup.Bytes)
	}
	if removed, actionErr := s.quarantineActions.Cleanup(ctx, time.Now().UTC(), batchSize); actionErr != nil {
		log.Error("cleanup quarantine actions", "error", actionErr)
	} else if removed > 0 {
		log.Info("quarantine: removed expired actions", "removed", removed)
	}
}

func quarantineDigestConfig(cfg *config.Config) virus.QuarantineDigestConfig {
	return virus.QuarantineDigestConfig{
		BaseURL: cfg.QuarantineDigestBaseURL, FromAddress: cfg.QuarantineDigestFrom,
		MaxEntries: cfg.QuarantineDigestMaxEntries, MaxJobsPerRun: cfg.QuarantineDigestMaxJobs,
		MaxAttempts: cfg.QuarantineDigestMaxRetries, RetryBase: time.Duration(cfg.QuarantineDigestRetrySecs) * time.Second,
		JobRetention: time.Duration(cfg.QuarantineDigestJobDays) * 24 * time.Hour,
	}
}

// quarantineDigestScheduler runs quarantine digest mail while the setting is
// enabled. Enabling, disabling and every digest limit apply without restart:
// the service and its durable state persist, only the scheduler loops and the
// administration exposure follow the setting.
type quarantineDigestScheduler struct {
	server *server

	mu          sync.Mutex
	service     *virus.QuarantineDigestService
	stop        context.CancelFunc
	setInterval func(time.Duration)
	from        atomic.Pointer[mail.Address]
	jobLimit    atomic.Int64
}

// startQuarantineDigests registers the digest settings as live and starts the
// scheduler when digests are enabled.
func (s *server) startQuarantineDigests() error {
	scheduler := &quarantineDigestScheduler{server: s}
	if err := scheduler.apply(s.cfg); err != nil {
		return startupError("initialize quarantine digests", err)
	}
	return s.cfgService.RegisterApplier(scheduler.apply,
		"quarantine_digest_enabled", "quarantine_digest_base_url", "quarantine_digest_from", "quarantine_digest_poll_minutes",
		"quarantine_digest_max_entries", "quarantine_digest_max_jobs_per_run", "quarantine_digest_max_retries",
		"quarantine_digest_retry_seconds", "quarantine_digest_job_retention_days")
}

func (d *quarantineDigestScheduler) apply(cfg *config.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.server
	if !cfg.QuarantineDigestEnabled {
		if d.stop != nil {
			d.stop()
			d.stop, d.setInterval = nil, nil
			s.appHandler.ConfigureQuarantineDigests(nil)
		}
		return nil
	}
	digestConfig := quarantineDigestConfig(cfg)
	if d.service == nil {
		service, err := virus.NewQuarantineDigestService(s.ts, s.quarantineStore, s.quarantineActions, s.digestRecipient, digestConfig)
		if err != nil {
			return err
		}
		d.service = service
	} else if err := d.service.SetConfig(digestConfig); err != nil {
		return err
	}
	from, _ := mail.ParseAddress(cfg.QuarantineDigestFrom)
	d.from.Store(from)
	d.jobLimit.Store(int64(cfg.QuarantineDigestMaxJobs))
	interval := time.Duration(cfg.QuarantineDigestPollMins) * time.Minute
	if d.stop != nil {
		d.setInterval(interval)
		return nil
	}
	s.appHandler.ConfigureQuarantineDigests(d.service)
	var ctx context.Context
	ctx, d.stop = context.WithCancel(s.ctx)
	d.setInterval = d.startLoops(ctx, interval)
	return nil
}

// digestRecipient resolves the address a user's digest is delivered to.
func (s *server) digestRecipient(ctx context.Context, userID string) (string, error) {
	identities, err := s.ts.UserStore().ListEmailAddressesForUser(ctx, userID)
	if err != nil {
		return "", err
	}
	for _, identity := range identities {
		if identity.Enabled && identity.Primary {
			return identity.ID, nil
		}
	}
	for _, identity := range identities {
		if identity.Enabled {
			return identity.ID, nil
		}
	}
	return "", store.ErrNotFound
}

// startLoops runs the digest pass and the daily job cleanup until ctx ends and
// returns the setter for the pass interval.
func (d *quarantineDigestScheduler) startLoops(ctx context.Context, interval time.Duration) func(time.Duration) {
	s := d.server
	sendDigest := func(sendCtx context.Context, job virus.QuarantineDigestJob) error {
		return s.enqueueDerived(sendCtx, smtp.DerivedMessage{Kind: "quarantine-digest", Recipient: job.Recipient, EnvelopeSender: d.from.Load().Address, FullMessage: job.FullMessage, ParentID: job.ID, CorrelationID: job.ID, DKIM: &dkim.Request{}})
	}
	runDigests := func() {
		result, runErr := d.service.Run(ctx, sendDigest)
		if runErr != nil {
			log.Error("run quarantine digests", "error", runErr)
		} else if result.Prepared+result.Empty+result.Sent+result.Retried+result.Failed > 0 {
			log.Info("quarantine digest pass", "prepared", result.Prepared, "empty", result.Empty, "sent", result.Sent, "retried", result.Retried, "failed", result.Failed)
		}
	}
	cleanupJobs := func() {
		if removed, cleanupErr := d.service.Cleanup(ctx, time.Now().UTC(), int(d.jobLimit.Load())); cleanupErr != nil {
			log.Error("cleanup quarantine digest jobs", "error", cleanupErr)
		} else if removed > 0 {
			log.Info("quarantine: removed terminal digest jobs", "removed", removed)
		}
	}
	cleanupJobs()
	s.background.Every(24*time.Hour, false, cleanupJobs)
	s.spawn(runDigests)
	return everyAdjustable(s.background, interval, runDigests)
}
