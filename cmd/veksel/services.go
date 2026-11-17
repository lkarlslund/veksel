package main

import (
	"context"
	"fmt"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/accountverify"
	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/certificates"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/keyring"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/mcpserver"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/rules"
	searchindex "github.com/lkarlslund/veksel/pkg/search"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/webhook"
)

// capacityTargetList lists the filesystems whose free space is monitored: the
// system data directory and every currently configured account root.
func (s *server) capacityTargetList() []health.CapacityTarget {
	targets := []health.CapacityTarget{{ID: "system", Label: "System data", Path: s.cfg.DataDir}}
	for _, root := range s.accountManager.Roots() {
		targets = append(targets, health.CapacityTarget{ID: "account-root:" + root.ID, Label: "Account root " + root.ID, Path: root.Path})
	}
	return targets
}

// openAccounts discovers account storage, reconciles it with the system user
// catalog, and starts scheduled account verification.
func (s *server) openAccounts() error {
	cfg, ts, ctx := s.cfg, s.ts, s.ctx
	s.protocolAuth = protocolauth.New(ts)
	// Account data-encryption keys are wrapped by the same installation key
	// ring that protects stored credentials.
	keys, err := keyring.For(ctx, ts.Store())
	if err != nil {
		return startupError("load installation key ring", err)
	}
	discoveryStarted := time.Now()
	accountManager, err := account.NewManagerWithRoots(account.RootsFromDefinitions(cfg.DataDir, cfg.AccountStorageRoots), cfg.PrimaryAccountRoot, cfg.DefaultAccountEngine, account.WithKeyRing(keys))
	if err != nil {
		return startupError("discover accounts", err)
	}
	logSlowStartupStep("account discovery", discoveryStarted)
	s.accountManager = accountManager
	accountManager.SetIdleTimeout(time.Duration(cfg.AccountIdleCloseSeconds) * time.Second)
	accountManager.SetRetainedCleanupDays(cfg.AccountRetainedCleanupDays)
	if err := accountManager.SetEncryptionDefault(cfg.StorageEncryptionDefault); err != nil {
		return startupError("apply storage encryption default", err)
	}
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		return accountManager.SetEncryptionDefault(cfg.StorageEncryptionDefault)
	}, "storage_encryption_default"); err != nil {
		return err
	}
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		accountManager.SetIdleTimeout(time.Duration(cfg.AccountIdleCloseSeconds) * time.Second)
		return nil
	}, "account_idle_close_seconds"); err != nil {
		return err
	}
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		return accountManager.SetRoots(account.RootsFromDefinitions(cfg.DataDir, cfg.AccountStorageRoots), cfg.PrimaryAccountRoot)
	}, "account_storage_roots", "primary_account_root"); err != nil {
		return err
	}
	s.cleanup.push(func() { accountManager.Close() })
	s.accountVerification, err = accountverify.New(ctx, ts, accountManager, accountverify.Policy{
		Enabled:  cfg.AccountVerificationEnabled,
		Interval: time.Duration(cfg.AccountVerificationIntervalHrs) * time.Hour,
		Workers:  cfg.AccountVerificationWorkers,
	})
	if err != nil {
		return startupError("initialize scheduled account verification", err)
	}
	s.capacityCollector = health.NewCapacityCollector(health.OSCapacityProber{}, time.Minute)
	if issues := accountManager.Issues(); len(issues) > 0 {
		for _, issue := range issues {
			log.Error("account discovery issue", "path", issue.Path, "code", issue.Code, "error", issue.Message)
		}
		log.Error("account reconciliation disabled until discovery issues are resolved", "issues", len(issues))
	} else if err := s.reconcileAccounts(); err != nil {
		return err
	}
	s.cleanup.push(s.accountVerification.Start(ctx))
	return nil
}

// reconcileAccounts ensures every system user has account storage and a
// system folder catalog matching the account-local folder schema.
func (s *server) reconcileAccounts() error {
	ctx, ts := s.ctx, s.ts
	users, listErr := ts.UserStore().List(ctx)
	if listErr != nil {
		return startupError("list users for account discovery", listErr)
	}
	for _, user := range users {
		userStarted := time.Now()
		// Default folders evolve additively. Keep the system RBAC resource
		// catalog in step with the account-local folder schema before the
		// account manager applies the same migration to its active store.
		if ensureErr := ts.FolderStore().EnsureForUser(ctx, user.ID); ensureErr != nil {
			log.Error("ensure system folder catalog", "user", user.ID, "error", ensureErr)
			return fmt.Errorf("ensure system folder catalog: %w", ensureErr)
		}
		if created, ensureErr := (account.Provisioner{TS: ts, Manager: s.accountManager}).Sync(ctx, user.ID); ensureErr != nil {
			log.Error("ensure account storage", "user", user.ID, "error", ensureErr)
			return fmt.Errorf("ensure account storage: %w", ensureErr)
		} else if created {
			log.Info("discovered system user into account storage", "user", user.ID)
		}
		logSlowStartupStep("account reconciliation", userStarted, "user", user.ID)
	}
	return nil
}

// startSystemServices opens certificates, the ACME challenge listener,
// authorization indexes, mail policy, greylisting, and webhook delivery.
func (s *server) startSystemServices() error {
	cfg, ts, ctx := s.cfg, s.ts, s.ctx
	certificateProvider, err := certificates.New(ts, cfg)
	if err != nil {
		log.Error("initialize certificate provider", "error", err)
		certificateProvider, _ = certificates.New(ts, nil)
	}
	s.certificates = certificateProvider
	s.cleanup.push(certificateProvider.Close)
	if err := certificateProvider.StartHTTPChallenge(); err != nil {
		log.Error("start ACME HTTP-01 listener", "error", err)
	} else if addr := certificateProvider.ChallengeAddr(); addr != "" {
		log.Info("certificate: ACME HTTP-01 listener started", "addr", addr)
	}
	if err := model.NewPolicyStore(ts).RebuildIndexes(ctx); err != nil {
		return startupError("rebuild authorization indexes", err)
	}
	s.mailPolicies, err = mailpolicy.NewService(ctx, mailpolicy.NewRepository(ts.Store()))
	if err != nil {
		return startupError("initialize mail policy", err)
	}
	s.greylisting, err = greylist.New(ctx, ts.Store(), greylistConfig(cfg))
	if err != nil {
		return startupError("initialize greylisting", err)
	}
	s.cleanupGreylisting()
	s.background.Every(time.Hour, false, s.cleanupGreylisting)
	if err := s.startBans(); err != nil {
		return err
	}

	// Initialize webhook dispatcher with retry policy from config.
	s.webhooks = webhook.New(
		model.NewWebhookStore(ts),
		model.NewWebhookDeliveryStore(ts),
		model.NewWebhookOutboxStore(ts),
		webhookRetryPolicy(cfg),
	)
	s.webhooks.SetAllowPrivateNetworks(cfg.OutboundHTTPAllowPrivateNetworks)
	s.webhooks.Start()
	s.cleanup.pushAbort(s.webhooks.Stop)
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		s.webhooks.SetPolicy(webhookRetryPolicy(cfg))
		return nil
	}, "webhook_max_retries", "webhook_base_delay", "webhook_timeout"); err != nil {
		return err
	}

	// Initialize protocol controllers for live start/stop from admin UI.
	s.protocolControl = &protocolControlImpl{
		controllers: &protocolControllers{
			cfg:          cfg,
			ts:           ts,
			met:          s.met,
			webhookDisp:  s.webhooks,
			certificates: certificateProvider,
			protocolAuth: s.protocolAuth,
			bans:         s.bans,
		},
	}
	return nil
}

// webhookRetryPolicy is the managed webhook retry policy for cfg.
func webhookRetryPolicy(cfg *config.Config) webhook.RetryPolicy {
	return webhook.RetryPolicy{
		MaxRetries:        cfg.WebhookMaxRetries,
		BaseDelay:         cfg.WebhookBaseDelayDuration(),
		BackoffMultiplier: model.DefaultBackoffMultiplier,
		Timeout:           cfg.WebhookTimeoutDuration(),
	}
}

func (s *server) cleanupGreylisting() {
	removed, cleanupErr := s.greylisting.Cleanup(s.ctx, 10_000)
	if cleanupErr != nil {
		log.Error("cleanup greylisting", "error", cleanupErr)
	} else if removed > 0 {
		log.Info("greylisting: removed expired triplets", "removed", removed)
	}
}

// buildFolderSpace assembles the authorized folder stack: account storage,
// the durable command journal, search, the optional cache, and automation.
func (s *server) buildFolderSpace() error {
	cfg, ts, ctx := s.cfg, s.ts, s.ctx
	accountFolderSpace, err := service.NewAccountFolderSpace(ctx, ts, s.accountManager, authz.New(ts))
	if err != nil {
		return startupError("initialize account folder space", err)
	}
	accountFolderSpace.SetChangeRetention(cfg.ChangeHistoryRetentionDays, cfg.ChangeHistoryMaxEntries)
	// Holds apply before the durable journal replays deletions.
	compliance, err := service.NewCompliance(ctx, ts)
	if err != nil {
		return startupError("initialize compliance", err)
	}
	s.compliance = compliance
	accountFolderSpace.SetLegalHolds(compliance)
	pruneAccountHistory := func() {
		pruneAccountChanges(ctx, accountFolderSpace)
		pruneAccountItemHistory(ctx, accountFolderSpace)
	}
	// Pruning walks every account's history, so it runs in the background
	// instead of delaying startup by an amount that grows with mailbox size.
	s.background.Every(24*time.Hour, true, pruneAccountHistory)
	durableFolderSpace, err := service.NewDurableFolderSpace(ctx, s.store, accountFolderSpace)
	if err != nil {
		return startupError("initialize durable folder space", err)
	}
	s.cleanup.push(durableFolderSpace.Close)
	searchManager, err := searchindex.New(ctx, s.accountManager, durableFolderSpace, authz.New(ts), searchConfig(cfg))
	if err != nil {
		return startupError("initialize account search", err)
	}
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		return searchManager.Reconfigure(searchConfig(cfg))
	}, "search_enabled", "search_index_workers", "search_batch_size", "search_idle_close_seconds",
		"search_max_extracted_bytes", "search_query_max_results", "search_index_encrypted_accounts"); err != nil {
		return err
	}
	s.search = searchManager
	s.cleanup.push(func() {
		if err := searchManager.Close(); err != nil {
			log.Error("close account search", "error", err)
		}
	})
	s.folderCache = service.NewCachedFolderSpace(durableFolderSpace, folderCacheConfig(cfg))
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		s.folderCache.SetConfig(folderCacheConfig(cfg))
		return nil
	}, "folder_cache_enabled", "folder_cache_ttl_seconds", "folder_cache_max_entries", "folder_cache_max_bytes"); err != nil {
		return err
	}
	var folderSpace service.FolderSpace = s.folderCache
	automation, err := rules.NewEngine(ctx, s.store, folderSpace)
	if err != nil {
		return startupError("initialize folder automation", err)
	}
	s.automation = automation
	s.cleanup.push(func() { automation.Close() })
	automatedFolderSpace, err := rules.NewFolderSpace(folderSpace, automation)
	if err != nil {
		return startupError("initialize automated folder space", err)
	}
	s.folderSpace = automatedFolderSpace
	if err := s.startRetention(accountFolderSpace); err != nil {
		return err
	}
	if err := s.buildCalendarScheduling(automatedFolderSpace); err != nil {
		return err
	}
	if err := s.buildSpamClassifier(automatedFolderSpace); err != nil {
		return err
	}
	// MCP is always mounted; the HTTP service gate follows mcp_enabled.
	references, err := mcpserver.NewReferenceService(ctx, ts, 30*time.Minute)
	if err != nil {
		return startupError("initialize MCP references", err)
	}
	s.mux.Handle("/mcp", mcpserver.NewHandler(model.NewAPIKeyStore(ts), model.NewUserStore(ts), s.folderSpace, searchManager, references, audit.New(ts)))
	s.protocolControl.controllers.folderSpace = s.folderSpace
	s.protocolControl.controllers.search = searchManager
	s.protocolControl.controllers.mailIndex = mailindex.New(ts.Store())
	if s.accountManager != nil {
		s.protocolControl.controllers.mailIndex.SetSealer(s.accountManager)
	}
	s.sieveScripts = service.NewSieveRepository(s.folderSpace)
	return nil
}

// startRetention runs the retention job on the complete folder stack, with
// retention_enabled and retention_job_interval applied live.
func (s *server) startRetention(folders service.OwnFolderLister) error {
	job := service.NewRetentionJob(s.folderSpace, s.compliance, s.ts, audit.New(s.ts), s.met)
	job.Folders = folders
	job.SetPolicy(s.cfg.RetentionEnabled, s.cfg.RetentionJobIntervalDuration())
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		job.SetPolicy(cfg.RetentionEnabled, cfg.RetentionJobIntervalDuration())
		return nil
	}, "retention_enabled", "retention_job_interval"); err != nil {
		return err
	}
	s.retention = job
	s.background.Go(job.Run)
	return nil
}

func searchConfig(cfg *config.Config) searchindex.Config {
	return searchindex.Config{
		Enabled: cfg.SearchEnabled, Workers: cfg.SearchIndexWorkers, BatchSize: cfg.SearchBatchSize,
		IdleClose:         time.Duration(cfg.SearchIdleCloseSeconds) * time.Second,
		MaxExtractedBytes: cfg.SearchMaxExtractedBytes, QueryMaxResults: cfg.SearchQueryMaxResults,
		IndexEncryptedAccounts: cfg.SearchIndexEncryptedAccounts,
	}
}

func folderCacheConfig(cfg *config.Config) service.FolderCacheConfig {
	return service.FolderCacheConfig{
		Disabled:   !cfg.FolderCacheEnabled,
		TTL:        time.Duration(cfg.FolderCacheTTLSeconds) * time.Second,
		MaxEntries: cfg.FolderCacheMaxEntries,
		MaxBytes:   cfg.FolderCacheMaxBytes,
	}
}

func pruneAccountChanges(ctx context.Context, space *service.AccountFolderSpace) {
	result, pruneErr := space.PruneChanges(ctx, time.Now().UTC())
	if pruneErr != nil && ctx.Err() != nil {
		return // shutdown interrupted the background prune; it runs again next start
	} else if pruneErr != nil {
		log.Error("prune account change history", "error", pruneErr, "accounts_scanned", result.AccountsScanned, "accounts_skipped", result.AccountsSkipped, "changes_removed", result.ChangesRemoved)
	} else if result.ChangesRemoved > 0 {
		log.Info("account change history: pruned expired records", "accounts_scanned", result.AccountsScanned, "accounts_skipped", result.AccountsSkipped, "changes_removed", result.ChangesRemoved)
	}
}

func pruneAccountItemHistory(ctx context.Context, space *service.AccountFolderSpace) {
	result, pruneErr := space.PruneItemHistory(ctx, time.Now().UTC())
	if pruneErr != nil && ctx.Err() != nil {
		return // shutdown interrupted the background prune; it runs again next start
	} else if pruneErr != nil {
		log.Error("prune account item history", "error", pruneErr, "accounts_scanned", result.AccountsScanned, "accounts_skipped", result.AccountsSkipped, "versions_removed", result.VersionsRemoved)
	} else if result.VersionsRemoved > 0 {
		log.Info("account item history: pruned expired versions", "accounts_scanned", result.AccountsScanned, "accounts_skipped", result.AccountsSkipped, "versions_removed", result.VersionsRemoved)
	}
}
