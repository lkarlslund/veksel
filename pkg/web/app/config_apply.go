package app

import (
	"errors"
	"slices"
	"time"

	"github.com/lkarlslund/veksel/pkg/accountverify"
	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/config"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

// registerLiveSettings installs this handler's live appliers in the managed
// configuration registry; every other runtime owner registers its own.
func (h *Handler) registerLiveSettings() error {
	unavailable := func(component string) error { return errors.New(component + " is unavailable") }
	appliers := []struct {
		keys  []string
		apply config.Applier
	}{
		{[]string{"default_account_engine"}, func(cfg *config.Config) error {
			if h.accountManager == nil {
				return unavailable("account storage manager")
			}
			return h.accountManager.SetDefaultEngine(cfg.DefaultAccountEngine)
		}},
		{[]string{"account_retained_cleanup_days"}, func(cfg *config.Config) error {
			if h.accountManager == nil {
				return unavailable("account storage manager")
			}
			h.accountManager.SetRetainedCleanupDays(cfg.AccountRetainedCleanupDays)
			return nil
		}},
		{[]string{"account_verification_enabled", "account_verification_interval_hours", "account_verification_workers"}, func(cfg *config.Config) error {
			if h.accountVerification == nil {
				return unavailable("account verification scheduler")
			}
			if err := h.accountVerification.SetPolicy(accountverify.Policy{
				Enabled:  cfg.AccountVerificationEnabled,
				Interval: time.Duration(cfg.AccountVerificationIntervalHrs) * time.Hour,
				Workers:  cfg.AccountVerificationWorkers,
			}); err != nil {
				return err
			}
			if h.cfg != nil {
				h.cfg.AccountVerificationEnabled = cfg.AccountVerificationEnabled
				h.cfg.AccountVerificationIntervalHrs = cfg.AccountVerificationIntervalHrs
				h.cfg.AccountVerificationWorkers = cfg.AccountVerificationWorkers
			}
			return nil
		}},
		{[]string{"calendar_subscription_allow_private_networks"}, func(cfg *config.Config) error {
			h.calendarFeeds.SetAllowPrivateNetworks(cfg.CalendarSubscriptionAllowPrivateNetworks)
			return nil
		}},
		{[]string{"legal_hold_domain_admins", "retention_min_days"}, func(cfg *config.Config) error {
			h.compliancePolicy.Store(compliancePolicyFromConfig(cfg))
			return nil
		}},
		{[]string{"trash_retention_days"}, func(cfg *config.Config) error {
			h.workspace.SetTrashRetentionDays(cfg.TrashRetentionDays)
			return nil
		}},
		{[]string{"change_history_retention_days", "change_history_max_entries"}, func(cfg *config.Config) error {
			h.setChangeRetention(cfg.ChangeHistoryRetentionDays, cfg.ChangeHistoryMaxEntries)
			return nil
		}},
		{[]string{"quota_warning_percent", "quota_critical_percent"}, func(cfg *config.Config) error {
			if h.cfg == nil {
				return unavailable("runtime configuration")
			}
			h.cfg.QuotaWarningPercent, h.cfg.QuotaCriticalPercent = cfg.QuotaWarningPercent, cfg.QuotaCriticalPercent
			return nil
		}},
		{[]string{"alert_evaluation_seconds", "alert_queue_warning_minutes", "alert_queue_critical_minutes", "alert_webhook_warning_minutes", "alert_webhook_critical_minutes", "alert_storage_warning_free_percent", "alert_storage_critical_free_percent", "alert_certificate_warning_days", "alert_certificate_critical_days", "alert_notifications_enabled"}, func(cfg *config.Config) error {
			if h.cfg == nil {
				return unavailable("runtime configuration")
			}
			h.cfg.AlertEvaluationSeconds = cfg.AlertEvaluationSeconds
			h.cfg.AlertQueueWarningMinutes = cfg.AlertQueueWarningMinutes
			h.cfg.AlertQueueCriticalMinutes = cfg.AlertQueueCriticalMinutes
			h.cfg.AlertWebhookWarningMinutes = cfg.AlertWebhookWarningMinutes
			h.cfg.AlertWebhookCriticalMinutes = cfg.AlertWebhookCriticalMinutes
			h.cfg.AlertStorageWarningFreePercent = cfg.AlertStorageWarningFreePercent
			h.cfg.AlertStorageCriticalFreePercent = cfg.AlertStorageCriticalFreePercent
			h.cfg.AlertCertWarningDays = cfg.AlertCertWarningDays
			h.cfg.AlertCertCriticalDays = cfg.AlertCertCriticalDays
			h.cfg.AlertNotificationsEnabled = cfg.AlertNotificationsEnabled
			h.applyAlertDelivery(cfg)
			return nil
		}},
		{[]string{"alert_email_recipients", "alert_notify_url", "alert_notify_token", "alert_min_interval_minutes", "alert_digest", "quota_warning_emails_enabled"}, func(cfg *config.Config) error {
			if h.cfg == nil {
				return unavailable("runtime configuration")
			}
			h.cfg.AlertEmailRecipients = slices.Clone(cfg.AlertEmailRecipients)
			h.cfg.AlertNotifyURL, h.cfg.AlertNotifyToken = cfg.AlertNotifyURL, cfg.AlertNotifyToken
			h.cfg.AlertMinIntervalMinutes, h.cfg.AlertDigest = cfg.AlertMinIntervalMinutes, cfg.AlertDigest
			h.cfg.QuotaWarningEmailsEnabled = cfg.QuotaWarningEmailsEnabled
			h.applyAlertDelivery(cfg)
			return nil
		}},
		{[]string{"log_console_level"}, func(cfg *config.Config) error {
			logpkg.SetLevel(logpkg.ParseLevel(cfg.LogConsoleLevel))
			return nil
		}},
		{[]string{"log_file_level"}, func(cfg *config.Config) error {
			logpkg.SetFileLevel(logpkg.ParseLevel(cfg.LogFileLevel))
			return nil
		}},
		{[]string{"log_file_retention_days", "log_file_max_files"}, func(cfg *config.Config) error {
			logpkg.SetFileRetention(cfg.LogFileRetentionDays, cfg.LogFileMaxFiles)
			return nil
		}},
		{[]string{"log_format"}, func(cfg *config.Config) error {
			logpkg.SetFormat(cfg.LogFormat)
			return nil
		}},
		{[]string{"log_module_levels"}, func(cfg *config.Config) error {
			return logpkg.ConfigureModules(cfg.LogModuleLevels)
		}},
		{[]string{"web_two_factor_required"}, func(cfg *config.Config) error {
			h.setTwoFactorPolicy(cfg.WebTwoFactorRequired)
			return nil
		}},
		{[]string{"user_aliases_enabled", "user_aliases_max_per_user", "user_aliases_domains"}, func(cfg *config.Config) error {
			h.userAliases.Store(userAliasPolicyFromConfig(cfg))
			return nil
		}},
		{[]string{"http_trusted_proxies", "http_forwarded_header"}, func(cfg *config.Config) error {
			if h.trustedProxies == nil {
				return unavailable("trusted proxy resolver")
			}
			if err := h.trustedProxies.SetHeader(cfg.HTTPForwardedHeader); err != nil {
				return err
			}
			return h.trustedProxies.Set(cfg.HTTPTrustedProxies)
		}},
	}
	for _, a := range appliers {
		if err := h.configService.RegisterApplier(a.apply, a.keys...); err != nil {
			return err
		}
	}
	return nil
}

// applyAlertDelivery hands the alert channel policy to the notifier.
func (h *Handler) applyAlertDelivery(cfg *config.Config) {
	if h.alertNotifier != nil {
		h.alertNotifier.SetPolicy(alertnotify.PolicyFromConfig(cfg))
	}
}

// applyManagedConfiguration runs the registered live appliers for the
// requested keys; settings without an applier stay visibly pending.
func (h *Handler) applyManagedConfiguration(snapshot config.Snapshot, requested map[string]any) {
	if h.configService != nil {
		h.configService.Apply(snapshot, requested)
	}
}
