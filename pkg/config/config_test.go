package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultListenAddr(t *testing.T) {
	t.Setenv("VEKSEL_LISTEN", "")
	t.Setenv("VEKSEL_PPROF_LISTEN", "")
	t.Setenv("VEKSEL_TRASH_RETENTION_DAYS", "")

	cfg := Default()
	if got, want := cfg.ListenAddr, "0.0.0.0:8472"; got != want {
		t.Fatalf("ListenAddr = %q, want %q", got, want)
	}
	if cfg.PprofListenAddr != "" {
		t.Fatalf("PprofListenAddr = %q, want disabled", cfg.PprofListenAddr)
	}
	if got, want := cfg.Port(), 8472; got != want {
		t.Fatalf("Port() = %d, want %d", got, want)
	}
	if got, want := cfg.TrashRetentionDays, 30; got != want {
		t.Fatalf("TrashRetentionDays = %d, want %d", got, want)
	}
	if got, want := cfg.QueueReceiptRetentionDays, 7; got != want {
		t.Fatalf("QueueReceiptRetentionDays = %d, want %d", got, want)
	}
	if cfg.QuotaWarningPercent != 80 || cfg.QuotaCriticalPercent != 95 {
		t.Fatalf("quota thresholds = %d/%d, want 80/95", cfg.QuotaWarningPercent, cfg.QuotaCriticalPercent)
	}
	if cfg.GreylistEnabled || cfg.GreylistMinimumDelaySeconds != 300 || cfg.GreylistRetryWindowMinutes != 240 || cfg.GreylistPendingLifetimeHours != 24 || cfg.GreylistPassLifetimeDays != 36 || cfg.GreylistIPv4PrefixBits != 24 || cfg.GreylistIPv6PrefixBits != 64 || cfg.GreylistMaxEntries != 1_000_000 {
		t.Fatalf("greylist defaults = enabled %t delay %d retry %d pending %d pass %d prefixes %d/%d max %d", cfg.GreylistEnabled, cfg.GreylistMinimumDelaySeconds, cfg.GreylistRetryWindowMinutes, cfg.GreylistPendingLifetimeHours, cfg.GreylistPassLifetimeDays, cfg.GreylistIPv4PrefixBits, cfg.GreylistIPv6PrefixBits, cfg.GreylistMaxEntries)
	}
	if !cfg.ImapRequireTLSAuth {
		t.Fatal("IMAP password authentication must require TLS by default")
	}
	if !cfg.Pop3RequireTLSAuth {
		t.Fatal("POP3 password authentication must require TLS by default")
	}
	if cfg.QuarantineRetentionDays != 30 || cfg.QuarantineMaxEntries != 1_000_000 || cfg.QuarantineMaxBytes != 100<<30 || cfg.QuarantineCleanupMinutes != 60 || cfg.QuarantineCleanupBatchSize != 10_000 {
		t.Fatalf("quarantine defaults = retention %d, entries %d, bytes %d, cleanup %d/%d", cfg.QuarantineRetentionDays, cfg.QuarantineMaxEntries, cfg.QuarantineMaxBytes, cfg.QuarantineCleanupMinutes, cfg.QuarantineCleanupBatchSize)
	}
	if cfg.QuarantineDigestEnabled || cfg.QuarantineDigestFrom != "Veksel <postmaster@localhost>" || cfg.QuarantineDigestPollMins != 5 || cfg.QuarantineDigestMaxEntries != 50 || cfg.QuarantineDigestMaxJobs != 100 || cfg.QuarantineDigestMaxRetries != 10 || cfg.QuarantineDigestRetrySecs != 300 || cfg.QuarantineDigestJobDays != 30 || cfg.QuarantineActionTTLHours != 168 {
		t.Fatalf("quarantine digest defaults = %+v", cfg)
	}
	if cfg.AlertEvaluationSeconds != 15 || cfg.AlertQueueWarningMinutes != 15 || cfg.AlertQueueCriticalMinutes != 60 || cfg.AlertWebhookWarningMinutes != 5 || cfg.AlertWebhookCriticalMinutes != 30 || cfg.AlertStorageWarningFreePercent != 15 || cfg.AlertStorageCriticalFreePercent != 5 || cfg.AlertCertWarningDays != 30 || cfg.AlertCertCriticalDays != 7 || !cfg.AlertNotificationsEnabled {
		t.Fatalf("alert defaults = evaluation %d, queue %d/%d, webhook %d/%d, storage %d/%d, certificate %d/%d, notifications %t", cfg.AlertEvaluationSeconds, cfg.AlertQueueWarningMinutes, cfg.AlertQueueCriticalMinutes, cfg.AlertWebhookWarningMinutes, cfg.AlertWebhookCriticalMinutes, cfg.AlertStorageWarningFreePercent, cfg.AlertStorageCriticalFreePercent, cfg.AlertCertWarningDays, cfg.AlertCertCriticalDays, cfg.AlertNotificationsEnabled)
	}
}

func TestEnvironmentDoesNotChangeConfiguration(t *testing.T) {
	t.Setenv("VEKSEL_PPROF_LISTEN", "127.0.0.1:6060")
	t.Setenv("VEKSEL_STORE_PATH", "./elsewhere")
	if got, want := Default().PprofListenAddr, ""; got != want {
		t.Fatalf("PprofListenAddr = %q, want %q", got, want)
	}
}

func TestDefaultAtDerivesInternalPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instance")
	if got, want := DefaultAt(root).StorePath, filepath.Join(root, "pebble"); got != want {
		t.Fatalf("StorePath = %q, want %q", got, want)
	}
}
