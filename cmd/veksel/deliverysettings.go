package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/attachment"
	"github.com/lkarlslund/veksel/pkg/batv"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/contentscan"
	"github.com/lkarlslund/veksel/pkg/dmarc"
	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/srs"
	"github.com/lkarlslund/veksel/pkg/virus"
)

// deliveryRuntime holds the outbound routing, content scanning, DMARC
// reporting, and retention state that managed configuration replaces live.
// Each value is swapped atomically: work in progress finishes on the value it
// started with, and subsequent work uses the new one.
type deliveryRuntime struct {
	outbound           atomic.Pointer[outboundRoutes]
	scanning           contentscan.Switch
	virusScanEnabled   atomic.Bool
	spam               spam.Switch
	attachments        attachment.Switch
	spamDNS            *spam.DNS           // shared blocklist cache and zone health
	spamIdentities     *spam.IdentityCache // hosted domains and local display names for phishing checks
	reputation         spam.Reputation     // sender reputation shared by every engine generation
	fuzzy              spam.Fuzzy          // local fuzzy and bulk body detection shared by every engine generation
	autoAllowlist      atomic.Bool         // KNOWN_CORRESPONDENT is applied
	dmarc              dmarcReporting
	traceRetentionDays atomic.Int64
	addressing         atomic.Pointer[addressingPolicy]
	srs                *srs.Codec  // nil until the installation secrets load
	batv               *batv.Codec // nil until the installation secrets load
	backscatter        atomic.Pointer[batv.Policy]
	spamtraps          atomic.Pointer[config.Spamtraps] // nil until applied
}

// outboundRoutes is one immutable snapshot of the global relay and the
// direct-MX fallback used when no domain route applies.
type outboundRoutes struct {
	relay    *queue.RelayAdapter // nil without a configured relay
	directMX bool
}

// buildOutboundRoutes creates the global relay client for cfg.
func (s *server) buildOutboundRoutes(cfg *config.Config) *outboundRoutes {
	routes := &outboundRoutes{directMX: cfg.SmtpDirectMXEnabled}
	if cfg.RelayEnabled() {
		routes.relay = s.relayClient(smtp.RelayConfig{
			Host: cfg.RelayHost, Port: cfg.RelayPort, ServerName: cfg.RelayServerName,
			Username: cfg.RelayUsername, Password: cfg.RelayPassword,
			TLSSkipVerify: cfg.RelayTLSkipVerify, RequireTLS: cfg.RelayRequireTLS,
		})
	}
	return routes
}

// relayClient builds a relay client for target with the shared MTA-STS,
// DANE, and TLS reporting services.
func (s *server) relayClient(target smtp.RelayConfig) *queue.RelayAdapter {
	target.MTASTS, target.DANE, target.TLSPolicyEvidence = s.mtaSTS, s.dane.service, queue.RecordTLSPolicy
	target.TLSReporter, target.TLSReportError = s.tlsReporter, tlsReportError
	return queue.NewRelayAdapter(smtp.NewRelayClient(&target))
}

// relays reports whether non-local recipients have a global route.
func (routes *outboundRoutes) relays() bool {
	return routes.relay != nil || routes.directMX
}

// smtpServerName returns the current managed SMTP server name, used as the
// outbound EHLO name, DSN reporting MTA, and report submitter candidate.
func (s *server) smtpServerName() string {
	if s.cfgService != nil {
		return s.cfgService.Current().Config.SmtpServerName
	}
	return s.cfg.SmtpServerName
}

// outboundClient builds a per-delivery client for a route or direct MX
// (empty host), announcing the current server name.
func (s *server) outboundClient(target smtp.RelayConfig) *queue.RelayAdapter {
	target.ServerName = s.smtpServerName()
	return s.relayClient(target)
}

// deliverOutbound sends msg through the current global relay, else direct
// MX. A delivery keeps the routes it started with.
func (s *server) deliverOutbound(ctx context.Context, msg *queue.Message) error {
	routes := s.delivery.outbound.Load()
	switch {
	case routes.relay != nil:
		queue.RecordDeliveryRoute(ctx, "global-relay")
		return s.relay(ctx, routes.relay, msg)
	case routes.directMX:
		queue.RecordDeliveryRoute(ctx, "direct-mx")
		return s.relay(ctx, s.outboundClient(smtp.RelayConfig{Port: 25}), msg)
	}
	queue.RecordDeliveryRoute(ctx, "unrouted")
	return fmt.Errorf("5.1.1 recipient is not local and no outbound relay is configured")
}

// dmarcReporting gates aggregate observation recording and holds the current
// report sender. SMTP listeners and the admin UI keep this one value while
// enablement, identity, and retention change underneath it.
type dmarcReporting struct {
	recorder      *dmarc.AggregateRecorder
	enabled       atomic.Bool
	sender        atomic.Pointer[dmarc.AggregateReporter]
	retentionDays atomic.Int64
}

// Record stores an inbound observation while aggregate reporting is enabled.
func (d *dmarcReporting) Record(ctx context.Context, observation dmarc.AggregateObservation) error {
	if !d.enabled.Load() || d.recorder == nil {
		return nil
	}
	return d.recorder.Record(ctx, observation)
}

// ProcessDay sends one completed day's reports with the current sender.
func (d *dmarcReporting) ProcessDay(ctx context.Context, day string) ([]dmarc.AggregateReportJob, error) {
	sender := d.sender.Load()
	if sender == nil {
		return nil, errors.New("DMARC aggregate report delivery is not running")
	}
	return sender.ProcessDay(ctx, day)
}

// Running reports whether reports are currently being sent.
func (d *dmarcReporting) Running() bool { return d.enabled.Load() && d.sender.Load() != nil }

// configureDMARCReporting builds the report sender for cfg and installs it
// with the enablement and retention settings, or returns an error and keeps
// the current ones. Without a hosted submitter domain observations are still
// retained but no reports are sent.
func (s *server) configureDMARCReporting(cfg *config.Config, submitterDomain string) error {
	var sender *dmarc.AggregateReporter
	if cfg.DmarcAggregateEnabled && submitterDomain != "" {
		contact := strings.TrimSpace(cfg.DmarcAggregateEmail)
		if contact == "" {
			contact = "postmaster@" + submitterDomain
		}
		var err error
		sender, err = dmarc.NewAggregateReporter(s.dmarcAggregates, dmarc.AggregateReporterOptions{
			Identity:        dmarc.AggregateReportIdentity{Organization: cfg.DmarcAggregateOrganization, Email: contact},
			SubmitterDomain: submitterDomain, Mailer: s.dmarcReportMailer(),
		})
		if err != nil {
			return err
		}
	}
	reporting := &s.delivery.dmarc
	reporting.sender.Store(sender)
	reporting.enabled.Store(cfg.DmarcAggregateEnabled)
	reporting.retentionDays.Store(int64(cfg.DmarcAggregateRetentionDays))
	return nil
}

// buildContentScanner assembles the configured malware and spam scanners. It
// returns no pipeline while virus scanning is disabled.
func (s *server) buildContentScanner(cfg *config.Config) (*contentscan.Pipeline, contentscan.Trainer, error) {
	if !cfg.VirusScanEnabled {
		return nil, nil, nil
	}
	var engines []contentscan.Engine
	var trainer contentscan.Trainer
	addEngine := func(label string, scanner contentscan.Scanner, timeoutSeconds int, maxBytes int64, policyValue string) error {
		policy, err := contentscan.FailurePolicyString(policyValue)
		if err != nil {
			return fmt.Errorf("%s content scanner: %w", label, err)
		}
		engines = append(engines, contentscan.Engine{Scanner: scanner, Timeout: time.Duration(timeoutSeconds) * time.Second, MaxInputBytes: maxBytes, FailurePolicy: policy})
		return nil
	}
	if cfg.BuiltinScannerEnabled {
		if err := addEngine("built-in", contentscan.NewMalwareAdapter(virus.NewBuiltinScanner()), cfg.BuiltinScannerTimeoutSeconds, cfg.BuiltinScannerMaxBytes, cfg.BuiltinScannerFailurePolicy); err != nil {
			return nil, nil, err
		}
	}
	if cfg.ClamdEnabled {
		if err := addEngine("ClamAV", contentscan.NewMalwareAdapter(virus.NewClamAVScanner(cfg.ClamdSocket)), cfg.ClamdTimeoutSeconds, cfg.ClamdMaxBytes, cfg.ClamdFailurePolicy); err != nil {
			return nil, nil, err
		}
	}
	if cfg.RspamdEnabled {
		rspamdScanner, err := contentscan.NewRspamdScanner(cfg.RspamdEndpoint, cfg.RspamdPassword, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("Rspamd content scanner: %w", err)
		}
		if err := addEngine("Rspamd", rspamdScanner, cfg.RspamdTimeoutSeconds, cfg.RspamdMaxBytes, cfg.RspamdFailurePolicy); err != nil {
			return nil, nil, err
		}
		trainer = rspamdScanner
	}
	pipeline, err := contentscan.NewObserved(metrics.NewContentScanObserver(s.met), engines...)
	if err != nil {
		return nil, nil, fmt.Errorf("content scanner pipeline: %w", err)
	}
	return pipeline, trainer, nil
}

// applyContentScanning rebuilds the scanner set for cfg and swaps it in for
// the next message, or returns an error and keeps the current set. Scanner
// reachability never blocks the change: ClamAV is probed in the background
// and an unreachable daemon is logged and surfaces in scanner status.
func (s *server) applyContentScanning(cfg *config.Config) error {
	pipeline, trainer, err := s.buildContentScanner(cfg)
	if err != nil {
		return err
	}
	s.delivery.scanning.Set(pipeline, trainer)
	s.delivery.virusScanEnabled.Store(cfg.VirusScanEnabled)
	if cfg.VirusScanEnabled && cfg.ClamdEnabled {
		socket := cfg.ClamdSocket
		s.spawn(func() {
			if _, pingErr := virus.NewClamAVScanner(socket).Ping(); pingErr != nil {
				log.Warn("content scanning: ClamAV is unreachable", "socket", socket, "error", pingErr)
			}
		})
	}
	return nil
}

func queueLimits(cfg *config.Config) queue.Limits {
	return queue.Limits{
		MaxSize:           cfg.QueueMaxSize,
		Workers:           cfg.QueueWorkers,
		MaxPerDestination: cfg.QueueMaxPerDestination,
		MaxAge:            time.Duration(cfg.QueueMaxAgeHours) * time.Hour,
		RetryInitial:      time.Duration(cfg.QueueRetryInitialSecs) * time.Second,
		RetryMax:          time.Duration(cfg.QueueRetryMaxSecs) * time.Second,
		ReceiptRetention:  time.Duration(cfg.QueueReceiptRetentionDays) * 24 * time.Hour,
	}
}

func greylistConfig(cfg *config.Config) greylist.Config {
	return greylist.Config{
		Enabled:         cfg.GreylistEnabled,
		MinimumDelay:    time.Duration(cfg.GreylistMinimumDelaySeconds) * time.Second,
		RetryWindow:     time.Duration(cfg.GreylistRetryWindowMinutes) * time.Minute,
		PendingLifetime: time.Duration(cfg.GreylistPendingLifetimeHours) * time.Hour,
		PassLifetime:    time.Duration(cfg.GreylistPassLifetimeDays) * 24 * time.Hour,
		IPv4PrefixBits:  cfg.GreylistIPv4PrefixBits, IPv6PrefixBits: cfg.GreylistIPv6PrefixBits,
		MaxEntries: uint64(cfg.GreylistMaxEntries), ScoreTriggered: cfg.GreylistTrigger == "score",
		AutoWhitelistPasses:   cfg.GreylistAutoWhitelistPasses,
		AutoWhitelistLifetime: time.Duration(cfg.GreylistAutoWhitelistDays) * 24 * time.Hour,
		SkipSPFPass:           cfg.GreylistSkipSPFPass, SPFPoolTriplets: cfg.GreylistSPFPoolTriplets,
	}
}

// deliverySettings lists the live appliers owned by the delivery, queue,
// greylisting, and content scanning runtime.
func (s *server) deliverySettings() []struct {
	keys  []string
	apply config.Applier
} {
	return []struct {
		keys  []string
		apply config.Applier
	}{
		{[]string{"queue_max_size", "queue_workers", "queue_max_per_destination", "queue_max_age_hours", "queue_retry_initial_seconds", "queue_retry_max_seconds", "queue_receipt_retention_days"}, func(cfg *config.Config) error {
			return s.mailQueue.Reconfigure(queueLimits(cfg))
		}},
		{[]string{"relay_host", "relay_port", "relay_username", "relay_password", "relay_server_name", "relay_tls_skip_verify", "relay_require_tls", "smtp_direct_mx_enabled"}, func(cfg *config.Config) error {
			s.delivery.outbound.Store(s.buildOutboundRoutes(cfg))
			return nil
		}},
		{[]string{"dane_enabled", "dane_resolvers"}, func(cfg *config.Config) error {
			if err := s.applyDANE(cfg); err != nil {
				return err
			}
			s.spawn(s.probeDANE)
			return nil
		}},
		{[]string{"greylist_enabled", "greylist_minimum_delay_seconds", "greylist_retry_window_minutes", "greylist_pending_lifetime_hours", "greylist_pass_lifetime_days", "greylist_ipv4_prefix_bits", "greylist_ipv6_prefix_bits", "greylist_max_entries", "greylist_trigger", "greylist_auto_whitelist_passes", "greylist_auto_whitelist_days", "greylist_skip_spf_pass", "greylist_spf_pool_triplets"}, func(cfg *config.Config) error {
			return s.greylisting.SetConfig(greylistConfig(cfg))
		}},
		{[]string{"message_trace_retention_days"}, func(cfg *config.Config) error {
			s.delivery.traceRetentionDays.Store(int64(cfg.MessageTraceRetentionDays))
			s.spawn(s.pruneMessageTrace)
			return nil
		}},
		{[]string{"dmarc_aggregate_enabled", "dmarc_aggregate_organization", "dmarc_aggregate_email", "dmarc_aggregate_retention_days"}, func(cfg *config.Config) error {
			if err := s.configureDMARCReporting(cfg, s.systemMailDomain()); err != nil {
				return err
			}
			s.spawn(s.cleanupDMARCAggregates)
			return nil
		}},
		{[]string{"virus_scan_enabled", "builtin_scanner_enabled", "builtin_scanner_timeout_seconds", "builtin_scanner_max_bytes", "builtin_scanner_failure_policy", "clamd_enabled", "clamd_socket", "clamd_timeout_seconds", "clamd_max_bytes", "clamd_failure_policy", "rspamd_enabled", "rspamd_endpoint", "rspamd_password", "rspamd_timeout_seconds", "rspamd_max_bytes", "rspamd_failure_policy"}, s.applyContentScanning},
		{spamSettingKeys, s.applySpamFiltering},
		{outboundProtectionKeys, s.applyOutboundProtection},
		{[]string{"attachment_policy", "attachment_blocked_extensions", "attachment_check_submissions"}, func(cfg *config.Config) error {
			policy, err := attachment.NewPolicy(cfg.AttachmentSettings())
			if err != nil {
				return err
			}
			s.delivery.attachments.Set(policy)
			return nil
		}},
		{[]string{"recipient_delimiter", "srs_enabled", "srs_domain"}, func(cfg *config.Config) error {
			s.delivery.addressing.Store(addressingFromConfig(cfg))
			return nil
		}},
		{[]string{"batv_enabled", "batv_grace_period_hours"}, s.applyBATV},
		{spamtrapKeys, s.applySpamtraps},
		{[]string{"smtp_max_message_size"}, func(cfg *config.Config) error {
			// Running SMTP servers adopt the new limit through the same
			// reconfigure path as every other SMTP session setting.
			return s.protocolControl.controllers.reconfigure(cfg, &smtpProtocol)
		}},
	}
}

// registerDeliverySettings makes the delivery runtime's settings live. After
// an applier succeeds, its settings are also adopted into the shared runtime
// configuration so readers of it, and later listener restarts, see them.
func (s *server) registerDeliverySettings() error {
	if s.cfgService == nil {
		return nil
	}
	for _, setting := range s.deliverySettings() {
		keys, apply := setting.keys, setting.apply
		err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
			if err := apply(cfg); err != nil {
				return err
			}
			adoptSettings(s.cfg, cfg, keys)
			return nil
		}, keys...)
		if err != nil {
			return startupError("register delivery settings", err)
		}
	}
	return nil
}

// adoptSettings copies the settings named by keys from src into dst.
func adoptSettings(dst, src *config.Config, keys []string) {
	target, source := reflect.ValueOf(dst).Elem(), reflect.ValueOf(src).Elem()
	for index := range target.NumField() {
		key, _, _ := strings.Cut(target.Type().Field(index).Tag.Get("toml"), ",")
		if slices.Contains(keys, key) {
			target.Field(index).Set(source.Field(index))
		}
	}
}
