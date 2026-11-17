// Package config holds the application configuration.
package config

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/attachment"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/sendguard"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// Config holds the runtime configuration for Veksel.
type Config struct {
	HTTPListeners []HTTPListener `toml:"http_listeners" json:"http_listeners"`
	// ListenAddr is the HTTP listen address (e.g. "0.0.0.0:8472").
	ListenAddr       string `toml:"listen_addr"`
	HTTPSEnabled     bool   `toml:"https_enabled"`
	HTTPSListen      string `toml:"https_listen"`
	HTTPSCertificate string `toml:"https_certificate"`
	// HTTPTrustedProxies lists the reverse proxies (IP addresses or CIDR
	// prefixes) whose X-Forwarded-For, X-Forwarded-Proto and
	// X-Forwarded-Host headers are honoured. Empty trusts nobody.
	HTTPTrustedProxies []string `toml:"http_trusted_proxies"`
	// HTTPForwardedHeader names the one forwarding header family trusted
	// proxies set: "x-forwarded" (X-Forwarded-For/-Proto/-Host, X-Real-IP)
	// or "forwarded" (RFC 7239). The other family is ignored, because a
	// proxy passes through headers of the family it does not own.
	HTTPForwardedHeader string `toml:"http_forwarded_header"`
	// WebTwoFactorRequired selects which accounts must present a second
	// factor at web sign-in: "off", "administrators" or "all".
	WebTwoFactorRequired string `toml:"web_two_factor_required"`
	// TwoFactorRequiresAppPasswords makes accounts with a second factor use
	// application passwords on mail and groupware protocols, where no second
	// factor can be asked for; their primary password then signs in to the
	// web only.
	TwoFactorRequiresAppPasswords bool `toml:"two_factor_requires_app_passwords"`
	// PprofListenAddr is the optional, separate HTTP listen address for Go
	// runtime profiles. An empty value disables profiling.
	PprofListenAddr string `toml:"pprof_listen"`
	// MetricsToken is the bearer token Prometheus presents to scrape
	// /metrics. An empty value disables the unauthenticated scrape endpoint;
	// administrators still read metrics through the authenticated APIs.
	MetricsToken string `toml:"metrics_token"`
	// DataDir is the root directory for persistent data.
	DataDir string `toml:"-"`
	// StoreBackend selects the system metadata backend ("pebble" or "badger").
	StoreBackend store.Backend `toml:"system_engine"`
	// DefaultAccountEngine selects the initial engine for newly discovered or
	// created user account directories.
	DefaultAccountEngine store.Backend `toml:"default_account_engine"`
	// AccountStorageRoots contains named placements in "id=path" form.
	AccountStorageRoots []string `toml:"account_storage_roots"`
	PrimaryAccountRoot  string   `toml:"primary_account_root"`
	// StorePath optionally separates the database path from DataDir. DataDir
	// continues to own attachments and other non-KV data.
	StorePath string `toml:"-"`
	// AdminUser is the initial admin username.
	AdminUser string `toml:"-"`
	// AdminPassword is the initial admin password.
	AdminPassword string `toml:"-"`

	// SMTP server settings.
	SmtpEnabled                   bool   `toml:"smtp_enabled"`
	SmtpListen                    string `toml:"smtp_listen"` // e.g. ":25"
	SmtpSubmissionEnabled         bool   `toml:"smtp_submission_enabled"`
	SmtpSubmissionListen          string `toml:"smtp_submission_listen"` // e.g. ":587"
	SmtpImplicitTLSEnabled        bool   `toml:"smtp_implicit_tls_enabled"`
	SmtpTLSListen                 string `toml:"smtp_tls_listen"` // e.g. ":465" (implicit TLS)
	SmtpTlsCert                   string `toml:"-"`               // replaced by certificate assignment
	SmtpTlsKey                    string `toml:"-"`               // replaced by certificate assignment
	SmtpCertificate               string `toml:"smtp_certificate"`
	SmtpAuthMechanisms            string `toml:"smtp_auth_mechanisms"`
	SmtpMaxRecipients             int    `toml:"smtp_max_recipients"`
	SmtpMaxMessageSize            int64  `toml:"smtp_max_message_size"`
	SmtpMaxReceivedHeaders        int    `toml:"smtp_max_received_headers"`
	SmtpSubmissionReceivedPrivacy bool   `toml:"smtp_submission_received_privacy"`
	SmtpServerName                string `toml:"smtp_server_name"`
	SmtpPublicAddress             string `toml:"smtp_public_address"` // egress IP for reverse-DNS checks; empty = unknown
	SmtpDirectMXEnabled           bool   `toml:"smtp_direct_mx_enabled"`
	QueueMaxSize                  int    `toml:"queue_max_size"`
	QueueWorkers                  int    `toml:"queue_workers"`
	QueueMaxPerDestination        int    `toml:"queue_max_per_destination"`
	QueueMaxAgeHours              int    `toml:"queue_max_age_hours"`
	QueueRetryInitialSecs         int    `toml:"queue_retry_initial_seconds"`
	QueueRetryMaxSecs             int    `toml:"queue_retry_max_seconds"`
	QueueReceiptRetentionDays     int    `toml:"queue_receipt_retention_days"`
	MessageTraceRetentionDays     int    `toml:"message_trace_retention_days"`

	// Durable inbound SMTP greylisting settings. These are intentionally
	// ordinary managed configuration rather than environment overrides.
	GreylistEnabled              bool `toml:"greylist_enabled"`
	GreylistMinimumDelaySeconds  int  `toml:"greylist_minimum_delay_seconds"`
	GreylistRetryWindowMinutes   int  `toml:"greylist_retry_window_minutes"`
	GreylistPendingLifetimeHours int  `toml:"greylist_pending_lifetime_hours"`
	GreylistPassLifetimeDays     int  `toml:"greylist_pass_lifetime_days"`
	GreylistIPv4PrefixBits       int  `toml:"greylist_ipv4_prefix_bits"`
	GreylistIPv6PrefixBits       int  `toml:"greylist_ipv6_prefix_bits"`
	GreylistMaxEntries           int  `toml:"greylist_max_entries"`
	// GreylistTrigger is "always" (every unfamiliar triplet at RCPT) or
	// "score" (only messages reaching antispam_greylist_threshold).
	GreylistTrigger string `toml:"greylist_trigger"`
	// GreylistAutoWhitelistPasses whitelists a client network for every
	// sender after this many greylisting passes within the pass lifetime,
	// for GreylistAutoWhitelistDays after its latest message; 0 disables.
	GreylistAutoWhitelistPasses int `toml:"greylist_auto_whitelist_passes"`
	GreylistAutoWhitelistDays   int `toml:"greylist_auto_whitelist_days"`
	// GreylistSkipSPFPass skips greylisting when SPF passes for the envelope
	// sender's domain; GreylistSPFPoolTriplets instead keys the triplet on
	// that domain so retries from a provider's sending pool match.
	GreylistSkipSPFPass     bool `toml:"greylist_skip_spf_pass"`
	GreylistSPFPoolTriplets bool `toml:"greylist_spf_pool_triplets"`

	// IMAP server settings.
	ImapEnabled        bool   `toml:"imap_enabled"`
	ImapListen         string `toml:"imap_listen"`
	ImapTLSEnabled     bool   `toml:"imap_tls_enabled"`
	ImapTlsListen      string `toml:"imap_tls_listen"`
	ImapTlsCert        string `toml:"-"`
	ImapTlsKey         string `toml:"-"`
	ImapCertificate    string `toml:"imap_certificate"`
	ImapServerName     string `toml:"imap_server_name"`
	ImapRequireTLSAuth bool   `toml:"imap_require_tls_auth"`
	ImapMaxLiteralSize int64  `toml:"imap_max_literal_size"`

	// POP3 server settings.
	Pop3Enabled        bool   `toml:"pop3_enabled"`
	Pop3Listen         string `toml:"pop3_listen"`
	Pop3TLSEnabled     bool   `toml:"pop3_tls_enabled"`
	Pop3TlsListen      string `toml:"pop3_tls_listen"`
	Pop3TlsCert        string `toml:"-"`
	Pop3TlsKey         string `toml:"-"`
	Pop3Certificate    string `toml:"pop3_certificate"`
	Pop3ServerName     string `toml:"pop3_server_name"`
	Pop3RequireTLSAuth bool   `toml:"pop3_require_tls_auth"`

	// ManageSieve server settings (RFC 5804).
	ManageSieveEnabled        bool   `toml:"managesieve_enabled"`
	ManageSieveListen         string `toml:"managesieve_listen"`
	ManageSieveTLSEnabled     bool   `toml:"managesieve_tls_enabled"`
	ManageSieveTLSListen      string `toml:"managesieve_tls_listen"`
	ManageSieveCertificate    string `toml:"managesieve_certificate"`
	ManageSieveRequireTLSAuth bool   `toml:"managesieve_require_tls_auth"`

	// CORS settings.

	// Logging settings.
	LogDir               string            `toml:"-"`
	LogConsoleLevel      string            `toml:"log_console_level"`
	LogFileLevel         string            `toml:"log_file_level"`
	LogFormat            string            `toml:"log_format"`
	LogFileRetentionDays int               `toml:"log_file_retention_days"`
	LogFileMaxFiles      int               `toml:"log_file_max_files"`
	LogModuleLevels      map[string]string `toml:"log_module_levels"`

	// WebDAV file storage settings.
	DavEnabled         bool  `toml:"dav_enabled"`
	JmapEnabled        bool  `toml:"jmap_enabled"`
	MCPEnabled         bool  `toml:"mcp_enabled"`
	EwsEnabled         bool  `toml:"ews_enabled"`
	EasEnabled         bool  `toml:"eas_enabled"`
	WebdavMaxFileSize  int64 `toml:"webdav_max_file_size"`
	TrashRetentionDays int   `toml:"trash_retention_days"`
	// Compliance: the retention job applies retention policies every
	// RetentionJobInterval; RetentionMinDays is the shortest delete age a
	// domain administrator may set; LegalHoldDomainAdmins lets domain
	// administrators place legal holds within their domains.
	RetentionEnabled           bool   `toml:"retention_enabled"`
	RetentionJobInterval       string `toml:"retention_job_interval"`
	RetentionMinDays           int    `toml:"retention_min_days"`
	LegalHoldDomainAdmins      bool   `toml:"legal_hold_domain_admins"`
	ChangeHistoryRetentionDays int    `toml:"change_history_retention_days"`
	ChangeHistoryMaxEntries    int    `toml:"change_history_max_entries"`
	AccountIdleCloseSeconds    int    `toml:"account_idle_close_seconds"`
	AccountRetainedCleanupDays int    `toml:"account_retained_cleanup_days"`
	// StorageEncryptionDefault encrypts newly created accounts at rest.
	// Existing accounts change only through an explicit conversion.
	StorageEncryptionDefault        bool `toml:"storage_encryption_default"`
	AccountVerificationEnabled      bool `toml:"account_verification_enabled"`
	AccountVerificationIntervalHrs  int  `toml:"account_verification_interval_hours"`
	AccountVerificationWorkers      int  `toml:"account_verification_workers"`
	QuotaWarningPercent             int  `toml:"quota_warning_percent"`
	QuotaCriticalPercent            int  `toml:"quota_critical_percent"`
	AlertEvaluationSeconds          int  `toml:"alert_evaluation_seconds"`
	AlertQueueWarningMinutes        int  `toml:"alert_queue_warning_minutes"`
	AlertQueueCriticalMinutes       int  `toml:"alert_queue_critical_minutes"`
	AlertWebhookWarningMinutes      int  `toml:"alert_webhook_warning_minutes"`
	AlertWebhookCriticalMinutes     int  `toml:"alert_webhook_critical_minutes"`
	AlertStorageWarningFreePercent  int  `toml:"alert_storage_warning_free_percent"`
	AlertStorageCriticalFreePercent int  `toml:"alert_storage_critical_free_percent"`
	AlertCertWarningDays            int  `toml:"alert_certificate_warning_days"`
	AlertCertCriticalDays           int  `toml:"alert_certificate_critical_days"`
	AlertNotificationsEnabled       bool `toml:"alert_notifications_enabled"`
	// Scheduled backups. BackupDirectory is relative to the data directory
	// unless absolute; see BackupDirectoryPath.
	BackupSchedule          string   `toml:"backup_schedule"`
	BackupDirectory         string   `toml:"backup_directory"`
	BackupAgeRecipients     []string `toml:"backup_age_recipients"`
	BackupRetentionDaily    int      `toml:"backup_retention_daily"`
	BackupRetentionWeekly   int      `toml:"backup_retention_weekly"`
	FolderCacheEnabled      bool     `toml:"folder_cache_enabled"`
	FolderCacheTTLSeconds   int      `toml:"folder_cache_ttl_seconds"`
	FolderCacheMaxEntries   int      `toml:"folder_cache_max_entries"`
	FolderCacheMaxBytes     int64    `toml:"folder_cache_max_bytes"`
	SearchEnabled           bool     `toml:"search_enabled"`
	SearchIndexWorkers      int      `toml:"search_index_workers"`
	SearchBatchSize         int      `toml:"search_batch_size"`
	SearchIdleCloseSeconds  int      `toml:"search_idle_close_seconds"`
	SearchMaxExtractedBytes int64    `toml:"search_max_extracted_bytes"`
	SearchQueryMaxResults   int      `toml:"search_query_max_results"`
	// SearchIndexEncryptedAccounts keeps an on-disk full-text index for
	// accounts encrypted at rest. The index stores plaintext terms.
	SearchIndexEncryptedAccounts bool `toml:"search_index_encrypted_accounts"`

	// Alert delivery channels. AlertEmailRecipients receive alert mail;
	// AlertNotifyURL receives a generic JSON push (ntfy/Gotify-style) with
	// an optional bearer AlertNotifyToken.
	AlertEmailRecipients      []string `toml:"alert_email_recipients"`
	AlertNotifyURL            string   `toml:"alert_notify_url"`
	AlertNotifyToken          string   `toml:"alert_notify_token"`
	AlertMinIntervalMinutes   int      `toml:"alert_min_interval_minutes"`
	AlertDigest               string   `toml:"alert_digest"`
	QuotaWarningEmailsEnabled bool     `toml:"quota_warning_emails_enabled"`

	// Virus scanning settings.
	VirusScanEnabled             bool   `toml:"virus_scan_enabled"`
	BuiltinScannerEnabled        bool   `toml:"builtin_scanner_enabled"`
	BuiltinScannerTimeoutSeconds int    `toml:"builtin_scanner_timeout_seconds"`
	BuiltinScannerMaxBytes       int64  `toml:"builtin_scanner_max_bytes"`
	BuiltinScannerFailurePolicy  string `toml:"builtin_scanner_failure_policy"`
	ClamdEnabled                 bool   `toml:"clamd_enabled"`
	ClamdSocket                  string `toml:"clamd_socket"`
	ClamdTimeoutSeconds          int    `toml:"clamd_timeout_seconds"`
	ClamdMaxBytes                int64  `toml:"clamd_max_bytes"`
	ClamdFailurePolicy           string `toml:"clamd_failure_policy"`
	RspamdEnabled                bool   `toml:"rspamd_enabled"`
	RspamdEndpoint               string `toml:"rspamd_endpoint"`
	RspamdPassword               string `toml:"rspamd_password"`
	RspamdTimeoutSeconds         int    `toml:"rspamd_timeout_seconds"`
	RspamdMaxBytes               int64  `toml:"rspamd_max_bytes"`
	RspamdFailurePolicy          string `toml:"rspamd_failure_policy"`
	QuarantineRetentionDays      int    `toml:"quarantine_retention_days"`
	QuarantineMaxEntries         int64  `toml:"quarantine_max_entries"`
	QuarantineMaxBytes           int64  `toml:"quarantine_max_bytes"`
	QuarantineCleanupMinutes     int    `toml:"quarantine_cleanup_minutes"`
	QuarantineCleanupBatchSize   int    `toml:"quarantine_cleanup_batch_size"`
	QuarantineDigestEnabled      bool   `toml:"quarantine_digest_enabled"`
	QuarantineDigestBaseURL      string `toml:"quarantine_digest_base_url"`
	QuarantineDigestFrom         string `toml:"quarantine_digest_from"`
	QuarantineDigestPollMins     int    `toml:"quarantine_digest_poll_minutes"`
	QuarantineDigestMaxEntries   int    `toml:"quarantine_digest_max_entries"`
	QuarantineDigestMaxJobs      int    `toml:"quarantine_digest_max_jobs_per_run"`
	QuarantineDigestMaxRetries   int    `toml:"quarantine_digest_max_retries"`
	QuarantineDigestRetrySecs    int    `toml:"quarantine_digest_retry_seconds"`
	QuarantineDigestJobDays      int    `toml:"quarantine_digest_job_retention_days"`
	QuarantineActionTTLHours     int    `toml:"quarantine_action_ttl_hours"`

	// Built-in spam scoring of unauthenticated inbound mail. Thresholds
	// are total scores; zero greylist or reject thresholds disable those
	// actions. Symbol scores are SYMBOL=score overrides. Zones are DNS
	// blocklists, optionally followed by CODE=SYMBOL:SCORE rules. An empty
	// resolver uses the system resolver.
	AntispamEnabled           bool     `toml:"antispam_enabled"`
	AntispamJunkThreshold     float64  `toml:"antispam_junk_threshold"`
	AntispamGreylistThreshold float64  `toml:"antispam_greylist_threshold"`
	AntispamRejectThreshold   float64  `toml:"antispam_reject_threshold"`
	AntispamSymbolScores      []string `toml:"antispam_symbol_scores"`
	AntispamDNSBLZones        []string `toml:"antispam_dnsbl_zones"`
	AntispamRHSBLZones        []string `toml:"antispam_rhsbl_zones"`
	AntispamURIBLZones        []string `toml:"antispam_uribl_zones"`
	AntispamDNSResolver       string   `toml:"antispam_dns_resolver"`
	AntispamTrustedNetworks   []string `toml:"antispam_trusted_networks"`
	// Phishing checks: brand names or domains protected besides the hosted
	// domains, and link hosts scored as URL shorteners.
	AntispamProtectedBrands []string `toml:"antispam_protected_brands"`
	AntispamURLShorteners   []string `toml:"antispam_url_shorteners"`

	// Attachment inspection. AttachmentPolicy is the hard action for
	// dangerous executables: off, score (symbols only), quarantine, or
	// reject. Blocked extensions are the dangerous list. Submissions are
	// inspected only when AttachmentCheckSubmissions is set.
	AttachmentPolicy            string   `toml:"attachment_policy"`
	AttachmentBlockedExtensions []string `toml:"attachment_blocked_extensions"`
	AttachmentCheckSubmissions  bool     `toml:"attachment_check_submissions"`

	// Outbound protection. OutboundRateLimits are the default per-account
	// sending limits in name=value form (messages_per_hour,
	// recipients_per_hour, recipients_per_day; zero or absent is unlimited).
	// An account whose compromise score reaches OutboundCompromiseThreshold
	// (zero disables detection) has its outbound mail held for review when
	// OutboundHoldEnabled is set.
	OutboundRateLimits          []string `toml:"outbound_rate_limits"`
	OutboundCompromiseThreshold float64  `toml:"outbound_compromise_threshold"`
	OutboundHoldEnabled         bool     `toml:"outbound_hold_enabled"`

	// Built-in statistical (Bayesian) classifier. Each account's model
	// trains from moves into and out of Junk and scores once it has learned
	// min_learns spam and ham messages. Auto-learning trains from deliveries
	// at confident score extremes; the shared model learns from every
	// user's explicit actions and may affect transaction-level actions.
	AntispamBayesEnabled   bool `toml:"antispam_bayes_enabled"`
	AntispamBayesMinLearns int  `toml:"antispam_bayes_min_learns"`
	AntispamBayesAutolearn bool `toml:"antispam_bayes_autolearn"`
	AntispamBayesGlobal    bool `toml:"antispam_bayes_global"`

	// Sender reputation and correspondent allow-listing. Reputation tracks
	// decayed outcomes per authenticated sending domain and sending network
	// and scores a sender once it has min_samples of them. The auto
	// allow-list lowers the score of authenticated mail from addresses the
	// recipient has written to.
	AntispamAutoAllowlist        bool `toml:"antispam_auto_allowlist"`
	AntispamReputation           bool `toml:"antispam_reputation"`
	AntispamReputationMinSamples int  `toml:"antispam_reputation_min_samples"`

	// Local fuzzy and bulk body detection. Fuzzy matching compares a body
	// signature against those of mail users moved to Junk and of high-scoring
	// spam; the threshold is the similarity percent that counts as a match.
	// Bulk detection flags a near-identical body from more than
	// antispam_bulk_threshold unrelated senders within an hour.
	AntispamFuzzy          bool `toml:"antispam_fuzzy"`
	AntispamFuzzyThreshold int  `toml:"antispam_fuzzy_threshold"`
	AntispamBulkThreshold  int  `toml:"antispam_bulk_threshold"`

	// Spamtraps are addresses no legitimate sender knows: exact addresses
	// or local parts that apply on every hosted domain. Unauthenticated mail
	// to one is accepted but never delivered; it trains reputation and the
	// fuzzy signatures as spam and strikes the sending IP.
	AntispamSpamtraps []string `toml:"antispam_spamtraps"`

	// ARC (RFC 8617). ArcVerify validates inbound ARC chains and reports
	// arc= in Authentication-Results; a valid chain whose newest sealer is
	// in ArcTrustedSealers and recorded dmarc=pass overrides a DMARC
	// failure. ArcSealForwards adds an ARC set to forwarded and redirected
	// mail, signed with the forwarding domain's active DKIM key.
	ArcVerify         bool     `toml:"arc_verify"`
	ArcSealForwards   bool     `toml:"arc_seal_forwards"`
	ArcTrustedSealers []string `toml:"arc_trusted_sealers"`

	// Attachment storage settings.
	AttachmentDir string `toml:"-"`

	// VRFY and EXPN settings.
	// WARNING: Enabling these commands allows user and mailing-list enumeration.
	// They are disabled by default for security reasons.
	SmtpVrfyEnabled bool `toml:"smtp_vrfy_enabled"`
	SmtpExpnEnabled bool `toml:"smtp_expn_enabled"`

	// HELO policy settings.
	HeloPolicy string `toml:"helo_policy"`

	// Connection-stage screening of the inbound SMTP listener: the greeting
	// delay of the early-talker test (0 disables), the action for early
	// talkers (off, score, reject), the protocol violations that close a
	// session (0 never closes), the unknown recipients after which RCPT
	// replies are tarpitted (0 disables), and forward-confirmed reverse DNS
	// scoring.
	SmtpGreetDelayMs            int    `toml:"smtp_greet_delay_ms"`
	SmtpPregreetAction          string `toml:"smtp_pregreet_action"`
	SmtpProtocolViolationLimit  int    `toml:"smtp_protocol_violation_limit"`
	SmtpTarpitAfterUnknownRcpts int    `toml:"smtp_tarpit_after_unknown_rcpts"`
	SmtpFcrdnsCheck             bool   `toml:"smtp_fcrdns_check"`

	// SPF policy settings.
	SpfPolicy string `toml:"spf_policy"`

	// DKIM verification policy settings.
	DkimVerifyPolicy string `toml:"dkim_verify_policy"`

	// DMARC policy settings.
	DmarcPolicy                 string `toml:"dmarc_policy"`
	DmarcAggregateEnabled       bool   `toml:"dmarc_aggregate_enabled"`
	DmarcAggregateOrganization  string `toml:"dmarc_aggregate_organization"`
	DmarcAggregateEmail         string `toml:"dmarc_aggregate_email"`
	DmarcAggregateRetentionDays int    `toml:"dmarc_aggregate_retention_days"`

	// Local-domain identity policy for unauthenticated inbound SMTP.
	LocalDomainSpoofPolicy string `toml:"local_domain_spoof_policy"`

	// RecipientDelimiter separates a local user from a subaddress detail
	// (user+detail@domain). Each character is a delimiter; empty disables
	// subaddressing.
	RecipientDelimiter string `toml:"recipient_delimiter"`

	// Self-service temporary (disposable) aliases. UserAliasesDomains limits
	// them to the listed hosted domains; empty allows every hosted domain.
	UserAliasesEnabled    bool     `toml:"user_aliases_enabled"`
	UserAliasesMaxPerUser int      `toml:"user_aliases_max_per_user"`
	UserAliasesDomains    []string `toml:"user_aliases_domains"`

	// Sender Rewriting Scheme for forwarded and redirected mail. SrsDomain is
	// the domain of rewritten senders; empty uses SmtpServerName.
	SrsEnabled bool   `toml:"srs_enabled"`
	SrsDomain  string `toml:"srs_domain"`

	// Bounce Address Tag Validation: BatvEnabled signs the envelope sender
	// of locally originated mail and rejects null-sender mail to local
	// addresses without a valid tag, after BatvGracePeriodHours.
	BatvEnabled          bool `toml:"batv_enabled"`
	BatvGracePeriodHours int  `toml:"batv_grace_period_hours"`

	// CalendarImipEnabled mails iTIP invitations to external attendees and
	// applies scheduling messages in delivered mail (iMIP, RFC 6047).
	CalendarImipEnabled bool `toml:"calendar_imip_enabled"`

	// WkdEnabled serves user-published OpenPGP keys over the Web Key
	// Directory for hosted domains. AutocryptEnabled adds an Autocrypt header
	// to outgoing mail from identities that opted in with a published key.
	WkdEnabled       bool `toml:"wkd_enabled"`
	AutocryptEnabled bool `toml:"autocrypt_enabled"`
	// CalendarSubscriptionAllowPrivateNetworks lets calendar subscriptions
	// fetch feeds on loopback, private, and link-local addresses.
	CalendarSubscriptionAllowPrivateNetworks bool `toml:"calendar_subscription_allow_private_networks"`
	// OutboundHTTPAllowPrivateNetworks lets administrator-configured HTTP
	// endpoints (alert push, webhook subscriptions, DNS provider APIs) be on
	// loopback, private, and link-local addresses.
	OutboundHTTPAllowPrivateNetworks bool `toml:"outbound_http_allow_private_networks"`
	// SyncPrivateNetworks lists the private, loopback or link-local IP
	// addresses or CIDR prefixes external sync sources may reach, such as an
	// on-premises Exchange server. Empty limits sync sources to public
	// addresses, since any signed-in user can create a sync job.
	SyncPrivateNetworks []string `toml:"sync_private_networks"`
	// WebhookPrivateDestinations lists internal destinations ("10.0.0.5:7090",
	// "10.0.0.0/24") that server webhooks, created by administrators, may
	// reach. Personal webhooks only ever reach public addresses.
	WebhookPrivateDestinations []string `toml:"webhook_private_destinations"`
	// MtaStsMode is the MTA-STS policy (RFC 8461) served for every hosted
	// domain at https://mta-sts.<domain>/.well-known/mta-sts.txt, naming
	// smtp_server_name as the MX: "off" serves none, otherwise "none",
	// "testing" or "enforce".
	MtaStsMode string `toml:"mta_sts_mode"`

	// Outbound relay settings for delivering to external domains.
	RelayHost         string `toml:"relay_host"`
	RelayPort         int    `toml:"relay_port"`
	RelayUsername     string `toml:"relay_username"`
	RelayPassword     string `toml:"relay_password"`
	RelayServerName   string `toml:"relay_server_name"`
	RelayTLSkipVerify bool   `toml:"relay_tls_skip_verify"`
	RelayRequireTLS   bool   `toml:"relay_require_tls"`

	// DaneEnabled applies outbound DANE (RFC 7672) to direct MX delivery.
	// It is effective only with a trusted DNSSEC-validating resolver:
	// DaneResolvers (operator-trusted host[:port] entries) or, when empty,
	// the loopback resolvers from /etc/resolv.conf.
	DaneEnabled   bool     `toml:"dane_enabled"`
	DaneResolvers []string `toml:"dane_resolvers"`

	// Webhook delivery settings.
	WebhookMaxRetries int    `toml:"webhook_max_retries"`
	WebhookBaseDelay  string `toml:"webhook_base_delay"`
	WebhookTimeout    string `toml:"webhook_timeout"`

	// NTLM authentication settings.
	NtlmEnabled bool `toml:"ntlm_enabled"`

	// SASL-IR (Initial Response) settings.
	// When enabled, clients may send the initial SASL response inline with
	// the AUTH/AUTHENTICATE command, avoiding a round-trip (RFC 8305).
	SaslIrEnabled bool `toml:"sasl_ir_enabled"`

	// Mail connection admission (SMTP, IMAP, POP3). MailMaxConnectionsPerIP
	// caps concurrent connections from one client address on each listener;
	// zero disables the cap. MailConnectionLimitExempt lists IP addresses or
	// CIDR prefixes that bypass connection admission entirely.
	MailMaxConnectionsPerIP   int      `toml:"mail_max_connections_per_ip"`
	MailConnectionLimitExempt []string `toml:"mail_connection_limit_exempt"`

	// PROXY protocol (HAProxy v1/v2) on mail listeners. MailProxyProtocol
	// names the protocols (smtp, imap, pop3, managesieve) or individual
	// listeners (see MailProxyProtocolTargets) whose connections from
	// MailProxyProtocolTrusted sources must begin with a PROXY header that
	// relays the real client address.
	MailProxyProtocol        []string `toml:"mail_proxy_protocol"`
	MailProxyProtocolTrusted []string `toml:"mail_proxy_protocol_trusted"`

	// Abuse auto-ban engine. Thresholds are "count/window" strikes per client
	// address (ParseBanThreshold); BanDurations escalate for repeat offenders;
	// IPv6 clients are grouped by BanIPv6Prefix. Exempt addresses come from
	// loopback, MailConnectionLimitExempt, and HTTPTrustedProxies.
	BanEnabled              bool     `toml:"ban_enabled"`
	BanAuthFailures         string   `toml:"ban_auth_failures"`
	BanSecondFactorFailures string   `toml:"ban_second_factor_failures"`
	BanRcptUnknown          string   `toml:"ban_rcpt_unknown"`
	BanProtocolErrors       string   `toml:"ban_protocol_errors"`
	BanSpamtrapHits         string   `toml:"ban_spamtrap_hits"`
	BanDurations            []string `toml:"ban_durations"`
	BanIPv6Prefix           int      `toml:"ban_ipv6_prefix"`

	// LDAP directory accounts. Logins that match no local account are
	// verified against the directory (search with the service account, then
	// bind as the single matching entry) and provision a local account.
	// ldap:// URLs require StartTLS unless LdapAllowPlaintext is set;
	// LdapCACertificate (PEM) replaces the system roots for verification.
	LdapEnabled        bool     `toml:"ldap_enabled"`
	LdapURLs           []string `toml:"ldap_urls"`
	LdapAllowPlaintext bool     `toml:"ldap_allow_plaintext"`
	LdapCACertificate  string   `toml:"ldap_ca_certificate"`
	LdapBindDN         string   `toml:"ldap_bind_dn"`
	LdapBindPassword   string   `toml:"ldap_bind_password"`
	LdapBaseDN         string   `toml:"ldap_base_dn"`
	LdapUserFilter     string   `toml:"ldap_user_filter"`
	LdapIDAttributes   []string `toml:"ldap_id_attributes"`
	LdapAdminGroupDN   string   `toml:"ldap_admin_group_dn"`
	// LdapAdminRole is the role the administrator group grants: "owner"
	// (system.owner, the original behavior) or "admin" (system.admin,
	// operational administration that cannot assign ownership).
	LdapAdminRole           string `toml:"ldap_admin_role"`
	LdapSyncFilter          string `toml:"ldap_sync_filter"`
	LdapSyncIntervalMinutes int    `toml:"ldap_sync_interval_minutes"`
	LdapTimeoutSeconds      int    `toml:"ldap_timeout_seconds"`

	// Automatic Certificate Management Environment (ACME) settings.
	AcmeEnabled      bool   `toml:"acme_enabled"`
	AcmeAcceptTOS    bool   `toml:"acme_accept_tos"`
	AcmeEmail        string `toml:"acme_email"`
	AcmeDomains      string `toml:"acme_domains"`
	AcmeHTTPListen   string `toml:"acme_http_listen"`
	AcmeDirectoryURL string `toml:"acme_directory_url"`
	// AcmeChallenge selects HTTP-01 or DNS-01 per certificate: a default
	// mode (auto, http-01, dns-01) and optional host=mode overrides.
	AcmeChallenge             string `toml:"acme_challenge"`
	AcmeDNSPropagationSeconds int    `toml:"acme_dns_propagation_seconds"`

	// Built-in authoritative DNS server for zones using the builtin DNS
	// provider. DNSServerListen is bound for UDP and TCP;
	// DNSServerNameservers are the NS names published at each zone apex
	// (empty uses the SMTP server name); DNSServerDNSSEC signs answers
	// online; DNSServerAXFRTSIG, "[algorithm:]name:base64-secret", allows
	// TSIG-signed zone transfers to secondaries.
	DNSServerEnabled     bool     `toml:"dns_server_enabled"`
	DNSServerListen      string   `toml:"dns_server_listen"`
	DNSServerNameservers []string `toml:"dns_server_nameservers"`
	DNSServerDNSSEC      bool     `toml:"dns_server_dnssec"`
	DNSServerAXFRTSIG    string   `toml:"dns_server_axfr_tsig"`
}

// Default returns a Config with safe standalone defaults. Environment
// variables never modify Veksel product configuration.
func Default() *Config {
	return DefaultAt("./data")
}

// DefaultAt returns defaults rooted at dataDir.
func DefaultAt(dataDir string) *Config {
	return &Config{
		HTTPListeners:                 defaultHTTPListeners(),
		ListenAddr:                    "0.0.0.0:8472",
		WebTwoFactorRequired:          "off",
		TwoFactorRequiresAppPasswords: true,
		HTTPSEnabled:                  false,
		HTTPSListen:                   "0.0.0.0:8443",
		HTTPTrustedProxies:            []string{},
		SyncPrivateNetworks:           []string{},
		WebhookPrivateDestinations:    []string{},
		MtaStsMode:                    "testing",
		HTTPForwardedHeader:           ForwardedHeaderX,
		PprofListenAddr:               "",
		MetricsToken:                  "",
		DataDir:                       dataDir,
		StoreBackend:                  store.BackendPebble,
		DefaultAccountEngine:          store.BackendPebble,
		AccountStorageRoots:           []string{"default=accounts"},
		PrimaryAccountRoot:            "default",
		StorePath:                     filepath.Join(dataDir, "pebble"),
		SmtpEnabled:                   true,
		SmtpListen:                    "0.0.0.0:25",
		SmtpSubmissionEnabled:         true,
		SmtpSubmissionListen:          "0.0.0.0:587",
		SmtpImplicitTLSEnabled:        false,
		SmtpTLSListen:                 "0.0.0.0:465",
		SmtpAuthMechanisms:            "PLAIN,LOGIN",
		SmtpMaxRecipients:             100,
		SmtpMaxMessageSize:            50 * 1024 * 1024,
		SmtpMaxReceivedHeaders:        50,
		SmtpServerName:                "",
		SmtpPublicAddress:             "",
		SmtpDirectMXEnabled:           true,
		DaneEnabled:                   true,
		DaneResolvers:                 []string{},
		QueueMaxSize:                  10000,
		QueueWorkers:                  4,
		QueueMaxPerDestination:        2,
		QueueMaxAgeHours:              5 * 24,
		QueueRetryInitialSecs:         60,
		QueueRetryMaxSecs:             4 * 60 * 60,
		QueueReceiptRetentionDays:     7,
		ImapMaxLiteralSize:            50 * 1024 * 1024,
		MessageTraceRetentionDays:     30,
		GreylistEnabled:               false,
		GreylistMinimumDelaySeconds:   5 * 60,
		GreylistRetryWindowMinutes:    4 * 60,
		GreylistPendingLifetimeHours:  24,
		GreylistPassLifetimeDays:      36,
		GreylistIPv4PrefixBits:        24,
		GreylistIPv6PrefixBits:        64,
		GreylistMaxEntries:            1_000_000,
		GreylistTrigger:               "always",
		GreylistAutoWhitelistPasses:   5,
		GreylistAutoWhitelistDays:     36,
		GreylistSPFPoolTriplets:       true,
		ImapEnabled:                   true,
		ImapListen:                    "0.0.0.0:143",
		ImapTLSEnabled:                true,
		ImapTlsListen:                 "0.0.0.0:993",
		ImapServerName:                "",
		ImapRequireTLSAuth:            true,
		Pop3Enabled:                   true,
		Pop3Listen:                    "0.0.0.0:110",
		Pop3TLSEnabled:                true,
		Pop3TlsListen:                 "0.0.0.0:995",
		Pop3ServerName:                "",
		Pop3RequireTLSAuth:            true,
		ManageSieveEnabled:            false,
		ManageSieveListen:             "0.0.0.0:4190",
		ManageSieveTLSEnabled:         false,
		ManageSieveTLSListen:          "0.0.0.0:4191",
		ManageSieveRequireTLSAuth:     true,
		AcmeEnabled:                   false,
		AcmeAcceptTOS:                 false,
		AcmeHTTPListen:                "0.0.0.0:80",
		AcmeDirectoryURL:              "https://acme-v02.api.letsencrypt.org/directory",
		AcmeChallenge:                 ACMEChallengeAuto,
		AcmeDNSPropagationSeconds:     120,
		DNSServerListen:               "0.0.0.0:53",
		SmtpSubmissionReceivedPrivacy: false,

		// Logging defaults.
		LogDir:               filepath.Join(dataDir, "logs"),
		LogConsoleLevel:      "info",
		LogFileLevel:         "info",
		LogFormat:            "text",
		LogFileRetentionDays: 30,
		LogFileMaxFiles:      10,
		LogModuleLevels:      logpkg.DefaultModuleLevels(),

		// WebDAV defaults.
		DavEnabled:                      true,
		JmapEnabled:                     true,
		MCPEnabled:                      false,
		EwsEnabled:                      true,
		EasEnabled:                      true,
		WebdavMaxFileSize:               100 * 1024 * 1024,
		TrashRetentionDays:              30,
		RetentionEnabled:                true,
		RetentionJobInterval:            "6h",
		RetentionMinDays:                30,
		LegalHoldDomainAdmins:           false,
		ChangeHistoryRetentionDays:      90,
		ChangeHistoryMaxEntries:         1_000_000,
		AccountIdleCloseSeconds:         300,
		AccountRetainedCleanupDays:      30,
		AccountVerificationEnabled:      false,
		AccountVerificationIntervalHrs:  168,
		AccountVerificationWorkers:      1,
		QuotaWarningPercent:             80,
		QuotaCriticalPercent:            95,
		AlertEvaluationSeconds:          15,
		AlertQueueWarningMinutes:        15,
		AlertQueueCriticalMinutes:       60,
		AlertWebhookWarningMinutes:      5,
		AlertWebhookCriticalMinutes:     30,
		AlertStorageWarningFreePercent:  15,
		AlertStorageCriticalFreePercent: 5,
		AlertCertWarningDays:            30,
		AlertCertCriticalDays:           7,
		AlertNotificationsEnabled:       true,
		BackupSchedule:                  "off",
		BackupDirectory:                 "backups",
		BackupAgeRecipients:             []string{},
		BackupRetentionDaily:            7,
		BackupRetentionWeekly:           4,
		AlertEmailRecipients:            []string{},
		AlertMinIntervalMinutes:         30,
		AlertDigest:                     AlertDigestOff,
		QuotaWarningEmailsEnabled:       true,
		FolderCacheEnabled:              true,
		FolderCacheTTLSeconds:           30,
		FolderCacheMaxEntries:           4096,
		FolderCacheMaxBytes:             64 << 20,
		SearchEnabled:                   true,
		SearchIndexWorkers:              2,
		SearchBatchSize:                 256,
		SearchIdleCloseSeconds:          300,
		SearchMaxExtractedBytes:         1 << 20,
		SearchQueryMaxResults:           100,

		// Virus scanning defaults.
		VirusScanEnabled:             true,
		BuiltinScannerEnabled:        true,
		BuiltinScannerTimeoutSeconds: 5,
		BuiltinScannerMaxBytes:       50 * 1024 * 1024,
		BuiltinScannerFailurePolicy:  "fail-closed",
		ClamdEnabled:                 false,
		ClamdSocket:                  "127.0.0.1:3310",
		ClamdTimeoutSeconds:          30,
		ClamdMaxBytes:                50 * 1024 * 1024,
		ClamdFailurePolicy:           "fail-closed",
		RspamdEnabled:                false,
		RspamdEndpoint:               "http://127.0.0.1:11333",
		RspamdTimeoutSeconds:         15,
		RspamdMaxBytes:               50 * 1024 * 1024,
		RspamdFailurePolicy:          "fail-closed",
		AntispamEnabled:              true,
		AntispamJunkThreshold:        spam.DefaultThresholds().Junk,
		AntispamGreylistThreshold:    spam.DefaultThresholds().Greylist,
		AntispamRejectThreshold:      spam.DefaultThresholds().Reject,
		AntispamSymbolScores:         []string{},
		AntispamDNSBLZones:           spam.DefaultZones(spam.ZoneDNSBL),
		AntispamRHSBLZones:           spam.DefaultZones(spam.ZoneRHSBL),
		AntispamURIBLZones:           spam.DefaultZones(spam.ZoneURIBL),
		AntispamTrustedNetworks:      []string{},
		AntispamProtectedBrands:      []string{},
		AntispamURLShorteners:        spam.DefaultURLShorteners(),
		AttachmentPolicy:             string(attachment.ModeQuarantine),
		AttachmentBlockedExtensions:  attachment.DefaultBlockedExtensions(),
		OutboundRateLimits:           sendguard.DefaultLimits().Entries(),
		OutboundCompromiseThreshold:  sendguard.DefaultCompromiseThreshold,
		OutboundHoldEnabled:          true,
		AntispamBayesEnabled:         true,
		AntispamBayesMinLearns:       200,
		AntispamAutoAllowlist:        true,
		AntispamReputation:           true,
		AntispamReputationMinSamples: spam.DefaultReputationMinSamples,
		AntispamFuzzy:                true,
		AntispamFuzzyThreshold:       spam.DefaultFuzzyThreshold,
		AntispamBulkThreshold:        spam.DefaultBulkThreshold,
		AntispamSpamtraps:            []string{},
		ArcVerify:                    true,
		ArcSealForwards:              true,
		ArcTrustedSealers:            []string{},
		QuarantineRetentionDays:      30,
		QuarantineMaxEntries:         1_000_000,
		QuarantineMaxBytes:           100 << 30,
		QuarantineCleanupMinutes:     60,
		QuarantineCleanupBatchSize:   10_000,
		QuarantineDigestEnabled:      false,
		QuarantineDigestFrom:         "Veksel <postmaster@localhost>",
		QuarantineDigestPollMins:     5,
		QuarantineDigestMaxEntries:   50,
		QuarantineDigestMaxJobs:      100,
		QuarantineDigestMaxRetries:   10,
		QuarantineDigestRetrySecs:    300,
		QuarantineDigestJobDays:      30,
		QuarantineActionTTLHours:     168,

		// Attachment storage defaults.

		// VRFY and EXPN defaults — disabled for security.
		// WARNING: Enabling VRFY allows user enumeration attacks.
		// WARNING: Enabling EXPN allows mailing-list enumeration attacks.
		SmtpVrfyEnabled: false,
		SmtpExpnEnabled: false,

		// HELO policy defaults.
		HeloPolicy: "warn",

		// Connection screening scores early talkers rather than rejecting
		// them; trusted and loopback clients are never screened.
		SmtpGreetDelayMs:            2000,
		SmtpPregreetAction:          "score",
		SmtpProtocolViolationLimit:  10,
		SmtpTarpitAfterUnknownRcpts: 5,
		SmtpFcrdnsCheck:             true,

		// SPF policy defaults.
		SpfPolicy: "warn",

		// DKIM verification policy defaults.
		DkimVerifyPolicy: "warn",

		// DMARC policy defaults.
		DmarcPolicy:                 "warn",
		DmarcAggregateEnabled:       true,
		DmarcAggregateOrganization:  "Veksel",
		DmarcAggregateRetentionDays: 30,

		// Reject unauthenticated local identities unless SPF/DMARC authenticate
		// the corresponding envelope/header domain.
		LocalDomainSpoofPolicy: "reject",

		// Subaddressing and forwarding sender rewriting.
		RecipientDelimiter: "+",
		SrsEnabled:         true,
		SrsDomain:          "",

		UserAliasesEnabled:    true,
		UserAliasesMaxPerUser: 50,
		UserAliasesDomains:    []string{},

		// Signed return paths stay off: some receivers mishandle them.
		BatvGracePeriodHours: 7 * 24,

		// Calendar email invitations.
		CalendarImipEnabled: true,
		WkdEnabled:          true,

		// Outbound relay defaults.
		RelayPort: 587,

		// Webhook delivery defaults.
		WebhookMaxRetries: 5,
		WebhookBaseDelay:  "1s",
		WebhookTimeout:    "10s",

		// NTLM authentication defaults.
		NtlmEnabled: false,

		// SASL-IR defaults — enabled by default for better performance.
		SaslIrEnabled: true,

		// Sized for many users sharing one address (office or carrier NAT).
		MailMaxConnectionsPerIP:   200,
		MailConnectionLimitExempt: []string{},
		MailProxyProtocol:         []string{},
		MailProxyProtocolTrusted:  []string{},

		// Abuse bans are on with conservative thresholds; shared office or
		// carrier NAT addresses belong in mail_connection_limit_exempt.
		BanEnabled:              true,
		BanAuthFailures:         "20/10m",
		BanSecondFactorFailures: "10/10m",
		BanRcptUnknown:          "20/10m",
		BanProtocolErrors:       "30/10m",
		BanSpamtrapHits:         "1/24h",
		BanDurations:            []string{"10m", "1h", "1d", "1w"},
		BanIPv6Prefix:           64,

		// LDAP directory accounts are off until a directory is configured.
		LdapEnabled:             false,
		LdapURLs:                []string{},
		LdapUserFilter:          "(&(objectClass=person)(|(uid={login})(mail={login})(sAMAccountName={login})(userPrincipalName={login})))",
		LdapIDAttributes:        []string{"sAMAccountName", "uid"},
		LdapAdminRole:           "owner",
		LdapSyncFilter:          "(&(objectClass=person)(!(objectClass=computer)))",
		LdapSyncIntervalMinutes: 60,
		LdapTimeoutSeconds:      10,
	}
}

// OpenStore creates the configured store backend.
func (c *Config) OpenStore() (store.Store, error) {
	path := c.StorePath
	if path == "" {
		path = c.DataDir
	}
	switch c.StoreBackend {
	case store.BackendPebble:
		return pebblestore.New(path)
	case store.BackendBadger:
		return badgerstore.New(path)
	default:
		return nil, fmt.Errorf("unknown store backend: %q", c.StoreBackend)
	}
}

// Port extracts the port from ListenAddr, defaulting to 8472.
func (c *Config) Port() int {
	// Simple extraction — good enough for ":8472" or "0.0.0.0:8472".
	addr := c.ListenAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			p, err := strconv.Atoi(addr[i+1:])
			if err == nil {
				return p
			}
		}
	}
	return 8472
}

// AttachmentDirResolved returns the resolved attachment directory path.
// If AttachmentDir is not explicitly set, it defaults to DataDir/attachments.
func (c *Config) AttachmentDirResolved() string {
	if c.AttachmentDir != "" {
		return c.AttachmentDir
	}
	return c.DataDir + "/attachments"
}

// BackupDirectoryPath returns the absolute destination of scheduled backups:
// BackupDirectory itself when absolute, otherwise relative to DataDir.
func (c *Config) BackupDirectoryPath() string {
	path := c.BackupDirectory
	if !filepath.IsAbs(path) {
		path = filepath.Join(c.DataDir, path)
	}
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return filepath.Clean(path)
}

// AntispamSettings returns the spam engine settings this configuration
// describes; trusted networks and the resolver are parsed separately.
func (c *Config) AntispamSettings() spam.Settings {
	return spam.Settings{
		Thresholds:   spam.Thresholds{Junk: c.AntispamJunkThreshold, Greylist: c.AntispamGreylistThreshold, Reject: c.AntispamRejectThreshold},
		SymbolScores: c.AntispamSymbolScores, DNSBL: c.AntispamDNSBLZones, RHSBL: c.AntispamRHSBLZones, URIBL: c.AntispamURIBLZones,
		ProtectedBrands: c.AntispamProtectedBrands, URLShorteners: c.AntispamURLShorteners,
	}
}

// OutboundProtection returns the outbound sending guard configuration.
func (c *Config) OutboundProtection() (sendguard.Config, error) {
	limits, err := sendguard.ParseLimits(c.OutboundRateLimits)
	if err != nil {
		return sendguard.Config{}, fmt.Errorf("outbound_rate_limits: %w", err)
	}
	return sendguard.Config{Defaults: limits, CompromiseThreshold: c.OutboundCompromiseThreshold, HoldEnabled: c.OutboundHoldEnabled}, nil
}

// AttachmentSettings returns the attachment policy settings this
// configuration describes.
func (c *Config) AttachmentSettings() attachment.Settings {
	return attachment.Settings{Mode: c.AttachmentPolicy, BlockedExtensions: c.AttachmentBlockedExtensions, CheckSubmissions: c.AttachmentCheckSubmissions}
}

// RelayEnabled returns true if outbound relay is configured.
func (c *Config) RelayEnabled() bool {
	return c.RelayHost != ""
}

// WebhookBaseDelayDuration parses WebhookBaseDelay into a time.Duration.
// Returns 1 second if the value is empty or invalid.
func (c *Config) WebhookBaseDelayDuration() time.Duration {
	if c.WebhookBaseDelay == "" {
		return time.Second
	}
	d, err := time.ParseDuration(c.WebhookBaseDelay)
	if err != nil {
		return time.Second
	}
	return d
}

// RetentionJobIntervalDuration parses RetentionJobInterval, defaulting to six
// hours when it is empty or invalid.
func (c *Config) RetentionJobIntervalDuration() time.Duration {
	d, err := time.ParseDuration(c.RetentionJobInterval)
	if err != nil || d <= 0 {
		return 6 * time.Hour
	}
	return d
}

// WebhookTimeoutDuration parses WebhookTimeout into a time.Duration.
// Returns 10 seconds if the value is empty or invalid.
func (c *Config) WebhookTimeoutDuration() time.Duration {
	if c.WebhookTimeout == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(c.WebhookTimeout)
	if err != nil {
		return 10 * time.Second
	}
	return d
}
