package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"reflect"
	"slices"
	"sort"

	"github.com/pelletier/go-toml/v2/unstable/edit"
)

// PlannedChange describes one exact desired-value transition. Sensitive
// values are redacted before this type crosses the service boundary.
type PlannedChange struct {
	Key             string `json:"key"`
	Before          any    `json:"before,omitempty"`
	After           any    `json:"after,omitempty"`
	Effective       any    `json:"effective,omitempty"`
	Sensitive       bool   `json:"sensitive,omitempty"`
	RestartRequired bool   `json:"restart_required"`
}

// DependencyGroup identifies settings validated as one operational unit.
type DependencyGroup struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Keys        []string `json:"keys"`
	ChangedKeys []string `json:"changed_keys"`
}

// ChangePlan is the immutable public result of validating a patch or restore.
type ChangePlan struct {
	BaseRevision     string            `json:"base_revision"`
	ProposedRevision string            `json:"proposed_revision"`
	Changes          []PlannedChange   `json:"changes"`
	DependencyGroups []DependencyGroup `json:"dependency_groups"`
	RestartRequired  bool              `json:"restart_required"`
	LiveApplyKeys    []string          `json:"live_apply_keys,omitempty"`
}

type preparedChangePlan struct {
	ChangePlan
	previous  []byte
	contents  []byte
	candidate *Config
}

type dependencyDefinition struct {
	id    string
	label string
	keys  []string
}

var configurationDependencies = []dependencyDefinition{
	{id: "http", label: "HTTP(S) listeners and services", keys: []string{"http_listeners", "dav_enabled", "jmap_enabled", "mcp_enabled", "ews_enabled", "eas_enabled"}},
	{id: "trusted-proxies", label: "Trusted reverse proxies", keys: []string{"http_trusted_proxies", "http_forwarded_header"}},
	{id: "web-two-factor", label: "Web sign-in two-factor policy", keys: []string{"web_two_factor_required"}},
	{id: "protocol-app-passwords", label: "Protocol passwords for two-factor accounts", keys: []string{"two_factor_requires_app_passwords"}},
	{id: "smtp", label: "SMTP listeners and identity", keys: []string{"smtp_enabled", "smtp_listen", "smtp_submission_enabled", "smtp_submission_listen", "smtp_implicit_tls_enabled", "smtp_tls_listen", "smtp_certificate", "smtp_server_name", "smtp_public_address", "smtp_auth_mechanisms", "smtp_max_recipients", "smtp_max_message_size", "smtp_max_received_headers", "smtp_submission_received_privacy", "local_domain_spoof_policy"}},
	{id: "user-aliases", label: "Temporary user aliases", keys: []string{"user_aliases_enabled", "user_aliases_max_per_user", "user_aliases_domains"}},
	{id: "addressing", label: "Recipient addressing and forwarding", keys: []string{"recipient_delimiter", "srs_enabled", "srs_domain"}},
	{id: "backscatter", label: "Bounce address tag validation", keys: []string{"batv_enabled", "batv_grace_period_hours"}},
	{id: "calendar-imip", label: "Calendar email invitations", keys: []string{"calendar_imip_enabled"}},
	{id: "openpgp", label: "OpenPGP key discovery", keys: []string{"wkd_enabled", "autocrypt_enabled"}},
	{id: "greylisting", label: "Inbound SMTP greylisting", keys: []string{"greylist_enabled", "greylist_minimum_delay_seconds", "greylist_retry_window_minutes", "greylist_pending_lifetime_hours", "greylist_pass_lifetime_days", "greylist_ipv4_prefix_bits", "greylist_ipv6_prefix_bits", "greylist_max_entries", "greylist_trigger", "greylist_auto_whitelist_passes", "greylist_auto_whitelist_days", "greylist_skip_spf_pass", "greylist_spf_pool_triplets"}},
	{id: "calendar-subscriptions", label: "Calendar subscriptions", keys: []string{"calendar_subscription_allow_private_networks"}},
	{id: "outbound-http", label: "Outbound HTTP endpoints", keys: []string{"outbound_http_allow_private_networks"}},
	{id: "sync-network", label: "Sync source networks", keys: []string{"sync_private_networks"}},
	{id: "webhook-network", label: "Webhook internal destinations", keys: []string{"webhook_private_destinations"}},
	{id: "mta-sts-policy", label: "Published MTA-STS policy", keys: []string{"mta_sts_mode"}},
	{id: "antispam", label: "Built-in spam scoring", keys: []string{"antispam_enabled", "antispam_junk_threshold", "antispam_greylist_threshold", "antispam_reject_threshold", "antispam_symbol_scores", "antispam_dnsbl_zones", "antispam_rhsbl_zones", "antispam_uribl_zones", "antispam_dns_resolver", "antispam_trusted_networks", "antispam_protected_brands", "antispam_url_shorteners"}},
	{id: "attachments", label: "Attachment policy", keys: []string{"attachment_policy", "attachment_blocked_extensions", "attachment_check_submissions"}},
	{id: "outbound-protection", label: "Outbound sending limits and compromise protection", keys: []string{"outbound_rate_limits", "outbound_compromise_threshold", "outbound_hold_enabled"}},
	{id: "antispam-bayes", label: "Statistical spam classifier", keys: []string{"antispam_bayes_enabled", "antispam_bayes_min_learns", "antispam_bayes_autolearn", "antispam_bayes_global"}},
	{id: "antispam-fuzzy", label: "Fuzzy and bulk body detection", keys: []string{"antispam_fuzzy", "antispam_fuzzy_threshold", "antispam_bulk_threshold"}},
	{id: "antispam-spamtraps", label: "Spamtraps", keys: []string{"antispam_spamtraps"}},
	{id: "arc", label: "ARC verification and sealing", keys: []string{"arc_verify", "arc_seal_forwards", "arc_trusted_sealers"}},
	{id: "antispam-reputation", label: "Sender reputation and auto-allowlist", keys: []string{"antispam_auto_allowlist", "antispam_reputation", "antispam_reputation_min_samples"}},
	{id: "content-scanning", label: "Content scanner engines", keys: []string{"virus_scan_enabled", "builtin_scanner_enabled", "builtin_scanner_timeout_seconds", "builtin_scanner_max_bytes", "builtin_scanner_failure_policy", "clamd_enabled", "clamd_socket", "clamd_timeout_seconds", "clamd_max_bytes", "clamd_failure_policy", "rspamd_enabled", "rspamd_endpoint", "rspamd_password", "rspamd_timeout_seconds", "rspamd_max_bytes", "rspamd_failure_policy"}},
	{id: "imap", label: "IMAP listeners and identity", keys: []string{"imap_enabled", "imap_listen", "imap_tls_enabled", "imap_tls_listen", "imap_certificate", "imap_server_name", "imap_require_tls_auth", "imap_max_literal_size"}},
	{id: "pop3", label: "POP3 listeners and identity", keys: []string{"pop3_enabled", "pop3_listen", "pop3_tls_enabled", "pop3_tls_listen", "pop3_certificate", "pop3_server_name", "pop3_require_tls_auth"}},
	{id: "smtp-screening", label: "SMTP connection screening", keys: []string{"smtp_greet_delay_ms", "smtp_pregreet_action", "smtp_protocol_violation_limit", "smtp_tarpit_after_unknown_rcpts", "smtp_fcrdns_check"}},
	{id: "mail-admission", label: "Mail connection limits", keys: []string{"mail_max_connections_per_ip", "mail_connection_limit_exempt"}},
	{id: "abuse-bans", label: "Abuse auto-ban engine", keys: []string{"ban_enabled", "ban_auth_failures", "ban_second_factor_failures", "ban_rcpt_unknown", "ban_protocol_errors", "ban_spamtrap_hits", "ban_durations", "ban_ipv6_prefix"}},
	{id: "mail-proxy-protocol", label: "Mail PROXY protocol", keys: []string{"mail_proxy_protocol", "mail_proxy_protocol_trusted"}},
	{id: "managesieve", label: "ManageSieve listeners", keys: []string{"managesieve_enabled", "managesieve_listen", "managesieve_tls_enabled", "managesieve_tls_listen", "managesieve_certificate", "managesieve_require_tls_auth"}},
	{id: "queue", label: "Queue concurrency and retry", keys: []string{"queue_max_size", "queue_workers", "queue_max_per_destination", "queue_max_age_hours", "queue_retry_initial_seconds", "queue_retry_max_seconds", "queue_receipt_retention_days", "message_trace_retention_days"}},
	{id: "routing", label: "Outbound routing and TLS", keys: []string{"smtp_direct_mx_enabled", "relay_host", "relay_port", "relay_username", "relay_password", "relay_server_name", "relay_tls_skip_verify", "relay_require_tls", "dane_enabled", "dane_resolvers"}},
	{id: "account-storage", label: "Account storage and verification", keys: []string{"default_account_engine", "account_storage_roots", "primary_account_root", "account_idle_close_seconds", "account_retained_cleanup_days", "storage_encryption_default", "account_verification_enabled", "account_verification_interval_hours", "account_verification_workers"}},
	{id: "quota-pressure", label: "Quota pressure thresholds", keys: []string{"quota_warning_percent", "quota_critical_percent"}},
	{id: "health-alerts", label: "Health evaluation and notifications", keys: []string{"alert_evaluation_seconds", "alert_queue_warning_minutes", "alert_queue_critical_minutes", "alert_webhook_warning_minutes", "alert_webhook_critical_minutes", "alert_storage_warning_free_percent", "alert_storage_critical_free_percent", "alert_certificate_warning_days", "alert_certificate_critical_days", "alert_notifications_enabled"}},
	{id: "backups", label: "Scheduled backups", keys: []string{"backup_schedule", "backup_directory", "backup_age_recipients", "backup_retention_daily", "backup_retention_weekly"}},
	{id: "alert-delivery", label: "Alert delivery channels", keys: []string{"alert_email_recipients", "alert_notify_url", "alert_notify_token", "alert_min_interval_minutes", "alert_digest", "quota_warning_emails_enabled"}},
	{id: "compliance", label: "Retention policies and legal hold", keys: []string{"retention_enabled", "retention_job_interval", "retention_min_days", "legal_hold_domain_admins"}},
	{id: "change-history", label: "Folder change retention", keys: []string{"change_history_retention_days", "change_history_max_entries", "trash_retention_days"}},
	{id: "folder-cache", label: "Folder read cache", keys: []string{"folder_cache_enabled", "folder_cache_ttl_seconds", "folder_cache_max_entries", "folder_cache_max_bytes"}},
	{id: "search", label: "Account search indexing", keys: []string{"search_enabled", "search_index_workers", "search_batch_size", "search_idle_close_seconds", "search_max_extracted_bytes", "search_query_max_results", "search_index_encrypted_accounts"}},
	{id: "ldap", label: "LDAP directory accounts", keys: []string{"ldap_enabled", "ldap_urls", "ldap_allow_plaintext", "ldap_ca_certificate", "ldap_bind_dn", "ldap_bind_password", "ldap_base_dn", "ldap_user_filter", "ldap_id_attributes", "ldap_admin_group_dn", "ldap_admin_role", "ldap_sync_filter", "ldap_sync_interval_minutes", "ldap_timeout_seconds"}},
	{id: "dns-server", label: "Built-in DNS server", keys: []string{"dns_server_enabled", "dns_server_listen", "dns_server_nameservers", "dns_server_dnssec", "dns_server_axfr_tsig"}},
	{id: "acme", label: "Automatic certificates", keys: []string{"acme_enabled", "acme_accept_tos", "acme_email", "acme_domains", "acme_http_listen", "acme_directory_url", "acme_challenge", "acme_dns_propagation_seconds"}},
}

// PlanPatch validates a complete candidate without writing any file.
func (s *Service) PlanPatch(expectedRevision string, changes map[string]any) (ChangePlan, error) {
	_, plan, err := s.PreviewPatch(expectedRevision, changes)
	return plan, err
}

// PlanRestore validates a retained target and returns its exact prospective
// plan without changing configuration or history.
func (s *Service) PlanRestore(expectedRevision, targetRevision string) (ChangePlan, error) {
	if !validRevision(targetRevision) {
		return ChangePlan{}, errors.New("valid target revision is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if expectedRevision == "" || expectedRevision != s.revision {
		return ChangePlan{}, ErrRevisionConflict
	}
	currentContents, err := s.readCurrentContentsLocked()
	if err != nil {
		return ChangePlan{}, err
	}
	if revision(currentContents) != s.revision {
		return ChangePlan{}, fmt.Errorf("%w: configuration file changed outside Veksel; reload it before restoring", ErrRevisionConflict)
	}
	if targetRevision == s.revision {
		return ChangePlan{BaseRevision: s.revision, ProposedRevision: s.revision}, nil
	}
	targetContents, err := os.ReadFile(s.historySnapshotPath(targetRevision))
	if errors.Is(err, fs.ErrNotExist) {
		return ChangePlan{}, storeNotFoundRevision(targetRevision)
	}
	if err != nil {
		return ChangePlan{}, err
	}
	if revision(targetContents) != targetRevision {
		return ChangePlan{}, errors.New("configuration history snapshot checksum mismatch")
	}
	candidate, err := s.decode(targetContents)
	if err != nil {
		return ChangePlan{}, err
	}
	prepared, err := s.prepareCandidatePlanLocked(currentContents, targetContents, candidate)
	return prepared.ChangePlan, err
}

// PreviewPatch returns the candidate snapshot and its plan from one locked
// validation pass.
func (s *Service) PreviewPatch(expectedRevision string, changes map[string]any) (Snapshot, ChangePlan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prepared, err := s.preparePatchLocked(expectedRevision, changes)
	if err != nil {
		return Snapshot{}, ChangePlan{}, err
	}
	return Snapshot{Config: clone(prepared.candidate), Revision: prepared.ProposedRevision, Schema: slices.Clone(s.schema)}, prepared.ChangePlan, nil
}

func (s *Service) preparePatchLocked(expectedRevision string, changes map[string]any) (preparedChangePlan, error) {
	if expectedRevision == "" || expectedRevision != s.revision {
		return preparedChangePlan{}, ErrRevisionConflict
	}
	contents, err := s.readCurrentContentsLocked()
	if err != nil {
		return preparedChangePlan{}, err
	}
	if revision(contents) != s.revision {
		return preparedChangePlan{}, fmt.Errorf("%w: configuration file changed outside Veksel; reload it before applying another change", ErrRevisionConflict)
	}
	if len(changes) == 0 {
		return s.prepareCandidatePlanLocked(contents, contents, s.desired)
	}
	doc, err := edit.Parse(contents)
	if err != nil {
		return preparedChangePlan{}, fmt.Errorf("parse editable configuration: %w", err)
	}
	known := make(map[string]SettingSpec, len(s.schema))
	for _, spec := range s.schema {
		known[spec.Key] = spec
	}
	for key, value := range changes {
		spec, ok := known[key]
		if !ok {
			return preparedChangePlan{}, fmt.Errorf("unknown setting %q", key)
		}
		if key == "system_engine" && fmt.Sprint(value) != string(s.desired.StoreBackend) {
			return preparedChangePlan{}, errors.New("system_engine cannot be changed while Veksel runs: it selects the engine of the system data store, and a new engine would open an empty store. Convert the data offline with veksel-store-migrate, then edit system_engine in config.toml")
		}
		if number, ok := value.(float64); ok && (spec.Type == "int" || spec.Type == "int64") {
			if math.Trunc(number) != number {
				return preparedChangePlan{}, fmt.Errorf("setting %q requires an integer", key)
			}
			value = int64(number)
		}
		if key == "log_module_levels" {
			levels, err := stringMap(value)
			if err != nil {
				return preparedChangePlan{}, fmt.Errorf("setting %q: %w", key, err)
			}
			for module := range s.desired.LogModuleLevels {
				if _, retained := levels[module]; !retained {
					doc.Delete([]string{key, module})
				}
			}
			modules := make([]string, 0, len(levels))
			for module := range levels {
				modules = append(modules, module)
			}
			sort.Strings(modules)
			for _, module := range modules {
				if err := doc.Set([]string{key, module}, levels[module]); err != nil {
					return preparedChangePlan{}, fmt.Errorf("set %q.%q: %w", key, module, err)
				}
			}
			continue
		}
		if key == "http_listeners" {
			encoded, err := json.Marshal(value)
			if err != nil {
				return preparedChangePlan{}, fmt.Errorf("setting %q: %w", key, err)
			}
			var listeners []HTTPListener
			if err := json.Unmarshal(encoded, &listeners); err != nil {
				return preparedChangePlan{}, fmt.Errorf("setting %q: %w", key, err)
			}
			doc.Delete([]string{key})
			if err := doc.Set([]string{key}, listeners); err != nil {
				return preparedChangePlan{}, fmt.Errorf("set %q: %w", key, err)
			}
			continue
		}
		if err := doc.Set([]string{key}, value); err != nil {
			return preparedChangePlan{}, fmt.Errorf("set %q: %w", key, err)
		}
	}
	next := doc.Bytes()
	candidate, err := s.decode(next)
	if err != nil {
		return preparedChangePlan{}, err
	}
	return s.prepareCandidatePlanLocked(contents, next, candidate)
}

func stringMap(value any) (map[string]string, error) {
	switch typed := value.(type) {
	case map[string]string:
		return typed, nil
	case map[string]any:
		result := make(map[string]string, len(typed))
		for key, value := range typed {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("%q must be a string", key)
			}
			result[key] = text
		}
		return result, nil
	default:
		return nil, errors.New("requires a string map")
	}
}

func (s *Service) prepareCandidatePlanLocked(previous, contents []byte, candidate *Config) (preparedChangePlan, error) {
	before, after := publicConfigValues(s.desired), publicConfigValues(candidate)
	plan := ChangePlan{BaseRevision: s.revision, ProposedRevision: revision(contents)}
	changed := make(map[string]bool)
	for _, spec := range s.schema {
		left, right := before[spec.Key], after[spec.Key]
		if reflect.DeepEqual(left, right) {
			continue
		}
		change := PlannedChange{
			Key: spec.Key, Before: left, After: right, Effective: s.effective[spec.Key],
			Sensitive: spec.Sensitive, RestartRequired: spec.RestartRequired,
		}
		if spec.Sensitive {
			change.Before, change.After, change.Effective = redactedValue, redactedValue, redactedValue
		}
		plan.Changes = append(plan.Changes, change)
		changed[spec.Key] = true
		if spec.RestartRequired {
			plan.RestartRequired = true
		} else {
			plan.LiveApplyKeys = append(plan.LiveApplyKeys, spec.Key)
		}
	}
	for _, definition := range configurationDependencies {
		group := DependencyGroup{ID: definition.id, Label: definition.label, Keys: slices.Clone(definition.keys)}
		for _, key := range definition.keys {
			if changed[key] {
				group.ChangedKeys = append(group.ChangedKeys, key)
			}
		}
		if len(group.ChangedKeys) > 0 {
			plan.DependencyGroups = append(plan.DependencyGroups, group)
		}
	}
	return preparedChangePlan{ChangePlan: plan, previous: slices.Clone(previous), contents: slices.Clone(contents), candidate: clone(candidate)}, nil
}

func (s *Service) readCurrentContentsLocked() ([]byte, error) {
	contents, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	return contents, nil
}
