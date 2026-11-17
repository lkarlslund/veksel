package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/pelletier/go-toml/v2"
)

var adminSections = map[string]struct{}{
	"overview": {}, "health": {}, "domains": {}, "recipients": {}, "resources": {}, "accounts": {}, "protocols": {}, "certificates": {}, "routing": {},
	"outbound-tls": {}, "policies": {}, "security": {}, "bans": {}, "directory": {}, "quarantine": {}, "notifications": {}, "logs": {}, "operations": {}, "settings": {}, "compliance": {},
}

func validAdminSection(section string) bool { _, ok := adminSections[section]; return ok }

// domainAdminSections and domainAdminOperations are the administration
// pages a domain administrator may open; their APIs filter to its domains.
var domainAdminSections = map[string]bool{"domains": true, "accounts": true, "recipients": true, "compliance": true}

var domainAdminOperations = map[string]bool{"trace": true}

// ownerOnlySetting reports whether key decides who becomes an administrator
// through the directory, so system.admin cannot use it to make itself an
// owner. That covers the admin group and role and everything that chooses
// or trusts the directory answering: pointing ldap_urls at a server the
// caller runs would let it report any memberOf.
func ownerOnlySetting(key string) bool {
	switch key {
	case "ldap_enabled", "ldap_sync_interval_minutes", "ldap_timeout_seconds":
		return false
	}
	return strings.HasPrefix(key, "ldap_")
}

var adminOperations = map[string]struct{}{
	"overview": {}, "logging": {}, "queue": {}, "trace": {}, "audit": {}, "backup": {}, "support": {},
}

func validAdminOperation(operation string) bool { _, ok := adminOperations[operation]; return ok }

var adminProtocols = map[string]struct{}{
	"http": {}, "smtp": {}, "imap": {}, "pop3": {}, "managesieve": {}, "dav": {}, "jmap": {}, "mcp": {}, "ews": {}, "eas": {},
}

func validAdminProtocol(protocol string) bool { _, ok := adminProtocols[protocol]; return ok }

// ProtocolControl is the small runtime boundary needed by the unified UI.
type ProtocolControl interface {
	StartIMAP()
	StopIMAP()
	IsIMAPRunning() bool
	StartSMTP()
	StopSMTP()
	IsSMTPRunning() bool
	StartPOP3()
	StopPOP3()
	IsPOP3Running() bool
}

// ProtocolRuntimeStatus reports observed listener state separately from the
// administrator's desired enabled setting.
type ProtocolRuntimeStatus struct {
	Running     bool      `json:"running"`
	Listeners   []string  `json:"listeners"`
	Error       string    `json:"error,omitempty"`
	Attempt     uint64    `json:"attempt"`
	AttemptedAt time.Time `json:"attempted_at,omitzero"`
}

type protocolRuntimeStatusProvider interface {
	ProtocolRuntimeStatus(string) ProtocolRuntimeStatus
}

type SystemQueue interface {
	Size() int
	Stats() queue.Stats
	List(queue.Status) []*queue.Message
	Retry(string) bool
	Remove(string) bool
	Cancel(string) bool
	Hold(string) bool
	HoldWithReason(string, string) bool
	Release(string) bool
	PruneReceipts(context.Context, time.Time, int, bool) (queue.ReceiptPruneResult, error)
}

func (h *Handler) adminSettingSchema() []model.Setting {
	if h.cfg == nil {
		return nil
	}
	c := h.cfg
	str := func(v string) json.RawMessage { b, _ := json.Marshal(v); return b }
	integer := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	boolean := func(v bool) json.RawMessage {
		if v {
			return json.RawMessage("true")
		}
		return json.RawMessage("false")
	}
	settings := []model.Setting{
		{Key: "smtp_enabled", Label: "SMTP enabled", Category: "smtp", Type: "bool", Description: "Accept inbound mail on the SMTP listener", DefaultJSON: boolean(c.SmtpEnabled)},
		{Key: "smtp_listen", Label: "SMTP listener", Category: "smtp", Type: "string", Description: "Inbound SMTP bind address", DefaultJSON: str(c.SmtpListen), Placeholder: "0.0.0.0:25"},
		{Key: "smtp_submission_enabled", Label: "Submission enabled", Category: "smtp", Type: "bool", Description: "Accept authenticated submissions using STARTTLS", DefaultJSON: boolean(c.SmtpSubmissionEnabled)},
		{Key: "smtp_submission_listen", Label: "Submission listener", Category: "smtp", Type: "string", Description: "Authenticated STARTTLS submission bind address", DefaultJSON: str(c.SmtpSubmissionListen), Placeholder: "0.0.0.0:587"},
		{Key: "smtp_implicit_tls_enabled", Label: "Secure submission enabled", Category: "smtp", Type: "bool", Description: "Accept authenticated submissions over implicit TLS", DefaultJSON: boolean(c.SmtpImplicitTLSEnabled)},
		{Key: "smtp_tls_listen", Label: "Secure submission listener", Category: "smtp", Type: "string", Description: "Implicit TLS submission bind address", DefaultJSON: str(c.SmtpTLSListen), Placeholder: "0.0.0.0:465"},
		{Key: "smtp_server_name", Label: "Server name", Category: "smtp", Type: "string", Description: "Public FQDN for EHLO and Message-IDs; must resolve and match reverse DNS. Empty uses the machine host name", DefaultJSON: str(c.SmtpServerName)},
		{Key: "smtp_public_address", Label: "Public egress address", Category: "smtp", Type: "string", Description: "Public IP this server sends mail from. Set it when the server is behind NAT: reverse DNS (PTR), SPF, and blocklist checks then use this address instead of what the server name resolves to. Empty = the server name's addresses", DefaultJSON: str(c.SmtpPublicAddress), Placeholder: "203.0.113.10"},
		{Key: "smtp_auth_mechanisms", Label: "Login methods", Category: "smtp", Type: "checklist", Description: "Authentication methods offered by submission listeners", DefaultJSON: str(c.SmtpAuthMechanisms), EnumOptions: []string{"PLAIN", "LOGIN"}},
		{Key: "smtp_certificate", Label: "Certificate", Category: "smtp", Type: "certificate", Description: "Certificate used by SMTP STARTTLS and secure submission", DefaultJSON: str(c.SmtpCertificate)},
		{Key: "smtp_max_recipients", Label: "Maximum recipients", Category: "smtp", Type: "int", Description: "Maximum recipients per transaction", DefaultJSON: integer(c.SmtpMaxRecipients), Min: 1, Max: 1000},
		{Key: "smtp_max_message_size", Label: "Maximum message bytes", Category: "smtp", Type: "int64", Description: "Maximum accepted RFC 5322 message size", DefaultJSON: integer(c.SmtpMaxMessageSize), Min: 1024, Max: 524288000},
		{Key: "smtp_max_received_headers", Label: "Maximum Received headers", Category: "smtp", Type: "number", Description: "Reject probable routing loops before queue acceptance", DefaultJSON: integer(c.SmtpMaxReceivedHeaders), Min: 1, Max: 1000, Advanced: true},
		{Key: "smtp_submission_received_privacy", Label: "Hide submitter address in Received", Category: "smtp", Type: "bool", Description: "Leave the client IP address and reverse DNS name out of the Received header Veksel adds to authenticated submissions; the server name, protocol, ID, and date stay", DefaultJSON: boolean(c.SmtpSubmissionReceivedPrivacy), Advanced: true},
		{Key: "mail_max_connections_per_ip", Label: "Mail connections per address", Category: "security", Type: "int", Description: "Maximum concurrent SMTP, IMAP, or POP3 connections from one client IP on each listener; size it for every user behind a shared office or NAT address. 0 disables the cap", DefaultJSON: integer(c.MailMaxConnectionsPerIP), Min: 0, Max: 100000, Advanced: true},
		{Key: "mail_connection_limit_exempt", Label: "Mail connection limit exemptions", Category: "security", Type: "list", Description: "IP addresses or CIDR prefixes, such as a webmail or sync gateway, that bypass mail connection limits; failed-login throttling still applies", DefaultJSON: integer(c.MailConnectionLimitExempt), Placeholder: "10.0.0.0/8", Advanced: true},
		{Key: "mail_proxy_protocol", Label: "Mail PROXY protocol", Category: "security", Type: "list", Description: "Mail listeners behind a load balancer that relays the client address with a HAProxy PROXY v1/v2 header: smtp, imap, pop3, managesieve for all of a protocol's listeners, or smtp-relay, submission, smtps, imap-starttls, imaps, pop3-starttls, pop3s, managesieve-starttls, managesieve-tls for one. Connections from trusted proxies must send the header; others are served directly and refused if they send one", DefaultJSON: integer(c.MailProxyProtocol), Placeholder: "smtp", Advanced: true},
		{Key: "mail_proxy_protocol_trusted", Label: "Trusted mail proxies", Category: "security", Type: "list", Description: "IP addresses or CIDR prefixes of the load balancers allowed to send PROXY headers on the listeners named in Mail PROXY protocol", DefaultJSON: integer(c.MailProxyProtocolTrusted), Placeholder: "10.0.0.5", Advanced: true},
		{Key: "http_trusted_proxies", Label: "Trusted reverse proxies", Category: "security", Type: "list", Description: "IP addresses or CIDR prefixes of reverse proxies whose X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Host headers are honoured; empty trusts nobody", DefaultJSON: integer(c.HTTPTrustedProxies), Placeholder: "127.0.0.1/32", Advanced: true},
		{Key: "http_forwarded_header", Label: "Forwarding header", Category: "security", Type: "enum", Description: "The one forwarding header family your trusted reverse proxies set: x-forwarded (X-Forwarded-For/-Proto/-Host, as HAProxy, nginx, Traefik and Caddy send) or forwarded (RFC 7239). The other family is ignored, because a proxy passes a client's copy of it through", DefaultJSON: str(c.HTTPForwardedHeader), EnumOptions: []string{"x-forwarded", "forwarded"}, Advanced: true},
		{Key: "web_two_factor_required", Label: "Require two-factor sign-in", Category: "security", Type: "enum", Description: "Accounts that must enrol and present a second factor (authenticator app or security key) at web sign-in; applies at the next sign-in. Protocol logins keep using application passwords", DefaultJSON: str(c.WebTwoFactorRequired), EnumOptions: []string{"off", "administrators", "all"}},
		{Key: "two_factor_requires_app_passwords", Label: "Second factor requires app passwords", Category: "security", Type: "bool", Description: "Accounts with a second factor must use application passwords for IMAP, SMTP, POP3, DAV, JMAP, ManageSieve, EWS and ActiveSync, which cannot ask for a second factor; their primary password then signs in to the web only", DefaultJSON: boolean(c.TwoFactorRequiresAppPasswords)},
		{Key: "ban_enabled", Label: "Abuse auto-ban", Category: "security", Type: "bool", Description: "Ban client networks that repeatedly fail logins or second factors, probe unknown recipients, or send invalid SMTP commands; banned clients are refused on every mail protocol and HTTP service. Loopback, mail connection limit exemptions, and trusted proxies are never banned", DefaultJSON: boolean(c.BanEnabled)},
		{Key: "ban_auth_failures", Label: "Failed logins before ban", Category: "security", Type: "string", Description: "count/window of failed password logins across SMTP, IMAP, POP3, ManageSieve, web, DAV, JMAP, and Exchange that bans a client network; 0 disables", DefaultJSON: str(c.BanAuthFailures), Placeholder: "20/10m", Advanced: true},
		{Key: "ban_second_factor_failures", Label: "Second-factor failures before ban", Category: "security", Type: "string", Description: "count/window of failed authenticator or recovery codes that bans a client network; 0 disables", DefaultJSON: str(c.BanSecondFactorFailures), Placeholder: "10/10m", Advanced: true},
		{Key: "ban_rcpt_unknown", Label: "Unknown recipients before ban", Category: "security", Type: "string", Description: "count/window of SMTP recipients rejected as unknown (directory harvesting) that bans an unauthenticated client network; 0 disables", DefaultJSON: str(c.BanRcptUnknown), Placeholder: "20/10m", Advanced: true},
		{Key: "ban_protocol_errors", Label: "SMTP command errors before ban", Category: "security", Type: "string", Description: "count/window of SMTP 500-504 command errors that bans an unauthenticated client network; 0 disables", DefaultJSON: str(c.BanProtocolErrors), Placeholder: "30/10m", Advanced: true},
		{Key: "ban_spamtrap_hits", Label: "Spamtrap hits before ban", Category: "security", Type: "string", Description: "count/window of unauthenticated messages to spamtrap addresses that bans the sending network; 0 disables", DefaultJSON: str(c.BanSpamtrapHits), Placeholder: "1/24h", Advanced: true},
		{Key: "ban_durations", Label: "Ban durations", Category: "security", Type: "list", Description: "Escalating ban lengths for a network's first, second, and later offenses within 30 days, such as 10m, 1h, 1d, 1w; the last repeats", DefaultJSON: integer(c.BanDurations), Placeholder: "1h", Advanced: true},
		{Key: "ban_ipv6_prefix", Label: "IPv6 ban prefix", Category: "security", Type: "int", Description: "IPv6 prefix length banned as one client network; IPv4 bans single addresses", DefaultJSON: integer(c.BanIPv6Prefix), Min: 32, Max: 128, Advanced: true},
		{Key: "greylist_enabled", Label: "Greylisting enabled", Category: "security", Type: "bool", Description: "Temporarily defer unfamiliar unauthenticated SMTP sender triplets", DefaultJSON: boolean(c.GreylistEnabled)},
		{Key: "greylist_trigger", Label: "Greylisting trigger", Category: "security", Type: "enum", Description: "always defers every unfamiliar sender triplet; score defers only messages reaching the spam greylist score", DefaultJSON: str(c.GreylistTrigger), EnumOptions: []string{"always", "score"}, Advanced: true},
		{Key: "greylist_minimum_delay_seconds", Label: "Greylist minimum delay", Category: "security", Type: "int", Description: "Seconds a new sender triplet must wait before retrying", DefaultJSON: integer(c.GreylistMinimumDelaySeconds), Min: 1, Max: 86400},
		{Key: "greylist_retry_window_minutes", Label: "Greylist retry window", Category: "security", Type: "int", Description: "Minutes in which a retry can validate a pending triplet", DefaultJSON: integer(c.GreylistRetryWindowMinutes), Min: 1, Max: 10080, Advanced: true},
		{Key: "greylist_pending_lifetime_hours", Label: "Pending triplet lifetime", Category: "security", Type: "int", Description: "Hours to retain an unvalidated sender triplet", DefaultJSON: integer(c.GreylistPendingLifetimeHours), Min: 1, Max: 720, Advanced: true},
		{Key: "greylist_pass_lifetime_days", Label: "Validated triplet lifetime", Category: "security", Type: "int", Description: "Days a validated sender triplet bypasses the initial delay", DefaultJSON: integer(c.GreylistPassLifetimeDays), Min: 1, Max: 365, Advanced: true},
		{Key: "greylist_ipv4_prefix_bits", Label: "IPv4 network prefix", Category: "security", Type: "int", Description: "IPv4 prefix length used to group retrying source addresses", DefaultJSON: integer(c.GreylistIPv4PrefixBits), Min: 0, Max: 32, Advanced: true},
		{Key: "greylist_ipv6_prefix_bits", Label: "IPv6 network prefix", Category: "security", Type: "int", Description: "IPv6 prefix length used to group retrying source addresses", DefaultJSON: integer(c.GreylistIPv6PrefixBits), Min: 0, Max: 128, Advanced: true},
		{Key: "greylist_max_entries", Label: "Greylist entry limit", Category: "security", Type: "int", Description: "Maximum durable triplets before greylisting fails open", DefaultJSON: integer(c.GreylistMaxEntries), Min: 100, Max: 10000000, Advanced: true},
		{Key: "greylist_auto_whitelist_passes", Label: "Auto-whitelist after passes", Category: "security", Type: "int", Description: "Greylisting passes within the validated triplet lifetime after which a client network skips greylisting for every sender and recipient; 0 disables", DefaultJSON: integer(c.GreylistAutoWhitelistPasses), Min: 0, Max: 1000, Advanced: true},
		{Key: "greylist_auto_whitelist_days", Label: "Auto-whitelist lifetime", Category: "security", Type: "int", Description: "Days an auto-whitelisted client network stays whitelisted after its latest message", DefaultJSON: integer(c.GreylistAutoWhitelistDays), Min: 1, Max: 365, Advanced: true},
		{Key: "greylist_skip_spf_pass", Label: "Skip greylisting on SPF pass", Category: "security", Type: "bool", Description: "Accept mail without greylisting when SPF passes for the envelope sender's domain from the connecting address", DefaultJSON: boolean(c.GreylistSkipSPFPass), Advanced: true},
		{Key: "greylist_spf_pool_triplets", Label: "Match sending pools by SPF", Category: "security", Type: "bool", Description: "When SPF passes, key the triplet on the sender's domain instead of the client network, so a provider retrying from another address in its pool is not delayed again", DefaultJSON: boolean(c.GreylistSPFPoolTriplets), Advanced: true},
		{Key: "smtp_direct_mx_enabled", Label: "Direct MX delivery", Category: "routing", Type: "bool", Description: "Deliver directly to recipient-domain MX servers when no specific route or smart host applies", DefaultJSON: boolean(c.SmtpDirectMXEnabled)},
		{Key: "queue_max_size", Label: "Maximum queued deliveries", Category: "routing", Type: "int", Description: "Durable queue capacity measured per recipient", DefaultJSON: integer(c.QueueMaxSize), Min: 1, Max: 10000000},
		{Key: "queue_workers", Label: "Delivery workers", Category: "routing", Type: "int", Description: "Maximum concurrent queue deliveries", DefaultJSON: integer(c.QueueWorkers), Min: 1, Max: 128},
		{Key: "queue_max_per_destination", Label: "Workers per destination", Category: "routing", Type: "int", Description: "Maximum concurrent deliveries to one account or remote domain", DefaultJSON: integer(c.QueueMaxPerDestination), Min: 1, Max: 128},
		{Key: "queue_max_age_hours", Label: "Maximum delivery age", Category: "routing", Type: "int", Description: "Hours before an undelivered message expires", DefaultJSON: integer(c.QueueMaxAgeHours), Min: 1, Max: 8760},
		{Key: "queue_retry_initial_seconds", Label: "Initial retry delay", Category: "routing", Type: "int", Description: "Seconds before the first retry; later retries back off exponentially", DefaultJSON: integer(c.QueueRetryInitialSecs), Min: 1, Max: 86400},
		{Key: "queue_retry_max_seconds", Label: "Maximum retry delay", Category: "routing", Type: "int", Description: "Upper bound for exponential retry delay", DefaultJSON: integer(c.QueueRetryMaxSecs), Min: 1, Max: 604800},
		{Key: "queue_receipt_retention_days", Label: "Completion receipt retention", Category: "routing", Type: "int", Description: "Days to retain payload-free delivery identities for replay protection", DefaultJSON: integer(c.QueueReceiptRetentionDays), Min: 1, Max: 3650, Advanced: true},
		{Key: "message_trace_retention_days", Label: "Message trace retention", Category: "routing", Type: "int", Description: "Days to retain metadata-only delivery histories", DefaultJSON: integer(c.MessageTraceRetentionDays), Min: 1, Max: 3650},
		{Key: "recipient_delimiter", Label: "Subaddress delimiters", Category: "smtp", Type: "string", Description: "Characters that separate a user from a detail, so user+detail@domain delivers to user@domain when no exact address exists; each character is a delimiter and empty disables subaddressing", DefaultJSON: str(c.RecipientDelimiter), Placeholder: "+"},
		{Key: "user_aliases_enabled", Label: "Temporary user aliases", Category: "smtp", Type: "bool", Description: "Let users create disposable aliases on hosted domains; existing aliases keep working and administrators can disable them per account", DefaultJSON: boolean(c.UserAliasesEnabled)},
		{Key: "user_aliases_max_per_user", Label: "Temporary aliases per user", Category: "smtp", Type: "int", Description: "Most active temporary aliases one account may hold", DefaultJSON: integer(c.UserAliasesMaxPerUser), Min: 1, Max: 10000},
		{Key: "user_aliases_domains", Label: "Temporary alias domains", Category: "smtp", Type: "list", Description: "Hosted domains where users may create temporary aliases; empty allows every hosted domain", DefaultJSON: integer(c.UserAliasesDomains), Placeholder: "example.com"},
		{Key: "srs_enabled", Label: "Rewrite forwarded senders (SRS)", Category: "routing", Type: "bool", Description: "Forwarded and redirected mail from remote senders uses a signed SRS envelope sender so it passes SPF at the destination; bounces to SRS addresses are verified and returned", DefaultJSON: boolean(c.SrsEnabled)},
		{Key: "batv_enabled", Label: "Signed return paths (BATV)", Category: "routing", Type: "bool", Description: "Sign the envelope sender of mail from hosted domains with a prvs= tag and reject bounces to local addresses that lack a valid tag (backscatter). Off by default because some receivers and mailing lists mishandle tagged senders", DefaultJSON: boolean(c.BatvEnabled)},
		{Key: "batv_grace_period_hours", Label: "BATV grace period", Category: "routing", Type: "int", Description: "Hours after enabling signed return paths during which untagged bounces are still accepted, for mail sent before signing began", DefaultJSON: integer(c.BatvGracePeriodHours), Min: 0, Max: 720, Advanced: true},
		{Key: "srs_domain", Label: "SRS domain", Category: "routing", Type: "string", Description: "Domain of rewritten senders; its SPF must authorize this server and its MX must reach it. Empty uses the SMTP server name", DefaultJSON: str(c.SrsDomain), Placeholder: "mail.example.com", Advanced: true},
		{Key: "smtp_vrfy_enabled", Label: "Allow VRFY", Category: "smtp", Type: "bool", Description: "Exposes whether an address exists", DefaultJSON: boolean(c.SmtpVrfyEnabled)},
		{Key: "smtp_expn_enabled", Label: "Allow EXPN", Category: "smtp", Type: "bool", Description: "Exposes mailing-list membership", DefaultJSON: boolean(c.SmtpExpnEnabled)},
		{Key: "imap_enabled", Label: "IMAP enabled", Category: "imap", Type: "bool", Description: "Mailbox synchronization and access", DefaultJSON: boolean(c.ImapEnabled)},
		{Key: "imap_listen", Label: "IMAP listener", Category: "imap", Type: "string", Description: "STARTTLS listener", DefaultJSON: str(c.ImapListen), Placeholder: "0.0.0.0:143"},
		{Key: "imap_tls_enabled", Label: "IMAPS enabled", Category: "imap", Type: "bool", Description: "Accept IMAP over implicit TLS", DefaultJSON: boolean(c.ImapTLSEnabled)},
		{Key: "imap_tls_listen", Label: "IMAPS listener", Category: "imap", Type: "string", Description: "Implicit TLS listener", DefaultJSON: str(c.ImapTlsListen), Placeholder: "0.0.0.0:993"},
		{Key: "imap_server_name", Label: "Server name", Category: "imap", Type: "string", Description: "Hostname in the IMAP greeting. Empty uses the machine host name", DefaultJSON: str(c.ImapServerName)},
		{Key: "imap_require_tls_auth", Label: "Require TLS for authentication", Category: "imap", Type: "bool", Description: "Do not accept passwords before TLS is active", DefaultJSON: boolean(c.ImapRequireTLSAuth)},
		{Key: "imap_certificate", Label: "Certificate", Category: "imap", Type: "certificate", Description: "Certificate used by IMAP STARTTLS and IMAPS", DefaultJSON: str(c.ImapCertificate)},
		{Key: "imap_max_literal_size", Label: "Maximum APPEND bytes", Category: "imap", Type: "int64", Description: "Maximum bytes in one literal or atomic MULTIAPPEND command", DefaultJSON: integer(c.ImapMaxLiteralSize), Min: 4096, Max: 1073741824, Advanced: true},
		{Key: "pop3_enabled", Label: "POP3 enabled", Category: "pop3", Type: "bool", Description: "Legacy mailbox download access", DefaultJSON: boolean(c.Pop3Enabled)},
		{Key: "pop3_listen", Label: "POP3 listener", Category: "pop3", Type: "string", Description: "STLS listener", DefaultJSON: str(c.Pop3Listen), Placeholder: "0.0.0.0:110"},
		{Key: "pop3_tls_enabled", Label: "POP3S enabled", Category: "pop3", Type: "bool", Description: "Accept POP3 over implicit TLS", DefaultJSON: boolean(c.Pop3TLSEnabled)},
		{Key: "pop3_tls_listen", Label: "POP3S listener", Category: "pop3", Type: "string", Description: "Implicit TLS listener", DefaultJSON: str(c.Pop3TlsListen), Placeholder: "0.0.0.0:995"},
		{Key: "pop3_server_name", Label: "Server name", Category: "pop3", Type: "string", Description: "Hostname in the POP3 greeting. Empty uses the machine host name", DefaultJSON: str(c.Pop3ServerName)},
		{Key: "pop3_certificate", Label: "Certificate", Category: "pop3", Type: "certificate", Description: "Certificate used by POP3 STLS and POP3S", DefaultJSON: str(c.Pop3Certificate)},
		{Key: "pop3_require_tls_auth", Label: "Require TLS for authentication", Category: "pop3", Type: "bool", Description: "Do not accept passwords before TLS is active", DefaultJSON: boolean(c.Pop3RequireTLSAuth)},
		{Key: "managesieve_enabled", Label: "ManageSieve enabled", Category: "managesieve", Type: "bool", Description: "Allow authenticated clients to manage named Sieve scripts", DefaultJSON: boolean(c.ManageSieveEnabled)},
		{Key: "managesieve_listen", Label: "ManageSieve listener", Category: "managesieve", Type: "string", Description: "RFC 5804 listener with STARTTLS", DefaultJSON: str(c.ManageSieveListen), Placeholder: "0.0.0.0:4190"},
		{Key: "managesieve_tls_enabled", Label: "Implicit TLS enabled", Category: "managesieve", Type: "bool", Description: "Accept ManageSieve over an implicit TLS listener", DefaultJSON: boolean(c.ManageSieveTLSEnabled)},
		{Key: "managesieve_tls_listen", Label: "Implicit TLS listener", Category: "managesieve", Type: "string", Description: "Optional secure ManageSieve listener", DefaultJSON: str(c.ManageSieveTLSListen), Placeholder: "0.0.0.0:4191"},
		{Key: "managesieve_certificate", Label: "Certificate", Category: "managesieve", Type: "certificate", Description: "Certificate used by STARTTLS and implicit TLS", DefaultJSON: str(c.ManageSieveCertificate)},
		{Key: "managesieve_require_tls_auth", Label: "Require TLS for authentication", Category: "managesieve", Type: "bool", Description: "Do not accept passwords before TLS is active", DefaultJSON: boolean(c.ManageSieveRequireTLSAuth)},
		{Key: "dav_enabled", Label: "DAV services enabled", Category: "dav", Type: "bool", Description: "Enable CalDAV, CardDAV, and WebDAV on their assigned HTTP(S) listeners", DefaultJSON: boolean(c.DavEnabled)},
		{Key: "calendar_imip_enabled", Label: "Calendar email invitations (iMIP)", Category: "dav", Type: "bool", Description: "Mail invitations, updates, and cancellations to external attendees of local organizers, and apply replies and invitations that arrive by mail", DefaultJSON: boolean(c.CalendarImipEnabled)},
		{Key: "wkd_enabled", Label: "OpenPGP Web Key Directory", Category: "smtp", Type: "bool", Description: "Serve user-published OpenPGP public keys for hosted domains at https://openpgpkey.<domain>/.well-known/openpgpkey/ and https://<domain>/.well-known/openpgpkey/ (WKD); adds an openpgpkey CNAME to the expected DNS records", DefaultJSON: boolean(c.WkdEnabled)},
		{Key: "autocrypt_enabled", Label: "Autocrypt headers", Category: "smtp", Type: "bool", Description: "Add an Autocrypt header with the sender's published public key to outgoing mail from identities that turned Autocrypt on", DefaultJSON: boolean(c.AutocryptEnabled)},
		{Key: "calendar_subscription_allow_private_networks", Label: "Calendar subscriptions may reach private networks", Category: "dav", Type: "bool", Description: "Let users subscribe to calendar feeds on loopback, private, and link-local addresses; leave off unless feeds are served from inside your network", DefaultJSON: boolean(c.CalendarSubscriptionAllowPrivateNetworks)},
		{Key: "webdav_max_file_size", Label: "WebDAV maximum file bytes", Category: "dav", Type: "int64", Description: "Maximum WebDAV upload size", DefaultJSON: integer(c.WebdavMaxFileSize), Min: 1024, Max: 10737418240},
		{Key: "jmap_enabled", Label: "JMAP enabled", Category: "jmap", Type: "bool", Description: "Enable JMAP Core and Mail on their assigned HTTP(S) listeners", DefaultJSON: boolean(c.JmapEnabled)},
		{Key: "mcp_enabled", Label: "MCP enabled", Category: "mcp", Type: "bool", Description: "Enable authenticated Model Context Protocol tools on assigned HTTP(S) listeners", DefaultJSON: boolean(c.MCPEnabled)},
		{Key: "ews_enabled", Label: "Exchange Web Services (EWS) enabled", Category: "ews", Type: "bool", Description: "Enable Exchange Web Services on its assigned HTTP(S) listeners", DefaultJSON: boolean(c.EwsEnabled)},
		{Key: "eas_enabled", Label: "Exchange ActiveSync (EAS) enabled", Category: "eas", Type: "bool", Description: "Enable Exchange ActiveSync on its assigned HTTP(S) listeners", DefaultJSON: boolean(c.EasEnabled)},
		{Key: "relay_host", Label: "Relay host", Category: "routing", Type: "string", Description: "Outbound smart host; empty uses local-domain delivery only", DefaultJSON: str(c.RelayHost), Placeholder: "smtp.example.net"},
		{Key: "relay_port", Label: "Relay port", Category: "routing", Type: "int", Description: "Outbound SMTP relay port", DefaultJSON: integer(c.RelayPort), Min: 1, Max: 65535},
		{Key: "relay_username", Label: "Relay username", Category: "routing", Type: "string", Description: "Optional relay authentication identity", DefaultJSON: str(c.RelayUsername)},
		{Key: "relay_password", Label: "Relay password", Category: "routing", Type: "string", Description: "Optional relay secret", DefaultJSON: str(c.RelayPassword), Sensitive: true},
		{Key: "relay_require_tls", Label: "Require relay TLS", Category: "routing", Type: "bool", Description: "Reject a relay that cannot negotiate TLS", DefaultJSON: boolean(c.RelayRequireTLS)},
		{Key: "dane_enabled", Label: "Outbound DANE", Category: "routing", Type: "bool", Description: "Authenticate direct MX delivery with DNSSEC-signed TLSA records (RFC 7672); effective only with a trusted DNSSEC-validating resolver, shown under Outbound TLS", DefaultJSON: boolean(c.DaneEnabled)},
		{Key: "dane_resolvers", Label: "DANE validating resolvers", Category: "routing", Type: "list", Description: "Trusted DNSSEC-validating resolvers (IP or IP:port) whose AD bit DANE relies on; empty uses only loopback resolvers from /etc/resolv.conf", DefaultJSON: integer(c.DaneResolvers), Placeholder: "127.0.0.1", Advanced: true},
		{Key: "helo_policy", Label: "HELO policy", Category: "security", Type: "enum", Description: "Handling of invalid HELO/EHLO", DefaultJSON: str(c.HeloPolicy), EnumOptions: []string{"off", "warn", "reject"}},
		{Key: "smtp_greet_delay_ms", Label: "SMTP greeting delay", Category: "security", Type: "int", Description: "Milliseconds the inbound SMTP greeting is held back after its first line to catch clients that talk before it finishes; clients that waited are not delayed again for a day, and exempt and loopback clients never are. 0 disables the test", DefaultJSON: integer(c.SmtpGreetDelayMs), Min: 0, Max: 6000, Advanced: true},
		{Key: "smtp_pregreet_action", Label: "Early-talker action", Category: "security", Type: "enum", Description: "off disables the greeting test; score adds SMTP_PREGREET and a ban strike; reject also answers 554 and disconnects", DefaultJSON: str(c.SmtpPregreetAction), EnumOptions: []string{"off", "score", "reject"}, Advanced: true},
		{Key: "smtp_protocol_violation_limit", Label: "SMTP protocol violation limit", Category: "security", Type: "int", Description: "Protocol violations (early talking, unpermitted pipelining, bare LF, NUL, overlong or unknown commands, excess RSET/NOOP, cleartext AUTH on port 25) after which an inbound session is closed with 421 and a ban strike; 0 never closes", DefaultJSON: integer(c.SmtpProtocolViolationLimit), Min: 0, Max: 1000, Advanced: true},
		{Key: "smtp_tarpit_after_unknown_rcpts", Label: "Tarpit after unknown recipients", Category: "security", Type: "int", Description: "Unknown recipients in one inbound session after which every further RCPT reply is delayed one second more, up to 10 seconds; 0 disables", DefaultJSON: integer(c.SmtpTarpitAfterUnknownRcpts), Min: 0, Max: 1000, Advanced: true},
		{Key: "smtp_fcrdns_check", Label: "Forward-confirmed reverse DNS", Category: "security", Type: "bool", Description: "Score inbound clients without reverse DNS (RDNS_NONE), whose name does not resolve back to them (RDNS_NOT_FCRDNS), or with dynamic-looking names (RDNS_DYNAMIC)", DefaultJSON: boolean(c.SmtpFcrdnsCheck), Advanced: true},
		{Key: "spf_policy", Label: "SPF policy", Category: "security", Type: "enum", Description: "Handling of SPF failures", DefaultJSON: str(c.SpfPolicy), EnumOptions: []string{"off", "warn", "reject"}},
		{Key: "dkim_verify_policy", Label: "DKIM policy", Category: "security", Type: "enum", Description: "Handling of DKIM failures", DefaultJSON: str(c.DkimVerifyPolicy), EnumOptions: []string{"off", "warn", "reject"}},
		{Key: "dmarc_policy", Label: "DMARC policy", Category: "security", Type: "enum", Description: "Handling of DMARC failures", DefaultJSON: str(c.DmarcPolicy), EnumOptions: []string{"off", "warn", "reject"}},
		{Key: "arc_verify", Label: "ARC verification", Category: "security", Type: "bool", Description: "Validate the ARC chain (RFC 8617) of inbound mail and record arc=pass, fail, or none in Authentication-Results", DefaultJSON: boolean(c.ArcVerify)},
		{Key: "arc_trusted_sealers", Label: "Trusted ARC sealers", Category: "security", Type: "list", Description: "Forwarding domains (and their subdomains) whose valid ARC seal, recording dmarc=pass before forwarding, overrides a DMARC failure for mail they forwarded", DefaultJSON: integer(c.ArcTrustedSealers), Placeholder: "google.com", Advanced: true},
		{Key: "arc_seal_forwards", Label: "ARC-seal forwarded mail", Category: "security", Type: "bool", Description: "Add an ARC set to forwarded and Sieve-redirected mail, signed with the forwarding domain's active DKIM key, so receivers can trust the original authentication results", DefaultJSON: boolean(c.ArcSealForwards)},
		{Key: "dmarc_aggregate_enabled", Label: "DMARC aggregate reports", Category: "security", Type: "bool", Description: "Generate and securely queue requested aggregate reports", DefaultJSON: boolean(c.DmarcAggregateEnabled)},
		{Key: "dmarc_aggregate_organization", Label: "DMARC report organization", Category: "security", Type: "string", Description: "Organization shown in aggregate report metadata", DefaultJSON: str(c.DmarcAggregateOrganization)},
		{Key: "dmarc_aggregate_email", Label: "DMARC report contact", Category: "security", Type: "string", Description: "Report contact address; empty uses postmaster at the submitter domain", DefaultJSON: str(c.DmarcAggregateEmail), Placeholder: "postmaster@example.com"},
		{Key: "dmarc_aggregate_retention_days", Label: "DMARC report retention", Category: "security", Type: "int", Description: "Days to retain observations and delivery evidence", DefaultJSON: integer(c.DmarcAggregateRetentionDays), Min: 7, Max: 3650, Advanced: true},
		{Key: "local_domain_spoof_policy", Label: "Local identity protection", Category: "security", Type: "enum", Description: "Handling of unauthenticated local envelope or From identities without SPF/DMARC pass", DefaultJSON: str(c.LocalDomainSpoofPolicy), EnumOptions: []string{"off", "warn", "reject"}},
		{Key: "virus_scan_enabled", Label: "Content scanning", Category: "security", Type: "bool", Description: "Run enabled content engines for accepted messages", DefaultJSON: boolean(c.VirusScanEnabled)},
		{Key: "builtin_scanner_enabled", Label: "Built-in baseline", Category: "security", Type: "bool", Description: "Run the local baseline malware signatures", DefaultJSON: boolean(c.BuiltinScannerEnabled)},
		{Key: "builtin_scanner_timeout_seconds", Label: "Built-in timeout", Category: "security", Type: "int", Description: "Maximum seconds for the built-in scanner", DefaultJSON: integer(c.BuiltinScannerTimeoutSeconds), Min: 1, Max: 600, Advanced: true},
		{Key: "builtin_scanner_max_bytes", Label: "Built-in maximum bytes", Category: "security", Type: "int64", Description: "Largest message accepted by the built-in scanner", DefaultJSON: integer(c.BuiltinScannerMaxBytes), Min: 1024, Max: 1073741824, Advanced: true},
		{Key: "builtin_scanner_failure_policy", Label: "Built-in outage policy", Category: "security", Type: "enum", Description: "Admission action when the built-in scanner cannot decide", DefaultJSON: str(c.BuiltinScannerFailurePolicy), EnumOptions: []string{"fail-open", "fail-closed", "quarantine"}, Advanced: true},
		{Key: "clamd_enabled", Label: "ClamAV", Category: "security", Type: "bool", Description: "Scan through a clamd service", DefaultJSON: boolean(c.ClamdEnabled)},
		{Key: "clamd_socket", Label: "ClamAV endpoint", Category: "security", Type: "string", Description: "host:port, unix:/path, or an absolute local-socket path", DefaultJSON: str(c.ClamdSocket), Placeholder: "127.0.0.1:3310", Advanced: true},
		{Key: "clamd_timeout_seconds", Label: "ClamAV timeout", Category: "security", Type: "int", Description: "Maximum seconds for each clamd request", DefaultJSON: integer(c.ClamdTimeoutSeconds), Min: 1, Max: 600, Advanced: true},
		{Key: "clamd_max_bytes", Label: "ClamAV maximum bytes", Category: "security", Type: "int64", Description: "Largest message streamed to clamd", DefaultJSON: integer(c.ClamdMaxBytes), Min: 1024, Max: 1073741824, Advanced: true},
		{Key: "clamd_failure_policy", Label: "ClamAV outage policy", Category: "security", Type: "enum", Description: "Admission action when clamd cannot decide", DefaultJSON: str(c.ClamdFailurePolicy), EnumOptions: []string{"fail-open", "fail-closed", "quarantine"}, Advanced: true},
		{Key: "rspamd_enabled", Label: "Rspamd", Category: "security", Type: "bool", Description: "Use Rspamd scoring, symbols, malware verdicts, and training", DefaultJSON: boolean(c.RspamdEnabled)},
		{Key: "rspamd_endpoint", Label: "Rspamd endpoint", Category: "security", Type: "string", Description: "HTTP(S) worker or controller URL", DefaultJSON: str(c.RspamdEndpoint), Placeholder: "http://127.0.0.1:11333", Advanced: true},
		{Key: "rspamd_password", Label: "Rspamd password", Category: "security", Type: "string", Description: "Optional controller password for scanning and training", DefaultJSON: str(c.RspamdPassword), Sensitive: true, Advanced: true},
		{Key: "rspamd_timeout_seconds", Label: "Rspamd timeout", Category: "security", Type: "int", Description: "Maximum seconds for each Rspamd request", DefaultJSON: integer(c.RspamdTimeoutSeconds), Min: 1, Max: 600, Advanced: true},
		{Key: "rspamd_max_bytes", Label: "Rspamd maximum bytes", Category: "security", Type: "int64", Description: "Largest message sent to Rspamd", DefaultJSON: integer(c.RspamdMaxBytes), Min: 1024, Max: 1073741824, Advanced: true},
		{Key: "rspamd_failure_policy", Label: "Rspamd outage policy", Category: "security", Type: "enum", Description: "Admission action when Rspamd cannot decide", DefaultJSON: str(c.RspamdFailurePolicy), EnumOptions: []string{"fail-open", "fail-closed", "quarantine"}, Advanced: true},
		{Key: "antispam_enabled", Label: "Built-in spam scoring", Category: "security", Type: "bool", Description: "Score unauthenticated inbound mail with header, content, SPF/DKIM/DMARC, and DNS blocklist symbols; the score files Junk, greylists, or rejects", DefaultJSON: boolean(c.AntispamEnabled)},
		{Key: "antispam_junk_threshold", Label: "Spam Junk score", Category: "security", Type: "number", Description: "Score at which mail is flagged and filed in Junk, unless the account sets its own threshold", DefaultJSON: integer(c.AntispamJunkThreshold), Min: 1, Max: 1000},
		{Key: "antispam_greylist_threshold", Label: "Spam greylist score", Category: "security", Type: "number", Description: "Score at which score-triggered greylisting defers a message; 0 disables", DefaultJSON: integer(c.AntispamGreylistThreshold), Max: 1000, Advanced: true},
		{Key: "antispam_reject_threshold", Label: "Spam reject score", Category: "security", Type: "number", Description: "Score at which SMTP rejects the message outright; 0 disables", DefaultJSON: integer(c.AntispamRejectThreshold), Max: 1000},
		{Key: "antispam_symbol_scores", Label: "Spam symbol scores", Category: "security", Type: "list", Description: "Per-symbol score overrides in SYMBOL=score form, such as RBL_SPAMHAUS_PBL=0; the symbol must exist", DefaultJSON: integer(c.AntispamSymbolScores), Placeholder: "MISSING_DATE=1.5", Advanced: true},
		{Key: "antispam_dnsbl_zones", Label: "IP blocklists (DNSBL)", Category: "security", Type: "list", Description: "Zones queried for the connecting IP; known lists use built-in return codes, others accept rules such as zone 127.0.0.2=SYMBOL:3", DefaultJSON: integer(c.AntispamDNSBLZones), Placeholder: "zen.spamhaus.org", Advanced: true},
		{Key: "antispam_rhsbl_zones", Label: "Sender domain blocklists (RHSBL)", Category: "security", Type: "list", Description: "Zones queried for the envelope, From, and HELO domains", DefaultJSON: integer(c.AntispamRHSBLZones), Placeholder: "dbl.spamhaus.org", Advanced: true},
		{Key: "antispam_uribl_zones", Label: "Link domain blocklists (URIBL)", Category: "security", Type: "list", Description: "Zones queried for domains linked in message bodies", DefaultJSON: integer(c.AntispamURIBLZones), Placeholder: "multi.surbl.org", Advanced: true},
		{Key: "antispam_dns_resolver", Label: "Blocklist DNS resolver", Category: "security", Type: "string", Description: "IP address (optional :port) of a local recursive resolver for blocklist lookups; empty uses the system resolver. Blocklists refuse queries relayed through large public resolvers", DefaultJSON: str(c.AntispamDNSResolver), Placeholder: "127.0.0.1:53", Advanced: true},
		{Key: "antispam_bayes_enabled", Label: "Statistical spam classifier", Category: "security", Type: "bool", Description: "Learn each account's spam from its moves into and out of Junk and add BAYES_SPAM or BAYES_HAM to that account's score once trained", DefaultJSON: boolean(c.AntispamBayesEnabled)},
		{Key: "antispam_bayes_min_learns", Label: "Classifier minimum training", Category: "security", Type: "number", Description: "Spam and ham messages a model must each learn before it scores", DefaultJSON: integer(c.AntispamBayesMinLearns), Min: 1, Max: 100000, Advanced: true},
		{Key: "antispam_bayes_autolearn", Label: "Classifier auto-learning", Category: "security", Type: "bool", Description: "Also learn from deliveries scored confidently spam, or near zero from an allow-listed sender with passing DKIM or DMARC", DefaultJSON: boolean(c.AntispamBayesAutolearn), Advanced: true},
		{Key: "antispam_bayes_global", Label: "Shared classifier model", Category: "security", Type: "bool", Description: "Train one server-wide model from every user's Junk actions; it scores accounts whose own model is not ready and can reject a transaction", DefaultJSON: boolean(c.AntispamBayesGlobal), Advanced: true},
		{Key: "antispam_auto_allowlist", Label: "Auto-allowlist correspondents", Category: "security", Type: "bool", Description: "Lower the score (KNOWN_CORRESPONDENT) of mail from an address the recipient has written to, only when the message authenticates as that sender with DMARC or an aligned SPF or DKIM pass", DefaultJSON: boolean(c.AntispamAutoAllowlist), Advanced: true},
		{Key: "antispam_reputation", Label: "Sender reputation", Category: "security", Type: "bool", Description: "Learn decayed delivery outcomes per authenticated sending domain and sending network, including users' Junk and Not-junk moves, and score REP_DOMAIN_GOOD, REP_DOMAIN_BAD, and REP_IP_BAD", DefaultJSON: boolean(c.AntispamReputation), Advanced: true},
		{Key: "antispam_reputation_min_samples", Label: "Reputation minimum samples", Category: "security", Type: "number", Description: "Decayed observations a sender needs before its reputation scores; confidence reaches full strength at four times this", DefaultJSON: integer(c.AntispamReputationMinSamples), Min: 1, Max: 100000, Advanced: true},
		{Key: "antispam_fuzzy", Label: "Fuzzy and bulk body detection", Category: "security", Type: "bool", Description: "Match message bodies against mail users moved to Junk and high-scoring spam (FUZZY_SPAM), and flag near-identical bodies from many unrelated senders (BULK_SAME_BODY; BULK_NEWSLETTER informs for DKIM-signed List-Unsubscribe mail)", DefaultJSON: boolean(c.AntispamFuzzy), Advanced: true},
		{Key: "antispam_fuzzy_threshold", Label: "Fuzzy match similarity", Category: "security", Type: "number", Description: "Percent body similarity that counts as a fuzzy match", DefaultJSON: integer(c.AntispamFuzzyThreshold), Min: 50, Max: 100, Advanced: true},
		{Key: "antispam_bulk_threshold", Label: "Bulk sender count", Category: "security", Type: "number", Description: "Distinct unrelated senders of a near-identical body within an hour that make it bulk", DefaultJSON: integer(c.AntispamBulkThreshold), Min: 2, Max: 60, Advanced: true},
		{Key: "antispam_spamtraps", Label: "Spamtrap addresses", Category: "security", Type: "list", Description: "Addresses no legitimate sender knows, as a full address or a local part for every hosted domain; they must not be real users or aliases. Unauthenticated mail to a trap is accepted but never delivered: it teaches reputation and fuzzy signatures that the message is spam, strikes the sending IP (ban_spamtrap_hits), and adds SPAMTRAP_HIT to copies for real recipients of the same transaction", DefaultJSON: integer(c.AntispamSpamtraps), Placeholder: "trap", Advanced: true},
		{Key: "antispam_trusted_networks", Label: "Spam scoring trusted networks", Category: "security", Type: "list", Description: "IP addresses or CIDR prefixes never looked up in blocklists, in addition to loopback and private ranges", DefaultJSON: integer(c.AntispamTrustedNetworks), Placeholder: "192.0.2.0/24", Advanced: true},
		{Key: "antispam_protected_brands", Label: "Protected brands", Category: "security", Type: "list", Description: "Brand names or domains guarded against impersonation and lookalike domains, in addition to the hosted domains; a display name or subject naming one scores PHISH_BRAND unless DMARC passes for the brand", DefaultJSON: integer(c.AntispamProtectedBrands), Placeholder: "paypal.com", Advanced: true},
		{Key: "antispam_url_shorteners", Label: "URL shorteners", Category: "security", Type: "list", Description: "Link hosts scored as URL shorteners (PHISH_URL_SHORTENER) because they hide the destination", DefaultJSON: integer(c.AntispamURLShorteners), Placeholder: "bit.ly", Advanced: true},
		{Key: "attachment_policy", Label: "Dangerous attachment policy", Category: "security", Type: "enum", Description: "Action for executable attachments (blocked extensions, or executable content hidden under another name): off skips attachment inspection, score only adds ATTACH_* spam symbols, quarantine isolates the message for each recipient, reject refuses it at SMTP", DefaultJSON: str(c.AttachmentPolicy), EnumOptions: []string{"off", "score", "quarantine", "reject"}},
		{Key: "attachment_blocked_extensions", Label: "Blocked attachment extensions", Category: "security", Type: "list", Description: "File extensions treated as dangerous, also inside ZIP archives and when hidden behind a document extension such as invoice.pdf.exe", DefaultJSON: integer(c.AttachmentBlockedExtensions), Placeholder: "exe", Advanced: true},
		{Key: "outbound_rate_limits", Label: "Outbound sending limits", Category: "security", Type: "list", Description: "Default per-account limits for authenticated submissions across SMTP, webmail, JMAP, EWS, and EAS, in name=value form: messages_per_hour, recipients_per_hour, recipients_per_day; zero or absent is unlimited. Accounts can override them. Over the limit, SMTP answers 451 4.7.0 and the APIs answer 429", DefaultJSON: integer(c.OutboundRateLimits), Placeholder: "recipients_per_hour=2000"},
		{Key: "outbound_compromise_threshold", Label: "Compromised account score", Category: "security", Type: "number", Description: "Score at which an account counts as compromised, summed from sending spikes, new recipient domains, bounce rate, logins from many networks, and spammy outbound content; 0 disables detection", DefaultJSON: integer(c.OutboundCompromiseThreshold), Min: 0, Max: 1000, Advanced: true},
		{Key: "outbound_hold_enabled", Label: "Hold mail of compromised accounts", Category: "security", Type: "bool", Description: "Hold a suspected compromised account's outbound mail in the queue until an administrator releases or purges it; when off, only an alert is raised", DefaultJSON: boolean(c.OutboundHoldEnabled)},
		{Key: "attachment_check_submissions", Label: "Inspect authenticated submissions", Category: "security", Type: "bool", Description: "Also inspect mail sent by signed-in users; dangerous executables are then rejected at submission instead of quarantined. Off by default so users can send legitimate files", DefaultJSON: boolean(c.AttachmentCheckSubmissions), Advanced: true},
		{Key: "metrics_token", Label: "Metrics scrape token", Category: "security", Type: "string", Description: "Bearer token Prometheus presents to scrape /metrics; empty disables the endpoint", DefaultJSON: str(c.MetricsToken), Sensitive: true, Advanced: true},
		{Key: "quarantine_retention_days", Label: "Quarantine retention", Category: "security", Type: "int", Description: "Days isolated messages remain available before automatic deletion", DefaultJSON: integer(c.QuarantineRetentionDays), Min: 1, Max: 3650},
		{Key: "quarantine_max_entries", Label: "Quarantine item limit", Category: "security", Type: "int64", Description: "Maximum isolated messages; admission defers rather than deleting unexpired content", DefaultJSON: integer(c.QuarantineMaxEntries), Min: 1, Max: 100000000, Advanced: true},
		{Key: "quarantine_max_bytes", Label: "Quarantine byte limit", Category: "security", Type: "int64", Description: "Maximum logical message bytes retained in quarantine", DefaultJSON: integer(c.QuarantineMaxBytes), Min: 1048576, Max: 1125899906842624, Advanced: true},
		{Key: "quarantine_cleanup_minutes", Label: "Quarantine cleanup interval", Category: "security", Type: "int", Description: "Minutes between bounded expiry passes", DefaultJSON: integer(c.QuarantineCleanupMinutes), Min: 1, Max: 1440, Advanced: true},
		{Key: "quarantine_cleanup_batch_size", Label: "Quarantine cleanup batch", Category: "security", Type: "int", Description: "Maximum expired messages removed in one transaction", DefaultJSON: integer(c.QuarantineCleanupBatchSize), Min: 1, Max: 1000000, Advanced: true},
		{Key: "quarantine_digest_enabled", Label: "Quarantine digests", Category: "security", Type: "bool", Description: "Allow users to opt into scheduled quarantine summary email", DefaultJSON: boolean(c.QuarantineDigestEnabled)},
		{Key: "quarantine_digest_base_url", Label: "Digest public origin", Category: "security", Type: "string", Description: "HTTPS origin used for expiring release and spam-confirmation links", DefaultJSON: str(c.QuarantineDigestBaseURL), Placeholder: "https://mail.example.com"},
		{Key: "quarantine_digest_from", Label: "Digest sender", Category: "security", Type: "string", Description: "From identity used for quarantine digest email", DefaultJSON: str(c.QuarantineDigestFrom), Placeholder: "Veksel <postmaster@example.com>"},
		{Key: "quarantine_digest_poll_minutes", Label: "Digest scheduler interval", Category: "security", Type: "int", Description: "Minutes between restart-safe due-job and retry passes", DefaultJSON: integer(c.QuarantineDigestPollMins), Min: 1, Max: 1440, Advanced: true},
		{Key: "quarantine_digest_max_entries", Label: "Messages per digest", Category: "security", Type: "int", Description: "Maximum isolated messages represented in one digest", DefaultJSON: integer(c.QuarantineDigestMaxEntries), Min: 1, Max: 1000, Advanced: true},
		{Key: "quarantine_digest_max_jobs_per_run", Label: "Digest scheduler batch", Category: "security", Type: "int", Description: "Maximum due or retry jobs processed in one pass", DefaultJSON: integer(c.QuarantineDigestMaxJobs), Min: 1, Max: 10000, Advanced: true},
		{Key: "quarantine_digest_max_retries", Label: "Digest delivery attempts", Category: "security", Type: "int", Description: "Attempts before a digest job becomes terminally failed", DefaultJSON: integer(c.QuarantineDigestMaxRetries), Min: 1, Max: 100, Advanced: true},
		{Key: "quarantine_digest_retry_seconds", Label: "Digest initial retry", Category: "security", Type: "int", Description: "Initial retry delay; subsequent attempts back off to 24 hours", DefaultJSON: integer(c.QuarantineDigestRetrySecs), Min: 1, Max: 86400, Advanced: true},
		{Key: "quarantine_digest_job_retention_days", Label: "Digest job retention", Category: "security", Type: "int", Description: "Days to retain payload-free terminal digest evidence", DefaultJSON: integer(c.QuarantineDigestJobDays), Min: 1, Max: 3650, Advanced: true},
		{Key: "quarantine_action_ttl_hours", Label: "Digest action lifetime", Category: "security", Type: "int", Description: "Maximum hours signed single-purpose actions remain valid", DefaultJSON: integer(c.QuarantineActionTTLHours), Min: 1, Max: 8760, Advanced: true},
		{Key: "default_account_engine", Label: "Default account storage", Category: "system", Type: "enum", Description: "Storage engine used when a new account is created", DefaultJSON: str(string(c.DefaultAccountEngine)), EnumOptions: []string{"pebble", "badger"}},
		{Key: "account_storage_roots", Label: "Account storage roots", Category: "system", Type: "list", Description: "Named account locations in id=path form", DefaultJSON: integer(c.AccountStorageRoots), Advanced: true},
		{Key: "primary_account_root", Label: "Primary account root", Category: "system", Type: "string", Description: "Named root used for new accounts", DefaultJSON: str(c.PrimaryAccountRoot), Advanced: true},
		{Key: "log_console_level", Label: "Console logging", Category: "system", Type: "enum", Description: "Minimum console severity", DefaultJSON: str(c.LogConsoleLevel), EnumOptions: []string{"trace", "debug", "info", "warn", "error", "fatal"}},
		{Key: "log_file_level", Label: "File logging", Category: "system", Type: "enum", Description: "Minimum file severity before module filtering; off disables file logs (for example under journald)", DefaultJSON: str(c.LogFileLevel), EnumOptions: []string{"trace", "debug", "info", "warn", "error", "fatal", "off"}},
		{Key: "log_file_retention_days", Label: "Log file retention", Category: "system", Type: "int", Description: "Days of daily log files to keep", DefaultJSON: integer(c.LogFileRetentionDays), Min: 1, Max: 3650, Advanced: true},
		{Key: "log_file_max_files", Label: "Log file count limit", Category: "system", Type: "int", Description: "Maximum number of daily log files to keep", DefaultJSON: integer(c.LogFileMaxFiles), Min: 1, Max: 3650, Advanced: true},
		{Key: "retention_enabled", Label: "Retention policies", Category: "system", Type: "bool", Description: "Run the background job that deletes or archives mail older than its effective retention policy; legal holds always block deletion", DefaultJSON: boolean(c.RetentionEnabled)},
		{Key: "retention_job_interval", Label: "Retention job interval", Category: "system", Type: "string", Description: "How often the retention job starts a bounded pass, as a duration from 15m to 168h", DefaultJSON: integer(c.RetentionJobInterval), Placeholder: "6h", Advanced: true},
		{Key: "retention_min_days", Label: "Domain retention floor", Category: "system", Type: "int", Description: "Shortest delete age, in days, a domain administrator may set in a retention policy", DefaultJSON: integer(c.RetentionMinDays), Min: 1, Max: 36500, Advanced: true},
		{Key: "legal_hold_domain_admins", Label: "Domain administrators place legal holds", Category: "system", Type: "bool", Description: "Let domain administrators place and release legal holds on accounts and domains they administer", DefaultJSON: boolean(c.LegalHoldDomainAdmins)},
		{Key: "trash_retention_days", Label: "Trash retention days", Category: "system", Type: "int", Description: "Days recoverably deleted folders and items remain before purge eligibility", DefaultJSON: integer(c.TrashRetentionDays), Min: 1, Max: 3650},
		{Key: "change_history_retention_days", Label: "Change history retention", Category: "system", Type: "int", Description: "Days incremental folder changes remain available to synchronization clients", DefaultJSON: integer(c.ChangeHistoryRetentionDays), Min: 1, Max: 3650},
		{Key: "account_retained_cleanup_days", Label: "Rollback copy retention", Category: "system", Type: "int", Description: "Days to retain verified account move and conversion rollback copies before a durable cleanup job", DefaultJSON: integer(c.AccountRetainedCleanupDays), Min: 1, Max: 3650, Advanced: true},
		{Key: "storage_encryption_default", Label: "Encrypt new accounts", Category: "system", Type: "bool", Description: "Encrypt newly created accounts at rest with their own key, wrapped by the installation key ring. Existing accounts are encrypted or decrypted by an explicit verified conversion under Accounts, Storage", DefaultJSON: boolean(c.StorageEncryptionDefault)},
		{Key: "account_verification_enabled", Label: "Scheduled account verification", Category: "system", Type: "bool", Description: "Run recurring read-only integrity checks for every discovered account", DefaultJSON: boolean(c.AccountVerificationEnabled)},
		{Key: "account_verification_interval_hours", Label: "Account verification interval", Category: "system", Type: "int", Description: "Hours between successful integrity checks for each account", DefaultJSON: integer(c.AccountVerificationIntervalHrs), Min: 1, Max: 8760, Advanced: true},
		{Key: "account_verification_workers", Label: "Account verification workers", Category: "system", Type: "int", Description: "Maximum account integrity checks running concurrently", DefaultJSON: integer(c.AccountVerificationWorkers), Min: 1, Max: 16, Advanced: true},
		{Key: "quota_warning_percent", Label: "Quota warning threshold", Category: "quota", Type: "int", Description: "Usage percentage where accounts enter warning state", DefaultJSON: integer(c.QuotaWarningPercent), Min: 1, Max: 99},
		{Key: "quota_critical_percent", Label: "Quota critical threshold", Category: "quota", Type: "int", Description: "Usage percentage where accounts enter critical state", DefaultJSON: integer(c.QuotaCriticalPercent), Min: 2, Max: 100},
		{Key: "alert_evaluation_seconds", Label: "Health evaluation interval", Category: "system", Type: "int", Description: "Seconds between durable health alert evaluations", DefaultJSON: integer(c.AlertEvaluationSeconds), Min: 5, Max: 3600, Advanced: true},
		{Key: "alert_queue_warning_minutes", Label: "Queue age warning", Category: "system", Type: "int", Description: "Oldest queued delivery age in minutes before warning", DefaultJSON: integer(c.AlertQueueWarningMinutes), Min: 1, Max: 10079, Advanced: true},
		{Key: "alert_queue_critical_minutes", Label: "Queue age critical", Category: "system", Type: "int", Description: "Oldest queued delivery age in minutes before critical alert", DefaultJSON: integer(c.AlertQueueCriticalMinutes), Min: 2, Max: 10080, Advanced: true},
		{Key: "alert_webhook_warning_minutes", Label: "Webhook backlog warning", Category: "system", Type: "int", Description: "Oldest pending webhook age in minutes before warning", DefaultJSON: integer(c.AlertWebhookWarningMinutes), Min: 1, Max: 10079, Advanced: true},
		{Key: "alert_webhook_critical_minutes", Label: "Webhook backlog critical", Category: "system", Type: "int", Description: "Oldest pending webhook age in minutes before critical alert", DefaultJSON: integer(c.AlertWebhookCriticalMinutes), Min: 2, Max: 10080, Advanced: true},
		{Key: "alert_storage_warning_free_percent", Label: "Storage free-space warning", Category: "system", Type: "int", Description: "Available filesystem percentage at or below which to warn", DefaultJSON: integer(c.AlertStorageWarningFreePercent), Min: 2, Max: 99, Advanced: true},
		{Key: "alert_storage_critical_free_percent", Label: "Storage free-space critical", Category: "system", Type: "int", Description: "Available filesystem percentage at or below which to raise a critical alert", DefaultJSON: integer(c.AlertStorageCriticalFreePercent), Min: 1, Max: 98, Advanced: true},
		{Key: "alert_certificate_warning_days", Label: "Certificate expiry warning", Category: "system", Type: "int", Description: "Days before stored certificate expiry to begin warning", DefaultJSON: integer(c.AlertCertWarningDays), Min: 2, Max: 3650, Advanced: true},
		{Key: "alert_certificate_critical_days", Label: "Certificate expiry critical", Category: "system", Type: "int", Description: "Days before stored certificate expiry becomes critical", DefaultJSON: integer(c.AlertCertCriticalDays), Min: 1, Max: 3649, Advanced: true},
		{Key: "alert_notifications_enabled", Label: "Health transition notifications", Category: "system", Type: "bool", Description: "Publish alert transitions to administrators and subscribed webhooks", DefaultJSON: boolean(c.AlertNotificationsEnabled), Advanced: true},
		{Key: "backup_schedule", Label: "Backup schedule", Category: "backup", Type: "string", Description: "When scheduled installation backups run, in server local time: off, daily, weekly, HH:MM (daily), or DAY HH:MM (weekly, for example sun 03:00). A run missed during downtime is caught up once at startup", DefaultJSON: str(c.BackupSchedule), Placeholder: "daily 03:00"},
		{Key: "backup_directory", Label: "Backup directory", Category: "backup", Type: "string", Description: "Destination for scheduled archives; relative paths are inside the data directory. Use a separate disk or a mounted NAS or remote filesystem for real recovery, because veksel restore --force clears the data directory", DefaultJSON: str(c.BackupDirectory), Placeholder: "/mnt/backup/veksel"},
		{Key: "backup_age_recipients", Label: "Encryption recipients", Category: "backup", Type: "list", Description: "Public keys that scheduled archives are encrypted to with age: age1... or ssh-ed25519/ssh-rsa keys. The server cannot decrypt them; keep the private key offline and pass it to veksel restore --identity. Empty stores archives unencrypted", DefaultJSON: integer(c.BackupAgeRecipients), Placeholder: "age1..."},
		{Key: "backup_retention_daily", Label: "Daily archives kept", Category: "backup", Type: "int", Description: "Newest archive of each of this many most recent days is kept", DefaultJSON: integer(c.BackupRetentionDaily), Min: 0, Max: 3650},
		{Key: "backup_retention_weekly", Label: "Weekly archives kept", Category: "backup", Type: "int", Description: "Newest archive of each of this many most recent weeks is kept; only archives the scheduler wrote are ever deleted", DefaultJSON: integer(c.BackupRetentionWeekly), Min: 0, Max: 520},
		{Key: "alert_email_recipients", Label: "Alert email recipients", Category: "system", Type: "list", Description: "Administrator addresses that receive alert notification mail from the system mail domain", DefaultJSON: integer(c.AlertEmailRecipients), Placeholder: "ops@example.com", Advanced: true},
		{Key: "alert_notify_url", Label: "Alert push URL", Category: "system", Type: "string", Description: "HTTP(S) URL that receives a JSON push for each alert notification (Gotify-compatible title, message, and priority)", DefaultJSON: str(c.AlertNotifyURL), Placeholder: "https://push.example.com/message", Sensitive: true, Advanced: true},
		{Key: "outbound_http_allow_private_networks", Label: "Outbound HTTP may reach private networks", Category: "system", Type: "bool", Description: "Let the alert push URL, webhook subscriptions, and DNS provider APIs use loopback, private, and link-local addresses; leave off unless those endpoints run inside your network", DefaultJSON: boolean(c.OutboundHTTPAllowPrivateNetworks), Advanced: true},
		{Key: "sync_private_networks", Label: "Sync sources may reach", Category: "system", Type: "list", Description: "Private, loopback or link-local IP addresses or CIDR prefixes that external sync sources (IMAP, POP3, EWS, ActiveSync, CalDAV, CardDAV) may connect to, such as an on-premises Exchange server being migrated; empty limits sync sources to public addresses, since any signed-in user can create a sync job", DefaultJSON: integer(c.SyncPrivateNetworks), Placeholder: "10.0.0.25", Advanced: true},
		{Key: "webhook_private_destinations", Label: "Server webhooks may reach", Category: "system", Type: "list", Description: "Internal destinations that server webhooks (created by administrators) may deliver to, as address:port or CIDR, for example 10.0.0.5:7090; personal webhooks never reach internal addresses", DefaultJSON: integer(c.WebhookPrivateDestinations), Placeholder: "10.0.0.5:7090", Advanced: true},
		{Key: "mta_sts_mode", Label: "Published MTA-STS policy", Category: "smtp", Type: "enum", Description: "The MTA-STS policy (RFC 8461) served for every hosted domain at https://mta-sts.<domain>/.well-known/mta-sts.txt with the SMTP server name as MX; publish the _mta-sts TXT record shown in each domain's DNS guidance. Start with testing and move to enforce once TLS reports are clean; off serves no policy", DefaultJSON: str(c.MtaStsMode), EnumOptions: []string{"off", "none", "testing", "enforce"}},
		{Key: "alert_notify_token", Label: "Alert push token", Category: "system", Type: "string", Description: "Optional bearer token sent with alert pushes; never shown or logged", DefaultJSON: str(c.AlertNotifyToken), Sensitive: true, Advanced: true},
		{Key: "alert_min_interval_minutes", Label: "Alert re-notify interval", Category: "system", Type: "int", Description: "Minimum minutes between notifications for one alert; flaps inside the window coalesce and escalations bypass it; zero disables", DefaultJSON: integer(c.AlertMinIntervalMinutes), Min: 0, Max: 1440, Advanced: true},
		{Key: "alert_digest", Label: "Alert digest", Category: "system", Type: "enum", Description: "Send each alert change immediately, or batch changes into one daily digest", DefaultJSON: str(c.AlertDigest), EnumOptions: []string{"off", "daily"}, Advanced: true},
		{Key: "quota_warning_emails_enabled", Label: "Quota warning mail", Category: "quota", Type: "bool", Description: "Mail users once each time their usage crosses the warning, critical, or 100% quota threshold", DefaultJSON: boolean(c.QuotaWarningEmailsEnabled)},
		{Key: "change_history_max_entries", Label: "Change history entry limit", Category: "system", Type: "int", Description: "Maximum retained incremental changes per account", DefaultJSON: integer(c.ChangeHistoryMaxEntries), Min: 1, Max: 100000000},
		{Key: "account_idle_close_seconds", Label: "Close idle account stores", Category: "system", Type: "int", Description: "Seconds before an unused account backend is closed; zero keeps stores open", DefaultJSON: integer(c.AccountIdleCloseSeconds), Min: 0, Max: 86400, Advanced: true},
		{Key: "folder_cache_enabled", Label: "Folder read cache", Category: "system", Type: "bool", Description: "Cache authorized folder and item reads between every protocol and the backend", DefaultJSON: boolean(c.FolderCacheEnabled), Advanced: true},
		{Key: "folder_cache_ttl_seconds", Label: "Folder cache lifetime", Category: "system", Type: "int", Description: "Maximum seconds a read remains cached", DefaultJSON: integer(c.FolderCacheTTLSeconds), Min: 1, Max: 86400, Advanced: true},
		{Key: "folder_cache_max_entries", Label: "Folder cache entry limit", Category: "system", Type: "int", Description: "Maximum number of cached reads", DefaultJSON: integer(c.FolderCacheMaxEntries), Min: 1, Max: 1000000, Advanced: true},
		{Key: "folder_cache_max_bytes", Label: "Folder cache byte limit", Category: "system", Type: "int", Description: "Approximate memory ceiling for cached folder and item data", DefaultJSON: integer(c.FolderCacheMaxBytes), Min: 1048576, Max: 17179869184, Advanced: true},
		{Key: "ldap_enabled", Label: "Directory accounts enabled", Category: "directory", Type: "bool", Description: "Verify sign-ins that match no local account against the LDAP or Active Directory server and provision their accounts. Local accounts, including the owner, keep working when the directory is unreachable", DefaultJSON: boolean(c.LdapEnabled)},
		{Key: "ldap_urls", Label: "Directory servers", Category: "directory", Type: "list", Description: "ldaps:// or ldap:// URLs tried in order for failover; ldap:// is upgraded with StartTLS", DefaultJSON: integer(c.LdapURLs), Placeholder: "ldaps://dc1.example.com, ldaps://dc2.example.com"},
		{Key: "ldap_bind_dn", Label: "Service account DN", Category: "directory", Type: "string", Description: "Account used to search for users; empty searches anonymously", DefaultJSON: str(c.LdapBindDN), Placeholder: "CN=veksel,OU=Service Accounts,DC=example,DC=com"},
		{Key: "ldap_bind_password", Label: "Service account password", Category: "directory", Type: "string", Description: "Password of the service account; never shown or logged", DefaultJSON: str(c.LdapBindPassword), Sensitive: true},
		{Key: "ldap_base_dn", Label: "User search base", Category: "directory", Type: "string", Description: "Subtree searched for user entries", DefaultJSON: str(c.LdapBaseDN), Placeholder: "DC=example,DC=com"},
		{Key: "ldap_admin_group_dn", Label: "Administrator group DN", Category: "directory", Type: "string", Description: "Direct members get administration (the role chosen by Administrator group role), re-evaluated at every sign-in and sync; empty grants no role. Only a system owner can change it", DefaultJSON: str(c.LdapAdminGroupDN), Placeholder: "CN=Mail Admins,OU=Groups,DC=example,DC=com"},
		{Key: "ldap_admin_role", Label: "Administrator group role", Category: "directory", Type: "enum", Description: "owner grants the system owner role (unrestricted, the original behavior); admin grants the system administrator role (full operational administration, but no owner or role assignment, backup restore, or raw configuration). Only a system owner can change it", DefaultJSON: str(c.LdapAdminRole), EnumOptions: []string{"owner", "admin"}},
		{Key: "ldap_sync_interval_minutes", Label: "Sync interval", Category: "directory", Type: "int", Description: "Minutes between syncs that refresh directory accounts and disable those removed or disabled in the directory; 0 turns scheduled sync off", DefaultJSON: integer(c.LdapSyncIntervalMinutes), Min: 0, Max: 10080},
		{Key: "ldap_user_filter", Label: "Sign-in filter", Category: "directory", Type: "string", Description: "Filter that must match exactly one entry for a login; {login} is replaced by the escaped login", DefaultJSON: str(c.LdapUserFilter), Advanced: true},
		{Key: "ldap_id_attributes", Label: "Account ID attributes", Category: "directory", Type: "list", Description: "The first present attribute, lowercased, becomes the local account ID", DefaultJSON: integer(c.LdapIDAttributes), Placeholder: "sAMAccountName, uid", Advanced: true},
		{Key: "ldap_sync_filter", Label: "Sync filter", Category: "directory", Type: "string", Description: "Filter listing every user the sync considers; directory accounts it does not match are disabled", DefaultJSON: str(c.LdapSyncFilter), Advanced: true},
		{Key: "ldap_ca_certificate", Label: "Directory CA certificate", Category: "directory", Type: "text", Description: "PEM certificate authorities trusted for the directory instead of the system roots", DefaultJSON: str(c.LdapCACertificate), Placeholder: "-----BEGIN CERTIFICATE-----", Advanced: true},
		{Key: "ldap_allow_plaintext", Label: "Allow unencrypted LDAP", Category: "directory", Type: "bool", Description: "Use ldap:// URLs without StartTLS, sending passwords in clear text; only for an isolated test network", DefaultJSON: boolean(c.LdapAllowPlaintext), Advanced: true},
		{Key: "ldap_timeout_seconds", Label: "Directory timeout", Category: "directory", Type: "int", Description: "Seconds allowed for each connection attempt and directory request", DefaultJSON: integer(c.LdapTimeoutSeconds), Min: 1, Max: 300, Advanced: true},
		{Key: "acme_enabled", Label: "Let's Encrypt enabled", Category: "certificates", Type: "bool", Description: "Obtain and renew certificates automatically with ACME", DefaultJSON: boolean(c.AcmeEnabled)},
		{Key: "acme_accept_tos", Label: "Accept subscriber agreement", Category: "certificates", Type: "bool", Description: "Required before Let's Encrypt can create an account or issue certificates", DefaultJSON: boolean(c.AcmeAcceptTOS)},
		{Key: "acme_email", Label: "ACME account email", Category: "certificates", Type: "string", Description: "Address used for expiry and account notices", DefaultJSON: str(c.AcmeEmail)},
		{Key: "acme_domains", Label: "Managed hostnames", Category: "certificates", Type: "string", Description: "Comma-separated hostnames allowed for automatic issuance", DefaultJSON: str(c.AcmeDomains), Placeholder: "mail.example.com"},
		{Key: "acme_http_listen", Label: "HTTP-01 listener", Category: "certificates", Type: "string", Description: "Public listener used for ACME HTTP-01 challenges", DefaultJSON: str(c.AcmeHTTPListen), Placeholder: "0.0.0.0:80"},
		{Key: "acme_directory_url", Label: "ACME directory", Category: "certificates", Type: "string", Description: "Let's Encrypt production or staging directory URL", DefaultJSON: str(c.AcmeDirectoryURL)},
		{Key: "acme_challenge", Label: "Challenge type", Category: "certificates", Type: "string", Description: "auto uses DNS-01 when a DNS provider covers the hostname (required for wildcards) and HTTP-01 otherwise; add host=http-01 or host=dns-01 to set one certificate", DefaultJSON: str(c.AcmeChallenge), Placeholder: "auto, mail.example.com=http-01"},
		{Key: "acme_dns_propagation_seconds", Label: "DNS-01 propagation timeout", Category: "certificates", Type: "int", Description: "Seconds to wait for the authoritative nameservers to serve a DNS-01 challenge record", DefaultJSON: integer(c.AcmeDNSPropagationSeconds), Min: 10, Max: 3600, Advanced: true},
		{Key: "dns_server_enabled", Label: "Built-in DNS server", Category: "dns", Type: "bool", Description: "Answer authoritative DNS queries over UDP and TCP for zones using the built-in DNS provider. The server never recurses: other names are refused", DefaultJSON: boolean(c.DNSServerEnabled)},
		{Key: "dns_server_listen", Label: "DNS listener", Category: "dns", Type: "string", Description: "UDP and TCP bind address; port 53 needs CAP_NET_BIND_SERVICE or root", DefaultJSON: str(c.DNSServerListen), Placeholder: "0.0.0.0:53"},
		{Key: "dns_server_nameservers", Label: "Nameserver names", Category: "dns", Type: "list", Description: "NS names published at every hosted zone apex, the first being the SOA primary; register the same names (with glue addresses for names inside the zone) at the registrar. Empty uses the SMTP server name", DefaultJSON: integer(c.DNSServerNameservers), Placeholder: "ns1.example.com"},
		{Key: "dns_server_dnssec", Label: "DNSSEC signing", Category: "dns", Type: "bool", Description: "Sign answers online with each zone's ECDSA P-256 key and prove nonexistence with compact NSEC denial. Give the DS records shown with the zone records to the registrar only after enabling this", DefaultJSON: boolean(c.DNSServerDNSSEC), Advanced: true},
		{Key: "dns_server_axfr_tsig", Label: "Zone transfer key", Category: "dns", Type: "string", Description: "TSIG key as [algorithm:]name:base64-secret that secondaries must sign AXFR requests with; empty disables zone transfers. Transfers are refused while DNSSEC signing is on", DefaultJSON: str(c.DNSServerAXFRTSIG), Placeholder: "hmac-sha256:xfr-key:base64secret", Sensitive: true, Advanced: true},
	}
	if h.configService == nil {
		return settings
	}
	// Restart requirements come from the live-applier registry, not literals.
	restart := make(map[string]bool)
	for _, spec := range h.configService.Current().Schema {
		restart[spec.Key] = spec.RestartRequired
	}
	for i := range settings {
		settings[i].RestartRequired = restart[settings[i].Key]
	}
	existing := make(map[string]struct{}, len(settings))
	for _, setting := range settings {
		existing[setting.Key] = struct{}{}
	}
	for _, spec := range h.configService.Current().Schema {
		if spec.Key == "log_module_levels" { // Rendered by the dedicated module registry controls.
			continue
		}
		if _, found := existing[spec.Key]; found {
			continue
		}
		settingType := spec.Type
		if settingType == "slice" {
			settingType = "list"
		}
		setting := model.Setting{
			Key: spec.Key, Label: configSettingLabel(spec.Key), Category: configSettingCategory(spec.Category),
			Type: settingType, Description: spec.Description, RestartRequired: spec.RestartRequired,
			Sensitive: spec.Sensitive, Advanced: spec.Level == "advanced",
		}
		if spec.Key == "system_engine" || spec.Key == "default_account_engine" {
			setting.EnumOptions = []string{"pebble", "badger"}
		}
		settings = append(settings, setting)
	}
	return settings
}

func configSettingLabel(key string) string {
	words := strings.Split(key, "_")
	for i, word := range words {
		if word != "" {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

func configSettingCategory(category string) string {
	switch category {
	case "cors", "webhook", "attachment", "pprof", "log", "trash", "system":
		return "system"
	case "relay":
		return "routing"
	case "virus", "clamd", "helo", "spf", "dkim", "dmarc", "ntlm", "sasl":
		return "security"
	case "acme":
		return "certificates"
	default:
		return category
	}
}

func (h *Handler) apiAdminSettings(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	settings := h.adminSettingSchema()
	snapshot := h.configService.Current()
	encoded, _ := toml.Marshal(snapshot.Config)
	values := make(map[string]any)
	_ = toml.Unmarshal(encoded, &values)
	for i := range settings {
		if value, found := values[settings[i].Key]; found {
			settings[i].ValueJSON, _ = json.Marshal(value)
		} else {
			settings[i].ValueJSON = settings[i].DefaultJSON
		}
	}
	status := map[string]bool{}
	runtimeStatus := map[string]ProtocolRuntimeStatus{}
	if h.protocols != nil {
		status = map[string]bool{"smtp": h.protocols.IsSMTPRunning(), "imap": h.protocols.IsIMAPRunning(), "pop3": h.protocols.IsPOP3Running()}
		if provider, ok := h.protocols.(protocolRuntimeStatusProvider); ok {
			for _, protocol := range []string{"smtp", "imap", "pop3", "managesieve"} {
				runtimeStatus[protocol] = provider.ProtocolRuntimeStatus(protocol)
			}
		}
	}
	for i := range settings {
		if settings[i].Sensitive {
			settings[i].ValueJSON = json.RawMessage(`""`)
			settings[i].DefaultJSON = json.RawMessage(`""`)
		}
	}
	response := map[string]any{"settings": settings, "status": status, "protocol_status": runtimeStatus, "capabilities": h.capabilities}
	response["apply_state"] = h.configService.ApplyStates()
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminPatchSettings(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	desiredConfig := h.configService.Current().Config
	var body struct {
		Settings map[string]json.RawMessage `json:"settings"`
	}
	if err := decodeJSON(r, &body); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	schema := map[string]model.Setting{}
	for _, setting := range h.adminSettingSchema() {
		schema[setting.Key] = setting
	}
	restartRequired := false
	for key, value := range body.Settings {
		setting, ok := schema[key]
		if !ok {
			jsonError(w, http.StatusBadRequest, "unknown setting: "+key)
			return
		}
		if ownerOnlySetting(key) && !h.isOwner(r.Context(), currentActor(r).ID) {
			jsonError(w, http.StatusForbidden, key+": only a system owner can change who becomes an administrator")
			return
		}
		if err := model.Validate(setting, value); err != nil {
			jsonError(w, http.StatusBadRequest, key+": "+err.Error())
			return
		}
		if setting.Type == "certificate" {
			var assignment string
			if err := json.Unmarshal(value, &assignment); err != nil {
				jsonError(w, http.StatusBadRequest, key+": invalid certificate assignment")
				return
			}
			if strings.HasPrefix(assignment, "stored:") {
				if _, err := h.ts.TLSCertStore().Get(r.Context(), strings.TrimPrefix(assignment, "stored:")); err != nil {
					jsonError(w, http.StatusBadRequest, key+": stored certificate does not exist")
					return
				}
			} else if strings.HasPrefix(assignment, "acme:") {
				managed := ""
				enabled := desiredConfig != nil && desiredConfig.AcmeEnabled
				if raw, ok := body.Settings["acme_enabled"]; ok {
					_ = json.Unmarshal(raw, &enabled)
				}
				if raw, ok := body.Settings["acme_domains"]; ok {
					_ = json.Unmarshal(raw, &managed)
				} else if desiredConfig != nil {
					managed = desiredConfig.AcmeDomains
				}
				wanted, found := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(assignment, "acme:"))), false
				for _, domain := range strings.Split(managed, ",") {
					if strings.ToLower(strings.TrimSpace(domain)) == wanted {
						found = true
						break
					}
				}
				if !enabled || wanted == "" || !found {
					jsonError(w, http.StatusBadRequest, key+": ACME hostname is not configured")
					return
				}
			} else if assignment != "" && !strings.HasPrefix(assignment, "acme:") {
				jsonError(w, http.StatusBadRequest, key+": assignment must use stored: or acme:")
				return
			}
		}
		if setting.RestartRequired {
			restartRequired = true
		}
	}
	changes := make(map[string]any, len(body.Settings))
	for key, value := range body.Settings {
		setting := schema[key]
		if setting.Sensitive && string(value) == `""` {
			continue
		}
		var decoded any
		if err := json.Unmarshal(value, &decoded); err != nil {
			jsonError(w, http.StatusBadRequest, key+": "+err.Error())
			return
		}
		changes[key] = decoded
	}
	snapshot := h.configService.Current()
	after, err := h.configService.PatchWithMetadata(snapshot.Revision, changes, config.MutationMetadata{Actor: currentActor(r).ID, Source: "settings-api"})
	if errors.Is(err, config.ErrRevisionConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.applyManagedConfiguration(after, changes)
	for key := range changes {
		h.audit.Log(currentActor(r).ID, "setting.update", key, nil)
	}
	jsonResponse(w, http.StatusOK, map[string]any{"updated": len(changes), "restart_required": restartRequired, "revision": after.Revision})
}

func (h *Handler) apiAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	reach, ok := h.requireAccountAdmin(w, r, id, authz.DomainAccountsManage)
	if !ok {
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.compliance.RequireAccountDeletable(r.Context(), id); err != nil {
			apiError(w, err)
			return
		}
		if err := h.users.Delete(r.Context(), id); err != nil {
			apiError(w, err)
			return
		}
		h.audit.Log(currentActor(r).ID, "account.delete", id, reach.auditDetails(nil))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var request struct {
		DisplayName     string `json:"display_name"`
		Enabled         *bool  `json:"enabled"`
		Password        string `json:"password"`
		MaxStorageBytes *int64 `json:"max_storage_bytes"`
		MaxItems        *int   `json:"max_items"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Password != "" && len(request.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "password must contain at least 8 characters")
		return
	}
	if request.MaxStorageBytes != nil && *request.MaxStorageBytes < 0 || request.MaxItems != nil && *request.MaxItems < 0 {
		jsonError(w, http.StatusBadRequest, "quota limits cannot be negative")
		return
	}
	var passwordHash string
	if request.Password != "" {
		var err error
		passwordHash, err = auth.HashPassword(request.Password)
		if err != nil {
			apiError(w, err)
			return
		}
	}
	if request.MaxStorageBytes != nil && reach.domain != "" {
		h.domainLimitMu.Lock()
		defer h.domainLimitMu.Unlock()
		current, err := h.users.Get(r.Context(), id)
		if err != nil {
			apiError(w, err)
			return
		}
		if *request.MaxStorageBytes != current.MaxStorageBytes {
			if err := h.checkAccountQuota(r.Context(), reach.domain, current.MaxStorageBytes, *request.MaxStorageBytes, reach.delegated); err != nil {
				apiError(w, err)
				return
			}
		}
	}
	err := h.users.Update(r.Context(), id, func(user *model.User) {
		user.DisplayName = strings.TrimSpace(request.DisplayName)
		if request.Enabled != nil {
			user.Enabled = *request.Enabled
		}
		if passwordHash != "" {
			user.PasswordHash = passwordHash
		}
		if request.MaxStorageBytes != nil {
			user.MaxStorageBytes = *request.MaxStorageBytes
		}
		if request.MaxItems != nil {
			user.MaxItems = *request.MaxItems
		}
	})
	if err != nil {
		apiError(w, err)
		return
	}
	if err := h.syncAccountManifest(r.Context(), id); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.update", id, reach.auditDetails(nil))
	jsonResponse(w, http.StatusOK, map[string]string{"id": id})
}

func (h *Handler) apiAdminUpdateDomain(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if r.Method == http.MethodDelete {
		if !h.requireAdminAPI(w, r) {
			return
		}
		identities, err := h.users.ListEmailAddressesForDomain(r.Context(), id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			apiError(w, err)
			return
		}
		if len(identities) != 0 {
			jsonError(w, http.StatusConflict, "domain still has email identities; remove or reassign them first")
			return
		}
		aliases, err := h.ts.RecipientAliasStore().List(r.Context())
		if err != nil {
			apiError(w, err)
			return
		}
		for _, alias := range aliases {
			if alias.DomainID == strings.ToLower(strings.TrimSpace(id)) {
				jsonError(w, http.StatusConflict, "domain still has recipient aliases; remove them first")
				return
			}
		}
		if err := h.ts.DomainStore().Delete(r.Context(), id); err != nil {
			apiError(w, err)
			return
		}
		h.audit.Log(currentActor(r).ID, "domain.delete", id, nil)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var request struct {
		Enabled          *bool   `json:"enabled"`
		VirusScanEnabled *bool   `json:"virus_scan_enabled"`
		CatchAll         *string `json:"catch_all"`
		// UnknownRecipients is split delivery to the domain's outbound
		// route; system administrators only.
		UnknownRecipients *model.UnknownRecipientPolicy `json:"unknown_recipients"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Delivery state and scanning are system settings; a domain
	// administrator may change only the catch-all, to an identity in a
	// domain it administers.
	delegated := !h.isAdmin(r.Context(), currentActor(r).ID)
	if delegated {
		if !h.requireDomainAction(w, r, id, authz.DomainCatchAllManage) {
			return
		}
		if request.Enabled != nil || request.VirusScanEnabled != nil || request.UnknownRecipients != nil {
			jsonError(w, http.StatusForbidden, "only a system administrator can change domain delivery or scanning")
			return
		}
	}
	if policy := request.UnknownRecipients; policy != nil {
		if err := policy.Validate(); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if policy.Route {
			route, err := h.ts.OutboundRouteStore().Get(r.Context(), id)
			if err != nil || !route.Enabled || route.Transport != model.OutboundTransportRelay {
				jsonError(w, http.StatusBadRequest, "split delivery needs an enabled relay outbound route for "+id+" that names the other server")
				return
			}
		}
	}
	if request.CatchAll != nil {
		if target := strings.TrimSpace(*request.CatchAll); target != "" && delegated && !h.domainAllowed(r.Context(), currentActor(r).ID, addressDomain(target), authz.DomainIdentitiesManage) {
			jsonError(w, http.StatusForbidden, "the catch-all target must be an identity in a domain you administer")
			return
		}
		if err := h.ts.DomainStore().SetCatchAll(r.Context(), id, *request.CatchAll); err != nil {
			apiError(w, err)
			return
		}
	}
	err := h.ts.DomainStore().Update(r.Context(), id, func(domain *model.Domain) {
		if request.Enabled != nil {
			domain.Enabled = *request.Enabled
		}
		if request.VirusScanEnabled != nil {
			domain.VirusScanEnabled = *request.VirusScanEnabled
		}
		if request.UnknownRecipients != nil {
			domain.UnknownRecipients = *request.UnknownRecipients
		}
	})
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "domain.update", id, accountAccess{domain: id, delegated: delegated}.auditDetails(nil))
	jsonResponse(w, http.StatusOK, map[string]string{"id": id})
}

func (h *Handler) apiAdminQueue(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	if h.systemQueue == nil {
		jsonResponse(w, http.StatusOK, []*queue.Message{})
		return
	}
	jsonResponse(w, http.StatusOK, filterQueueMessages(h.systemQueue.List(""), h.traceScopeFor(r.Context(), currentActor(r).ID, scope)))
}

func (h *Handler) apiAdminQueueDetail(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	if h.systemQueue == nil {
		jsonError(w, http.StatusNotFound, "queue item not found")
		return
	}
	getter, ok := h.systemQueue.(interface{ Get(string) *queue.Message })
	if !ok {
		jsonError(w, http.StatusServiceUnavailable, "queue detail is unavailable")
		return
	}
	message := getter.Get(r.PathValue("id"))
	if visible := h.traceScopeFor(r.Context(), currentActor(r).ID, scope); message != nil && visible != nil && !visible(string(message.Direction), message.EnvelopeSender, message.Recipient) {
		message = nil
	}
	detail := queue.ProjectMessageDetail(message)
	if detail == nil {
		jsonError(w, http.StatusNotFound, "queue item not found")
		return
	}
	jsonResponse(w, http.StatusOK, detail)
}

func (h *Handler) apiAdminQueueStats(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.systemQueue == nil {
		jsonResponse(w, http.StatusOK, queue.Stats{ByStatus: map[queue.Status]int{}, ByDirection: map[queue.Direction]int{}})
		return
	}
	jsonResponse(w, http.StatusOK, h.systemQueue.Stats())
}

type queueReceiptPruneRequest struct {
	OlderThanDays int  `json:"older_than_days"`
	Limit         int  `json:"limit"`
	DryRun        bool `json:"dry_run"`
}

func (h *Handler) apiAdminQueueReceiptPrune(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request queueReceiptPruneRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.OlderThanDays < 1 || request.OlderThanDays > 3650 {
		jsonError(w, http.StatusBadRequest, "older_than_days must be between 1 and 3650")
		return
	}
	if request.Limit == 0 {
		request.Limit = 500
	}
	if request.Limit < 1 || request.Limit > 10000 {
		jsonError(w, http.StatusBadRequest, "limit must be between 1 and 10000")
		return
	}
	if h.systemQueue == nil {
		jsonError(w, http.StatusServiceUnavailable, "system queue is unavailable")
		return
	}
	result, pruneErr := h.systemQueue.PruneReceipts(r.Context(), time.Now().UTC().AddDate(0, 0, -request.OlderThanDays), request.Limit, request.DryRun)
	details := map[string]string{"dry_run": strconv.FormatBool(request.DryRun), "examined": strconv.Itoa(result.Examined), "removed": strconv.Itoa(result.Removed), "before": result.Before.Format(time.RFC3339)}
	if pruneErr != nil {
		details["error"] = pruneErr.Error()
	}
	h.audit.Log(currentActor(r).ID, "queue.receipts.prune", "completion-receipts", details)
	errorText := ""
	if pruneErr != nil {
		errorText = pruneErr.Error()
	}
	jsonResponse(w, http.StatusOK, map[string]any{"result": result, "error": errorText})
}

func (h *Handler) apiAdminCacheStats(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.folderCache == nil || !h.folderCache.Enabled() {
		jsonResponse(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	stats := h.folderCache.Stats()
	jsonResponse(w, http.StatusOK, map[string]any{"enabled": true, "entries": stats.Entries, "bytes": stats.Bytes, "hits": stats.Hits, "misses": stats.Misses, "evictions": stats.Evictions})
}

func (h *Handler) apiAdminQueueRetry(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	id := r.PathValue("id")
	if h.systemQueue == nil || !h.systemQueue.Retry(id) {
		jsonError(w, http.StatusConflict, "message is not waiting for delivery or failed")
		return
	}
	h.audit.Log(currentActor(r).ID, "queue.retry", id, nil)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "pending"})
}

func (h *Handler) apiAdminQueueCancel(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	id := r.PathValue("id")
	if h.systemQueue == nil || !h.systemQueue.Cancel(id) {
		jsonError(w, http.StatusConflict, "message is processing, missing, or already cancelled")
		return
	}
	h.audit.Log(currentActor(r).ID, "queue.cancel", id, nil)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (h *Handler) apiAdminQueueHold(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	id := r.PathValue("id")
	if h.systemQueue == nil || !h.systemQueue.Hold(id) {
		jsonError(w, http.StatusConflict, "message cannot be held in its current state")
		return
	}
	h.audit.Log(currentActor(r).ID, "queue.hold", id, nil)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "paused"})
}

func (h *Handler) apiAdminQueueRelease(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	id := r.PathValue("id")
	if h.systemQueue == nil || !h.systemQueue.Release(id) {
		jsonError(w, http.StatusConflict, "message is not paused")
		return
	}
	h.audit.Log(currentActor(r).ID, "queue.release", id, nil)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "pending"})
}

type queueActionRequest struct {
	Action string   `json:"action"`
	IDs    []string `json:"ids"`
	Reason string   `json:"reason,omitempty"`
}

type queueActionResult struct {
	ID     string `json:"id"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type queueRerouteRequest struct {
	Route  string `json:"route"`
	Reason string `json:"reason"`
}

func (h *Handler) apiAdminQueueReroute(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request queueRerouteRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Route = strings.ToLower(strings.TrimSpace(request.Route))
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" || len(request.Reason) > 512 {
		jsonError(w, http.StatusBadRequest, "a reason of at most 512 characters is required")
		return
	}
	if request.Route != "" {
		route, err := h.ts.OutboundRouteStore().Get(r.Context(), request.Route)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				jsonError(w, http.StatusBadRequest, "configured outbound route not found")
			} else {
				apiError(w, err)
			}
			return
		}
		if !route.Enabled {
			jsonError(w, http.StatusConflict, "configured outbound route is disabled")
			return
		}
		request.Route = route.Domain
	}
	rerouter, ok := h.systemQueue.(interface {
		Reroute(string, string, string, string) (queue.RouteChange, error)
	})
	if !ok {
		jsonError(w, http.StatusServiceUnavailable, "queue rerouting is unavailable")
		return
	}
	change, err := rerouter.Reroute(r.PathValue("id"), request.Route, currentActor(r).ID, request.Reason)
	if err != nil {
		switch {
		case errors.Is(err, queue.ErrRerouteNotFound):
			jsonError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, queue.ErrRerouteDirection), errors.Is(err, queue.ErrRerouteState), errors.Is(err, queue.ErrRerouteUnchanged):
			jsonError(w, http.StatusConflict, err.Error())
		default:
			apiError(w, err)
		}
		return
	}
	details := map[string]string{"previous_route": change.Previous, "route": change.Current, "reason": change.Reason}
	if change.Current == "" {
		details["route"] = "automatic"
	}
	h.audit.Log(currentActor(r).ID, "queue.reroute", r.PathValue("id"), details)
	jsonResponse(w, http.StatusOK, map[string]any{"change": change})
}

// apiAdminQueueAction returns one result per requested ID. This avoids
// pretending a multi-record operation is atomic while still making partial
// outcomes explicit and safely retryable by an administrator.
func (h *Handler) apiAdminQueueAction(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request queueActionRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.systemQueue == nil || len(request.IDs) == 0 || len(request.IDs) > 500 {
		jsonError(w, http.StatusBadRequest, "between 1 and 500 queue IDs are required")
		return
	}
	if request.Action != "hold" && request.Action != "release" && request.Action != "retry" && request.Action != "cancel" {
		jsonError(w, http.StatusBadRequest, "action must be hold, release, retry, or cancel")
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Action == "hold" && request.Reason == "" {
		request.Reason = "Held by administrator"
	}
	seen := make(map[string]struct{}, len(request.IDs))
	for index, id := range request.IDs {
		if id = strings.TrimSpace(id); id == "" {
			jsonError(w, http.StatusBadRequest, "queue IDs must not be empty")
			return
		}
		if _, exists := seen[id]; exists {
			jsonError(w, http.StatusBadRequest, "duplicate queue IDs are not allowed")
			return
		}
		seen[id] = struct{}{}
		request.IDs[index] = id
	}
	results := make([]queueActionResult, 0, len(request.IDs))
	for _, id := range request.IDs {
		result := queueActionResult{ID: id}
		var ok bool
		switch request.Action {
		case "hold":
			ok, result.Status = h.systemQueue.HoldWithReason(id, request.Reason), "paused"
		case "release":
			ok, result.Status = h.systemQueue.Release(id), "pending"
		case "retry":
			ok, result.Status = h.systemQueue.Retry(id), "pending"
		case "cancel":
			ok, result.Status = h.systemQueue.Cancel(id), "cancelled"
		}
		if !ok {
			result.Status, result.Error = "", "message cannot perform action in its current state"
		} else {
			details := map[string]string{"bulk": "true"}
			if request.Action == "hold" {
				details["reason"] = request.Reason
			}
			h.audit.Log(currentActor(r).ID, "queue."+request.Action, id, details)
		}
		results = append(results, result)
	}
	jsonResponse(w, http.StatusOK, map[string]any{"results": results})
}

func (h *Handler) requireAdminAPI(w http.ResponseWriter, r *http.Request) bool {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}
