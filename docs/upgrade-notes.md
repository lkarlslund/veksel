# Upgrade notes

Behaviour changes and new defaults that an operator should know before and
after upgrading. The newest release is listed first. For the mechanics of an
upgrade (stop, back up, replace the binary, start) see
[Upgrading](deployment.md#12-upgrading). Every setting named here applies live
and can be changed in the administration UI or API; the exact defaults are in
[configuration](configuration.md) and
[`configuration-default.toml`](configuration-default.toml).

## Release of 2026-10-23

### Mail acceptance and delivery

| Change | What you may notice | What to do |
|---|---|---|
| **Attachment policy defaults to `quarantine`** (`attachment_policy`) | Inbound mail carrying a dangerous attachment (`.exe`, `.js`, `.iso`, macro-free scripts, shortcuts, and the rest of `attachment_blocked_extensions`, also inside ZIP files) is isolated per recipient instead of delivered. Authenticated submissions are not inspected unless `attachment_check_submissions` is on. | Review the quarantine after the upgrade. Use `score` to only add spam symbols, `reject` for `550 5.7.1`, or trim the extension list. |
| **Greylisting trigger** (`greylist_trigger`, default `always`) | Greylisting itself is still off (`greylist_enabled = false`). When you turn it on, `always` defers every unfamiliar triplet at RCPT. Auto-whitelisting (`greylist_auto_whitelist_*`) and SPF pool triplets are on. | Prefer `score` to delay only mail that already looks suspicious (threshold `antispam_greylist_threshold`, default 4). |
| **DKIM signing on every local path** | Webmail, scheduled send, JMAP, EWS, EAS, Sieve notifications, vacation replies, and reports are signed with the active key of the hosted domain in the `From` header. SMTP no longer signs an unauthenticated message just because it claims a hosted sender domain. A domain with no active key is sent unsigned. | Make sure every hosted domain has an active DKIM key and published record (Domains, DNS records). |
| **Received headers** | Every accepted message gets an RFC 5321 `Received:` field. Messages that already carry more than `smtp_max_received_headers` (default 50, was 100) are refused with `554 5.4.6`. | Set `smtp_submission_received_privacy` to hide client addresses on submissions. |
| **Strict DATA reader** | The body ends only at CRLF.CRLF. Bare LF is normalised to CRLF, dot-stuffing is removed, and a `.` line next to a bare LF is rejected with `554` (SMTP smuggling protection). Clients that send bare LF line endings are repaired, but malformed senders may be refused. | Watch for `554` from legacy software and fix the sender. |
| **Connection screening on port 25** | A 2 second greeting delay (`smtp_greet_delay_ms`) detects early talkers; clients that waited are remembered for 24 hours. Protocol violations close a session after 10, unknown recipients are tarpitted after 5, and FCrDNS is scored. Loopback and `mail_connection_limit_exempt` are skipped; submission is never screened. | Set `smtp_greet_delay_ms = 0` and `smtp_pregreet_action = "off"` if an internal relay cannot cope. |
| **Mail proxy** | `mail_proxy_protocol` (empty by default) must name each listener behind a load balancer, with `mail_proxy_protocol_trusted` set. | See [PROXY protocol](deployment.md#behind-a-tcp-load-balancer-proxy-protocol). |

### Spam, reputation and bans

- **Built-in spam scoring is on** (`antispam_enabled = true`): Junk at 6,
  greylist-by-score at 4, reject at 15 (`0` disables a threshold). It queries
  public DNS blocklists (Spamhaus, Barracuda, SpamCop, PSBL, SURBL, URIBL).
  Large public resolvers are often blocked by these lists, so run a local
  resolver ([deployment](deployment.md#dns-resolver-for-spam-blocklists)) or
  override `antispam_dns_resolver`.
- **Account spam threshold semantics.** An account's own non-zero spam
  threshold replaces the server `antispam_junk_threshold` for that account; `0`
  means "use the server default". Only the Junk decision is per account.
- **Per-user Bayesian classifier** is enabled (`antispam_bayes_enabled`) and
  starts scoring after 200 learned messages (`antispam_bayes_min_learns`);
  auto-learning and the shared model are off. Sender reputation, the
  authenticated correspondent auto-allowlist, fuzzy and bulk body detection are
  on; spamtraps and brand protection lists are empty until you fill them.
- **Abuse auto-ban is on** (`ban_enabled`): 20 failed logins or 20 unknown
  recipients in 10 minutes, 30 SMTP protocol errors in 10 minutes, 10 failed
  second-factor codes, or a single spamtrap hit bans the client network
  (IPv6 by /64) for 10 minutes, then 1 hour, 1 day, 1 week. Loopback and
  exempt networks are never banned. Behind a reverse proxy, set
  `http_trusted_proxies` and `mail_proxy_protocol` correctly, or every user
  appears to come from the proxy and one abuser bans everybody. Review bans in
  **Administration → Security**.
- **Outbound limits.** Per-account sending limits and compromised-account
  holds are enforced on submission.
- **ARC** verification and forward sealing are on (`arc_verify`,
  `arc_seal_forwards`); `arc_trusted_sealers` is empty.
- **BATV** (`batv_enabled`) and **SRS** (`srs_enabled`, on) apply to forwarded
  and bounced mail; BATV is off by default.

### Outbound HTTP and administrator-configured endpoints

`outbound_http_allow_private_networks` defaults to **false**. Alert push URLs,
webhook subscriptions, and DNS-provider APIs (webhook and Cloudflare
connectors) that resolve to loopback, private, link-local or reserved
addresses are refused, and redirects are re-checked. A LAN webhook or
notification server stops working until you turn the setting on. Calendar
subscriptions and SMTP TLS report endpoints are always guarded.

### Authorization changes

- **Backup downloads are owner-only.** Installation, system, and scheduled
  backup archives contain configuration secrets, password hashes, and mail, so
  `system.admin` can no longer download them. eDiscovery and legal holds on
  owner accounts also need an owner.
- **LDAP connection settings are owner-only.** All `ldap_*` settings except
  enable, timeout and sync interval can only be changed by a system owner
  (a directory under attacker control could report the owner group).
- **Domain administrators** (delegated administration) cannot manage accounts
  that hold any system-scope role binding, and domain-scoped holds and
  exports are limited to what the actor could export individually. Deleting an
  account now also removes its role bindings and group memberships.
- **Resource accounts** (rooms and equipment) are non-interactive. They refuse
  passwords, application passwords, API keys, sessions, and two-factor
  enrolment; booking works through calendar sharing and scheduling only.

### Derived data, rebuilds and storage

- **Search mapping version 10.** Full-text indexes rebuild once in the
  background on the first start after upgrade, to a leaner layout that is
  typically a fifth to a quarter of the previous size (no composite `_all`
  field or term vectors, only the fields hits are served from are stored,
  body text of `multipart/alternative` mail is indexed once, DKIM/ARC
  signature blobs keep only their `d=`/`s=`/`i=` tags, and each text
  attachment contributes at most 256 KB within `search_max_extracted_bytes`).
  Searches answer from the previous index until the new one is ready; the old
  one is then removed. No setting changes.
- **Search mapping version 8.** Full-text indexes rebuild in the background on
  the first start after upgrade (categories, mail fields). Search results are
  incomplete until each account finishes; a rebuild never blocks mail.
- **Projections** for the mail list, conversations, and calendar (reminders,
  scheduling fields) are built in the background instead of on first request.
  They are now stored in a compact binary encoding: existing projections load
  and convert themselves on first use, the unread-count projection rebuilds
  once from flags alone (it now also tracks flagged mail for follow-ups), and
  recently active users' mail and calendar projections are warmed after
  startup. Rolling back to an earlier build is safe; it cannot read the new
  encoding and rebuilds those projections in the background.
- **Encryption at rest is off by default** (`storage_encryption_default =
  false`). Existing accounts are never converted by an upgrade. If you turn
  encryption on for an account, its full-text index and list projections stop
  holding plaintext unless `search_index_encrypted_accounts` is on. Back up
  the installation key ring with your archives; there is no recovery key.
- **Backups** are scheduled (`backup_schedule`, default `off`) and may be
  age-encrypted (`backup_age_recipients`). Turn them on and verify one
  restore before relying on them.
- **Alerts** are delivered by mail or HTTP push only when you configure a
  channel; quota warning mails are on by default.

### Features that arrive switched off

Greylisting, BATV, Autocrypt, the built-in DNS server, ACME, LDAP, MCP,
ManageSieve, scheduled backups, two-factor enforcement
(`web_two_factor_required = off`), and storage encryption are all off until
you enable them. The first-run checklist on **Administration → Overview**
lists what a production server still needs.

## Webhooks: message events need an account or domain filter (2026-11-08)

`message.received` used to go to every webhook that subscribed to it, with
sender, recipients and subject for every mailbox on the server. Webhooks
now carry optional account and domain filters (`accounts`, `domains`, and
"Only for accounts / domains" in Administration → Notifications). Message
events go only to webhooks whose filter matches the receiving account or
the recipient's domain; an existing webhook without a filter stops
receiving message events until one is set, and saving a webhook that
subscribes to message events requires a filter. Server-wide events
(health alerts) are unchanged. The `message.received` payload now also
carries `account_id`, the envelope `recipient`, `cc`, `date`, `message_id`
and `size`, with decoded header values; each webhook can add headers,
text/HTML body, attachment list or the raw message (see `webhooks.md`).
