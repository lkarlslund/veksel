# Linux deployment

This guide installs Veksel on a Linux host as a hardened systemd service. Veksel
is a single static binary. It needs no database or other external service.
Everything it stores lives in one data directory. This guide uses
`/var/lib/veksel`.

Veksel is still in early development. Read the [feature coverage](features.md)
before you depend on it for real mail.

## Layout

| Path | Purpose |
|---|---|
| `/usr/local/bin/veksel` | Server binary |
| `/etc/systemd/system/veksel.service` | Unit, copied from [`deploy/systemd/veksel.service`](../deploy/systemd/veksel.service) |
| `/var/lib/veksel` | `--data-dir`: `config.toml`, system store, account stores (`accounts/`), configuration history, and `logs/` |

`--data-dir` is the only startup setting. All product settings live in
`/var/lib/veksel/config.toml` (see [Configuration](configuration.md)). You
change them in the administration UI or through the REST API. Environment
variables do not override anything, so the unit sets none.

## Order of work

A first deployment goes in this order. Each step is a numbered section below.

1. Create the service user, install the binary and the systemd unit (1-3).
2. Claim the server by creating the system owner, enrol a second factor for
   it, and work through the first-run checklist (4).
3. Set the public host name, add certificates or enable ACME (HTTP-01, or
   DNS-01 through a DNS provider for wildcards) (5).
4. Open the firewall; put a PROXY-protocol load balancer in front only if you
   have one (6).
5. Publish mail DNS (MX, SPF, DKIM, DMARC, MTA-STS, TLSA, PTR) by hand, through
   a DNS provider, or by hosting the zone on Veksel, and install a local
   DNSSEC-validating resolver for DANE and the spam blocklists (7).
6. Check logging and health (8-9), configure alert channels (9), and set up
   scheduled, age-encrypted backups outside the data directory (10).
7. Optionally connect LDAP (13), compliance policies (14), and account
   encryption at rest (off by default; see section 10).
8. Plan upgrades (12) and read the [upgrade notes](upgrade-notes.md) first.

## 1. Create the service user

```sh
sudo useradd --system --home-dir /var/lib/veksel --no-create-home \
  --shell /usr/sbin/nologin veksel
```

You do not need to create `/var/lib/veksel` yourself. The unit's
`StateDirectory=veksel` makes systemd create it with mode `0700`, owned by
`veksel:veksel`.

## 2. Install the binary

**From a release.** Download the archive for your architecture and variant
(for example `veksel_rNNNN_linux_amd64_full.tar.gz`) plus `SHA256SUMS` from the
GitHub release. Verify the checksum, then install:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf veksel_rNNNN_linux_amd64_full.tar.gz veksel
sudo install -m 0755 veksel /usr/local/bin/veksel
veksel --version
```

[Builds and Releases](releases.md) describes the variants (`full`,
`noexchange`, and others), `BUILD-INFO.json`, and full-manifest verification
with `cmd/veksel-release`.

**From source.** This needs a Go toolchain:

```sh
CGO_ENABLED=0 go build -trimpath -o veksel ./cmd/veksel
sudo install -m 0755 veksel /usr/local/bin/veksel
```

## 3. Install and start the unit

```sh
sudo install -m 0644 deploy/systemd/veksel.service /etc/systemd/system/veksel.service
sudo systemctl daemon-reload
sudo systemctl enable --now veksel
systemctl status veksel
```

What the unit does:

- Runs as `veksel:veksel` with `ExecStart=/usr/local/bin/veksel --data-dir /var/lib/veksel`.
- Grants only `CAP_NET_BIND_SERVICE` (ambient and bounding set). The default
  listeners on ports 25, 110, 143, 465, 587, 993, and 995, and the ACME
  HTTP-01 listener on port 80, can bind without root.
- Sends `SIGTERM` on stop. Veksel closes the queue and listeners before it
  exits. `TimeoutStopSec=30s` gives the drain time to finish before systemd
  sends `SIGKILL`.
- Sets `Restart=on-failure` and `LimitNOFILE=65536`.
- Applies sandboxing: `ProtectSystem=strict` with only `/var/lib/veksel`
  writable, a private `/tmp`, no devices, no home directories, no new
  privileges, kernel and cgroup protection, `MemoryDenyWriteExecute`, and a
  `@system-service` syscall filter. Sockets are limited to
  `AF_INET`/`AF_INET6`/`AF_UNIX`.

Make local changes in a drop-in (`sudo systemctl edit veksel`), not in the
shipped file. Two common cases:

- If you add an account storage root outside `/var/lib/veksel`
  (`account_storage_roots`), add `ReadWritePaths=/that/path`.
- If you point `clamd_socket` at a Unix socket owned by another service, add
  the `veksel` user to that socket's group with `SupplementaryGroups=`.

## 4. Claim the server

On first start with an empty data directory, Veksel writes a default
`config.toml` and logs a one-time setup link. The directory must exist
(systemd's `StateDirectory=` creates it); `veksel --data-dir DIR --init`
creates a missing one. Veksel refuses to start on an unknown argument or a
missing data directory, so a mistyped command never brings up a second,
unclaimed server:

```sh
journalctl -u veksel | grep 'setup pending'
```

The matching line (printed to standard error, so it reaches the journal but
never the rotating log files, which redact secrets) contains a full link such
as `http://mail.example.com:8472/app/setup?token=…`, built from the first
listener serving the web application (a wildcard bind address is replaced by
the host name). Open it and create the system owner.
Only someone holding the token can claim the server. Still, finish setup
before you expose the host more widely.

Settings marked as needing a restart take effect after:

```sh
sudo systemctl restart veksel
```

A restart requested with `POST /api/v1/admin/server/restart` drains
connections and exits with status 75; the unit's `RestartForceExitStatus=75`
makes systemd start it again. `POST /api/v1/admin/server/shutdown` exits 0 and
the service stays stopped. Both need an administrator session or API key.

### Two-factor sign-in for administrators

Do this right after claiming the server. Open **Settings → Two-factor
sign-in** and enrol an authenticator app or a security key, then store the ten
recovery codes offline. Then set `web_two_factor_required` to `administrators`
(or `all`) so that no administrator can sign in with a password alone; the
setting is `off` by default. A locked-out administrator can be recovered with
`veksel reset-password --clear-2fa` (section 11). Details are in
[configuration](configuration.md#two-factor-web-sign-in).

### First-run checklist and deliverability self-test

After claiming the server, open **Administration → Overview**. The setup
checklist shows a live pass, warning, or fail for each step of a production
mail server, with a link to the page that fixes it:

- a hosted domain exists and the public host name (`smtp_server_name`) is a
  fully qualified domain name;
- every enabled HTTPS listener has a valid certificate (or TLS terminates at a
  trusted reverse proxy);
- MX, SPF, DKIM, and DMARC are published for every domain (the same checks as
  the domain's DNS records view, see [DNS for mail](#7-dns-for-mail));
- reverse DNS of the public address (`smtp_public_address`, or the host name's
  addresses) names the host and forward-confirms;
- outbound port 25 is reachable. This is an active probe of a public mail
  server, run only when you press **Run probe**; if it fails, relay through a
  smarthost route on port 587;
- scheduled backups are on and write outside the data directory;
- an alert channel (mail, webhook, or push) is configured;
- a local DNSSEC-validating resolver is detected (the DANE probe) and the
  blocklists accept its queries (see
  [DNS resolver for spam blocklists](#dns-resolver-for-spam-blocklists));
- your administrator account has a second factor;
- a deliverability test message has been delivered.

Results are cached for ten minutes; **Refresh** re-reads DNS and runtime state.
An item that does not apply can be dismissed (and restored) for every
administrator.

The **Deliverability self-test** below the checklist checks one sending
identity's domain: SPF for the server's public addresses, a DKIM signature made
with the active key and verified against DNS, DMARC presence and alignment,
forward-confirmed reverse DNS, and listing of the public IPv4/IPv6 addresses on
the configured DNSBL zones. Each failure explains the remedy. Enter an external
mailbox you can read to also send a DKIM-signed test message through the normal
queue; the report follows it to delivery and shows the destination, the TLS
policy used (DANE, MTA-STS, or opportunistic), and the remote server's
response. Check the received message's `Authentication-Results` header for the
receiver's own verdict. The self-test is audited and limited to a few runs per
quarter hour.

### Delegating domain administration

To let someone run one hosted domain without system access, open
**Administration → Domains**, edit the domain, and add their account under
**Domain administrators**. Set the domain's limits in the same editor first:
maximum accounts and aliases, a storage ceiling (the sum of account quotas),
the default and largest account quota a domain administrator may assign, and
default send limits. Domain administrators get a reduced console (Domains,
Accounts, Recipients, Message trace) limited to their domains and cannot
change limits, protocols, certificates, settings, or roles. Their actions are
audited under their own name with `admin_scope=domain:<name>`. See
[Authorization](authorization.md#administrative-roles) for the exact
boundaries and for the `system.admin` role.

## 5. Identity and TLS

Under Administration, set the public host name the server announces. The keys
are `smtp_server_name`, `imap_server_name`, and `pop3_server_name`; when
empty (the default) they use the machine host name, and `relay_server_name`
falls back to `smtp_server_name`. `smtp_server_name` is used for EHLO/HELO, so
set it to the host's public fully qualified name, the same name as the MX
target and the PTR record. Startup logs a `mail identity:` warning when it is
not a resolvable fully qualified name.

First-run setup asks for the public mail host name (prefilled with the machine
host name). A different, valid FQDN is saved as `smtp_server_name` only;
`imap_server_name` and `pop3_server_name` stay empty and keep deriving from the
machine host name. The value takes effect after a restart. An invalid name is
rejected before the owner is created.

Behind NAT the addresses of `smtp_server_name` may not be the public egress
address. Set `smtp_public_address` to the real egress IP (Veksel never probes
for it); the DNS guidance view and the startup `mail identity:` warnings then
verify that this address reverse-resolves to `smtp_server_name` and that the
name resolves forward to the same address (FCrDNS).

Certificates are managed under Administration → Certificates. Each listener's
certificate setting names an assignment:

- `stored:NAME` is a certificate you uploaded (PEM certificate and key).
- `acme:DOMAIN` is a Let's Encrypt certificate that Veksel obtains and renews.

To use ACME, set `acme_enabled = true`, `acme_accept_tos = true`,
`acme_email`, and `acme_domains` (a list of host names). Veksel answers HTTP-01
challenges on `acme_http_listen`, which defaults to `0.0.0.0:80`, so port 80
must be reachable from the internet. `acme_directory_url` defaults to Let's
Encrypt production. ACME refuses to start unless the subscriber agreement is
accepted and at least one domain is listed.

When a DNS provider covers a host name (see [Publishing records through a DNS
provider](#publishing-records-through-a-dns-provider)), Veksel issues that
certificate with DNS-01 instead: it publishes the `_acme-challenge` TXT record,
waits until every authoritative nameserver serves it (up to
`acme_dns_propagation_seconds`, default 120), and removes it afterwards. DNS-01
needs no inbound port 80 and is the only way to get wildcard certificates, so
`acme_domains` may list `*.example.com` and listeners may use
`acme:*.example.com`. `acme_challenge` picks the challenge per certificate:
`auto` (the default) uses DNS-01 when a provider covers the name and HTTP-01
otherwise, and overrides such as `auto, mail.example.com=http-01` pin one
certificate. A wildcard cannot use HTTP-01. DNS-01 certificates are issued in
the background, renewed 30 days before expiry, and cached in the store.

Assign the certificate in these settings:

| Setting | Listener |
|---|---|
| `smtp_certificate` | SMTP STARTTLS on 25/587 and implicit TLS on 465 (`smtp_implicit_tls_enabled`) |
| `imap_certificate` | IMAP STARTTLS on 143 and IMAPS on 993 |
| `pop3_certificate` | POP3 STLS on 110 and POP3S on 995 |
| `managesieve_certificate` | ManageSieve, if enabled |
| `certificate` on an `[[http_listeners]]` entry with `transport = 'https'` | Web UI, DAV, JMAP, EWS, EAS, autodiscovery |

The implicit-TLS listeners (993, 995, 465) stay down until a certificate is
assigned. For the web UI, add an HTTPS listener in Administration, for example
on `0.0.0.0:443`. You can enable HSTS on that listener. After that, either
disable the plain `default-http` listener on 8472 or keep it reachable only
from trusted networks.

### Installable web app, notifications, and security headers

Browsers only install the web app, register its service worker, and show
desktop notifications on a secure origin: serve the web UI over HTTPS (or
reach it as `localhost`). Plain-HTTP access keeps working, without the
install prompt or offline page.

Veksel serves these public files; a reverse proxy must pass them through
unchanged and must not cache them longer than `Cache-Control: no-cache`
allows:

| Path | Content type | Notes |
|---|---|---|
| `/app/manifest.webmanifest` | `application/manifest+json` | Name, `/app/` scope, icons, theme colors |
| `/app/sw.js` | `text/javascript` | Service worker; `Service-Worker-Allowed: /app/`; its own policy `default-src 'self'` |
| `/app/offline` | `text/html` | Offline fallback; `default-src 'self'; frame-ancestors 'none'`, no inline script or style |

The worker's scope is `/app/`. It precaches only the content-versioned
`/static/` shell and the offline page, never intercepts `/api/`, `/dav/`, or
cross-origin requests, and never stores page HTML or API responses. Every
asset change produces a new worker script, so an upgrade installs the new
shell and deletes the old one. The offline page shows a bounded read-only copy
(20 recently opened messages, today's agenda) that the signed-in page writes
to the browser's Cache Storage for the person's own folders only; it is not
written while working as another account and is deleted on sign-out.

The app shell itself sends no Content-Security-Policy. If your proxy adds
one, allow at least `script-src 'self'`, `worker-src 'self'`,
`manifest-src 'self'`, `media-src 'self'` (notification sound),
`img-src 'self' data: blob:`, `connect-src 'self'` with your `wss:` origin
for the event stream, and `style-src 'self' 'unsafe-inline'` (the web app
sets inline styles).

## 6. Firewall

Open only what you use:

| Port | Purpose | Setting |
|---|---|---|
| 25/tcp | Inbound mail from other servers | `smtp_listen` |
| 587/tcp | Client submission (STARTTLS) | `smtp_submission_listen` |
| 465/tcp | Client submission (implicit TLS), off by default | `smtp_tls_listen` |
| 993/tcp, 143/tcp | IMAP | `imap_tls_listen`, `imap_listen` |
| 995/tcp, 110/tcp | POP3 | `pop3_tls_listen`, `pop3_listen` |
| 4190/tcp | ManageSieve, off by default | `managesieve_listen` |
| 443/tcp (or your choice) | HTTPS web, DAV, JMAP, EWS, EAS | `[[http_listeners]]` |
| 8472/tcp | Default plain HTTP listener | `[[http_listeners]]` `default-http` |
| 80/tcp | ACME HTTP-01 challenges | `acme_http_listen` |
| 53/udp, 53/tcp | Built-in authoritative DNS server, off by default | `dns_server_listen` |

Example with `ufw`:

```sh
sudo ufw allow 25,80,443,587,993/tcp
```

Direct delivery needs outbound TCP 25 (`smtp_direct_mx_enabled`). Many cloud
providers block it. If yours does, set `relay_host`, `relay_port`, and
credentials to send through a smart host. Keep `pprof_listen` empty, or bound
to loopback. It has no authentication.

Veksel bans abusive clients itself (Admin → Bans): repeated failed logins or
second factors on any protocol, unknown-recipient harvesting, and SMTP command
errors ban the client network for an escalating duration, and banned clients
are refused at connection accept and HTTP request entry. No fail2ban jail or
log parsing is needed. Add shared office or carrier NAT addresses, webmail or
sync gateways, and monitoring hosts to `mail_connection_limit_exempt`, and
reverse proxies to `http_trusted_proxies`, so they are never banned; behind a
load balancer, enable the PROXY protocol or trusted proxies first, or the
balancer's own address is the one counted. See
[Abuse auto-ban](configuration.md#abuse-auto-ban).

### Behind a TCP load balancer (PROXY protocol)

When mail ports reach Veksel through HAProxy, nginx `stream`, a cloud network
load balancer, or container port publishing that rewrites source addresses,
have the proxy send a PROXY protocol header so rate limits, greylisting, SPF,
blocklists, logs, and audit see the real client. Enable it for the affected
listeners and trust only the proxy addresses (Administration → Settings, or
`data/config.toml`):

```toml
mail_proxy_protocol = ["smtp", "imap"]          # or e.g. ["smtp-relay", "imaps"]
mail_proxy_protocol_trusted = ["10.0.0.5"]      # the load balancer(s)
```

A trusted proxy must then send the header on every connection; direct clients
from other addresses keep working with their own address, and are disconnected
if they try to send a header themselves. Do not list networks that untrusted
clients can connect from.

HAProxy (version 2 header; `send-proxy` sends version 1):

```haproxy
frontend smtp
    mode tcp
    bind :25
    default_backend veksel_smtp

backend veksel_smtp
    mode tcp
    server veksel 10.0.0.10:25 send-proxy-v2 check

frontend imaps
    mode tcp
    bind :993
    default_backend veksel_imaps

backend veksel_imaps
    mode tcp
    # The header precedes TLS; Veksel terminates TLS itself.
    server veksel 10.0.0.10:993 send-proxy-v2 check
```

HAProxy health checks send the header too while they use the server's own
address and port; a check with a separate `port` or `addr` needs
`check-send-proxy`, or Veksel refuses and logs it.

nginx `stream` (version 1 header):

```nginx
stream {
    server {
        listen 25;
        proxy_pass 10.0.0.10:25;
        proxy_protocol on;
    }
    server {
        listen 993;
        proxy_pass 10.0.0.10:993;
        proxy_protocol on;
    }
}
```

## 7. DNS for mail

Add each mail domain under Administration → Domains. Replace `example.com`,
`mail.example.com`, and `192.0.2.10` with your own values.

| Record | Example | Notes |
|---|---|---|
| A / AAAA | `mail.example.com. A 192.0.2.10` | The host name clients and other servers connect to |
| MX | `example.com. MX 10 mail.example.com.` | One per hosted domain |
| SPF (TXT) | `example.com. TXT "v=spf1 mx -all"` | Authorizes your MX host to send for the domain |
| DKIM (TXT) | `SELECTOR._domainkey.example.com. TXT "v=DKIM1; k=rsa; p=…"` | Copy the exact name and value from Administration → Domains → DKIM after you stage a key. Activate the key once the record resolves. |
| DMARC (TXT) | `_dmarc.example.com. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"` | Begin with `p=none` while you check alignment |
| PTR (rDNS) | `10.2.0.192.in-addr.arpa. PTR mail.example.com.` | Set at your hosting provider. Must match the A record and `smtp_server_name`. |
| openpgpkey (CNAME) | `openpgpkey.example.com. CNAME mail.example.com.` | Optional, expected while `wkd_enabled` is on: the OpenPGP Web Key Directory advanced method. An A/AAAA record to the server works too, and the HTTPS certificate for that host name must be served. Without it, clients fall back to the direct method on `example.com` itself. |

After adding a domain, open Administration → Domains → DNS records (the ⌖ action) to see every expected record for that domain with copy buttons and a live status (ok, missing, mismatch, error) checked from the server's resolver. DMARC and PTR are suggestions you publish yourself; PTR is set at your IP provider.

The DKIM view also walks you through key rotation: stage a key, publish the
record, activate it, then retire the old key. Veksel checks SPF, DKIM, and
DMARC on inbound mail (`spf_policy`, `dkim_verify_policy`, `dmarc_policy`).
For optional outbound reporting, see the MTA-STS and TLS reporting sections of
[Configuration](configuration.md).

### Publishing records through a DNS provider

Instead of copying records by hand, connect the zone to a DNS provider from the
same DNS records view (**Connect DNS provider…**). One provider connection
covers a zone apex and every hosted domain below it. Three connectors exist,
plus Veksel' own DNS server (see [Hosting DNS on Veksel](#hosting-dns-on-veksel)):

| Provider | Settings | Credential |
|---|---|---|
| Cloudflare | optional `zone_id` (looked up from the zone name otherwise) | API token with Zone → DNS → Edit for the zone |
| RFC 2136 dynamic update | `server` (primary, `host[:port]`), `key_name`, `algorithm` (default `hmac-sha256`) | base64 TSIG secret; the server must allow that key to update the zone |
| Generic webhook | `url` | optional bearer token |

The webhook connector lets any other DNS service be bridged by a small HTTP
endpoint: `GET URL?zone=Z&name=N&type=T` returns `{"records":[...]}`, and
`POST URL` receives `{"action":"upsert"|"delete","zone":Z,"record":{...}}`,
where a record is `{"id","type","name","value","ttl"}` and listed IDs are passed
back unchanged.

Credentials are encrypted with the installation's stored-credential key (the
one that protects sync credentials and rotates with it), are never returned by
the API, and are never written to logs or audit details.

**Publish records…** compares the expected MX, SPF, DMARC, and DKIM records with
what the provider serves and shows each as create, update, unchanged, conflict,
or delete. Nothing changes until you apply. Veksel records which records it
created and only updates or deletes those; a record it did not create (for
example an existing SPF policy) is a conflict and is replaced only when you
tick the confirmation. Records Veksel did not create are never deleted. An SPF
record the guidance already accepts as authorizing the server, any DMARC policy,
and a DKIM record with the same public key all count as unchanged.

With a provider connected, DKIM rotation publishes itself: staging a key
publishes its selector, the retiring key's record stays published through the
overlap, and retiring (deleting) the old key removes its record. Every change is
audited (`dns.record.create`, `dns.record.update`, `dns.record.delete`,
`dns.record.failed`), and a failed publish or rotation publish turns the
"DNS provider publishing" health component degraded, which raises a health alert
until a later change in that zone succeeds.

The same connection enables ACME DNS-01 certificates (see
[Identity and TLS](#5-identity-and-tls)).

**Outbound DANE needs a local validating resolver.** Veksel enforces RFC 7672
DANE for direct MX delivery only when it can trust DNSSEC answers, which
means a DNSSEC-validating resolver on loopback: for example unbound, or
systemd-resolved with `DNSSEC=yes` in `/etc/systemd/resolved.conf`, listed as
a loopback `nameserver` in `/etc/resolv.conf`. Remote resolvers from
`/etc/resolv.conf` are ignored for DANE because their AD bit can be forged on
the way. To use another resolver you trust, list it in `dane_resolvers`.
Administration → Outbound TLS shows whether DANE is active and whether the
resolver passed the validation probe:

```sh
dig +dnssec isc.org SOA @127.0.0.1 | grep flags     # expect "ad"
dig dnssec-failed.org SOA @127.0.0.1 | grep status  # expect SERVFAIL
```

To publish DANE for your own inbound mail, sign the zone and add
`_25._tcp.mail.example.com. TLSA 3 1 1 <sha256 of the certificate public key>`.
Publish the next key's record before you rotate the certificate.

### Hosting DNS on Veksel

Without a DNS hosting API, Veksel can serve the zone itself, as Mail-in-a-Box
does. Choose **Veksel built-in DNS server** as the zone's provider in the DNS
records view, then enable the server in **Built-in DNS server** on the Domains
page (`dns_server_enabled`). Publishing, DKIM rotation, and ACME DNS-01 then
write to records Veksel stores and serves; **Zone records…** lists them, adds
your own (A, AAAA, CNAME, MX, TXT, SRV, CAA), and shows the SOA serial.

1. Pick two nameserver names, ideally inside the zone (`ns1.example.com`,
   `ns2.example.com`) or under another domain you control, and set them in
   `dns_server_nameservers`. Both may point at this server; a second server
   that pulls the zone by TSIG-signed AXFR (`dns_server_axfr_tsig`) adds real
   redundancy, for example BIND or Knot configured as a secondary with the
   same key:

   ```sh
   dig -y hmac-sha256:xfr-key:BASE64SECRET @mail.example.com example.com AXFR
   ```

2. Add A (and AAAA) records for those names and for the mail host with
   **Zone records…**: `ns1.example.com A 203.0.113.10`,
   `mail.example.com A 203.0.113.10`. Then publish the domain records.
3. At the registrar, set the domain's nameservers to the same names. Names
   inside the zone need glue records: give the registrar each name's address
   (often under "host records", "glue", or "register nameserver"). Check the
   delegation and the answers before relying on them:

   ```sh
   dig +norec @203.0.113.10 example.com SOA     # aa flag, from this server
   dig example.com NS +trace                     # the registrar delegates here
   ```

4. Open 53/udp and 53/tcp. The systemd unit already grants
   `CAP_NET_BIND_SERVICE`. On hosts running systemd-resolved, its stub
   listener holds 127.0.0.53:53, which blocks binding `0.0.0.0:53`: bind
   `dns_server_listen` to the public address instead (`203.0.113.10:53`) or
   set `DNSStubListener=no` in `/etc/systemd/resolved.conf`.

The server only answers for hosted zones, never recurses, rate limits UDP
responses per client network, and keeps UDP answers within 1232 bytes (larger
DKIM records go over TCP), so it is safe to expose; see
[Built-in DNS server](configuration.md#built-in-dns-server).

**DNSSEC.** Enable `dns_server_dnssec` once the delegation works. Answers are
then signed online with each zone's ECDSA P-256 key. **Zone records…** shows
the DS record (key tag, algorithm 13, digest type 2) to enter at the
registrar; add it only after signing is on and `dig +dnssec example.com SOA
@203.0.113.10` returns RRSIG records. To roll the key, **Stage new key**, add
the new DS record at the registrar next to the old one, wait at least a day,
then **Activate staged key** and remove the old DS record. Turning DNSSEC off
while a DS record is registered makes validating resolvers reject the zone:
remove the DS record first and wait for its TTL. Zone transfers are refused
while signing is on, so signed zones have no AXFR secondaries.

### DNS resolver for spam blocklists

Built-in spam scoring looks up the connecting IP, sender domains, and linked
domains in DNS blocklists (Spamhaus, Barracuda, SpamCop, PSBL, SURBL, URIBL).
These lists refuse queries that arrive through large public resolvers such as
8.8.8.8, 1.1.1.1, or 9.9.9.9, and many hosting providers forward the system
resolver to one. Veksel detects the refusal answers and reports a degraded
"Spam blocklist lookups" component on the health page instead of scoring
them, but no blocklist protection works until queries leave from your own
resolver.

Run a local recursive caching resolver that queries the root servers itself,
for example Unbound:

```sh
sudo apt install unbound    # or: dnf install unbound
```

```conf
# /etc/unbound/unbound.conf.d/veksel.conf
server:
    interface: 127.0.0.1
    access-control: 127.0.0.0/8 allow
    # No forward-zone: resolve recursively from the roots.
```

```sh
sudo systemctl enable --now unbound
dig +short 2.0.0.127.zen.spamhaus.org @127.0.0.1   # expect 127.0.0.2 / .4 / .10 test answers
```

Then set Administration → Security → "Blocklist DNS resolver" (an advanced setting)
(`antispam_dns_resolver`) to `127.0.0.1`. The change applies live and clears
the blocklist cache. High-volume sites need a commercial feed (for example a
Spamhaus Data Query Service key, configured as the zone
`<key>.zen.dq.spamhaus.net`); see
[Configuration](configuration.md#built-in-spam-scoring) for zone syntax,
thresholds, and per-symbol score overrides.

## 8. Logging with journald

Veksel writes logs to two places:

- **Console** (stderr). systemd sends this to the journal. Its threshold is
  `log_console_level` (default `info`) and its format is `log_format` (`text`
  or `json`). Both apply without a restart.
- **Built-in rotating files** at `/var/lib/veksel/logs/veksel-YYYY-MM-DD.log`.
  Its threshold is `log_file_level`, which defaults to `info`. The files
  rotate daily and are kept for 30 days. The Operations → Logging view in
  the administration UI reads these files.

```sh
journalctl -u veksel -f                  # follow
journalctl -u veksel --since today -p warning
```

Use journald as the main log. Set `log_file_level = 'off'` to stop writing
every record twice; the Operations → Logging view then has no files to show.
Otherwise keep `log_file_level` no higher than the level you want there.
Per-module thresholds are in `[log_module_levels]`. Set `log_format = 'json'`
if a log shipper reads the journal.

## 9. Health checks

These HTTP endpoints are served on the HTTP listener. They need no
authentication.

- `GET /health/live`: the process is up.
- `GET /health/ready`: Veksel is ready to serve.
- `GET /api/v1/health/ready`: per-component readiness.
- `GET /health` and `GET /api/v1/health`: overall status only. Build and
  listener details require an administrator's `X-API-Key` on `/api/v1/health`.

`GET /metrics` serves Prometheus metrics only to scrapers presenting
`Authorization: Bearer <metrics_token>`; it is disabled while `metrics_token`
is empty. See [configuration](configuration.md#diagnostics).

```sh
curl -fsS http://127.0.0.1:8472/health/ready
```

### Alert channels

Health alerts are visible in **Administration → Health** but nobody watches
that page at 3 a.m. Under the **Notifications** panel configure at least one
channel: `alert_email_recipients` (mail from the server itself, so use an
address outside this server), or `alert_notify_url` with an optional
`alert_notify_token` for an HTTP push to a chat or paging service. Use the
panel's test send to confirm delivery. Alerts cover queue age, webhook
failures, storage space, certificate expiry, failed backups and more; the
thresholds and rate limits are in
[configuration](configuration.md#alert-delivery-channels). A push URL on a
private network (for example a LAN notification server) is refused unless
`outbound_http_allow_private_networks` is turned on; see the
[upgrade notes](upgrade-notes.md).

## 10. Backups

A Veksel backup is one *installation archive*: a tar file that holds
`config.toml`, the system store (users, domains, folder catalog, policies,
queue, TLS certificates, and the ACME account and certificate cache), and every
account's mail, calendar, contact, and file data, including attachments, with
a SHA-256 manifest over all of it. Account storage roots outside
`/var/lib/veksel` are included. [Storage](storage.md#backup-and-restore)
describes the format and what is left out.

### Creating a backup

**Online.** The server keeps running. In the administration UI, open
Operations → Backup and choose Download backup. With an administrator's API
key that has the `api.read` scope (issue one under Settings → API keys):

```sh
curl -fsS -X POST -H "X-API-Key: $KEY" -o veksel-$(date +%F).tar \
  http://127.0.0.1:8472/api/v1/admin/backup/download
```

Each store is copied from its own consistent snapshot. Mail that arrives while
the backup runs can show up in one store but not another. For a single point
in time, back up offline. The archive streams as it is written. If the backup
fails partway, the server breaks the connection, so `curl -f` exits non-zero
instead of keeping a truncated file.

**Offline.** Stop the server first. The embedded stores lock their
directories, so `veksel backup` refuses to run while the server holds them:

```sh
sudo install -d -o veksel -g veksel -m 0700 /var/backups/veksel
sudo systemctl stop veksel
sudo -u veksel /usr/local/bin/veksel backup --data-dir /var/lib/veksel \
  --output /var/backups/veksel/veksel-$(date +%F).tar
sudo systemctl start veksel
```

The archive is written to a temporary file next to `--output` and renamed
only when it is complete.

Both kinds stream: memory use stays flat however large the accounts are (about
170 MB peak for a 1 GB archive in a restore drill). Each account bundle is
spooled to a temporary file before it is added, in the data directory for an
online backup and next to `--output` for an offline one, so that disk needs
room for the largest account's bundle as well as the archive. A full disk
fails the backup and removes the partial file.

Neither the download nor `veksel backup` is encrypted, even with
`backup_age_recipients` set; only scheduled archives are. Both contain the
installation key ring that decrypts encrypted accounts (see
[Account encryption keys](#account-encryption-keys)), so encrypt them before
they leave the machine.

### Scheduled backups

The server can take the online backup itself on a schedule. Set it under
Operations → Backup → Schedule settings, or in `config.toml`:

```toml
backup_schedule = "daily 03:00"          # or weekly, "sun 03:00", off
backup_directory = "/mnt/backup/veksel"   # a separate disk, NAS, or remote mount
backup_age_recipients = ["age1..."]      # optional; public keys only
backup_retention_daily = 7
backup_retention_weekly = 4
```

Times are server local time. Each run writes
`veksel-scheduled-<UTC time>.tar` (`.tar.age` when encrypted) through a hidden
temporary file that is fsynced and renamed only when complete, so a partial
archive is never left under the final name. The run first checks the
directory has room for the previous archive plus a quarter. While the archive
is written, the restore drill from `veksel backup-verify` checks the same
stream, and the stored file is read back to confirm its digest. A run that
was missed while the server was down runs once after startup. Scheduled runs,
Run now, and Download backup never overlap; a second request gets
`409 Conflict` while one runs.

Retention keeps the newest archive of each of the last
`backup_retention_daily` days and of each of the last
`backup_retention_weekly` ISO weeks, and always the newest one. It deletes
only archives the scheduler recorded writing, and only while each file still
has the recorded name and size. Other files in the directory are never
touched.

A failed or interrupted run, and no successful run for a schedule period plus
six hours, raise the `scheduled-backup` operational alert on the Health
page. Every run and every retention deletion is in the audit log. The Backup
page lists the retained archives and offers downloads only when the backup
directory is inside the data directory.

The default `backup_directory` is `backups` inside the data directory. That
protects against mistakes, not against losing the disk, and
`veksel restore --force` deletes it along with the rest of the data
directory. For disaster recovery point it at another disk, or at a mounted
NAS (NFS, SMB) or remote filesystem (for example sshfs or rclone mount) that
the `veksel` user can write. Veksel does not upload to object storage itself.

**Encryption.** With `backup_age_recipients` set, archives are encrypted with
[age](https://age-encryption.org) to every listed public key: native
`age1...` keys or OpenSSH `ssh-ed25519` / `ssh-rsa` keys. The server holds no
private key, so it cannot read its own backups, and neither can anyone who
copies the backup directory. Create a key pair on a machine you trust and
keep the private key offline, in at least two places:

```sh
age-keygen -o veksel-backup.key      # prints the public key: age1...
```

Lose every private key and the encrypted archives cannot be restored.

### Account encryption keys

Accounts can be encrypted at rest (System settings → Encrypt new accounts for
new accounts, Accounts → Storage → Convert for existing ones; see
[Storage](storage.md#encryption-at-rest)). Know where the keys are before you
rely on it:

- **The installation key ring** is stored in the system store under
  `/var/lib/veksel` (namespace `sync_job_credential_keys`). It wraps every
  account's data key, as well as stored sync passwords, TOTP seeds, and DNS
  provider secrets. It is not a separate file and not in `config.toml`.
- **Each account's data key** is in
  `<account root>/<account-id>/generations/<generation>/encryption.json`,
  wrapped by the key ring. It is useless without the key ring.
- **Backups.** Every installation archive and every system-store backup
  contains the key ring, next to the encrypted account bundles. Whoever holds
  an unencrypted archive can therefore read encrypted accounts: set
  `backup_age_recipients` for scheduled archives and encrypt manual ones
  (`age -r age1... -o backup.tar.age backup.tar`). Disk-level encryption of
  `/var/lib/veksel` still matters, because the key ring sits beside the account
  roots on a single-disk host; keep account roots on separate storage if you
  need the ring and the data apart.
- **Exported account bundles** (the administrator export API and account
  moves) of encrypted accounts are encrypted and restore only on an installation
  that has the same key ring: this one, or one restored from its archive.
- **Rotation.** Rotate installation key in the Storage panel creates a new key
  version and rewraps account data keys and sync credentials without
  rewriting mail. Retired versions are kept, so older backups still restore.
  To re-encrypt an account's data under a new data key, convert it with
  "Re-encrypt under a new account key".

If the key ring is lost (the system store is destroyed and no backup of it
survives), encrypted accounts cannot be recovered by anyone, and stored sync
passwords and two-factor seeds must be re-entered. There is no recovery key.
Restoring the system store from any archive taken after the account was
encrypted brings the key ring back; an older archive also works, because the
ring only grows and every version still decrypts what it wrapped. To check
that a backup can recover encrypted accounts, run `veksel backup-verify`: it
rebuilds every encrypted account from the archive with the archived key ring.

An encrypted account has no on-disk full-text index unless
`search_index_encrypted_accounts` is enabled, because the index would hold
plaintext terms. Web search and the web contacts list report the index as
unavailable for such accounts, and IMAP `SEARCH` scans the folder instead.

### Verifying a backup

Verify every copy you plan to rely on, preferably on the machine where you
store it:

```sh
veksel backup-verify --input veksel-2026-10-21.tar
```

This checks every digest, parses `config.toml`, verifies the system store, and
rebuilds each account in a scratch directory (`--temp-dir`, default the system
temporary directory) and runs the account integrity check on it. It changes
nothing and prints the manifest as JSON. Operations → Backup → Verify backup
does the same for an uploaded file of up to 500 MB. Every command exits
non-zero on failure, including for a truncated or modified archive.

The digests catch damage such as truncation, bit rot, or a partial copy. They
do not prove who wrote a plain archive, because whoever can change the
archive can rewrite its manifest as well. Age-encrypted archives are
authenticated, so tampering with them fails decryption.

Encrypted archives are recognized from their header. Pass the private key
with `--identity`; it accepts an age identity file or an unencrypted OpenSSH
private key:

```sh
veksel backup-verify --input veksel-scheduled-20261021T010000Z.tar.age --identity veksel-backup.key
```

The upload form cannot verify encrypted archives, because the server has no
private key.

The archive contains password hashes, TLS private keys, and all mail. Store it
encrypted and with restricted access.

### Disaster recovery

To rebuild a lost server on a fresh host:

1. Create the service user and install the same or a newer Veksel release
   (sections [1](#1-create-the-service-user) and
   [2](#2-install-the-binary)). An older release refuses archives with a
   newer schema.
2. Install the unit as in section [3](#3-install-and-start-the-unit), but do
   not start it yet. Create the empty data directory:

   ```sh
   sudo install -d -o veksel -g veksel -m 0700 /var/lib/veksel
   ```

3. Copy the archive to the host and verify it:

   ```sh
   sudo -u veksel /usr/local/bin/veksel backup-verify --input /var/backups/veksel/veksel-2026-10-21.tar
   ```

   For an encrypted scheduled archive, copy the private key to the host as
   well, readable only by the `veksel` user, and add `--identity`:

   ```sh
   sudo install -o veksel -g veksel -m 0400 veksel-backup.key /root/veksel-backup.key
   sudo -u veksel /usr/local/bin/veksel backup-verify \
     --input /mnt/backup/veksel/veksel-scheduled-20261021T010000Z.tar.age \
     --identity /root/veksel-backup.key
   ```

4. Restore it into the empty data directory:

   ```sh
   sudo -u veksel /usr/local/bin/veksel restore --data-dir /var/lib/veksel \
     --input /var/backups/veksel/veksel-2026-10-21.tar
   ```

   An encrypted archive takes the same `--identity` option. It is decrypted
   while it is read; no plaintext copy is written outside the data directory.
   Delete the key from the host when the restore is done.

   `restore` refuses a directory that already holds data, and an account root
   from `config.toml` that already holds accounts. It checks this, and the
   whole archive, before it writes anything. If you have to overwrite, add
   `--force`: it then deletes the directory's contents and any account
   directories in the configured account roots. The archive is extracted
   inside the data directory, so the disk needs room for about twice the
   archive size.

   If an account root in `config.toml` uses an absolute path, restore creates
   it, so it must be writable by the `veksel` user. When the new host lays out
   its disks differently, move the root with `--account-root ID=PATH`
   (repeatable; the root IDs are in `account_storage_roots`). The restored
   `config.toml` records the new path:

   ```sh
   sudo -u veksel /usr/local/bin/veksel restore --data-dir /var/lib/veksel \
     --input /var/backups/veksel/veksel-2026-10-21.tar \
     --account-root archive=/srv/veksel-archive
   ```

   If the restore fails after it started writing, for example because the
   disk filled up, it removes what it wrote and leaves the data directory
   empty, so you can fix the cause and run it again.
5. Start the server and check it:

   ```sh
   sudo systemctl start veksel
   journalctl -u veksel -n 50
   curl -fsS http://127.0.0.1:8472/health/ready
   ```

6. Sign in as an administrator. Check that users, domains, and certificates
   are listed, and open a mailbox over IMAP or in the web client. Search
   indexes rebuild in the background after the first start.

   Mail clients resynchronize in full on their next connection. The backup
   is older than what they last saw, so the restore gives every folder a new
   IMAP `UIDVALIDITY` and expires CalDAV, CardDAV, JMAP, and ActiveSync sync
   state (see [Storage](storage.md#backup-and-restore)); otherwise clients
   would keep mail the server no longer has under reused message numbers.
   Expect the first sync of large mailboxes to take a while, and anything that
   arrived after the backup to be missing.
7. If the new host has a different IP address, update the DNS records from
   section [7](#7-dns-for-mail), and the firewall from section
   [6](#6-firewall).

**Restore drills.** A restored server is a full copy: it retries the queued
outbound mail, fetches external accounts, sends alerts and webhooks, and runs
scheduled backups into the same `backup_directory`. For a drill on a second
host, keep it off the network or, before you start it, edit the restored
`config.toml` to turn off `backup_schedule` (or point `backup_directory`
elsewhere) and the outbound services you do not want to run twice.

The online restore endpoint (`POST /api/v1/admin/backup/restore`) only
replaces the system store of a running server, using a
`POST /api/v1/admin/backup/download?scope=system` archive. It rejects
installation archives.

Use [scheduled backups](#scheduled-backups) for routine copies. For a single
point in time, run the offline command in a maintenance window, from a systemd
timer or cron job.

## 11. Lost administrator password

`reset-password` needs exclusive access to the store, so stop the service
first. Run it as the `veksel` user so file ownership stays correct:

```sh
sudo systemctl stop veksel
sudo -u veksel /usr/local/bin/veksel reset-password --data-dir /var/lib/veksel USER
sudo systemctl start veksel
```

It prints a new random password. If you leave out `USER`, it prints the list
of user IDs instead.

If the owner has lost their authenticator app, security keys and recovery
codes, add `--clear-2fa` to remove every second factor as well; add
`--keep-password` to remove only the factors and leave the password as it is:

```sh
sudo -u veksel /usr/local/bin/veksel reset-password --data-dir /var/lib/veksel --clear-2fa --keep-password USER
```

The reset is recorded in the audit log. When `web_two_factor_required` covers
the account, the next sign-in walks the user through enrolling a new factor.

## 12. Upgrading

```sh
sudo systemctl stop veksel
sudo -u veksel /usr/local/bin/veksel backup --data-dir /var/lib/veksel \
  --output /var/backups/veksel/veksel-pre-upgrade-$(date +%F).tar   # recommended
sudo install -m 0755 veksel /usr/local/bin/veksel
sudo systemctl start veksel
journalctl -u veksel -n 50
```

Read the [upgrade notes](upgrade-notes.md) before every upgrade; they list
behaviour changes and new defaults. Things to expect after the first start of
a newer release:

- Full-text search indexes are rebuilt in the background when the index
  mapping version changes. Search results fill in as the rebuild progresses;
  mail delivery and the protocols stay available.
- Mail list and calendar projections (previews, conversations, reminders,
  scheduling fields) are rebuilt in the background rather than on first
  request, so large mailboxes may be slow to list for a short while.
- Encryption at rest is off for existing accounts and stays off for new ones
  unless `storage_encryption_default` is set; upgrading never encrypts or
  decrypts data by itself.
- New protection settings (attachment policy, connection screening, ban
  engine, spam scoring) arrive with their documented defaults. Review the
  Health page and the upgrade notes after the upgrade.

The system store records its schema version. A release refuses to start on a
store written by a newer release and logs `system store schema is newer than
this binary supports`. A newer release upgrades an older store when it starts,
and upgrades a system backup from an older release as it restores it.
Upgrading to system schema 3 retires the per-user API key that older releases
stored on the user record; clients using one must switch to a named key (see
[authorization](authorization.md#api-key-capabilities)).
Keep the pre-upgrade backup until the new release is running normally. To roll
back, stop the service, put back the old binary, and restore the pre-upgrade
backup with `veksel restore --force`.

## 13. Directory integration (LDAP / Active Directory)

Veksel can sign users in with their LDAP or Active Directory password and
create their accounts on first sign-in. Keep the owner as a local account: local
accounts never depend on the directory, so administration keeps working when
the directory is down or misconfigured.

1. Create a read-only service account that can search the user subtree and
   read the administrator group, for example
   `CN=veksel,OU=Service Accounts,DC=example,DC=com`.
2. Add the mail domains under **Domains** first. Directory addresses are only
   added on hosted, enabled domains.
3. Under **Administration → Directory (LDAP)**, set the servers
   (`ldaps://dc1.example.com`, `ldaps://dc2.example.com` for failover), the
   service account DN and password, and the user search base. Leave the
   default filters for Active Directory; for OpenLDAP the defaults match
   `uid` and `mail`. If the directory uses a private CA, paste its PEM
   certificate under the advanced settings.
4. Optionally set the administrator group DN. Its direct members get
   administration: the system owner role by default, or the narrower system
   administrator role (no owner or role assignment, backup restore, or raw
   configuration) when **Administrator group role** is `admin`. Only a system
   owner can change either setting; restrict who can change the group in the
   directory.
5. Click **Test connection**. It connects, binds as the service account, runs
   a sample search and reads the administrator group, and shows each step.
6. Enable directory accounts, review the change plan and apply it. The change
   is live; no restart is needed.

Users then sign in to the web interface, mail clients and DAV clients with
their directory login (user name, UPN or email address) and password. Mail
clients may also use application passwords, which keep working while the
directory is unreachable. Passwords are changed in the directory, not in Veksel.

The hourly sync (`ldap_sync_interval_minutes`) refreshes names, addresses and
the administrator role, and disables accounts removed or disabled in the
directory; their mail and files are kept, and the account is enabled again if
the entry returns. Run **Sync now** after bulk changes. Port 636 (LDAPS) or
389 with StartTLS must be reachable from the Veksel host. See
[configuration](configuration.md#ldap-directory-accounts) for every setting.

## 14. Compliance: retention, legal hold, and eDiscovery

**Administration → Compliance** holds the three compliance tools. System
administrators see every policy and hold; domain administrators see those of
their domains.

**Retention policies.** Add a policy to delete, or move to Archive, mail older
than a number of days, for the installation, a domain, or an account, and for
all mail folders, one special folder, or a folder path pattern. The most
specific policy applies; users see it under **Properties…** on a mail folder.
The background job runs every `retention_job_interval` (six hours by default),
resumes after a restart from the last completed account, and records each pass
in the audit log (`retention.run`); **Run retention now** starts a pass at
once. Start with archive policies or long delete ages, since deletion by
retention cannot be undone.

**Legal hold.** Place a hold on an account or domain with a case ID or reason
and, optionally, an end date. From then on nothing the account owns can be
destroyed: users can still delete mail, but it moves to a hidden preserved
state (**Preserved deletions** on the hold lists it), retention skips the
account, and deleting the account is refused. Releasing the hold lets the next
retention pass finish the deferred deletions. Domain administrators can place
holds only when `legal_hold_domain_admins` is on. Holds are kept in the system
store and survive restarts and restores from backup.

**eDiscovery export.** Choose an account or domain, an optional date range,
participants, and keywords, and download a ZIP of matching messages as `.eml`
files, including trash and preserved deletions. `manifest.json` lists every
message with its account, folder, dates, hold state, and SHA-256, so the
export can be verified independently. Exports stream with bounded memory, stop
at the chosen message limit (marked `truncated` in the manifest), and are
audited as `ediscovery.export`. Keyword search uses the account search index
when it is ready and a slower folder scan otherwise. See
[configuration](configuration.md#retention-and-legal-hold-settings) for the
settings and exact semantics.
