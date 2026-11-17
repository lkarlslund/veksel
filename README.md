# Veksel

Veksel is a self-hosted mail and groupware server in one Go process. Mail,
calendars, contacts, tasks and files live in embedded storage (Pebble or
Badger) and are served through one authorization-aware folder/item model, so
the web app and every protocol see the same data under the same permissions.
It needs no external database, queue, or object store. Veksel is in early
development and is not production-ready yet; read the
[feature coverage](docs/features.md) before you rely on it.

## What it does

- **Protocols:** SMTP/submission/SMTPS, IMAP4rev2, POP3, ManageSieve, CalDAV,
  CardDAV, WebDAV, JMAP (Mail, Contacts, Calendars), Exchange Web Services and
  ActiveSync (both compile-time optional), autodiscovery, Apple configuration
  profiles, an MCP endpoint, and PROXY protocol behind load balancers.
- **Webmail:** an Outlook-style web app with conversations and reading
  layouts, a rich HTML composer, undo send, snooze, pin and follow-up,
  categories, rules and templates, unified search, keyboard shortcuts and
  context menus, desktop notifications, and an installable offline shell.
- **Calendar and scheduling:** meetings with local and external attendees
  (iTIP/iMIP), a scheduling assistant, proposals, reminders, recurrence, sharing
  with roles, published and subscribed calendars, ICS import/export, rooms and
  equipment, birthdays.
- **Contacts, tasks, files:** address books with groups, cards and favorites;
  VTODO tasks with subtasks; a Files workspace with previews, share links, and
  trash/history.
- **Anti-spam and mail security:** SPF, DKIM, DMARC, ARC, MTA-STS, DANE,
  TLS-RPT; weighted spam scoring with DNS blocklists, phishing, attachment and
  header checks, per-user Bayesian learning, reputation, fuzzy/bulk detection,
  spamtraps, greylisting, connection screening, BATV, SRS, ClamAV/Rspamd
  adapters, and explainable quarantine.
- **Account security:** TOTP and WebAuthn two-factor with enforcement policy,
  application passwords per protocol, LDAP/Active Directory sign-in, a
  fail2ban-like ban engine, per-account encryption at rest (opt-in), outbound
  sending limits, and OpenPGP key discovery (WKD, Autocrypt).
- **Operations:** a first-run checklist and deliverability self-test, health
  alerts by mail, webhook or push, scheduled age-encrypted backups with
  verification, DNS publishing through Cloudflare, RFC 2136 or webhook
  connectors or a built-in authoritative DNS server with DNSSEC, ACME HTTP-01
  and DNS-01 certificates, retention policies, legal hold and eDiscovery export,
  delegated domain administrators, Prometheus metrics, and live
  configuration with revision history (no restarts).

## Quick start

```sh
go build -o veksel ./cmd/veksel
./veksel --data-dir ./data
```

A fresh data directory logs a one-time `/app/setup?token=...` link; open it to
create the system owner, then follow the checklist on Administration >
Overview. The web app listens on `0.0.0.0:8472` by default. For a real
installation (systemd unit, certificates, DNS, backups) follow the
[Linux deployment guide](docs/deployment.md).

If every administrator password is lost, stop the server and run
`veksel reset-password --data-dir ./data USER`; it prints a new random password.

`--data-dir` is the only runtime bootstrap setting. Product configuration is
created at `data/config.toml` and thereafter managed through the administration
UI or REST API. Environment variables do not override server behavior.

## Documentation

| Read | For |
|---|---|
| [Linux deployment](docs/deployment.md) | Install, systemd, TLS/ACME, DNS, backups, upgrades |
| [Upgrade notes](docs/upgrade-notes.md) | New defaults and behaviour changes operators must know |
| [Configuration](docs/configuration.md) | Every setting, default, and live-apply behaviour |
| [Feature coverage](docs/features.md) | What is implemented, by area |
| [Documentation index](docs/index.md) | Architecture, storage, authorization, protocols, releases |

Veksel is free software released under the [MIT License](LICENSE).

## Development

Requirements are the Go version declared in [`go.mod`](go.mod) and a POSIX
shell. From the repository root:

```sh
./dev-restart.sh
```

The supervised development server waits until Go, template, CSS, or
JavaScript sources have been unchanged for 120 seconds, rebuilds, and restarts
only when the build succeeds. It binds `0.0.0.0:8472` by default; access it locally at
`http://127.0.0.1:8472`. Do not run a second server beside it. On a new data
directory, open the `setup pending` link from the server log and create the
first system owner.

Run the normal quality gate with:

```sh
make quality
```
