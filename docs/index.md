# Veksel Documentation

## Overview

Veksel is an early-development, self-hosted email and personal-data server. It
runs as one standalone Go process with embedded storage and standard protocol
adapters; no external database, queue, or object-storage service is required.

## Documents

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Design principles, high-level diagram, current package layout, data model |
| [Domain Model](design-model.md) | Current folder/item model, stable identities, accounting, indexes, and default folders |
| [Authorization](authorization.md) | Folder-oriented RBAC, delegation, impersonation, identity grants, and share links |
| [Protocol Handlers](protocol-handlers.md) | Current SMTP, IMAP, POP3, DAV, JMAP, EWS, EAS, autodiscovery, and sync boundaries |
| [IMAP4rev2 audit](imap4rev2-audit.md) | Completed RFC 9051 behavior and interoperability gate |
| [UI style guide](ui-style-guide.md) | Visual and interaction rules for the web interface: colour, type, buttons, dialogs, forms, lists, status, responsive, accessibility |
| [Webhooks](webhooks.md) | Event delivery format, signatures, account/domain scope, and the message.received payload with optional headers, body and raw message |
| [Storage Layer](storage.md) | Embedded system/account stores, production engines, conversion, caching, history, and queue durability |
| [Configuration](configuration.md) | Managed configuration schema, every setting and default, API/UI application, validation, and runtime state |
| [Default configuration](configuration-default.toml) | Exact generated TOML defaults, guarded by a code consistency test |
| [Linux deployment](deployment.md) | systemd unit, install, TLS/ACME, firewall, mail DNS, alerts, journald, backup, recovery, and upgrades |
| [Upgrade notes](upgrade-notes.md) | Behaviour changes and new defaults operators must know before upgrading |
| [Builds and Releases](releases.md) | Standalone CI/release matrix, provenance, checksums, reruns, and recovery |
| [Feature Coverage](features.md) | Broad implemented and possible-future capability coverage; not the work queue |

## Quick Reference

### What Exists Today

- Embedded Pebble and Badger production engines, independently selectable per
  account; JSON remains test/offline-diagnostic storage only.
- Typed, hierarchical folders containing opaque items for mail, calendars,
  contacts, files, notes, and scheduling collections.
- One RBAC-enforcing `service.FolderSpace` used by the web application, REST,
  SMTP, IMAP, POP3, DAV, JMAP, EWS/EAS, rules, search, and external sync.
- A durable system queue for incoming/outgoing work, account-local accounting,
  recoverable trash/history, backend conversion, search indexes, and backups.
- A unified user and administration web application with API-managed,
  comment-preserving TOML configuration and canonical operational health.

### What's Needed Next

See [Feature Coverage](features.md) for what is implemented and what is still
missing.
