# Veksel Architecture

Veksel is an early-development, self-hosted email and personal-data server. It
unifies mail, calendars, contacts, and files under one consistent model exposed
through standard protocols and a unified web/REST application.

## Design Principles

1. **One data model, many protocols** — Email, calendar, contacts, and files all share the same Folder → Item storage primitive. Protocols are translation layers, not data owners.
2. **Embedded all-in-one application** — No PostgreSQL, Redis, S3/object-storage
   service, external message queue, or service-backed metadata/blob tier.
   Everything required to operate Veksel runs in one process and uses
   Veksel-owned embedded storage. Multiple embedded account backends may exist
   behind the common storage boundary, but external storage services are not a
   product direction. Future compression, deduplication, or application-managed
   encryption at rest belongs inside the embedded storage/object layer and
   must remain transparent to FolderSpace and every application/protocol
   consumer above it.
3. **Standard protocols first** — Expose SMTP, IMAP, POP3, CalDAV, CardDAV,
   WebDAV, JMAP, EWS, EAS, and HTTP so existing clients can use the same data.
4. **Managed configuration** — Product settings live in a comment-preserving TOML document and are validated and changed through the administration API/UI.
5. **Independent accounts** — Each account owns a discoverable directory and storage generation, allowing engine choice and conversion per user.

All user data crosses one authorization-aware `service.FolderSpace` boundary.
Folders are typed containers, while item bytes remain opaque to the service:
MIME, iCalendar, vCard, and file payloads are interpreted only by their protocol
adapters. IMAP, POP3, SMTP/Sieve, CalDAV, CardDAV, WebDAV, EWS, EAS, and mailbox
migration therefore share the same list/get/create/update/move/copy/delete
contract and cannot couple themselves to a storage backend.

Mutating folder-space calls are recorded in a disk-backed command journal before
they are applied. Replaying that journal is idempotent, so a process restart can
finish interrupted mutations. Mail adds a delivery queue at the same durability
boundary: SMTP ingress and outbound submission are persisted before a worker
commits local delivery through `FolderSpace` or hands external delivery to the
SMTP relay.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  veksel process  │
│  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  SMTP  │  │  IMAP  │  │ CalDAV  │  │ CardDAV  │  ...  │
│  │ Listener │  │ Listener │  │ Listener │  │ Listener │  │
│  │ :25/587  │  │ :143/993 │  │ :443  │  │ :443  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│  │  │  │  │  │
│  └──────────────┴──────────────┴──────────────┘  │
│  │  │
│  ┌─────────▼─────────┐  │
│  │  Protocol Adapters│  │
│  │ (protocol → model) │  │
│  └─────────┬─────────┘  │
│  │  │
│  ┌─────────▼─────────┐  │
│  │ service.FolderSpace │  │
│  │ authz + cache + log │  │
│  └─────────┬─────────┘  │
│  │  │
│  ┌─────────▼─────────┐  │
│  │ model/ typed CRUD │  │
│  └─────────┬─────────┘  │
│  │  │
│  ┌─────────▼─────────┐  │
│  │  store.Store  │  │
│  │ (KV interface)  │  │
│  └─────────┬─────────┘  │
│  │  │
│  ┌───────────────┴───────────────┐  │
│  │ pebblestore │ badgerstore     │  │
│  └─────────────┴─────────────────┘  │
│  │
│  ┌──────────────────────────────────────────┐  │
│  │  HTTP Server (0.0.0.0:8472)  │  │
│  │  /app — unified user/admin UI │  │
│  │  /static  — embedded assets  │  │
│  │  /health  — health check  │  │
│  │  /dav/*  — CalDAV/CardDAV/WebDAV  │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Current package layout

```
cmd/veksel/  — server bootstrap, signal handling, graceful shutdown
pkg/config/  — managed, comment-preserving TOML configuration
pkg/account/ — account discovery, generations, conversion, and leases
pkg/store/  — generic KV store interface
  jsonstore/  — inspectable test/debug backend with atomic batch recovery
  pebblestore/  — Pebble LSM-tree account/system backend
  badgerstore/  — Badger account/system backend
pkg/model/  — domain types and typed CRUD wrappers
pkg/queue/  — durable inbound/outbound system queue and delivery worker
pkg/health/  — canonical runtime snapshots, cached filesystem capacity, managed policy, and durable alerts
pkg/webhook/  — durable subscription outbox, leased retry, and delivery evidence
pkg/service/ — authorized/cached folder boundary and atomic change journal
pkg/authz/  — roles, groups, bindings, delegation, impersonation, and policy evaluation
pkg/search/  — per-account Bleve indexes and rebuild/catch-up lifecycle
pkg/rules/  — protocol-neutral folder automation and retained run evidence
pkg/migration/ — resumable IMAP, EWS, EAS, CalDAV, and CardDAV source sync
pkg/smtp/  — mail transfer/submission and external relay
pkg/imap/  — IMAP4rev1/rev2 mailbox adapter
pkg/pop3/  — POP3 mailbox adapter
pkg/caldav/  — CalDAV, CardDAV, and WebDAV adapter
pkg/jmap/  — JMAP Core/Mail/submission HTTP adapter
pkg/ews/  — optional EWS HTTP adapter
pkg/eas/  — optional EAS WBXML HTTP adapter
pkg/static/  — embedded static assets (CSS, JS, fonts)
pkg/web/app/  — unified user/admin UI and the one REST control plane (session or API-key auth)
```

## Data Model

The model is intentionally flat and uniform:

- **Domain** — a managed mail domain (`example.com`)
- **User** — an account that owns folders and email addresses
- **EmailAddress** — an alias (`alice@example.com`) pointing to a user on a domain, with triple-index (by address, by user, by domain)
- **Folder** — a typed container (`mail`, `calendar`, `contacts`, `files`,
  `notes`, and scheduling types) owned by a user; stable `ParentID` forms its
  hierarchy while path remains mutable
- **Item** — a single entry in a folder, opaque `[]byte` data with headers

Folders are the universal storage primitive. An email message, a calendar event,
a contact card, and a file are all Items in differently typed Folders. Protocol
handlers translate between their native formats and this uniform model through
`FolderSpace`; direct protocol access to item storage is guarded by an
architecture test.

The system store owns global identity/configuration/policy/queue metadata and
account manifests. Each account generation owns that account's folders, items,
indexes, accounting, history, and retained changes. Visible entities may have
multiple secondary keys; callers never construct backend keys directly.

See the [domain model](design-model.md), [storage](storage.md),
[authorization](authorization.md), and [protocol handlers](protocol-handlers.md)
for the current detailed contracts.
