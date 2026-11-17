# Domain model

This document describes the current model contract. Exact serialized fields and
namespace keys remain owned by `pkg/model/`; examples here explain identities
and relationships rather than defining a second schema.

## Core invariants

1. Folders are the universal content container. Mail, calendar events,
   contacts, files, notes, and scheduling objects are opaque items in a typed
   folder.
2. A folder belongs to exactly one account. Sharing and delegation are policy,
   not duplicate storage ownership.
3. Stable opaque IDs are authorization and synchronization identities. Mutable
   names and paths are presentation/protocol attributes.
4. Protocols and the web/API layer access content through
   `service.FolderSpace`; they do not select or open account backends.
5. Each account owns a discoverable directory and active storage generation.
   Global domains, users, routes, queue state, policy, and account manifests
   live in the system store.

## Global entities

### Domain

A `model.Domain` is keyed by its normalized domain name. It carries enabled
state, creation time, outbound DKIM material/selector, and the domain scanning
switch. Domain routing and TLS policy are separate model records rather than
fields hidden in a protocol handler.

### User

A `model.User` is the account identity and owns display name, bcrypt password
hash, enabled state, timestamps, quota counters/limits, and user-level mail
features such as Sieve, forwarding, vacation response, and spam threshold.
API keys, sessions, authorization bindings, and sync profiles are separate
durable records.

The current item and logical-byte totals on the user are derived accounting,
updated with folder mutations. Zero quota limits mean unlimited. The last
enabled system owner cannot be disabled or deleted.

### Email address

A `model.EmailAddress` maps one normalized full address to a local user and
domain. It records local part, primary/enabled state, and creation time. The
email namespace maintains three lookup directions:

```text
addr:<address>   -> EmailAddress
user:<user-id>   -> addresses owned by the user
domain:<domain>  -> addresses hosted on the domain
```

This supports constant-scope recipient routing and administration lists without
scanning all aliases. Send As and Send on Behalf are explicit identity policy;
owning or knowing an address does not bypass authorization.

## Account-local content

### Folder

A `model.Folder` contains an immutable ID, owner ID, mutable name/path,
`ParentID`, type, delimiter, subscription state, system/special-use role, and
timestamps. Parent IDs—not path prefixes—form the authoritative hierarchy.
Custom folders use random `fld_…` resource IDs; built-in special-use folders
have deterministic per-account IDs so protocol and recovery code can resolve
them without depending on localized paths.

Folder types currently include:

- `mail`
- `calendar`
- `contacts`
- `files`
- `notes`
- `schedule-inbox`
- `schedule-outbox`

Mail metadata includes UIDVALIDITY, next UID, and highest MODSEQ. Calendar
folders can carry color and description. Recoverable deletion retains original
parent/path and purge timing. Current item count and logical bytes are maintained
as folder metadata, so quota and status views do not enumerate items.

Item-history policy is a generic folder capability, not a file-only feature.
When enabled, immutable snapshots and their separate count/byte accounting are
committed with updates, metadata changes, moves, deletion, trash, and restore.

### Item

A `model.Item` has an immutable ID, folder ID, optional protocol-facing name,
opaque bytes, searchable headers, logical size, and timestamps. External source
identities are namespaced in `ExternalIDs` and indexed per folder so repeated
sync runs converge without scanning or duplicating items.

Mail items additionally use UID, flags, internal date, and MODSEQ. Recoverably
trashed items retain the original folder/name and purge timing. Items are not
append-only: authorized update, move, copy, trash, restore, and purge operations
are first-class FolderSpace mutations with accounting, cache invalidation,
history, and change-journal semantics.

Large payload and MIME attachment bytes may be represented through the embedded
object/attachment layer while the public item is reassembled consistently.
That is an internal storage capability and does not change the FolderSpace API.

## Default folder set

Account bootstrap ensures the following system folders exist:

| Path | Type | Special use | Initially subscribed |
|---|---|---|---:|
| `INBOX` | mail | inbox | yes |
| `Drafts` | mail | drafts | yes |
| `Sent` | mail | sent | yes |
| `Trash` | mail | trash | yes |
| `Junk` | mail | junk | yes |
| `Archive` | mail | archive | yes |
| `Calendar` | calendar | calendar | no |
| `Contacts` | contacts | contacts | no |
| `Recent recipients` | contacts | recent-recipients | no |
| `Files` | files | files | no |
| `schedule-inbox` | schedule-inbox | schedule-inbox | no |
| `schedule-outbox` | schedule-outbox | schedule-outbox | no |

Special-use role is unique per account and can be reassigned where the service
allows it; a path string is never used as the durable role.

## Index and key principles

Model namespaces are flat key/value collections, but records are not limited to
one JSON object per visible entity. Secondary keys provide folder membership,
path/name lookup, IMAP UID/date lookup, external IDs, recoverable trash,
authorization, queue, history, and operational projections. Representative
item keys include:

```text
<item-id>                                  -> current item record
member:<folder-id>:<item-id>               -> folder membership
name:<folder-id>:<resource-name>            -> protocol name lookup
uid:<folder-id>:<uid>                       -> IMAP UID lookup
date:<folder-id>:<YYYYMMDD>:<item-id>       -> date-range lookup
external:<folder-id>:<source-hash>          -> source identity lookup
trash:<user-id>:<item-id>                   -> recoverable trash lookup
```

Callers must use model stores and FolderSpace rather than constructing these
keys. This permits index repair, engine conversion, and storage-format changes
without leaking backend layout into protocol code.

## Mutation and synchronization semantics

FolderSpace records mutations in a durable command journal before applying
them. Backend batch support groups the item, indexes, folder/account accounting,
history snapshot, and retained change record as one logical operation. Replay
is idempotent after restart.

The retained folder journal feeds IMAP QRESYNC, DAV sync tokens, JMAP changes,
EWS/EAS synchronization, browser invalidation, search catch-up, and external
sync reconciliation. If a client state predates retention, adapters return an
explicit stale-state outcome instead of inventing a partial change history.

See [storage](storage.md) for account generations and engines and
[authorization](authorization.md) for policy evaluation.
