# Storage and consistency

Veksel separates global control-plane data from account data. Global domains,
identities, routing, configuration references, and the durable system queue use
the configured system backend. Each account lives in its own directory with a
manifest and independently selectable storage generation.

## Generic store contract

`store.Store` is a namespace-scoped key/value interface whose values are opaque
bytes. It provides get, set, insert-if-absent, delete, list, prefix scan,
namespace lifecycle, and close operations. Production account engines must
also provide atomic `store.Batch` semantics because a visible folder mutation
and its incremental change record are one commit.

| Backend | Implementation | Intended use |
|---|---|---|
| `pebble` | `pkg/store/pebblestore` | Default embedded LSM engine |
| `badger` | `pkg/store/badgerstore` | Interchangeable embedded engine |
| `json` | `pkg/store/jsonstore` | Debug/test engine with atomic disk batch journal |

JSON remains useful for inspectable tests, but it is not an account engine
offered for normal deployment. Its batch implementation publishes changed
namespaces atomically and recovers an interrupted disk journal when reopened.

`model.TypedStore` adds typed JSON serialization, namespace creation, indexes,
and model-specific stores without exposing backend details to consumers.

## Account layout and lifecycle

The account catalog discovers directories under the accounts root. Each
manifest identifies the account, addresses, active generation, engine, and
conversion state. A generation owns the index database and object storage.
Live conversion builds a new generation, fences the account, switches the
manifest atomically, and keeps other accounts available. Protocols receive a
temporary-unavailable response while that one account is fenced; incoming mail
remains durable in the system queue for retry.

The account manager leases an open generation for each operation. Idle
generations are closed only when no lease is held and reopen transparently on
the next acquisition. This bounds file descriptors and backend memory without
making storage lifecycle visible to protocol adapters.

## Encryption at rest

Each account can be encrypted at rest. Encryption is a property of an account
generation, so it is turned on, turned off, or re-keyed by the same verified
generation conversion that changes engines; it is never a restart setting.

### Key hierarchy

| Key | Where it lives | Purpose |
|---|---|---|
| Installation key ring (KEK) | System store namespace `sync_job_credential_keys`: versioned random AES-256 keys, one active | Wraps every account data key, stored sync credentials, TOTP seeds and DNS provider secrets (`pkg/keyring`) |
| Account data key (DEK) | `generations/<generation>/encryption.json` in the account directory, as a keyring envelope | 256 random bits per generation; HKDF-SHA256 derives independent value, key-name, and stream subkeys (`pkg/dek`) |
| Bundle key | Header of an encrypted account bundle, wrapped by the KEK | Random per export |

A DEK is wrapped with AES-256-GCM under the active KEK, with the generation ID
bound as associated data, so a key file copied to another generation does not
open. The manifest records `encrypted`, so a deleted key file is reported as a
mismatch instead of ciphertext being read as plaintext. Opening an encrypted
account without the key ring, or with a ring that lacks the wrapping key
version, fails with an explicit error.

### What is encrypted

`pkg/store/cryptstore` decorates the account engine (Pebble or Badger), so
every backend gets the same behavior, including atomic batches, stable views,
iteration, compaction, and `store.WithoutSync` marks, which pass through to
the engine's own batch.

- **Values.** Every index value is sealed with XChaCha20-Poly1305 under a
  random 192-bit nonce (41 bytes of overhead). The associated data is the
  namespace and the logical key, so a ciphertext moved to another record
  fails authentication. Compare-and-swap compares plaintext and then swaps on
  the exact stored ciphertext, so a concurrent writer still loses.
- **Payloads.** The object store seals each payload as a chunked
  XChaCha20-Poly1305 stream (64 KiB chunks, counter and final-chunk flag in
  the nonce, so truncation, reordering, and extension are detected), bound to
  its segment and offset. The segment record carries an opaque header instead
  of the item ID, folder ID, and content type. An object reference keeps the
  logical length and SHA-256, which live only inside the encrypted index, plus
  the stored ciphertext length and digest.
- **Sensitive key names.** Engines order and prefix-scan keys, so key names
  stay plaintext except for families that embed user-chosen or correspondent
  text (`model.ProtectedKeyFamilies`): `items` `name:<folder>:<resource name>`
  (DAV hrefs and file names), `acl` `<folder>:<grantee>`, and
  `vacation_replies` `<user>:<sender>`. Their leading segments stay plaintext
  and the rest is deterministically encrypted (SIV: HMAC-SHA256 tag as the
  AES-256-CTR IV), which keeps point lookups working. The decorator restores
  logical keys and their lexicographic order on every list, scan, and
  iteration, buffering at most one family block at a time, and a scan prefix
  that reaches into an encrypted tail is answered by scanning its block and
  filtering.

### What remains visible

Inside the account directory: namespace names; opaque item, folder, history
and change IDs; folder-path and owner index entries, which are SHA-256 digests;
external-ID index entries, also digests; UID, mod-sequence and internal-date
index keys (so per-folder item counts and message dates); record and payload
sizes; and file timestamps. The manifest stays plaintext: account ID, login,
display name, addresses, engine and state.

Outside the account directory, the system store is not encrypted. It holds the
user directory, the folder catalog used for authorization (folder names),
policies, the delivery queue and quarantine (messages in transit), message
trace and audit metadata, and the key ring itself. Veksel keeps derived copies
of encrypted accounts out of plaintext:

- The on-disk full-text search index, which would store plaintext terms and
  fields, is not built for encrypted accounts, and an existing index is
  deleted. Search reports `ErrSearchNotIndexed`; IMAP `SEARCH` falls back to
  scanning the selected folder. `search_index_encrypted_accounts` opts back in
  when the index directory is protected by other means.
- Mail-list and calendar projections in the system store
  (`folder_derived_indexes`: subjects, senders, previews, event titles) are
  sealed under the active generation's data key; a conversion changes the
  generation, so the projection is rebuilt.

### Operations

`storage_encryption_default` (live) encrypts accounts created from then on. An
existing account is encrypted, decrypted, or re-keyed with a conversion
(`POST /api/v1/admin/account-storage/{login}/conversions` with `encrypted`
and/or `rotate_key`, or Accounts › Storage › Convert): the account is fenced,
its logical image is copied into a new generation, both images are verified by
digest (and the target again after reopening), the manifest switches
atomically, and the previous generation is retained under the usual rollback
and cleanup rules. A failure rolls back to the source generation. Rolling a
conversion back restores the source engine and encryption.

Rotating the installation key (`POST /api/v1/admin/account-storage/encryption/rotate`,
or the Storage panel) activates a new KEK, rewraps stored sync credentials,
and rewraps the DEK of every encrypted generation, including retained ones,
without touching encrypted data. Each key file is replaced atomically; a
partial run leaves keys under a retired but still readable KEK and is
completed by `.../encryption/rewrap`. Retired KEKs are never deleted, so
anything sealed earlier stays readable. `GET .../encryption` reports which
KEK version wraps each account and how many are wrapped by a retired one.

### Bundles and backups

An encrypted account exports as an encrypted bundle: a
`VEKSEL-ENCRYPTED-BUNDLE-1` header line with the KEK-wrapped bundle key,
followed by the ordinary logical bundle as a chunked stream. It restores only
where the same key ring is available (the same installation, or a restore of
its system store); restoring re-encrypts it under a new DEK. Move and restore
use the same encrypted bundles, so plaintext never reaches a temporary file.
Installation archives therefore carry ciphertext bundles plus the key ring in
`system.tar.gz`; encrypt the archive itself with age to protect that key ring.
Verification restores the archived system store into a scratch store only
when an encrypted bundle needs its key ring. The user's portable data export
(ZIP) remains plaintext, because the owner requests it.

### Overhead

Measured on an AMD Ryzen AI MAX+ 395 with Pebble (`go test -bench`):

| Path | Plaintext | Encrypted |
|---|---:|---:|
| Store `Get`, 1 KiB value | 2.7–3.2 µs | 4.9–5.3 µs |
| Store `Set` without sync, 1 KiB | 2.3–2.5 µs | 6.2–6.4 µs |
| Store `Iterate`, 2,000 × 1 KiB values | 1.5–1.8 ms | 4.9–5.5 ms |
| Store `Get` of a protected key name | 1.2–1.3 µs | 4.3 µs |
| Object read, 8 KiB | 17.9 µs | 26.5 µs |
| Object read, 1 MiB | 0.74 ms (1.4 GB/s) | 1.66 ms (630 MB/s) |
| Account item list page, 100 messages, metadata | 0.87–0.91 ms | 1.31–1.69 ms |
| Account item list page, 100 × 4 KiB with payloads | 2.62 ms | 3.38–3.89 ms |
| Account item read with payload | 22–26 µs | 31–34 µs |

## Folder-space boundary

All mail, calendars, contacts, files, migration/sync, and Exchange adapters use
the authorization-aware `service.FolderSpace`. Protocol handlers never open an
account engine or model item store directly. Folders are typed containers and
items carry opaque protocol payloads plus generic metadata.

A bounded `CachedFolderSpace` decorator sits at this boundary. It caches
self-owned folder/item reads, returns deep copies, and invalidates affected
scopes only after a mutation succeeds. Entry count, approximate bytes, TTL,
hits, misses, and evictions are observable. Shared/delegated reads bypass the
cache to keep authorization revocation immediate.

Folder metadata carries versioned item-count and logical-byte counters, and
the account quota root carries their aggregate. `FolderSpace.AccountUsage`
is the authorized projection for account totals, configured limits,
accounting readiness, and per-item-type subtotals. Quota displays and APIs use
these counters; they never enumerate item identities or load payloads. Trashed
folder trees continue to count until purge, including descendants beneath a
trashed parent.

Synchronization reconciliation reads the same constant-time folder metadata.
For every completed or failed source folder, the job retains source inventory,
destination item and logical-byte totals before and after transfer, imported,
unchanged, deleted and trashed counts, checkpoint, timestamps and drift state.
It never lists destination items merely to calculate status or quota.

Terminal synchronization attempts are also copied into a dedicated run-history
namespace. These immutable, secret-free records retain policy, throughput,
source pressure, conflict, deletion, folder-fidelity and failure evidence after
the mutable job moves on to later runs. Successful final cutover runs switch the
profile to manual scheduling only after this evidence and the final checkpoint
are durable. Deleting a profile removes its run history and credential record;
the synchronized folder data remains owned by the destination account.

Stored synchronization passwords are not embedded in job records. Their
dedicated namespace contains versioned AES-256-GCM envelopes authenticated to
the job ID. The installation key ring (`pkg/keyring`, one shared instance per
system store) tracks the active and retained key versions; legacy plaintext
values are replaced after the first successful read. Rotation publishes a new
active key before rewrapping entries and keeps old versions readable, making
partial rotation and restart recoverable. The same ring wraps account data
keys (see [encryption at rest](#encryption-at-rest)).

## Optional generic item history

Every typed folder can independently enable immutable item history. This is a
FolderSpace capability, not a file-only feature: mail, calendar, contact, file,
note, and future item types use the same policy and operations. The policy can
bound retention by age, versions per item, or both. Enabling history with no
explicit bounds applies conservative defaults; configured bounds are validated
before they reach a backend.

Before update, metadata change, move, delete, trash, or restore, the current
item is captured in the same atomic backend transaction as the mutation and
its incremental change record. Creation and copy do not synthesize a previous
version. Listing versions is metadata-only; retrieving or restoring one
materializes its opaque payload. Restoring a live item preserves its identity,
folder, UID, deletion lifecycle, and protocol sequencing. If the item was
deleted, restore recreates it with a new item identity in the version's folder.
A live item that has moved to another folder produces a conflict instead of
silently crossing an authorization boundary.

History version count and logical bytes are versioned folder metadata. History
bytes count toward the account storage quota, while versions do not count as
live items. Age pruning runs at startup and daily, and the per-item bound is
enforced before each capture. Folder purge releases its retained history first.
Account integrity checks verify and can repair derived history counters.

The history namespace stores logical snapshots and secondary indexes. With an
object log, an unchanged current payload reference is reused; otherwise a new
immutable object is written. Account conversion and portable bundle export
materialize snapshots and rewrite payload references into the destination
generation, so no backend-specific or stale source reference escapes the
logical transfer boundary.

## Atomic retained change history

Every committed folder-space mutation writes one `ChangeRecord` in the same
backend batch as its domain changes. A record has a monotonically increasing
sequence, unique mutation ID, commit time, and one or more metadata-only
effects. Multi-effect operations such as moves are never split across pages.

Effects include create, update, move, destroy, trash, and restore, with folder,
UID, and mod-sequence metadata needed by protocol projections. Opaque state
tokens (`c1.<sequence>`) support scoped paging by object and folder. A token
older than the retention floor returns `ErrChangeStateExpired`, telling a
client to perform a full resynchronization instead of receiving incomplete
history.

The same history drives:

- JMAP `*/changes` state transitions;
- EWS `SyncFolderItems`, including deletes;
- Exchange ActiveSync collection sync keys and paging;
- IMAP CONDSTORE/QRESYNC changed records and `VANISHED` tombstones;
- DAV `sync-collection` tokens and deleted-resource responses.

## Durable system queue

Incoming SMTP, authenticated submissions, local/outbound delivery, forwards,
notifications, and vacation replies are persisted before acknowledgement. A
batch journal makes multi-recipient enqueue all-or-none. Startup restores
interrupted `processing` records to `pending` while retaining terminal failures
for inspection.

Retry timing and failure state are durable. A terminal failure and its delivery
status notification are committed together; the deterministic notification ID
makes recovery idempotent and prevents duplicate bounces. Empty envelope
senders do not generate DSNs, so bounces cannot loop. Administrators can retry
failed work or cancel pending/failed work through the authorized operations API
and UI. Delivered work is marked before cleanup so a cleanup interruption does
not redeliver it.

Content-scanner evidence is metadata on the same durable queue record, not a
second filtering database. Each recipient receives a bounded JSON transcript
of the engines that ran and a compact summary. Quarantine records retain the
reason type, reason, authentication result, and scanner transcript for later
inspection; message traces retain the summary. No scanner retains or persists
an additional copy of the message body.

## Durable quarantine

The system quarantine uses the same generic store contract as other control-
plane data. A versioned accounting record tracks retained entry count and
logical message bytes in constant time. Owner and chronological expiry indexes
support personal listing and bounded lifecycle work without reading every
entry or payload. Entry admission, replacement, deletion, accounting and index
changes share a backend batch.

Configured ceilings never trigger opportunistic eviction of an unexpired
message: admission returns a capacity error so SMTP queue delivery can defer.
Startup and periodic jobs remove only a bounded set of expired entries. The
administrator repair operation treats entry records as truth and reconstructs
the derived accounting and indexes after imports or interrupted maintenance.

Quarantine digest preferences, jobs, signed-action lifecycle records and the
random HMAC key are durable metadata. A job stores its exact MIME payload
before entering the system queue, uses a deterministic identity, and resumes
leased delivery after restart. Terminal jobs clear MIME data while retaining
bounded operational evidence. Action claims are immutable, expiring, owner-
scoped and replay-safe; a failed worker releases its short lease for retry.

## Schema versions

The system store records its layout version under `schema/system`
(`model.SystemSchemaVersion`). Startup and offline tools refuse a store whose
version is newer than the binary supports, before changing anything. They
upgrade an older or unversioned store and record the current version. Account
manifests carry their own `schema_version`, and account discovery rejects
manifests from a newer schema.

## Backup and restore

An installation archive is an uncompressed tar file. Its members are already
compressed, and they appear in this order:

| Member | Content |
|---|---|
| `config.toml` | The managed configuration, byte for byte |
| `system.tar.gz` | The system store as a v2 logical backup: every namespace and key, with its own SHA-256 manifest and `system_schema_version` |
| `accounts/<account-id>.tar.gz` | One portable account bundle per account, as made by account export: manifest, metadata records, items with their payloads and attachments, and item history, plus a digest of the logical image. An encrypted account's member is an [encrypted bundle](#bundles-and-backups) despite the name, and its manifest entry says `encrypted` |
| `manifest.json` | Always last. Records the format (`veksel-installation`, version 1), the creation time, the Veksel version, the system backend and schema version, the account schema version, the size and SHA-256 of every other member, and each account's ID, login, storage root ID, and engine |

The system store is read from one store view, and each account from its own
view, so each store is consistent on its own. The stores are not frozen
together, so an online backup can catch a message in the queue but not yet in
the account, or the reverse. An offline backup has no such gap. A backup fails
when account discovery reports an issue, or when an account is in the middle
of an engine conversion, rather than silently leaving the account out.

Verification reads the whole archive. It rejects unknown, duplicate, missing,
or modified members, truncated archives, archive format and schema versions
newer than the binary, and an invalid `config.toml`. It verifies the system
store backup and rebuilds every account bundle into a scratch generation,
then runs the account integrity check on it. The digests detect damage, not
forgery: someone who can rewrite a plain archive can rewrite its manifest too.
An age-encrypted archive is also authenticated by age. Data after the end of
the tar stream is ignored.

Restore requires an empty target unless forced, and every account root in the
restored configuration must hold no accounts. It extracts and verifies the
archive inside the target directory and makes all of these checks before it
writes anything, so a refused restore leaves the target as it was. Then it
writes `config.toml`, restores the system store into the engine that
configuration selects, and rebuilds each account in its recorded storage root,
or the primary root if that root is no longer configured. `--account-root
ID=PATH` moves a root to a new path and records that path in the restored
`config.toml`. Each account keeps its ID, login, and engine and gets a fresh
generation. It becomes visible only after its digest and integrity check pass.
If the restore fails after it started writing, it empties the data directory
again and deletes the account directories it created. Search indexes are
derived data and rebuild after the first start because the generation
changed.

A restored account is older than the state its clients last saw: mail that
arrived, and changes made, after the backup are gone, and the server would
otherwise hand out the same UIDs, mod-sequences, ETags, and change states
again for different content. A restore therefore rebases each account's
synchronization state. Every folder gets a greater IMAP `UIDVALIDITY` and its
mod-sequence counter jumps ahead, and the change journal jumps ahead with all
earlier states expired. IMAP clients discard their cache for each folder and
download it again; CalDAV and CardDAV sync tokens are refused with
`valid-sync-token`, JMAP `/changes` answers `cannotCalculateChanges`, and
ActiveSync reports an invalid sync key, so each client resynchronizes in full. Items
keep their IDs and UIDs. The single-account restore under Accounts → Storage
does the same.

An archive does not include logs, configuration history, retained old
generations, conversion and lifecycle job records, or search indexes. The
`attachments/` directory is not included either, because the server stores
attachments in account object storage, not there.

A scheduled backup is the same installation archive, optionally wrapped in an
[age](https://age-encryption.org) file (`.tar.age`) encrypted to the
configured recipients. Restore and verification detect the age header and
need the matching private key (`--identity`); without it they stop before
reading anything else. The scheduler's ledger of archives it wrote lives in
the `backup_schedule` namespace of the system store, so it travels with the
system store backup.
