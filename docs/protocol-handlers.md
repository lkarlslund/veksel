# Protocol handlers

Every protocol adapter translates wire concepts to the same
authorization-aware `service.FolderSpace`. Handlers do not own mailbox data and
architecture tests prevent protocol packages from bypassing that boundary for
folder or item access. MIME, iCalendar, vCard, WBXML, SOAP, and JMAP conversion
remain at the adapter edge; the folder service treats item payloads as opaque.

## Current package and endpoint map

| Surface | Implementation | Default endpoint | Storage mapping |
|---|---|---|---|
| SMTP and submission | `pkg/smtp/` | TCP 25, 587, optional 465 | Accepted work enters the durable system queue; local delivery and Sent copies use FolderSpace |
| IMAP | `pkg/imap/` | TCP 143, optional 993 | Mail folders/items, flags, UIDs, metadata, ACLs, and retained changes |
| POP3 | `pkg/pop3/` | TCP 110, optional 995 | Authorized INBOX projection; deletion is committed at update-state QUIT |
| CalDAV, CardDAV, WebDAV | `pkg/caldav/` | `/dav/{account}/…` | Calendar, contacts, files, and scheduling folder types |
| JMAP | `pkg/jmap/` | `/.well-known/jmap`, `/jmap/*` | Mail, Contacts, Calendars, and Files projections, submission, vacation response, changes, and push |
| Exchange Web Services | `pkg/ews/` | `/EWS/Exchange.asmx` | Optional SOAP translation for folders/items and submission |
| Exchange ActiveSync | `pkg/eas/` | `/Microsoft-Server-ActiveSync` | Optional device/collection state over typed folders and submission |
| Client discovery | `pkg/autodiscover/` | `/autodiscover/*`, `/.well-known/*`, `/mail/*`, `/browser/*` | Non-payload account and effective protocol metadata |
| External sync sources | `pkg/migration/` | `/api/v1/sync-jobs/*` | Read-only IMAP, EWS, EAS, CalDAV, and CardDAV sources imported through FolderSpace |

`cmd/veksel/` owns process wiring, listeners, effective managed configuration,
certificate resolution, and shutdown. Protocol packages are reusable adapters;
there is no separate server or DAV data-layer package.

## Shared request path

```text
client wire request
        │
        ▼
protocol parser and authentication
        │
        ▼
actor + effective account + requested action
        │
        ▼
service.FolderSpace (RBAC, quota, cache, history, change journal)
        │
        ▼
account-routed model/store backend
```

Cross-account access is never inferred from a username or URL alone. Each
adapter supplies the immutable actor and effective subject, and FolderSpace
evaluates delegation, explicit folder rights, search grants, or identity grants
for the requested operation. Temporary account maintenance is returned as a
retryable protocol error.

## Mail transport and access

### SMTP

The SMTP server implements receiving, authenticated submission, STARTTLS and
implicit TLS, PLAIN/LOGIN/XOAUTH2, SMTPUTF8, 8BITMIME, PIPELINING, CHUNKING,
enhanced status codes, and DSN negotiation. Receiving and submission can be
enabled independently and each listener is configured through managed TOML.

Veksel acknowledges accepted mail only after the complete work item is durable
in the generic system queue. Queue workers apply routing, authentication
results, greylisting/content policy, local delivery, forwarding, direct MX or
relay delivery, retries, terminal receipts, and message-trace evidence. Local
items are created through FolderSpace rather than by the listener.

### IMAP

The IMAP server supports IMAP4rev1 and negotiated IMAP4rev2 behavior, TLS and
SASL authentication, namespace/list/status operations, fetch/search/store,
atomic append and multiappend, copy/move/expunge, IDLE, ACL, METADATA,
CONDSTORE/QRESYNC, compression, and related tested extensions recorded in the
[feature coverage](features.md). Stable folder IDs are distinct from mutable
mailbox paths; UIDs and retained folder changes are backend metadata.

### POP3

The POP3 server implements the authorization, transaction, and update states;
USER/PASS and AUTH PLAIN/LOGIN; CAPA, STLS, STAT, LIST, RETR, TOP, UIDL, DELE,
RSET, NOOP, and QUIT. It projects the authorized INBOX only. DELE marks session
state and the final removal occurs on a successful update-state QUIT.

## HTTP protocols

### DAV

One `pkg/caldav/` handler serves WebDAV base operations plus CalDAV and CardDAV
under `/dav/`. Calendar collections map to `calendar` folders and iCalendar
items; address books map to `contacts` folders and vCards; ordinary WebDAV
collections map to `files` folders and arbitrary byte payloads. Scheduling
collections, recurrence/timezone handling, sharing, sync tokens, multiget,
query, move/copy, and bounded file upload behavior use the same folder service.

DAV uses HTTP authentication on the shared HTTP/HTTPS listener. `dav_enabled`
controls mounting and `webdav_max_file_size` bounds file payloads.

### JMAP

`pkg/jmap/` provides authenticated session discovery, batched method calls,
mailbox/email/thread methods, query and retained changes, identity and
submission methods, vacation response, upload/download/blob copy, and event
source push. `/jmap/upload/{accountId}` stores blobs in the account's Files
folder and all account selection is re-authorized server-side.

JMAP for Contacts (RFC 9610) and JMAP Calendars (draft-ietf-jmap-calendars)
project the same contact and calendar collections CardDAV and CalDAV serve.
Items stay vCard and iCalendar: `jscontact.go` and `jscalendar.go` convert
to JSContact and JSCalendar on read and patch the stored object on write, so
properties the converter does not own survive. Ids are FolderSpace item and
folder ids; `/changes` reads the retained account journal filtered to the
type's collections, and `/queryChanges` reports every item changed since the
query state as removed and, when it still matches, added. An account is
visible when the actor owns or is delegated it, or can see one of its mail,
contact, or calendar folders; the session lists only the capabilities whose
collections are visible, and `myRights` comes from the authorization engine
while FolderSpace enforces every write. Event writes pass through the
automated FolderSpace, so the iMIP item observer sends invitations, updates,
and cancellations when an organizer saves a meeting.

The EventSource polls each visible account journal and emits an RFC 8620
`StateChange` naming only the types whose records moved; the first event
reports the current state of every type.

Compatibility notes: `CalendarEvent/query` does not support
`expandRecurrences`, and `sendSchedulingMessages` is ignored because
scheduling follows the server-wide `calendar_imip_enabled` setting. Calendar
`color`, `description`, `sortOrder`, and default alerts, and address-book
`description`, are not stored; set responses report the server value. Only
calendars accept `isDefault`/`onSuccessSetIsDefault`. Additional JSCalendar
locations and links beyond the first, and JSCalendar properties without an
iCalendar mapping, are not stored. WebSocket push (RFC 8887) is not offered.

### Exchange protocols

EWS and EAS are ordinary FolderSpace adapters, not storage implementations.
Their HTTP endpoints use the shared listener and authenticate each request.
The full build contains both; build tags `noews` and `noeas` remove the relevant
server and sync-source registration. Managed `ews_enabled` and `eas_enabled`
settings control included adapters at runtime. Disabled-at-build and
disabled-at-runtime states remain distinct in operational Health.

The same packages also have source clients under `pkg/migration/ews/` and
`pkg/migration/eas/`. Sync profiles are deliberately `Source → Veksel`: they do
not write back to Exchange. Source credentials may be supplied per run or kept
in the encrypted credential store for schedules and restart resume.

## Incremental state and events

JMAP changes, EWS `SyncFolderItems`, EAS collection synchronization, IMAP
QRESYNC, and DAV `sync-collection` project the atomic FolderSpace change
journal. Adapters page complete logical mutations and return their protocol's
stale-state response when retention no longer covers a client token.

The browser RPC replacement follows the same separation: commands and queries
use REST under `/api/v1`, the same handlers that administrator API-key clients
call (see [authorization](authorization.md#api-key-capabilities));
`/api/v1/events` is an authenticated same-origin
WebSocket carrying identifiers and invalidation events only. Consumers refetch
canonical REST state after reconnect or event loss.

## TLS, configuration, and diagnostics

Listener enablement, addresses, authentication choices, limits, and certificate
assignments are managed settings described in [configuration](configuration.md).
Certificates are stored separately from TOML and assigned by ID. Health reports
desired, compiled, listening, TLS/certificate, and failure state without
presenting an enabled setting as proof that a socket is running.

Protocol integration tests live beside each adapter. Broader scratch-server
scenarios exercise setup, administration APIs, SMTP routing, queueing, and local
mail delivery without relying on the browser UI.
