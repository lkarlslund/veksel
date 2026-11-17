# Client compatibility matrix

This report is generated from `compatibility/matrix.toml`. A pass applies only to the named evidence tier; modeled transcripts and protocol libraries are not real-client certification.

Run declared Go probes with `go run ./cmd/veksel-compat verify`. Native application runners are explicit; for example, `go run ./cmd/veksel-compat thunderbird --binary /path/to/thunderbird --version 153.1.0esr` uses an isolated profile, display, account, and store.

| Client | Version / platform | Workflow | Protocols | Result | Evidence | Owner |
|---|---|---|---|---|---|---|
| Apple Mail | current release / macOS | mail core | autodiscover, imap, smtp-submission | pending | manual | protocols/mail |
| Apple Mail, Calendar, and Contacts | current release / iOS/iPadOS | mobile groupware | eas, caldav, carddav | pending | manual | protocols/mobile |
| curl | 8.23.0 / Linux amd64 | IMAP, POP3, and SMTP URL transfers | imap, smtp-submission, pop3 | pass | real-client | protocols/mail |
| Apple Calendar/Contacts, Thunderbird, DAVx⁵, Evolution request sequences | 2026-10 transcripts / Linux amd64 | calendar and contacts client request sequences | caldav, carddav | limited | modeled-transcript | protocols/dav |
| DAVx⁵ | 4.x / Android | calendar and contacts | caldav, carddav | pending | manual | protocols/dav |
| iOS/macOS Mail, Samsung Email, Gmail, Nine, Windows Mail (ActiveSync command replay) | 2026-10 transcripts / Linux amd64 | documented ActiveSync request sequences: provisioning, folder and item sync, push, compose, calendar, contacts, tasks | eas | pass | modeled-transcript | protocols/mobile |
| Mac Mail and Outlook for Mac (EWS command replay) | 2026-10 transcripts / Linux amd64 | batched distinguished-folder discovery, hierarchy and item sync, read state, send, recipient resolution, free/busy, calendar items with recurrence and CalendarView, meeting responses, contacts, tasks, out-of-office, attachments, pull and streaming notifications | ews | limited | modeled-transcript | protocols/exchange |
| ActiveSync clients, Outlook mobile and Windows (Autodiscover replay) | 2026-10 transcripts / Linux amd64 | POX mobilesync and Outlook schemas, Autodiscover v2 JSON | autodiscover | pass | modeled-transcript | protocols/exchange |
| go-imap/v2 | 2.0.0-beta.8 / Linux amd64 | mail protocol regression | imap | pass | protocol-library | protocols/imap |
| go-smtp | 0.24.0 / Linux amd64 | message submission regression | smtp-submission | pass | protocol-library | protocols/smtp |
| go-webdav/caldav | 0.7.0 / Linux amd64 | calendar protocol regression | caldav | pass | protocol-library | protocols/dav |
| go-webdav/carddav | 0.7.0 / Linux amd64 | contacts protocol regression | carddav | pass | protocol-library | protocols/dav |
| Thunderbird, Apple Mail, Outlook, K-9, Gmail app, Evolution (command replay) | 2026-10 transcripts / Linux amd64 | documented IMAP command sequences of desktop and mobile clients | imap | pass | modeled-transcript | protocols/imap |
| Fastmail web, Ltt.rs/jmap-mua, jmap-client (JS/Rust), Mailtemi (request replay) | 2026-10 sequences / Linux amd64 | RFC 8620/8621 request sequences of JMAP mail clients | jmap | pass | modeled-transcript | protocols/jmap |
| jmapc (Python JMAP client) | 0.4.0 / Linux amd64 | JMAP mail: session, recent threads, send with submission, push | jmap | pass | protocol-library | protocols/jmap |
| OfflineIMAP | 8.0.0 / Linux amd64 | mail synchronization to Maildir | imap | limited | real-client | protocols/imap |
| Microsoft Outlook 2024 | 2024 / Windows | Exchange and Internet mail | autodiscover, ews, imap, smtp-submission | pending | manual | protocols/exchange |
| python caldav (caldav-server-tester) | 3.6.0 / Linux amd64 | CalDAV feature and scheduling probe | caldav | limited | real-client | protocols/dav |
| Python imaplib, smtplib, and poplib | 3.12.13 / Linux amd64 | mail library sessions over STARTTLS and implicit TLS | imap, smtp-submission, pop3 | pass | protocol-library | protocols/mail |
| Roundcube Webmail | 1.7.2 / Linux amd64 | mail core | imap, smtp-submission | limited | modeled-transcript | protocols/imap |
| swaks | develop-8a05259830 / Linux amd64 | SMTP delivery and authenticated submission | smtp-submission | pass | real-client | protocols/smtp |
| Thunderbird Desktop | 153.1.0esr / Linux amd64 | mail core | autodiscover, imap, smtp-submission | limited | real-client | protocols/imap |
| vdirsyncer | 0.21.0 / Linux amd64 | calendar and contacts synchronization | caldav, carddav | pass | real-client | protocols/dav |

## Evidence and limitations

### Apple Mail — mail core

- Limitation: No current macOS runner is available; exact Mail build, account discovery, IMAP/SMTP authentication, folder operations, search, send, and IDLE remain unverified.
- Version source: <https://support.apple.com/guide/mail/welcome/mac>

### Apple Mail, Calendar, and Contacts — mobile groupware

- Limitation: No physical iOS/iPadOS device run is retained; Exchange ActiveSync provisioning and push, CalDAV, and CardDAV remain unverified in Apple applications.
- Version source: <https://support.apple.com/guide/iphone/set-up-mail-contacts-and-calendar-accounts-iph44d1ae58a/ios>

### curl — IMAP, POP3, and SMTP URL transfers

Tested 2026-10-23 at revision `01909f7`.
- Verified: imaps:// section fetch by UID, imap:// with --ssl-reqd mailbox listing and a custom UID SEARCH command
- Verified: pop3s:// LIST and pop3:// with --ssl-reqd RETR and UIDL
- Verified: smtp:// with --ssl-reqd and smtps:// authenticated submission delivered locally; a MAIL FROM of another account's address was refused
- Limitation: curl exercises single-command transfers; IDLE, flags, and multi-command synchronization are covered by the other scenarios
- Version source: <https://curl.se/changes.html>

### Apple Calendar/Contacts, Thunderbird, DAVx⁵, Evolution request sequences — calendar and contacts client request sequences

Tested 2026-10-23 at revision `ecf9871`.
- Verified: pkg/caldav TestInterop* replay the request sequences of Apple Calendar/Contacts (principal probe, home Depth 1 with getctag, MKCALENDAR with color/order, PROPPATCH, MOVE between calendars, principal-property-search, quota), Thunderbird (VTODO calendar-query, PARTSTAT change, address book rename), DAVx⁵ (multistatus content type, sync-collection, conditional writes), and Evolution (prop-filter searches, RFC 6352 addressbook-query), plus non-ASCII names, charsets, shared-calendar sync, and attendee replies
- Verified: cmd/veksel TestDAVEntryDiscovery covers PROPFIND / redirection, unauthenticated OPTIONS, and the UTF-8 Basic challenge
- Limitation: Modeled transcripts, not the applications: Apple, Thunderbird, DAVx⁵, Evolution, and GNOME Online Accounts were not executed; shared calendars are reachable by collection URL only (they are not listed in the sharee's home and calendar-proxy delegation is not implemented)
- Version source: <https://www.davx5.com/manual/technical_information.html>

### DAVx⁵ — calendar and contacts

- Limitation: No Android device or emulator run is retained; DAVx⁵'s documented request sequences (unauthenticated OPTIONS, PROPFIND discovery, home-set listing, sync-collection with getetag, multiget, If-Match writes) are replayed by the dav-client-transcripts scenario, but contact photos, conflicts, and the app's own behavior remain unverified in DAVx⁵.
- Version source: <https://www.davx5.com/manual/technical_information.html>

### iOS/macOS Mail, Samsung Email, Gmail, Nine, Windows Mail (ActiveSync command replay) — documented ActiveSync request sequences: provisioning, folder and item sync, push, compose, calendar, contacts, tasks

Tested 2026-10-23 at revision `347af49`.
- Verified: WBXML code pages match MS-ASWBXML token for token (the Settings page was shifted by two and calendar TimeZone was misnamed)
- Verified: OPTIONS, base64 request lines (Windows Mail), two-phase Provision with a policy document, 144/449 on a stale X-MS-PolicyKey, and remote wipe with acknowledgement
- Verified: FolderSync publishes only mail, calendar, contact and task folders with MS-ASCMD default types, replays a lost response, and does not echo FolderCreate
- Verified: Sync honors BodyPreference (text, HTML, MIME with MIMESupport) with truncation, previews and attachment FileReferences; client Add answers ClientId to ServerId; client changes are not echoed; DeletesAsMoves moves to Trash; server-wins conflicts; a retried SyncKey replays without duplicating Adds; empty Sync repeats the cached request
- Verified: Ping long-polls the change journal outside the partnership lock and reports changed folders; heartbeat and folder bounds return 5/6
- Verified: SendMail (WBXML and 12.1 MIME), SmartReply/SmartForward appending the original and its attachments, ClientId retry detection, 16.x draft Send
- Verified: calendar items map time zones, recurrence, exceptions, attendees and all-day events in both directions; contacts and tasks round-trip; MeetingRequest and MeetingResponse; Search (GAL, Mailbox), ResolveRecipients with availability, Settings Oof/UserInformation, GetItemEstimate, MoveItems and ItemOperations
- Verified: Veksel' own Exchange-oriented EAS migration client reads mail, calendar and contacts back through the server
- Verified: a scripted live client against a built binary (iOS 16.1 and Samsung 14.1 identities) passed provisioning, push, send/reply, attachments, meeting invitation and acceptance, contacts, base64 requests and policy enforcement
- Limitation: No physical iOS, Android or Windows client was run; the sequences are replays of documented and observed requests.
- Limitation: Not implemented: ValidateCert and S/MIME certificate retrieval, ItemOperations conversation Move, Supported (ghosted properties), Sync Partial merging, 16.1 Find beyond FreeText, Notes class, multipart ItemOperations responses, device quarantine/allow lists.
- Version source: <https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-ascmd/>

### Mac Mail and Outlook for Mac (EWS command replay) — batched distinguished-folder discovery, hierarchy and item sync, read state, send, recipient resolution, free/busy, calendar items with recurrence and CalendarView, meeting responses, contacts, tasks, out-of-office, attachments, pull and streaming notifications

Tested 2026-10-23 at revision `26c67d5`.
- Verified: batched GetFolder over distinguished folders answers each ID in order, with ErrorFolderNotFound for absent ones and a synthetic msgfolderroot
- Verified: hierarchy responses carry ParentFolderId and Default-shape counts and hide internal folders
- Verified: items carry IsRead, From, recipients, ParentFolderId and ItemClass; UpdateItem marks batches read; per-item errors replace SOAP faults
- Verified: GetUserAvailability returns merged and per-event free/busy in the request's time zone; ResolveNames searches the address list and contacts
- Verified: Outlook for Mac CreateItem meetings (local times with StartTimeZone, HTML body, attendees, weekly recurrence) are stored as iCalendar with TZID, RRULE, ORGANIZER and VTIMEZONE; scheduling goes through implicit iMIP and SendToNone silences it
- Verified: CalendarView expands recurring series into Occurrence/Exception items with occurrence IDs and pages at MaxEntriesReturned; OccurrenceItemId updates create exceptions and deletes add EXDATEs, shown as ModifiedOccurrences and DeletedOccurrences
- Verified: invitations render MyResponseType, Organizer, attendee ResponseType and ResponseObjects, Exchange 2007 clients get MeetingTimeZone instead of StartTimeZone, and AcceptItem answers through the scheduling service
- Verified: contacts and tasks round-trip as Contact (indexed email, phone and address updates, contact photo attachment) and Task (dates, status, percent complete); SyncFolderItems over calendar and contacts folders emits CalendarItem and Contact
- Verified: GetUserOofSettings/SetUserOofSettings map to the vacation responder; GetAttachment, CreateAttachment and DeleteAttachment work on message MIME parts
- Verified: pull Subscribe returns a SubscriptionId and Watermark; GetEvents maps the change journal to NewMailEvent, CreatedEvent, ModifiedEvent, MovedEvent and DeletedEvent with item and folder IDs, PreviousWatermark and MoreEvents, a StatusEvent when idle, and resumes from a Subscribe Watermark
- Verified: GetStreamingEvents holds the response open and writes a chunked SOAP envelope within 200 ms of a commit, ConnectionStatus OK keepalives, and Closed at ConnectionTimeout; Unsubscribe, unknown or lapsed subscriptions (ErrorSubscriptionNotFound), the wrong subscription kind (ErrorInvalidSubscription) and another user's subscription answer per-message errors
- Limitation: No Mac Mail or Outlook for Mac run is retained.
- Limitation: Push subscriptions and ConvertId are not implemented and CopiedEvent is never raised (a copy reports CreatedEvent); subscriptions are in memory and lost on restart, so clients resubscribe; meeting requests in the Inbox are messages (no MeetingRequest type); calendar item and task attachments are not supported.
- Version source: <https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/ews-operations-in-exchange>

### ActiveSync clients, Outlook mobile and Windows (Autodiscover replay) — POX mobilesync and Outlook schemas, Autodiscover v2 JSON

Tested 2026-10-23 at revision `347af49`.
- Verified: a mobilesync POX request is challenged, then answered in the mobilesync schema with the MobileSync URL (it used to get the Outlook schema)
- Verified: Autodiscover v2 JSON returns ActiveSync, EWS and AutodiscoverV1 URLs and ProtocolNotSupported otherwise
- Verified: the Outlook POX schema still returns EXPR (EWS) and SMTP
- Limitation: SOAP Autodiscover was covered by its existing tests only; no real client discovery run is retained.
- Version source: <https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxdisco/>

### go-imap/v2 — mail protocol regression

Tested 2026-08-19 at revision `4113be1`.
- Verified: authentication, mailbox listing, append/fetch, IDLE, move, and a complete session pass through the published go-imap/v2 client
- Limitation: A protocol-library pass does not prove rendering, account setup, offline caching, or behavior of a desktop mail application.
- Version source: <https://github.com/emersion/go-imap/releases/tag/v2.0.0-beta.8>

### go-smtp — message submission regression

Tested 2026-08-19 at revision `4113be1`.
- Verified: STARTTLS, AUTH PLAIN, and authenticated full-session message submission pass through the published go-smtp client
- Limitation: A protocol-library pass does not cover application identity selection, composer behavior, certificate prompts, or OAuth setup.
- Version source: <https://github.com/emersion/go-smtp/releases/tag/v0.24.0>

### go-webdav/caldav — calendar protocol regression

Tested 2026-08-19 at revision `4113be1`.
- Verified: calendar discovery, object CRUD, calendar-query, and multiget pass through go-webdav/caldav
- Limitation: A protocol-library pass does not prove vendor scheduling, reminders, timezone rendering, background sync, or conflict UI.
- Version source: <https://github.com/emersion/go-webdav/releases/tag/v0.7.0>

### go-webdav/carddav — contacts protocol regression

Tested 2026-08-19 at revision `4113be1`.
- Verified: address-object CRUD, address-book query and multiget, multiple collections, and vCard 3/4 pass through go-webdav/carddav
- Limitation: A protocol-library pass does not prove mobile background sync, UI field mapping, conflict prompts, or vendor-specific discovery.
- Version source: <https://github.com/emersion/go-webdav/releases/tag/v0.7.0>

### Thunderbird, Apple Mail, Outlook, K-9, Gmail app, Evolution (command replay) — documented IMAP command sequences of desktop and mobile clients

Tested 2026-10-23 at revision `01909f7`.
- Verified: replayed on a live server: Thunderbird (CAPABILITY, AUTHENTICATE PLAIN, ID, NAMESPACE, LIST "" "", LIST (SUBSCRIBED) RETURN (SPECIAL-USE), LSUB, SELECT (CONDSTORE), header UID FETCH, IDLE, STATUS ... RECENT HIGHESTMODSEQ, UID STORE/COPY/EXPUNGE, APPEND), Apple Mail (ID, LIST "" "", UID FETCH (CHANGEDSINCE), UID SEARCH 1:* NOT DELETED, partial BODY.PEEK, MYRIGHTS, GETQUOTAROOT, IDLE), Outlook (NOOP polling, UID FETCH BODY.PEEK[], UID STORE .SILENT, CREATE/APPEND, CHECK), K-9 (SASL-IR, EXAMINE, UID MOVE, IDLE), Gmail app (ENVELOPE/BODYSTRUCTURE, partial TEXT) and Evolution (ENABLE QRESYNC CONDSTORE, LIST RETURN, UID FETCH (CHANGEDSINCE n VANISHED)) all completed with OK
- Verified: the Go regression tests in this scenario replay each exchange that failed before the fix
- Verified: fixed during this run: LIST "" "" returned no delimiter; FLAGS lacked \Seen; CREATE "a/b/c" created "c" at the top level; STATUS refused RECENT and HIGHESTMODSEQ; FETCH (CHANGEDSINCE) and VANISHED failed; STORE (UNCHANGEDSINCE) wiped all flags; UID FETCH omitted UID; COPY dropped flags; SEARCH refused sequence-set keys; LOGIN and other commands rejected literals; NOOP never reported new mail and expunges from other sessions renumbered messages silently; IDLE hung under COMPRESS=DEFLATE; UID EXPUNGE answered "* n EXPUNGE uid"; SORT compared raw header text
- Version source: <https://www.rfc-editor.org/rfc/rfc9051>

### Fastmail web, Ltt.rs/jmap-mua, jmap-client (JS/Rust), Mailtemi (request replay) — RFC 8620/8621 request sequences of JMAP mail clients

Tested 2026-10-23 at revision `27981f9`.
- Verified: replayed on a live server with curl and Python (about 160 assertions): session fields and URL templates, request errors (notJSON, notRequest, unknownCapability, limit with maxCallsInRequest/maxSizeRequest), method errors (unknownMethod, accountNotFound, invalidArguments, stateMismatch, anchorNotFound, unsupportedFilter, unsupportedSort, cannotCalculateChanges), result references with /*/ paths, /get with ids null and properties, /changes with maxChanges, /set with creation ids across calls and patch paths, /query filters, sorts, anchors and collapseThreads, Email/queryChanges, Email/import, Email/parse, upload/download, EmailSubmission with onSuccessUpdateEmail, Identity, VacationResponse, SearchSnippet, Thread/get, header:* forms, bodyStructure and body values
- Verified: the Go regression tests in this scenario replay each exchange that failed before the fix
- Verified: fixed during this run: the result-reference "*" path never mapped over arrays; Email/get ignored properties, offered no header: forms or bodyStructure, did not decode quoted-printable/base64 or charsets, and gave HTML-only mail an empty textBody; Email/set ignored patch paths, wrote raw RFC 3339 Date headers, and could not attach blobs; isAscending defaulted to false; collapseThreads, anchors and negative positions were ignored; EmailSubmission ignored onSuccessUpdateEmail; mail limits sat in the session capability; downloads served attachments still base64-encoded; PushSubscription stored subscriptions but never pushed
- Limitation: Sequences are modeled on the published request patterns of these clients, not captured from the applications
- Limitation: Text, body and attachment searches go through the full-text index, which reached new mail 5-7 s after delivery in this run; mailbox listings are answered directly and are current
- Limitation: WebSocket (RFC 8887), MDN (RFC 9007) and Blob/upload (RFC 9404) are not implemented and are not advertised
- Version source: <https://www.rfc-editor.org/rfc/rfc8621>

### jmapc (Python JMAP client) — JMAP mail: session, recent threads, send with submission, push

Tested 2026-10-23 at revision `27981f9`.
- Verified: jmapc 0.4.0 (isolated venv, Python 3.12) parsed the session and core limits, ran Core/echo, the library's recent-threads chain (Mailbox/query role inbox, Email/query collapseThreads with a nested #inMailbox reference, Email/get, Thread/get on /list/*/threadId, Email/get on /list/*/emailIds), Identity/get, Mailbox/get, the send-email sequence (Email/set create with bodyValues and headers, EmailSubmission/set with an envelope and onSuccessDestroyEmail, answered by an implicit Email/set), SearchSnippet/get, Email/changes, Mailbox/changes, and an EventSource StateChange
- Verified: fixed during this run: references nested in a filter were rejected as unsupportedFilter, so the recent-threads chain failed at its second call
- Limitation: jmapc only speaks https; the run rewrote its https:// session URL to the plain-HTTP test listener
- Version source: <https://github.com/smkent/jmapc>

### OfflineIMAP — mail synchronization to Maildir

Tested 2026-10-22 at revision `6700b75`.
- Verified: OfflineIMAP 8.0.0 (imaplib2 3.06, Python 3.12.13, OpenSSL 3.5.6) synchronized a Veksel mailbox over IMAP with STARTTLS and a self-signed certificate: `offlineimap.py -c offlineimaprc` with a Maildir local repository, remote `ssl = no`, `starttls = yes`, and `sslcacertfile` set to the certificate; messages were seeded by SMTP delivery
- Verified: pass: first full sync created all folders (INBOX, Drafts, Sent, Trash, Junk, Archive) and downloaded 5 seeded messages
- Verified: pass: incremental sync downloaded 5 further messages
- Verified: pass: client-to-server flag change (\Seen, \Flagged) and server-to-client flag change (\Answered, \Seen) round-tripped
- Verified: pass: client-side deletion and server-side deletion with expunge each propagated
- Verified: pass: a Maildir message created locally was uploaded with APPEND, and a locally created Maildir folder became an IMAP mailbox
- Verified: pass: a no-change sync was idempotent
- Verified: fixed during this run: the generic 10 commands per second IMAP limiter disconnected the first sync with BYE; the per-IP login limiter counted successful logins and refused later connections; STORE upper-cased flags, so \Seen was stored as \SEEN and keywords lost their case
- Verified: fixed 2026-10-22: the intermittent stall after STARTTLS (client waiting for CAPABILITY, server idle in a TLS read) was triggered by the TLS 1.3 session ticket Go sends in the server's first flight; imaplib2 processes it in its reader thread while its writer thread sends CAPABILITY on the same OpenSSL connection, and the command never reaches the server. With tickets 25 of 300 imaplib2 STARTTLS sessions hung, with IMAP session tickets disabled 0 of 300 on the same build, then 0 of 400 on the fixed build
- Verified: pass: 50 consecutive OfflineIMAP syncs ran back to back without stalls or connection refusals on the fixed build (previously runs needed a 3 second gap to stay under the per-IP connection limiter)
- Limitation: OfflineIMAP 8.0.0 does not start on Python 3.12 unpatched; the run used the v8.0.0 source tree with three client-side compatibility edits (SafeConfigParser alias, removal of the unused imp import, accepting sqlite threadsafety 3), which do not alter protocol behavior
- Limitation: The STARTTLS stall is an imaplib2 threading defect (concurrent SSL reads and writes on one OpenSSL connection); Veksel avoids triggering it by not issuing IMAP session tickets, but other post-handshake TLS messages could still expose it
- Limitation: Implicit-TLS (port 993 style) could not be exercised because OfflineIMAP 8.0.0 fails with an internal 'int object is not subscriptable' error on Python 3.12; IDLE, QRESYNC/CONDSTORE, and large mailboxes were not tested
- Version source: <https://github.com/OfflineIMAP/offlineimap3/releases/tag/v8.0.0>

### Microsoft Outlook 2024 — Exchange and Internet mail

- Limitation: No licensed Windows Outlook runner is available; Outlook 2024 does not provide a complete Veksel path through EWS alone, and MAPI/HTTP is not implemented.
- Version source: <https://learn.microsoft.com/en-us/lifecycle/products/outlook-2024>

### python caldav (caldav-server-tester) — CalDAV feature and scheduling probe

Tested 2026-10-23 at revision `ecf9871`.
- Verified: caldav-server-tester 1.6.0 on python caldav 3.6.0 (Python 3.13) probed a scratch server with three accounts over HTTP Basic, against both `http://127.0.0.1:PORT/` and `/dav/`
- Verified: pass: discovery from the bare host, current-user-principal, MKCALENDAR with display name and component set, stable URLs, PROPFIND (prop, allprop, Depth 1), calendar-color and calendar-order, event/task/recurrence/exception/timezone save-load, If-Match and If-None-Match, comp-type, time-range (event, task, open-ended, DURATION), text and category search, is-not-defined, recurrence expand with exceptions, sync-token (initial, incremental, deletions, invalid token 403), free-busy-query, implicit scheduling to a second local account, outbox free-busy, principal search for self
- Verified: fixed during this run: PROPFIND / answered 405; MKCALENDAR answered 405; PROPPATCH stored nothing; If-Match and If-None-Match were ignored; comp-filters other than VEVENT/VTODO, prop-filters, and open time ranges were ignored; recurring events came back as one response per occurrence; invalid sync tokens answered 409; a PROPPATCH with a named color wedged the durable folder journal so the next start failed
- Limitation: unsupported by design or not yet implemented: VJOURNAL collections (refused with supported-calendar-component), mixed VEVENT+VTODO calendars, the no-uid-conflict precondition, schedule-inbox delivery (invitations are auto-scheduled into the calendar), Schedule-Tag, VTODO recurrence expansion, VALARM time ranges, truncated initial sync (an initial snapshot beyond DAV:limit is refused with 507), named calendar colors, listing all principals
- Limitation: principal-property-search sent to the bare host `/` reaches the web application (405); sent to `/dav/` it is answered
- Version source: <https://pypi.org/project/caldav/3.6.0/>

### Python imaplib, smtplib, and poplib — mail library sessions over STARTTLS and implicit TLS

Tested 2026-10-23 at revision `01909f7`.
- Verified: imaplib over STARTTLS (port 143 style) and implicit TLS: LOGINDISABLED before STARTTLS, LOGIN, LIST, CREATE of a modified UTF-7 hierarchy, SELECT, APPEND with flags and date, SEARCH, UID SEARCH, FETCH, STORE, COPY with COPYUID, NOOP, STATUS, read-only EXAMINE
- Verified: smtplib on submission (STARTTLS) and implicit TLS: AUTH PLAIN and LOGIN, one message to 30 recipients without PIPELINING, eight messages in one session, BODY=8BITMIME and SMTPUTF8
- Verified: poplib over implicit TLS: CAPA, USER/PASS, STAT, UIDL
- Verified: fixed during this run: smtplib was cut off with 421 after about 20 commands (30 recipients, or a seventh message) by the generic command burst limit
- Version source: <https://docs.python.org/3.12/library/imaplib.html>

### Roundcube Webmail — mail core

Tested 2026-08-19 at revision `4113be1`.
- Verified: a Roundcube-shaped IMAP sequence for LIST/LSUB, STATUS, SELECT, ESEARCH, SORT, and header FETCH passes
- Limitation: Roundcube itself and its PHP IMAP stack were not executed; SMTP submission, MIME rendering, ACL UI, search variants, and folder mutations remain real-client gaps.
- Version source: <https://roundcube.net/news/2026/07/05/security-updates-1.6.17-and-1.7.2>

### swaks — SMTP delivery and authenticated submission

Tested 2026-10-23 at revision `01909f7`.
- Verified: swaks (develop branch script at commit 8a05259830, Perl 5.44, Net::SSLeay 1.94, IO::Socket::SSL 2.089) exercised the inbound SMTP listener and the submission listener
- Verified: pass (2026-10-23): implicit-TLS submission (`-tlsc --auth LOGIN`, port 465 style) and pipelined STARTTLS submission (`-tls --auth PLAIN --pipeline`) delivered locally; AUTH on a cleartext submission session is not offered
- Verified: pass: inbound delivery to a local mailbox (`swaks --server HOST:PORT --from sender@remote.example --to user@local.test`) was accepted and appeared over IMAP; an unknown local recipient was refused with 550 5.0.0 and an unhosted recipient on the inbound port was refused with 550
- Verified: pass: submission refuses unauthenticated mail with 530 5.7.0 and does not advertise AUTH before STARTTLS
- Verified: pass: submission with `-tls --auth PLAIN` and `-tls --auth LOGIN` after STARTTLS (self-signed certificate) authenticated with 235 and delivered a message to another local account; wrong password returned 535 5.7.8
- Verified: pass: authenticating as one account while using another account's address as the sender is refused at DATA with 550 5.7.1
- Limitation: Outbound delivery to external domains, DKIM signing, and OAuth were not exercised
- Limitation: Tested with a self-signed certificate that swaks does not verify by default
- Version source: <https://github.com/jetmore/swaks/commit/8a05259830>

### Thunderbird Desktop — mail core

Tested 2026-08-19 at revision `129b8c4`.
- Verified: the official Thunderbird Desktop binary starts with an isolated profile and authenticates to a disposable Veksel account
- Verified: Thunderbird negotiates CAPABILITY, NAMESPACE, COMPRESS DEFLATE, and ID, lists folders, selects Inbox, and issues UID FETCH for a seeded message
- Verified: the native workflow uses FolderSpace authorization and retains only normalized command names, never credentials or item content
- Limitation: This retained native run covers IMAP account use and message retrieval only; autoconfig, stored credentials, SMTP submission, MIME rendering, offline sync, search, and folder mutations remain unverified.
- Version source: <https://www.thunderbird.net/en-US/thunderbird/releases/>

### vdirsyncer — calendar and contacts synchronization

Tested 2026-10-23 at revision `ecf9871`.
- Verified: vdirsyncer 0.21.0 (Python 3.13) synced CalDAV and CardDAV with a filesystem storage per `vdirsyncer discover` and `vdirsyncer sync`; the storage URL was the bare host `http://127.0.0.1:PORT/` with HTTP Basic credentials, so discovery used /.well-known/caldav and /.well-known/carddav, current-user-principal, and the home sets
- Verified: pass (2026-10-23): discovery found every calendar (including a shared and a non-ASCII `Kalender æøå` collection) and address book; local create, server create (raw PUT), local modification uploaded with If-Match and the ETag from the PUT reply, server deletion, local deletion, and an idempotent repeat sync all propagated for events and vCards
- Verified: fixed 2026-10-21: addressbook-multiget (the RFC 6352 report name) was refused with 400; calendar-multiget responses omitted getetag; /.well-known/caldav and /.well-known/carddav, PROPFIND on /dav/, current-user-principal, calendar-home-set, and addressbook-home-set were missing, so only a URL naming the account root worked
- Limitation: vdirsyncer does not use sync-collection, calendar-query, or free-busy reports, recurrence expansion, attachments, scheduling (iTIP), contact photos, sharing, or collection creation; those are covered by the python caldav probe and the client request transcripts
- Limitation: Run over plain HTTP on loopback; HTTPS, OAuth, and application passwords were not exercised; vdirsyncer's `Deleting an item with no etag` warning is its own inverted log condition (the DELETE carries If-Match)
- Version source: <https://pypi.org/project/vdirsyncer/0.21.0/>
