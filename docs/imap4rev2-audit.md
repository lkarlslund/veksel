# IMAP4rev2 Conformance Audit

This is the implementation gate for advertising `IMAP4rev2`. It maps the
server requirements folded into RFC 9051 to Veksel wire behavior. A row is only
`pass` after positive, malformed/negative, state, authorization, and relevant
rev1-compatibility tests exist. The gate is complete: protected sessions
advertise both `IMAP4rev1` and `IMAP4rev2`, and rev2 semantics activate only
after the client sends `ENABLE IMAP4rev2`.

Status values are `pass`, `partial`, `missing`, and `not applicable`.

## Session, syntax, and compatibility

| Requirement | Status | Evidence or gap |
|---|---|---|
| Dual `IMAP4rev1`/`IMAP4rev2` capability and `ENABLE IMAP4rev2` | pass | Protected greetings and CAPABILITY advertise both versions; plaintext remains rev1-only, and a client explicitly enables rev2 per session |
| Rev1 behavior before ENABLE; rev2 behavior after ENABLE | pass | End-to-end implicit-TLS negotiation verifies rev1 compatibility before ENABLE and native normalized UTF-8 CREATE/LIST behavior after ENABLE |
| Strict command tokenization, quoted strings, escapes, lists, literals and syntax rejection | pass | Quoted strings/escapes, structured FETCH/LIST/SEARCH/SORT parsing, bounded literals, missing operands, surplus arguments, malformed sets/groups and no-argument commands are covered without panic paths |
| Native Net-Unicode UTF-8 and NFC validation in rev2 mode | pass | Rev2 mailbox input is UTF-8 validated and NFC-normalized; mailbox response encoding and decomposed-name tests are covered |
| Canonical modified UTF-7 compatibility in rev1 mode | pass | Canonical codec, malformed/non-canonical rejection, command normalization and mailbox response encoding are covered |
| 63-bit message/body-part sizes | pass | STATUS/FETCH preserve the maximum signed 63-bit value, partial origins avoid overflow, negative accounting metadata is rejected, and APPEND remains bounded by configured resource limits |
| TLS 1.2+ and protected plaintext authentication configuration | pass | STARTTLS and implicit TLS force a cloned TLS 1.2+ configuration; rev2 capability/ENABLE require a protected session, while rev1 compatibility remains available on explicitly configured development listeners |

## Folded commands and responses

| Requirement | Initial status | Evidence or gap |
|---|---|---|
| NAMESPACE | pass | Personal and shared namespaces have raw-wire syntax, argument rejection, and authenticated-state coverage |
| STATUS MESSAGES/UIDNEXT/UIDVALIDITY/UNSEEN/DELETED/SIZE | pass | Durable counts/size and metadata-only flag counts have raw-wire positive and malformed-item coverage |
| LIST selection/return options and CHILDREN | pass | Selection/return options, multiple patterns, reference names, hierarchy-correct `%`/`*` wildcards, CHILDREN, recursive subscribed parents with CHILDINFO and inline LIST-STATUS are covered |
| SPECIAL-USE attributes | pass | Inbox, Archive, Drafts, Junk, Sent and Trash roles are emitted consistently in standard and extended LIST responses; CREATE-SPECIAL-USE is a separate optional extension and is not advertised |
| ESEARCH RETURN MIN/MAX/ALL/COUNT/SAVE | pass | Rev1 extension requests and forced rev2 sessions have raw-wire result/correlator, empty-result, UID and SAVE interaction coverage; ordinary rev1 SEARCH remains compatible |
| SEARCHRES `$` | pass | Saved results use stable UIDs, translate across sequence/UID contexts, survive expunges, reset on SELECT, support empty results and are populated by advertised SORT RETURN (SAVE) without an unsolicited SORT response |
| UTF-8 default/US-ASCII and UTF-8 CHARSET; BADCHARSET for others | pass | Default and explicit charsets, BADCHARSET, synchronized UTF-8 literals, invalid encodings, nested boolean groups, quoted values, MIME/header/charset decoding and NFC matching are covered through raw-wire and Go client tests |
| ENABLE | pass | Authenticated-state, non-empty syntax, capability atoms, ignored unknowns, QRESYNC/CONDSTORE, UTF8=ACCEPT (UTF-8 mailbox names and the APPEND UTF8 form) and gated TLS-only IMAP4rev2 transitions are covered |
| UIDPLUS | pass | APPENDUID, sequence/UID COPYUID mappings, UID EXPUNGE and missing-destination response semantics are covered |
| IDLE | pass | Authenticated/selected entry, no-argument syntax, DONE-only continuation input, server timeout completion, EXISTS/EXPUNGE/FETCH UID updates, multi-session delivery, and prompt reports of changes made through other protocols are covered |
| MOVE | pass | Sequence and UID variants use protocol-neutral folder operations and return TRYCREATE/COPYUID; response and mutation behavior are covered |
| LITERAL+ | pass | Non-synchronizing literals of any size up to the APPEND limit or command-line/SEARCH budget; oversized ones end the session (RFC 7888 4) without executing their content |
| FETCH ENVELOPE and BODY/BODYSTRUCTURE | pass | MIME headers, decoded display strings, address fallback rules, single/multipart structures, parameters, dispositions and a real Go IMAP client round trip are covered |
| FETCH BODY sections and partials | pass | Full/header/text, header inclusion/exclusion, nested MIME parts, partial ranges, PEEK/Seen behavior, LF-only input and multiple literals in one response are covered through unit and client tests |
| FETCH-side BINARY/BINARY.PEEK/BINARY.SIZE subset | pass | Leaf and nested multipart decoding, base64/quoted-printable/identity CTEs, partials, exact decoded size, literal8, CRLF normalization, UNKNOWN-CTE and Seen/Peek behavior are covered; BINARY is advertised now that APPEND accepts literal8 (`~{n}`, also non-synchronizing) and a composite section returns its identity-encoded content |
| SELECT/EXAMINE required FLAGS, EXISTS, LIST, PERMANENTFLAGS, UIDNEXT, UIDVALIDITY | pass | Forced-rev2 wire tests cover required data, no RECENT, read-write response code, and rev1 regressions |
| CLOSED on replacing a selected mailbox | pass | Replacement emits CLOSED; failed selection preserves the previous mailbox and is covered directly |
| COPY/MOVE TRYCREATE and COPYUID | pass | Sequence and UID variants return TRYCREATE for missing destinations and tagged COPYUID with destination UIDVALIDITY/source UIDs |
| Unsolicited FETCH always includes UID | pass | STORE, UID STORE, IDLE flag notifications and QRESYNC changes carry UID; tests retain solicited FETCH behavior |
| Rev2 response codes and BAD/NO distinction | pass | Command arity, malformed sets/groups/FETCH data items and invalid atoms produce BAD; operational authorization/storage/decode failures produce NO with TRYCREATE, OVERQUOTA, UNAVAILABLE, BADCHARSET and UNKNOWN-CTE where applicable |

## Existing extensions retained outside the folded baseline

CONDSTORE/QRESYNC, ACL/RIGHTS, METADATA, SORT, THREAD, COMPRESS, ID,
MULTIAPPEND, OAuth2/NTLM authentication, and shared-folder RBAC remain separate
capabilities. Advertising one of these continues to require its own complete
wire behavior; `IMAP4rev2` does not make an incomplete extension valid.

SORT and THREAD now use their RFC 5256 parenthesized criteria/charset grammar,
standard response shapes, separate sequence/UID modes and separate THREAD
capability atoms, with Go-client round trips. Historical unparenthesized SORT
and Veksel THREAD forms remain accepted only as rev1 compatibility input.

## Interoperability gate

- Raw-wire RFC 9051 positive and negative suite: passing.
- Existing Go IMAP rev1 regression suite: passing after the tranche.
- Go IMAP rev2 protected-session negotiation and UTF-8 transcript: passing.
- Thunderbird named-client transcript: passing.
- Roundcube named-client transcript: passing.
- Full tests, race, vet, lint, vulnerability scan: recorded in the completed tranche evidence.
