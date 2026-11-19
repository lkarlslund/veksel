# Authorization architecture

Veksel authorizes content through typed folders rather than separate mail,
calendar, contacts, and files ACL systems. Protocol-specific rights are
adapters around one application policy model.

## Resources and principals

Policy resources form this hierarchy:

```text
system -> account -> folder -> subfolder/item
       -> domain -> identity
```

Folders use their stable `ParentID` for inheritance. Paths are mutable protocol
and presentation identifiers and are not authorization boundaries. Items
inherit the policy of their containing folder.

Local users and flat groups are policy principals. API keys are credentials of
a user and can restrict, but never increase, that user's effective access.

## Decisions

Bindings attach a built-in/custom role or a direct permission set to a
principal and resource. A binding is an `allow` or `deny`, applies to either the
resource itself or its subtree, and may expire.

Evaluation is default-deny. A matching explicit deny overrides an allow.
System owners and resource owners cannot be locked out by ordinary resource
denies. Acting as a different account is rejected unless the actor has an
account delegation or administrative impersonation permission.

The stable folder permission vocabulary is:

- `folder.discover`
- `folder.metadata.read`, `folder.metadata.write`
- `folder.items.list`, `folder.items.read`, `folder.items.create`
- `folder.items.update`, `folder.items.delete`, `folder.items.expunge`
- `folder.children.create`, `folder.children.rename`, `folder.children.delete`
- `folder.permissions.read`, `folder.permissions.manage`
- `folder.shares.manage`

Side effects which are not generic folder operations retain namespaced
permissions, including `calendar.schedule`, `mail.redirect`,
`identity.send_as`, and `identity.send_on_behalf`.

## Enforcement boundary

REST, browser, IMAP, CalDAV, CardDAV, and WebDAV handlers must resolve their
request to an actor, effective subject, action, and resource. Application
services enforce the decision before calling model stores; UI visibility is
never an authorization control.

The WebSocket channel at `/api/v1/events` is events-out only. A connection is
authenticated with the same HttpOnly application session and accepts only a
same-origin upgrade. Events are addressed to user subscriptions and contain
identifiers/invalidation metadata, never message bodies. Slow clients may lose
events and therefore refetch canonical REST resources after reconnecting.

## Acting as another account

Account delegation and administrative impersonation are deliberately separate:

- A delegation is a revocable `account.delegate` role binding on an account.
  The binding is re-evaluated on every request, including its expiry and any
  explicit deny. Revocation returns an active session to its actor.
- Impersonation requires `account.impersonate`, the administrator's password,
  a recorded reason, and has a maximum 15-minute lifetime. It reaches the
  account's mailbox and personal settings (profile name, identities and
  signatures, auto-reply, rules, categories, templates, saved searches,
  aliases, encryption keys, devices, notifications, display). The account's
  password, two-factor methods, web sessions, application passwords, API
  keys, webhooks, grants, share links, synchronization jobs, account export
  and remote device wipe answer `403` until the administrator returns to
  their own account, so nothing set up during support outlives it. A
  delegate keeps their own settings while working in another mailbox.
- Sessions always persist both immutable `actor_id` and effective `subject_id`.
  Audit records retain the actor; changing the subject never changes who is
  accountable for the operation.
- Sending rights are not implied by account delegation. `identity.send_as` and
  `identity.send_on_behalf` must be granted independently per email identity.

The last enabled system owner cannot be disabled or deleted. This invariant is
enforced in the model store so older HTTP handlers cannot bypass it.

## Administrative roles

Three built-in roles open administration:

- **`system.owner`** (on `system`) holds every permission. Only owners hold
  `authorization.roles.write`, which gates owner authority: creating roles,
  changing groups, backup restore, raw configuration patch, restore, and
  recovery, and the `ldap_admin_group_dn` and `ldap_admin_role` settings.
- **`system.admin`** (on `system`) holds `system.*`, `domain.*`, `account.*`,
  `identity.*`, and `folder.*`: full operational administration, including
  domain limits and assigning domain administrators, but none of the owner
  authority above. The engine refuses administrative (system- or
  domain-level) bindings that would reach another user's account, folders, or
  identities when that user is a system owner (reason
  `owner_account_protected`), so a system administrator cannot impersonate,
  reset, disable, or delete an owner and thereby become one. Direct grants on
  an owner's resources (shares, delegation) are unaffected.
- **`domain.admin`** (on one `domain`) holds `domain.read`,
  `domain.accounts.manage`, `domain.identities.manage`,
  `domain.catchall.manage`, and `domain.trace.read`. It does not hold
  `domain.limits.manage` or `domain.admins.manage`, so it cannot change its
  domain's limits or grant administration. An account belongs to the domain
  of its primary identity.

Web administration (`isAdmin`) means `system.manage` on `system`;
`authorization.roles.read` is still accepted so custom roles written before
`system.manage` keep working.

Delegated administration is enforced in the REST handlers through checks on
the specific Domain resource, never by filtering the UI:

- Listings (`/admin/users`, `/admin/domains`, `/admin/recipient-aliases`,
  `/admin/accounts/usage`, `/admin/message-trace`, `/admin/queue`) return only
  the actor's domains, or for trace and queue only messages whose sender or
  recipient is in them; trace statistics are withheld.
- Account endpoints (edit, disable, delete, usage, identities, credential and
  second-factor reset, sending status and limits) require
  `domain.accounts.manage` on the account's primary domain. A domain
  administrator cannot manage an account that holds system administration or
  administers a domain outside its own scope.
- Identity and recipient-alias changes require `domain.identities.manage` on
  the address's domain; alias targets and catch-all targets must be in domains
  the actor administers. Domain delivery and scanning settings, domain
  creation and deletion, DKIM rotation, DNS publishing, and every
  installation-wide endpoint stay system-only.
- New accounts created by a domain administrator need a primary address in its
  domain. Per-domain limits apply at create and update: maximum accounts and
  aliases (non-primary identities plus recipient aliases) and the storage
  ceiling (sum of account quotas; every account then needs a quota) bind every
  administrator, while the maximum account quota and the send-limit ceiling
  (the account's inherited limits) bind domain administrators. Violations
  answer `409` with the limit named.
- Delegated actions are audited with the acting administrator as actor and
  `admin_scope=domain:<name>` in the details.

Domain administrators use browser sessions; REST API keys remain limited to
system administrators.

## REST and protocol adapters

The canonical browser surface is `/app`. Commands and queries use `/api/v1`:

- `/api/v1/workspace/folders`, `/workspace/items`, `/workspace/items/page`, `/workspace/item`
- `/api/v1/workspace/folders/{id}/history` reads or configures the folder
  policy; nested `/items/{itemID}/versions` routes list, retrieve, and restore
  immutable snapshots. Folder metadata/list/read/update/create permissions are
  evaluated independently for the requested operation, including deleted-item
  recreation.
- `/api/v1/grants` lists the current actor's personally manageable folder,
  account-delegation/search, and identity grants; `/grants/{id}` inspects,
  updates, or revokes one grant, and `/grants/{id}/effective-access` expands its
  role and evaluates the recipient's current combined policy. Global
  system/domain authority does not expand this user-settings projection.
  Updates use `expected_updated_at` for optimistic concurrency and may change
  only access, effect, inheritance, and expiry; principal and resource identity
  are immutable.
- `/api/v1/share-links` creates and lists revocable capability links for one
  exact folder or item; `/share/#<token>` keeps the one-time bearer secret in
  the URL fragment, and anonymous `/api/v1/public/share` operations receive it
  only in the `Authorization: Share` header. Link use re-evaluates the
  creator's current folder rights and accesses content only through the routed
  FolderSpace. Item links never expose siblings. Management mutations require
  session CSRF, while public responses are non-cacheable and deny framing and
  referrer propagation.
- `/api/v1/folders/{id}/grants`
- `/api/v1/accounts/{id}/delegations`
- `/api/v1/identities/{id}/grants`
- `/api/v1/session/delegation`, `/session/impersonation`
- `/api/v1/mail/submissions`

For user principals, effective-access results include one current allow/deny
decision per represented permission, including the policy reason and matching
binding identifiers. Group grants report their expanded permissions and member
count; policy remains user-contextual, so each member is evaluated when that
member acts rather than presenting one misleading group-wide allow result.

IMAP ACL rights are mapped to the stable folder actions. IMAP `SETACL` also
writes canonical policy, while IMAP access and shared-mailbox discovery consult
the policy engine when the server supplies it. DAV cross-account requests are
checked against folder policy (or explicit account delegation) after Basic
authentication; knowing valid credentials for one account cannot select a
different account merely by changing the URL.

## API key capabilities

Every `/api/v1` route has one handler with two authentication front-ends:

- **Browser session.** The session cookie authenticates; `POST`, `PUT`,
  `PATCH`, and `DELETE` also need the `X-CSRF-Token` header.
- **`X-API-Key`.** The key's owner must be an enabled system administrator,
  otherwise the request is refused with `403`; ordinary users' keys serve MCP
  only. Named keys need `api.read` for `GET`/`HEAD` and for the `POST`
  routes that only read (search queries, authorization checks, automation
  and contact-import previews, mail-policy simulation, configuration
  validation, support-bundle and backup download, and backup verification),
  `api.write` for other changes, and `keys.manage` for changes under
  `/api/v1/user/api-keys`. The OpenAPI document names each operation's scope.
  Keys are not ambient credentials, so these requests need no CSRF token. A
  few session-bound routes (`/api/v1/session`, delegation and impersonation,
  browser sessions, `/api/v1/events`) refuse keys.

Requests without valid credentials receive `401`. Handlers then apply the same
authorization to both front-ends; key requests act as the key's owner.

Named keys are issued under user settings (`POST /api/v1/user/api-keys`).
Everyone can issue `mcp.read` and `mcp.write` keys; only administrators can
issue the REST scopes, and a key-authenticated caller cannot issue or rotate a
key holding scopes it lacks. Named keys created before scopes existed are
treated as `api.read` plus `keys.manage`.

Only named keys authenticate. The older single key stored on a user record is
retired: it no longer authenticates anywhere, and system schema 3 deletes its
stored hash. **Breaking change:** a client still sending such a key receives
`401` and must be given a named key with the scopes it needs. Rejecting an
unknown key costs only the named-key lookup, which narrows candidates by the
non-secret key prefix (named keys created before prefixes were stored are
still compared one by one until rotated); user records are never scanned.

`GET /api/v1/swagger.json` (viewer at `/api/docs/`) is an OpenAPI 3 document
generated from the route table. It lists every operation, its path parameters,
and the credentials and scope it needs; it does not model request and response
bodies.

## Operational limits

Policy binding and index writes are repaired by the startup index rebuild but
are not yet transactional across every backend. Mail acceptance is durable:
both inbound and outbound work is committed to the generic store-backed system
queue before SMTP or the web submission API reports acceptance.
