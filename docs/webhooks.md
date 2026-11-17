# Webhooks

There are two kinds:

- **Personal webhooks** (Settings → Webhooks, API `/api/v1/user/webhooks`):
  any user sends their own new mail to a service. They receive only the
  owner's `message.received` events, optionally narrowed to some of the
  owner's addresses or aliases (`addresses`), and choose the content with
  `include`. At most 10 per user. When acting as another account, the
  page manages that account's webhooks.
- **Server webhooks** (Administration → Notifications, API
  `/api/v1/admin/notifications/webhooks`): server-wide events such as
  health alerts, and mail events for chosen accounts, domains or
  addresses.

Both send events to HTTP(S) endpoints the same way. Each
delivery is a `POST` with a JSON body, retried with backoff until the
endpoint answers 2xx.

## Request

Headers:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-Webhook-Event` | Event name, e.g. `message.received` |
| `X-Webhook-ID` | Event ID; the same on every retry, use it to de-duplicate |
| `X-Webhook-Signature` | `sha256=` + hex HMAC-SHA256 of the raw body with the webhook secret (when one is set) |

Body:

```json
{
  "event": "message.received",
  "id": "evt_…",
  "timestamp": "2026-11-08T10:15:02Z",
  "payload": { … }
}
```

## Scope

`message.*` events are about one account's mail and go only to webhooks
whose **addresses** filter contains the envelope recipient (an account
address or an alias such as `domains@example.com`), whose **accounts**
filter contains the receiving account, or whose **domains** filter
contains the recipient's domain. A webhook without a
filter receives only server-wide events (health alerts). Saving a webhook
that subscribes to message events requires a filter.

## `message.received` payload

Always present:

| Field | Meaning |
|---|---|
| `account_id` | Account that received the message |
| `recipient` | Envelope recipient (`RCPT TO`), e.g. an alias address |
| `folder_id`, `item_id` | Where it was filed |
| `from`, `to`, `cc`, `subject` | Header values, RFC 2047 decoded |
| `date`, `message_id` | `Date` and `Message-ID` headers as sent |
| `size` | Message size in bytes |

Optional parts, chosen per webhook under "Message content to include"
(API field `include`):

| `include` | Adds |
|---|---|
| `headers` | `headers`: every header field, lower-case name → list of values in message order (raw, not decoded) |
| `text` | `text`: decoded plain-text body |
| `html` | `html`: HTML body, sanitized (scripts and remote content removed) |
| `attachments` | `attachments`: `[{"name", "content_type", "size", "inline"}]` (metadata only) |
| `raw` | `raw`: the complete RFC 5322 message, base64. Messages over 16 MiB send `raw_omitted` with the reason instead |

Only the parts at least one matching webhook asked for are built, and
each webhook receives only its own parts.

Example with `include: ["text", "raw"]`:

```json
{
  "event": "message.received",
  "id": "evt_01…",
  "timestamp": "2026-11-08T10:15:02Z",
  "payload": {
    "account_id": "domains",
    "recipient": "domains@example.com",
    "folder_id": "fld_…",
    "item_id": "itm_…",
    "from": "Mette Kær <mette@example.test>",
    "to": "domains@example.com",
    "cc": "",
    "subject": "Ny konto",
    "date": "Sat, 08 Nov 2026 11:15:01 +0100",
    "message_id": "<abc@example.test>",
    "size": 2312,
    "text": "Hej, opret venligst kontoen.\n",
    "raw": "RnJvbTogPT91dGYtOD9xP01ldHRl…"
  }
}
```

## API

`POST/PATCH /api/v1/admin/notifications/webhooks` accepts `url`, `events`,
`addresses`, `accounts`, `domains`, `include`, `active`, `secret`, `max_retries` and
`backoff_multiplier`.
