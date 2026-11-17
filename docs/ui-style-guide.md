# UI style guide

How the Veksel web interface looks, reads and behaves. Every UI change follows
it; when a change needs to break a rule, change the rule here in the same
commit and say why.

The implementation lives in three files loaded after the legacy
stylesheets:

- `pkg/static/css/refresh.css`: tokens and component styles. New styling
  goes here, not into `app.css` or `admin.css`.
- `pkg/static/js/icons.js`: the line-icon set (`window.vekselIcon(name)`) and
  the glyph-to-icon mapping for buttons.
- `pkg/static/js/ui-enhance.js`: markup enhancements (compose layout,
  avatars, password-manager opt-out, redundant Close buttons, setting-group
  jump links).

## Principles

1. **Quiet by default, colour for meaning.** Surfaces are neutral grey.
   Teal (`--brand`) marks only selection, unread state, focus and the single
   primary action. Green, amber and red mean healthy, attention and failure,
   and nothing else.
2. **Say it once.** No label above a title that repeats it, no footer button
   that repeats the ×, no badge on every row saying the normal state.
3. **Show the exception, not the rule.** Mark what is disabled, failing,
   unread or changed; leave the normal state unmarked.
4. **Most-used first.** Order fields, actions and lists by how often people
   need them; fold the rest behind a disclosure.
5. **Dense but legible.** Compact rows and controls, never below 12px text
   or a 32px hit target for pointer controls (40px on phones).

## Colour and surfaces

Use the tokens; never hard-code a colour in component CSS.

| Token | Use |
|---|---|
| `--bg-canvas` / `--bg-primary` | Page and side panes |
| `--bg-secondary` | Content surfaces: lists, reading pane, cards, dialogs |
| `--bg-tertiary` | Inset fields, pills, toolbars inside a surface |
| `--bg-hover` / `--bg-active` | Hover / selected row |
| `--border-light` / `--border-color` | Hairlines inside / around a surface |
| `--text-primary` / `--text-secondary` / `--text-muted` | Content / supporting / metadata |
| `--brand`, `--brand-bg` | Primary action, selection, unread, focus |
| `--success`, `--warning`, `--danger` (+ `-bg`) | Status only |

- Both themes are defined: light on `:root`, dark on
  `html[data-color-scheme="dark"]`. Check every change in both.
- Separate panes with a hairline or a surface change, not a box per pane.
- Depth: `--shadow-md` for popovers and floating panels, `--shadow-lg` for
  dialogs. No offset ("hard") shadows.
- Radius scale: `--radius-sm` 4px (tags, editor buttons), `--radius-md` 6px
  (buttons, inputs), `--radius-lg` 8px (cards, rows, avatars in lists are
  round), `--radius-xl` 12px (dialogs). Pills and badges are fully round.

## Typography

- Inter (embedded), sentence case everywhere. **No all-caps labels**; the
  only exception is calendar weekday headers.
- Page title 1.45rem/650; dialog title 1.05rem/650; section heading
  0.92rem/650; body 0.82–0.9rem; metadata 0.72–0.76rem in `--text-muted`.
- Monospace only for machine values: log fields, keys, hashes, addresses in
  technical views.
- Numbers in tables and times use tabular figures (set globally).

## Buttons and actions

- **Prefer icon buttons for frequent, well-known actions**: reply, forward,
  archive, delete, flag, edit, refresh, attach, print, more, close, navigate.
  Every icon button has `title` and `aria-label` naming the action.
- **Use a text button** when the action is the page's primary call to
  action ("New alias or group", "Send", "Save event") or has no unambiguous
  icon. A primary button may carry a leading `+` icon.
- **One primary button per view or dialog.** Everything else is a secondary
  (outlined) or ghost (icon-only, no border) button.
- Destructive actions (Delete, Remove) are red text without a fill until
  hovered, and sit apart from the primary action (left side of a footer).
- Labels are verbs that say what happens: "Send", "Save event",
  "Add postmaster@". Never "Submit" or "OK". Keep the same verb through
  the flow (button "Publish", toast "Published").
- Icons come from `icons.js` only: 24×24 viewbox, 1.75 stroke, round caps.
  Never use emoji or Unicode symbols as icons. A button whose whole label
  is a known glyph (✎ ⌫ ↩ ⋯ …) is converted automatically, but new code
  should render `vekselIcon(name)` directly.
- Group related icon buttons; separate groups with spacing, not dividers.
  Show row actions on hover/focus (and always on touch), not permanently.

## Dialogs

- Header: one title and the × close button (plus at most one or two header
  icon actions, such as Templates). No eyebrow label above the title.
- Footer: primary action at the right; Cancel next to it only when the
  dialog edits something; destructive action at the far left. No "Close"
  button when the header has ×.
- Prefer a side panel or inline editing over a modal when the user needs the
  list behind it. Modals have a fixed size per kind (settings modal is one
  size for every page).
- Escape closes; focus returns to the control that opened the dialog.

## Forms

- Show the fields people need; fold advanced or rarely changed ones into a
  `<details>` ("Delivery options", "Advanced"). Mark a folded section when
  something inside it differs from the default.
- Compose-style forms use single-line rows (label left, borderless input)
  with the focused row marked by a brand edge.
- Settings lists: label and description on the left, control on the right.
  Lists longer than 14 settings are grouped with headings and a sticky jump
  list.
- Booleans are switches (`.material-switch`), not checkboxes, in settings.
  Checkboxes are for selection and for options inside a form.
- Fields that are not credentials opt out of password-manager overlays
  (`data-bwignore`, `data-1p-ignore`, `data-lpignore`); `ui-enhance.js` does
  this for inputs outside the login form.
- Errors appear next to the field and say what to do.

## Lists and tables

- Rows: primary text in `--text-primary`, metadata in `--text-muted` below or
  to the right. Unread/attention is shown with weight plus a brand dot or
  edge, not colour alone.
- Columns earn their place: drop columns that repeat other columns (domain
  of an address) or show the normal state (Enabled on every row, Updated).
  Put such detail in the row's detail view or a tooltip.
- Sentence-case column headings in `--text-muted`; sortable headings show the
  direction only when sorted.
- Filters and sort controls in toolbars are pills that size to their
  content, never full-width selects.
- Empty states span the table/pane, say what is missing, and offer the next
  step ("No aliases or groups yet. Create one to …").

## Status and feedback

- Status pills: tinted background, round dot, sentence case
  (`.status-pill.enabled/.disabled/.planned`). Use them for exceptions;
  don't badge the default state on every row.
- Health and checks: failures first, then warnings, then unknown, then
  passing (dimmed).
- Toasts confirm completed actions in past tense ("Alias created.");
  errors explain what went wrong and how to fix it, without apologising.
- Connection/live indicators appear only when something is wrong.

## People and things

- People get an avatar: initials on a colour derived from their address
  (mail) or name (contacts) via `window.vekselHue`. Same person, same colour
  everywhere.
- Folders, search results and other typed objects get a type icon.

## Layout and navigation

- Navigation menus are grouped under short sentence-case headings (People,
  Mail, Protection…). No duplicate entries; one place per page.
- Name things by what users understand, not by implementation
  ("Aliases & groups", not "Recipients"; "Calendars & contacts (DAV)").
- A setting lives on the page about the thing it controls; "Find any
  setting" is the safety net, not the organisation.
- The top bar holds the page's search and primary action; pages without
  tools don't show an empty bar.
- Reading text is limited to about 46rem line length.

## Responsive

- Check 1440×900 and 390×844. On phones: dialogs become full-screen, the
  top bar keeps search and an icon-only primary action, toolbars scroll
  horizontally instead of wrapping, and footers stay on one row.

## Accessibility

- Visible focus on every interactive element (brand outline).
- Icon-only controls always have an accessible name.
- Never rely on colour alone: pair it with text, an icon or weight.
- Respect `prefers-reduced-motion`; motion is limited to short transitions
  that answer an action.

## Checking a change

1. Run a local dev instance (`./dev-restart.sh`) and seed realistic data.
2. Screenshot the affected screens at both sizes and in both themes
   (headless Playwright works without touching anyone's browser).
3. Compare against this guide, fix, and re-check before committing.
4. `go test -short ./pkg/static ./pkg/web/app`; update UI tests that pin
   old markup only when the guide calls for the change.
