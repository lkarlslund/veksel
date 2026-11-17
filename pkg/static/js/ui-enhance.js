// UI enhancements that restructure markup app.js renders, without
// changing its behaviour: elements are moved, never recreated, so their
// listeners keep working.
(() => {
  'use strict';
  const icon = name => (window.vekselIcon ? window.vekselIcon(name) : '');

  // A stable hue per address gives each correspondent a recognisable colour.
  const hue = value => {
    let hash = 0;
    for (const char of String(value || '').toLowerCase()) hash = (hash * 31 + char.codePointAt(0)) >>> 0;
    return Math.round((hash % 997) * 137.508) % 360;
  };
  window.vekselHue = hue;
  const initials = name => {
    const words = String(name || '').replace(/@.*$/, '').replace(/[^\p{L}\p{N}\s]/gu, ' ').trim().split(/\s+/).filter(Boolean);
    return ((words[0]?.[0] || '?') + (words.length > 1 ? words.at(-1)[0] : '')).toUpperCase();
  };
  window.vekselInitials = initials;

  // Message rows get a sender avatar in the selection column; the checkbox
  // takes its place on hover or while selecting.
  const decorateRow = row => {
    if (row.querySelector(':scope > .row-avatar')) return;
    const sender = row.querySelector('.message-meta small[data-person]');
    if (!sender) return;
    const avatar = document.createElement('span');
    avatar.className = 'row-avatar';
    avatar.setAttribute('aria-hidden', 'true');
    avatar.style.setProperty('--avatar-h', hue(sender.dataset.person));
    avatar.textContent = initials(sender.dataset.personName || sender.textContent);
    row.prepend(avatar);
  };

  // Password managers (Bitwarden, 1Password, LastPass) attach inline menus
  // to fields that look like logins. Recipient, subject and search fields
  // are not credentials.
  const ignorePasswordManagers = root => {
    root.querySelectorAll('input:not([type=password]):not([data-bwignore])').forEach(input => {
      if (input.form?.matches('#login-form, form[action="/app/login"]')) return;
      input.setAttribute('data-bwignore', '');
      input.setAttribute('data-1p-ignore', '');
      input.setAttribute('data-lpignore', 'true');
      input.setAttribute('data-form-type', 'other');
    });
  };

  const enhanceCompose = dialog => {
    if (!dialog || dialog.dataset.enhanced) return;
    const form = dialog.querySelector('#compose-form');
    const scroll = dialog.querySelector('.compose-editor-scroll');
    const actions = dialog.querySelector('.dialog-actions');
    if (!form || !scroll || !actions) return;
    dialog.dataset.enhanced = 'true';
    dialog.classList.add('compose-v2');
    form.classList.add('compose-v2');

    // Cc and Bcc stay folded behind a toggle on the To row until used.
    const copy = scroll.querySelector('.compose-copy-fields');
    const toLabel = form.elements.to?.closest('label');
    if (copy && toLabel) {
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'compose-copy-toggle';
      toggle.textContent = 'Cc Bcc';
      toggle.title = 'Add Cc and Bcc recipients';
      toggle.onclick = () => { form.classList.add('show-copy'); form.elements.cc?.focus(); };
      toLabel.append(toggle);
    }
    const syncCopy = () => {
      const used = ['cc', 'bcc'].some(name => (form.elements[name]?.value || '').trim()) ||
        copy?.querySelector('.recipient-chip, .recipient-token');
      form.classList.toggle('show-copy', Boolean(used));
    };

    // Delivery options fold into a disclosure. app.js adds them after the
    // dialog exists, so they are wrapped whenever they appear.
    const wrapOptions = () => {
      const options = scroll.querySelector(':scope > .compose-delivery-options');
      if (!options) return;
      const details = document.createElement('details');
      details.className = 'compose-options';
      const summary = document.createElement('summary');
      summary.textContent = 'Delivery options';
      details.append(summary);
      const anchor = scroll.querySelector(':scope > .compose-operation-status');
      if (anchor) anchor.before(details); else scroll.append(details);
      details.append(options);
      const markChanged = () => {
        const changed = [...options.querySelectorAll('select')].some(select => select.selectedIndex > 0) ||
          [...options.querySelectorAll('input[type=checkbox]')].some(box => box.checked);
        summary.dataset.changed = changed ? 'true' : '';
      };
      options.addEventListener('change', markChanged);
      new MutationObserver(markChanged).observe(options, { subtree: true, childList: true, attributes: true });
      markChanged();
    };
    wrapOptions();
    new MutationObserver(wrapOptions).observe(scroll, { childList: true });

    // Footer: Send first, then send later and attach as icons; draft state
    // and the save button sit on the right. The × in the header closes.
    const send = actions.querySelector('#send-message');
    const later = actions.querySelector('#send-later');
    const save = actions.querySelector('#save-draft');
    const status = actions.querySelector('#draft-save-status');
    actions.querySelectorAll('.btn[data-compose-close]').forEach(button => { button.hidden = true; });
    if (send) send.textContent = 'Send';
    if (later) {
      later.classList.add('icon-only');
      later.title = 'Send later';
      later.setAttribute('aria-label', 'Send later');
      later.innerHTML = icon('clock');
    }
    if (save) {
      save.classList.add('icon-only');
      save.title = 'Save draft now';
      save.setAttribute('aria-label', 'Save draft now');
      save.innerHTML = icon('save');
    }
    // app.js provides an attach button with an attachment count.
    const attach = actions.querySelector('.compose-attach-action');
    const lead = document.createElement('div');
    lead.className = 'compose-send-group';
    [send, later, attach].filter(Boolean).forEach(element => lead.append(element));
    actions.prepend(lead);
    // app.js may add its attach button after this runs; keep it in the group.
    const adoptAttach = () => {
      const late = actions.querySelector(':scope > .compose-attach-action');
      if (late) lead.append(late);
    };
    adoptAttach();
    new MutationObserver(adoptAttach).observe(actions, { childList: true });
    if (status) status.classList.add('compose-draft-state');

    // The drop zone appears over the form only while files are dragged in.
    let depth = 0;
    const hasFiles = event => [...(event.dataTransfer?.types || [])].includes('Files');
    form.addEventListener('dragenter', event => { if (hasFiles(event)) { depth++; form.classList.add('dragging-files'); } });
    form.addEventListener('dragleave', event => { if (hasFiles(event) && --depth <= 0) { depth = 0; form.classList.remove('dragging-files'); } });
    form.addEventListener('drop', () => { depth = 0; form.classList.remove('dragging-files'); }, true);
    form.vekselSyncCopy = syncCopy;

    new MutationObserver(() => {
      if (!dialog.open && !form.closest('#item-view')) { form.classList.remove('show-copy'); form.classList.remove('dragging-files'); return; }
      syncCopy();
      ignorePasswordManagers(dialog);
    }).observe(dialog, { attributes: true, attributeFilter: ['open'] });
    form.addEventListener('input', event => { if (['cc', 'bcc'].includes(event.target.name)) syncCopy(); });
  };

  // Templates in the compose header becomes an icon button.
  const enhanceTemplateAction = button => {
    if (button.dataset.enhanced) return;
    button.dataset.enhanced = 'true';
    button.classList.add('icon-only');
    button.title = 'Message templates';
    button.setAttribute('aria-label', 'Message templates');
    button.innerHTML = icon('template');
  };

  // A footer "Close" button repeats the × in the dialog header.
  const hideRedundantClose = root => {
    root.querySelectorAll?.('dialog .dialog-actions [data-close]').forEach(button => {
      if (button.textContent.trim() !== 'Close') return;
      const dialog = button.closest('dialog');
      if (dialog?.querySelector('.dialog-header [data-close], .dialog-header .icon-button')) button.hidden = true;
    });
  };

  const scan = root => {
    if (root.nodeType !== 1) return;
    hideRedundantClose(root.matches?.('dialog') ? root.parentElement || root : root);
    ignorePasswordManagers(root);
    if (root.matches?.('.message-row')) decorateRow(root);
    root.querySelectorAll?.('.message-row').forEach(decorateRow);
    root.querySelectorAll?.('.message-sender-avatar:not([style])').forEach(avatar => {
      const person = avatar.parentElement?.querySelector('[data-person]');
      if (person) avatar.style.setProperty('--avatar-h', hue(person.dataset.person));
    });
    const compose = root.id === 'compose-dialog' ? root : root.querySelector?.('#compose-dialog');
    if (compose) enhanceCompose(compose);
    const movedForm = root.id === 'compose-form' ? root : root.querySelector?.('#compose-form');
    if (movedForm?.vekselSyncCopy) { movedForm.vekselSyncCopy(); ignorePasswordManagers(movedForm); }
    const template = root.id === 'message-templates-toggle' ? root : root.querySelector?.('#message-templates-toggle');
    if (template) enhanceTemplateAction(template);
  };

  // Setting group jump links scroll within the page without touching the URL.
  document.addEventListener('click', event => {
    const link = event.target.closest?.('[data-setting-group-link]');
    if (!link) return;
    event.preventDefault();
    const target = document.querySelector(link.getAttribute('href'));
    const scroller = target?.closest('.workspace-panel-body');
    if (!target || !scroller) return;
    const nav = link.closest('.setting-group-nav');
    const offset = target.getBoundingClientRect().top - scroller.getBoundingClientRect().top - (nav ? nav.offsetHeight : 0);
    scroller.scrollBy({ top: offset, behavior: 'smooth' });
  });

  const start = () => {
    // Server-rendered times shown in the viewer's own time zone.
    document.querySelectorAll('time[data-local-time]').forEach(element => {
      const value = new Date(element.getAttribute('datetime'));
      if (!Number.isNaN(value.getTime())) element.textContent = value.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    scan(document.body);
    new MutationObserver(records => records.forEach(record => record.addedNodes.forEach(scan)))
      .observe(document.body, { childList: true, subtree: true });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
