// Icons: icon buttons across the app are written with a single Unicode
// glyph (✎, ⌫, ↩ …). Those render differently on every platform, so this
// replaces a lone glyph in an icon button with a matching line icon. The
// button keeps its title and aria-label; the SVG is decorative.
(() => {
  'use strict';
  const paths = {
    trash: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v5M14 11v5',
    edit: 'M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4',
    left: 'M15 6l-6 6 6 6',
    right: 'M9 6l6 6-6 6',
    down: 'M12 5v14M6 13l6 6 6-6',
    up: 'M12 19V5M6 11l6-6 6 6',
    close: 'M6 6l12 12M18 6L6 18',
    check: 'M5 12.5l4.5 4.5L19 7',
    warning: 'M12 4l9 16H3zM12 10v4M12 17v.5',
    layout: 'M4 5h16v14H4zM10 5v14',
    search: 'M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 1 0 0-13M15.5 15.5L20 20',
    refresh: 'M19 12a7 7 0 1 1-2.05-4.95M19 4v4h-4',
    undo: 'M9 14L4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3',
    forward: 'M5 12h14M13 6l6 6-6 6',
    conversation: 'M4 5h12v9H8l-4 3zM20 9v10l-3-2.5H10',
    expand: 'M14 4h6v6M10 20H4v-6M20 4l-6 6M4 20l6-6',
    collapse: 'M4 14h6v6M20 10h-6V4M10 14l-6 6M14 10l6-6',
    flag: 'M6 21V4M6 4h11l-2.5 4L17 12H6',
    clock: 'M12 4a8 8 0 1 0 0 16 8 8 0 1 0 0-16M12 8v4.5l3 2',
    unread: 'M12 6a6 6 0 1 0 0 12 6 6 0 1 0 0-12',
    archive: 'M3 5h18v4H3zM5 9v10h14V9M10 13h4',
    print: 'M7 9V4h10v5M7 17H4v-7h16v7h-3M7 14h10v6H7z',
    more: 'M5 12h.01M12 12h.01M19 12h.01',
    reply: 'M10 8L5 12.5l5 4.5M5 12.5h9a5 5 0 0 1 5 5V19',
    replyAll: 'M12 8l-4.5 4.5L12 17M7.5 8L3 12.5 7.5 17M7.5 12.5H15a5 5 0 0 1 5 5V19',
    sort: 'M8 4v16M4 16l4 4 4-4M16 20V4M12 8l4-4 4 4',
    info: 'M12 4a8 8 0 1 0 0 16 8 8 0 1 0 0-16M12 11v5M12 8v.5',
    play: 'M8 5l11 7-11 7z',
    pause: 'M8 5v14M16 5v14',
    route: 'M4 12h11M11 7l5 5-5 5M20 5v14',
    plus: 'M12 5v14M5 12h14',
    folders: 'M4 6h6l2 2h8v10H4zM4 10h16',
    settings: 'M12 9a3 3 0 1 0 0 6 3 3 0 1 0 0-6M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3.9a7 7 0 0 0-2-1.2L14.2 3h-4.4l-.4 2.6a7 7 0 0 0-2 1.2l-2.3-.9-2 3.4 2 1.5a7 7 0 0 0 0 2.4l-2 1.5 2 3.4 2.3-.9a7 7 0 0 0 2 1.2l.4 2.6h4.4l.4-2.6a7 7 0 0 0 2-1.2l2.3.9 2-3.4-2-1.5c.1-.4.1-.8.1-1.2',
    save: 'M5 4h11l3 3v13H5zM8 4v5h7V4M8 20v-6h8v6',
    attach: 'M20 11.5l-7.8 7.8a5 5 0 0 1-7.1-7.1l8.2-8.2a3.4 3.4 0 0 1 4.8 4.8l-8.2 8.2a1.7 1.7 0 0 1-2.4-2.4l7.5-7.5',
    template: 'M5 4h14v16H5zM8.5 8.5h7M8.5 12h7M8.5 15.5h4',
    bulletList: 'M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01',
    numberList: 'M10 6h10M10 12h10M10 18h10M4 5l1.5-1v5M3.8 13.5a1.4 1.4 0 0 1 2.4 1L4 17h2.5',
    outdent: 'M20 6H10M20 12h-7M20 18H10M7 9l-3 3 3 3',
    indent: 'M20 6H10M20 12h-7M20 18H10M4 9l3 3-3 3',
    align: 'M4 6h16M4 10h10M4 14h16M4 18h10',
    link: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1',
    quote: 'M5 17V12a5 5 0 0 1 4-5M14 17V12a5 5 0 0 1 4-5M5 12h4v5H5zM14 12h4v5h-4z',
    clearFormat: 'M6 5h12M12 5l-3 14M4 4l16 16',
    image: 'M4 5h16v14H4zM4 16l5-5 4 4 2-2 5 5M15.5 8.5h.01',
    emoji: 'M12 4a8 8 0 1 0 0 16 8 8 0 1 0 0-16M9 14.5a4 4 0 0 0 6 0M9.5 10h.01M14.5 10h.01',
    redo: 'M15 14l5-5-5-5M20 9H10a6 6 0 0 0 0 12h3',
    mail: 'M3 6h18v12H3zM3 7l9 6 9-6',
    calendar: 'M4 6h16v14H4zM4 10h16M8 3v4M16 3v4',
    person: 'M12 4a4 4 0 1 0 0 8 4 4 0 1 0 0-8M4 20c1.5-4 4.5-6 8-6s6.5 2 8 6',
    file: 'M6 3h8l4 4v14H6zM14 3v4h4',
    menu: 'M4 7h16M4 12h16M4 17h16',
    themeAuto: 'M12 4a8 8 0 1 0 0 16 8 8 0 1 0 0-16M12 4v16',
    themeLight: 'M12 8a4 4 0 1 0 0 8 4 4 0 1 0 0-8M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
    themeDark: 'M20 14.5A8 8 0 1 1 9.5 4 6.5 6.5 0 0 0 20 14.5z',
    openAs: 'M14 4h6v6M20 4l-8 8M18 14v6H4V6h6',
    bell: 'M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15zM10 20.5a2 2 0 0 0 4 0',
  };
  const glyphs = {
    '⌫': 'trash', '✎': 'edit', '‹': 'left', '›': 'right', '↓': 'down', '↑': 'up', '×': 'close', '✕': 'close',
    '✓': 'check', '⚠': 'warning', '◫': 'layout', '⌕': 'search', '↻': 'refresh', '↶': 'undo', '→': 'forward',
    '⧉': 'conversation', '⤢': 'expand', '⤡': 'collapse', '⚑': 'flag', '◷': 'clock', '○': 'unread', '▤': 'archive',
    '⎙': 'print', '⋯': 'more', '↩': 'reply', '↪': 'replyAll', '↕': 'sort', 'ⓘ': 'info', '▷': 'play', '▶': 'play',
    'Ⅱ': 'pause', '⇢': 'route', '＋': 'plus', '+': 'plus', '⊟': 'folders', '⊞': 'folders', '♢': 'bell', '↗': 'openAs', '•≡': 'bulletList', '1≡': 'numberList', '⇤': 'outdent', '⇥': 'indent', '☰': 'align', '🔗': 'link', '❝': 'quote', 'T̸': 'clearFormat', '🖼': 'image', '☺': 'emoji', '↷': 'redo', '⚙': 'settings',
  };
  const svg = name => `<svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${paths[name]}"/></svg>`;
  const themeGlyphs = { 'A': 'themeAuto', '☀': 'themeLight', '◐': 'themeDark' };
  const selector = '[data-theme-icon],button,.toolbar-icon,.icon-action,.admin-alert-button>span';
  const upgrade = button => {
    if (button.querySelector('svg')) return;
    const text = button.textContent.trim();
    const name = button.hasAttribute('data-theme-icon') ? themeGlyphs[text] : glyphs[text];
    if (!name || button.children.length) return;
    if (button.classList.contains('mobile-menu')) { button.innerHTML = svg('menu'); button.dataset.icon = 'menu'; return; }
    if (!button.hasAttribute('aria-label') && button.title) button.setAttribute('aria-label', button.title);
    button.innerHTML = svg(name);
    button.dataset.icon = name;
  };
  const scan = root => {
    if (root.nodeType !== 1) return;
    if (root.matches(selector)) upgrade(root);
    root.querySelectorAll(selector).forEach(upgrade);
  };
  const start = () => {
    scan(document.body);
    new MutationObserver(records => {
      for (const record of records) {
        if (record.type === 'characterData') {
          const button = record.target.parentElement?.closest(selector);
          if (button) { delete button.dataset.icon; upgrade(button); }
          continue;
        }
        record.addedNodes.forEach(node => {
          if (node.nodeType === 3) {
            const button = node.parentElement?.closest(selector);
            if (button) upgrade(button);
          } else scan(node);
        });
      }
    }).observe(document.body, { childList: true, subtree: true, characterData: true });
  };
  window.vekselIcon = svg;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
