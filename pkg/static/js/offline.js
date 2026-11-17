// Offline page (UX-OWA-010): renders the read-only snapshot the signed-in app
// stored in this browser's offline data cache. All text goes through
// textContent; nothing here talks to the API.
(() => {
  const cacheName = 'veksel-offline-data';
  const status = document.querySelector('#offline-status');
  const read = async name => {
    try {
      const cache = await caches.open(cacheName);
      const response = await cache.match(`/app/offline-data/${name}.json`);
      return response ? await response.json() : null;
    } catch (_) {
      return null;
    }
  };
  const format = (value, options) => {
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? '' : new Intl.DateTimeFormat(undefined, options).format(date);
  };
  const item = (title, detail, onOpen) => {
    const entry = document.createElement('li');
    const target = document.createElement(onOpen ? 'button' : 'div');
    if (onOpen) {
      target.type = 'button';
      target.className = 'offline-entry';
      target.onclick = onOpen;
    }
    const strong = document.createElement('strong');
    strong.textContent = title;
    const small = document.createElement('small');
    small.textContent = detail;
    target.append(strong, small);
    entry.append(target);
    return entry;
  };
  const reader = document.querySelector('#offline-reader');
  const openMessage = message => {
    document.querySelector('#offline-reader-title').textContent = message.subject || '(no subject)';
    document.querySelector('#offline-reader-meta').textContent = [message.from, format(message.date, {dateStyle: 'medium', timeStyle: 'short'})].filter(Boolean).join(' · ');
    document.querySelector('#offline-reader-body').textContent = message.text || '';
    reader.hidden = false;
    reader.querySelector('h2').tabIndex = -1;
    reader.querySelector('h2').focus();
  };
  document.querySelector('#offline-reader-close').onclick = () => { reader.hidden = true; };
  document.querySelector('#offline-retry').onclick = () => location.reload();
  window.addEventListener('online', () => { status.textContent = 'Connection restored. Reloading…'; location.reload(); });
  Promise.all([read('agenda'), read('messages')]).then(([agenda, messages]) => {
    const now = new Date();
    const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    const events = agenda?.day === today ? agenda.events || [] : [];
    const agendaList = document.querySelector('#offline-agenda');
    if (events.length) {
      agendaList.replaceChildren(...events.map(event => item(event.summary || 'Untitled event', [event.all_day ? 'All day' : `${format(event.start, {timeStyle: 'short'})}–${format(event.end, {timeStyle: 'short'})}`, event.location].filter(Boolean).join(' · '))));
    }
    const list = messages?.items || [];
    if (list.length) document.querySelector('#offline-messages').replaceChildren(...list.map(message => item(message.subject || '(no subject)', [message.from, format(message.date, {dateStyle: 'medium', timeStyle: 'short'})].filter(Boolean).join(' · '), () => openMessage(message))));
    const saved = [agenda?.saved_at, messages?.saved_at].filter(Boolean).sort().at(-1);
    status.textContent = saved ? `Saved copies from ${format(saved, {dateStyle: 'medium', timeStyle: 'short'})}.` : 'No saved copies are available in this browser.';
  });
})();
