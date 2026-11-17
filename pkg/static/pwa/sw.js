// Veksel service worker (UX-OWA-010). Scope: /app/.
// It precaches the versioned app shell, answers failed navigations with the
// offline page, and focuses the app when a notification is clicked. It never
// intercepts API, DAV, protocol, or cross-origin requests and never stores a
// server response other than the public shell files listed below; the
// offline snapshot is written by the signed-in page itself and cleared on
// sign-out.
const VERSION = '__VEKSEL_SW_VERSION__';
const SHELL_CACHE = `veksel-shell-${VERSION}`;
const SHELL_ASSETS = __VEKSEL_SHELL_ASSETS__;
const OFFLINE_URL = '__VEKSEL_OFFLINE_URL__';
const DATA_CACHE = 'veksel-offline-data';
const shellURLs = new Set(SHELL_ASSETS.map(url => new URL(url, self.location.origin).href));

self.addEventListener('install', event => {
  event.waitUntil(caches.open(SHELL_CACHE).then(cache => cache.addAll(SHELL_ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(key => (key.startsWith('veksel-shell-') && key !== SHELL_CACHE)).map(key => caches.delete(key))))
    .then(() => self.clients.claim()));
});

// Only public, content-versioned shell files and the offline page are ever
// served from the cache.
const cacheable = url => url.origin === self.location.origin && shellURLs.has(url.href);

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/dav/') || url.pathname === '/app/sw.js') return;
  if (request.mode === 'navigate') {
    if (!url.pathname.startsWith('/app/')) return;
    // Pages are always fetched live (they carry session state and CSRF
    // tokens) and are never stored; only a failed fetch falls back.
    event.respondWith(fetch(request).catch(() => caches.match(OFFLINE_URL).then(page => page || Response.error())));
    return;
  }
  if (!cacheable(url)) return;
  event.respondWith(caches.open(SHELL_CACHE).then(cache => cache.match(request).then(hit => hit || fetch(request))));
});

self.addEventListener('message', event => {
  if (event.origin && event.origin !== self.location.origin) return;
  if (event.data?.type === 'veksel:clear-offline') event.waitUntil(caches.delete(DATA_CACHE));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = new URL(event.notification.data?.url || '/app/', self.location.origin);
  const url = target.origin === self.location.origin && target.pathname.startsWith('/app/') ? target.pathname + target.search + target.hash : '/app/';
  event.waitUntil(self.clients.matchAll({type: 'window', includeUncontrolled: true}).then(clients => {
    const client = clients.find(candidate => new URL(candidate.url).pathname.startsWith('/app/') && candidate.focused) || clients.find(candidate => new URL(candidate.url).pathname.startsWith('/app/'));
    if (client) {
      client.postMessage({type: 'veksel:notification-open', url});
      return client.focus();
    }
    return self.clients.openWindow(url);
  }));
});
