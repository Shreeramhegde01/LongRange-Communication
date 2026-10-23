/* Service worker for the LoRa Mesh Messenger.
 *
 * The whole point is offline use: nodes get deployed where there is no
 * cellular or internet coverage, so everything the app needs is cached on
 * first load and served from cache thereafter. After one install the app
 * never needs the network again - it talks to the node over Bluetooth.
 */
const CACHE = 'loramesh-v1';
const ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE)
      /* Individually, so one missing icon cannot fail the whole install. */
      .then(cache => Promise.allSettled(ASSETS.map(a => cache.add(a))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* Cache first: offline is the normal case here, not the exception. A network
 * copy is fetched when available and folded back in for the next launch. */
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then(cached => {
      const fresh = fetch(event.request).then(response => {
        if (response && response.status === 200 && response.type === 'basic') {
          const copy = response.clone();
          caches.open(CACHE).then(cache => cache.put(event.request, copy));
        }
        return response;
      }).catch(() => cached);

      return cached || fresh;
    })
  );
});
