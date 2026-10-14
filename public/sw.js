const cacheName = 'byteback-static-v11';
self.addEventListener('install', event => {
  event.waitUntil(caches.open(cacheName).then(cache =>
    cache.addAll(['/icon.svg', '/icon-192.png', '/icon-512.png', '/manifest.webmanifest', '/app.js', '/'])));
});
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin
    || !['/', '/app.js', '/manifest.webmanifest', '/icon.svg', '/icon-192.png', '/icon-512.png'].includes(url.pathname)) return;
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
});
