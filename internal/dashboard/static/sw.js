// Phoenix service worker. It keeps ONLY the files listed here, which are the
// same for everyone and hold no data. Pages, JSON answers and secrets are
// never stored: they are not on the list, so they go straight to the server.

var CACHE = 'phoenix-static-1';
var FILES = [
    '/dashboard/static/style.css',
    '/dashboard/static/dashboard.js',
    '/dashboard/static/secrets.js',
    '/dashboard/static/phoenix-icon.svg',
    '/dashboard/static/icon-180.png',
    '/dashboard/static/icon-192.png',
    '/dashboard/static/icon-512.png',
    '/dashboard/static/manifest.json',
    '/dashboard/static/offline.html'
];

self.addEventListener('install', function(e) {
    e.waitUntil(caches.open(CACHE).then(function(c) { return c.addAll(FILES); }).then(function() { return self.skipWaiting(); }));
});

self.addEventListener('activate', function(e) {
    e.waitUntil(caches.keys().then(function(names) {
        return Promise.all(names.filter(function(n) { return n !== CACHE; }).map(function(n) { return caches.delete(n); }));
    }).then(function() { return self.clients.claim(); }));
});

self.addEventListener('fetch', function(e) {
    var url = new URL(e.request.url);
    if (e.request.method !== 'GET' || url.origin !== self.location.origin) return;

    // Listed static file: from the server, or the kept copy when offline.
    if (!url.search && FILES.indexOf(url.pathname) >= 0) {
        e.respondWith(fetch(e.request).then(function(r) {
            if (r.ok && r.type === 'basic' && !r.redirected) {
                var copy = r.clone();
                e.waitUntil(caches.open(CACHE).then(function(c) { return c.put(url.pathname, copy); }));
            }
            return r;
        }).catch(function() { return caches.match(url.pathname); }));
        return;
    }
    // A page: from the server only. Offline shows a fixed "can't reach" page.
    if (e.request.mode === 'navigate') {
        e.respondWith(fetch(e.request).catch(function() { return caches.match('/dashboard/static/offline.html'); }));
    }
});
