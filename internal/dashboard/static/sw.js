// Phoenix service worker. It keeps ONLY the files listed here, which are the
// same for everyone and hold no data. Pages, JSON answers and secrets are
// never stored: they are not on the list, so they go straight to the server.

var CACHE = 'phoenix-static-2';
var FILES = [
    '/dashboard/static/style.css',
    '/dashboard/static/dashboard.js',
    '/dashboard/static/secrets.js',
    '/dashboard/static/phoenix-icon.svg',
    '/dashboard/static/icon-180.png',
    '/dashboard/static/icon-192.png',
    '/dashboard/static/icon-512.png',
    '/dashboard/static/manifest.json'
];

// The page shown when Phoenix can't be reached. It is written here rather than
// stored, so no HTML from the network is ever kept.
var OFFLINE = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Phoenix - offline</title>' +
    '<link rel="stylesheet" href="/dashboard/static/style.css"></head><body class="login-body"><div class="login-card">' +
    '<img src="/dashboard/static/phoenix-icon.svg" alt="" class="login-icon"><h1 class="login-title">Can\'t reach Phoenix</h1>' +
    '<p class="hint">Nothing is kept on this device, so it needs a connection to the server.</p>' +
    '<p><a class="btn btn-primary" href="/dashboard/secrets">Try again</a></p></div></body></html>';

// storable says whether an answer really is the static file at path: not a
// sign-in page a proxy put there, and not marked as not to be stored.
var TYPES = {
    css: ['text/css'], js: ['text/javascript', 'application/javascript'], svg: ['image/svg+xml'],
    png: ['image/png'], json: ['application/json']
};
function storable(path, r) {
    var type = (r.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
    var cc = (r.headers.get('Cache-Control') || '').toLowerCase();
    return r.ok && r.type === 'basic' && !r.redirected && cc.indexOf('no-store') < 0 &&
        new URL(r.url).pathname === path && TYPES[path.split('.').pop()].indexOf(type) >= 0;
}

self.addEventListener('install', function(e) {
    e.waitUntil(caches.open(CACHE).then(function(c) {
        return Promise.all(FILES.map(function(path) {
            return fetch(path, { cache: 'no-cache' }).then(function(r) { if (storable(path, r)) return c.put(path, r); });
        }));
    }).then(function() { return self.skipWaiting(); }));
});

self.addEventListener('activate', function(e) {
    e.waitUntil(caches.keys().then(function(names) {
        // Other apps on this address keep their caches here too.
        return Promise.all(names.filter(function(n) { return n.indexOf('phoenix-static-') === 0 && n !== CACHE; }).map(function(n) { return caches.delete(n); }));
    }).then(function() { return self.clients.claim(); }));
});

// kept is the stored copy of a listed file.
function kept(path) {
    return caches.open(CACHE).then(function(c) { return c.match(path); }).then(function(r) { return r || Response.error(); });
}

self.addEventListener('fetch', function(e) {
    var url = new URL(e.request.url);
    if (e.request.method !== 'GET' || url.origin !== self.location.origin) return;

    // Listed static file: from the server, or the kept copy when offline.
    if (!url.search && FILES.indexOf(url.pathname) >= 0) {
        e.respondWith(fetch(e.request).then(function(r) {
            if (storable(url.pathname, r)) {
                var copy = r.clone();
                e.waitUntil(caches.open(CACHE).then(function(c) { return c.put(url.pathname, copy); }));
            }
            return r;
        }).catch(function() { return kept(url.pathname); }));
        return;
    }
    // A page: from the server only. Offline shows a fixed "can't reach" page.
    if (e.request.mode === 'navigate') {
        e.respondWith(fetch(e.request).catch(function() {
            return new Response(OFFLINE, { headers: {
                'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin',
                'Content-Security-Policy': "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'"
            } });
        }));
    }
});

// Android shows a request's notification through this worker. Tapping it opens
// that request, in a Phoenix window that is already open if there is one.
self.addEventListener('notificationclick', function(e) {
    e.notification.close();
    var url = new URL((e.notification.data || {}).url || '/dashboard/requests', self.location.origin);
    if (url.origin !== self.location.origin || url.pathname.indexOf('/dashboard/') !== 0) return;
    e.waitUntil(clients.matchAll({ type: 'window' }).then(function(open) {
        return open.length ? open[0].focus().then(function(c) { return c.navigate(url.href); }) : clients.openWindow(url.href);
    }));
});
