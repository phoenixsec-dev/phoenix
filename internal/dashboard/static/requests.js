// Live access requests, on every dashboard page (see requests.go).
//
// Asks the server every two seconds what is waiting. On the Requests page new
// cards join the list; anywhere else they pop up. A card that is on screen is
// never redrawn, so ticks, a picked time or a half-typed note stay as they are.
// When its request ends, the card says how.
(function () {
    'use strict';

    var POLL_MS = 2000;       // page visible
    var RETRY_MAX_MS = 10000; // server unreachable
    var TIMEOUT_MS = 8000;    // a request a proxy never answers
    var ARM_MS = 700;         // a popup ignores taps this long, so one that
                              // appears under a finger is not answered by accident

    var page = document.querySelector('[data-requests-page]');
    var list = document.querySelector('[data-requests-waiting]');
    var sections = document.querySelector('[data-requests-sections]');
    var rev = '', fails = 0, stopped = false, timer = 0, inFlight = false, first = true;
    var clock = page ? Number(page.dataset.now) - Date.now() : 0; // server minus browser
    var popups = null, offline = null;
    var baseTitle = document.title;

    // --- small storage helpers: work without storage too -------------------
    var memory = {};
    function remember(store, key) {
        memory[key] = true;
        try { window[store].setItem('phoenix-' + key, '1'); } catch (e) { /* private window */ }
    }
    function known(store, key) {
        if (memory[key]) return true;
        try { return window[store].getItem('phoenix-' + key) !== null; } catch (e) { return false; }
    }

    // --- countdown ----------------------------------------------------------
    function left(seconds) {
        if (seconds <= 0) return 'time is up';
        var h = Math.floor(seconds / 3600), m = Math.floor(seconds % 3600 / 60), s = seconds % 60;
        if (h > 0) return 'in ' + h + 'h ' + m + 'm';
        return 'in ' + m + ':' + (s < 10 ? '0' : '') + s;
    }
    function tick() {
        var now = Math.floor((Date.now() + clock) / 1000);
        document.querySelectorAll('time[data-until]').forEach(function (el) {
            var card = el.closest('.rq-card');
            if (card && card.classList.contains('rq-done')) return;
            var text = left(Number(el.dataset.until) - now);
            el.textContent = card && text.indexOf('in ') === 0 ? text.slice(3) + ' left' : text;
        });
    }

    // --- cards ---------------------------------------------------------------
    function toElement(html) {
        var t = document.createElement('template');
        t.innerHTML = html;
        return t.content.querySelector('.rq-card');
    }
    function container() {
        if (list) return list;
        if (!popups) {
            popups = document.createElement('div');
            popups.className = 'rq-popups';
            popups.setAttribute('role', 'alert');
            document.body.appendChild(popups);
        }
        return popups;
    }
    function shown(id) { return document.querySelector('.rq-card[data-request="' + id + '"]'); }

    function addCard(item) {
        if (!list && known('sessionStorage', 'later-' + item.id)) return;
        var card = toElement(item.html);
        if (!card) return;
        if (!list) {
            var later = document.createElement('button');
            later.type = 'button';
            later.className = 'rq-later';
            later.textContent = 'Later';
            later.addEventListener('click', function () {
                remember('sessionStorage', 'later-' + item.id);
                card.remove();
            });
            card.insertBefore(later, card.firstChild);
            arm(card);
        }
        container().appendChild(card);
        wire(card);
    }
    function arm(card) {
        var buttons = card.querySelectorAll('button[name=choice]');
        buttons.forEach(function (b) { b.disabled = true; });
        setTimeout(function () {
            if (!card.dataset.busy) buttons.forEach(function (b) { b.disabled = false; });
        }, ARM_MS);
    }

    // endCard turns a card into a line saying how its request ended.
    function endCard(card, text, state) {
        if (card.classList.contains('rq-done')) return;
        card.classList.add('rq-done');
        card.querySelectorAll('button, input, select').forEach(function (el) {
            if (!el.classList.contains('rq-later')) el.disabled = true;
        });
        var time = card.querySelector('.rq-left');
        if (time) time.textContent = '';
        var error = card.querySelector('.rq-error');
        if (error) error.remove();
        var out = document.createElement('div');
        out.className = 'rq-outcome';
        var badge = document.createElement('span');
        badge.className = 'status-badge status-' + state;
        badge.textContent = text;
        out.appendChild(badge);
        card.appendChild(out);
        var later = card.querySelector('.rq-later');
        if (later) {
            later.textContent = 'Close';
            // An expired one stays until it is closed, so nobody misses it.
            if (state !== 'expired') setTimeout(function () { card.remove(); }, 4000);
        }
    }

    // wire makes a card answer in place instead of loading a page.
    function wire(card) {
        var form = card.querySelector('form');
        if (!form || form.dataset.wired) return;
        form.dataset.wired = '1';
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            if (card.dataset.busy || card.classList.contains('rq-done')) return; // double tap
            var choice = e.submitter && e.submitter.value;
            if (!choice) return;
            var body = new URLSearchParams(new FormData(form));
            body.set('choice', choice);
            card.dataset.busy = '1';
            var buttons = form.querySelectorAll('button[name=choice]');
            buttons.forEach(function (b) { b.disabled = true; });
            say(card, '');
            send(form.getAttribute('action'), body).then(function (r) {
                if (r.closed) endCard(card, r.message, r.ok ? r.state : (r.state || 'expired'));
                else if (!r.ok) say(card, r.message);
            }).catch(function (err) {
                say(card, err.message);
            }).then(function () {
                delete card.dataset.busy;
                if (!card.classList.contains('rq-done')) buttons.forEach(function (b) { b.disabled = false; });
                poll();
            });
        });
    }
    function say(card, text) {
        var el = card.querySelector('.rq-error');
        if (!el) {
            el = document.createElement('div');
            el.className = 'rq-error';
            el.setAttribute('role', 'alert');
            card.querySelector('.rq-buttons').after(el);
        }
        el.textContent = text;
    }

    // send posts a form and returns the server's JSON answer.
    function send(url, body) {
        return fetch(url, {
            method: 'POST', credentials: 'same-origin', cache: 'no-store',
            headers: { 'Accept': 'application/json' }, body: body
        }).then(function (r) {
            var type = r.headers.get('Content-Type') || '';
            if (type.indexOf('application/json') < 0) {
                throw new Error(r.redirected ? 'You are signed out. Reload the page and log in.' : 'The server did not accept that. Reload the page and try again.');
            }
            return r.json();
        }, function () {
            throw new Error('Could not reach Phoenix. Nothing was confirmed; try again.');
        });
    }

    // --- sections below the list (Requests page) -------------------------------
    var waitingSections = null;
    function showSections(html) {
        // Not while someone is on a button in there.
        if (sections.contains(document.activeElement) && document.activeElement !== document.body) {
            waitingSections = html;
            return;
        }
        waitingSections = null;
        if (sections.innerHTML !== html) sections.innerHTML = html;
        tick();
    }
    function wireSections() {
        sections.addEventListener('focusout', function () {
            setTimeout(function () { if (waitingSections !== null) showSections(waitingSections); }, 0);
        });
        sections.addEventListener('submit', function (e) {
            e.preventDefault();
            var form = e.target, button = form.querySelector('button');
            if (button.disabled) return;
            button.disabled = true;
            send(form.getAttribute('action'), new URLSearchParams(new FormData(form))).then(function (r) {
                notice(r.message, !r.ok);
            }).catch(function (err) { notice(err.message, true); }).then(function () {
                button.disabled = false;
                button.blur();
                rev = '';
                poll();
            });
        });
    }
    function notice(text, bad) {
        var box = document.querySelector('[data-requests-notice]');
        var el = document.createElement('div');
        el.className = 'flash flash-sticky ' + (bad ? 'flash-error' : 'flash-info');
        el.setAttribute('role', 'status');
        el.textContent = text;
        box.replaceChildren(el);
        if (!bad) setTimeout(function () { el.remove(); }, 8000);
    }

    // --- browser notification ---------------------------------------------------
    function canNotify() { return 'Notification' in window && window.isSecureContext; }
    function notifyFor(item) {
        if (known('localStorage', 'seen-' + item.id)) return;
        remember('localStorage', 'seen-' + item.id);
        if (!document.hidden || !canNotify() || Notification.permission !== 'granted') return;
        var card = toElement(item.html);
        try {
            // No secret names: a notification can show on a locked screen.
            var n = new Notification('Phoenix: ' + (card ? card.dataset.agent : 'an agent') + ' is asking', {
                body: 'Open Phoenix to answer.', tag: item.id, icon: '/dashboard/static/phoenix-icon.svg'
            });
            n.onclick = function () {
                window.focus();
                window.location.href = '/dashboard/requests/' + item.id;
            };
        } catch (e) { /* Android only allows this from a service worker */ }
    }
    function offerNotify() {
        var box = document.querySelector('[data-requests-notify]');
        if (!box || !canNotify() || Notification.permission !== 'default') return;
        box.hidden = false;
        box.querySelector('button').addEventListener('click', function () {
            Notification.requestPermission().then(function () { box.hidden = true; });
        });
    }

    // --- polling ------------------------------------------------------------------
    function apply(feed) {
        rev = feed.rev;
        clock = feed.now - Date.now();
        var waiting = {};
        feed.waiting.forEach(function (item) {
            waiting[item.id] = true;
            if (!shown(item.id)) addCard(item);
            notifyFor(item);
        });
        var ended = {};
        feed.ended.forEach(function (e) { ended[e.id] = e; });
        document.querySelectorAll('.rq-card').forEach(function (card) {
            var id = card.dataset.request;
            if (waiting[id] || card.dataset.busy) return;
            var e = ended[id] || { text: 'No longer waiting', state: 'expired' };
            endCard(card, e.text, e.state);
        });
        var n = feed.waiting.length;
        document.querySelectorAll('[data-requests-badge]').forEach(function (b) {
            b.textContent = n;
            b.hidden = n === 0;
        });
        document.title = n > 0 ? '(' + n + ') ' + baseTitle : baseTitle;
        var empty = document.querySelector('[data-requests-empty]');
        if (empty) empty.hidden = list.children.length > 0;
        if (sections && feed.sections) showSections(feed.sections);
        if (first) { first = false; focusCard(); }
        tick();
    }
    function poll() {
        if (stopped || inFlight) return;
        clearTimeout(timer);
        inFlight = true;
        var ctl = new AbortController();
        var cut = setTimeout(function () { ctl.abort(); }, TIMEOUT_MS);
        fetch('/dashboard/requests/feed?rev=' + rev + (page ? '&page=1' : ''), {
            credentials: 'same-origin', cache: 'no-store', signal: ctl.signal
        }).then(function (r) {
            if (r.status === 401) {
                stopped = true;
                banner('Signed out. ', page ? '/dashboard/login?next=/dashboard/requests' : '/dashboard/login');
                return null;
            }
            if (r.status !== 200 && r.status !== 204) throw new Error('HTTP ' + r.status);
            return r.status === 204 ? null : r.json();
        }).then(function (feed) {
            if (stopped) return;
            fails = 0;
            banner('');
            if (feed) apply(feed);
        }).catch(function () {
            fails++;
            // One miss is nothing; say so when it lasts.
            if (fails > 1) banner('Connection lost. Trying again...');
        }).then(function () {
            clearTimeout(cut);
            inFlight = false;
            next();
        });
    }
    function next() {
        if (stopped) return;
        // A tab nobody looks at and that may not notify has nothing to do.
        if (document.hidden && !(canNotify() && Notification.permission === 'granted')) return;
        timer = setTimeout(poll, Math.min(POLL_MS * Math.max(1, fails), RETRY_MAX_MS));
    }
    function banner(text, loginURL) {
        if (!text) {
            if (offline) { offline.remove(); offline = null; }
            return;
        }
        if (!offline) {
            offline = document.createElement('div');
            offline.className = 'rq-offline';
            offline.setAttribute('role', 'status');
            document.body.appendChild(offline);
        }
        offline.textContent = text;
        if (loginURL) {
            var a = document.createElement('a');
            a.href = loginURL;
            a.textContent = 'Log in';
            offline.appendChild(a);
        }
    }

    // focusCard brings the request a link named to the top of the screen.
    function focusCard() {
        if (!page) return;
        var id = page.dataset.focus || location.hash.slice(1);
        if (!/^req_[0-9a-f]{32}$/.test(id)) return;
        var card = shown(id);
        if (card) {
            card.classList.add('rq-focus');
            card.scrollIntoView({ block: 'center' });
        } else if (!page.dataset.focus) {
            location.replace('/dashboard/requests/' + id); // an old #req_... link to one that ended
        }
    }

    document.querySelectorAll('.rq-card').forEach(wire);
    if (sections) wireSections();
    offerNotify();
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) return;
        stopped = false; // maybe logged in again in another tab
        poll();
    });
    window.addEventListener('online', poll);
    window.addEventListener('pageshow', function (e) { if (e.persisted) poll(); });
    tick();
    setInterval(tick, 1000);
    poll();
})();
