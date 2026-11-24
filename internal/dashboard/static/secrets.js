// Phoenix dashboard: the secrets pages (search, show, copy, forms).
//
// A value reaches this page only as the answer to a POST the person caused,
// is kept only as long as it takes to copy or while it is on screen, and is
// never written to storage.

window.PhoenixSecrets = (function() {
    'use strict';

    var SHOW_SECONDS = 20;
    var HIDDEN_TEXT = '••••••••';

    function el(id) { return document.getElementById(id); }

    // --- Talking to the server ---

    // NeedsPassword is thrown by send when the sign-in is not recent enough.
    function NeedsPassword() {}

    // send POSTs a form and returns the JSON answer. Throws NeedsPassword, or
    // an Error with a message to show.
    async function send(url, data) {
        var r;
        try {
            r = await fetch(url, {
                method: 'POST', body: new URLSearchParams(data), redirect: 'manual',
                credentials: 'same-origin', cache: 'no-store'
            });
        } catch (e) {
            throw new Error('Phoenix could not be reached.');
        }
        if (r.type === 'opaqueredirect') { // signed out
            location.assign('/dashboard/login');
            throw new Error('You are signed out.');
        }
        var answer;
        try { answer = await r.json(); } catch (e) { throw new Error('The request was refused. Reload the page and try again.'); }
        if (answer.reauth) throw new NeedsPassword();
        if (!r.ok) throw new Error(answer.error || 'Something went wrong.');
        return answer;
    }

    // askPassword opens the password box and resolves once it was accepted.
    // Rejects with no message when cancelled.
    function askPassword(csrf) {
        var dialog = el('reauth'), form = el('reauth-form'), input = el('reauth-password'), error = el('reauth-error');
        return new Promise(function(resolve, reject) {
            var ok = false, checking = false;
            error.hidden = true;
            input.value = '';
            form.onsubmit = async function(e) {
                e.preventDefault();
                if (checking) return;
                checking = true;
                try {
                    await send('/dashboard/reauth', { _csrf: csrf, password: input.value });
                    ok = true;
                    dialog.close();
                } catch (err) {
                    checking = false;
                    error.textContent = err.message;
                    error.hidden = false;
                    input.value = '';
                    input.focus();
                }
            };
            // Not while the server is checking: it would unlock all the same.
            el('reauth-cancel').onclick = function() { if (!checking) dialog.close(); };
            dialog.oncancel = function(e) { if (checking) e.preventDefault(); };
            window.addEventListener('pagehide', function() { input.value = ''; if (dialog.open) dialog.close(); }, { once: true });
            dialog.onclose = function() {
                input.value = '';
                if (ok) resolve(); else reject(new Error(''));
            };
            dialog.showModal();
            input.focus();
        });
    }

    // post is send, asking for the password once if the server wants it.
    async function post(url, data) {
        try {
            return await send(url, data);
        } catch (e) {
            if (!(e instanceof NeedsPassword)) throw e;
        }
        await askPassword(data._csrf);
        return send(url, data);
    }

    // --- Search as you type ---

    var search = el('secret-search');
    if (search) {
        var rows = Array.prototype.slice.call(document.querySelectorAll('#secret-list [data-search]'));
        var filter = function() {
            var words = search.value.toLowerCase().split(/\s+/).filter(Boolean), shown = 0;
            rows.forEach(function(row) {
                var text = row.getAttribute('data-search');
                row.hidden = !words.every(function(w) { return text.indexOf(w) >= 0; });
                if (!row.hidden) shown++;
            });
            el('secret-count').textContent = shown + ' of ' + rows.length;
            el('secret-none').hidden = shown > 0;
        };
        search.addEventListener('input', filter);
        search.form.addEventListener('submit', function(e) {
            e.preventDefault();
            var first = rows.filter(function(row) { return !row.hidden; });
            if (first.length === 1) location.assign(first[0].href); else search.blur();
        });
        window.addEventListener('pageshow', filter); // the browser may refill the box
        filter();
    }

    // --- One secret ---

    // copyText puts text on the clipboard. pending is a promise, so the
    // browser still counts the click as the reason while the value is on its
    // way (Safari insists).
    async function copyText(pending) {
        if (window.isSecureContext && navigator.clipboard) {
            if (window.ClipboardItem && navigator.clipboard.write) {
                var failed = null;
                var blob = pending.then(function(t) { return new Blob([t], { type: 'text/plain' }); });
                blob.catch(function(e) { failed = e; });
                try {
                    await navigator.clipboard.write([new ClipboardItem({ 'text/plain': blob })]);
                    return;
                } catch (e) {
                    await pending; // rethrows a failed fetch
                    if (failed) throw failed;
                }
            }
            await navigator.clipboard.writeText(await pending);
            return;
        }
        // Plain http: no clipboard API. The old way needs the text in the page
        // for a moment.
        var box = document.createElement('textarea');
        box.value = await pending;
        box.className = 'offscreen';
        document.body.appendChild(box);
        box.select();
        var done = document.execCommand('copy');
        box.value = '';
        box.remove();
        if (!done) throw new Error('This browser would not copy.');
    }

    var secret = el('secret');
    if (secret) {
        var csrf = secret.getAttribute('data-csrf'), path = secret.getAttribute('data-path');
        var message = el('secret-message'), valueBox = el('value'), showBtn = el('show'), copyBtn = el('copy');
        var timer = null, shown = false;

        var say = function(text, bad) {
            message.textContent = text;
            message.className = 'flash flash-sticky ' + (bad ? 'flash-error' : 'flash-ok');
            message.hidden = !text;
        };
        var hide = function() {
            shown = false;
            clearInterval(timer);
            if (valueBox) {
                valueBox.textContent = HIDDEN_TEXT;
                valueBox.classList.remove('shown');
            }
            if (showBtn) showBtn.textContent = 'Show';
        };
        var show = function(text) {
            var left = SHOW_SECONDS;
            valueBox.textContent = text;
            valueBox.classList.add('shown');
            shown = true;
            showBtn.textContent = 'Hide (' + left + ')';
            clearInterval(timer);
            timer = setInterval(function() {
                left--;
                if (left <= 0) hide(); else showBtn.textContent = 'Hide (' + left + ')';
            }, 1000);
        };
        // Never on screen behind another app, in a background tab, or in the
        // copy of this page the browser keeps for the back button.
        document.addEventListener('visibilitychange', function() { if (document.hidden) hide(); });
        window.addEventListener('pagehide', hide);

        // extra.link is the link copy-and-open will open; the server refuses
        // if the secret's link is no longer that one.
        var fetchValue = function(use, extra) {
            return send('/dashboard/secrets/value', Object.assign({ _csrf: csrf, path: path, use: use }, extra))
                .then(function(a) { return a.value; });
        };
        // run does one button's work: it blocks double taps, asks for the
        // password if needed and then tries once more.
        var busy = false;
        var run = async function(work) {
            if (busy) return;
            busy = true;
            say('');
            try {
                try {
                    await work();
                } catch (e) {
                    if (!(e instanceof NeedsPassword)) throw e;
                    await askPassword(csrf);
                    await work();
                }
            } catch (e) {
                // A browser that wants a fresh tap to allow the clipboard.
                if (e && e.name === 'NotAllowedError') say('Unlocked. Tap the button once more to copy.', true);
                else if (e && e.message) say(e.message, true);
            }
            busy = false;
        };

        if (showBtn) {
            showBtn.addEventListener('click', function() {
                if (shown) { hide(); return; }
                run(async function() {
                    var text = await fetchValue('show');
                    if (!document.hidden) show(text);
                });
            });
            copyBtn.addEventListener('click', function() {
                run(async function() {
                    await copyText(fetchValue('copy'));
                    say('Password copied.');
                });
            });
        }
        if (el('copy-username')) {
            el('copy-username').addEventListener('click', function() {
                run(async function() {
                    await copyText(Promise.resolve(el('username').textContent));
                    say('Username copied.');
                });
            });
        }
        if (el('copy-open')) {
            el('copy-open').addEventListener('click', function() {
                run(async function() {
                    await copyText(fetchValue('copy', { link: el('open-link').getAttribute('data-link') }));
                    say('Password copied. If the page did not open, tap the link below.');
                    el('open-link').click();
                });
            });
        }
    }

    // --- Add and edit forms ---

    // generate makes a 24-character password (about 143 bits) with at least
    // one of each kind of character that sites ask for.
    function generate() {
        var set = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        for (;;) {
            var bytes = crypto.getRandomValues(new Uint8Array(24)), out = '';
            bytes.forEach(function(b) { out += set[b & 63]; }); // 64 characters: no bias
            if (/[A-Z]/.test(out) && /[a-z]/.test(out) && /[0-9]/.test(out) && /[-_]/.test(out)) return out;
        }
    }

    var form = el('secret-form');
    if (form) {
        var value = el('value-input'), error = el('form-error'), sending = false;
        if (value) {
            var toggle = el('value-toggle');
            var remask = null;
            var mask = function(on) {
                clearTimeout(remask);
                value.classList.toggle('masked', on);
                toggle.textContent = on ? 'Show' : 'Hide';
                if (!on) remask = setTimeout(function() { mask(true); }, SHOW_SECONDS * 1000);
            };
            toggle.addEventListener('click', function() { mask(!value.classList.contains('masked')); });
            el('value-generate').addEventListener('click', function() { value.value = generate(); mask(false); });
            document.addEventListener('visibilitychange', function() { if (document.hidden) mask(true); });
            window.addEventListener('pagehide', function() { value.value = ''; mask(true); });
        }
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            if (sending) return;
            sending = true;
            error.hidden = true;
            var data = {}, changed = false;
            Array.prototype.forEach.call(form.elements, function(f) {
                if (!f.name || (f.type === 'checkbox' && !f.checked)) return;
                // Send only what was edited, so saving one field never puts
                // back an old copy of another.
                var text = f.type === 'text' || f.type === 'textarea';
                // A one-line box drops line breaks from what it was given.
                var was = f.type === 'text' ? f.defaultValue.replace(/[\r\n]/g, '') : f.defaultValue;
                if (text && f.value === was && f.name !== 'path') return;
                if (text) changed = true;
                data[f.name] = f.value;
            });
            try {
                if (!changed) throw new Error('Nothing was changed.');
                var answer = await post(form.getAttribute('action'), data);
                if (value) value.value = '';
                location.replace(answer.next);
                return;
            } catch (err) {
                error.textContent = err.message;
                error.hidden = !err.message;
            }
            sending = false;
        });
    }

    // A page the browser kept for the back button is out of date, and may
    // belong to a login that has ended: load it again.
    window.addEventListener('pageshow', function(e) { if (e.persisted) location.reload(); });

    return { post: post };
})();
