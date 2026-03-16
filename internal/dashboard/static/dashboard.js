// Phoenix Dashboard — minimal client-side behavior

(function() {
    'use strict';

    // Confirm dialogs for destructive actions
    document.querySelectorAll('[data-confirm]').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            if (!confirm(this.getAttribute('data-confirm'))) {
                e.preventDefault();
            }
        });
    });

    // Relative time display
    function updateTimes() {
        document.querySelectorAll('[data-time]').forEach(function(el) {
            var ts = parseInt(el.getAttribute('data-time'), 10);
            if (!ts) return;
            var diff = Math.floor(Date.now() / 1000) - ts;
            if (diff < 0) diff = 0;
            var text;
            if (diff < 60) {
                text = diff + 's ago';
            } else if (diff < 3600) {
                text = Math.floor(diff / 60) + 'm ago';
            } else if (diff < 86400) {
                var h = Math.floor(diff / 3600);
                var m = Math.floor((diff % 3600) / 60);
                text = h + 'h ' + m + 'm ago';
            } else {
                var d = Math.floor(diff / 86400);
                text = d + 'd ago';
            }
            el.textContent = text;
        });
    }
    updateTimes();
    setInterval(updateTimes, 15000);

    // Auto-refresh audit page every 30s
    var auditTable = document.getElementById('audit-table');
    if (auditTable) {
        setInterval(function() {
            var url = window.location.href;
            fetch(url, { credentials: 'same-origin' })
                .then(function(r) { return r.text(); })
                .then(function(html) {
                    var parser = new DOMParser();
                    var doc = parser.parseFromString(html, 'text/html');
                    var newTable = doc.getElementById('audit-table');
                    if (newTable) {
                        auditTable.innerHTML = newTable.innerHTML;
                        updateTimes();
                    }
                })
                .catch(function() {}); // silently fail
        }, 30000);
    }

    // Auto-dismiss flash messages after 5s
    document.querySelectorAll('.flash').forEach(function(el) {
        setTimeout(function() {
            el.style.transition = 'opacity 0.3s';
            el.style.opacity = '0';
            setTimeout(function() { el.remove(); }, 300);
        }, 5000);
    });
})();
