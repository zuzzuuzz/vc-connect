(function () {
    'use strict';

    document.title = 'VC Connect — VelourCare Ortho';

    // File protocol warning when opened directly off disk
    function checkFileProtocol() {
        if (window.location.protocol === 'file:') {
            var el = document.getElementById('file-protocol-warning');
            if (el) el.style.display = 'block';
        }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', checkFileProtocol);
    } else {
        checkFileProtocol();
    }

    // 1. WebSocket / Pusher mock for local portal runtime without standalone Reverb server
    var OriginalWebSocket = window.WebSocket;
    if (OriginalWebSocket) {
        window.WebSocket = function (url, protocols) {
            if (typeof url === 'string' && (url.indexOf('/app/vf10kobs7iwkrqdkyp0m') !== -1 || url.indexOf('wss://localhost') !== -1 || url.indexOf('ws://localhost') !== -1)) {
                var mockWs = {
                    url: url,
                    readyState: 1,
                    send: function () {},
                    close: function () {
                        this.readyState = 3;
                        if (this.onclose) this.onclose({ code: 1000, reason: 'Normal closure', wasClean: true });
                    },
                    addEventListener: function (type, fn) {
                        this['on' + type] = fn;
                    },
                    removeEventListener: function () {}
                };
                setTimeout(function () {
                    if (mockWs.onopen) mockWs.onopen({ type: 'open' });
                    if (mockWs.onmessage) {
                        mockWs.onmessage({
                            data: JSON.stringify({
                                event: 'pusher:connection_established',
                                data: JSON.stringify({
                                    socket_id: 'velourcare-mock-socket-' + Math.random().toString(36).slice(2, 9),
                                    activity_timeout: 120
                                })
                            })
                        });
                    }
                }, 50);
                return mockWs;
            }
            return protocols !== undefined ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
        };
        window.WebSocket.prototype = OriginalWebSocket.prototype;
        window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
        window.WebSocket.OPEN = OriginalWebSocket.OPEN;
        window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
        window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
    }

    // 2. Dynamic RTL & Arabic Language Synchronization
    function syncDirWithLocale() {
        try {
            var isAr = false;
            var layout = localStorage.getItem('layout') || localStorage.getItem('pinia_layout') || localStorage.getItem('app.locale');
            if (layout && (layout.indexOf('"locale":"ar"') !== -1 || layout.indexOf('"ar"') !== -1)) {
                isAr = true;
            }
            document.documentElement.setAttribute('dir', isAr ? 'rtl' : 'ltr');
            document.documentElement.setAttribute('lang', isAr ? 'ar' : 'en');
        } catch (e) {}
    }
    syncDirWithLocale();
    window.addEventListener('storage', syncDirWithLocale);

    // 3. Complete PHI & Auth State Purge on Logout / Session Expiry / User Switch
    var SENSITIVE_KEYS = [
        'case.draft',
        'auth.user',
        'auth.role_slug',
        'auth.permissions',
        'auth.token',
        'auth.client_id',
        'auth.rememberMe',
        'resetValue'
    ];
    var isPurging = false;

    function purgeClientState(redirectToLogin) {
        if (isPurging) return;
        isPurging = true;
        try {
            for (var i = 0; i < SENSITIVE_KEYS.length; i++) {
                try { Storage.prototype.removeItem.call(localStorage, SENSITIVE_KEYS[i]); } catch (e) {}
                try { Storage.prototype.removeItem.call(sessionStorage, SENSITIVE_KEYS[i]); } catch (e) {}
            }
        } finally {
            isPurging = false;
        }
        if (redirectToLogin) {
            var p = window.location.pathname || '';
            if (p.indexOf('/login') === -1 && p.indexOf('/forgot-password') === -1 && p.indexOf('/reset-password') === -1) {
                setTimeout(function () {
                    window.location.replace('/login');
                }, 40);
            }
        }
    }

    var origRemoveItem = Storage.prototype.removeItem;
    var origSetItem = Storage.prototype.setItem;

    Storage.prototype.removeItem = function (key) {
        origRemoveItem.apply(this, arguments);
        if (this === localStorage && !isPurging && key === 'auth.user') {
            purgeClientState(true);
        }
    };

    Storage.prototype.setItem = function (key, value) {
        if (this === localStorage && key === 'auth.user') {
            try {
                var prevRaw = localStorage.getItem('auth.user');
                var prevUser = prevRaw ? JSON.parse(prevRaw) : null;
                var nextUser = value ? JSON.parse(value) : null;
                if (prevUser && nextUser && prevUser.id !== nextUser.id) {
                    origRemoveItem.call(localStorage, 'case.draft');
                }
            } catch (e) {}
        }
        origSetItem.apply(this, arguments);
    };

    // Intercept XHR and fetch calls to /auth/logout to guarantee purge even if storage wasn't touched
    if (window.fetch) {
        var origFetch = window.fetch;
        window.fetch = function (input) {
            var url = typeof input === 'string' ? input : (input && input.url) || '';
            var p = origFetch.apply(this, arguments);
            if (url.indexOf('/auth/logout') !== -1) {
                return p.finally(function () { purgeClientState(true); });
            }
            return p;
        };
    }

    if (window.XMLHttpRequest) {
        var origOpen = XMLHttpRequest.prototype.open;
        var origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function (method, url) {
            this._vcUrl = typeof url === 'string' ? url : '';
            return origOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function () {
            if (this._vcUrl && this._vcUrl.indexOf('/auth/logout') !== -1) {
                this.addEventListener('loadend', function () {
                    purgeClientState(true);
                });
            }
            return origSend.apply(this, arguments);
        };
    }

    window.vcPurgeClientState = purgeClientState;
})();
