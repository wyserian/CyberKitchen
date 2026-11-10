/*
   core.js - CyberKitchen dashboard engine
   Generic, tool-agnostic: theme, toast, clipboard, download, storage, DOM
   helpers, tool registry, hash router and mount manager.
   Tools register a mount function by id via CK.registerTool(id, mountFn).
   Fully offline: no external dependencies.
*/
var CK = (function () {
  'use strict';

  var SVG_MOON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
  var SVG_SUN  = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';

  /* Storage (namespaced, failure-safe) */
  var PREFIX = 'ck.';
  var store = {
    get: function (k, d) {
      try { var v = localStorage.getItem(PREFIX + k); return v === null ? d : v; }
      catch (e) { return d; }
    },
    set: function (k, v) { try { localStorage.setItem(PREFIX + k, v); } catch (e) {} }
  };

  /* DOM helpers */
  function iconSvg(inner, size) {
    size = size || 15;
    return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="none" ' +
      'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + inner + '</svg>';
  }
  function el(tag, attrs, html) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === 'class') n.className = attrs[k];
      else if (k === 'html') n.innerHTML = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    if (html != null) n.innerHTML = html;
    return n;
  }

  /* Byte helpers shared by every tool (one copy, so they cannot drift apart) */
  function toHex(bytes) { bytes = new Uint8Array(bytes); var s = ''; for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0'); return s; }
  // Hex text -> bytes. Tolerates spaces, : , - separators and 0x / \x prefixes; anything else throws
  function hexToBytes(h) {
    h = String(h).replace(/\\x/gi, '').replace(/(^|[\s,:;-])0x/gi, '$1').replace(/[\s,:;-]/g, '');
    if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2) throw new Error('Invalid hexadecimal: use pairs of 0-9 / a-f');
    var a = new Uint8Array(h.length / 2);
    for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
    return a;
  }
  function b64(bytes) { bytes = new Uint8Array(bytes); var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  // Base64 or Base64URL text -> bytes (whitespace ignored); throws on invalid input
  function unb64(str) { str = String(str).replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin; try { bin = atob(str); } catch (e) { throw new Error('Invalid Base64'); } var a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  // Bytes -> unpadded Base64URL
  function b64u(bytes) { return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  // UTF-8 text <-> unpadded Base64URL (share links, JWT parts)
  function b64uEnc(str) { return b64u(new TextEncoder().encode(str)); }
  function b64uDec(str) { return new TextDecoder().decode(unb64(str)); }
  function pem(label, buf) { return '-----BEGIN ' + label + '-----\n' + b64(buf).replace(/(.{64})/g, '$1\n').trim() + '\n-----END ' + label + '-----'; }
  function unpem(str) { return unb64(String(str).replace(/-----[^-]+-----/g, '')); }
  // Join byte arrays (Uint8Array or plain arrays of numbers) into one Uint8Array
  function cat() {
    var parts = [].map.call(arguments, function (p) { return p instanceof Uint8Array ? p : new Uint8Array(p); }), n = 0, off = 0, i;
    for (i = 0; i < parts.length; i++) n += parts[i].length;
    var o = new Uint8Array(n);
    for (i = 0; i < parts.length; i++) { o.set(parts[i], off); off += parts[i].length; }
    return o;
  }
  // Run slow work after a short delay so the button spinner paints first; returns a promise of its result
  function later(fn) { return new Promise(function (res, rej) { setTimeout(function () { try { res(fn()); } catch (e) { rej(e); } }, 20); }); }
  // Text in a chosen format ('hex' | 'base64' | UTF-8 otherwise) -> bytes
  function textBytes(v, fmt) { return fmt === 'hex' ? hexToBytes(v) : fmt === 'base64' ? unb64(v) : new TextEncoder().encode(v); }
  // Best guess at the format of a key / IV / data field, and its length in bytes
  function detectFmt(s) {
    var c = (s || '').trim(), clean = c.replace(/\s/g, '');
    if (/^[0-9a-fA-F\s]+$/.test(c) && clean.length % 2 === 0 && clean.length >= 2) return 'hex';
    if (/^[A-Za-z0-9+/=\s]+$/.test(c) && clean.length % 4 === 0 && clean.length >= 4) { try { atob(clean); return 'base64'; } catch (e) { } }
    return 'utf8';
  }
  function fmtByteLen(s, fmt) {
    if (fmt === 'hex') return s.replace(/[^0-9a-fA-F]/g, '').length / 2;
    if (fmt === 'base64') { try { return atob(s.trim().replace(/\s/g, '')).length; } catch (e) { return null; } }
    return new TextEncoder().encode(s).length;
  }
  function fmtLabel(fmt) { return fmt === 'hex' ? 'Hexadecimal' : fmt === 'base64' ? 'Base64' : 'UTF-8'; }
  function rndBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  // Unbiased random integer in [0, max) (rejection sampling)
  function randInt(max) { var limit = Math.floor(0x100000000 / max) * max, a = new Uint32Array(1); do { crypto.getRandomValues(a); } while (a[0] >= limit); return a[0] % max; }
  // 32-bit number -> dotted IPv4
  function ipStr(n) { n = n >>> 0; return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
  // n random bytes as hex / Base64, or n printable ASCII characters. Bytes >= 188 are
  // rejected so each of the 94 characters is equally likely (188 = 2 * 94).
  function randomSecret(n, fmt) {
    if (fmt === 'hex') return toHex(rndBytes(n));
    if (fmt === 'base64') return b64(rndBytes(n));
    var s = '';
    while (s.length < n) { var b = rndBytes(Math.min(n, 65536)); for (var i = 0; i < b.length && s.length < n; i++) if (b[i] < 188) s += String.fromCharCode(33 + b[i] % 94); }
    return s;
  }

  /* Theme */
  var theme = {
    load: function () {
      var t = store.get('theme', 'dark');
      document.documentElement.setAttribute('data-theme', t);
      this._icon(t);
    },
    toggle: function () {
      var root = document.documentElement;
      var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      // Switch every colour at once: otherwise controls with hover transitions
      // fade from the old theme and flash light/dark against the new one.
      root.classList.add('theme-switching');
      root.setAttribute('data-theme', next);
      void root.offsetWidth; // apply the new colours while transitions are off
      requestAnimationFrame(function () { root.classList.remove('theme-switching'); });
      store.set('theme', next);
      this._icon(next);
    },
    _icon: function (t) {
      var i = document.getElementById('themeIcon');
      if (i) i.innerHTML = t === 'dark' ? SVG_SUN : SVG_MOON;
    }
  };

  /* Toast. Optional action = { label, fn, ms } adds a button (e.g. Undo); ms overrides how long it stays.
     Errors and actionable toasts stay longer so they can be read and used;
     clicking the toast dismisses it. Announced to screen readers. */
  var _toastEl = null, _toastTimer = null;
  function _hideToast() { if (_toastEl) _toastEl.classList.remove('show'); }
  function toast(msg, type, action) {
    type = type || 'success';
    if (!_toastEl) {
      _toastEl = el('div', { class: 'toast', role: 'status', 'aria-live': 'polite' });
      _toastEl.addEventListener('click', _hideToast);
      document.body.appendChild(_toastEl);
    }
    _toastEl.textContent = msg;
    if (action) {
      var b = el('button', { class: 'toast-act' });
      b.textContent = action.label;
      b.addEventListener('click', function (e) { e.stopPropagation(); _hideToast(); action.fn(); });
      _toastEl.appendChild(b);
    }
    _toastEl.className = 'toast ' + type;
    // force reflow so re-triggering the transition works
    void _toastEl.offsetWidth;
    _toastEl.classList.add('show');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(_hideToast, action && action.ms || (action || type === 'error' ? 6000 : type === 'warn' ? 4000 : 2600));
  }

  /* Clipboard */
  // onOk replaces the default "Copied" toast (used by share links)
  function copy(text, onOk) {
    if (text == null || text === '') { toast('Nothing to copy', 'warn'); return; }
    var ok = function () { if (onOk) onOk(); else toast('Copied to clipboard', 'success'); };
    var fallback = function () {
      try {
        var ta = el('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
        document.body.appendChild(ta);
        ta.focus(); ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        ok();
      } catch (e) { toast('Copy failed', 'error'); }
    };
    if (navigator.clipboard && navigator.clipboard.writeText)
      navigator.clipboard.writeText(text).then(ok).catch(fallback);
    else fallback();
  }

  /* Share link for a tool's state. Secret fields (keys, passwords) are left out unless the user
     chooses to include them: links end up in chat logs and browser history.
     secrets: { stateKey: 'label shown to the user' } */
  function share(id, state, secrets) {
    var base = location.href.split('#')[0] + '#tool=' + id + '&s=';
    var held = Object.keys(secrets || {}).filter(function (k) { return state[k]; });
    if (!held.length) { copy(base + b64uEnc(JSON.stringify(state))); return; }
    var safe = {}; Object.keys(state).forEach(function (k) { if (held.indexOf(k) < 0) safe[k] = state[k]; });
    var names = held.map(function (k) { return secrets[k]; }).join(' and ');
    copy(base + b64uEnc(JSON.stringify(safe)), function () {
      toast('Link copied without your ' + names, 'warn', { label: 'Include it', fn: function () {
        copy(base + b64uEnc(JSON.stringify(state)), function () { toast('Link includes your ' + names + ': share it only with people you trust', 'warn'); });
      } });
    });
  }

  /* Clipboard paste (returns a promise of text, or null) */
  function paste() {
    if (navigator.clipboard && navigator.clipboard.readText)
      return navigator.clipboard.readText().catch(function () { return null; });
    return Promise.resolve(null);
  }

  /* Download */
  function download(text, filename, mime) {
    if (text == null || text === '') { toast('Nothing to save', 'warn'); return; }
    var a = el('a');
    a.href = URL.createObjectURL(new Blob([text], { type: mime || 'text/plain' }));
    a.download = filename || 'cyberkitchen.txt';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Download started', 'success');
  }

  /* Tool registry */
  var _tools = [];          // manifest: {id,label,category,tag,icon,keys}; keys = extra search words
  var _categoryOrder = [];
  var _mounts = {};         // id -> mount function
  var _containers = {};     // id -> DOM element (created lazily)
  var _active = null;
  var _homeEl = null;       // landing page shown when no tool is selected

  function defineTools(list, categoryOrder) {
    _tools = list || [];
    _categoryOrder = categoryOrder || [];
  }
  function getTool(id) {
    for (var i = 0; i < _tools.length; i++) if (_tools[i].id === id) return _tools[i];
    return null;
  }
  // Tool scripts load before app.js boots, so every tool is registered before any mount
  function registerTool(id, mountFn) { _mounts[id] = mountFn; }
  // Non-empty categories in display order (listed order first, then any others as first seen)
  function _byCategory(fn) {
    var cats = _categoryOrder.slice();
    _tools.forEach(function (t) { if (cats.indexOf(t.category) === -1) cats.push(t.category); });
    cats.forEach(function (cat) {
      var inCat = _tools.filter(function (t) { return t.category === cat; });
      if (inCat.length) fn(cat, inCat);
    });
  }

  /* Rail */
  function buildRail() {
    var scroll = document.getElementById('railScroll');
    if (!scroll) return;
    scroll.innerHTML = '';
    _byCategory(function (cat, inCat) {
      scroll.appendChild(el('div', { class: 'grp' }, cat));
      inCat.forEach(function (t) {
        var btn = el('button', { class: 'item', 'data-id': t.id, title: t.label });
        btn.innerHTML = iconSvg(t.icon) +
          '<span class="nm">' + t.label + '</span>';
        btn.addEventListener('click', function () {
          navigate(t.id);
          document.body.classList.remove('drawer-open');
        });
        scroll.appendChild(btn);
      });
    });
  }
  function _markActiveRail(id) {
    var items = document.querySelectorAll('#railScroll .item');
    for (var i = 0; i < items.length; i++)
      items[i].classList.toggle('active', items[i].getAttribute('data-id') === id);
  }

  /* Mount management */
  function _doMount(id) {
    var root = _containers[id];
    if (_mounts[id]) {
      _mounts[id](root, { toast: toast });
      rememberSettings(id, root);
    } else {
      _renderPlaceholder(root, getTool(id));
    }
  }

  /* Remember a tool's settings: dropdowns, switches and number fields in its config panel.
     Text fields are never stored, so keys, secrets, passwords and inputs stay out of storage.
     A share link in the URL takes precedence over saved settings. */
  var SETTINGS = '.config select, .config input[type=checkbox], .config input[type=number], .config input[type=range]';
  function _settingEls(root) {
    var els = [].slice.call(root.querySelectorAll(SETTINGS)), seen = {};
    // Key each control by its label (plus a counter for repeats), so saved values survive layout changes
    return els.map(function (e) {
      var f = e.closest('.switch') || e.closest('.field'), lbl = f ? (f.querySelector('label') || f).textContent.trim() : '';
      var k = (lbl || e.tagName) + '|' + (e.type || ''); seen[k] = (seen[k] || 0) + 1;
      return { el: e, key: k + '#' + seen[k] };
    });
  }
  function rememberSettings(id, root) {
    var name = 'cfg.' + id, timer = null;
    if (!/(?:^|[#&])s=/.test(location.hash)) {
      var saved = null; try { saved = JSON.parse(store.get(name, 'null')); } catch (e) { }
      if (saved) {
        var rank = function (e) { return e.tagName === 'SELECT' ? 0 : e.type === 'checkbox' ? 1 : 2; };
        _settingEls(root).sort(function (a, b) { return rank(a.el) - rank(b.el); }).forEach(function (c) {
          var v = saved[c.key], e = c.el;
          if (v === undefined) return;
          if (e.type === 'checkbox') { if (e.checked !== v) { e.checked = v; e.dispatchEvent(new Event('change', { bubbles: true })); } }
          else if (e.value !== v && (e.tagName !== 'SELECT' || [].some.call(e.options, function (o) { return o.value === v; }))) {
            e.value = v; e.dispatchEvent(new Event(e.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
          }
        });
      }
    }
    function save() { var o = {}; _settingEls(root).forEach(function (c) { o[c.key] = c.el.type === 'checkbox' ? c.el.checked : c.el.value; }); store.set(name, JSON.stringify(o)); }
    function later() { clearTimeout(timer); timer = setTimeout(save, 300); }
    // click covers settings changed in code, e.g. by Reset or Detect
    root.addEventListener('change', later); root.addEventListener('input', later); root.addEventListener('click', later);
  }

  // Shown only when a tool's script failed to load (e.g. a library did not download)
  function _renderPlaceholder(root, tool) {
    var head = el('div', { class: 'tool-head' });
    head.innerHTML = '<h1>' + tool.label + '</h1>';
    var panel = el('div', { class: 'panel' });
    var ph = el('div', { class: 'ph' });
    ph.innerHTML =
      '<div class="ph-ico">' + iconSvg(tool.icon, 26) + '</div>' +
      '<div class="ph-title">' + tool.label + ' failed to load</div>' +
      '<div class="ph-note">Reload the page. If it keeps happening, clear this site\'s data so the offline copy is fetched again.</div>';
    panel.appendChild(ph);
    root.appendChild(head);
    root.appendChild(panel);
  }

  function activate(id) {
    if (!getTool(id)) id = _tools.length ? _tools[0].id : null;
    if (!id) return;
    _active = id;
    var main = document.getElementById('main');
    if (!_containers[id]) {
      var c = el('div', { class: 'tool', 'data-id': id });
      _containers[id] = c;
      main.appendChild(c);
      _doMount(id);
    }
    Object.keys(_containers).forEach(function (k) {
      _containers[k].hidden = (k !== id);
    });
    if (_homeEl) _homeEl.hidden = true;
    _markActiveRail(id);
    document.title = getTool(id).label + ' - CyberKitchen';
  }

  /* Home / landing page: shown when no tool is selected.
     Per-category card metadata (icon, one-line description, accent colour). */
  var CAT_META = {
    Encryption: { color: '#3b82f6', desc: 'Symmetric & asymmetric encryption', icon: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>' },
    Hashing: { color: '#10b981', desc: 'Hashing & key derivation', icon: '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>' },
    Encoding: { color: '#f59e0b', desc: 'Encode, decode & convert', icon: '<path d="M8 6 3 12l5 6M16 6l5 6-5 6M13 4l-2 16"/>' },
    Authentication: { color: '#8b5cf6', desc: 'One-time codes & tokens', icon: '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/>' },
    Networking: { color: '#06b6d4', desc: 'IP & subnet calculators', icon: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-2h12v2"/>' },
    Developer: { color: '#ec4899', desc: 'Everyday developer utilities', icon: '<path d="M8 4H6a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h2M16 4h2a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-2"/>' },
    Generators: { color: '#6366f1', desc: 'Passwords, data & QR codes', icon: '<path d="m4 20 10-10M14.5 4.5l1 2 2 1-2 1-1 2-1-2-2-1 2-1zM6.5 11.5l.8 1.7 1.7.8-1.7.8-.8 1.7-.8-1.7-1.7-.8 1.7-.8z"/>' }
  };
  function _rgba(hex, a) { var n = parseInt(hex.slice(1), 16); return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')'; }

  function _buildHome() {
    var wrap = el('div', { class: 'home' });
    var inner = el('div', { class: 'home-inner' });
    var hero = el('div', { class: 'home-hero' });
    hero.innerHTML = '<h1>Recipes for Hackers</h1><p>A browser-based toolkit for encryption, hashing, key derivation, encoding, conversion, authentication, networking and developer utilities. All processing happens locally, so no data ever leaves your machine.</p>';
    inner.appendChild(hero);

    // Live tool search
    var search = el('input', { class: 'home-search', type: 'search', placeholder: 'Search tools...', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Search tools', 'aria-keyshortcuts': '/' });
    // "/" focuses the search from anywhere on the home page (unless typing in a field)
    document.addEventListener('keydown', function (e) {
      if (e.key !== '/' || _active !== null || e.ctrlKey || e.metaKey || e.altKey) return;
      var t = e.target.tagName;
      if (t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || e.target.isContentEditable) return;
      e.preventDefault(); search.focus();
    });
    // Search box with a right-aligned "/" shortcut hint (hidden while typing)
    var searchWrap = el('div', { class: 'home-search-wrap' });
    searchWrap.appendChild(search);
    searchWrap.appendChild(el('kbd', { class: 'home-kbd', 'aria-hidden': 'true' }, '/'));
    inner.appendChild(searchWrap);

    var grid = el('div', { class: 'home-grid' });
    var sections = [];
    _byCategory(function (cat, inCat) {
      var meta = CAT_META[cat] || { color: '#3b82f6', desc: '', icon: '<circle cx="12" cy="12" r="9"/>' };
      var card = el('div', { class: 'home-cat-card' });
      var head = el('div', { class: 'hcc-head' });
      // Accent underline in the category colour separates one section from the next
      head.style.borderBottom = '2px solid ' + _rgba(meta.color, 0.45);
      head.style.paddingBottom = '9px';
      head.innerHTML = '<span class="hcc-ico" style="background:' + _rgba(meta.color, 0.13) + ';color:' + meta.color + '">' + iconSvg(meta.icon, 19) + '</span>' +
        '<span class="hcc-txt"><span class="hcc-title">' + cat + '</span><span class="hcc-desc">' + meta.desc + '</span></span>';
      card.appendChild(head);
      var list = el('div', { class: 'hcc-tools' });
      var rows = [];
      inCat.forEach(function (t) {
        var row = el('button', { class: 'hcc-tool', 'data-id': t.id, title: t.label });
        row.innerHTML = '<span class="hcc-ticon">' + iconSvg(t.icon, 15) + '</span><span class="hcc-tname">' + t.label + '</span>' + (t.tag ? '<span class="hcc-ttag">' + t.tag + '</span>' : '');
        row.addEventListener('click', function () { navigate(t.id); });
        list.appendChild(row);
        rows.push({ el: row, id: t.id, text: (t.label + ' ' + (t.tag || '') + ' ' + (t.keys || '') + ' ' + cat + ' ' + (meta.desc || '')).toLowerCase() });
      });
      card.appendChild(list);
      grid.appendChild(card);
      sections.push({ card: card, rows: rows });
    });
    inner.appendChild(grid);
    wrap.appendChild(inner);

    function filterTools() {
      var q = search.value.trim().toLowerCase();
      sections.forEach(function (sec) {
        var any = false;
        sec.rows.forEach(function (r) { var hit = !q || r.text.indexOf(q) >= 0; r.el.style.display = hit ? '' : 'none'; if (hit) any = true; });
        sec.card.style.display = any ? '' : 'none';
      });
    }
    search.addEventListener('input', filterTools);
    search.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter') return;
      for (var i = 0; i < sections.length; i++) for (var j = 0; j < sections[i].rows.length; j++) {
        if (sections[i].rows[j].el.style.display !== 'none') { navigate(sections[i].rows[j].id); return; }
      }
    });
    return wrap;
  }
  function showHome() {
    _active = null;
    var main = document.getElementById('main');
    if (!_homeEl) { _homeEl = _buildHome(); main.appendChild(_homeEl); }
    Object.keys(_containers).forEach(function (k) { _containers[k].hidden = true; });
    _homeEl.hidden = false;
    _markActiveRail(null);
    document.title = 'CyberKitchen - Recipes for Hackers';
  }

  /* Router */
  function currentId() {
    var m = /(?:^|[#&])tool=([\w-]+)/.exec(location.hash || '');
    return m ? m[1] : null;
  }
  function navigate(id) {
    if (id === _active) return;
    location.hash = 'tool=' + id;
  }
  function _onHash() {
    var id = currentId();
    if (id) { if (id !== _active) activate(id); }
    else if (_active !== null || !_homeEl) showHome();
  }

  /* Shell wiring */
  function _wireShell() {
    var themeBtn = document.getElementById('themeBtn');
    if (themeBtn) themeBtn.addEventListener('click', function () { theme.toggle(); });

    var backdrop = document.getElementById('backdrop');
    if (backdrop) backdrop.addEventListener('click', function () { document.body.classList.remove('drawer-open'); });

    // Brand returns to the home page without a full reload
    var brand = document.querySelector('.brand');
    if (brand) brand.addEventListener('click', function (e) {
      e.preventDefault();
      document.body.classList.remove('drawer-open');
      if (currentId()) location.hash = ''; else showHome();
    });
  }

  function boot() {
    theme.load();
    buildRail();
    _wireShell();
    var id = currentId();
    if (id) activate(id); else showHome();
    window.addEventListener('hashchange', _onHash);
  }

  // Rough password strength: 6-point score to a labelled, colour-coded rating (used by attachStrength)
  function pwStrength(pw) {
    var s = 0;
    if (pw.length >= 8) s++; if (pw.length >= 12) s++;
    if (/[A-Z]/.test(pw)) s++; if (/[a-z]/.test(pw)) s++;
    if (/[0-9]/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw)) s++;
    var i = Math.min(s, 6);
    return { label: ['Too short', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong', 'Excellent'][i], cls: ['err', 'err', 'warn', 'warn', 'ok', 'ok', 'ok'][i] };
  }
  // Attach a live strength pill to a text panel's input, sitting just left of the char-count
  function attachStrength(panelObj) {
    var panel = panelObj.panel, ta = panelObj.ta;
    var badge = el('span', { class: 'pw-strength' });
    panel.appendChild(badge);
    var cc = panel.querySelector('.char-count');
    function update() {
      var pw = ta.value;
      if (!pw) { badge.style.display = 'none'; return; }
      badge.style.display = '';
      var r = pwStrength(pw);
      badge.textContent = r.label;
      badge.className = 'pw-strength ' + r.cls;
      badge.style.right = (23 + (cc ? cc.offsetWidth : 0) + 8) + 'px';
    }
    if (panelObj.onContent) panelObj.onContent(update); else ta.addEventListener('input', update);
    update();
    return update;
  }

  // Flash a pass/fail highlight on one or more textareas, auto-clearing after 5s
  function flashVerify(match) {
    var els = Array.prototype.slice.call(arguments, 1).filter(Boolean);
    els.forEach(function (t) {
      clearTimeout(t._vfTimer);
      t.classList.remove('verify-match', 'verify-fail');
      t.classList.add(match ? 'verify-match' : 'verify-fail');
      t._vfTimer = setTimeout(function () { t.classList.remove('verify-match', 'verify-fail'); }, 5000);
    });
  }

  return {
    boot: boot, defineTools: defineTools, registerTool: registerTool,
    toast: toast, copy: copy, paste: paste, download: download,
    el: el, iconSvg: iconSvg, flashVerify: flashVerify, attachStrength: attachStrength,
    share: share, rememberSettings: rememberSettings, toHex: toHex, hexToBytes: hexToBytes, b64: b64, unb64: unb64, b64u: b64u, b64uEnc: b64uEnc, b64uDec: b64uDec,
    pem: pem, unpem: unpem, cat: cat, later: later, textBytes: textBytes, detectFmt: detectFmt, fmtByteLen: fmtByteLen, fmtLabel: fmtLabel,
    rndBytes: rndBytes, randInt: randInt, randomSecret: randomSecret, ipStr: ipStr
  };
})();
