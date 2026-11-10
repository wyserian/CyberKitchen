/*
   text.js - Text Cleaner
   Three modes on pasted text, all local:
   - Clean: whitespace, blank and duplicate lines, sorting, case, HTML, punctuation,
     Unicode, and removal of invisible characters (zero-width, bidi overrides).
   - Extract: emails, URLs, domains, IPv4/IPv6, UUIDs, JWTs, Base64 and hex (decoded) and hashes.
   - Redact: hide emails, IPs, JWTs, API keys and tokens, private keys and card
     numbers before sharing. Known formats only, so the output still needs a review.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec, BS = String.fromCharCode(92);

  // Regex character class from code points and [from, to] ranges. Built at run time so
  // the source never contains raw invisible characters.
  function u(c) { return BS + 'u' + ('000' + c.toString(16)).slice(-4); }
  function cls(list) { return '[' + list.map(function (r) { return typeof r === 'number' ? u(r) : u(r[0]) + '-' + u(r[1]); }).join('') + ']'; }
  // Zero-width characters, bidi overrides, BOM, soft hyphen and control characters (tab and newlines kept)
  var INVISIBLE = new RegExp(cls([[0, 8], 11, 12, [14, 31], 127, 0xAD, [0x200B, 0x200F], [0x202A, 0x202E], [0x2060, 0x2064], [0x2066, 0x2069], 0xFEFF]), 'g');
  var MARKS = new RegExp(cls([[0x300, 0x36F]]), 'g');
  var PUNCT = {};
  [[0x2018, "'"], [0x2019, "'"], [0x201A, "'"], [0x201B, "'"], [0x2032, "'"], [0x201C, '"'], [0x201D, '"'], [0x201E, '"'], [0x201F, '"'],
    [0x2033, '"'], [0x2013, '-'], [0x2014, '-'], [0x2212, '-'], [0x2026, '...'], [0xA0, ' ']].forEach(function (p) { PUNCT[String.fromCharCode(p[0])] = p[1]; });
  var PUNCT_RE = new RegExp(cls(Object.keys(PUNCT).map(function (c) { return c.charCodeAt(0); })), 'g');

  /* ---- Clean ---- */
  var ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  function stripHtml(s) {
    return s.replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, '').replace(/<!--[\s\S]*?-->/g, '')
      .replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li|tr|h[1-6])\s*>/gi, '\n').replace(/<[^>]+>/g, '')
      .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, function (m, e) {
        if (e.charAt(0) === '#') { var n = /x/i.test(e.charAt(1)) ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : m; }
        return ENT[e.toLowerCase()] != null ? ENT[e.toLowerCase()] : m;
      });
  }
  function words(l) { return l.replace(/([\p{Ll}\p{N}])(\p{Lu})/gu, '$1 $2').split(/[^\p{L}\p{N}]+/u).filter(Boolean); }
  function lowerAll(ws) { return ws.map(function (w) { return w.toLowerCase(); }); }
  var CASES = {
    lower: function (l) { return l.toLowerCase(); },
    upper: function (l) { return l.toUpperCase(); },
    title: function (l) { return l.toLowerCase().replace(/(^|[^\p{L}\p{N}'])(\p{L})/gu, function (m, a, b) { return a + b.toUpperCase(); }); },
    camel: function (l) { return lowerAll(words(l)).map(function (w, i) { return i ? w.charAt(0).toUpperCase() + w.slice(1) : w; }).join(''); },
    snake: function (l) { return lowerAll(words(l)).join('_'); },
    kebab: function (l) { return lowerAll(words(l)).join('-'); }
  };
  function clean(src, o) {
    var invisible = 0, s = src;
    if (o.invisible) s = s.replace(INVISIBLE, function () { invisible++; return ''; });
    if (o.html) s = stripHtml(s);
    if (o.ascii) s = s.replace(PUNCT_RE, function (c) { return PUNCT[c]; });
    if (o.unicode !== 'none') s = s.normalize(o.unicode);
    if (o.accents) s = s.normalize('NFD').replace(MARKS, '').normalize('NFC');
    var lines = s.split(/\r\n|\r|\n/), before = lines.length, dupes = 0;
    lines = lines.map(function (l) {
      if (o.trim) l = l.trim();
      if (o.collapse) l = l.replace(/[ \t]+/g, ' ');
      return CASES[o.case] ? CASES[o.case](l) : l;
    });
    if (o.blank) lines = lines.filter(function (l) { return l.trim() !== ''; });
    if (o.dedupe) { var seen = new Set(); lines = lines.filter(function (l) { if (seen.has(l)) { dupes++; return false; } seen.add(l); return true; }); }
    if (o.sort === 'az') lines.sort(function (a, b) { return a.localeCompare(b); });
    else if (o.sort === 'za') lines.sort(function (a, b) { return b.localeCompare(a); });
    else if (o.sort === 'len') lines.sort(function (a, b) { return a.length - b.length; });
    return { text: lines.join('\n'), before: before, after: lines.length, invisible: invisible, dupes: dupes };
  }

  /* ---- Extract ---- */
  var EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;
  var URL_RE = /\b(?:https?|ftp):\/\/[^\s<>"'`]+/gi;
  // Not part of a longer dotted number (so version strings like 1.2.3.4.5 are skipped)
  var IPV4 = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\.?\d)/g;
  var IPV6_CAND = /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/gi;
  var UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
  var JWT = /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  var HEX = /(?<![0-9a-f])[0-9a-f]{32,128}(?![0-9a-f])/gi;
  var HASH_LEN = { 32: 'MD5', 40: 'SHA-1', 56: 'SHA-224', 64: 'SHA-256', 96: 'SHA-384', 128: 'SHA-512' };

  function isIPv6(s) {
    var halves = s.split('::');
    if (halves.length > 2 || !/[0-9a-f]/i.test(s)) return false;
    var groups = (halves[0] ? halves[0].split(':') : []).concat(halves[1] ? halves[1].split(':') : []);
    if (!groups.every(function (g) { return /^[0-9a-f]{1,4}$/i.test(g); })) return false;
    return halves.length === 2 ? groups.length < 8 : groups.length === 8;
  }
  // Drop trailing sentence punctuation and unbalanced closing brackets from a URL
  function trimUrl(v) {
    var pair = { ')': '(', ']': '[', '}': '{' };
    for (;;) {
      v = v.replace(/[.,;:!?'"]+$/, '');
      var last = v.slice(-1), open = pair[last];
      if (!open || v.split(open).length >= v.split(last).length) return v;
      v = v.slice(0, -1);
    }
  }
  var B64 = /(?<![A-Za-z0-9+\/_-])[A-Za-z0-9+\/_-]{12,}={0,2}(?![A-Za-z0-9+\/=_-])/g, CTRL = new RegExp(INVISIBLE.source);
  // \x41\x42..., 0x4142... or 41424344..., and byte pairs split by spaces or colons (41 42 43 44, 41:42:43:44)
  var HEXSTR = /(?<![0-9A-Za-z_:\\-])(?:(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x)?[0-9a-fA-F]{8,}|[0-9a-fA-F]{2}([ :])(?:[0-9a-fA-F]{2}\1){2,}[0-9a-fA-F]{2})(?![0-9A-Za-z_:-])/g;
  // "value  ->  decoded" when the bytes are readable UTF-8 text, else the value alone when keepBinary
  function decoded(v, toBytes, keepBinary) {
    var t; try { t = new TextDecoder('utf-8', { fatal: true }).decode(toBytes(v)); } catch (e) { t = null; }
    if (t != null && t.trim() && !CTRL.test(t)) { t = t.replace(/\s+/g, ' ').trim(); return v + '  ->  ' + (t.length > 60 ? t.slice(0, 60) + '...' : t); }
    return keepBinary ? v : '';
  }
  // Base64 (standard or URL-safe). Needs upper and lower case plus a digit or symbol, so plain
  // words and hex hashes are skipped. Binary also needs 24+ chars and a digit, so paths and
  // identifiers (random/maxObserveMousemove) are not listed.
  function base64(s) {
    return all(B64, s.replace(URL_RE, ' ').replace(JWT, ' ')).map(function (v) {
      if (v.replace(/=+$/, '').length % 4 === 1 || !/[A-Z]/.test(v) || !/[a-z]/.test(v) || !/[\d+\/_=-]/.test(v)) return '';
      return decoded(v, CK.unb64, v.length >= 24 && /\d/.test(v));
    }).filter(Boolean);
  }
  // Hex: even length; unbroken forms need digits and letters. Binary needs 16+ hex digits (so a
  // MAC address is skipped), and binary of hash length is left to Hashes.
  function hex(s) {
    return all(HEXSTR, s.replace(URL_RE, ' ')).map(function (v) {
      var sep = /\\x|[\s:]/i.test(v), h = v.replace(/\\x|[\s:]|^0x/gi, '');
      if (h.length % 2 || (!sep && (!/\d/.test(h) || !/[a-f]/i.test(h)))) return '';
      return decoded(v, CK.hexToBytes, h.length >= 16 && !HASH_LEN[h.length]);
    }).filter(Boolean);
  }
  function all(re, s) { return s.match(re) || []; }
  var FIND = {
    emails: { label: 'Emails', find: function (s) { return all(EMAIL, s); } },
    urls: { label: 'URLs', find: function (s) { return all(URL_RE, s).map(trimUrl); } },
    domains: { label: 'Domains', find: function (s) {
      var hosts = all(URL_RE, s).map(function (v) { try { return new URL(trimUrl(v)).hostname; } catch (e) { return ''; } });
      return hosts.concat(all(EMAIL, s).map(function (e) { return e.split('@')[1]; }))
        .map(function (h) { return h.toLowerCase(); }).filter(function (h) { return h && !/^[\d.]+$/.test(h) && h.charAt(0) !== '['; });
    } },
    ipv4: { label: 'IPv4 addresses', find: function (s) { return all(IPV4, s); } },
    ipv6: { label: 'IPv6 addresses', find: function (s) { return all(IPV6_CAND, s).filter(isIPv6); } },
    uuids: { label: 'UUIDs', find: function (s) { return all(UUID, s); } },
    jwts: { label: 'JWTs', find: function (s) { return all(JWT, s); } },
    base64: { label: 'Base64', find: base64 },
    hex: { label: 'Hex', find: hex },
    hashes: { label: 'Hashes', find: function (s) { return all(HEX, s).filter(function (h) { return HASH_LEN[h.length]; }).map(function (h) { return HASH_LEN[h.length] + '  ' + h; }); } }
  };
  function listOut(vals, o) {
    var counts = new Map();
    vals.forEach(function (v) { counts.set(v, (counts.get(v) || 0) + 1); });
    var keys = o.unique || o.counts ? Array.from(counts.keys()) : vals.slice();
    if (o.sort) keys.sort(function (a, b) { return a.localeCompare(b); });
    return keys.map(function (k) { return o.counts ? (counts.get(k) + 'x').padStart(5) + '  ' + k : k; });
  }
  function extract(src, type, o) {
    var ids = type === 'all' ? Object.keys(FIND) : [type], total = 0, out = [];
    ids.forEach(function (id) {
      var vals = listOut(FIND[id].find(src), o);
      total += vals.length;
      if (type !== 'all') out = vals;
      else if (vals.length) out.push((out.length ? '\n' : '') + FIND[id].label + ' (' + vals.length + ')', vals.join('\n'));
    });
    return { text: out.join('\n'), found: total };
  }

  /* ---- Redact ---- */
  function luhn(d) { var sum = 0; for (var i = 0; i < d.length; i++) { var n = +d.charAt(d.length - 1 - i); if (i % 2) { n *= 2; if (n > 9) n -= 9; } sum += n; } return sum % 10 === 0; }
  // Order matters: whole private-key blocks and JWTs go before the shorter patterns inside them.
  // keep: the pattern's first group is kept (e.g. "Bearer "), only the secret after it is hidden.
  var REDACT = [
    { cat: 'privkeys', name: 'private key', tag: '[PRIVATE KEY]', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g },
    { cat: 'jwts', name: 'JWT', tag: '[JWT]', re: JWT },
    { cat: 'keys', name: 'AWS access key', tag: '[AWS KEY]', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { cat: 'keys', name: 'GitHub token', tag: '[GITHUB TOKEN]', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
    { cat: 'keys', name: 'Slack token', tag: '[SLACK TOKEN]', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
    { cat: 'keys', name: 'Stripe key', tag: '[STRIPE KEY]', re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
    { cat: 'keys', name: 'Google API key', tag: '[GOOGLE KEY]', re: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g },
    { cat: 'keys', name: 'API key', tag: '[API KEY]', re: /\bsk-[A-Za-z0-9_-]{20,}/g },
    { cat: 'keys', name: 'bearer token', tag: '[TOKEN]', keep: true, re: /(\bBearer\s+)[A-Za-z0-9._~+\/-]{16,}=*/g },
    { cat: 'keys', name: 'URL password', tag: '[PASSWORD]', keep: true, re: /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:\/@]+:)[^\s@\/]+(?=@)/gi },
    { cat: 'cards', name: 'card number', tag: '[CARD]', luhn: true, re: /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g },
    { cat: 'emails', name: 'email', tag: '[EMAIL]', re: EMAIL },
    { cat: 'ips', name: 'IP address', tag: '[IP]', re: IPV4 },
    { cat: 'ips', name: 'IP address', tag: '[IP]', v6: true, re: IPV6_CAND }
  ];
  function plural(n, one) { return n + ' ' + (n === 1 ? one : /s$/.test(one) ? one + 'es' : one + 's'); }
  function redact(src, cats) {
    var hits = {}, s = src;
    REDACT.forEach(function (r) {
      if (!cats[r.cat]) return;
      s = s.replace(r.re, function (m, g1) {
        if (r.luhn) { var d = m.replace(/\D/g, ''); if (d.length < 13 || d.length > 19 || !luhn(d)) return m; }
        if (r.v6 && !isIPv6(m)) return m;
        hits[r.name] = (hits[r.name] || 0) + 1;
        return r.keep ? g1 + r.tag : r.tag;
      });
    });
    var names = Object.keys(hits);
    return { text: s, hidden: names.reduce(function (n, k) { return n + hits[k]; }, 0), summary: names.map(function (k) { return plural(hits[k], k); }).join(', ') };
  }

  var I_TEXT = '<path d="M4 6h16M4 12h10M4 18h7"/><path d="m18 14 1 2.5 2.5 1-2.5 1-1 2.5-1-2.5-2.5-1 2.5-1z"/>';

  CK.registerTool('text', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('Text Cleaner'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_TEXT);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.swap, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Mode first; only the chosen mode's options are shown next to it
    var grid = el('div', { class: 'cfg-grid wide-right' });
    var colA = el('div', { class: 'col' }), colB = el('div', { class: 'col' });
    var modeSel = ui.select([['clean', 'Clean'], ['extract', 'Extract'], ['redact', 'Redact']], function () { applyMode(); run(); }, 'clean');
    colA.appendChild(ui.field('Mode', modeSel));
    function row() { return el('div', { style: 'display:flex; flex-wrap:wrap; gap:8px 18px; align-items:center;' }); }
    // key -> { cb, def }; key -> { sel, def }
    var SW = {}, SEL = {};
    function sw(key, label, def, list) { var t = ui.toggle(label, def, run); list.appendChild(t.wrap); SW[key] = { cb: t.cb, def: def }; }
    function sel(key, items, def) { var s = ui.select(items, run, def); SEL[key] = { sel: s, def: def }; return s; }

    var cleanBox = el('div', { class: 'col' }), cRow = row();
    sw('trim', 'Trim lines', true, cRow); sw('collapse', 'Collapse spaces', true, cRow);
    sw('blank', 'Remove blank lines', false, cRow); sw('dedupe', 'Remove duplicate lines', false, cRow);
    sw('invisible', 'Remove invisible characters', true, cRow); sw('html', 'Strip HTML tags', false, cRow);
    sw('ascii', 'Plain ASCII punctuation', false, cRow); sw('accents', 'Remove accents', false, cRow);
    var cSel = el('div', { style: 'display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px 14px;' });
    cSel.appendChild(ui.field('Case', sel('case', [['none', 'Unchanged'], ['lower', 'lowercase'], ['upper', 'UPPERCASE'], ['title', 'Title Case'], ['camel', 'camelCase'], ['snake', 'snake_case'], ['kebab', 'kebab-case']], 'none')));
    cSel.appendChild(ui.field('Sort lines', sel('sort', [['none', 'Keep order'], ['az', 'A to Z'], ['za', 'Z to A'], ['len', 'By length']], 'none')));
    cSel.appendChild(ui.field('Unicode', sel('unicode', [['none', 'Unchanged'], ['NFC', 'NFC (composed)'], ['NFKC', 'NFKC (compatibility)']], 'none')));
    cleanBox.appendChild(ui.field('Cleanup', cRow)); cleanBox.appendChild(cSel);

    var extractBox = el('div', { class: 'col' }), eRow = row();
    var findItems = [['all', 'Everything']].concat(Object.keys(FIND).map(function (k) { return [k, FIND[k].label]; }));
    sw('unique', 'Unique only', true, eRow); sw('sorted', 'Sort A to Z', false, eRow); sw('counts', 'Show counts', false, eRow);
    extractBox.appendChild(ui.field('Find', sel('find', findItems, 'all'))); extractBox.appendChild(ui.field('Options', eRow));

    var redactBox = el('div', { class: 'col' }), rRow = row();
    sw('emails', 'Emails', true, rRow); sw('ips', 'IP addresses', true, rRow); sw('jwts', 'JWTs', true, rRow);
    sw('keys', 'API keys and tokens', true, rRow); sw('privkeys', 'Private keys', true, rRow); sw('cards', 'Card numbers', true, rRow);
    redactBox.appendChild(ui.field('Hide', rRow));

    colB.appendChild(cleanBox); colB.appendChild(extractBox); colB.appendChild(redactBox);
    grid.appendChild(colA); grid.appendChild(colB);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_TEXT, placeholder: 'Paste text, logs or HTML...', primaries: [{ label: 'Apply', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt', onInput: run });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: CK.ui.IC.out, placeholder: 'Result appears here...', readonly: true, actions: ['copy', 'download'], downloadName: 'output.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function opt() {
      var r = {};
      Object.keys(SW).forEach(function (k) { r[k] = SW[k].cb.checked; });
      Object.keys(SEL).forEach(function (k) { r[k] = SEL[k].sel.value; });
      return r;
    }
    function applyMode() {
      var m = modeSel.value;
      cleanBox.style.display = m === 'clean' ? '' : 'none';
      extractBox.style.display = m === 'extract' ? '' : 'none';
      redactBox.style.display = m === 'redact' ? '' : 'none';
    }
    var REVIEW = 'Catches known formats only: review before sharing.';
    function show(badge, desc) { ui.setSel(strip, 'Text Cleaner', badge, desc); }
    function idle() {
      var m = modeSel.value;
      show(m === 'clean' ? 'Clean' : m === 'extract' ? 'Extract' : 'Redact',
        m === 'clean' ? 'Tidy whitespace, lines, case and Unicode; remove invisible characters.' :
        m === 'extract' ? 'Pull emails, URLs, IPs, UUIDs, JWTs, Base64, hex and hashes out of any text.' :
        'Hide emails, IPs, tokens, keys and card numbers before sharing. ' + REVIEW);
    }
    function run() {
      var src = inP.ta.value, m = modeSel.value, op = opt(), r;
      if (!src) { outP.ta.value = ''; idle(); return; }
      if (m === 'clean') {
        r = clean(src, op); outP.ta.value = r.text;
        show(r.after + ' lines', r.before + ' lines in, ' + r.after + ' out' + (r.dupes ? ', ' + plural(r.dupes, 'duplicate') + ' removed' : '') +
          (r.invisible ? ', ' + plural(r.invisible, 'invisible character') + ' removed' : '') + '.');
      } else if (m === 'extract') {
        r = extract(src, op.find, { unique: op.unique, sort: op.sorted, counts: op.counts }); outP.ta.value = r.text;
        show(r.found + ' found', r.found ? (op.unique || op.counts ? 'Unique values' : 'All occurrences') + (op.counts ? ' with how often each appears.' : '.') : 'Nothing found.');
      } else {
        r = redact(src, op); outP.ta.value = r.text;
        show(r.hidden + ' hidden', (r.hidden ? 'Hid ' + r.summary + '. ' : 'Nothing found to hide. ') + REVIEW);
      }
    }
    function doSwap() { inP.ta.value = outP.ta.value; run(); }
    // The text itself may hold secrets (that is what Redact is for), so share links leave it out by default
    function doShare() { CK.share('text', { m: modeSel.value, o: opt(), in: inP.ta.value }, { in: 'text' }); }
    function doReset() {
      inP.ta.value = ''; modeSel.value = 'clean';
      Object.keys(SW).forEach(function (k) { SW[k].cb.checked = SW[k].def; });
      Object.keys(SEL).forEach(function (k) { SEL[k].sel.value = SEL[k].def; });
      applyMode(); run();
    }

    var m0 = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m0) {
      try {
        var st = JSON.parse(b64uDec(m0[1]));
        if (st.m) modeSel.value = st.m;
        Object.keys(st.o || {}).forEach(function (k) { if (SW[k]) SW[k].cb.checked = !!st.o[k]; else if (SEL[k]) SEL[k].sel.value = st.o[k]; });
        inP.ta.value = st.in || '';
      } catch (e) { }
    }
    applyMode(); run();
  });
})();
