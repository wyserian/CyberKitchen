/*
   hash.js - Cryptographic Hash
   Select one algorithm (MD5, SHA-1, RIPEMD-160, CRC32, SHA-2, SHA-3, Keccak),
   optional HMAC, input UTF-8/Hex/Base64, output hex/HEX/Base64/Base64URL.
   Input-driven panels with Hash, plus Verify / Detect / Swap / Share / Reset.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec, toHex = CK.toHex, hexToBytes = CK.hexToBytes, unb64 = CK.unb64, b64 = CK.b64, randomSecret = CK.randomSecret;
  function concat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }
  function webBytes(algo, b) { return crypto.subtle.digest(algo, b).then(function (h) { return new Uint8Array(h); }); }
  function P(hex) { return Promise.resolve(hexToBytes(hex)); }

  // hb: bytes -> Promise<Uint8Array>; block = HMAC block size; bytes = digest length
  var ALGOS = [
    { id: 'md5', label: 'MD5', group: 'Legacy', badge: 'RFC1321', bytes: 16, block: 64, hb: function (b) { return P(HashLib.md5(b)); } },
    { id: 'sha1', label: 'SHA-1', group: 'Legacy', badge: 'SHA-1', bytes: 20, block: 64, hb: function (b) { return webBytes('SHA-1', b); } },
    { id: 'ripemd160', label: 'RIPEMD-160', group: 'Legacy', badge: 'RIPEMD', bytes: 20, block: 64, hb: function (b) { return P(HashLib.ripemd160(b)); } },
    { id: 'crc32', label: 'CRC32', group: 'Legacy', badge: 'Checksum', bytes: 4, block: 0, hmac: false, hb: function (b) { return P(HashLib.crc32(b)); } },
    { id: 'sha256', label: 'SHA-256', group: 'SHA-2', badge: 'SHA-2', bytes: 32, block: 64, hb: function (b) { return webBytes('SHA-256', b); } },
    { id: 'sha384', label: 'SHA-384', group: 'SHA-2', badge: 'SHA-2', bytes: 48, block: 128, hb: function (b) { return webBytes('SHA-384', b); } },
    { id: 'sha512', label: 'SHA-512', group: 'SHA-2', badge: 'SHA-2', bytes: 64, block: 128, hb: function (b) { return webBytes('SHA-512', b); } },
    { id: 'sha3-224', label: 'SHA3-224', group: 'SHA-3', badge: 'SHA-3', bytes: 28, block: 144, hb: function (b) { return P(HashLib.sha3(224, b)); } },
    { id: 'sha3-256', label: 'SHA3-256', group: 'SHA-3', badge: 'SHA-3', bytes: 32, block: 136, hb: function (b) { return P(HashLib.sha3(256, b)); } },
    { id: 'sha3-384', label: 'SHA3-384', group: 'SHA-3', badge: 'SHA-3', bytes: 48, block: 104, hb: function (b) { return P(HashLib.sha3(384, b)); } },
    { id: 'sha3-512', label: 'SHA3-512', group: 'SHA-3', badge: 'SHA-3', bytes: 64, block: 72, hb: function (b) { return P(HashLib.sha3(512, b)); } },
    { id: 'keccak-256', label: 'Keccak-256', group: 'SHA-3', badge: 'Keccak', bytes: 32, block: 136, hb: function (b) { return P(HashLib.keccak(256, b)); } }
  ];
  function get(id) { for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) return ALGOS[i]; return null; }
  var GROUPS = ['Legacy', 'SHA-2', 'SHA-3'];
  var BY_LEN = { 4: 'crc32', 16: 'md5', 20: 'sha1', 28: 'sha3-224', 32: 'sha256', 48: 'sha384', 64: 'sha512' };

  function hmac(algo, keyBytes, msgBytes) {
    var bs = algo.block;
    return (keyBytes.length > bs ? algo.hb(keyBytes) : Promise.resolve(keyBytes)).then(function (k0) {
      var k = new Uint8Array(bs), ipad = new Uint8Array(bs), opad = new Uint8Array(bs), i; k.set(k0);
      for (i = 0; i < bs; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
      return algo.hb(concat(ipad, msgBytes)).then(function (inner) { return algo.hb(concat(opad, inner)); });
    });
  }
  function fmtHex(hx, fmt) { if (fmt === 'HEX') return hx.toUpperCase(); if (fmt === 'base64') return b64(hexToBytes(hx)); if (fmt === 'base64url') return CK.b64u(hexToBytes(hx)); return hx; }
  function outByteLen(s) { s = s.trim().replace(/\s/g, ''); if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return s.length / 2; try { return unb64(s).length; } catch (e) { return null; } }

  var I_HASH = CK.ui.IC.hash;
  var I_FILE = CK.ui.IC.file;
  var I_CHECK = CK.ui.IC.check;
  var I_DETECT = CK.ui.IC.detect;
  var I_SWAP = CK.ui.IC.swap;
  var I_SHARE = CK.ui.IC.share;
  var I_RESET = CK.ui.IC.reset;
  var I_SHUF = CK.ui.IC.shuffle;

  CK.registerTool('hash', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'sha256';

    root.appendChild(ui.head('Cryptographic Hash'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_HASH);
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SWAP, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left column split into two sub-columns: algorithm picker | HMAC. Right column: formats.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'hash-left' });
    var colR = el('div', { class: 'col' });

    // One dropdown per algorithm group; picking from one clears the others
    var groupSelects = {};
    var pickGrid = el('div', { style: 'display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px 14px;' });
    GROUPS.forEach(function (g) {
      var items = ALGOS.filter(function (a) { return a.group === g; });
      var sel = ui.select([{ value: '', label: 'Select...' }].concat(items.map(function (a) { return { value: a.id, label: a.label }; })), function (v) { if (v) select(v); }, '');
      groupSelects[g] = sel;
      pickGrid.appendChild(ui.field(g, sel));
    });
    function syncSelects(id) { var grp = (get(id) || {}).group; GROUPS.forEach(function (g) { groupSelects[g].value = (g === grp ? id : ''); }); }
    var pickWrap = el('div'); pickWrap.appendChild(pickGrid);

    // HMAC sub-column
    var hmacWrap = el('div', { class: 'col' });
    var hmacCb = el('input', { type: 'checkbox' });
    var hmacSwitch = el('label', { class: 'switch' });
    hmacSwitch.appendChild(hmacCb); hmacSwitch.appendChild(el('span', { class: 'track' })); hmacSwitch.appendChild(el('span', {}, 'HMAC Mode'));
    hmacWrap.appendChild(hmacSwitch);
    var keyInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'HMAC key' });
    var keyFmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hexadecimal'], ['base64', 'Base64']], null, 'utf8');
    var keyGen = ui.iconBtn(I_SHUF, 'Random', genKey);
    var keyWrap = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    keyInput.style.flex = '1'; keyInput.style.minWidth = '0'; keyFmt.style.width = 'auto'; keyWrap.appendChild(keyInput); keyWrap.appendChild(keyFmt); keyWrap.appendChild(keyGen);
    var keyField = ui.field('HMAC key', keyWrap); keyField.style.display = 'none';
    hmacWrap.appendChild(keyField);
    hmacCb.addEventListener('change', function () { keyField.style.display = hmacCb.checked ? '' : 'none'; });

    colL.appendChild(pickWrap); colL.appendChild(hmacWrap);

    var inFmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hexadecimal'], ['base64', 'Base64']], null, 'utf8');
    var outFmt = ui.select([['hex', 'Hexadecimal (lower)'], ['HEX', 'Hexadecimal (UPPER)'], ['base64', 'Base64'], ['base64url', 'Base64 URL-safe']], null, 'hex');
    colR.appendChild(ui.field('Input format', inFmt));
    colR.appendChild(ui.field('Output format', outFmt));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    function genKey() { var a = get(current); keyInput.value = randomSecret(a.bytes || 32, keyFmt.value); if (!hmacCb.checked) { hmacCb.checked = true; keyField.style.display = ''; } }

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_FILE, placeholder: 'Text to hash...', primaries: [{ label: 'Hash', cls: 'enc', onClick: doHash }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt' });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_HASH, placeholder: 'Digest appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'digest.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function select(id) { var a = get(id); if (!a) return; current = id; syncSelects(id); ui.setSel(strip, a.label, a.badge, a.label + ' digest, ' + a.bytes + ' bytes'); }
    function inputBytes() { var v = inP.ta.value; return v ? CK.textBytes(v, inFmt.value) : null; }
    function keyBytes() { return CK.textBytes(keyInput.value, keyFmt.value); }
    // returns Promise<hex> for the current algorithm (HMAC-aware)
    function digest(bytes) {
      var a = get(current);
      if (hmacCb.checked && keyInput.value) { if (a.hmac === false) return Promise.reject(new Error(a.label + ' does not support HMAC')); var kb; try { kb = keyBytes(); } catch (e) { return Promise.reject(e); } return hmac(a, kb, bytes).then(toHex); }
      return a.hb(bytes).then(toHex);
    }

    function doHash() {
      var bytes; try { bytes = inputBytes(); } catch (e) { ctx.toast(e.message, 'error'); return; }
      if (!bytes) { ctx.toast('Input is empty', 'warn'); return; }
      return digest(bytes).then(function (hx) { outP.ta.value = fmtHex(hx, outFmt.value); clearVerify(); ctx.toast('Hashed (' + get(current).label + (hmacCb.checked && keyInput.value ? ' HMAC' : '') + ')', 'success'); })
        .catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doVerify() {
      clearVerify();
      var bytes; try { bytes = inputBytes(); } catch (e) { ctx.toast(e.message, 'error'); return; }
      if (!bytes || !outP.ta.value) { ctx.toast('Both panels need content', 'warn'); return; }
      var want = outP.ta.value.trim();
      digest(bytes).then(function (hx) {
        var got = fmtHex(hx, outFmt.value);
        var match = (want.toLowerCase() === got.toLowerCase()) || (want.toLowerCase() === hx.toLowerCase());
        CK.flashVerify(match, inP.ta, outP.ta);
        ctx.toast(match ? 'Match: output is the ' + get(current).label + ' of the input' : 'No match', match ? 'success' : 'error');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doDetect() {
      var s = outP.ta.value.trim();
      if (!s) { ctx.toast('Put a digest in the output first', 'warn'); return; }
      var len = outByteLen(s), id = len ? BY_LEN[len] : null;
      if (id) { select(id); ctx.toast('Guessed ' + get(id).label + ' (' + len + ' bytes, best-effort)', 'success'); }
      else ctx.toast('Could not detect the hash length', 'warn');
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearVerify(); ctx.toast('Output moved to input', 'success'); }
    function doShare() { var st = { a: current, inf: inFmt.value, outf: outFmt.value, hm: hmacCb.checked ? 1 : 0, kf: keyFmt.value, k: keyInput.value, in: inP.ta.value, out: outP.ta.value }; CK.share('hash', st, { k: 'HMAC key' }); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; keyInput.value = ''; hmacCb.checked = false; keyField.style.display = 'none'; inFmt.value = 'utf8'; outFmt.value = 'hex'; keyFmt.value = 'utf8'; clearVerify(); select('sha256'); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); if (st.a) current = st.a; inFmt.value = st.inf || 'utf8'; outFmt.value = st.outf || 'hex'; keyFmt.value = st.kf || 'utf8'; keyInput.value = st.k || ''; hmacCb.checked = !!st.hm; keyField.style.display = hmacCb.checked ? '' : 'none'; inP.ta.value = st.in || ''; outP.ta.value = st.out || ''; } catch (e) { } }
    select(current);
  });
})();
