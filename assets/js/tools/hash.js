/*
   hash.js - Hash
   Select one algorithm: MD5, SHA-1, RIPEMD-160, SHA-2 (incl. SHA-512/t), SHA-3, SHAKE,
   Keccak, BLAKE / BLAKE2 / BLAKE3 (noble-hashes) or a fast checksum (CRC, Adler, FNV,
   Murmur3, xxHash, Jenkins, keyed SipHash). Optional HMAC, input UTF-8/Hex/Base64, output hex/HEX/Base64/Base64URL.
   Input-driven panels with Hash, plus Verify / Detect / Swap / Share / Reset.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec, toHex = CK.toHex, hexToBytes = CK.hexToBytes, unb64 = CK.unb64, b64 = CK.b64, randomSecret = CK.randomSecret;
  var concat = CK.cat;
  function webBytes(algo, b) { return crypto.subtle.digest(algo, b).then(function (h) { return new Uint8Array(h); }); }
  function P(hex) { return Promise.resolve(hexToBytes(hex)); }

  function N(name, opts) { return function (b) { return Promise.resolve(Noble[name](b, opts)); }; }
  function L(name) { return function (b) { return P(HashLib[name](b)); }; }

  // hb: bytes -> Promise<Uint8Array>; block = HMAC block size; bytes = digest length.
  // hmac: false = not a keyed-hash candidate; keyed = needs its own key (SipHash).
  // Shared with File Checksum (CK.hashAlgos), so both tools offer the same list.
  var ALGOS = [
    { id: 'md5', label: 'MD5', group: 'Legacy', badge: 'RFC 1321', bytes: 16, block: 64, hb: N('md5') },
    { id: 'sha1', label: 'SHA-1', group: 'Legacy', badge: 'FIPS 180', bytes: 20, block: 64, hb: function (b) { return webBytes('SHA-1', b); } },
    { id: 'ripemd160', label: 'RIPEMD-160', group: 'Legacy', badge: 'RIPEMD', bytes: 20, block: 64, hb: N('ripemd160') },
    { id: 'sha224', label: 'SHA-224', group: 'SHA-2', badge: 'FIPS 180', bytes: 28, block: 64, hb: N('sha224') },
    { id: 'sha256', label: 'SHA-256', group: 'SHA-2', badge: 'FIPS 180', bytes: 32, block: 64, hb: function (b) { return webBytes('SHA-256', b); } },
    { id: 'sha384', label: 'SHA-384', group: 'SHA-2', badge: 'FIPS 180', bytes: 48, block: 128, hb: function (b) { return webBytes('SHA-384', b); } },
    { id: 'sha512', label: 'SHA-512', group: 'SHA-2', badge: 'FIPS 180', bytes: 64, block: 128, hb: function (b) { return webBytes('SHA-512', b); } },
    { id: 'sha512-224', label: 'SHA-512/224', group: 'SHA-2', badge: 'FIPS 180', bytes: 28, block: 128, hb: N('sha512_224') },
    { id: 'sha512-256', label: 'SHA-512/256', group: 'SHA-2', badge: 'FIPS 180', bytes: 32, block: 128, hb: N('sha512_256') },
    { id: 'sha3-224', label: 'SHA3-224', group: 'SHA-3', badge: 'FIPS 202', bytes: 28, block: 144, hb: N('sha3_224') },
    { id: 'sha3-256', label: 'SHA3-256', group: 'SHA-3', badge: 'FIPS 202', bytes: 32, block: 136, hb: N('sha3_256') },
    { id: 'sha3-384', label: 'SHA3-384', group: 'SHA-3', badge: 'FIPS 202', bytes: 48, block: 104, hb: N('sha3_384') },
    { id: 'sha3-512', label: 'SHA3-512', group: 'SHA-3', badge: 'FIPS 202', bytes: 64, block: 72, hb: N('sha3_512') },
    { id: 'shake128', label: 'SHAKE128 (256-bit)', group: 'SHA-3', badge: 'FIPS 202', bytes: 32, hmac: false, hb: N('shake128', { dkLen: 32 }) },
    { id: 'shake256', label: 'SHAKE256 (512-bit)', group: 'SHA-3', badge: 'FIPS 202', bytes: 64, hmac: false, hb: N('shake256', { dkLen: 64 }) },
    { id: 'keccak-224', label: 'Keccak-224', group: 'SHA-3', badge: 'Keccak', bytes: 28, block: 144, hb: N('keccak_224') },
    { id: 'keccak-256', label: 'Keccak-256', group: 'SHA-3', badge: 'Keccak', bytes: 32, block: 136, hb: N('keccak_256') },
    { id: 'keccak-384', label: 'Keccak-384', group: 'SHA-3', badge: 'Keccak', bytes: 48, block: 104, hb: N('keccak_384') },
    { id: 'keccak-512', label: 'Keccak-512', group: 'SHA-3', badge: 'Keccak', bytes: 64, block: 72, hb: N('keccak_512') },
    { id: 'blake224', label: 'BLAKE-224', group: 'BLAKE', badge: 'SHA-3 finalist', bytes: 28, block: 64, hb: N('blake224') },
    { id: 'blake256', label: 'BLAKE-256', group: 'BLAKE', badge: 'SHA-3 finalist', bytes: 32, block: 64, hb: N('blake256') },
    { id: 'blake384', label: 'BLAKE-384', group: 'BLAKE', badge: 'SHA-3 finalist', bytes: 48, block: 128, hb: N('blake384') },
    { id: 'blake512', label: 'BLAKE-512', group: 'BLAKE', badge: 'SHA-3 finalist', bytes: 64, block: 128, hb: N('blake512') },
    { id: 'blake2s', label: 'BLAKE2s-256', group: 'BLAKE', badge: 'RFC 7693', bytes: 32, block: 64, hb: N('blake2s') },
    { id: 'blake2b', label: 'BLAKE2b-512', group: 'BLAKE', badge: 'RFC 7693', bytes: 64, block: 128, hb: N('blake2b') },
    { id: 'blake3', label: 'BLAKE3', group: 'BLAKE', badge: 'BLAKE3', bytes: 32, block: 64, hb: N('blake3') },
    { id: 'crc32', label: 'CRC32', group: 'Checksum', badge: 'Checksum', bytes: 4, hmac: false, hb: L('crc32') },
    { id: 'crc64', label: 'CRC-64/XZ', group: 'Checksum', badge: 'Checksum', bytes: 8, hmac: false, hb: L('crc64') },
    { id: 'adler32', label: 'Adler-32', group: 'Checksum', badge: 'RFC 1950', bytes: 4, hmac: false, hb: L('adler32') },
    { id: 'fnv1-32', label: 'FNV-1 (32-bit)', group: 'Checksum', badge: 'Non-crypto', bytes: 4, hmac: false, hb: L('fnv1_32') },
    { id: 'fnv1a-32', label: 'FNV-1a (32-bit)', group: 'Checksum', badge: 'Non-crypto', bytes: 4, hmac: false, hb: L('fnv1a_32') },
    { id: 'fnv1-64', label: 'FNV-1 (64-bit)', group: 'Checksum', badge: 'Non-crypto', bytes: 8, hmac: false, hb: L('fnv1_64') },
    { id: 'fnv1a-64', label: 'FNV-1a (64-bit)', group: 'Checksum', badge: 'Non-crypto', bytes: 8, hmac: false, hb: L('fnv1a_64') },
    { id: 'murmur3', label: 'MurmurHash3 (32-bit)', group: 'Checksum', badge: 'Non-crypto', bytes: 4, hmac: false, hb: L('murmur3') },
    { id: 'xxh32', label: 'xxHash32', group: 'Checksum', badge: 'Non-crypto', bytes: 4, hmac: false, hb: L('xxh32') },
    { id: 'xxh64', label: 'xxHash64', group: 'Checksum', badge: 'Non-crypto', bytes: 8, hmac: false, hb: L('xxh64') },
    { id: 'jenkins', label: 'Jenkins one-at-a-time', group: 'Checksum', badge: 'Non-crypto', bytes: 4, hmac: false, hb: L('oaat') },
    { id: 'siphash', label: 'SipHash-2-4 (keyed)', group: 'Checksum', badge: 'Keyed PRF', bytes: 8, hmac: false, keyed: 16, hb: function (b, k) { return P(HashLib.siphash(k, b)); } }
  ];
  function get(id) { for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) return ALGOS[i]; return null; }
  CK.hashAlgos = ALGOS;
  var GROUPS = ['Legacy', 'SHA-2', 'SHA-3', 'BLAKE', 'Checksum'];
  var BY_LEN = { 4: 'crc32', 8: 'crc64', 16: 'md5', 20: 'sha1', 28: 'sha3-224', 32: 'sha256', 48: 'sha384', 64: 'sha512' };

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

  CK.registerTool('hash', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'sha256';

    root.appendChild(ui.head('Hash'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(CK.ui.IC.hash);
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.detect, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.swap, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left column split into two sub-columns: algorithm picker | HMAC. Right column: formats.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'hash-left' });
    var colR = el('div', { class: 'col' });

    // One dropdown per algorithm group; picking from one clears the others
    var groupSelects = {};
    var pickGrid = el('div', { style: 'display:grid; grid-template-columns:repeat(auto-fit,minmax(185px,1fr)); gap:10px 14px;' });
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
    var keyGen = ui.iconBtn(CK.ui.IC.shuffle, 'Random', genKey);
    var keyWrap = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    keyInput.style.flex = '1'; keyInput.style.minWidth = '0'; keyFmt.style.width = 'auto'; keyWrap.appendChild(keyInput); keyWrap.appendChild(keyFmt); keyWrap.appendChild(keyGen);
    var keyField = ui.field('Key', keyWrap); keyField.style.display = 'none';
    hmacWrap.appendChild(keyField);
    hmacCb.addEventListener('change', syncKey);
    // HMAC switch for hashes that support it; SipHash always shows its own key; checksums show neither
    function syncKey() {
      var a = get(current);
      hmacSwitch.style.display = a.hmac === false ? 'none' : '';
      keyField.style.display = a.keyed || (a.hmac !== false && hmacCb.checked) ? '' : 'none';
      keyInput.placeholder = a.keyed ? a.keyed + '-byte key' : 'HMAC key';
    }

    colL.appendChild(pickWrap); colL.appendChild(hmacWrap);

    var inFmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hexadecimal'], ['base64', 'Base64']], null, 'utf8');
    var outFmt = ui.select([['hex', 'Hexadecimal (lower)'], ['HEX', 'Hexadecimal (UPPER)'], ['base64', 'Base64'], ['base64url', 'Base64 URL-safe']], null, 'hex');
    colR.appendChild(ui.field('Input format', inFmt));
    colR.appendChild(ui.field('Output format', outFmt));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    // A UTF-8 key of n printable characters is n bytes, so SipHash's 16 bytes hold in every format
    function genKey() { var a = get(current); keyInput.value = randomSecret(a.keyed || a.bytes || 32, keyFmt.value); if (!a.keyed) hmacCb.checked = true; syncKey(); }

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: CK.ui.IC.file, placeholder: 'Text to hash...', primaries: [{ label: 'Hash', cls: 'enc', onClick: doHash }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt' });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: CK.ui.IC.hash, placeholder: 'Digest appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'digest.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function select(id) {
      var a = get(id); if (!a) return; current = id; syncSelects(id); syncKey();
      ui.setSel(strip, a.label, a.badge, a.label + (a.group === 'Checksum' ? ' checksum, ' + a.bytes + ' bytes. Fast, not for security.' : ' digest, ' + a.bytes + ' bytes'));
    }
    function inputBytes() { var v = inP.ta.value; return v ? CK.textBytes(v, inFmt.value) : null; }
    function keyBytes() { return CK.textBytes(keyInput.value, keyFmt.value); }
    // returns Promise<hex> for the current algorithm (HMAC-aware)
    function digest(bytes) {
      var a = get(current);
      if (a.keyed) { var k; try { k = keyBytes(); } catch (e) { return Promise.reject(e); } return a.hb(bytes, k).then(toHex); }
      if (a.hmac !== false && hmacCb.checked && keyInput.value) { var kb; try { kb = keyBytes(); } catch (e) { return Promise.reject(e); } return hmac(a, kb, bytes).then(toHex); }
      return a.hb(bytes).then(toHex);
    }

    function doHash() {
      var bytes; try { bytes = inputBytes(); } catch (e) { ctx.toast(e.message, 'error'); return; }
      if (!bytes) { ctx.toast('Input is empty', 'warn'); return; }
      return digest(bytes).then(function (hx) { outP.ta.value = fmtHex(hx, outFmt.value); clearVerify(); ctx.toast('Hashed (' + get(current).label + (get(current).hmac !== false && hmacCb.checked && keyInput.value ? ' HMAC' : '') + ')', 'success'); })
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
