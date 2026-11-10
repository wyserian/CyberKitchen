/*
   cipher.js - Symmetric Ciphers
   Authenticated encryption (ChaCha20-Poly1305, XChaCha20-Poly1305, XSalsa20-Poly1305,
   AES-GCM, AES-GCM-SIV, AES-SIV, AES-CCM, AES-EAX, AES-OCB3), stream ciphers (ChaCha20,
   XChaCha20, Salsa20, XSalsa20, RC4, Rabbit), AES-XTS, AES key wrap and DES / 3DES.
   Ciphers come from noble-ciphers and crypto-js. CCM, EAX, OCB3 and XTS are built here on
   noble's AES block cipher (ECB / CBC / CTR / CMAC) and checked against published vectors.
   AEAD output is ciphertext followed by the 16-byte tag.
*/
(function () {
  'use strict';
  var toHex = CK.toHex, hexToBytes = CK.hexToBytes, b64 = CK.b64, b64uDec = CK.b64uDec;
  var ENC = new TextEncoder(), C = window.CryptoJS;

  var cat = CK.cat;
  function xor(a, b) { var o = new Uint8Array(a.length); for (var i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; }
  function eq(a, b) { if (a.length !== b.length) return false; var d = 0; for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
  function pad16(x) { var r = x.length % 16; return r ? cat(x, new Uint8Array(16 - r)) : x; }
  function authFail() { throw new Error('Authentication failed: wrong key, nonce, associated data, or the ciphertext was changed'); }
  // noble's ECB object is single-use, so independent blocks are encrypted together in one call
  function ecbE(k, d) { return Noble.ecb(k, { disablePadding: true }).encrypt(d); }
  function ecbD(k, d) { return Noble.ecb(k, { disablePadding: true }).decrypt(d); }
  function blocks(d) { var out = []; for (var i = 0; i < d.length; i += 16) out.push(d.subarray(i, i + 16)); return out; }
  function split(c, t) { if (c.length < t) throw new Error('Ciphertext is shorter than the ' + t + '-byte tag'); return [c.subarray(0, c.length - t), c.subarray(c.length - t)]; }

  /* ---- AES-CCM (RFC 3610, NIST SP 800-38C) ---- */
  function ccmMac(k, n, aad, pt, M) {
    var q = 15 - n.length, b0 = new Uint8Array(16), i, L;
    b0[0] = (aad.length ? 64 : 0) | (((M - 2) / 2) << 3) | (q - 1); b0.set(n, 1);
    for (i = 0, L = pt.length; i < q; i++, L = Math.floor(L / 256)) b0[15 - i] = L & 255;
    var a = new Uint8Array(0), la = aad.length;
    if (la) a = cat(la < 0xFF00 ? new Uint8Array([la >> 8, la & 255]) : new Uint8Array([0xFF, 0xFE, (la >>> 24) & 255, (la >>> 16) & 255, (la >>> 8) & 255, la & 255]), aad);
    var c = Noble.cbc(k, new Uint8Array(16), { disablePadding: true }).encrypt(cat(b0, pad16(a), pad16(pt)));
    return c.subarray(c.length - 16, c.length - 16 + M);
  }
  // Counter blocks A_0 (masks the tag) then A_1.. (data); a full-width increment equals CCM's q-byte counter at these sizes
  function ccmCtr(k, n, d) { var a0 = new Uint8Array(16); a0[0] = 14 - n.length; a0.set(n, 1); var s = Noble.ctr(k, a0).encrypt(cat(new Uint8Array(16), d)); return [s.subarray(0, 16), s.subarray(16)]; }
  // The message length is stored in 15 - nonce bytes, e.g. at most 65,535 bytes with a 13-byte nonce
  function ccmCheck(n, M, len) {
    if (n.length < 7 || n.length > 13) throw new Error('CCM nonce must be 7 to 13 bytes');
    if (M < 4 || M > 16 || M % 2) throw new Error('CCM tag must be 4 to 16 bytes, even');
    if (len >= Math.pow(2, 8 * (15 - n.length))) throw new Error('Message too long for a ' + n.length + '-byte CCM nonce: use a shorter nonce (e.g. 12 bytes allows 16 MB)');
  }
  function ccmEnc(k, n, pt, aad, M) { M = M || 16; ccmCheck(n, M, pt.length); var r = ccmCtr(k, n, pt); return cat(r[1], xor(ccmMac(k, n, aad, pt, M), r[0].subarray(0, M))); }
  function ccmDec(k, n, c, aad, M) {
    M = M || 16; ccmCheck(n, M, Math.max(0, c.length - M)); var p = split(c, M), r = ccmCtr(k, n, p[0]);
    if (!eq(xor(ccmMac(k, n, aad, r[1], M), r[0].subarray(0, M)), p[1])) authFail();
    return r[1];
  }

  /* ---- AES-EAX (Bellare, Rogaway, Wagner) ---- */
  function omac(k, t, m) { var b = new Uint8Array(16); b[15] = t; return Noble.cmac(cat(b, m), k); }
  function eaxEnc(k, n, pt, aad) { var n2 = omac(k, 0, n), c = Noble.ctr(k, n2).encrypt(pt); return cat(c, xor(xor(n2, omac(k, 2, c)), omac(k, 1, aad))); }
  function eaxDec(k, n, ct, aad) {
    var p = split(ct, 16), n2 = omac(k, 0, n);
    if (!eq(xor(xor(n2, omac(k, 2, p[0])), omac(k, 1, aad)), p[1])) authFail();
    return Noble.ctr(k, n2).decrypt(p[0]);
  }

  /* ---- AES-OCB3 (RFC 7253), 128-bit tag ---- */
  function dbl(s) { var o = new Uint8Array(16), c = s[0] >> 7; for (var i = 0; i < 15; i++) o[i] = ((s[i] << 1) | (s[i + 1] >> 7)) & 255; o[15] = ((s[15] << 1) & 255) ^ (c ? 0x87 : 0); return o; }
  function ntz(i) { var n = 0; while (!(i & 1)) { i >>>= 1; n++; } return n; }
  function ocbKeys(k) { var ls = ecbE(k, new Uint8Array(16)), L = [dbl(dbl(ls))]; return { star: ls, dollar: dbl(ls), L: function (i) { while (L.length <= i) L.push(dbl(L[L.length - 1])); return L[i]; } }; }
  // Offsets for blocks 1..m, starting from off0
  function ocbOffsets(K, off0, m) { var o = [], cur = off0; for (var i = 1; i <= m; i++) { cur = xor(cur, K.L(ntz(i))); o.push(cur); } return o; }
  function ocbHash(k, K, a) {
    var full = Math.floor(a.length / 16), offs = ocbOffsets(K, new Uint8Array(16), full), sum = new Uint8Array(16), i, ins = [];
    for (i = 0; i < full; i++) ins.push(xor(a.subarray(i * 16, i * 16 + 16), offs[i]));
    if (a.length % 16) { var last = new Uint8Array(16), rest = a.subarray(full * 16); last.set(rest); last[rest.length] = 0x80; ins.push(xor(last, xor(full ? offs[full - 1] : new Uint8Array(16), K.star))); }
    if (ins.length) blocks(ecbE(k, cat.apply(null, ins))).forEach(function (b) { sum = xor(sum, b); });
    return sum;
  }
  function ocbStart(k, n) {
    if (n.length < 1 || n.length > 15) throw new Error('OCB nonce must be 1 to 15 bytes');
    var nonce = new Uint8Array(16); nonce[15 - n.length] = 1; nonce.set(n, 16 - n.length);
    var bottom = nonce[15] & 63, top = nonce.slice(); top[15] &= 0xC0;
    var kt = ecbE(k, top), st = new Uint8Array(24), off = new Uint8Array(16), B = bottom >> 3, b = bottom & 7, i;
    st.set(kt); for (i = 0; i < 8; i++) st[16 + i] = kt[i] ^ kt[i + 1];
    for (i = 0; i < 16; i++) off[i] = b ? ((st[i + B] << b) | (st[i + B + 1] >> (8 - b))) & 255 : st[i + B];
    return off;
  }
  function ocb(k, n, data, aad, decrypt) {
    var K = ocbKeys(k), tagIn = decrypt ? split(data, 16) : null; if (decrypt) data = tagIn[0];
    var full = Math.floor(data.length / 16), off0 = ocbStart(k, n), offs = ocbOffsets(K, off0, full), i, ins = [];
    for (i = 0; i < full; i++) ins.push(xor(data.subarray(i * 16, i * 16 + 16), offs[i]));
    var mid = full ? blocks((decrypt ? ecbD : ecbE)(k, cat.apply(null, ins))).map(function (b, j) { return xor(b, offs[j]); }) : [];
    var out = cat.apply(null, mid.concat([new Uint8Array(0)])), plain = decrypt ? out : data.subarray(0, full * 16);
    var sum = new Uint8Array(16), off = full ? offs[full - 1] : off0;
    blocks(plain).forEach(function (b) { sum = xor(sum, b); });
    var rest = data.subarray(full * 16);
    if (rest.length) {
      off = xor(off, K.star);
      var pad = ecbE(k, off), tail = xor(rest, pad.subarray(0, rest.length)), pt = decrypt ? tail : rest, last = new Uint8Array(16);
      last.set(pt); last[pt.length] = 0x80; sum = xor(sum, last); out = cat(out, tail);
    }
    var tag = xor(ecbE(k, xor(xor(sum, off), K.dollar)), ocbHash(k, K, aad));
    if (decrypt) { if (!eq(tag, tagIn[1])) authFail(); return out; }
    return cat(out, tag);
  }

  /* ---- AES-XTS (IEEE 1619), with ciphertext stealing ---- */
  function mulA(t) { var o = new Uint8Array(16), c = 0; for (var i = 0; i < 16; i++) { o[i] = ((t[i] << 1) | c) & 255; c = t[i] >> 7; } if (c) o[0] ^= 0x87; return o; }
  function xts(key, tweak, d, decrypt) {
    if (key.length !== 32 && key.length !== 64) throw new Error('XTS key must be 32 or 64 bytes (two AES keys)');
    if (tweak.length !== 16) throw new Error('XTS tweak must be 16 bytes');
    if (d.length < 16) throw new Error('XTS needs at least 16 bytes of data');
    var h = key.length / 2, k1 = key.subarray(0, h), k2 = key.subarray(h), T = [ecbE(k2, tweak)];
    var m = Math.ceil(d.length / 16), r = d.length % 16, plainFull = r ? m - 2 : m, i;
    for (i = 1; i < m; i++) T.push(mulA(T[i - 1]));
    var f = decrypt ? ecbD : ecbE, ins = [];
    for (i = 0; i < plainFull; i++) ins.push(xor(d.subarray(i * 16, i * 16 + 16), T[i]));
    var out = plainFull ? blocks(f(k1, cat.apply(null, ins))).map(function (b, j) { return xor(b, T[j]); }) : [];
    if (r) {
      // Last full block and the partial block swap tweaks when decrypting
      var a = d.subarray(plainFull * 16, plainFull * 16 + 16), b = d.subarray(plainFull * 16 + 16), t1 = T[decrypt ? m - 1 : m - 2], t2 = T[decrypt ? m - 2 : m - 1];
      var cc = xor(f(k1, xor(a, t1)), t1), pp = cat(b, cc.subarray(r));
      out.push(xor(f(k1, xor(pp, t2)), t2), cc.subarray(0, r));
    }
    return cat.apply(null, out.concat([new Uint8Array(0)]));
  }
  CK.aesModes = { ccmEnc: ccmEnc, ccmDec: ccmDec, eaxEnc: eaxEnc, eaxDec: eaxDec, ocb: ocb, xts: xts };

  /* ---- crypto-js bridges (DES, 3DES, RC4, Rabbit) ---- */
  function wa(b) { return C.enc.Hex.parse(toHex(b)); }
  function unwa(w) { if (w.sigBytes < 0) throw new Error('Decryption failed: wrong key or IV'); return hexToBytes(w.toString(C.enc.Hex)); }
  function cjs(A, cbc) {
    function o(n) { return cbc ? { iv: wa(n), mode: C.mode.CBC, padding: C.pad.Pkcs7 } : n.length ? { iv: wa(n) } : {}; }
    return {
      enc: function (k, n, d) { return unwa(A.encrypt(wa(d), wa(k), o(n)).ciphertext); },
      dec: function (k, n, d) { return unwa(A.decrypt(C.lib.CipherParams.create({ ciphertext: wa(d) }), wa(k), o(n))); }
    };
  }
  function nobleAead(f) { return { enc: function (k, n, d, a) { return f(k, n, a).encrypt(d); }, dec: function (k, n, d, a) { try { return f(k, n, a).decrypt(d); } catch (e) { authFail(); } } }; }
  function stream(f) { return { enc: function (k, n, d) { return f(k, n, d); }, dec: function (k, n, d) { return f(k, n, d); } }; }
  function siv() { function ad(a, n) { return [a, n].filter(function (x) { return x.length; }); } return { enc: function (k, n, d, a) { return Noble.aessiv.apply(null, [k].concat(ad(a, n))).encrypt(d); }, dec: function (k, n, d, a) { try { return Noble.aessiv.apply(null, [k].concat(ad(a, n))).decrypt(d); } catch (e) { authFail(); } } }; }
  function kw(f, name) { return { enc: function (k, n, d) { return f(k).encrypt(d); }, dec: function (k, n, d) { try { return f(k).decrypt(d); } catch (e) { throw new Error(name + ' unwrap failed: wrong key or damaged data'); } } }; }

  // keys: allowed key sizes (bytes; [] = any 1-256); nonce: [min, max, default] in bytes; aad: takes associated data
  var A16 = [16, 24, 32];
  var ALGOS = [
    { id: 'chacha20poly1305', label: 'ChaCha20-Poly1305', group: 'AEAD', badge: 'RFC 8439', keys: [32], nonce: [12, 12, 12], aad: true, f: nobleAead(function (k, n, a) { return Noble.chacha20poly1305(k, n, a); }) },
    { id: 'xchacha20poly1305', label: 'XChaCha20-Poly1305', group: 'AEAD', badge: 'XChaCha', keys: [32], nonce: [24, 24, 24], aad: true, f: nobleAead(function (k, n, a) { return Noble.xchacha20poly1305(k, n, a); }) },
    { id: 'xsalsa20poly1305', label: 'XSalsa20-Poly1305 (secretbox)', group: 'AEAD', badge: 'NaCl', keys: [32], nonce: [24, 24, 24], f: nobleAead(function (k, n) { return Noble.xsalsa20poly1305(k, n); }) },
    { id: 'aes-gcm', label: 'AES-GCM', group: 'AEAD', badge: 'SP 800-38D', keys: A16, nonce: [12, 12, 12], aad: true, f: nobleAead(function (k, n, a) { return Noble.gcm(k, n, a); }) },
    { id: 'aes-gcm-siv', label: 'AES-GCM-SIV', group: 'AEAD', badge: 'RFC 8452', keys: [16, 32], nonce: [12, 12, 12], aad: true, f: nobleAead(function (k, n, a) { return Noble.gcmsiv(k, n, a); }) },
    { id: 'aes-siv', label: 'AES-SIV', group: 'AEAD', badge: 'RFC 5297', keys: [32, 48, 64], nonce: [0, 64, 16], aad: true, f: siv() },
    { id: 'aes-ccm', label: 'AES-CCM', group: 'AEAD', badge: 'RFC 3610', keys: A16, nonce: [7, 13, 13], aad: true, f: { enc: function (k, n, d, a) { return ccmEnc(k, n, d, a); }, dec: function (k, n, d, a) { return ccmDec(k, n, d, a); } } },
    { id: 'aes-eax', label: 'AES-EAX', group: 'AEAD', badge: 'EAX', keys: A16, nonce: [1, 64, 16], aad: true, f: { enc: eaxEnc, dec: eaxDec } },
    { id: 'aes-ocb', label: 'AES-OCB3', group: 'AEAD', badge: 'RFC 7253', keys: A16, nonce: [1, 15, 12], aad: true, f: { enc: function (k, n, d, a) { return ocb(k, n, d, a, false); }, dec: function (k, n, d, a) { return ocb(k, n, d, a, true); } } },
    { id: 'chacha20', label: 'ChaCha20', group: 'Stream', badge: 'RFC 8439', keys: [32], nonce: [12, 12, 12], f: stream(function (k, n, d) { return Noble.chacha20(k, n, d); }) },
    { id: 'xchacha20', label: 'XChaCha20', group: 'Stream', badge: 'XChaCha', keys: [32], nonce: [24, 24, 24], f: stream(function (k, n, d) { return Noble.xchacha20(k, n, d); }) },
    { id: 'salsa20', label: 'Salsa20', group: 'Stream', badge: 'eSTREAM', keys: [32], nonce: [8, 8, 8], f: stream(function (k, n, d) { return Noble.salsa20(k, n, d); }) },
    { id: 'xsalsa20', label: 'XSalsa20', group: 'Stream', badge: 'NaCl', keys: [32], nonce: [24, 24, 24], f: stream(function (k, n, d) { return Noble.xsalsa20(k, n, d); }) },
    { id: 'rabbit', label: 'Rabbit', group: 'Stream', badge: 'RFC 4503', keys: [16], nonce: [0, 8, 8], only: [0, 8], nonceName: 'IV', f: cjs(C.Rabbit) },
    { id: 'rc4', label: 'RC4 (broken)', group: 'Stream', badge: 'Legacy', keys: [], nonce: [0, 0, 0], f: cjs(C.RC4) },
    { id: 'aes-xts', label: 'AES-XTS (disk sectors)', group: 'Block', badge: 'IEEE 1619', keys: [32, 64], nonce: [16, 16, 16], nonceName: 'tweak', f: { enc: function (k, n, d) { return xts(k, n, d, false); }, dec: function (k, n, d) { return xts(k, n, d, true); } } },
    { id: 'aes-kw', label: 'AES Key Wrap', group: 'Block', badge: 'RFC 3394', keys: A16, nonce: [0, 0, 0], f: kw(function (k) { return Noble.aeskw(k); }, 'Key wrap') },
    { id: 'aes-kwp', label: 'AES Key Wrap with Padding', group: 'Block', badge: 'RFC 5649', keys: A16, nonce: [0, 0, 0], f: kw(function (k) { return Noble.aeskwp(k); }, 'Key wrap') },
    { id: '3des', label: 'Triple DES (3DES, CBC)', group: 'Block', badge: 'Legacy', keys: [16, 24], nonce: [8, 8, 8], nonceName: 'IV', f: cjs(C.TripleDES, true) },
    { id: 'des', label: 'DES (CBC, broken)', group: 'Block', badge: 'Legacy', keys: [8], nonce: [8, 8, 8], nonceName: 'IV', f: cjs(C.DES, true) }
  ];
  function get(id) { for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) return ALGOS[i]; return null; }
  var GROUP_NAME = { AEAD: 'Authenticated', Stream: 'Stream', Block: 'Block / wrap' };

  var I_SYM = '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2"/>';
  var I_OUT = '<path d="M6 10V7a6 6 0 0 1 12 0v3M5 10h14v10H5z"/>';

  CK.registerTool('cipher', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'chacha20poly1305';
    root.appendChild(ui.head('Symmetric Ciphers'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SYM);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.swap, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-right' });
    var colA = el('div', { class: 'col' }), colB = el('div', { class: 'col' });
    var algoSel = ui.select(ALGOS.map(function (a) { return [a.id, GROUP_NAME[a.group] + ': ' + a.label]; }), function (v) { select(v); }, current);
    colA.appendChild(ui.field('Algorithm', algoSel));
    var ptFmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hexadecimal'], ['base64', 'Base64']], null, 'utf8');
    var ctFmt = ui.select([['base64', 'Base64'], ['hex', 'Hexadecimal']], null, 'base64');
    colA.appendChild(ui.field('Plaintext format', ptFmt)); colA.appendChild(ui.field('Ciphertext format', ctFmt));

    // Secret-ish byte field: text + format + Random
    function byteField(label, place, onRandom) {
      var inp = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: place });
      var fmt = ui.select([['hex', 'Hexadecimal'], ['base64', 'Base64'], ['utf8', 'UTF-8']], null, 'hex');
      var row = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
      inp.style.flex = '1'; inp.style.minWidth = '0'; fmt.style.width = 'auto';
      row.appendChild(inp); row.appendChild(fmt); row.appendChild(ui.iconBtn(CK.ui.IC.shuffle, 'Random', onRandom));
      var f = ui.field(label, row); colB.appendChild(f);
      return { inp: inp, fmt: fmt, field: f, bytes: function () { return CK.textBytes(inp.value.trim(), fmt.value); } };
    }
    var key = byteField('Key', 'Secret key', function () { var a = get(current); setRandom(key, a.keys.length ? a.keys[a.keys.length - 1] : 16); });
    var nonce = byteField('Nonce / IV', 'Nonce', function () { setRandom(nonce, get(current).nonce[2]); });
    var aadInp = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Optional; authenticated, not encrypted' });
    var aadField = ui.field('Associated data (UTF-8)', aadInp); colB.appendChild(aadField);
    function setRandom(f, n) { if (f.fmt.value === 'utf8') f.fmt.value = 'hex'; f.inp.value = f.fmt.value === 'hex' ? toHex(CK.rndBytes(n)) : b64(CK.rndBytes(n)); }

    grid.appendChild(colA); grid.appendChild(colB);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: CK.ui.IC.file, placeholder: 'Plaintext to encrypt, or ciphertext to decrypt...', primaries: [{ label: 'Encrypt', cls: 'enc', onClick: doEncrypt }, { label: 'Decrypt', cls: 'dec', onClick: doDecrypt }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt' });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_OUT, placeholder: 'Result appears here...', actions: ['copy', 'clear', 'download'], downloadName: 'output.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function sizes(a) { return a.keys.length ? a.keys.join(' / ') + '-byte key' : 'key of any length'; }
    function select(id) {
      var a = get(id); if (!a) return; current = id; algoSel.value = id;
      var nn = a.nonceName || 'nonce', n = a.nonce;
      nonce.field.style.display = n[1] ? '' : 'none';
      nonce.inp.placeholder = (n[0] ? '' : 'Optional ') + (n[0] === n[1] || a.only ? n[1] + '-byte ' : n[0] + ' to ' + n[1] + ' bytes, ') + nn;
      aadField.style.display = a.aad ? '' : 'none';
      key.inp.placeholder = sizes(a);
      var desc = sizes(a) + (n[1] ? ', ' + (n[0] === n[1] ? n[1] + '-byte ' : a.only ? 'optional ' + n[1] + '-byte ' : n[0] + '-' + n[1] + ' byte ') + nn : '') +
        (a.group === 'AEAD' ? '. Output is ciphertext + 16-byte tag; tampering is detected.' : a.badge === 'Legacy' ? '. Not secure: for old data only.' : a.group === 'Stream' ? '. No integrity check: pair with a MAC or use an AEAD.' : '.') +
        (n[0] && a.id !== 'aes-xts' ? ' Never reuse a nonce with the same key.' : '');
      ui.setSel(strip, a.label, a.badge, desc);
    }
    function params(a) {
      var k = key.bytes(), n = a.nonce[1] ? nonce.bytes() : new Uint8Array(0);
      if (!k.length) throw new Error('Key is required');
      if (a.keys.length ? a.keys.indexOf(k.length) < 0 : k.length > 256) throw new Error(a.label + ' needs a ' + sizes(a) + ' (got ' + k.length + ' bytes)');
      if (a.only && a.only.indexOf(n.length) < 0) throw new Error(a.label + ' takes no IV or an 8-byte IV (got ' + n.length + ' bytes)');
      if (n.length < a.nonce[0] || n.length > a.nonce[1]) throw new Error(a.label + ' needs a ' + (a.nonce[0] === a.nonce[1] ? a.nonce[1] + '-byte' : a.nonce[0] + ' to ' + a.nonce[1] + ' byte') + ' ' + (a.nonceName || 'nonce') + ' (got ' + n.length + ')');
      return { k: k, n: n, ad: ENC.encode(aadInp.value) };
    }
    function show(b, fmt) {
      if (fmt === 'hex') return toHex(b);
      if (fmt === 'base64') return b64(b);
      try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch (e) { throw new Error('The result is not valid UTF-8 text: set Plaintext format to Hexadecimal or Base64'); }
    }
    function doEncrypt() {
      try {
        var a = get(current);
        if (!inP.ta.value) throw new Error('Input is empty');
        var made = '';
        if (a.nonce[0] && !nonce.inp.value.trim()) { setRandom(nonce, a.nonce[2]); made = ' with a new random ' + (a.nonceName || 'nonce') + ' (keep it for decryption)'; }
        var p = params(a);
        outP.ta.value = show(a.f.enc(p.k, p.n, CK.textBytes(inP.ta.value, ptFmt.value), p.ad), ctFmt.value);
        ctx.toast('Encrypted (' + a.label + ')' + made, 'success');
      } catch (e) { ctx.toast(e.message, 'error'); }
    }
    function doDecrypt() {
      try {
        var a = get(current);
        if (!inP.ta.value.trim()) throw new Error('Input is empty');
        var p = params(a);
        outP.ta.value = show(a.f.dec(p.k, p.n, CK.textBytes(inP.ta.value.trim(), ctFmt.value), p.ad), ptFmt.value);
        ctx.toast('Decrypted (' + a.label + ')', 'success');
      } catch (e) { ctx.toast(e.message, 'error'); }
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; }
    function doShare() {
      CK.share('cipher', { a: current, kf: key.fmt.value, k: key.inp.value, nf: nonce.fmt.value, n: nonce.inp.value, ad: aadInp.value, pf: ptFmt.value, cf: ctFmt.value, in: inP.ta.value }, { k: 'key', in: 'input text' });
    }
    function doReset() {
      inP.ta.value = ''; outP.ta.value = ''; key.inp.value = ''; nonce.inp.value = ''; aadInp.value = '';
      key.fmt.value = 'hex'; nonce.fmt.value = 'hex'; ptFmt.value = 'utf8'; ctFmt.value = 'base64'; select('chacha20poly1305');
    }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) {
      try {
        var st = JSON.parse(b64uDec(m[1]));
        if (get(st.a)) current = st.a;
        key.fmt.value = st.kf || 'hex'; key.inp.value = st.k || ''; nonce.fmt.value = st.nf || 'hex'; nonce.inp.value = st.n || '';
        aadInp.value = st.ad || ''; ptFmt.value = st.pf || 'utf8'; ctFmt.value = st.cf || 'base64'; inP.ta.value = st.in || '';
      } catch (e) { }
    }
    select(current);
  });
})();
