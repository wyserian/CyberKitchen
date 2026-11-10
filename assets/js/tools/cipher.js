/*
   cipher.js - Symmetric Ciphers
   One tool for every symmetric cipher. AES: GCM, GCM-SIV, SIV, CCM, EAX, OCB3 (authenticated),
   CBC / ECB with five paddings, CFB, OFB, CTR, XTS and key wrap. Also ChaCha20(-Poly1305), XChaCha20,
   Salsa20, XSalsa20(-Poly1305), Rabbit, RC4, 3DES and DES. Ciphers come from noble-ciphers and
   crypto-js; CCM, EAX, OCB3 and XTS are built here on noble's AES block cipher and checked against
   published vectors. Authenticated output is ciphertext followed by the 16-byte tag.
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

  /* ---- crypto-js bridges (AES classic modes, DES, 3DES, RC4, Rabbit) ---- */
  var PADS = { Pkcs7: C.pad.Pkcs7, ZeroPadding: C.pad.ZeroPadding, Iso10126: C.pad.Iso10126, AnsiX923: C.pad.Ansix923, NoPadding: C.pad.NoPadding };
  var PAD_LABEL = { Pkcs7: 'PKCS#7', ZeroPadding: 'zero padding', Iso10126: 'ISO 10126', AnsiX923: 'ANSI X9.23', NoPadding: 'no padding' };
  function wa(b) { return C.enc.Hex.parse(toHex(b)); }
  function unwa(w) { if (w.sigBytes < 0) throw new Error('Decryption failed: wrong key, initialization vector or padding'); return hexToBytes(w.toString(C.enc.Hex)); }
  // mode: a crypto-js block mode, or none for the stream ciphers. CBC / ECB use the Padding field;
  // CFB / OFB / CTR are stream modes and are never padded.
  function cjs(A, mode) {
    var padded = mode === C.mode.CBC || mode === C.mode.ECB;
    function o(n, pad) { var x = {}; if (mode) { x.mode = mode; x.padding = padded ? PADS[pad] || C.pad.Pkcs7 : C.pad.NoPadding; } if (n.length) x.iv = wa(n); return x; }
    function whole(d, pad) { var bs = A.blockSize * 4; if (padded && pad === 'NoPadding' && d.length % bs) throw new Error('Without padding the data must be a multiple of ' + bs + ' bytes (got ' + d.length + ')'); }
    return {
      enc: function (k, n, d, a, pad) { whole(d, pad); return unwa(A.encrypt(wa(d), wa(k), o(n, pad)).ciphertext); },
      dec: function (k, n, d, a, pad) { return unwa(A.decrypt(C.lib.CipherParams.create({ ciphertext: wa(d) }), wa(k), o(n, pad))); }
    };
  }
  function nobleAead(f) { return { enc: function (k, n, d, a) { return f(k, n, a).encrypt(d); }, dec: function (k, n, d, a) { try { return f(k, n, a).decrypt(d); } catch (e) { authFail(); } } }; }
  function stream(f) { return { enc: function (k, n, d) { return f(k, n, d); }, dec: function (k, n, d) { return f(k, n, d); } }; }
  function siv() { function ad(a, n) { return [a, n].filter(function (x) { return x.length; }); } return { enc: function (k, n, d, a) { return Noble.aessiv.apply(null, [k].concat(ad(a, n))).encrypt(d); }, dec: function (k, n, d, a) { try { return Noble.aessiv.apply(null, [k].concat(ad(a, n))).decrypt(d); } catch (e) { authFail(); } } }; }
  function kw(f) { return { enc: function (k, n, d) { return f(k).encrypt(d); }, dec: function (k, n, d) { try { return f(k).decrypt(d); } catch (e) { throw new Error('Key unwrap failed: wrong key or damaged data'); } } }; }

  // keys: allowed key sizes (bytes; [] = any 1-256); nonce: [min, max, default] in bytes; only: the exact sizes allowed;
  // aad: takes associated data; padded: uses the Padding field
  var A16 = [16, 24, 32];
  var ALGOS = [
    { id: 'aes-gcm', label: 'AES-GCM', group: 'AEAD', badge: 'SP 800-38D', keys: A16, nonce: [12, 12, 12], aad: true, f: nobleAead(function (k, n, a) { return Noble.gcm(k, n, a); }) },
    { id: 'aes-gcm-siv', label: 'AES-GCM-SIV', group: 'AEAD', badge: 'RFC 8452', keys: [16, 32], nonce: [12, 12, 12], aad: true, f: nobleAead(function (k, n, a) { return Noble.gcmsiv(k, n, a); }) },
    { id: 'aes-siv', label: 'AES-SIV', group: 'AEAD', badge: 'RFC 5297', keys: [32, 48, 64], nonce: [0, 64, 16], aad: true, f: siv() },
    { id: 'aes-ccm', label: 'AES-CCM', group: 'AEAD', badge: 'RFC 3610', keys: A16, nonce: [7, 13, 13], aad: true, f: { enc: function (k, n, d, a) { return ccmEnc(k, n, d, a); }, dec: function (k, n, d, a) { return ccmDec(k, n, d, a); } } },
    { id: 'aes-eax', label: 'AES-EAX', group: 'AEAD', badge: 'EAX', keys: A16, nonce: [1, 64, 16], aad: true, f: { enc: eaxEnc, dec: eaxDec } },
    { id: 'aes-ocb', label: 'AES-OCB3', group: 'AEAD', badge: 'RFC 7253', keys: A16, nonce: [1, 15, 12], aad: true, f: { enc: function (k, n, d, a) { return ocb(k, n, d, a, false); }, dec: function (k, n, d, a) { return ocb(k, n, d, a, true); } } },
    { id: 'chacha20poly1305', label: 'ChaCha20-Poly1305', group: 'AEAD', badge: 'RFC 8439', keys: [32], nonce: [12, 12, 12], aad: true, f: nobleAead(function (k, n, a) { return Noble.chacha20poly1305(k, n, a); }) },
    { id: 'xchacha20poly1305', label: 'XChaCha20-Poly1305', group: 'AEAD', badge: 'XChaCha', keys: [32], nonce: [24, 24, 24], aad: true, f: nobleAead(function (k, n, a) { return Noble.xchacha20poly1305(k, n, a); }) },
    { id: 'xsalsa20poly1305', label: 'XSalsa20-Poly1305 (secretbox)', group: 'AEAD', badge: 'NaCl', keys: [32], nonce: [24, 24, 24], f: nobleAead(function (k, n) { return Noble.xsalsa20poly1305(k, n); }) },
    { id: 'aes-cbc', label: 'AES-CBC (Cipher Block Chaining)', group: 'AES', badge: 'SP 800-38A', keys: A16, nonce: [16, 16, 16], padded: true, f: cjs(C.AES, C.mode.CBC) },
    { id: 'aes-ecb', label: 'AES-ECB (Electronic Codebook)', group: 'AES', badge: 'SP 800-38A', keys: A16, nonce: [0, 0, 0], padded: true, f: cjs(C.AES, C.mode.ECB) },
    { id: 'aes-cfb', label: 'AES-CFB (Cipher Feedback)', group: 'AES', badge: 'SP 800-38A', keys: A16, nonce: [16, 16, 16], f: cjs(C.AES, C.mode.CFB) },
    { id: 'aes-ofb', label: 'AES-OFB (Output Feedback)', group: 'AES', badge: 'SP 800-38A', keys: A16, nonce: [16, 16, 16], f: cjs(C.AES, C.mode.OFB) },
    { id: 'aes-ctr', label: 'AES-CTR (Counter)', group: 'AES', badge: 'SP 800-38A', keys: A16, nonce: [16, 16, 16], f: cjs(C.AES, C.mode.CTR) },
    { id: 'aes-xts', label: 'AES-XTS (disk sectors)', group: 'AES', badge: 'IEEE 1619', keys: [32, 64], nonce: [16, 16, 16], nonceName: 'tweak', f: { enc: function (k, n, d) { return xts(k, n, d, false); }, dec: function (k, n, d) { return xts(k, n, d, true); } } },
    { id: 'aes-kw', label: 'AES Key Wrap', group: 'AES', badge: 'RFC 3394', keys: A16, nonce: [0, 0, 0], f: kw(function (k) { return Noble.aeskw(k); }) },
    { id: 'aes-kwp', label: 'AES Key Wrap with Padding', group: 'AES', badge: 'RFC 5649', keys: A16, nonce: [0, 0, 0], f: kw(function (k) { return Noble.aeskwp(k); }) },
    { id: 'chacha20', label: 'ChaCha20', group: 'Stream', badge: 'RFC 8439', keys: [32], nonce: [12, 12, 12], f: stream(function (k, n, d) { return Noble.chacha20(k, n, d); }) },
    { id: 'xchacha20', label: 'XChaCha20', group: 'Stream', badge: 'XChaCha', keys: [32], nonce: [24, 24, 24], f: stream(function (k, n, d) { return Noble.xchacha20(k, n, d); }) },
    { id: 'salsa20', label: 'Salsa20', group: 'Stream', badge: 'eSTREAM', keys: [32], nonce: [8, 8, 8], f: stream(function (k, n, d) { return Noble.salsa20(k, n, d); }) },
    { id: 'xsalsa20', label: 'XSalsa20', group: 'Stream', badge: 'NaCl', keys: [32], nonce: [24, 24, 24], f: stream(function (k, n, d) { return Noble.xsalsa20(k, n, d); }) },
    { id: 'rabbit', label: 'Rabbit', group: 'Stream', badge: 'RFC 4503', keys: [16], nonce: [0, 8, 8], only: [0, 8], f: cjs(C.Rabbit) },
    { id: 'rc4', label: 'RC4 (broken)', group: 'Stream', badge: 'Legacy', keys: [], nonce: [0, 0, 0], f: cjs(C.RC4) },
    { id: '3des', label: 'Triple DES (3DES, CBC)', group: 'Legacy', badge: 'SP 800-67', keys: [16, 24], nonce: [8, 8, 8], padded: true, f: cjs(C.TripleDES, C.mode.CBC) },
    { id: 'des', label: 'DES (CBC, broken)', group: 'Legacy', badge: 'FIPS 46', keys: [8], nonce: [8, 8, 8], padded: true, f: cjs(C.DES, C.mode.CBC) }
  ];
  function get(id) { for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) return ALGOS[i]; return null; }
  var GROUP_NAME = { AEAD: 'Authenticated', AES: 'AES', Stream: 'Stream', Legacy: 'Legacy' };

  var I_OUT = '<path d="M6 10V7a6 6 0 0 1 12 0v3M5 10h14v10H5z"/>';

  CK.registerTool('cipher', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'aes-gcm';

    root.appendChild(ui.head('Symmetric Ciphers'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(CK.ui.IC.key);
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.detect, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.swap, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Main grid: left column is a 2x2 sub-grid (Algorithm / Key over Padding or Associated Data /
    // Initialization Vector); right column is the formats
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2 mp-kv' });
    var colR = el('div', { class: 'col' });

    // Byte field: text + format + Random, as in the other crypto tools
    function byteField(label, place, fmt0, onRandom) {
      var inp = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: place });
      var fmt = ui.select([['utf8', 'UTF-8'], ['hex', 'Hexadecimal'], ['base64', 'Base64']], function () { updateSel(); }, fmt0);
      var row = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
      inp.style.flex = '1'; inp.style.minWidth = '0'; fmt.style.width = 'auto';
      row.appendChild(inp); row.appendChild(fmt); row.appendChild(ui.iconBtn(CK.ui.IC.shuffle, 'Random', onRandom));
      inp.addEventListener('input', function () { updateSel(); clearVerify(); });
      return { inp: inp, fmt: fmt, field: ui.field(label, row), bytes: function () { return CK.textBytes(inp.value.trim(), fmt.value); } };
    }
    var key = byteField('Key', 'Encryption key', 'hex', function () { var a = get(current); setRandom(key, a.keys.length ? a.keys[a.keys.length - 1] : 16); updateSel(); });
    var nonce = byteField('Initialization Vector', 'Initialization vector', 'hex', function () { setRandom(nonce, get(current).nonce[2]); });
    var algoSel = ui.select(ui.grouped(ALGOS, function (a) { return GROUP_NAME[a.group]; }, function (a) { return [a.id, a.label]; }), function (v) { select(v); }, current);
    var padSel = ui.select([['Pkcs7', 'PKCS#7'], ['ZeroPadding', 'Zero padding'], ['Iso10126', 'ISO 10126'], ['AnsiX923', 'ANSI X9.23'], ['NoPadding', 'No padding']], function () { updateSel(); }, 'Pkcs7');
    var padF = ui.field('Padding', padSel);
    var aadInp = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Optional, UTF-8: authenticated but not encrypted' });
    aadInp.addEventListener('input', clearVerify);
    var aadF = ui.field('Associated Data', aadInp);
    var ptFmt = ui.select([['utf8', 'UTF-8'], ['base64', 'Base64'], ['hex', 'Hexadecimal']], null, 'utf8');
    var ctFmt = ui.select([['base64', 'Base64'], ['hex', 'Hexadecimal']], null, 'base64');
    // Left sub-grid, row-flow order: Algorithm, Key (row 1), Padding or Associated Data, Initialization Vector (row 2).
    // No algorithm uses both: padding is for the classic block modes, associated data for authenticated ones.
    var optSlot = el('div', { class: 'col' }); optSlot.appendChild(padF); optSlot.appendChild(aadF);
    colL.appendChild(ui.field('Algorithm', algoSel)); colL.appendChild(key.field);
    colL.appendChild(optSlot); colL.appendChild(nonce.field);
    // Right column: Input format (plaintext), Output format (ciphertext)
    colR.appendChild(ui.field('Input format', ptFmt));
    colR.appendChild(ui.field('Output format', ctFmt));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: CK.ui.IC.key, placeholder: 'Plaintext to encrypt, or ciphertext to decrypt...', primaries: [{ label: 'Encrypt', cls: 'enc', onClick: doEncrypt }, { label: 'Decrypt', cls: 'dec', onClick: doDecrypt }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.txt' });
    var outP = ui.textPanel({ title: 'OUTPUT', icon: I_OUT, placeholder: 'Result appears here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'output.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function setRandom(f, n) { if (f.fmt.value === 'utf8') f.fmt.value = 'hex'; f.inp.value = f.fmt.value === 'hex' ? toHex(CK.rndBytes(n)) : b64(CK.rndBytes(n)); }
    function sizes(a) { return a.keys.length ? a.keys.join(' / ') + '-byte key' : 'key of any length'; }
    function nonceName(a) { return a.nonceName || (a.group === 'AEAD' || a.id.indexOf('chacha') >= 0 || a.id.indexOf('salsa') >= 0 ? 'nonce' : 'initialization vector'); }
    function nonceSize(a) { var n = a.nonce; return n[0] === n[1] ? n[1] + '-byte' : a.only ? 'optional ' + n[1] + '-byte' : n[0] + ' to ' + n[1] + ' byte'; }
    function select(id) {
      var a = get(id); if (!a) return; current = id; algoSel.value = id;
      // Hidden, not removed, so the initialization vector keeps its grid cell; padding and associated data share one
      nonce.field.style.visibility = a.nonce[1] ? '' : 'hidden';
      padF.style.display = a.padded ? '' : 'none';
      aadF.style.display = a.aad ? '' : 'none';
      nonce.inp.placeholder = (a.nonce[0] ? '' : 'Optional ') + nonceSize(a).replace('optional ', '') + ' ' + nonceName(a);
      key.inp.placeholder = sizes(a);
      updateSel();
    }
    function updateSel() {
      var a = get(current), kb; try { kb = key.bytes().length; } catch (e) { kb = -1; }
      var ok = kb > 0 && (a.keys.length ? a.keys.indexOf(kb) >= 0 : kb <= 256);
      var note = a.group === 'AEAD' ? 'authenticated, 16-byte tag' : a.group === 'Legacy' || a.badge === 'Legacy' ? 'insecure, old data only' : /kw/.test(a.id) ? 'wraps keys' : a.id === 'aes-xts' ? 'for disk sectors, no integrity check' : a.id === 'aes-ecb' ? 'insecure: equal blocks give equal ciphertext' : 'no integrity check';
      var desc = sizes(a) + (a.nonce[1] ? ' · ' + nonceSize(a) + ' ' + nonceName(a) : '') + (a.padded ? ' · ' + PAD_LABEL[padSel.value] : '') + ' · ' + note;
      ui.setSel(strip, a.label, kb > 0 ? kb + ' bytes' + (ok ? '' : ' (invalid)') : a.badge, desc);
    }
    function params(a) {
      var k = key.bytes(), n = a.nonce[1] ? nonce.bytes() : new Uint8Array(0);
      if (!k.length) throw new Error('Key required');
      if (a.keys.length ? a.keys.indexOf(k.length) < 0 : k.length > 256) throw new Error(a.label + ' needs a ' + sizes(a) + ' (got ' + k.length + ' bytes)');
      if (a.only && a.only.indexOf(n.length) < 0) throw new Error(a.label + ' takes no initialization vector or an 8-byte one (got ' + n.length + ' bytes)');
      if (n.length < a.nonce[0] || n.length > a.nonce[1]) throw new Error(a.label + ' needs a ' + nonceSize(a) + ' ' + nonceName(a) + ' (got ' + n.length + ')');
      return { k: k, n: n, ad: ENC.encode(aadInp.value) };
    }
    function show(b, fmt) {
      if (fmt === 'hex') return toHex(b);
      if (fmt === 'base64') return b64(b);
      try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch (e) { throw new Error('The result is not valid UTF-8 text: set Input format to Hexadecimal or Base64'); }
    }
    // dir 'enc': plaintext (Input format) -> ciphertext (Output format); 'dec': the reverse
    function run(dir, src) {
      var a = get(current), p = params(a);
      return dir === 'enc' ? show(a.f.enc(p.k, p.n, CK.textBytes(src, ptFmt.value), p.ad, padSel.value), ctFmt.value)
        : show(a.f.dec(p.k, p.n, CK.textBytes(src.trim(), ctFmt.value), p.ad, padSel.value), ptFmt.value);
    }
    function doEncrypt() {
      try {
        var a = get(current), made = '';
        if (!inP.ta.value) throw new Error('Plaintext is empty');
        if (a.nonce[0] && !nonce.inp.value.trim()) { setRandom(nonce, a.nonce[2]); made = ' with a new random ' + nonceName(a) + ' (keep it for decryption)'; }
        outP.ta.value = run('enc', inP.ta.value); clearVerify();
        ctx.toast('Encrypted (' + a.label + ')' + made, 'success');
      } catch (e) { ctx.toast(e.message, 'error'); }
    }
    function doDecrypt() {
      try {
        if (!inP.ta.value.trim()) throw new Error('Input is empty');
        outP.ta.value = run('dec', inP.ta.value); clearVerify();
        ctx.toast('Decrypted (' + get(current).label + ')', 'success');
      } catch (e) { ctx.toast(e.message, 'error'); }
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearVerify(); ctx.toast('Output moved to input', 'success'); }
    function doVerify() {
      clearVerify();
      var a = inP.ta.value, b = outP.ta.value;
      if (!a || !b) { ctx.toast('Both panels need content', 'warn'); return; }
      try { params(get(current)); } catch (e) { ctx.toast(e.message, 'error'); return; }
      function attempt(dir, src) { try { return run(dir, src); } catch (e) { return null; } }
      var match = attempt('enc', a) === b.trim() || attempt('dec', a) === b || attempt('enc', b) === a.trim() || attempt('dec', b) === a;
      CK.flashVerify(match, inP.ta, outP.ta);
      ctx.toast(match ? 'Match: input and output are a valid ' + get(current).label + ' pair' : 'No match', match ? 'success' : 'error');
    }
    // Input format from the text, and the key / initialization vector formats from theirs
    function doDetect() {
      var s = inP.ta.value.trim();
      if (!s) { ctx.toast('Enter data in the input first', 'warn'); return; }
      var fmt = CK.detectFmt(s); ptFmt.value = fmt;
      [key, nonce].forEach(function (f) { if (f.inp.value.trim()) f.fmt.value = CK.detectFmt(f.inp.value); });
      updateSel();
      ctx.toast(get(current).label + ' · detected ' + CK.fmtLabel(fmt) + ' input (' + CK.fmtByteLen(s, fmt) + ' bytes)', 'success');
    }
    function doShare() {
      CK.share('cipher', { a: current, kf: key.fmt.value, k: key.inp.value, nf: nonce.fmt.value, n: nonce.inp.value, p: padSel.value, ad: aadInp.value, pf: ptFmt.value, cf: ctFmt.value, in: inP.ta.value }, { k: 'key', in: 'input text' });
    }
    function doReset() {
      inP.ta.value = ''; outP.ta.value = ''; key.inp.value = ''; nonce.inp.value = ''; aadInp.value = '';
      key.fmt.value = 'hex'; nonce.fmt.value = 'hex'; padSel.value = 'Pkcs7'; ptFmt.value = 'utf8'; ctFmt.value = 'base64';
      clearVerify(); select('aes-gcm'); ctx.toast('Reset complete', 'success');
    }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) {
      try {
        var st = JSON.parse(b64uDec(m[1]));
        if (get(st.a)) current = st.a;
        key.fmt.value = st.kf || 'hex'; key.inp.value = st.k || ''; nonce.fmt.value = st.nf || 'hex'; nonce.inp.value = st.n || '';
        padSel.value = st.p || 'Pkcs7'; aadInp.value = st.ad || ''; ptFmt.value = st.pf || 'utf8'; ctFmt.value = st.cf || 'base64'; inP.ta.value = st.in || '';
      } catch (e) { }
    }
    select(current);
  });
})();
