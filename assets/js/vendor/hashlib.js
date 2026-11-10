/*
   hashlib.js - pure-JS hash algorithms not provided by Web Crypto.
   Self-authored, offline. Exposes window.HashLib: md5, sha3, keccak, ripemd160, crc32, plus
   fast non-cryptographic checksums (adler32, crc64, fnv1/fnv1a, oaat, murmur3, xxh32, xxh64, siphash).
   Web Crypto and noble-hashes cover the SHA-2 family, SHAKE and BLAKE.
*/
window.HashLib = (function () {
  'use strict';

  function toHex(bytes) { var s = ''; for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0'); return s; }

  /* MD5 (RFC 1321) on a Uint8Array, returns hex */
  var MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  var MD5_K = (function () { var k = []; for (var i = 0; i < 64; i++) k[i] = (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) | 0; return k; })();
  function md5(bytes) {
    function add(a, b) { return (a + b) | 0; }
    function rol(n, c) { return (n << c) | (n >>> (32 - c)); }
    var len = bytes.length, padLen = (((len + 8) >> 6) + 1) << 6;
    var msg = new Uint8Array(padLen); msg.set(bytes); msg[len] = 0x80;
    var bits = len * 8;
    msg[padLen - 8] = bits & 0xff; msg[padLen - 7] = (bits >>> 8) & 0xff; msg[padLen - 6] = (bits >>> 16) & 0xff; msg[padLen - 5] = (bits >>> 24) & 0xff;
    var hi = Math.floor(len / 536870912); msg[padLen - 4] = hi & 0xff; msg[padLen - 3] = (hi >>> 8) & 0xff; msg[padLen - 2] = (hi >>> 16) & 0xff; msg[padLen - 1] = (hi >>> 24) & 0xff;
    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (var off = 0; off < padLen; off += 64) {
      var M = []; for (var j = 0; j < 16; j++) M[j] = msg[off + j * 4] | (msg[off + j * 4 + 1] << 8) | (msg[off + j * 4 + 2] << 16) | (msg[off + j * 4 + 3] << 24);
      var A = a0, B = b0, C = c0, D = d0;
      for (var i = 0; i < 64; i++) {
        var F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7 * i) & 15; }
        F = add(add(add(F, A), MD5_K[i]), M[g]);
        A = D; D = C; C = B; B = add(B, rol(F, MD5_S[i]));
      }
      a0 = add(a0, A); b0 = add(b0, B); c0 = add(c0, C); d0 = add(d0, D);
    }
    function h(n) { var s = ''; for (var i = 0; i < 4; i++) s += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0'); return s; }
    return h(a0) + h(b0) + h(c0) + h(d0);
  }

  /* Keccak-f[1600] sponge (BigInt lanes) - powers SHA-3 and Keccak */
  var MASK = (1n << 64n) - 1n;
  var RC = [0x1n, 0x8082n, 0x800000000000808An, 0x8000000080008000n, 0x808Bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n, 0x8An, 0x88n, 0x80008009n, 0x8000000An, 0x8000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800An, 0x800000008000000An, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
  var ROFF = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
  function rotl(x, n) { n = BigInt(n); return ((x << n) | (x >> (64n - n))) & MASK; }
  function keccakF(A) {
    for (var round = 0; round < 24; round++) {
      var C = [], x, y;
      for (x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
      var D = [];
      for (x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) A[x + 5 * y] = A[x + 5 * y] ^ D[x];
      var B = [];
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], ROFF[x][y]);
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) A[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y] & MASK) & B[((x + 2) % 5) + 5 * y]);
      A[0] = A[0] ^ RC[round];
    }
  }
  function sponge(rateBytes, padByte, outLen, input) {
    var A = []; for (var i = 0; i < 25; i++) A.push(0n);
    var p = 0, len = input.length, j;
    while (p + rateBytes <= len) {
      for (j = 0; j < rateBytes; j++) A[j >> 3] = A[j >> 3] ^ (BigInt(input[p + j]) << BigInt(8 * (j % 8)));
      keccakF(A); p += rateBytes;
    }
    var last = new Uint8Array(rateBytes), rem = len - p;
    for (j = 0; j < rem; j++) last[j] = input[p + j];
    last[rem] ^= padByte; last[rateBytes - 1] ^= 0x80;
    for (j = 0; j < rateBytes; j++) A[j >> 3] = A[j >> 3] ^ (BigInt(last[j]) << BigInt(8 * (j % 8)));
    keccakF(A);
    var out = new Uint8Array(outLen), got = 0;
    while (got < outLen) {
      for (j = 0; j < rateBytes && got < outLen; j++) out[got++] = Number((A[j >> 3] >> BigInt(8 * (j % 8))) & 0xffn);
      if (got < outLen) keccakF(A);
    }
    return out;
  }
  function sha3(bits, bytes) { return toHex(sponge(200 - 2 * (bits / 8), 0x06, bits / 8, bytes)); }
  function keccak(bits, bytes) { return toHex(sponge(200 - 2 * (bits / 8), 0x01, bits / 8, bytes)); }

  /* RIPEMD-160 (on a Uint8Array, returns hex) */
  function ripemd160(bytes) {
    function rol(x, n) { return (x << n) | (x >>> (32 - n)); }
    var zl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
    var zr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
    var sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
    var sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
    var hl = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    var hr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
    function f(j, x, y, z) { return j < 16 ? (x ^ y ^ z) : j < 32 ? ((x & y) | (~x & z)) : j < 48 ? ((x | ~y) ^ z) : j < 64 ? ((x & z) | (y & ~z)) : (x ^ (y | ~z)); }
    var len = bytes.length, padLen = (((len + 8) >> 6) + 1) << 6;
    var m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80;
    var bits = len * 8; m[padLen - 8] = bits & 0xff; m[padLen - 7] = (bits >>> 8) & 0xff; m[padLen - 6] = (bits >>> 16) & 0xff; m[padLen - 5] = (bits >>> 24) & 0xff;
    var hiB = Math.floor(len / 536870912); m[padLen - 4] = hiB & 0xff;
    var h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    for (var off = 0; off < padLen; off += 64) {
      var X = []; for (var i = 0; i < 16; i++) X[i] = m[off + i * 4] | (m[off + i * 4 + 1] << 8) | (m[off + i * 4 + 2] << 16) | (m[off + i * 4 + 3] << 24);
      var al = h0, bl = h1, cl = h2, dl = h3, el2 = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4, t;
      for (var j = 0; j < 80; j++) {
        t = (rol((al + f(j, bl, cl, dl) + X[zl[j]] + hl[(j / 16) | 0]) | 0, sl[j]) + el2) | 0;
        al = el2; el2 = dl; dl = rol(cl, 10); cl = bl; bl = t;
        t = (rol((ar + f(79 - j, br, cr, dr) + X[zr[j]] + hr[(j / 16) | 0]) | 0, sr[j]) + er) | 0;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
      }
      t = (h1 + cl + dr) | 0; h1 = (h2 + dl + er) | 0; h2 = (h3 + el2 + ar) | 0; h3 = (h4 + al + br) | 0; h4 = (h0 + bl + cr) | 0; h0 = t;
    }
    function le(n) { var s = ''; for (var i = 0; i < 4; i++) s += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0'); return s; }
    return le(h0) + le(h1) + le(h2) + le(h3) + le(h4);
  }

  /* CRC32 */
  var CRCT = (function () { var t = []; for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
  function crc32(bytes) { var c = 0xFFFFFFFF; for (var i = 0; i < bytes.length; i++) c = CRCT[(c ^ bytes[i]) & 0xff] ^ (c >>> 8); return ((c ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0'); }

  /* Non-cryptographic checksums and hashes. Each returns the value as big-endian hex,
     the way their reference tools print it. */
  function hx(n, w) { return (n >>> 0).toString(16).padStart(w || 8, '0'); }
  function hx64(n) { return BigInt.asUintN(64, n).toString(16).padStart(16, '0'); }
  var M64 = (1n << 64n) - 1n;

  // Adler-32 (RFC 1950)
  function adler32(b) { var a = 1, s = 0; for (var i = 0; i < b.length; i++) { a = (a + b[i]) % 65521; s = (s + a) % 65521; } return hx(s * 65536 + a); }
  // CRC-64/XZ (ECMA-182 polynomial, reflected, init and final XOR all ones), as two 32-bit halves
  var C64 = (function () {
    var hi = new Uint32Array(256), lo = new Uint32Array(256), PH = 0xC96C5795, PL = 0xD7870F42;
    for (var n = 0; n < 256; n++) { var h = 0, l = n; for (var k = 0; k < 8; k++) { var bit = l & 1; l = (l >>> 1) | ((h & 1) << 31); h = h >>> 1; if (bit) { h ^= PH; l ^= PL; } } hi[n] = h >>> 0; lo[n] = l >>> 0; }
    return { hi: hi, lo: lo };
  })();
  function crc64(b) {
    var h = 0xFFFFFFFF, l = 0xFFFFFFFF;
    for (var i = 0; i < b.length; i++) { var t = (l ^ b[i]) & 0xff; l = ((l >>> 8) | (h << 24)) ^ C64.lo[t]; h = (h >>> 8) ^ C64.hi[t]; }
    return hx(~h) + hx(~l);
  }
  // FNV-1 / FNV-1a, 32 and 64 bit. shortcut: 64-bit uses BigInt per byte, slow above ~50 MB; upgrade to 32-bit limbs if needed
  function fnv32(b, a) { var h = 0x811c9dc5; for (var i = 0; i < b.length; i++) { if (a) h ^= b[i]; h = Math.imul(h, 0x01000193); if (!a) h ^= b[i]; } return hx(h); }
  function fnv64(b, a) { var h = 0xcbf29ce484222325n, p = 0x100000001b3n; for (var i = 0; i < b.length; i++) { if (a) h ^= BigInt(b[i]); h = (h * p) & M64; if (!a) h ^= BigInt(b[i]); } return hx64(h); }
  // Bob Jenkins' one-at-a-time hash
  function oaat(b) { var h = 0; for (var i = 0; i < b.length; i++) { h = (h + b[i]) | 0; h = (h + (h << 10)) | 0; h ^= h >>> 6; } h = (h + (h << 3)) | 0; h ^= h >>> 11; h = (h + (h << 15)) | 0; return hx(h); }
  function rotl(x, r) { return (x << r) | (x >>> (32 - r)); }
  function u32le(b, i) { return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0; }
  // MurmurHash3 x86 32-bit, seed 0
  function murmur3(b) {
    var h = 0, c1 = 0xcc9e2d51, c2 = 0x1b873593, n = b.length & ~3, k, i;
    for (i = 0; i < n; i += 4) { k = Math.imul(rotl(Math.imul(u32le(b, i), c1), 15), c2); h = (Math.imul(rotl(h ^ k, 13), 5) + 0xe6546b64) | 0; }
    k = 0; switch (b.length & 3) { case 3: k ^= b[i + 2] << 16; case 2: k ^= b[i + 1] << 8; case 1: k ^= b[i]; h ^= Math.imul(rotl(Math.imul(k, c1), 15), c2); } // cases fall through on purpose
    h ^= b.length; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
    return hx(h);
  }
  // xxHash32, seed 0
  var X1 = 0x9E3779B1, X2 = 0x85EBCA77, X3 = 0xC2B2AE3D, X4 = 0x27D4EB2F, X5 = 0x165667B1;
  function xxr(a, v) { return Math.imul(rotl((a + Math.imul(v, X2)) | 0, 13), X1); }
  function xxh32(b) {
    var len = b.length, i = 0, h;
    if (len >= 16) {
      var v1 = (X1 + X2) | 0, v2 = X2, v3 = 0, v4 = -X1 | 0;
      for (; i + 16 <= len; i += 16) { v1 = xxr(v1, u32le(b, i)); v2 = xxr(v2, u32le(b, i + 4)); v3 = xxr(v3, u32le(b, i + 8)); v4 = xxr(v4, u32le(b, i + 12)); }
      h = (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) | 0;
    } else h = X5;
    h = (h + len) | 0;
    for (; i + 4 <= len; i += 4) h = Math.imul(rotl((h + Math.imul(u32le(b, i), X3)) | 0, 17), X4);
    for (; i < len; i++) h = Math.imul(rotl((h + Math.imul(b[i], X5)) | 0, 11), X1);
    h ^= h >>> 15; h = Math.imul(h, X2); h ^= h >>> 13; h = Math.imul(h, X3); h ^= h >>> 16;
    return hx(h);
  }
  // xxHash64, seed 0. shortcut: BigInt arithmetic, slow above ~50 MB; upgrade to 32-bit limbs if needed
  var P1 = 0x9E3779B185EBCA87n, P2 = 0xC2B2AE3D27D4EB4Fn, P3 = 0x165667B19E3779F9n, P4 = 0x85EBCA77C2B2AE63n, P5 = 0x27D4EB2F165667C5n;
  function rotl64(x, r) { r = BigInt(r); return ((x << r) | (x >> (64n - r))) & M64; }
  function u64le(b, i) { return BigInt(u32le(b, i)) | (BigInt(u32le(b, i + 4)) << 32n); }
  function xr64(a, v) { return (rotl64((a + v * P2) & M64, 31) * P1) & M64; }
  function xm64(h, v) { return ((h ^ xr64(0n, v)) * P1 + P4) & M64; }
  function xxh64(b) {
    var len = b.length, i = 0, h;
    if (len >= 32) {
      var v1 = (P1 + P2) & M64, v2 = P2, v3 = 0n, v4 = (-P1) & M64;
      for (; i + 32 <= len; i += 32) { v1 = xr64(v1, u64le(b, i)); v2 = xr64(v2, u64le(b, i + 8)); v3 = xr64(v3, u64le(b, i + 16)); v4 = xr64(v4, u64le(b, i + 24)); }
      h = (rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)) & M64;
      h = xm64(h, v1); h = xm64(h, v2); h = xm64(h, v3); h = xm64(h, v4);
    } else h = P5;
    h = (h + BigInt(len)) & M64;
    for (; i + 8 <= len; i += 8) h = (rotl64(h ^ xr64(0n, u64le(b, i)), 27) * P1 + P4) & M64;
    if (i + 4 <= len) { h = (rotl64(h ^ ((BigInt(u32le(b, i)) * P1) & M64), 23) * P2 + P3) & M64; i += 4; }
    for (; i < len; i++) h = (rotl64(h ^ ((BigInt(b[i]) * P5) & M64), 11) * P1) & M64;
    h ^= h >> 33n; h = (h * P2) & M64; h ^= h >> 29n; h = (h * P3) & M64; h ^= h >> 32n;
    return hx64(h);
  }
  // SipHash-2-4 with a 16-byte key; the 64-bit result printed as a number (reference byte order reversed)
  function siphash(key, b) {
    if (key.length !== 16) throw new Error('SipHash needs a 16-byte key');
    var k0 = u64le(key, 0), k1 = u64le(key, 8);
    var v0 = k0 ^ 0x736f6d6570736575n, v1 = k1 ^ 0x646f72616e646f6dn, v2 = k0 ^ 0x6c7967656e657261n, v3 = k1 ^ 0x7465646279746573n;
    function round() {
      v0 = (v0 + v1) & M64; v1 = rotl64(v1, 13) ^ v0; v0 = rotl64(v0, 32);
      v2 = (v2 + v3) & M64; v3 = rotl64(v3, 16) ^ v2;
      v0 = (v0 + v3) & M64; v3 = rotl64(v3, 21) ^ v0;
      v2 = (v2 + v1) & M64; v1 = rotl64(v1, 17) ^ v2; v2 = rotl64(v2, 32);
    }
    var n = b.length & ~7, m, i;
    for (i = 0; i < n; i += 8) { m = u64le(b, i); v3 ^= m; round(); round(); v0 ^= m; }
    m = BigInt(b.length & 255) << 56n;
    for (var j = 0; i + j < b.length; j++) m |= BigInt(b[i + j]) << BigInt(8 * j);
    v3 ^= m; round(); round(); v0 ^= m;
    v2 ^= 0xffn; round(); round(); round(); round();
    return hx64(v0 ^ v1 ^ v2 ^ v3);
  }

  return {
    md5: md5, sha3: sha3, keccak: keccak, crc32: crc32, ripemd160: ripemd160, toHex: toHex,
    adler32: adler32, crc64: crc64, fnv1_32: function (b) { return fnv32(b, false); }, fnv1a_32: function (b) { return fnv32(b, true); },
    fnv1_64: function (b) { return fnv64(b, false); }, fnv1a_64: function (b) { return fnv64(b, true); },
    oaat: oaat, murmur3: murmur3, xxh32: xxh32, xxh64: xxh64, siphash: siphash
  };
})();
