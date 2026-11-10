/*
   hashlib.js - fast non-cryptographic checksums not found in Web Crypto or noble-hashes.
   Self-authored, offline. Exposes window.HashLib: crc32, crc64, adler32, fnv1/fnv1a (32 and 64 bit),
   oaat (Jenkins), murmur3, xxh32, xxh64 and keyed siphash. Cryptographic hashes come from noble-hashes.
*/
window.HashLib = (function () {
  'use strict';

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
  function rotl32(x, r) { return (x << r) | (x >>> (32 - r)); }
  function u32le(b, i) { return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0; }
  // MurmurHash3 x86 32-bit, seed 0
  function murmur3(b) {
    var h = 0, c1 = 0xcc9e2d51, c2 = 0x1b873593, n = b.length & ~3, k, i;
    for (i = 0; i < n; i += 4) { k = Math.imul(rotl32(Math.imul(u32le(b, i), c1), 15), c2); h = (Math.imul(rotl32(h ^ k, 13), 5) + 0xe6546b64) | 0; }
    k = 0; switch (b.length & 3) { case 3: k ^= b[i + 2] << 16; case 2: k ^= b[i + 1] << 8; case 1: k ^= b[i]; h ^= Math.imul(rotl32(Math.imul(k, c1), 15), c2); } // cases fall through on purpose
    h ^= b.length; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
    return hx(h);
  }
  // xxHash32, seed 0
  var X1 = 0x9E3779B1, X2 = 0x85EBCA77, X3 = 0xC2B2AE3D, X4 = 0x27D4EB2F, X5 = 0x165667B1;
  function xxr(a, v) { return Math.imul(rotl32((a + Math.imul(v, X2)) | 0, 13), X1); }
  function xxh32(b) {
    var len = b.length, i = 0, h;
    if (len >= 16) {
      var v1 = (X1 + X2) | 0, v2 = X2, v3 = 0, v4 = -X1 | 0;
      for (; i + 16 <= len; i += 16) { v1 = xxr(v1, u32le(b, i)); v2 = xxr(v2, u32le(b, i + 4)); v3 = xxr(v3, u32le(b, i + 8)); v4 = xxr(v4, u32le(b, i + 12)); }
      h = (rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)) | 0;
    } else h = X5;
    h = (h + len) | 0;
    for (; i + 4 <= len; i += 4) h = Math.imul(rotl32((h + Math.imul(u32le(b, i), X3)) | 0, 17), X4);
    for (; i < len; i++) h = Math.imul(rotl32((h + Math.imul(b[i], X5)) | 0, 11), X1);
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
    crc32: crc32,
    adler32: adler32, crc64: crc64, fnv1_32: function (b) { return fnv32(b, false); }, fnv1a_32: function (b) { return fnv32(b, true); },
    fnv1_64: function (b) { return fnv64(b, false); }, fnv1a_64: function (b) { return fnv64(b, true); },
    oaat: oaat, murmur3: murmur3, xxh32: xxh32, xxh64: xxh64, siphash: siphash
  };
})();
