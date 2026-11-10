/*
   app.js - tool manifest, start-up and offline support.
   Kept out of index.html so the Content Security Policy can forbid inline scripts.
*/
/* Tool manifest. Icons are inner SVG paths (rendered by CK.iconSvg).
   Each tool's logic is registered later via CK.registerTool(id, fn). */
CK.defineTools([
  { id:'cipher',    label:'Symmetric Ciphers',  category:'Symmetric Encryption', tag:'AES', keys:'aes cbc ecb cfb ofb ctr padding pkcs7 gcm siv ccm eax ocb xts key wrap chacha20 xchacha20 salsa20 xsalsa20 poly1305 aead des 3des triple rc4 rabbit',  icon:'<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2"/>' },
  { id:'classical', label:'Classical Ciphers',  category:'Symmetric Encryption', tag:'27',   icon:'<path d="M4 7V5h16v2M9 20h6M12 5v15"/>' },
  { id:'rsa',       label:'RSA',                category:'Asymmetric Encryption', tag:'RSA',  icon:'<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>' },
  { id:'keyx',      label:'Key Exchange',       category:'Asymmetric Encryption', tag:'KEX', keys:'diffie hellman dh dhe ecdh ecdhe x25519 x448 ml-kem kyber x-wing kem post-quantum',  icon:'<circle cx="6" cy="12" r="3"/><circle cx="18" cy="12" r="3"/><path d="M9 12h6M12 5l3 3-3 3M12 13l-3 3 3 3"/>' },
  { id:'signature', label:'Digital Signatures', category:'Asymmetric Encryption', tag:'sig', keys:'ecdsa ed25519 ed448 eddsa rsa-pss pkcs1 secp256k1 ml-dsa dilithium slh-dsa sphincs falcon post-quantum',  icon:'<path d="M3 17c3-3 5-8 7-8s-1 7 1 7 3-4 4-4 1 3 3 3h3M3 21h18"/>' },
  { id:'x509',      label:'X.509 Certificate',  category:'Asymmetric Encryption', tag:'x509', icon:'<rect x="4" y="3" width="16" height="13" rx="2"/><circle cx="12" cy="8" r="2.5"/><path d="M9.5 14l-1 6 3.5-2 3.5 2-1-6"/>' },
  { id:'hash',      label:'Hash',               category:'Hashing',        tag:'SHA3', keys:'checksum md5 sha1 sha224 sha256 sha512 sha3 shake keccak blake blake2 blake3 ripemd crc32 crc64 adler fnv murmur xxhash jenkins siphash', icon:'<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>' },
  { id:'checksum',  label:'File Checksum',      category:'Hashing',        tag:'sum', keys:'crc sha md5 blake xxhash file hash',  icon:'<path d="M14 3v5h5M6 3h9l5 5v13H6z"/><path d="m9 14 2 2 4-4"/>' },
  { id:'passhash',  label:'Password Hashing',   category:'Hashing',        tag:'pw', keys:'bcrypt argon2 argon2id argon2i argon2d password verify',  icon:'<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M8 12h.01M12 12h.01M16 12h.01"/>' },
  { id:'kdf',       label:'Key Derivation',     category:'Hashing',        tag:'KDF', keys:'pbkdf2 scrypt hkdf',  icon:'<path d="M3 5h18l-7 8v6l-4 2v-8z"/>' },
  { id:'hashid',    label:'Hash Identifier',    category:'Hashing',        tag:'ID',   icon:'<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>' },
  { id:'encode',    label:'Encoder / Decoder',  category:'Encoding',       tag:'26',   icon:'<path d="M7 7 3 12l4 5M17 7l4 5-4 5M14 4l-4 16"/>' },
  { id:'number',    label:'Number Converter',   category:'Encoding',       tag:'hex',  icon:'<path d="M6 4v16M6 4h4a3 3 0 0 1 0 6H6M14 4h4v6h-4zM14 14h4v6h-4z"/>' },
  { id:'totp',      label:'TOTP / HOTP',        category:'Authentication', tag:'2FA',  icon:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>' },
  { id:'jwt',       label:'JSON Web Token',     category:'Authentication', tag:'JWT',  icon:'<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/>' },
  { id:'cidr',      label:'CIDR / Subnet',      category:'Networking',     tag:'CIDR', icon:'<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-2h12v2"/>' },
  { id:'ipconv',    label:'IP Converter',       category:'Networking',     tag:'IP',   icon:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>' },
  { id:'json',      label:'JSON Toolkit',       category:'Developer',      tag:'JSON', icon:'<path d="M8 4H6a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h2M16 4h2a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-2"/>' },
  { id:'regex',     label:'Regex Tester',       category:'Developer',      tag:'.*',   icon:'<path d="M17 3v6M14.5 4.5l5 3M14.5 7.5l5-3M5 20a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM7 14V4"/>' },
  { id:'timestamp', label:'Timestamp',          category:'Developer',      tag:'time', icon:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>' },
  { id:'diff',      label:'Text Diff',          category:'Developer',      tag:'diff', icon:'<path d="M9 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h4M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M12 3v18"/>' },
  { id:'color',     label:'Color Converter',    category:'Developer',      tag:'hex',  icon:'<path d="M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z"/>' },
  { id:'markdown',  label:'Markdown Viewer',    category:'Developer',      tag:'MD',   icon:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 15V9l3 3 3-3v6M18 9v4M16 13l2 2 2-2"/>' },
  { id:'html',      label:'HTML Viewer',        category:'Developer',      tag:'HTML', icon:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M9.5 13l-2 2 2 2M14.5 13l2 2-2 2"/>' },
  { id:'text',      label:'Text Cleaner',       category:'Developer',      tag:'txt',  icon:'<path d="M4 6h16M4 12h10M4 18h7"/><path d="m18 14 1 2.5 2.5 1-2.5 1-1 2.5-1-2.5-2.5-1 2.5-1z"/>' },
  { id:'password',  label:'Password Generator', category:'Generators',     tag:'pw',   icon:'<rect x="4" y="4" width="16" height="16" rx="3"/><circle cx="9" cy="9" r="1.2"/><circle cx="15" cy="15" r="1.2"/><circle cx="15" cy="9" r="1.2"/><circle cx="9" cy="15" r="1.2"/>' },
  { id:'fakedata',  label:'Fake Data',          category:'Generators',     tag:'fkr',  icon:'<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>' },
  { id:'qr',        label:'QR Code',            category:'Generators',     tag:'QR',   icon:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3M20 14v.01M14 20v.01M20 20v.01M17 17v.01"/>' }
], ['Symmetric Encryption','Asymmetric Encryption','Hashing','Encoding','Authentication','Networking','Developer','Generators']);

CK.boot();

if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    // A new service worker takes over straight away (skipWaiting), but this page is still running
    // the files it loaded: offer a reload. No prompt on the very first install.
    var hadController = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.addEventListener('controllerchange', function () {
      if (hadController) CK.toast('A new version of CyberKitchen is ready', 'success', { label: 'Reload', ms: 20000, fn: function () { location.reload(); } });
    });
    navigator.serviceWorker.register('sw.js').catch(function () {});
  });
}
