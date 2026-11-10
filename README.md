# CyberKitchen

> Recipes for hackers.

**[Live site](https://wyserian.github.io/CyberKitchen/)**

CyberKitchen is a fast, 100% client-side security and developer toolkit that runs entirely in your browser. It bundles symmetric and post-quantum encryption, key exchange, digital signatures, hashing, file checksums, key derivation, encoding, number conversion, authentication tokens, networking calculators, developer utilities and data generators into one installable, offline-first app. No servers, no tracking, and no data ever leaves your machine, so every tool works with no network after the first load.

It is built with vanilla JavaScript and no build step. Cryptography uses the Web Crypto API where possible, with vendored libraries for the rest: the audited [noble](https://paulmillr.com/noble/) hashes, ciphers, curves and post-quantum libraries (MD5, RIPEMD-160, SHA-2/3, SHAKE, scrypt, BLAKE2/3, ChaCha20, AES-GCM/SIV, Ed448, X25519/X448, ML-KEM, ML-DSA, SLH-DSA, Falcon), crypto-js, bcrypt.js, argon2-browser, qrcode-generator, and a self-authored hashlib.js for fast non-cryptographic checksums (CRC, Adler-32, FNV, xxHash, MurmurHash3, SipHash). A service worker precaches the app so it keeps working fully offline, with light and dark themes (dark by default).
