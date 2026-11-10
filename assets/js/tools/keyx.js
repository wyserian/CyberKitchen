/*
   keyx.js - Key Exchange
   Agree on a shared secret. Diffie-Hellman style: X25519 / X448 (RFC 7748), ECDH on P-256 /
   P-384 / P-521 / secp256k1 (noble-curves), and finite-field DH over the RFC 3526 MODP and
   RFC 7919 FFDHE groups (BigInt, generator 2). Fresh keys per session make any of these
   ephemeral (DHE / ECDHE). Key encapsulation: ML-KEM-512/768/1024 (FIPS 203) and the X-Wing
   hybrid (ML-KEM-768 + X25519), from noble-post-quantum.
*/
(function () {
  'use strict';
  var later = CK.later, toHex = CK.toHex, hexToBytes = CK.hexToBytes, unb64 = CK.unb64, b64 = CK.b64, b64uDec = CK.b64uDec;

  // Group primes as hex, derived from pi (MODP) and e (FFDHE) by the RFC formulas and checked to be safe primes
  var P = {
    ffdhe2048: 'ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff',
    ffdhe3072: 'ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff',
    ffdhe4096: 'ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e655f6affffffffffffffff',
    modp2048: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff',
    modp3072: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff',
    modp4096: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff'
  };
  function big(b) { return BigInt('0x' + (toHex(b) || '0')); }
  function bytesOf(n, len) { var h = n.toString(16).padStart(len * 2, '0'); return hexToBytes(h); }
  function modpow(b, e, m) { var r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
  function ff(name) {
    var p = BigInt('0x' + P[name]), len = P[name].length / 2;
    function pubOf(x) { return bytesOf(modpow(2n, big(x), p), len); }
    return {
      lengths: { secretKey: len, publicKey: len },
      keygen: function () { var x = bytesOf(2n + big(CK.rndBytes(len)) % (p - 3n), len); return { secretKey: x, publicKey: pubOf(x) }; },
      getPublicKey: pubOf,
      getSharedSecret: function (x, y) {
        var Y = big(y);
        if (Y < 2n || Y > p - 2n) throw new Error('Peer public key is out of range for this group');
        return bytesOf(modpow(Y, big(x), p), len);
      }
    };
  }
  // ECDH secret = the shared point's x-coordinate (as Web Crypto, OpenSSL and SP 800-56A give it)
  function ec(name) { var c = function () { return Noble[name]; }; return { get lengths() { return c().lengths; }, keygen: function () { return c().keygen(); }, getPublicKey: function (s) { return c().getPublicKey(s); }, getSharedSecret: function (s, p) { return c().getSharedSecret(s, p).subarray(1); } }; }
  function nb(name) { return { get lengths() { return Noble[name].lengths; }, keygen: function () { return Noble[name].keygen(); }, getPublicKey: function (s) { return Noble[name].getPublicKey(s); }, getSharedSecret: function (s, p) { return Noble[name].getSharedSecret(s, p); }, encapsulate: function (p) { return Noble[name].encapsulate(p); }, decapsulate: function (c, s) { return Noble[name].decapsulate(c, s); } }; }

  // kem: key encapsulation (Encapsulate / Decapsulate) instead of Diffie-Hellman (Derive)
  var ALGS = [
    { id: 'x25519', label: 'X25519', badge: 'RFC 7748', lib: nb('x25519') },
    { id: 'x448', label: 'X448', badge: 'RFC 7748', lib: nb('x448') },
    { id: 'p256', label: 'ECDH P-256', badge: 'SP 800-56A', lib: ec('p256') },
    { id: 'p384', label: 'ECDH P-384', badge: 'SP 800-56A', lib: ec('p384') },
    { id: 'p521', label: 'ECDH P-521', badge: 'SP 800-56A', lib: ec('p521') },
    { id: 'secp256k1', label: 'ECDH secp256k1', badge: 'SEC 2', lib: ec('secp256k1') },
    { id: 'ffdhe2048', label: 'DH ffdhe2048', badge: 'RFC 7919', lib: ff('ffdhe2048') },
    { id: 'ffdhe3072', label: 'DH ffdhe3072', badge: 'RFC 7919', lib: ff('ffdhe3072') },
    { id: 'ffdhe4096', label: 'DH ffdhe4096', badge: 'RFC 7919', lib: ff('ffdhe4096') },
    { id: 'modp2048', label: 'DH MODP 2048 (group 14)', badge: 'RFC 3526', lib: ff('modp2048') },
    { id: 'modp3072', label: 'DH MODP 3072 (group 15)', badge: 'RFC 3526', lib: ff('modp3072') },
    { id: 'modp4096', label: 'DH MODP 4096 (group 16)', badge: 'RFC 3526', lib: ff('modp4096') },
    { id: 'mlkem512', label: 'ML-KEM-512 (Kyber)', badge: 'FIPS 203', kem: true, lib: nb('ml_kem512') },
    { id: 'mlkem768', label: 'ML-KEM-768 (Kyber)', badge: 'FIPS 203', kem: true, lib: nb('ml_kem768') },
    { id: 'mlkem1024', label: 'ML-KEM-1024 (Kyber)', badge: 'FIPS 203', kem: true, lib: nb('ml_kem1024') },
    { id: 'xwing', label: 'X-Wing (ML-KEM-768 + X25519)', badge: 'Hybrid', kem: true, lib: nb('ml_kem768_x25519') }
  ];
  function get(id) { for (var i = 0; i < ALGS.length; i++) if (ALGS[i].id === id) return ALGS[i]; return null; }

  var I_KX = '<circle cx="6" cy="12" r="3"/><circle cx="18" cy="12" r="3"/><path d="M9 12h6M12 5l3 3-3 3M12 13l-3 3 3 3"/>';

  CK.registerTool('keyx', function (root, ctx) {
    var ui = CK.ui, el = CK.el, current = 'x25519';
    root.appendChild(ui.head('Key Exchange'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_KX);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-right' });
    var colA = el('div', { class: 'col' }), colB = el('div', { class: 'col' });
    var algoSel = ui.select(ALGS.map(function (a) { return [a.id, a.label]; }), function (v) { select(v); }, current);
    var fmtSel = ui.select([['hex', 'Hexadecimal'], ['base64', 'Base64']], function () { reformat(); }, 'hex');
    colA.appendChild(ui.field('Algorithm', algoSel)); colA.appendChild(ui.field('Key format', fmtSel));
    function keyInput(place) { var i = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: place }); i.style.flex = '1'; i.style.minWidth = '0'; i.style.fontSize = '11px'; return i; }
    var privIn = keyInput('Your private key'), pubIn = keyInput('Your public key (derived from the private key)');
    var privRow = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    privRow.appendChild(privIn); privRow.appendChild(ui.iconBtn(CK.ui.IC.shuffle, 'Generate keypair', doGenerate));
    colB.appendChild(ui.field('Your private key', privRow));
    colB.appendChild(ui.field('Your public key', pubIn));
    privIn.addEventListener('input', derivePub);
    grid.appendChild(colA); grid.appendChild(colB);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PEER INPUT', icon: CK.ui.IC.key, placeholder: '', primaries: [{ label: 'Derive', cls: 'enc', onClick: doPrimary }, { label: 'Decapsulate', cls: 'dec', onClick: doDecap }], actions: ['copy', 'paste', 'clear'] });
    var outP = ui.textPanel({ title: 'SHARED SECRET', icon: CK.ui.IC.out, placeholder: 'The shared secret appears here...', readonly: true, actions: ['copy', 'download'], downloadName: 'shared-secret.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);
    var prims = [].filter.call(inP.panel.querySelectorAll('.panel-hdr button'), function (b) { return /\bprim\b/.test(b.className); });

    function text(b) { return fmtSel.value === 'base64' ? b64(b) : toHex(b); }
    function bytes(t, what) {
      t = (t || '').trim().replace(/\s/g, '');
      if (!t) throw new Error(what + ' is empty');
      return /^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0 ? hexToBytes(t) : unb64(t);
    }
    function priv() {
      var a = get(current), k = bytes(privIn.value, 'Your private key'), L = a.lib.lengths;
      if (k.length !== L.secretKey) throw new Error(a.label + ' private keys are ' + L.secretKey + ' bytes (got ' + k.length + ')');
      return k;
    }
    function peerPub() {
      var a = get(current), k = bytes(inP.ta.value, 'Peer public key'), L = a.lib.lengths;
      if (k.length !== L.publicKey && k.length !== L.publicKeyUncompressed) throw new Error(a.label + ' public keys are ' + L.publicKey + ' bytes (got ' + k.length + ')');
      return k;
    }
    function select(id) {
      var a = get(id); if (!a) return; current = id; algoSel.value = id;
      var L = a.lib.lengths;
      prims[0].textContent = a.kem ? 'Encapsulate' : 'Derive';
      prims[1].style.display = a.kem ? '' : 'none';
      inP.ta.placeholder = a.kem ? 'Encapsulate: paste the recipient\'s public key.\nDecapsulate: paste the ciphertext you received (uses your private key).' : 'Paste the other party\'s public key, then Derive.';
      ui.setSel(strip, a.label, a.badge, a.kem ?
        'Key encapsulation: the sender encapsulates to the recipient\'s ' + L.publicKey + '-byte public key and sends the ' + L.cipherText + '-byte ciphertext; the recipient decapsulates it with their private key. Both get the same 32-byte secret.' + (a.id === 'xwing' ? ' Secure if either ML-KEM or X25519 holds.' : ' Post-quantum.') :
        'Each side combines its own private key with the other\'s public key and gets the same secret. ' + L.publicKey + '-byte public keys.' + (/^(ff|modp)/.test(a.id) ? ' Large keys: generating takes a moment.' : '') + ' Hash the secret (e.g. with HKDF) before using it as a key.');
    }
    function derivePub() { try { pubIn.value = text(get(current).lib.getPublicKey(priv())); } catch (e) { pubIn.value = ''; } }
    function reformat() { [privIn, pubIn].forEach(function (i) { try { if (i.value.trim()) i.value = text(bytes(i.value, 'Key')); } catch (e) { } }); }

    function doGenerate() {
      var a = get(current);
      return later(function () { return a.lib.keygen(); }).then(function (k) {
        privIn.value = text(k.secretKey); pubIn.value = text(k.publicKey); outP.ta.value = '';
        ctx.toast(a.label + ' keypair generated: share the public key', 'success');
      }).catch(function (e) { ctx.toast('Key generation failed: ' + e.message, 'error'); });
    }
    function doPrimary() {
      var a = get(current);
      if (a.kem) return later(function () { return a.lib.encapsulate(peerPub()); }).then(function (r) {
        outP.ta.value = 'Ciphertext (send this to the key owner):\n' + text(r.cipherText) + '\n\nShared secret:\n' + text(r.sharedSecret);
        ctx.toast('Encapsulated: send the ciphertext, keep the secret', 'success');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
      return later(function () { return a.lib.getSharedSecret(priv(), peerPub()); }).then(function (s) {
        outP.ta.value = text(s); ctx.toast('Shared secret derived (' + s.length + ' bytes)', 'success');
      }).catch(function (e) { ctx.toast(/point|Point|curve/.test(e.message) ? 'Peer public key is not a valid ' + a.label + ' point' : e.message, 'error'); });
    }
    function doDecap() {
      var a = get(current);
      return later(function () {
        var c = bytes(inP.ta.value, 'Ciphertext');
        if (c.length !== a.lib.lengths.cipherText) throw new Error(a.label + ' ciphertexts are ' + a.lib.lengths.cipherText + ' bytes (got ' + c.length + ')');
        return a.lib.decapsulate(c, priv());
      }).then(function (s) { outP.ta.value = text(s); ctx.toast('Decapsulated: this is the sender\'s shared secret', 'success'); })
        .catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doShare() { CK.share('keyx', { a: current, f: fmtSel.value, pk: privIn.value, pub: pubIn.value, in: inP.ta.value }, { pk: 'private key' }); }
    function doReset() { privIn.value = ''; pubIn.value = ''; inP.ta.value = ''; outP.ta.value = ''; fmtSel.value = 'hex'; select('x25519'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); if (get(st.a)) current = st.a; fmtSel.value = st.f || 'hex'; privIn.value = st.pk || ''; pubIn.value = st.pub || ''; inP.ta.value = st.in || ''; } catch (e) { } }
    select(current);
  });
})();
