/*
   signature.js - Digital Signatures
   Web Crypto: ECDSA on P-256 / P-384 / P-521, Ed25519 (RFC 8032), RSA-PSS and
   RSASSA-PKCS1-v1_5, with keys as PEM (SPKI / PKCS#8, or OpenSSL "EC PRIVATE KEY") or JWK.
   noble-curves / noble-post-quantum: Ed448, ECDSA secp256k1, ML-DSA (FIPS 204),
   SLH-DSA (FIPS 205) and Falcon, with raw keys as hex or Base64.
   Keypair generation; ECDSA signatures as raw r||s (JOSE) or DER (OpenSSL), and Verify
   accepts either. Detect finds the algorithm from a pasted key.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec, toHex = CK.toHex, hexToBytes = CK.hexToBytes, unb64 = CK.unb64, b64 = CK.b64, pem = CK.pem, unpem = CK.unpem;

  /* Minimal DER helpers */
  var cat = CK.cat, later = CK.later;
  function derLen(n) { return n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]; }
  function der(tag, body) { return cat([tag], derLen(body.length), body); }
  // ECDSA raw r||s (Web Crypto / JOSE) -> DER SEQUENCE { INTEGER r, INTEGER s } (OpenSSL)
  function rawToDer(raw) {
    var n = raw.length / 2;
    function int(b) { var i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); return der(0x02, b[0] & 0x80 ? cat([0], b) : b); }
    return der(0x30, cat(int(raw.slice(0, n)), int(raw.slice(n))));
  }
  // DER -> raw r||s with each integer left-padded to n bytes; throws if not exact DER
  function derToRaw(d, n) {
    var p = 0;
    function len() { var l = d[p++]; if (l & 0x80) { var k = l & 0x7f; if (k < 1 || k > 2) throw new Error('Bad DER length'); l = 0; while (k--) l = (l << 8) | d[p++]; } return l; }
    if (d[p++] !== 0x30) throw new Error('Not DER');
    if (len() !== d.length - p) throw new Error('Bad DER length');
    var out = new Uint8Array(2 * n);
    for (var j = 0; j < 2; j++) {
      if (d[p++] !== 0x02) throw new Error('Not DER');
      var l = len(), v = d.slice(p, p + l); p += l;
      if (v.length !== l) throw new Error('Truncated DER');
      while (v.length > n && v[0] === 0) v = v.slice(1);
      if (v.length > n) throw new Error('Integer too long for the curve');
      out.set(v, j * n + (n - v.length));
    }
    if (p !== d.length) throw new Error('Trailing bytes after DER');
    return out;
  }
  var OID_EC = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
  // OpenSSL SEC1 "EC PRIVATE KEY" -> PKCS#8 PrivateKeyInfo for the given curve
  function sec1ToPkcs8(sec1, curveOid) { return der(0x30, cat([0x02, 0x01, 0x00], der(0x30, cat(OID_EC, curveOid)), der(0x04, sec1))); }

  // ec: ECDSA (raw/DER encoding); size: bytes per r / s. rsa: hash chosen by the user.
  // nb: noble implementation (raw keys); pq: post-quantum.
  function slh(v, name) { return { label: 'SLH-DSA-' + name, badge: 'FIPS 205', pq: true, nb: function () { return Noble.slh['slh_dsa_' + v]; } }; }
  var ALGS = {
    'P-256': { label: 'ECDSA P-256', badge: 'FIPS 186', ec: true, size: 32, hash: 'SHA-256', oid: [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] },
    'P-384': { label: 'ECDSA P-384', badge: 'FIPS 186', ec: true, size: 48, hash: 'SHA-384', oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] },
    'P-521': { label: 'ECDSA P-521', badge: 'FIPS 186', ec: true, size: 66, hash: 'SHA-512', oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23] },
    'secp256k1': { label: 'ECDSA secp256k1', badge: 'SEC 2', ec: true, size: 32, nb: function () { return Noble.secp256k1; } },
    'Ed25519': { label: 'Ed25519', badge: 'RFC 8032', size: 32 },
    'Ed448': { label: 'Ed448', badge: 'RFC 8032', nb: function () { return Noble.ed448; } },
    'RSA-PSS': { label: 'RSA-PSS', badge: 'RFC 8017', rsa: 'RSA-PSS', hash: 'SHA-256' },
    'RSA-PKCS1': { label: 'RSA PKCS#1 v1.5', badge: 'RFC 8017', rsa: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    'ML-DSA-44': { label: 'ML-DSA-44 (Dilithium)', badge: 'FIPS 204', pq: true, nb: function () { return Noble.ml_dsa44; } },
    'ML-DSA-65': { label: 'ML-DSA-65 (Dilithium)', badge: 'FIPS 204', pq: true, nb: function () { return Noble.ml_dsa65; } },
    'ML-DSA-87': { label: 'ML-DSA-87 (Dilithium)', badge: 'FIPS 204', pq: true, nb: function () { return Noble.ml_dsa87; } },
    // The 192s / 256s variants take 5-25 s to sign in a browser tab, so only the faster ones are offered
    'SLH-SHA2-128f': slh('sha2_128f', 'SHA2-128f'), 'SLH-SHA2-128s': slh('sha2_128s', 'SHA2-128s'),
    'SLH-SHA2-192f': slh('sha2_192f', 'SHA2-192f'), 'SLH-SHA2-256f': slh('sha2_256f', 'SHA2-256f'),
    'SLH-SHAKE-128f': slh('shake_128f', 'SHAKE-128f'), 'SLH-SHAKE-128s': slh('shake_128s', 'SHAKE-128s'),
    'SLH-SHAKE-192f': slh('shake_192f', 'SHAKE-192f'), 'SLH-SHAKE-256f': slh('shake_256f', 'SHAKE-256f'),
    'Falcon-512': { label: 'Falcon-512', badge: 'Falcon', pq: true, nb: function () { return Noble.falcon512; } },
    'Falcon-1024': { label: 'Falcon-1024', badge: 'Falcon', pq: true, nb: function () { return Noble.falcon1024; } }
  };
  var ORDER = Object.keys(ALGS);
  function keyAlg(id, hash) { var a = ALGS[id]; return a.rsa ? { name: a.rsa, hash: hash } : a.ec ? { name: 'ECDSA', namedCurve: id } : { name: 'Ed25519' }; }

  // PEM / JWK text -> Promise<CryptoKey> for usage 'sign' (private) or 'verify' (public)
  function importKeyAs(id, text, usage, hash) {
    return Promise.resolve().then(function () {
      text = text.trim();
      if (text.charAt(0) === '{') {
        var jwk = JSON.parse(text);
        delete jwk.key_ops; delete jwk.use; delete jwk.alg; jwk.ext = true;
        if (usage === 'verify') { delete jwk.d; delete jwk.p; delete jwk.q; delete jwk.dp; delete jwk.dq; delete jwk.qi; } // a private JWK also carries its public part
        return crypto.subtle.importKey('jwk', jwk, keyAlg(id, hash), false, [usage]);
      }
      var priv = usage === 'sign', buf = unpem(text);
      if (priv && /BEGIN EC PRIVATE KEY/.test(text)) { if (!ALGS[id].oid) throw new Error('Not an ' + ALGS[id].label + ' key'); buf = sec1ToPkcs8(buf, ALGS[id].oid); }
      return crypto.subtle.importKey(priv ? 'pkcs8' : 'spki', buf, keyAlg(id, hash), false, [usage]);
    });
  }
  // Raw noble key text (hex or Base64) -> bytes; checks the length for this algorithm
  function rawKey(id, text, which) {
    var t = text.trim().replace(/\s/g, ''), b = /^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0 ? hexToBytes(t) : unb64(t), L = ALGS[id].nb().lengths;
    var ok = which === 'secretKey' ? [L.secretKey] : [L.publicKey, L.publicKeyUncompressed];
    if (ok.indexOf(b.length) < 0) throw new Error(ALGS[id].label + ' ' + (which === 'secretKey' ? 'private' : 'public') + ' keys are ' + L[which] + ' bytes (got ' + b.length + ')');
    return b;
  }
  function keyText(b) { return b.length <= 64 ? toHex(b) : b64(b); }

  var I_SIG = '<path d="M3 17c3-3 5-8 7-8s-1 7 1 7 3-4 4-4 1 3 3 3h3M3 21h18"/>';

  CK.registerTool('signature', function (root, ctx) {
    var ui = CK.ui, el = CK.el, algo = 'P-256';

    root.appendChild(ui.head('Digital Signatures'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SIG);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.detect, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left: 2x2 sub-grid (Public key / Algorithm over Private key / Hash). Right: formats.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2 kv-mp' });
    var colR = el('div', { class: 'col' });
    var algoSel = ui.select(ORDER.map(function (id) { return [id, ALGS[id].label]; }), function (v) { setAlgo(v); }, 'P-256');
    var hashSel = ui.select([['SHA-256', 'SHA-256'], ['SHA-384', 'SHA-384'], ['SHA-512', 'SHA-512']], updateSel, 'SHA-256');
    var msgFmt = ui.select([['utf8', 'UTF-8'], ['base64', 'Base64'], ['hex', 'Hexadecimal']], null, 'utf8');
    var sigFmt = ui.select([['base64', 'Base64'], ['base64url', 'Base64 URL-safe'], ['hex', 'Hexadecimal']], null, 'base64');
    var encSel = ui.select([['raw', 'Raw r||s (JOSE / Web Crypto)'], ['der', 'DER (OpenSSL)']], null, 'raw');
    function keyBox(labelText) {
      var ta = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off' });
      ta.style.flex = '1'; ta.style.fontSize = '11px'; ta.style.minWidth = '0';
      var wrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
      wrap.appendChild(ta);
      wrap.appendChild(ui.iconBtn(CK.ui.IC.shuffle, 'Generate keypair', doGenerate));
      return { box: ui.field(labelText, wrap), ta: ta, name: labelText };
    }
    var pub = keyBox('Public key'), priv = keyBox('Private key');
    var hashField = ui.field('Hash', hashSel), encField = ui.field('Signature encoding', encSel);
    colL.appendChild(pub.box); colL.appendChild(ui.field('Algorithm', algoSel));
    colL.appendChild(priv.box); colL.appendChild(hashField);
    colR.appendChild(ui.field('Message format', msgFmt));
    colR.appendChild(ui.field('Signature format', sigFmt));
    colR.appendChild(encField);
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'MESSAGE', icon: CK.ui.IC.file, placeholder: 'Message to sign (private key), or to verify against the signature (public key)...', primaries: [{ label: 'Sign', cls: 'enc', onClick: doSign }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'message.txt' });
    var outP = ui.textPanel({ title: 'SIGNATURE', icon: I_SIG, placeholder: 'Signature appears here, or paste one to verify...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'signature.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function setAlgo(id) {
      algo = id; algoSel.value = id;
      var a = ALGS[id], webHash = !a.nb && (a.ec || a.rsa);
      hashField.style.display = webHash ? '' : 'none';
      encField.style.display = a.ec ? '' : 'none';
      if (webHash) hashSel.value = a.hash;
      [pub, priv].forEach(function (k) { k.ta.placeholder = k.name + (a.nb ? ' (raw, hex or Base64)' : ' (PEM or JWK)'); });
      updateSel();
    }
    function updateSel() {
      var a = ALGS[algo], L = a.nb && a.nb().lengths;
      var d = a.ec && !a.nb ? 'ECDSA over ' + algo + ' with ' + hashSel.value + ', ' + a.size * 2 + '-byte signature (raw) or DER' :
        algo === 'secp256k1' ? 'ECDSA over secp256k1 (Bitcoin, Ethereum) with SHA-256, low-S, 64-byte signature (raw) or DER' :
        a.rsa ? a.label + ' with ' + hashSel.value + (a.rsa === 'RSA-PSS' ? ', salt length = hash length' : '') + '; new keys are 2048-bit' :
        algo === 'Ed25519' ? 'Edwards-curve signature (RFC 8032), 64-byte signature' :
        a.label + ': ' + L.publicKey + '-byte public key, ' + L.secretKey + '-byte private key' + (L.signature ? ', ' + L.signature.toLocaleString() + '-byte signature' : ', variable-size signature') +
        (a.pq ? '. Post-quantum.' : '.');
      ui.setSel(strip, a.label, a.rsa || a.ec ? (a.nb ? 'SHA-256' : hashSel.value) : a.badge, d);
    }
    function sigAlg() { var a = ALGS[algo]; return a.rsa === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: { 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 }[hashSel.value] } : a.rsa ? { name: a.rsa } : a.ec ? { name: 'ECDSA', hash: hashSel.value } : { name: 'Ed25519' }; }
    function msgBytes() { return CK.textBytes(inP.ta.value, msgFmt.value); }
    function fmtSig(b) { if (sigFmt.value === 'hex') return toHex(b); return sigFmt.value === 'base64url' ? CK.b64u(b) : b64(b); }
    // Signature text -> raw bytes. Tries the chosen format first, then the others; for ECDSA accepts raw r||s or DER.
    function parseSig(text) {
      var a = ALGS[algo], want = a.size ? a.size * 2 : a.nb ? a.nb().lengths.signature : 0;
      var fmts = [sigFmt.value].concat(['hex', 'base64'].filter(function (f) { return f !== sigFmt.value; })), err = 'Unrecognised signature format';
      for (var i = 0; i < fmts.length; i++) {
        var b;
        try { b = fmts[i] === 'hex' ? hexToBytes(text) : unb64(text); } catch (e) { continue; }
        if (a.ec && b[0] === 0x30) { try { return derToRaw(b, a.size); } catch (e) { err = e.message; } }
        if (!want || b.length === want) return b;
        err = b.length + ' bytes; ' + a.label + ' signatures are ' + want + ' bytes' + (a.ec ? ' (raw) or DER' : '');
      }
      throw new Error(err);
    }
    function keyError(e, which) {
      if (e && e.name === 'NotSupportedError') return ALGS[algo].label + ' is not supported by this browser';
      return 'Invalid ' + which + ' key for ' + ALGS[algo].label + (e && /bytes/.test(e.message) ? ': ' + e.message : ' (try Detect)');
    }

    function doGenerate() {
      var a = ALGS[algo];
      if (a.nb) {
        return later(function () { return a.nb().keygen(); }).then(function (k) {
          pub.ta.value = keyText(k.publicKey); priv.ta.value = keyText(k.secretKey); ctx.toast(a.label + ' keypair generated', 'success');
        }).catch(function (e) { ctx.toast('Key generation failed: ' + e.message, 'error'); });
      }
      var spec = a.rsa ? { name: a.rsa, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: hashSel.value } : keyAlg(algo);
      return crypto.subtle.generateKey(spec, true, ['sign', 'verify'])
        .then(function (kp) { return Promise.all([crypto.subtle.exportKey('spki', kp.publicKey), crypto.subtle.exportKey('pkcs8', kp.privateKey)]); })
        .then(function (k) { pub.ta.value = pem('PUBLIC KEY', k[0]); priv.ta.value = pem('PRIVATE KEY', k[1]); ctx.toast(a.label + ' keypair generated', 'success'); })
        .catch(function (e) { ctx.toast(e && e.name === 'NotSupportedError' ? a.label + ' is not supported by this browser' : 'Key generation failed: ' + e.message, 'error'); });
    }
    // Promise<Uint8Array> raw signature (r||s for ECDSA)
    function signBytes(msg) {
      var a = ALGS[algo];
      if (a.nb) return later(function () { var sk; try { sk = rawKey(algo, priv.ta.value, 'secretKey'); } catch (e) { throw new Error(keyError(e, 'private')); } return a.nb().sign(msg, sk); });
      return importKeyAs(algo, priv.ta.value, 'sign', hashSel.value).then(function (key) {
        return crypto.subtle.sign(sigAlg(), key, msg).then(function (s) { return new Uint8Array(s); });
      }, function (e) { throw new Error(keyError(e, 'private')); });
    }
    function verifyBytes(sig, msg) {
      var a = ALGS[algo];
      if (a.nb) return later(function () { var pk; try { pk = rawKey(algo, pub.ta.value, 'publicKey'); } catch (e) { throw new Error(keyError(e, 'public')); } try { return a.nb().verify(sig, msg, pk); } catch (e) { return false; } });
      return importKeyAs(algo, pub.ta.value, 'verify', hashSel.value).then(function (key) { return crypto.subtle.verify(sigAlg(), key, sig, msg); }, function (e) { throw new Error(keyError(e, 'public')); });
    }
    function doSign() {
      if (!inP.ta.value) { ctx.toast('Message is empty', 'warn'); return; }
      if (!priv.ta.value.trim()) { ctx.toast('Private key required to sign', 'warn'); return; }
      var msg; try { msg = msgBytes(); } catch (e) { ctx.toast('Message is not valid ' + (msgFmt.value === 'hex' ? 'hexadecimal' : 'Base64'), 'error'); return; }
      var a = ALGS[algo];
      return signBytes(msg).then(function (b) {
        if (a.ec && encSel.value === 'der') b = rawToDer(b);
        outP.ta.value = fmtSig(b); clearVerify();
        ctx.toast('Signed with ' + a.label + (a.ec || a.rsa ? ' / ' + (a.nb ? 'SHA-256' : hashSel.value) : ''), 'success');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doVerify() {
      clearVerify();
      if (!pub.ta.value.trim()) { ctx.toast('Public key required to verify', 'warn'); return; }
      if (!inP.ta.value || !outP.ta.value.trim()) { ctx.toast('Both panels need content', 'warn'); return; }
      var msg; try { msg = msgBytes(); } catch (e) { ctx.toast('Message is not valid ' + (msgFmt.value === 'hex' ? 'hexadecimal' : 'Base64'), 'error'); return; }
      var sig; try { sig = parseSig(outP.ta.value); } catch (e) { CK.flashVerify(false, inP.ta, outP.ta); ctx.toast('Not a valid signature: ' + e.message, 'error'); return; }
      return verifyBytes(sig, msg).then(function (ok) {
        CK.flashVerify(ok, inP.ta, outP.ta);
        ctx.toast(ok ? 'Valid: signature matches the message and public key' : 'Invalid signature (check the key, hash and message format)', ok ? 'success' : 'error');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    // PEM / JWK: try each Web Crypto algorithm until the key imports. Raw keys: match the byte length.
    function doDetect() {
      var usePub = !!pub.ta.value.trim(), text = (usePub ? pub.ta.value : priv.ta.value).trim();
      if (!text) { ctx.toast('Paste a public or private key first', 'warn'); return; }
      var which = usePub ? 'publicKey' : 'secretKey', kind = usePub ? 'public' : 'private';
      if (!/-----BEGIN|^\{/.test(text)) {
        var hit = ORDER.filter(function (id) { if (!ALGS[id].nb) return false; try { rawKey(id, text, which); return true; } catch (e) { return false; } });
        if (!hit.length) { ctx.toast('No supported algorithm uses ' + kind + ' keys of this size', 'error'); return; }
        setAlgo(hit[0]);
        ctx.toast('Detected ' + ALGS[hit[0]].label + ' ' + kind + ' key' + (hit.length > 1 ? ' (same size: ' + hit.slice(1).map(function (id) { return ALGS[id].label; }).join(', ') + ')' : ''), 'success');
        return;
      }
      var web = ORDER.filter(function (id) { return !ALGS[id].nb; }), i = 0;
      (function next() {
        if (i >= web.length) { ctx.toast('Not an ECDSA (P-256/384/521), Ed25519 or RSA key', 'error'); return; }
        var id = web[i++];
        importKeyAs(id, text, usePub ? 'verify' : 'sign', ALGS[id].hash || 'SHA-256').then(function () {
          setAlgo(id); ctx.toast('Detected ' + ALGS[id].label + ' ' + kind + ' key', 'success');
        }, next);
      })();
    }
    function doShare() { var st = { a: algo, h: hashSel.value, mf: msgFmt.value, sf: sigFmt.value, e: encSel.value, pub: pub.ta.value, priv: priv.ta.value, in: inP.ta.value, out: outP.ta.value }; CK.share('signature', st, { priv: 'private key' }); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; pub.ta.value = ''; priv.ta.value = ''; msgFmt.value = 'utf8'; sigFmt.value = 'base64'; encSel.value = 'raw'; setAlgo('P-256'); clearVerify(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || ''), st = null;
    if (m) { try { st = JSON.parse(b64uDec(m[1])); } catch (e) { } }
    if (st) { if (ALGS[st.a]) algo = st.a; msgFmt.value = st.mf || 'utf8'; sigFmt.value = st.sf || 'base64'; encSel.value = st.e || 'raw'; pub.ta.value = st.pub || ''; priv.ta.value = st.priv || ''; inP.ta.value = st.in || ''; outP.ta.value = st.out || ''; }
    setAlgo(algo);
    if (st && st.h && hashField.style.display !== 'none') { hashSel.value = st.h; updateSel(); }
  });
})();
