/*
   signature.js - Digital Signatures (Web Crypto)
   ECDSA on P-256 / P-384 / P-521 (SHA-256/384/512) and Ed25519 (RFC 8032).
   Keys as PEM (SPKI / PKCS#8, or OpenSSL "EC PRIVATE KEY") or JWK; keypair
   generation; ECDSA signatures as raw r||s (JOSE) or DER (OpenSSL), and Verify
   accepts either. Detect finds the algorithm from a pasted key.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec, toHex = CK.toHex, hexToBytes = CK.hexToBytes, unb64 = CK.unb64, b64 = CK.b64, pem = CK.pem, unpem = CK.unpem;

  /* Minimal DER helpers */
  function cat() { var n = 0, i, parts = Array.prototype.map.call(arguments, function (p) { return p instanceof Uint8Array ? p : new Uint8Array(p); }); for (i = 0; i < parts.length; i++) n += parts[i].length; var o = new Uint8Array(n), off = 0; for (i = 0; i < parts.length; i++) { o.set(parts[i], off); off += parts[i].length; } return o; }
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

  var ALGS = {
    'P-256': { label: 'ECDSA P-256', ec: true, size: 32, hash: 'SHA-256', oid: [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] },
    'P-384': { label: 'ECDSA P-384', ec: true, size: 48, hash: 'SHA-384', oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] },
    'P-521': { label: 'ECDSA P-521', ec: true, size: 66, hash: 'SHA-512', oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23] },
    'Ed25519': { label: 'Ed25519', ec: false, size: 32 }
  };
  var ORDER = ['P-256', 'P-384', 'P-521', 'Ed25519'];
  function keyAlg(id) { return ALGS[id].ec ? { name: 'ECDSA', namedCurve: id } : { name: 'Ed25519' }; }

  // PEM / JWK text -> Promise<CryptoKey> for usage 'sign' (private) or 'verify' (public)
  function importKeyAs(id, text, usage) {
    return Promise.resolve().then(function () {
      text = text.trim();
      if (text.charAt(0) === '{') {
        var jwk = JSON.parse(text);
        delete jwk.key_ops; delete jwk.use; delete jwk.alg; jwk.ext = true;
        if (usage === 'verify') delete jwk.d; // a private JWK also carries its public part
        return crypto.subtle.importKey('jwk', jwk, keyAlg(id), false, [usage]);
      }
      var priv = usage === 'sign', buf = unpem(text);
      if (priv && /BEGIN EC PRIVATE KEY/.test(text)) { if (!ALGS[id].ec) throw new Error('Not an Ed25519 key'); buf = sec1ToPkcs8(buf, ALGS[id].oid); }
      return crypto.subtle.importKey(priv ? 'pkcs8' : 'spki', buf, keyAlg(id), false, [usage]);
    });
  }

  var I_SIG = '<path d="M3 17c3-3 5-8 7-8s-1 7 1 7 3-4 4-4 1 3 3 3h3M3 21h18"/>';
  var I_MSG = CK.ui.IC.file;
  var I_SHUF = CK.ui.IC.shuffle;
  var I_CHECK = CK.ui.IC.check;
  var I_DETECT = CK.ui.IC.detect;
  var I_SHARE = CK.ui.IC.share;
  var I_RESET = CK.ui.IC.reset;

  CK.registerTool('signature', function (root, ctx) {
    var ui = CK.ui, el = CK.el, algo = 'P-256';

    root.appendChild(ui.head('Digital Signatures'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SIG);
    strip.acts.appendChild(ui.iconBtn(I_DETECT, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(I_CHECK, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(I_SHARE, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(I_RESET, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left: 2x2 sub-grid (Public key / Algorithm over Private key / Hash). Right: formats.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2 kv-mp' });
    var colR = el('div', { class: 'col' });
    var algoSel = ui.select(ORDER.map(function (id) { return { value: id, label: ALGS[id].label }; }), function (v) { setAlgo(v); }, 'P-256');
    var hashSel = ui.select([['SHA-256', 'SHA-256'], ['SHA-384', 'SHA-384'], ['SHA-512', 'SHA-512']], updateSel, 'SHA-256');
    var msgFmt = ui.select([['utf8', 'UTF-8'], ['base64', 'Base64'], ['hex', 'Hexadecimal']], null, 'utf8');
    var sigFmt = ui.select([['base64', 'Base64'], ['base64url', 'Base64 URL-safe'], ['hex', 'Hexadecimal']], null, 'base64');
    var encSel = ui.select([['raw', 'Raw r||s (JOSE / Web Crypto)'], ['der', 'DER (OpenSSL)']], null, 'raw');
    function keyBox(labelText) {
      var ta = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: labelText + ' (PEM or JWK)' });
      ta.style.flex = '1'; ta.style.fontSize = '11px'; ta.style.minWidth = '0';
      var wrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
      wrap.appendChild(ta);
      wrap.appendChild(ui.iconBtn(I_SHUF, 'Generate keypair', doGenerate));
      return { box: ui.field(labelText, wrap), ta: ta };
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
    var inP = ui.textPanel({ title: 'MESSAGE', icon: I_MSG, placeholder: 'Message to sign (private key), or to verify against the signature (public key)...', primaries: [{ label: 'Sign', cls: 'enc', onClick: doSign }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'message.txt' });
    var outP = ui.textPanel({ title: 'SIGNATURE', icon: I_SIG, placeholder: 'Signature appears here, or paste one to verify...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'signature.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function setAlgo(id) {
      algo = id; algoSel.value = id;
      var a = ALGS[id];
      hashField.style.display = a.ec ? '' : 'none';
      encField.style.display = a.ec ? '' : 'none';
      if (a.ec) hashSel.value = a.hash;
      updateSel();
    }
    function updateSel() {
      var a = ALGS[algo];
      if (a.ec) ui.setSel(strip, a.label, hashSel.value, 'ECDSA over ' + algo + ' with ' + hashSel.value + ', ' + a.size * 2 + '-byte signature (raw) or DER');
      else ui.setSel(strip, 'Ed25519', 'EdDSA', 'Edwards-curve signature (RFC 8032), 64-byte signature');
    }
    function sigAlg() { return ALGS[algo].ec ? { name: 'ECDSA', hash: hashSel.value } : { name: 'Ed25519' }; }
    function msgBytes() { return CK.textBytes(inP.ta.value, msgFmt.value); }
    function fmtSig(b) { if (sigFmt.value === 'hex') return toHex(b); return sigFmt.value === 'base64url' ? CK.b64u(b) : b64(b); }
    // Signature text -> raw bytes for Web Crypto. Tries the chosen format first,
    // then the others; for ECDSA accepts raw r||s or DER.
    function parseSig(text) {
      var a = ALGS[algo], fmts = [sigFmt.value].concat(['hex', 'base64'].filter(function (f) { return f !== sigFmt.value; })), err = 'Unrecognised signature format';
      for (var i = 0; i < fmts.length; i++) {
        var b;
        try { b = fmts[i] === 'hex' ? hexToBytes(text) : unb64(text); } catch (e) { continue; }
        if (a.ec && b[0] === 0x30) { try { return derToRaw(b, a.size); } catch (e) { err = e.message; } }
        if (b.length === a.size * 2) return b;
        err = b.length + ' bytes; ' + a.label + ' signatures are ' + a.size * 2 + ' bytes' + (a.ec ? ' (raw) or DER' : '');
      }
      throw new Error(err);
    }
    function keyError(e, which) {
      if (e && e.name === 'NotSupportedError' && algo === 'Ed25519') return 'Ed25519 is not supported by this browser';
      return 'Invalid ' + which + ' key for ' + ALGS[algo].label + ' (try Detect)';
    }

    function doGenerate() {
      crypto.subtle.generateKey(keyAlg(algo), true, ['sign', 'verify'])
        .then(function (kp) { return Promise.all([crypto.subtle.exportKey('spki', kp.publicKey), crypto.subtle.exportKey('pkcs8', kp.privateKey)]); })
        .then(function (k) { pub.ta.value = pem('PUBLIC KEY', k[0]); priv.ta.value = pem('PRIVATE KEY', k[1]); ctx.toast(ALGS[algo].label + ' keypair generated', 'success'); })
        .catch(function (e) { ctx.toast(e && e.name === 'NotSupportedError' ? ALGS[algo].label + ' is not supported by this browser' : 'Key generation failed: ' + e.message, 'error'); });
    }
    function doSign() {
      if (!inP.ta.value) { ctx.toast('Message is empty', 'warn'); return; }
      if (!priv.ta.value.trim()) { ctx.toast('Private key required to sign', 'warn'); return; }
      var msg; try { msg = msgBytes(); } catch (e) { ctx.toast('Message is not valid ' + (msgFmt.value === 'hex' ? 'hexadecimal' : 'Base64'), 'error'); return; }
      return importKeyAs(algo, priv.ta.value, 'sign').then(function (key) {
        return crypto.subtle.sign(sigAlg(), key, msg).then(function (sig) {
          var b = new Uint8Array(sig);
          if (ALGS[algo].ec && encSel.value === 'der') b = rawToDer(b);
          outP.ta.value = fmtSig(b); clearVerify();
          ctx.toast('Signed with ' + ALGS[algo].label + (ALGS[algo].ec ? ' / ' + hashSel.value : ''), 'success');
        });
      }, function (e) { throw new Error(keyError(e, 'private')); }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doVerify() {
      clearVerify();
      if (!pub.ta.value.trim()) { ctx.toast('Public key required to verify', 'warn'); return; }
      if (!inP.ta.value || !outP.ta.value.trim()) { ctx.toast('Both panels need content', 'warn'); return; }
      var msg; try { msg = msgBytes(); } catch (e) { ctx.toast('Message is not valid ' + (msgFmt.value === 'hex' ? 'hexadecimal' : 'Base64'), 'error'); return; }
      var sig; try { sig = parseSig(outP.ta.value); } catch (e) { CK.flashVerify(false, inP.ta, outP.ta); ctx.toast('Not a valid signature: ' + e.message, 'error'); return; }
      importKeyAs(algo, pub.ta.value, 'verify').then(function (key) {
        return crypto.subtle.verify(sigAlg(), key, sig, msg).then(function (ok) {
          CK.flashVerify(ok, inP.ta, outP.ta);
          ctx.toast(ok ? 'Valid: signature matches the message and public key' : 'Invalid signature (check the key, hash and message format)', ok ? 'success' : 'error');
        });
      }, function (e) { throw new Error(keyError(e, 'public')); }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    // Try each algorithm until the pasted key imports
    function doDetect() {
      var usePub = !!pub.ta.value.trim(), text = usePub ? pub.ta.value : priv.ta.value;
      if (!text.trim()) { ctx.toast('Paste a public or private key first', 'warn'); return; }
      var i = 0;
      (function next() {
        if (i >= ORDER.length) { ctx.toast('Not an ECDSA (P-256/384/521) or Ed25519 key', 'error'); return; }
        var id = ORDER[i++];
        importKeyAs(id, text, usePub ? 'verify' : 'sign').then(function () {
          setAlgo(id); ctx.toast('Detected ' + ALGS[id].label + ' ' + (usePub ? 'public' : 'private') + ' key', 'success');
        }, next);
      })();
    }
    function doShare() { var st = { a: algo, h: hashSel.value, mf: msgFmt.value, sf: sigFmt.value, e: encSel.value, pub: pub.ta.value, priv: priv.ta.value, in: inP.ta.value, out: outP.ta.value }; CK.share('signature', st, { priv: 'private key' }); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; pub.ta.value = ''; priv.ta.value = ''; msgFmt.value = 'utf8'; sigFmt.value = 'base64'; encSel.value = 'raw'; setAlgo('P-256'); clearVerify(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || ''), st = null;
    if (m) { try { st = JSON.parse(b64uDec(m[1])); } catch (e) { } }
    if (st) { if (ALGS[st.a]) algo = st.a; msgFmt.value = st.mf || 'utf8'; sigFmt.value = st.sf || 'base64'; encSel.value = st.e || 'raw'; pub.ta.value = st.pub || ''; priv.ta.value = st.priv || ''; inP.ta.value = st.in || ''; outP.ta.value = st.out || ''; }
    setAlgo(algo);
    if (st && st.h && ALGS[algo].ec) { hashSel.value = st.h; updateSel(); }
  });
})();
