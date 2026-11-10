/*
   jwt.js - JSON Web Token tool (RFC 7519)
   Decode header + payload, sign, verify, and edit. HS256/384/512 use Web Crypto
   HMAC with a UTF-8/Base64/Hex secret; RS256, ES256, ES384 and EdDSA use Web
   Crypto with PEM or JWK public / private keys. Edit turns a token into an editable
   { header, payload } JSON in the input panel; Sign re-signs it (custom header
   fields kept, alg "none" gives an unsigned token). Fully offline.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec, pem = CK.pem, unpem = CK.unpem, randomSecret = CK.randomSecret, unb64 = CK.unb64;
  var ENC = new TextEncoder();
  var b64uBytes = CK.b64u, b64uStr = CK.b64uEnc, unb64u = unb64, unb64uText = b64uDec;

  var HASH = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
  // Public-key algorithms. Web Crypto's ECDSA output is raw r||s, exactly the JWS format.
  var ASYM = {
    RS256: { key: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, sig: { name: 'RSASSA-PKCS1-v1_5' }, desc: 'RSASSA-PKCS1-v1_5 with SHA-256',
      gen: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' } },
    ES256: { key: { name: 'ECDSA', namedCurve: 'P-256' }, sig: { name: 'ECDSA', hash: 'SHA-256' }, desc: 'ECDSA on P-256 with SHA-256' },
    ES384: { key: { name: 'ECDSA', namedCurve: 'P-384' }, sig: { name: 'ECDSA', hash: 'SHA-384' }, desc: 'ECDSA on P-384 with SHA-384' },
    EdDSA: { key: { name: 'Ed25519' }, sig: { name: 'Ed25519' }, desc: 'Ed25519 signature (RFC 8037)' }
  };
  function known(a) { return a === 'none' || !!HASH[a] || !!ASYM[a]; }
  // PEM (SPKI / PKCS#8) or JWK text -> CryptoKey for 'sign' (private) or 'verify' (public)
  function importAsym(a, text, usage) {
    text = String(text).trim();
    if (text.charAt(0) === '{') {
      var jwk = JSON.parse(text); delete jwk.alg; delete jwk.key_ops; delete jwk.use;
      if (usage === 'verify') delete jwk.d; // a private JWK also carries the public part
      return crypto.subtle.importKey('jwk', jwk, ASYM[a].key, false, [usage]);
    }
    return crypto.subtle.importKey(usage === 'sign' ? 'pkcs8' : 'spki', unpem(text), ASYM[a].key, false, [usage]);
  }

  var secretBytes = CK.textBytes;

  // signingInput -> Promise<base64url signature>
  function sign(algo, signingInput, keyState) { return Promise.resolve().then(function () {
    var data = ENC.encode(signingInput);
    if (ASYM[algo]) {
      if (!keyState.priv) return Promise.reject(new Error('Private key required for ' + algo));
      return importAsym(algo, keyState.priv, 'sign')
        .then(function (k) { return crypto.subtle.sign(ASYM[algo].sig, k, data); }).then(b64uBytes);
    }
    if (!keyState.secret) return Promise.reject(new Error('Secret required for ' + algo));
    return crypto.subtle.importKey('raw', secretBytes(keyState.secret, keyState.secretFmt), { name: 'HMAC', hash: { name: HASH[algo] } }, false, ['sign'])
      .then(function (k) { return crypto.subtle.sign('HMAC', k, data); }).then(b64uBytes);
  }); }
  // returns Promise<boolean>
  function verify(algo, signingInput, sigB64u, keyState) { return Promise.resolve().then(function () {
    var data = ENC.encode(signingInput), sig = unb64u(sigB64u);
    if (ASYM[algo]) {
      if (!keyState.pub) return Promise.reject(new Error('Public key required for ' + algo));
      return importAsym(algo, keyState.pub, 'verify')
        .then(function (k) { return crypto.subtle.verify(ASYM[algo].sig, k, sig, data); });
    }
    if (!keyState.secret) return Promise.reject(new Error('Secret required for ' + algo));
    return crypto.subtle.importKey('raw', secretBytes(keyState.secret, keyState.secretFmt), { name: 'HMAC', hash: { name: HASH[algo] } }, false, ['verify'])
      .then(function (k) { return crypto.subtle.verify('HMAC', k, sig, data); });
  }); }

  var I_TOKEN = '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/>';
  var I_JSON = '<path d="M8 4H6a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h2M16 4h2a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-2"/>';
  var I_NEW = '<path d="M12 5v14M5 12h14"/>';

  // { header:{...}, payload:{...} } as produced by Edit / New token
  function isEditDoc(v) {
    if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
    var k = Object.keys(v);
    return k.length === 2 && k.indexOf('header') >= 0 && k.indexOf('payload') >= 0 &&
      v.header && typeof v.header === 'object' && !Array.isArray(v.header) && v.payload !== null && typeof v.payload === 'object';
  }

  // Deep JSON equality, ignoring object key order
  function sameJson(a, b) {
    if (a === b) return true;
    if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
    var ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    return ka.every(function (k) { return Object.prototype.hasOwnProperty.call(b, k) && sameJson(a[k], b[k]); });
  }

  CK.registerTool('jwt', function (root, ctx) {
    var ui = CK.ui, el = CK.el, algo = 'HS256';

    root.appendChild(ui.head('JSON Web Token'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_TOKEN);
    strip.acts.appendChild(ui.iconBtn(I_NEW, 'New token', doNew));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.swap, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-right' }); // Algorithm first, then its secret / keys
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });

    var algoSel = ui.select([['HS256', 'HS256 (HMAC SHA-256)'], ['HS384', 'HS384 (HMAC SHA-384)'], ['HS512', 'HS512 (HMAC SHA-512)'], ['RS256', 'RS256 (RSA SHA-256)'], ['ES256', 'ES256 (ECDSA P-256)'], ['ES384', 'ES384 (ECDSA P-384)'], ['EdDSA', 'EdDSA (Ed25519)'], ['none', 'none (unsigned)']], function (v) { algo = v; applyAlgo(); updateSel(); }, 'HS256');
    colR.appendChild(ui.field('Algorithm', algoSel));

    // HMAC secret (HS*)
    var secretInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'HMAC secret' });
    var secretFmt = ui.select([['utf8', 'UTF-8'], ['base64', 'Base64'], ['hex', 'Hexadecimal']], null, 'utf8');
    var secretGen = ui.iconBtn(CK.ui.IC.shuffle, 'Random', function () { secretInput.value = randomSecret(32, secretFmt.value); });
    var secretWrap = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    secretInput.style.flex = '1'; secretInput.style.minWidth = '0'; secretFmt.style.width = 'auto';
    secretWrap.appendChild(secretInput); secretWrap.appendChild(secretFmt); secretWrap.appendChild(secretGen);
    var secretField = ui.field('Secret', secretWrap);
    colL.appendChild(secretField);

    // Public / private keys (RS256, ES256, ES384, EdDSA)
    function keyBox(labelText) {
      var input = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: labelText + ' (PEM or JWK)' });
      input.style.flex = '1'; input.style.minWidth = '0';
      var wrap = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
      wrap.appendChild(input);
      return { field: ui.field(labelText, wrap), input: input, wrap: wrap };
    }
    var pub = keyBox('Public key'), priv = keyBox('Private key');
    var genBtn = ui.iconBtn(CK.ui.IC.shuffle, 'Generate keypair', doGenerate);
    priv.wrap.appendChild(genBtn);
    pub.field.style.display = 'none'; priv.field.style.display = 'none';
    colL.appendChild(pub.field); colL.appendChild(priv.field);

    grid.appendChild(colR); grid.appendChild(colL);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'TOKEN / CLAIMS', icon: I_TOKEN, placeholder: 'Paste a JWT to decode, verify or edit (Edit loads its header and payload here to modify and re-sign), or a claims JSON to sign. New token starts from a template...', primaries: [{ label: 'Sign', cls: 'enc', onClick: doSign }, { label: 'Decode', cls: 'dec', onClick: doDecode }, { label: 'Edit', cls: 'dec', onClick: doEdit }], actions: ['copy', 'paste', 'clear'], onInput: clearVerify });
    var outP = ui.textPanel({ title: 'RESULT', icon: I_JSON, placeholder: 'Decoded header and payload, or the signed token...', actions: ['copy', 'download'], downloadName: 'jwt.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { inP.ta.classList.remove('verify-match', 'verify-fail'); outP.ta.classList.remove('verify-match', 'verify-fail'); }
    outP.ta.addEventListener('input', clearVerify);

    function keyState() { return { secret: secretInput.value, secretFmt: secretFmt.value, pub: pub.ta ? pub.ta.value : pub.input.value, priv: priv.input.value }; }
    // The keyBox exposes `.input`; alias `.ta` for RSA generation reuse
    pub.ta = pub.input; priv.ta = priv.input;

    function applyAlgo() {
      var asym = !!ASYM[algo];
      secretField.style.display = asym || algo === 'none' ? 'none' : ''; // alg none needs no key
      pub.field.style.display = asym ? '' : 'none';
      priv.field.style.display = asym ? '' : 'none';
    }
    function updateSel() { ui.setSel(strip, 'JWT · ' + algo, algo === 'none' ? 'unsigned' : algo.slice(0, 2), algo === 'none' ? 'No signature: anyone can change the token. For testing only.' : ASYM[algo] ? ASYM[algo].desc : 'HMAC with ' + HASH[algo]); }

    function doDecode() {
      var t = inP.ta.value.trim();
      var p = t.split('.');
      if (p.length < 2) { ctx.toast('Not a valid JWT (expected header.payload.signature)', 'error'); return; }
      function part(x) { try { return JSON.stringify(JSON.parse(unb64uText(x)), null, 2); } catch (e) { try { return unb64uText(x); } catch (e2) { return '(unreadable)'; } } }
      var header;
      try { header = JSON.parse(unb64uText(p[0])); } catch (e) { header = null; }
      if (header && known(header.alg)) { algo = header.alg; algoSel.value = algo; applyAlgo(); updateSel(); }
      var payObj; try { payObj = JSON.parse(unb64uText(p[1])); } catch (e) { }
      var out = 'Header:\n' + part(p[0]) + '\n\nPayload:\n' + part(p[1]);
      if (p[2]) out += '\n\nSignature (Base64 URL):\n' + p[2];
      // Human-readable timestamps, if present
      try {
        var pay = JSON.parse(unb64uText(p[1])), notes = [];
        ['iat', 'nbf', 'exp'].forEach(function (k) { if (typeof pay[k] === 'number') notes.push(k + ': ' + new Date(pay[k] * 1000).toISOString() + (k === 'exp' && pay[k] * 1000 < Date.now() ? ' (expired)' : '')); });
        if (notes.length) out += '\n\nTimestamps:\n' + notes.join('\n');
      } catch (e) { }
      // Keep the parsed parts so Swap can hand back clean, signable JSON instead of this text
      lastDecoded = header && typeof header === 'object' && payObj !== undefined ? { text: out, doc: pretty(header, payObj) } : null;
      outP.ta.value = out; clearVerify(); ctx.toast('Decoded', 'success');
    }
    var lastDecoded = null;
    // Output to input: a decoded view becomes { header, payload } JSON ready to Sign; a token moves as-is
    function doSwap() {
      var v = outP.ta.value;
      if (!v.trim()) { ctx.toast('Output is empty', 'warn'); return; }
      inP.ta.value = lastDecoded && lastDecoded.text === v ? lastDecoded.doc : v.trim();
      outP.ta.value = ''; lastDecoded = null; clearVerify();
    }
    function setAlgo(a) { algo = a; algoSel.value = a; applyAlgo(); updateSel(); }
    function pretty(header, payload) { return JSON.stringify({ header: header, payload: payload }, null, 2); }

    // Load a token's header + payload into the input as editable JSON
    function doEdit() {
      var t = inP.ta.value.trim();
      if (!t) { doNew(); return; }
      var parsed = null;
      try { parsed = JSON.parse(t); } catch (e) { }
      if (parsed !== null) {
        if (isEditDoc(parsed)) { ctx.toast('Already editable: change it, then Sign', 'warn'); return; }
        // Plain claims JSON: wrap it with a default header
        inP.ta.value = pretty({ alg: algo, typ: 'JWT' }, parsed); clearVerify();
        ctx.toast('Ready to edit: change header or payload, then Sign', 'success'); return;
      }
      var p = t.split('.'), header, payload;
      if (p.length < 2) { ctx.toast('Not a valid JWT (expected header.payload.signature)', 'error'); return; }
      try { header = JSON.parse(unb64uText(p[0])); } catch (e) { ctx.toast('Cannot read the token header', 'error'); return; }
      try { payload = JSON.parse(unb64uText(p[1])); } catch (e) { ctx.toast('Payload is not JSON, so it cannot be edited', 'error'); return; }
      if (!header || typeof header !== 'object' || Array.isArray(header)) { ctx.toast('Token header is not a JSON object', 'error'); return; }
      if (known(header.alg)) setAlgo(header.alg);
      inP.ta.value = pretty(header, payload); clearVerify();
      ctx.toast('Ready to edit: change header or payload, then Sign', 'success');
    }
    // Start a new token from a template
    function doNew() {
      var now = Math.floor(Date.now() / 1000);
      inP.ta.value = pretty({ alg: algo, typ: 'JWT' }, { sub: '1234567890', name: 'John Doe', iat: now, exp: now + 3600 });
      clearVerify(); ctx.toast('New token template: edit it, then Sign', 'success');
    }

    function doSign() {
      var claims = inP.ta.value.trim();
      if (!claims) { ctx.toast('Enter a claims JSON to sign', 'warn'); return; }
      var parsed;
      try { parsed = JSON.parse(claims); } catch (e) { ctx.toast('Input must be valid JSON (use Edit to load a token)', 'error'); return; }
      var header, payloadObj;
      if (isEditDoc(parsed)) {
        // Keep the user's header fields; alg in the header wins over the dropdown
        var a = parsed.header.alg;
        if (a === undefined) header = Object.assign({ alg: algo }, parsed.header);
        else if (known(a)) { header = parsed.header; if (a !== algo) setAlgo(a); }
        else { ctx.toast('Unsupported alg "' + a + '" (use HS256, HS384, HS512, RS256, ES256, ES384, EdDSA or none)', 'error'); return; }
        payloadObj = parsed.payload;
      } else {
        header = { alg: algo, typ: 'JWT' }; payloadObj = parsed;
      }
      var signingInput = b64uStr(JSON.stringify(header)) + '.' + b64uStr(JSON.stringify(payloadObj));
      if (header.alg === 'none') { outP.ta.value = signingInput + '.'; clearVerify(); ctx.toast('Unsigned token (alg none)', 'warn'); return; }
      return sign(header.alg, signingInput, keyState()).then(function (sig) {
        outP.ta.value = signingInput + '.' + sig; clearVerify(); ctx.toast('Signed with ' + header.alg, 'success');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    /* Verify, flashing both panels like the other tools.
       Input holds a JWT: check its signature.
       Input holds claims / { header, payload } JSON and the output a JWT: check
       the output's signature and that it carries exactly the input's contents. */
    function doVerify() {
      clearVerify();
      var inV = inP.ta.value.trim(), parsed = null;
      try { parsed = JSON.parse(inV); } catch (e) { }
      var fromOutput = parsed !== null && typeof parsed === 'object';
      var t = fromOutput ? outP.ta.value.trim() : inV, p = t.split('.');
      if (p.length !== 3) { ctx.toast(fromOutput ? 'Sign first: the output needs the token to check' : 'Put a full JWT (with signature) in the input', 'warn'); return; }
      var header, payload;
      try { header = JSON.parse(unb64uText(p[0])); } catch (e) { ctx.toast('Cannot read the token header', 'error'); return; }
      if (header && header.alg === 'none') { CK.flashVerify(false, inP.ta, outP.ta); ctx.toast('Token is unsigned (alg none)', 'error'); return; }
      if (!p[2]) { ctx.toast('Token has no signature', 'warn'); return; }
      var same = true;
      if (fromOutput) {
        try { payload = JSON.parse(unb64uText(p[1])); } catch (e) { payload = undefined; }
        if (isEditDoc(parsed)) {
          var want = parsed.header.alg === undefined ? Object.assign({ alg: header.alg }, parsed.header) : parsed.header;
          same = sameJson(want, header) && sameJson(parsed.payload, payload);
        } else same = sameJson(parsed, payload);
      }
      var a = (header && (HASH[header.alg] || ASYM[header.alg])) ? header.alg : algo;
      verify(a, p[0] + '.' + p[1], p[2], keyState()).then(function (ok) {
        var match = ok && same;
        CK.flashVerify(match, inP.ta, outP.ta);
        ctx.toast(match ? (fromOutput ? 'Match: output is a valid ' + a + ' token of the input' : 'Signature valid (' + a + ')') :
          !ok ? 'Signature does not match' : 'Signature valid, but the token does not match the input', match ? 'success' : 'error');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doGenerate() {
      ctx.toast('Generating ' + algo + ' keypair...', 'success');
      crypto.subtle.generateKey(ASYM[algo].gen || ASYM[algo].key, true, ['sign', 'verify'])
        .then(function (kp) { return Promise.all([crypto.subtle.exportKey('spki', kp.publicKey), crypto.subtle.exportKey('pkcs8', kp.privateKey)]); })
        .then(function (k) { pub.input.value = pem('PUBLIC KEY', k[0]); priv.input.value = pem('PRIVATE KEY', k[1]); ctx.toast('Keypair generated', 'success'); })
        .catch(function (e) { ctx.toast('Key generation failed: ' + e.message, 'error'); });
    }
    function doShare() { CK.share('jwt', { a: algo, sf: secretFmt.value, sec: secretInput.value, in: inP.ta.value }, { sec: 'secret' }); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; secretInput.value = ''; secretFmt.value = 'utf8'; pub.input.value = ''; priv.input.value = ''; algo = 'HS256'; algoSel.value = 'HS256'; applyAlgo(); updateSel(); clearVerify(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); algo = st.a || 'HS256'; algoSel.value = algo; secretFmt.value = st.sf || 'utf8'; secretInput.value = st.sec || ''; inP.ta.value = st.in || ''; } catch (e) { } }
    applyAlgo(); updateSel();
  });
})();
