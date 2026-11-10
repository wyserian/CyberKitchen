/*
   kdf.js - Key Derivation (PBKDF2 / scrypt / HKDF)
   Turn a password + salt into a derived key. PBKDF2 uses Web Crypto
   (SHA-1/256/384/512). scrypt (RFC 7914) and HKDF (RFC 5869) use noble-hashes;
   HKDF is extract-and-expand with an optional salt and info.
   Fully offline.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec, toHex = CK.toHex, rndBytes = CK.rndBytes, b64 = CK.b64;
  var ENC = new TextEncoder();
  function inputBytes(v, fmt) { return CK.textBytes(v || '', fmt); }

  function pbkdf2Web(passBytes, saltBytes, iterations, hash, dkLen) {
    return crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits'])
      .then(function (k) { return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: hash }, k, dkLen * 8); })
      .then(function (buf) { return new Uint8Array(buf); });
  }

  var I_LOCK = '<path d="M6 10V7a6 6 0 0 1 12 0v3M5 10h14v10H5z"/>';
  var ITERS = [100000, 310000, 600000];

  CK.registerTool('kdf', function (root, ctx) {
    var ui = CK.ui, el = CK.el, algo = 'pbkdf2';

    root.appendChild(ui.head('Key Derivation'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(CK.ui.IC.key);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'bc-left' });
    var colR = el('div', { class: 'col' });

    // Parameters column (left): Algorithm, then Hash (PBKDF2) or scrypt params below it
    var paramsWrap = el('div', { class: 'col' });
    var algoSel = ui.select([['pbkdf2', 'PBKDF2'], ['scrypt', 'scrypt'], ['hkdf', 'HKDF']], function (v) { algo = v; applyAlgo(); updateSel(); }, 'pbkdf2');
    paramsWrap.appendChild(ui.field('Algorithm', algoSel));

    // Hash (PBKDF2) directly below Algorithm
    var hashSel = ui.select([['SHA-256', 'SHA-256'], ['SHA-512', 'SHA-512'], ['SHA-384', 'SHA-384'], ['SHA-1', 'SHA-1']], function () { updateSel(); }, 'SHA-256');
    var hashField = ui.field('Hash', hashSel);
    paramsWrap.appendChild(hashField);

    // scrypt params (shown below Algorithm in place of Hash)
    var scWrap = el('div', { class: 'col' }); scWrap.style.display = 'none';
    var scRow = el('div', { style: 'display:flex; gap:8px; align-items:flex-end; flex-wrap:wrap;' });
    var nSel = ui.select([['14', '16384 (2^14)'], ['15', '32768 (2^15)'], ['16', '65536 (2^16)'], ['12', '4096 (2^12)'], ['10', '1024 (2^10)']], function () { updateSel(); }, '14'); nSel.style.width = 'auto';
    var rInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '32', value: '8' }); rInput.style.width = '64px';
    var pInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '16', value: '1' }); pInput.style.width = '64px';
    rInput.addEventListener('input', updateSel); pInput.addEventListener('input', updateSel);
    scRow.appendChild(ui.field('Cost (N)', nSel)); scRow.appendChild(ui.field('Block (r)', rInput)); scRow.appendChild(ui.field('Parallel (p)', pInput));
    scWrap.appendChild(scRow);
    paramsWrap.appendChild(scWrap);

    // Salt column (right): Salt, then Iterations (PBKDF2) below it
    var saltWrap = el('div', { class: 'col' });
    var saltInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Salt' });
    var saltFmt = ui.select([['base64', 'Base64'], ['hex', 'Hexadecimal'], ['utf8', 'UTF-8']], null, 'base64');
    var saltGen = ui.iconBtn(CK.ui.IC.shuffle, 'Random', function () { saltInput.value = saltFmt.value === 'hex' ? toHex(rndBytes(16)) : saltFmt.value === 'utf8' ? toHex(rndBytes(16)) : b64(rndBytes(16)); if (saltFmt.value === 'utf8') saltFmt.value = 'hex'; });
    var saltRow = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    saltInput.style.flex = '1'; saltInput.style.minWidth = '0'; saltFmt.style.width = 'auto';
    saltRow.appendChild(saltInput); saltRow.appendChild(saltFmt); saltRow.appendChild(saltGen);
    saltWrap.appendChild(ui.field('Salt', saltRow));

    // Iterations (PBKDF2) directly below Salt
    var iters = 310000;
    var iterBtns = {}, iterRow = el('div', { style: 'display:flex; gap:5px; align-items:center; flex-wrap:wrap;' });
    ITERS.forEach(function (v) { var b = el('button', { class: 'eb' }); b.textContent = (v / 1000) + 'k'; b.addEventListener('click', function () { iters = v; iterCustom.value = ''; markIters(); updateSel(); }); iterBtns[v] = b; iterRow.appendChild(b); });
    var iterCustom = el('input', { class: 'inp sm', type: 'number', min: '1', placeholder: 'Custom' }); iterCustom.style.width = '90px';
    iterCustom.addEventListener('input', function () { if (iterCustom.value !== '') { var n = +iterCustom.value; if (n >= 1) iters = n; } markIters(); updateSel(); });
    iterRow.appendChild(iterCustom);
    var iterField = ui.field('Iterations', iterRow);
    saltWrap.appendChild(iterField);

    // HKDF context string, in place of Iterations
    var infoInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Optional context, e.g. app name and purpose' });
    infoInput.addEventListener('input', updateSel);
    var infoField = ui.field('Info (UTF-8)', infoInput); infoField.style.display = 'none';
    saltWrap.appendChild(infoField);

    colL.appendChild(paramsWrap); colL.appendChild(saltWrap);

    var lenInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '1024', value: '32' }); lenInput.style.width = '90px';
    lenInput.addEventListener('input', updateSel);
    colR.appendChild(ui.field('Output length (bytes)', lenInput));
    var outFmt = ui.select([['hex', 'Hexadecimal'], ['base64', 'Base64']], null, 'hex');
    colR.appendChild(ui.field('Output format', outFmt));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: CK.ui.IC.key, placeholder: 'Password to derive a key from...', primaries: [{ label: 'Derive', cls: 'enc', onClick: doDerive }], actions: ['copy', 'paste', 'clear'] });
    var outP = ui.textPanel({ title: 'DERIVED KEY', icon: I_LOCK, placeholder: 'Derived key appears here...', readonly: true, actions: ['copy', 'download'], downloadName: 'derived-key.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);
    CK.attachStrength(inP);

    function clearVerify() { inP.ta.classList.remove('verify-match', 'verify-fail'); outP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearVerify);
    outP.ta.addEventListener('input', clearVerify);

    function markIters() { ITERS.forEach(function (v) { iterBtns[v].classList.toggle('active', iters === v && iterCustom.value === ''); }); }
    function applyAlgo() { var sc = algo === 'scrypt', hk = algo === 'hkdf'; hashField.style.display = sc ? 'none' : ''; iterField.style.display = sc || hk ? 'none' : ''; scWrap.style.display = sc ? '' : 'none'; infoField.style.display = hk ? '' : 'none'; }
    function updateSel() {
      if (algo === 'scrypt') { var N = Math.pow(2, +nSel.value); ui.setSel(strip, 'scrypt', 'RFC7914', 'scrypt · N=' + N.toLocaleString() + ' r=' + (+rInput.value || 8) + ' p=' + (+pInput.value || 1) + ' · ' + (+lenInput.value || 32) + '-byte key · memory-hard'); }
      else if (algo === 'hkdf') ui.setSel(strip, 'HKDF · ' + hashSel.value, 'RFC 5869', 'HMAC-' + hashSel.value + ' extract-and-expand · ' + (+lenInput.value || 32) + '-byte key. For high-entropy input keys, not passwords.');
      else ui.setSel(strip, 'PBKDF2 · ' + hashSel.value, 'PBKDF2', 'PBKDF2-HMAC-' + hashSel.value + ' · ' + iters.toLocaleString() + ' iterations · ' + (+lenInput.value || 32) + '-byte key'); }

    function saltBytes() { return inputBytes(saltInput.value, saltFmt.value); }
    function dkLen() { return Math.max(1, Math.min(1024, +lenInput.value || 32)); }
    function fmtOut(b) { return outFmt.value === 'base64' ? b64(b) : toHex(b); }

    // returns Promise<Uint8Array>
    function derive() {
      var pw = inP.ta.value;
      if (!pw) return Promise.reject(new Error('Password is empty'));
      var salt; try { salt = saltBytes(); } catch (e) { return Promise.reject(e); }
      if (algo === 'hkdf') {
        var H = { 'SHA-1': Noble.sha1, 'SHA-256': Noble.sha256, 'SHA-384': Noble.sha384, 'SHA-512': Noble.sha512 }[hashSel.value];
        if (dkLen() > 255 * H.outputLen) return Promise.reject(new Error('HKDF output is at most ' + 255 * H.outputLen + ' bytes for ' + hashSel.value));
        return Promise.resolve(Noble.hkdf(H, ENC.encode(pw), salt.length ? salt : undefined, ENC.encode(infoInput.value), dkLen()));
      }
      if (!salt.length) return Promise.reject(new Error('Salt is required'));
      if (algo === 'scrypt') {
        var N = Math.pow(2, +nSel.value), r = Math.max(1, +rInput.value || 8), p = Math.max(1, +pInput.value || 1);
        return new Promise(function (resolve, reject) {
          setTimeout(function () { try { resolve(Noble.scrypt(ENC.encode(pw), salt, { N: N, r: r, p: p, dkLen: dkLen() })); } catch (e) { reject(e); } }, 10);
        });
      }
      return pbkdf2Web(ENC.encode(pw), salt, iters, hashSel.value, dkLen());
    }
    function doDerive() {
      var t0 = performance.now();
      return derive().then(function (b) { outP.ta.value = fmtOut(b); clearVerify(); ctx.toast('Derived in ' + Math.round(performance.now() - t0) + ' ms', 'success'); })
        .catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doVerify() {
      clearVerify();
      var want = outP.ta.value.trim();
      if (!want) { ctx.toast('Put a derived key in the output to verify', 'warn'); return; }
      return derive().then(function (b) {
        var got = fmtOut(b), match = got.toLowerCase() === want.toLowerCase() || toHex(b) === want.toLowerCase() || b64(b) === want;
        CK.flashVerify(match, inP.ta, outP.ta);
        ctx.toast(match ? 'Match: the key derives from this password' : 'No match', match ? 'success' : 'error');
      }).catch(function (e) { ctx.toast(e.message, 'error'); });
    }
    function doShare() { CK.share('kdf', { a: algo, it: iters, h: hashSel.value, N: nSel.value, r: rInput.value, p: pInput.value, sf: saltFmt.value, salt: saltInput.value, dk: lenInput.value, of: outFmt.value, inf: infoInput.value }); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; algo = 'pbkdf2'; algoSel.value = 'pbkdf2'; iters = 310000; iterCustom.value = ''; hashSel.value = 'SHA-256'; nSel.value = '14'; rInput.value = '8'; pInput.value = '1'; saltInput.value = ''; infoInput.value = ''; saltFmt.value = 'base64'; lenInput.value = '32'; outFmt.value = 'hex'; applyAlgo(); markIters(); updateSel(); clearVerify(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); algo = st.a || 'pbkdf2'; algoSel.value = algo; iters = st.it || 310000; if (ITERS.indexOf(iters) < 0) iterCustom.value = iters; hashSel.value = st.h || 'SHA-256'; nSel.value = st.N || '14'; rInput.value = st.r || '8'; pInput.value = st.p || '1'; saltFmt.value = st.sf || 'base64'; saltInput.value = st.salt || ''; lenInput.value = st.dk || '32'; infoInput.value = st.inf || ''; outFmt.value = st.of || 'hex'; } catch (e) { } }
    if (!saltInput.value) saltInput.value = b64(rndBytes(16));
    applyAlgo(); markIters(); updateSel();
  });
})();
