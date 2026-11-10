/*
   bcrypt.js - Bcrypt hash / verify (vendored bcryptjs). Offline.
   Cost presets + custom, auto or custom salt (with random generator),
   Full-hash / Hash-only / JSON output. Verify / Detect / Swap / Share / Reset.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec;
  function lib() { if (typeof bcrypt !== 'undefined') return bcrypt; if (typeof dcodeIO !== 'undefined' && dcodeIO.bcrypt) return dcodeIO.bcrypt; return null; }
  function parseBcrypt(h) { var m = /^\$(2[abxy]?)\$(\d{2})\$([./A-Za-z0-9]{53})$/.exec(h); if (!m) return null; return { version: m[1], cost: parseInt(m[2], 10), salt: m[3].slice(0, 22), hashPart: m[3].slice(22) }; }
  // Per-cost guidance and rough in-browser timing (carried over from the standalone bcrypt tool)
  function costGuide(n) {
    var ms = 20 * Math.pow(2, n - 8);
    var time = ms < 1000 ? Math.round(ms) + ' ms' : (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + ' s';
    var desc = n <= 8 ? 'very fast, for development and testing only'
      : n <= 10 ? 'fast, a sensible minimum for production'
      : n === 11 ? 'a good balance of speed and security'
      : n === 12 ? 'recommended for most production apps'
      : n === 13 ? 'slow, for high-security contexts'
      : n === 14 ? 'very slow, use with caution in the browser'
      : 'extremely slow, for specialized use only';
    return { time: '~' + time, desc: desc };
  }

  var I_FISH = '<path d="M6.5 12c3-5 8-5 11 0-3 5-8 5-11 0zM15 11.5v.01"/>';
  var COSTS = [8, 10, 12, 14, 16];

  CK.registerTool('bcrypt', function (root, ctx) {
    var ui = CK.ui, el = CK.el, cost = 10;

    root.appendChild(ui.head('Bcrypt'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_FISH);
    strip.desc.style.whiteSpace = 'normal'; // let the full cost guidance wrap instead of truncating
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.detect, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.swap, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left column split: cost | custom salt. Right column: output.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'bc-left' });
    var colR = el('div', { class: 'col' });

    // Cost: 5 presets + custom input, all on one line
    var costBtns = {}, costRow = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    COSTS.forEach(function (v) {
      var b = el('button', { class: 'eb' }); b.textContent = v;
      b.addEventListener('click', function () { cost = v; custInput.value = ''; markCost(); updateSel(); });
      costBtns[v] = b; costRow.appendChild(b);
    });
    var custInput = el('input', { class: 'inp sm', type: 'number', min: '4', max: '31', placeholder: 'Custom' });
    custInput.style.width = '84px';
    custInput.addEventListener('input', function () { if (custInput.value !== '') { var n = +custInput.value; if (n >= 4 && n <= 31) cost = n; } markCost(); updateSel(); });
    costRow.appendChild(custInput);
    var costWrap = el('div'); costWrap.appendChild(ui.field('Cost (rounds)', costRow));

    // Custom salt (switch + salt input with random generator)
    var saltWrap = el('div', { class: 'col' });
    var saltCb = el('input', { type: 'checkbox' });
    var saltSwitch = el('label', { class: 'switch' });
    saltSwitch.appendChild(saltCb); saltSwitch.appendChild(el('span', { class: 'track' })); saltSwitch.appendChild(el('span', {}, 'Custom salt'));
    saltWrap.appendChild(saltSwitch);
    var saltInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: '$2a$10$22-char-salt' });
    var saltGen = ui.iconBtn(CK.ui.IC.shuffle, 'Random', function () { var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; } saltInput.value = b.genSaltSync(cost); });
    var saltRow = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    saltInput.style.flex = '1'; saltInput.style.minWidth = '0'; saltRow.appendChild(saltInput); saltRow.appendChild(saltGen);
    var saltField = ui.field('Salt', saltRow); saltField.style.display = 'none';
    saltWrap.appendChild(saltField);
    saltCb.addEventListener('change', function () { saltField.style.display = saltCb.checked ? '' : 'none'; });

    colL.appendChild(costWrap); colL.appendChild(saltWrap);

    var outSel = ui.select([['full', 'Full hash'], ['hashonly', 'Hash only'], ['json', 'JSON']], null, 'full');
    colR.appendChild(ui.field('Output', outSel));

    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: I_FISH, placeholder: 'Password to hash...', primaries: [{ label: 'Hash', cls: 'enc', onClick: doHash }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'password.txt' });
    var outP = ui.textPanel({ title: 'BCRYPT HASH', icon: CK.ui.IC.hash, placeholder: 'Hash output, or paste a $2 hash to verify...', primaries: [{ label: 'Inspect', cls: 'dec', onClick: doInspect }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'bcrypt.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);
    CK.attachStrength(inP);

    function clearV() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearV);
    outP.ta.addEventListener('input', clearV);
    function markCost() { COSTS.forEach(function (v) { costBtns[v].classList.toggle('active', cost === v && custInput.value === ''); }); }
    function updateSel() { var g = costGuide(cost); ui.setSel(strip, 'bcrypt cost ' + cost, '2^' + cost, 'Blowfish-based hashing · ' + Math.pow(2, cost).toLocaleString() + ' iterations · ' + g.desc + ' · ' + g.time); }
    function formatOut(hash) {
      if (outSel.value === 'hashonly') return hash.slice(-31);
      if (outSel.value === 'json') { var p = parseBcrypt(hash) || {}; return JSON.stringify({ algorithm: 'bcrypt', version: '$' + (p.version || ''), cost: p.cost, salt: p.salt, hash: p.hashPart, full: hash }, null, 2); }
      return hash;
    }

    function doHash() {
      var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
      var pw = inP.ta.value; if (!pw) { ctx.toast('Password is empty', 'warn'); return; }
      var t0 = performance.now();
      function done(err, hash) {
        if (err) { ctx.toast('Hash failed: ' + err.message, 'error'); return; }
        outP.ta.value = formatOut(hash); clearV();
        ctx.toast('Hashed in ' + Math.round(performance.now() - t0) + ' ms', 'success');
      }
      if (saltCb.checked) {
        var salt = saltInput.value.trim();
        if (!/^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{22}/.test(salt)) { ctx.toast('Custom salt must look like $2a$10$ + 22 chars', 'error'); return; }
        try { done(null, b.hashSync(pw, salt)); } catch (e) { done(e); }
        return;
      }
      return new Promise(function (resolve) { b.hash(pw, cost, function (err, hash) { done(err, hash); resolve(); }); });
    }
    function doVerify() {
      var b = lib(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
      var pw = inP.ta.value, hash = outP.ta.value.trim();
      if (!pw) { ctx.toast('Enter the password on the left', 'warn'); return; }
      if (!/^\$2[abxy]?\$/.test(hash)) { ctx.toast('Output is not a full bcrypt hash', 'error'); return; }
      b.compare(pw, hash, function (err, ok) { if (err) { ctx.toast('Verify failed: ' + err.message, 'error'); return; } clearV(); CK.flashVerify(ok, inP.ta, outP.ta); ctx.toast(ok ? 'Match: password is correct' : 'No match', ok ? 'success' : 'error'); });
    }
    function doDetect() {
      var p = parseBcrypt(outP.ta.value.trim());
      if (!p) { ctx.toast('Output is not a bcrypt hash', 'warn'); return; }
      cost = p.cost; if (COSTS.indexOf(cost) < 0) { custInput.value = cost; } else { custInput.value = ''; }
      markCost(); updateSel();
      ctx.toast('Detected bcrypt $' + p.version + ', cost ' + p.cost, 'success');
    }
    function doInspect() {
      var h = outP.ta.value.trim();
      if (!h) { ctx.toast('No hash in the output panel', 'warn'); return; }
      var p = parseBcrypt(h);
      if (!p) { ctx.toast('Output is not a valid bcrypt hash', 'error'); return; }
      outP.ta.value = [
        'Algorithm:  bcrypt',
        'Version:    $' + p.version,
        'Cost:       ' + p.cost + ' (2^' + p.cost + ' = ' + Math.pow(2, p.cost).toLocaleString() + ' iterations)',
        'Salt:       ' + p.salt,
        'Hash part:  ' + p.hashPart,
        'Full hash:  ' + h,
        'Total len:  ' + h.length + ' chars'
      ].join('\n');
      clearV(); ctx.toast('Hash inspected', 'success');
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearV(); ctx.toast('Output moved to input', 'success'); }
    function doShare() { var st = { c: cost, out: outSel.value, cs: saltCb.checked ? 1 : 0, salt: saltInput.value, pw: inP.ta.value, h: outP.ta.value }; CK.share('bcrypt', st, { pw: 'password' }); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; cost = 10; custInput.value = ''; outSel.value = 'full'; saltCb.checked = false; saltInput.value = ''; saltField.style.display = 'none'; clearV(); markCost(); updateSel(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); cost = st.c || 10; if (COSTS.indexOf(cost) < 0) custInput.value = cost; outSel.value = st.out || 'full'; saltCb.checked = !!st.cs; saltField.style.display = saltCb.checked ? '' : 'none'; saltInput.value = st.salt || ''; inP.ta.value = st.pw || ''; outP.ta.value = st.h || ''; } catch (e) { } }
    markCost(); updateSel();
  });
})();
