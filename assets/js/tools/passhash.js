/*
   passhash.js - Password Hashing
   bcrypt (vendored bcryptjs) and Argon2id / Argon2i / Argon2d (vendored argon2-browser, WASM inlined)
   in one tool. Cost settings per algorithm, auto or custom salt with a random generator,
   Encoded / Hash only / JSON output. Verify, Detect and Inspect read the algorithm from the
   pasted hash ($2... or $argon2...).
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec;
  function bc() { if (typeof bcrypt !== 'undefined') return bcrypt; if (typeof dcodeIO !== 'undefined' && dcodeIO.bcrypt) return dcodeIO.bcrypt; return null; }
  function parseBcrypt(h) { var m = /^\$(2[abxy]?)\$(\d{2})\$([./A-Za-z0-9]{53})$/.exec(h); if (!m) return null; return { version: m[1], cost: parseInt(m[2], 10), salt: m[3].slice(0, 22), hashPart: m[3].slice(22) }; }
  function parseArgon2(h) { var m = /^\$argon2([a-z]+)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$(.+)$/.exec(h); if (!m) return null; return { variant: m[1], version: +m[2], mem: +m[3], time: +m[4], par: +m[5], salt: m[6], hash: m[7] }; }

  var ALGS = {
    argon2id: { label: 'Argon2id', badge: 'RFC 9106', desc: 'hybrid of d and i, the recommended default' },
    argon2i: { label: 'Argon2i', badge: 'Timing safe', desc: 'data-independent, timing-safe' },
    argon2d: { label: 'Argon2d', badge: 'GPU hardened', desc: 'data-dependent, maximizes GPU resistance' },
    bcrypt: { label: 'bcrypt', badge: 'Blowfish', desc: 'Blowfish-based, 72-byte password limit' }
  };
  // Rough in-browser timing guidance
  function bcryptGuide(n) {
    var ms = 20 * Math.pow(2, n - 8), time = ms < 1000 ? Math.round(ms) + ' ms' : (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + ' s';
    var desc = n <= 8 ? 'development and testing only' : n <= 10 ? 'a sensible production minimum' : n === 11 ? 'a good balance' : n === 12 ? 'recommended for most apps' : n === 13 ? 'high-security' : n === 14 ? 'very slow in a browser' : 'extremely slow';
    return '~' + time + ', ' + desc;
  }
  function argonGuide(memKiB, t) {
    var score = (memKiB / 1024) * t;
    return score <= 8 ? 'under 100 ms' : score <= 32 ? '~100 to 300 ms' : score <= 128 ? '~300 ms to 1 s' : score <= 512 ? '~1 to 3 s' : '3 s or more';
  }

  var I_PW = '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M8 12h.01M12 12h.01M16 12h.01"/>';
  var COSTS = [8, 10, 12, 14, 16];
  var MEMS = [[1024, '1 MB'], [4096, '4 MB'], [16384, '16 MB'], [65536, '64 MB']];
  var TIMES = [1, 2, 3, 4, 5];

  CK.registerTool('passhash', function (root, ctx) {
    var ui = CK.ui, el = CK.el, algo = 'argon2id', cost = 10;

    root.appendChild(ui.head('Password Hashing'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_PW);
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.detect, 'Detect', doDetect));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.swap, 'Swap', doSwap));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    // Left column split into 4 sub-columns: Algorithm | cost settings | Parallelism + Output length | custom salt. Right column: output.
    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'argon-left' });
    var algoWrap = el('div', { class: 'col' }), costWrap = el('div', { class: 'col' }), parWrap = el('div', { class: 'col' }), saltWrap = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });

    var algoSel = ui.select(Object.keys(ALGS).map(function (k) { return [k, ALGS[k].label]; }), function (v) { setAlgo(v); }, algo);
    algoWrap.appendChild(ui.field('Algorithm', algoSel));

    // Preset buttons + a custom number input on one line
    function presets(list, input, onPick) {
      var row = el('div', { style: 'display:flex; gap:5px; align-items:center; flex-wrap:wrap;' }), btns = {};
      list.forEach(function (a) { var b = el('button', { class: 'eb' }); b.textContent = a[1]; b.addEventListener('click', function () { onPick(a[0]); updateSel(); }); btns[a[0]] = b; row.appendChild(b); });
      row.appendChild(input);
      return { row: row, mark: function (v) { list.forEach(function (a) { btns[a[0]].classList.toggle('active', v === a[0]); }); } };
    }
    // bcrypt cost factor: 2^n rounds
    var costInput = el('input', { class: 'inp sm', type: 'number', min: '4', max: '31', placeholder: 'Custom' });
    costInput.addEventListener('input', function () { var n = +costInput.value; if (costInput.value !== '' && n >= 4 && n <= 31) cost = n; updateSel(); });
    var costP = presets(COSTS.map(function (c) { return [c, String(c)]; }), costInput, function (v) { cost = v; costInput.value = ''; });
    var costField = ui.field('Cost factor', costP.row);
    // Argon2 memory and iterations
    var memInput = el('input', { class: 'inp sm', type: 'number', min: '256', max: '1048576', step: '256', value: '4096', placeholder: 'KiB' });
    var timeInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '20', value: '3' });
    memInput.addEventListener('input', updateSel); timeInput.addEventListener('input', updateSel);
    var memP = presets(MEMS, memInput, function (v) { memInput.value = v; });
    var timeP = presets(TIMES.map(function (t) { return [t, String(t)]; }), timeInput, function (v) { timeInput.value = v; });
    var memField = ui.field('Memory cost', memP.row), timeField = ui.field('Iterations', timeP.row);
    costWrap.appendChild(costField); costWrap.appendChild(memField); costWrap.appendChild(timeField);
    var parInput = el('input', { class: 'inp sm', type: 'number', min: '1', max: '16', value: '1' });
    var lenInput = el('input', { class: 'inp sm', type: 'number', min: '16', max: '64', value: '32' });
    parWrap.appendChild(ui.field('Parallelism', parInput)); parWrap.appendChild(ui.field('Output length (bytes)', lenInput));

    var saltCb = el('input', { type: 'checkbox' });
    var saltSwitch = el('label', { class: 'switch' });
    saltSwitch.appendChild(saltCb); saltSwitch.appendChild(el('span', { class: 'track' })); saltSwitch.appendChild(el('span', {}, 'Custom salt'));
    saltWrap.appendChild(saltSwitch);
    var saltInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off' });
    var saltRow = el('div', { style: 'display:flex; gap:5px; align-items:center; overflow:hidden;' });
    saltInput.style.flex = '1'; saltInput.style.minWidth = '0'; saltRow.appendChild(saltInput); saltRow.appendChild(ui.iconBtn(CK.ui.IC.shuffle, 'Random', randomSalt));
    var saltField = ui.field('Salt', saltRow); saltField.style.display = 'none';
    saltWrap.appendChild(saltField);
    saltCb.addEventListener('change', function () { saltField.style.display = saltCb.checked ? '' : 'none'; });

    colL.appendChild(algoWrap); colL.appendChild(costWrap); colL.appendChild(parWrap); colL.appendChild(saltWrap);
    var outSel = ui.select([['full', 'Encoded hash'], ['hashonly', 'Hash only'], ['json', 'JSON']], null, 'full');
    colR.appendChild(ui.field('Output', outSel));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'PASSWORD', icon: I_PW, placeholder: 'Password to hash...', primaries: [{ label: 'Hash', cls: 'enc', onClick: doHash }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'password.txt' });
    var outP = ui.textPanel({ title: 'HASH', icon: CK.ui.IC.hash, placeholder: 'Encoded hash, or paste a $2 / $argon2 hash to verify...', primaries: [{ label: 'Inspect', cls: 'dec', onClick: doInspect }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'password-hash.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);
    CK.attachStrength(inP);

    function clearV() { outP.ta.classList.remove('verify-match', 'verify-fail'); inP.ta.classList.remove('verify-match', 'verify-fail'); }
    inP.ta.addEventListener('input', clearV);
    outP.ta.addEventListener('input', clearV);

    function isBc() { return algo === 'bcrypt'; }
    function setAlgo(a) {
      algo = ALGS[a] ? a : 'argon2id'; algoSel.value = algo;
      costField.style.display = isBc() ? '' : 'none';
      memField.style.display = timeField.style.display = isBc() ? 'none' : '';
      parWrap.style.visibility = isBc() ? 'hidden' : '';
      saltInput.placeholder = isBc() ? '$2a$10$ + 22-character salt' : 'Salt (at least 8 characters)';
      updateSel();
    }
    function mem() { return Math.max(256, +memInput.value || 4096); }
    function iters() { return Math.max(1, +timeInput.value || 3); }
    function updateSel() {
      var a = ALGS[algo];
      costP.mark(costInput.value === '' ? cost : null); memP.mark(+memInput.value); timeP.mark(+timeInput.value);
      if (isBc()) { ui.setSel(strip, 'bcrypt · cost ' + cost, '2^' + cost, a.desc + ' · ' + Math.pow(2, cost).toLocaleString() + ' rounds · ' + bcryptGuide(cost)); return; }
      var m = mem(), ms = m >= 1024 ? (m / 1024 % 1 === 0 ? m / 1024 : (m / 1024).toFixed(1)) + ' MB' : m + ' KiB';
      ui.setSel(strip, a.label, a.badge, a.desc + ' · ' + ms + ' × ' + iters() + ' iterations · estimated ' + argonGuide(m, iters()));
    }
    function randomSalt() {
      if (isBc()) { var b = bc(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; } saltInput.value = b.genSaltSync(cost); return; }
      saltInput.value = CK.b64(CK.rndBytes(16)).replace(/=+$/, '');
    }
    function formatOut(enc) {
      var bcHash = /^\$2/.test(enc);
      if (outSel.value === 'hashonly') return bcHash ? enc.slice(-31) : enc.split('$').pop();
      if (outSel.value !== 'json') return enc;
      if (bcHash) { var b = parseBcrypt(enc) || {}; return JSON.stringify({ algorithm: 'bcrypt', version: '$' + (b.version || ''), cost: b.cost, salt: b.salt, hash: b.hashPart, encoded: enc }, null, 2); }
      var p = parseArgon2(enc) || {};
      return JSON.stringify({ algorithm: 'argon2' + p.variant, version: p.version, memoryKiB: p.mem, iterations: p.time, parallelism: p.par, salt: p.salt, hash: p.hash, encoded: enc }, null, 2);
    }

    function doHash() {
      var pw = inP.ta.value; if (!pw) { ctx.toast('Password is empty', 'warn'); return; }
      var t0 = performance.now();
      function done(enc) { outP.ta.value = formatOut(enc); clearV(); ctx.toast('Hashed in ' + Math.round(performance.now() - t0) + ' ms', 'success'); }
      function fail(e) { ctx.toast('Hash failed: ' + (e && e.message || e), 'error'); }
      if (isBc()) {
        var b = bc(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
        if (saltCb.checked) {
          var salt = saltInput.value.trim();
          if (!/^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{22}/.test(salt)) { ctx.toast('Custom salt must look like $2a$10$ + 22 characters', 'error'); return; }
          try { done(b.hashSync(pw, salt)); } catch (e) { fail(e); }
          return;
        }
        return new Promise(function (resolve) { b.hash(pw, cost, function (err, h) { if (err) fail(err); else done(h); resolve(); }); });
      }
      if (typeof argon2 === 'undefined') { ctx.toast('Argon2 library not loaded', 'error'); return; }
      var s;
      if (saltCb.checked) { if (saltInput.value.length < 8) { ctx.toast('Custom salt must be at least 8 characters', 'error'); return; } s = new TextEncoder().encode(saltInput.value); }
      else s = CK.rndBytes(16);
      var type = { argon2d: argon2.ArgonType.Argon2d, argon2i: argon2.ArgonType.Argon2i, argon2id: argon2.ArgonType.Argon2id }[algo];
      return argon2.hash({ pass: pw, salt: s, time: iters(), mem: mem(), parallelism: Math.max(1, +parInput.value || 1), hashLen: Math.max(16, Math.min(64, +lenInput.value || 32)), type: type })
        .then(function (res) { done(res.encoded); }, fail);
    }
    // The pasted hash says which algorithm checks it
    function doVerify() {
      var pw = inP.ta.value, h = outP.ta.value.trim();
      if (!pw) { ctx.toast('Enter the password on the left', 'warn'); return; }
      function result(ok) { clearV(); CK.flashVerify(ok, inP.ta, outP.ta); ctx.toast(ok ? 'Match: password is correct' : 'No match', ok ? 'success' : 'error'); }
      if (/^\$2[abxy]?\$/.test(h)) {
        var b = bc(); if (!b) { ctx.toast('bcrypt library not loaded', 'error'); return; }
        b.compare(pw, h, function (err, ok) { if (err) ctx.toast('Verify failed: ' + err.message, 'error'); else result(ok); });
        return;
      }
      if (/^\$argon2/.test(h)) {
        if (typeof argon2 === 'undefined') { ctx.toast('Argon2 library not loaded', 'error'); return; }
        return argon2.verify({ pass: pw, encoded: h }).then(function () { result(true); }, function () { result(false); });
      }
      ctx.toast('Output is not an encoded bcrypt ($2) or Argon2 ($argon2) hash', 'error');
    }
    function doDetect() {
      var h = outP.ta.value.trim(), b = parseBcrypt(h), p = parseArgon2(h);
      if (b) { cost = b.cost; costInput.value = COSTS.indexOf(cost) < 0 ? cost : ''; setAlgo('bcrypt'); ctx.toast('Detected bcrypt $' + b.version + ', cost ' + b.cost, 'success'); return; }
      if (p) { memInput.value = p.mem; timeInput.value = p.time; parInput.value = p.par; setAlgo('argon2' + p.variant); ctx.toast('Detected argon2' + p.variant + ', m=' + p.mem + ' t=' + p.time + ' p=' + p.par, 'success'); return; }
      ctx.toast('Output is not a bcrypt or Argon2 hash', 'warn');
    }
    function doInspect() {
      var h = outP.ta.value.trim();
      if (!h) { ctx.toast('No hash in the output panel', 'warn'); return; }
      var b = parseBcrypt(h), p = parseArgon2(h), lines;
      if (b) lines = ['Algorithm:   bcrypt', 'Version:     $' + b.version, 'Cost:        ' + b.cost + ' (2^' + b.cost + ' = ' + Math.pow(2, b.cost).toLocaleString() + ' rounds)', 'Salt:        ' + b.salt, 'Hash part:   ' + b.hashPart, 'Encoded:     ' + h, 'Length:      ' + h.length + ' characters'];
      else if (p) lines = ['Algorithm:   argon2' + p.variant, 'Version:     ' + p.version, 'Memory:      ' + p.mem + ' KiB', 'Iterations:  ' + p.time, 'Parallelism: ' + p.par, 'Salt (b64):  ' + p.salt, 'Hash (b64):  ' + p.hash, 'Encoded:     ' + h];
      else { ctx.toast('Output is not a valid bcrypt or Argon2 hash', 'error'); return; }
      outP.ta.value = lines.join('\n'); clearV(); ctx.toast('Hash inspected', 'success');
    }
    function doSwap() { inP.ta.value = outP.ta.value; outP.ta.value = ''; clearV(); ctx.toast('Output moved to input', 'success'); }
    function doShare() { CK.share('passhash', { a: algo, c: cost, m: memInput.value, t: timeInput.value, p: parInput.value, l: lenInput.value, out: outSel.value, cs: saltCb.checked ? 1 : 0, salt: saltInput.value, pw: inP.ta.value, h: outP.ta.value }, { pw: 'password' }); }
    function doReset() {
      inP.ta.value = ''; outP.ta.value = ''; cost = 10; costInput.value = ''; memInput.value = '4096'; timeInput.value = '3'; parInput.value = '1'; lenInput.value = '32';
      outSel.value = 'full'; saltCb.checked = false; saltInput.value = ''; saltField.style.display = 'none'; clearV(); setAlgo('argon2id'); ctx.toast('Reset complete', 'success');
    }

    // Share links
    var mm = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (mm) {
      try {
        var st = JSON.parse(b64uDec(mm[1]));
        algo = st.a || algo;
        if (st.c) { cost = +st.c; if (COSTS.indexOf(cost) < 0) costInput.value = cost; }
        memInput.value = st.m || '4096'; timeInput.value = st.t || '3'; parInput.value = st.p || '1'; lenInput.value = st.l || '32';
        outSel.value = st.out || 'full';
        saltCb.checked = !!st.cs; saltField.style.display = saltCb.checked ? '' : 'none'; saltInput.value = st.salt || '';
        inP.ta.value = st.pw || ''; outP.ta.value = st.h || '';
      } catch (e) { }
    }
    setAlgo(algo);
  });
})();
