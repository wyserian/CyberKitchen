/*
   regex.js - Regex Tester
   Live testing with match list, capture groups (numbered and named), flags,
   a highlighted rendering of the subject, and a library of common patterns.
   Uses the native RegExp engine. Pure JS, no dependencies.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec;

  var FLAGS = [['g', 'global'], ['i', 'ignore case'], ['m', 'multiline'], ['s', 'dotall'], ['u', 'unicode'], ['y', 'sticky']];
  var COMMON = [
    ['', 'Common patterns...'],
    ['[\\w.+-]+@[\\w-]+\\.[\\w.-]+', 'Email address'],
    ['https?://[\\w.-]+(?:/[\\w./?%&=-]*)?', 'URL (http/https)'],
    ['(?:\\d{1,3}\\.){3}\\d{1,3}', 'IPv4 address'],
    ['#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\\b', 'Hex color'],
    ['\\d{4}-\\d{2}-\\d{2}', 'Date (YYYY-MM-DD)'],
    ['[+]?[0-9][0-9 ()-]{7,}[0-9]', 'Phone number'],
    ['\\b[A-Za-z0-9._%+-]+\\b', 'Word / token'],
    ['"(?:[^"\\\\]|\\\\.)*"', 'Double-quoted string'],
    ['<([a-z]+)(?:[^<]*?)>.*?</\\1>', 'HTML tag pair']
  ];

  var I_REGEX = '<path d="M17 3v6M14.5 4.5l5 3M14.5 7.5l5-3M5 20a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM7 14V4"/>';

  CK.registerTool('regex', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('Regex Tester'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_REGEX);
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });

    var patInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'pattern, e.g. (\\w+)@(\\w+)' });
    patInput.addEventListener('input', run);
    colL.appendChild(ui.field('Pattern', patInput));

    // Flags as multi-select toggle buttons
    var flagState = { g: true, i: false, m: false, s: false, u: false, y: false };
    var flagBtns = {}, flagRow = el('div', { style: 'display:flex; gap:5px; align-items:center; flex-wrap:wrap;' });
    FLAGS.forEach(function (f) {
      var b = el('button', { class: 'eb', title: f[1] }); b.textContent = f[0];
      b.addEventListener('click', function () { flagState[f[0]] = !flagState[f[0]]; markFlags(); run(); });
      flagBtns[f[0]] = b; flagRow.appendChild(b);
    });
    colL.appendChild(ui.field('Flags', flagRow));

    var commonSel = ui.select(COMMON.map(function (c) { return { value: c[0], label: c[1] }; }), function (v) { if (v) { patInput.value = v; run(); } }, '');
    colR.appendChild(ui.field('Insert pattern', commonSel));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'TEST STRING', icon: I_REGEX, placeholder: 'Text to test the pattern against...', primaries: [{ label: 'Test', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    var outP = ui.textPanel({ title: 'MATCHES', icon: CK.ui.IC.out, placeholder: 'Matches and capture groups appear here...', readonly: true, actions: ['copy'] });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function markFlags() { FLAGS.forEach(function (f) { flagBtns[f[0]].classList.toggle('active', flagState[f[0]]); }); }
    function flagStr() { return FLAGS.map(function (f) { return f[0]; }).filter(function (k) { return flagState[k]; }).join(''); }

    // Runs the matching loop off the main thread; done(null) if it takes longer than 1 second
    var workerUrl = URL.createObjectURL(new Blob(['onmessage=function(e){var d=e.data,re=new RegExp(d.p,d.f),out=[],m,n=0;' +
      'while((m=re.exec(d.t))!==null){out.push({i:m.index,v:Array.prototype.slice.call(m),g:m.groups||null});' +
      'if(m.index===re.lastIndex)re.lastIndex++;if(++n>100000)break;}postMessage(out);};'], { type: 'text/javascript' }));
    var worker = null, timer = null;
    function stopWorker() { clearTimeout(timer); if (worker) { worker.terminate(); worker = null; } }
    function findAll(pat, flags, text, done) {
      stopWorker();
      worker = new Worker(workerUrl);
      worker.onmessage = function (e) { stopWorker(); done(e.data); };
      timer = setTimeout(function () { stopWorker(); done(null); }, 1000);
      worker.postMessage({ p: pat, f: flags, t: text });
    }

    function run() {
      stopWorker();
      var pat = patInput.value;
      if (!pat) { outP.ta.value = ''; ui.setSel(strip, 'Regex Tester', 'RegExp', 'Enter a pattern to test.'); return; }
      var flags = flagStr(), re;
      try { re = new RegExp(pat, flags); } catch (e) { outP.ta.value = ''; ui.setSel(strip, 'Invalid pattern', 'error', e.message); CK.flashVerify(false, inP.ta); return; }
      inP.ta.classList.remove('verify-match', 'verify-fail');
      var text = inP.ta.value;
      // Match in a worker so a catastrophic pattern like (a+)+ cannot freeze the page
      findAll(pat, flags.indexOf('g') >= 0 ? flags : flags + 'g', text, function (matches) {
        if (!matches) { outP.ta.value = ''; ui.setSel(strip, '/' + pat + '/' + flags, 'too slow', 'Stopped after 1 second: the pattern backtracks too much on this text (often nested quantifiers like (a+)+).'); CK.flashVerify(false, inP.ta); return; }
        ui.setSel(strip, '/' + pat + '/' + flags, matches.length + (matches.length === 1 ? ' match' : ' matches'), matches.length ? 'Pattern is valid and matched.' : 'Pattern is valid, no matches.');
        if (!matches.length) { outP.ta.value = 'No matches.'; return; }
        var lines = [matches.length + (matches.length === 1 ? ' match' : ' matches') + ':\n'];
        matches.forEach(function (mm, i) {
          lines.push('Match ' + (i + 1) + ' at index ' + mm.i + ': ' + JSON.stringify(mm.v[0]));
          for (var g = 1; g < mm.v.length; g++) if (mm.v[g] !== undefined) lines.push('  Group ' + g + ': ' + JSON.stringify(mm.v[g]));
          if (mm.g) Object.keys(mm.g).forEach(function (name) { lines.push('  Group "' + name + '": ' + JSON.stringify(mm.g[name])); });
        });
        // Highlighted rendering with matches wrapped in guillemets
        var hi = '', pos = 0;
        matches.forEach(function (mm) { hi += text.slice(pos, mm.i) + '«' + mm.v[0] + '»'; pos = mm.i + mm.v[0].length; });
        hi += text.slice(pos);
        lines.push('\nHighlighted (matches in « »):\n' + hi);
        outP.ta.value = lines.join('\n');
      });
    }
    function doShare() { CK.share('regex', { p: patInput.value, f: flagStr(), in: inP.ta.value }); }
    function doReset() { patInput.value = ''; inP.ta.value = ''; outP.ta.value = ''; commonSel.value = ''; flagState = { g: true, i: false, m: false, s: false, u: false, y: false }; markFlags(); inP.ta.classList.remove('verify-match', 'verify-fail'); ctx.toast('Reset complete', 'success'); }

    var m0 = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m0) { try { var st = JSON.parse(b64uDec(m0[1])); patInput.value = st.p || ''; inP.ta.value = st.in || ''; if (st.f != null) FLAGS.forEach(function (f) { flagState[f[0]] = st.f.indexOf(f[0]) >= 0; }); } catch (e) { } }
    markFlags(); run();
  });
})();
