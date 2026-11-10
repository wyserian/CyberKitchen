/*
   checksum.js - File Checksum
   Drop or choose a local file and compute its checksum with one selected
   algorithm (any from the Hash tool: SHA-2, SHA-3, BLAKE, MD5, CRC, xxHash...). Verify compares the output
   panel (bare hash, "hash  filename" or "ALGO (file) = hash") with the file's
   checksum for that algorithm. The file is read in the browser and never uploaded.
*/
(function () {
  'use strict';
  var toHex = CK.toHex, hexToBytes = CK.hexToBytes, unb64 = CK.unb64, b64 = CK.b64;
  // Same algorithms as the Hash tool (hash.js loads first), minus keyed SipHash; hx: bytes -> Promise<hex>
  var ALGOS = CK.hashAlgos.filter(function (a) { return !a.keyed; }).map(function (a) {
    return { id: a.id, label: a.label, group: a.group, bytes: a.bytes, hx: function (b) { return a.hb(b).then(toHex); } };
  });
  var GROUPS = ALGOS.map(function (a) { return a.group; }).filter(function (g, i, all) { return all.indexOf(g) === i; });
  function get(id) { for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) return ALGOS[i]; return null; }

  function fmtSize(n) {
    var u = ['bytes', 'KB', 'MB', 'GB'], i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i ? v.toFixed(v < 10 ? 2 : 1) + ' ' + u[i] + ' (' + n.toLocaleString() + ' bytes)' : n.toLocaleString() + ' bytes');
  }
  // Published checksum -> lowercase hex, or null. Accepts a bare hash (hex or
  // Base64), GNU "hash  filename" and BSD "ALGO (file) = hash" lines.
  function parseExpected(v) {
    v = v.trim(); if (!v) return null;
    var bsd = /\)\s*=\s*([0-9A-Za-z+/_-]+={0,2})\s*$/.exec(v);
    var tok = bsd ? bsd[1] : v.split(/\s+/)[0].replace(/^\*/, '');
    if (/^[0-9a-fA-F]+$/.test(tok) && tok.length % 2 === 0) return tok.toLowerCase();
    // Base64: the shortest supported checksum (CRC32) is 8 characters
    if (tok.length < 8 || !/^[0-9A-Za-z+/_-]+={0,2}$/.test(tok)) return null;
    try { var b = unb64(tok); return b.length ? toHex(b) : null; } catch (e) { return null; }
  }

  var I_SUM = '<path d="M14 3v5h5M6 3h9l5 5v13H6z"/><path d="m9 14 2 2 4-4"/>';
  var I_UPLOAD = '<path d="M12 16V4M7 9l5-5 5 5M5 20h14"/>';
  var IC_CLEAR = '<path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/>';

  CK.registerTool('checksum', function (root, ctx) {
    var ui = CK.ui, el = CK.el, iconSvg = CK.iconSvg;

    root.appendChild(ui.head('File Checksum'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_SUM);
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Verify', doVerify));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });
    // One dropdown per algorithm group, as in the Hash tool; picking from one clears the others
    var current = 'sha256', groupSelects = {};
    var pickGrid = el('div', { style: 'display:grid; grid-template-columns:repeat(auto-fit,minmax(185px,1fr)); gap:10px 14px;' });
    GROUPS.forEach(function (g) {
      var items = ALGOS.filter(function (a) { return a.group === g; });
      var sel = ui.select([{ value: '', label: 'Select...' }].concat(items.map(function (a) { return { value: a.id, label: a.label }; })), function (v) { if (v) { current = v; syncSelects(); onAlgo(); } }, '');
      groupSelects[g] = sel;
      pickGrid.appendChild(ui.field(g, sel));
    });
    function syncSelects() { var grp = get(current).group; GROUPS.forEach(function (g) { groupSelects[g].value = (g === grp ? current : ''); }); }
    var outFmt = ui.select([['hex', 'Hexadecimal (lower)'], ['HEX', 'Hexadecimal (UPPER)'], ['base64', 'Base64']], show, 'hex');
    colL.appendChild(pickGrid);
    colR.appendChild(ui.field('Output format', outFmt));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    // File panel: drop zone (styled like the text areas so Verify can colour it)
    var inP = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr', html: iconSvg(CK.ui.IC.file, 12) + ' ' });
    hdr.appendChild(document.createTextNode('FILE'));
    var fill = el('span', { class: 'fill' }), tb = el('span', { class: 'tb' });
    var picker = el('input', { type: 'file', style: 'display:none' });
    tb.appendChild(ui.iconBtn(I_UPLOAD, 'Choose file', function () { picker.click(); }));
    var clrBtn = ui.iconBtn(IC_CLEAR, 'Clear', clearFile); tb.appendChild(clrBtn);
    hdr.appendChild(fill); hdr.appendChild(tb);
    var drop = el('div', { class: 'ta cs-drop', tabindex: '0', role: 'button', 'aria-label': 'Choose a file to hash' });
    inP.appendChild(hdr); inP.appendChild(drop); inP.appendChild(picker);
    var outP = ui.textPanel({ title: 'CHECKSUM', icon: CK.ui.IC.hash, placeholder: 'Checksum appears here. Or paste the expected checksum and press Verify...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'checksum.txt' });
    io.appendChild(inP); io.appendChild(outP.panel);
    root.appendChild(io);

    // shown: the last checksum this tool wrote; anything else in the output is the user's expected value
    var file = null, bytes = null, digests = {}, busy = 0, shown = '';

    function algo() { return get(current); }
    function clearVerify() { drop.classList.remove('verify-match', 'verify-fail'); outP.ta.classList.remove('verify-match', 'verify-fail'); }
    function showDrop(state) {
      drop.innerHTML = '';
      drop.appendChild(el('span', { html: iconSvg(file ? CK.ui.IC.file : I_UPLOAD, 26) }));
      if (!file) {
        drop.appendChild(el('span', { class: 'cs-name' }, 'Drop a file here, or click to choose'));
      } else {
        var nm = el('span', { class: 'cs-name' }); nm.textContent = file.name; drop.appendChild(nm);
        var meta = el('span', { class: 'cs-meta' });
        meta.textContent = fmtSize(file.size) + (file.type ? ' · ' + file.type : '') + (file.lastModified ? ' · ' + new Date(file.lastModified).toLocaleString() : '');
        drop.appendChild(meta);
        drop.appendChild(el('span', { class: 'cs-hint' }, state === 'busy' ? 'Hashing...' : 'Click or drop to choose another file'));
      }
      clrBtn.disabled = !file;
    }
    function updateSel() { var a = algo(); ui.setSel(strip, a.label, a.bytes + ' bytes', a.label + ' checksum of a local file.'); }

    function fmt(hx) { return outFmt.value === 'HEX' ? hx.toUpperCase() : outFmt.value === 'base64' ? b64(hexToBytes(hx)) : hx; }
    // Write the checksum, unless the output holds the user's expected value: then verify against it
    function show() {
      var hx = bytes && digests[algo().id];
      if (!hx) return;
      var cur = outP.ta.value.trim();
      if (cur && cur !== shown) { doVerify(); return; }
      shown = fmt(hx); outP.ta.value = shown; clearVerify();
    }
    // Digest the current file with each algorithm not yet cached
    function compute(ids) {
      var gen = busy, todo = ids.filter(function (id) { return !digests[id]; });
      return todo.reduce(function (p, id) {
        return p.then(function () {
          if (gen !== busy) return;
          return get(id).hx(bytes).then(function (hx) { if (gen === busy) digests[id] = hx; });
        });
      }, Promise.resolve());
    }
    function onAlgo() { updateSel(); if (bytes) compute([algo().id]).then(show); }

    function load(f) {
      if (!f) return;
      busy++; var gen = busy;
      file = f; bytes = null; digests = {}; clearVerify(); showDrop('busy');
      var t0 = Date.now();
      f.arrayBuffer().then(function (buf) {
        if (gen !== busy) return;
        bytes = new Uint8Array(buf);
        // Let the "Hashing..." state paint before the synchronous hashes run
        return new Promise(function (r) { setTimeout(r, 30); }).then(function () { return compute([algo().id]); }).then(function () {
          if (gen !== busy) return;
          showDrop();
          ctx.toast('Hashed ' + f.name + ' in ' + ((Date.now() - t0) / 1000).toFixed(2) + ' s', 'success');
          show();
        });
      }).catch(function () {
        if (gen !== busy) return;
        file = null; bytes = null; showDrop();
        ctx.toast('Could not read the file (it may be too large for the browser)', 'error');
      });
    }
    function clearFile() {
      busy++; file = null; bytes = null; digests = {}; picker.value = '';
      if (outP.ta.value.trim() === shown) outP.ta.value = '';
      shown = ''; clearVerify(); showDrop();
    }

    function doVerify() {
      clearVerify();
      var raw = outP.ta.value.trim(), a = algo();
      if (!bytes) { ctx.toast('Choose a file first', 'warn'); return; }
      if (!raw) { ctx.toast('Paste the expected checksum in the output panel', 'warn'); return; }
      var want = parseExpected(raw);
      if (!want) { CK.flashVerify(false, drop, outP.ta); ctx.toast('That is not a hex or Base64 checksum', 'error'); return; }
      compute([a.id]).then(function () {
        var match = digests[a.id] === want;
        CK.flashVerify(match, drop, outP.ta);
        if (match) { ctx.toast('Match: ' + a.label + ' of ' + file.name, 'success'); return; }
        // Wrong length for the selected algorithm: name the ones it does fit
        var fits = ALGOS.filter(function (x) { return x.bytes * 2 === want.length; }).map(function (x) { return x.label; });
        ctx.toast(want.length === a.bytes * 2 ? 'No match (' + a.label + ')' :
          'No match: ' + a.label + ' is ' + a.bytes + ' bytes, this is ' + want.length / 2 + ' bytes' + (fits.length ? ' (that length is ' + fits.join(' or ') + ')' : ''), 'error');
      });
    }
    function doReset() {
      clearFile(); outP.ta.value = ''; current = 'sha256'; syncSelects(); outFmt.value = 'hex';
      updateSel(); ctx.toast('Reset complete', 'success');
    }

    outP.ta.addEventListener('input', clearVerify);
    picker.addEventListener('change', function () { load(picker.files[0]); });
    drop.addEventListener('click', function () { picker.click(); });
    drop.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); picker.click(); } });
    drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('drag'); });
    drop.addEventListener('dragleave', function () { drop.classList.remove('drag'); });
    drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('drag'); if (e.dataTransfer && e.dataTransfer.files[0]) load(e.dataTransfer.files[0]); });

    syncSelects(); updateSel(); showDrop();
  });
})();
