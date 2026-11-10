/*
   json.js - JSON Toolkit
   Format, minify, validate, type-annotated tree view, and a JSONPath query
   (subset: $, .key, ['key'], [n], [*], ..key). Pure JS, no dependencies.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec;

  function sortDeep(v) {
    if (Array.isArray(v)) return v.map(sortDeep);
    if (v && typeof v === 'object') { var o = {}; Object.keys(v).sort().forEach(function (k) { o[k] = sortDeep(v[k]); }); return o; }
    return v;
  }
  function typeOf(v) { return v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v; }
  function treeText(v) {
    var out = [];
    function walk(node, prefix, keyLabel) {
      var t = typeOf(node);
      if (t === 'object') { out.push(prefix + keyLabel + '{object, ' + Object.keys(node).length + ' keys}'); Object.keys(node).forEach(function (k) { walk(node[k], prefix + '  ', '"' + k + '": '); }); }
      else if (t === 'array') { out.push(prefix + keyLabel + '[array, ' + node.length + ' items]'); node.forEach(function (item, i) { walk(item, prefix + '  ', '[' + i + '] '); }); }
      else { var val = t === 'string' ? '"' + node + '"' : String(node); out.push(prefix + keyLabel + val + '  (' + t + ')'); }
    }
    walk(v, '', '');
    return out.join('\n');
  }

  /* JSONPath (subset). Returns an array of matched values. */
  function jsonPath(root, path) {
    var steps = [], re = /\.\.([A-Za-z_$][\w$]*)|\.([A-Za-z_$][\w$]*)|\[\s*'([^']*)'\s*\]|\[\s*"([^"]*)"\s*\]|\[\s*(\*)\s*\]|\[\s*(-?\d+)\s*\]|\.(\*)/g, m;
    var p = path.trim().replace(/^\$/, '');
    var last = 0;
    while ((m = re.exec(p)) !== null) {
      if (m.index !== last) throw new Error('Unsupported path syntax near: ' + p.slice(last));
      last = re.lastIndex;
      if (m[1] != null) steps.push({ t: 'recursive', k: m[1] });
      else if (m[2] != null) steps.push({ t: 'child', k: m[2] });
      else if (m[3] != null) steps.push({ t: 'child', k: m[3] });
      else if (m[4] != null) steps.push({ t: 'child', k: m[4] });
      else if (m[5] != null) steps.push({ t: 'wild' });
      else if (m[6] != null) steps.push({ t: 'index', i: +m[6] });
      else if (m[7] != null) steps.push({ t: 'wild' });
    }
    if (last !== p.length) throw new Error('Unsupported path syntax near: ' + p.slice(last));
    var cur = [root];
    steps.forEach(function (s) {
      var next = [];
      cur.forEach(function (node) {
        if (node == null) return;
        if (s.t === 'child') { if (typeof node === 'object' && s.k in node) next.push(node[s.k]); }
        else if (s.t === 'index') { if (Array.isArray(node)) { var i = s.i < 0 ? node.length + s.i : s.i; if (i >= 0 && i < node.length) next.push(node[i]); } }
        else if (s.t === 'wild') { if (Array.isArray(node)) node.forEach(function (x) { next.push(x); }); else if (typeof node === 'object') Object.keys(node).forEach(function (k) { next.push(node[k]); }); }
        else if (s.t === 'recursive') { (function rec(n) { if (n && typeof n === 'object') { if (!Array.isArray(n) && s.k in n) next.push(n[s.k]); (Array.isArray(n) ? n : Object.keys(n).map(function (k) { return n[k]; })).forEach(rec); } })(node); }
      });
      cur = next;
    });
    return cur;
  }

  var I_JSON = '<path d="M8 4H6a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h2M16 4h2a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-2"/>';
  var I_TREE = '<rect x="3" y="3" width="6" height="4" rx="1"/><rect x="15" y="10" width="6" height="4" rx="1"/><rect x="15" y="17" width="6" height="4" rx="1"/><path d="M6 7v9a2 2 0 0 0 2 2h7M6 12h9"/>';

  CK.registerTool('json', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('JSON Toolkit'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_JSON);
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.check, 'Validate', doValidate));
    strip.acts.appendChild(ui.iconBtn(I_TREE, 'Tree view', doTree));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);
    ui.setSel(strip, 'JSON Toolkit', 'RFC 8259', 'Format, minify, validate and query JSON. Everything runs locally.');

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col2' });
    var colR = el('div', { class: 'col' });
    var indentSel = ui.select([['2', '2 spaces'], ['4', '4 spaces'], ['tab', 'Tab']], null, '2');
    var sortCb = el('input', { type: 'checkbox' });
    var sortSwitch = el('label', { class: 'switch' }); sortSwitch.appendChild(sortCb); sortSwitch.appendChild(el('span', { class: 'track' })); sortSwitch.appendChild(el('span', {}, 'Sort keys'));
    colL.appendChild(ui.field('Indent', indentSel)); colL.appendChild(ui.field('Options', sortSwitch));
    var pathInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: "$.store.book[*].title" });
    var pathWrap = el('div', { style: 'display:flex; gap:5px; align-items:center;' });
    pathInput.style.flex = '1'; pathInput.style.minWidth = '0';
    var queryBtn = ui.iconBtn(CK.ui.IC.out, 'Query', doQuery);
    pathWrap.appendChild(pathInput); pathWrap.appendChild(queryBtn);
    colR.appendChild(ui.field('JSONPath query', pathWrap));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'JSON', icon: I_JSON, placeholder: '{ "hello": "world" }', primaries: [{ label: 'Format', cls: 'enc', onClick: doFormat }, { label: 'Minify', cls: 'dec', onClick: doMinify }], actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'input.json', onInput: clearVerify });
    var outP = ui.textPanel({ title: 'RESULT', icon: CK.ui.IC.out, placeholder: 'Formatted, minified or queried output...', actions: ['copy', 'download'], downloadName: 'output.json' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function clearVerify() { inP.ta.classList.remove('verify-match', 'verify-fail'); }
    function indent() { return indentSel.value === 'tab' ? '\t' : +indentSel.value; }
    function parse() {
      var v = inP.ta.value.trim();
      if (!v) throw new Error('Input is empty');
      var data = JSON.parse(v);
      return sortCb.checked ? sortDeep(data) : data;
    }
    function doFormat() { try { outP.ta.value = JSON.stringify(parse(), null, indent()); clearVerify(); ctx.toast('Formatted', 'success'); } catch (e) { ctx.toast(e.message, 'error'); } }
    function doMinify() { try { outP.ta.value = JSON.stringify(parse()); clearVerify(); ctx.toast('Minified', 'success'); } catch (e) { ctx.toast(e.message, 'error'); } }
    function doTree() { try { outP.ta.value = treeText(parse()); clearVerify(); ctx.toast('Tree view', 'success'); } catch (e) { ctx.toast(e.message, 'error'); } }
    function doValidate() {
      var v = inP.ta.value.trim();
      if (!v) { ctx.toast('Input is empty', 'warn'); return; }
      try { JSON.parse(v); CK.flashVerify(true, inP.ta); ctx.toast('Valid JSON', 'success'); }
      catch (e) { CK.flashVerify(false, inP.ta); ctx.toast('Invalid JSON: ' + e.message, 'error'); }
    }
    function doQuery() {
      try {
        var data = parse(), path = pathInput.value.trim();
        if (!path) { ctx.toast('Enter a JSONPath query', 'warn'); return; }
        var res = jsonPath(data, path);
        outP.ta.value = JSON.stringify(res, null, indent());
        ctx.toast(res.length + (res.length === 1 ? ' match' : ' matches'), res.length ? 'success' : 'warn');
      } catch (e) { ctx.toast(e.message, 'error'); }
    }
    function doShare() { CK.share('json', { in: inP.ta.value, ind: indentSel.value, sort: sortCb.checked ? 1 : 0, path: pathInput.value }); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; indentSel.value = '2'; sortCb.checked = false; pathInput.value = ''; clearVerify(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); inP.ta.value = st.in || ''; indentSel.value = st.ind || '2'; sortCb.checked = !!st.sort; pathInput.value = st.path || ''; } catch (e) { } }
  });
})();
