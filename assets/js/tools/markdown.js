/*
   markdown.js - Markdown / README Viewer
   Live edit on the left, rendered preview on the right. Self-contained Markdown
   renderer (headings, emphasis, code, lists, blockquotes, tables, links, images,
   rules). All input is HTML-escaped first, so raw HTML and javascript: URLs are
   neutralised. Pure JS, no dependencies.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec;

  function escText(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function safeUrl(u) { u = u.replace(/&amp;/g, '&').trim(); if (/^(javascript|data|vbscript):/i.test(u)) return '#'; return u.replace(/"/g, '%22').replace(/</g, '%3C').replace(/>/g, '%3E').replace(/&/g, '&amp;'); }

  function inline(text) {
    var s = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    var codes = [];
    s = s.replace(/`([^`]+)`/g, function (_, c) { codes.push(c); return '\u0000' + (codes.length - 1) + '\u0000'; });
    s = s.replace(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+[^)]*)?\)/g, function (_, alt, url) { return '<img src="' + safeUrl(url) + '" alt="' + alt.replace(/"/g, '&quot;') + '">'; });
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)(?:\s+[^)]*)?\)/g, function (_, t, url) { return '<a href="' + safeUrl(url) + '" target="_blank" rel="noopener">' + t + '</a>'; });
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/__([^_]+)__/g, '<strong>$1</strong>');
    s = s.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    s = s.replace(/~~([^~]+)~~/g, '<del>$1</del>');
    s = s.replace(/\u0000(\d+)\u0000/g, function (m, n) { return +n < codes.length ? '<code>' + codes[+n] + '</code>' : m; });
    return s;
  }

  function render(src) {
    var lines = String(src).replace(/\r\n?/g, '\n').split('\n'), out = [], i = 0;
    var blockStart = /^\s*(#{1,6}\s|>|```|[-*+]\s|\d+[.)]\s)/, hrRe = /^\s*([-*_])\s*(\1\s*){2,}$/;
    while (i < lines.length) {
      var line = lines[i];
      var fence = /^\s*```(.*)$/.exec(line);
      if (fence) {
        var lang = fence[1].trim(), buf = []; i++;
        while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) { buf.push(lines[i]); i++; }
        i++;
        out.push('<pre><code' + (lang ? ' class="lang-' + escText(lang) + '"' : '') + '>' + escText(buf.join('\n')) + '</code></pre>');
        continue;
      }
      if (/^\s*$/.test(line)) { i++; continue; }
      var h = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
      if (h) { var lvl = h[1].length; out.push('<h' + lvl + '>' + inline(h[2]) + '</h' + lvl + '>'); i++; continue; }
      if (hrRe.test(line)) { out.push('<hr>'); i++; continue; }
      if (/^\s*>/.test(line)) {
        var bq = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) { bq.push(lines[i].replace(/^\s*>\s?/, '')); i++; }
        out.push('<blockquote>' + render(bq.join('\n')) + '</blockquote>');
        continue;
      }
      // pipe table: header row, then a separator row of ---/:--: cells
      if (line.indexOf('|') >= 0 && i + 1 < lines.length && /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)+\|?\s*$/.test(lines[i + 1])) {
        function cells(row) { return row.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map(function (c) { return c.trim(); }); }
        var head = cells(line), rows = []; i += 2;
        while (i < lines.length && lines[i].indexOf('|') >= 0 && !/^\s*$/.test(lines[i])) { rows.push(cells(lines[i])); i++; }
        var t = '<table><thead><tr>' + head.map(function (c) { return '<th>' + inline(c) + '</th>'; }).join('') + '</tr></thead><tbody>';
        t += rows.map(function (r) { return '<tr>' + r.map(function (c) { return '<td>' + inline(c) + '</td>'; }).join('') + '</tr>'; }).join('');
        out.push(t + '</tbody></table>');
        continue;
      }
      var isOl = /^\s*\d+[.)]\s+/.test(line), isUl = /^\s*[-*+]\s+/.test(line);
      if (isOl || isUl) {
        var tag = isOl ? 'ol' : 'ul', items = [];
        while (i < lines.length) {
          var m = isOl ? /^\s*\d+[.)]\s+(.*)$/.exec(lines[i]) : /^\s*[-*+]\s+(.*)$/.exec(lines[i]);
          if (!m) break;
          items.push('<li>' + inline(m[1]) + '</li>'); i++;
        }
        out.push('<' + tag + '>' + items.join('') + '</' + tag + '>');
        continue;
      }
      var para = [line]; i++;
      while (i < lines.length && !/^\s*$/.test(lines[i]) && !blockStart.test(lines[i]) && !hrRe.test(lines[i])) { para.push(lines[i]); i++; }
      out.push('<p>' + inline(para.join('\n')).replace(/\n/g, '<br>') + '</p>');
    }
    return out.join('\n');
  }

  var I_MD = '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 15V9l3 3 3-3v6M18 9v4M16 13l2 2 2-2"/>';
  var I_EYE = '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>';
  var IC_COPY = '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>';
  var IC_DL = '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>';
  var I_NEW = '<path d="M14 3h7v7M21 3l-9 9M19 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5"/>';
  var VARS = ['--bg', '--surf', '--inset', '--inset2', '--txt', '--muted', '--bdr', '--cbdr', '--acc'];

  CK.registerTool('markdown', function (root, ctx) {
    var ui = CK.ui, el = CK.el, iconSvg = CK.iconSvg;

    root.appendChild(ui.head('Markdown Viewer'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_MD);
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);
    ui.setSel(strip, 'Markdown Viewer', 'live', 'Edit Markdown on the left and see it rendered on the right, in real time. Rendered locally with HTML escaping.');
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'MARKDOWN', icon: I_MD, placeholder: '# Type Markdown here...', actions: ['copy', 'paste', 'clear', 'download'], downloadName: 'README.md', onInput: run });
    io.appendChild(inP.panel);

    // Custom preview panel holding rendered HTML
    var outPanel = el('div', { class: 'panel io-p' });
    var hdr = el('div', { class: 'panel-hdr', html: iconSvg(I_EYE, 12) + ' ' });
    hdr.appendChild(document.createTextNode('PREVIEW'));
    var fill = el('span', { class: 'fill' }), tb = el('span', { class: 'tb' });
    tb.appendChild(ui.iconBtn(I_NEW, 'Open in new tab', doOpen));
    tb.appendChild(ui.iconBtn(IC_COPY, 'Copy HTML', function () { if (lastHtml) CK.copy(lastHtml); else ctx.toast('Nothing to copy', 'warn'); }));
    tb.appendChild(ui.iconBtn(IC_DL, 'Download HTML', function () { if (lastHtml) CK.download(fullHtml(), 'readme.html', 'text/html'); else ctx.toast('Nothing to save', 'warn'); }));
    hdr.appendChild(fill); hdr.appendChild(tb);
    var preview = el('div', { class: 'md-preview' });
    outPanel.appendChild(hdr); outPanel.appendChild(preview);
    io.appendChild(outPanel);
    root.appendChild(io);

    var lastHtml = '';
    function fullHtml() { return '<!doctype html>\n<html>\n<head><meta charset="utf-8"><title>README</title></head>\n<body>\n' + lastHtml + '\n</body>\n</html>'; }
    function run() { lastHtml = render(inP.ta.value); preview.innerHTML = lastHtml; }
    // Full-screen page (no box, edge to edge) styled like the preview: the current theme's colours plus the app's own
    // .md-preview rules. The CSP blocks every script, on top of the renderer's HTML escaping.
    function doOpen() {
      if (!lastHtml) { ctx.toast('Nothing to show', 'warn'); return; }
      var cs = getComputedStyle(document.documentElement);
      var css = ':root{' + VARS.map(function (n) { return n + ':' + cs.getPropertyValue(n).trim(); }).join(';') + ';color-scheme:' + cs.colorScheme + '}';
      [].forEach.call(document.styleSheets, function (sh) {
        try { [].forEach.call(sh.cssRules, function (r) { if (r.selectorText && r.selectorText.indexOf('.md-preview') >= 0) css += r.cssText; }); } catch (e) { }
      });
      css += '::-webkit-scrollbar{width:3px;height:3px}::-webkit-scrollbar-track,::-webkit-scrollbar-corner{background:transparent}::-webkit-scrollbar-button{display:none}::-webkit-scrollbar-thumb{background:transparent;border-radius:3px}:hover::-webkit-scrollbar-thumb{background:var(--cbdr)}' +
        'body{margin:0;background:var(--bg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}' +
        '.md-preview{background:none;border-radius:0;margin:0;padding:24px 32px;min-height:100vh;box-sizing:border-box;font-size:15px;}';
      var page = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src * data:">' +
        '<title>Markdown preview</title><style>' + css + '</style></head><body><div class="md-preview">' + lastHtml + '</div></body></html>';
      var url = URL.createObjectURL(new Blob([page], { type: 'text/html' }));
      window.open(url, '_blank', 'noopener');
      setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    }
    function doShare() { CK.share('markdown', { md: inP.ta.value }); }
    function doReset() { inP.ta.value = ''; run(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); inP.ta.value = st.md || ''; } catch (e) { } }
    run();
  });
})();
