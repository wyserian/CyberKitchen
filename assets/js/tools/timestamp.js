/*
   timestamp.js - Timestamp Converter
   Convert between Unix epoch (seconds or milliseconds), ISO 8601, local and
   UTC strings, with a relative time and a custom format. Pure JS, no deps.
*/
(function () {
  'use strict';
  var b64uDec = CK.b64uDec;

  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

  function pad(n, w) { n = String(n); while (n.length < (w || 2)) n = '0' + n; return n; }
  // Minimal date formatter: YYYY YY MM DD HH hh mm ss SSS A MMM ddd
  function format(d, fmt, utc) {
    var g = utc ? { y: d.getUTCFullYear(), mo: d.getUTCMonth(), da: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), s: d.getUTCSeconds(), ms: d.getUTCMilliseconds(), dw: d.getUTCDay() }
      : { y: d.getFullYear(), mo: d.getMonth(), da: d.getDate(), h: d.getHours(), mi: d.getMinutes(), s: d.getSeconds(), ms: d.getMilliseconds(), dw: d.getDay() };
    var h12 = g.h % 12 || 12;
    return fmt.replace(/YYYY|YY|MMM|MM|DD|ddd|HH|hh|mm|ss|SSS|A/g, function (t) {
      switch (t) {
        case 'YYYY': return g.y; case 'YY': return pad(g.y % 100);
        case 'MMM': return MONTHS[g.mo]; case 'MM': return pad(g.mo + 1); case 'DD': return pad(g.da);
        case 'ddd': return DAYS[g.dw];
        case 'HH': return pad(g.h); case 'hh': return pad(h12); case 'mm': return pad(g.mi); case 'ss': return pad(g.s);
        case 'SSS': return pad(g.ms, 3); case 'A': return g.h < 12 ? 'AM' : 'PM';
      }
      return t;
    });
  }
  function relative(ms) {
    var diff = ms - Date.now(), future = diff > 0, s = Math.abs(diff) / 1000;
    var units = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
    for (var i = 0; i < units.length; i++) { var v = Math.floor(s / units[i][1]); if (v >= 1) { var u = units[i][0] + (v > 1 ? 's' : ''); return future ? 'in ' + v + ' ' + u : v + ' ' + u + ' ago'; } }
    return 'just now';
  }
  // Parse the input into milliseconds since epoch, or null
  function toMs(s, mode) {
    s = s.trim();
    if (!s) return null;
    if (s.toLowerCase() === 'now') return Date.now();
    if (mode === 'auto') {
      if (/^-?\d+$/.test(s)) mode = s.replace('-', '').length >= 12 ? 'ms' : 'sec';
      else mode = 'iso';
    }
    if (mode === 'sec') return +s * 1000;
    if (mode === 'ms') return +s;
    var t = Date.parse(s);
    return isNaN(t) ? null : t;
  }

  var I_CLOCK = '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>';

  CK.registerTool('timestamp', function (root, ctx) {
    var ui = CK.ui, el = CK.el;

    root.appendChild(ui.head('Timestamp Converter'));

    var cfg = ui.configPanel();
    var strip = ui.selStrip(I_CLOCK);
    strip.desc.style.whiteSpace = 'normal';
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Now', doNow));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.share, 'Share', doShare));
    strip.acts.appendChild(ui.iconBtn(CK.ui.IC.reset, 'Reset', doReset));
    cfg.appendChild(strip.strip);

    var grid = el('div', { class: 'cfg-grid wide-left' });
    var colL = el('div', { class: 'col' });
    var colR = el('div', { class: 'col' });
    var modeSel = ui.select([['auto', 'Auto-detect'], ['sec', 'Unix seconds'], ['ms', 'Unix milliseconds'], ['iso', 'Date string']], run, 'auto');
    colL.appendChild(ui.field('Interpret input as', modeSel));
    var fmtInput = el('input', { class: 'inp', type: 'text', spellcheck: 'false', autocomplete: 'off', value: 'YYYY-MM-DD HH:mm:ss', placeholder: 'YYYY-MM-DD HH:mm:ss' });
    fmtInput.addEventListener('input', run);
    colR.appendChild(ui.field('Custom format (local)', fmtInput));
    grid.appendChild(colL); grid.appendChild(colR);
    cfg.appendChild(grid);
    root.appendChild(cfg);

    var io = ui.ioRow();
    var inP = ui.textPanel({ title: 'INPUT', icon: I_CLOCK, placeholder: '1700000000  ·  2023-11-14T22:13:20Z  ·  now', primaries: [{ label: 'Convert', cls: 'enc', onClick: run }], actions: ['copy', 'paste', 'clear'], onInput: run });
    var outP = ui.textPanel({ title: 'REPRESENTATIONS', icon: CK.ui.IC.out, placeholder: 'All representations appear here...', readonly: true, actions: ['copy', 'download'], downloadName: 'timestamp.txt' });
    io.appendChild(inP.panel); io.appendChild(outP.panel);
    root.appendChild(io);

    function padK(k) { return (k + ':').padEnd(20, ' '); }
    function run() {
      var ms = toMs(inP.ta.value, modeSel.value);
      if (ms == null) { outP.ta.value = ''; ui.setSel(strip, 'Timestamp Converter', 'epoch', 'Enter a Unix timestamp, an ISO date, or "now".'); return; }
      var d = new Date(ms);
      if (isNaN(d.getTime())) { outP.ta.value = ''; ui.setSel(strip, 'Invalid input', 'error', 'Could not parse that value.'); return; }
      ui.setSel(strip, format(d, 'YYYY-MM-DD HH:mm:ss', false), relative(ms), d.toUTCString());
      var lines = [
        padK('Unix seconds') + Math.floor(ms / 1000),
        padK('Unix milliseconds') + ms,
        padK('ISO 8601 (UTC)') + d.toISOString(),
        padK('UTC') + d.toUTCString(),
        padK('Local') + d.toString(),
        padK('Relative') + relative(ms),
        padK('Day of week') + DAYS[d.getDay()] + ' (' + d.getDay() + ')',
        padK('Custom (local)') + format(d, fmtInput.value, false),
        padK('Custom (UTC)') + format(d, fmtInput.value, true)
      ];
      outP.ta.value = lines.join('\n');
    }
    function doNow() { inP.ta.value = String(Date.now()); modeSel.value = 'ms'; run(); }
    function doShare() { CK.share('timestamp', { in: inP.ta.value, m: modeSel.value, f: fmtInput.value }); }
    function doReset() { inP.ta.value = ''; outP.ta.value = ''; modeSel.value = 'auto'; fmtInput.value = 'YYYY-MM-DD HH:mm:ss'; run(); ctx.toast('Reset complete', 'success'); }

    var m = /(?:^|[#&])s=([\w-]+)/.exec(location.hash || '');
    if (m) { try { var st = JSON.parse(b64uDec(m[1])); inP.ta.value = st.in || ''; modeSel.value = st.m || 'auto'; fmtInput.value = st.f || 'YYYY-MM-DD HH:mm:ss'; } catch (e) { } }
    run();
  });
})();
