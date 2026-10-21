/*
   test/run.js - regression tests for the hand-written crypto, parsers and sanitisers.
   No dependencies: `node test/run.js` (Node 20+). Loads the real app files into a
   minimal DOM stand-in and drives the tools the way a user would. Exit code 1 on failure.
*/
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm'), nc = require('crypto');
var ROOT = path.join(__dirname, '..');
var fails = 0, passes = 0;
function ok(cond, name) { if (cond) passes++; else { fails++; console.log('FAIL ' + name); } }
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
async function until(fn, ms) { for (var t = 0; t < (ms || 3000); t += 20) { if (fn()) return true; await sleep(20); } return false; }

/* ---- Minimal DOM stand-in: just what the tool builders use ---- */
function Node(tag) {
  this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {};
  this.className = ''; this._text = ''; this.style = {}; this.hidden = false; this.disabled = false;
  if (this.tagName === 'INPUT') this.value = '';
  var self = this;
  this.classList = {
    contains: function (c) { return self.className.split(' ').indexOf(c) >= 0; },
    toggle: function (c, on) { var a = self.className.split(' ').filter(Boolean), i = a.indexOf(c); if (on === undefined) on = i < 0; if (on && i < 0) a.push(c); if (!on && i >= 0) a.splice(i, 1); self.className = a.join(' '); },
    add: function () { for (var i = 0; i < arguments.length; i++) this.toggle(arguments[i], true); },
    remove: function () { for (var i = 0; i < arguments.length; i++) this.toggle(arguments[i], false); }
  };
}
Node.prototype.setAttribute = function (k, v) { this.attrs[k] = v; if (k === 'placeholder' || k === 'title' || k === 'type' || k === 'value') this[k] = v; };
Node.prototype.getAttribute = function (k) { return this.attrs[k]; };
Node.prototype.removeAttribute = function (k) { delete this.attrs[k]; };
Node.prototype.appendChild = function (c) { this.children.push(c); c.parentNode = this; return c; };
Node.prototype.insertBefore = function (c, ref) { var i = this.children.indexOf(ref); if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); c.parentNode = this; return c; };
Node.prototype.addEventListener = function (t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); };
Node.prototype.fire = function (t, extra) { var e = Object.assign({ target: this, preventDefault: function () {}, stopPropagation: function () {} }, extra || {}); (this.listeners[t] || []).forEach(function (f) { f(e); }); };
Node.prototype.focus = function () {};
Node.prototype.closest = function () { return null; };
Object.defineProperty(Node.prototype, 'firstChild', { get: function () { return this.children[0] || null; } });
Object.defineProperty(Node.prototype, 'innerHTML', { get: function () { return this._html || ''; }, set: function (v) { this._html = v; this.children = []; if (/class="lbl"/.test(v)) { var l = new Node('span'); l.className = 'lbl'; this.children.push(l); } } });
Object.defineProperty(Node.prototype, 'textContent', { get: function () { return this._text || this._html || ''; }, set: function (v) { this._text = v; } });
Node.prototype.querySelector = function (sel) { var cls = sel.replace('.', ''), q = this.children.slice(); while (q.length) { var n = q.shift(); if (n.className && n.className.split(' ').indexOf(cls) >= 0) return n; q = q.concat(n.children); } return null; };
global.HTMLTextAreaElement = function () {};
Object.defineProperty(HTMLTextAreaElement.prototype, 'value', { configurable: true, get: function () { return this._v || ''; }, set: function (v) { this._v = String(v); } });
global.window = global;
global.document = { createElement: function (t) { return new Node(t); }, createTextNode: function (t) { var n = new Node('#text'); n._text = t; return n; }, body: new Node('body'), documentElement: new Node('html'), getElementById: function () { return null; }, addEventListener: function () {} };
global.location = { hash: '', href: 'https://x.test/' };
global.localStorage = { getItem: function () { return null; }, setItem: function () {} };

/* ---- Load the real app ---- */
function load(p) { vm.runInThisContext(fs.readFileSync(path.join(ROOT, p), 'utf8'), { filename: p }); }
global.CryptoJS = require(path.join(ROOT, 'assets/js/vendor/crypto-js.min.js'));
['assets/js/core.js', 'assets/js/ui.js', 'assets/js/vendor/hashlib.js', 'assets/js/vendor/qrcode.min.js'].forEach(load);
var toasts = [];
CK.toast = function (m, t) { toasts.push((t || 'success') + ': ' + m); };
var mounts = {};
CK.registerTool = function (id, fn) { mounts[id] = fn; };
['hash', 'markdown', 'qr', 'x509', 'aes', 'kdf', 'totp', 'signature'].forEach(function (t) { load('assets/js/tools/' + t + '.js'); });

function all(n, out) { out = out || []; out.push(n); n.children.forEach(function (c) { all(c, out); }); return out; }
function mount(id) {
  var root = new Node('div'); mounts[id](root, { toast: CK.toast });
  var nodes = all(root);
  return {
    root: root,
    tas: nodes.filter(function (n) { return n.tagName === 'TEXTAREA'; }),
    field: function (label) { var f = nodes.filter(function (n) { return n.className === 'field' && n.children[0]._text === label; })[0]; return f && f.children[1]; },
    prim: function (label) { return nodes.filter(function (n) { return /^prim/.test(n.className) && n.textContent === label; })[0]; },
    byTitle: function (t) { return nodes.filter(function (n) { return n.title === t; })[0]; },
    byClass: function (c) { return all(root).filter(function (n) { return n.classList.contains(c); })[0]; }
  };
}
function set(el, v) { el.value = v; el.fire(el.tagName === 'SELECT' ? 'change' : 'input'); }
function last() { return toasts[toasts.length - 1] || ''; }
var hex = function (b) { return Buffer.from(b).toString('hex'); };

(async function () {
  /* Shared helpers (core.js) */
  ok(hex(CK.hexToBytes('de:ad be-ef')) === 'deadbeef', 'hex accepts : space - separators');
  ok(hex(CK.hexToBytes('0x41 0x42')) === '4142' && hex(CK.hexToBytes('\\x41\\x42')) === '4142', 'hex accepts 0x and \\x prefixes');
  ['hello', 'abc', '0g', '10x5'].forEach(function (s) { var t = false; try { CK.hexToBytes(s); } catch (e) { t = /Invalid hexadecimal/.test(e.message); } ok(t, 'hex rejects ' + JSON.stringify(s)); });
  var b64err = ''; try { CK.unb64('!!!!'); } catch (e) { b64err = e.message; }
  ok(b64err === 'Invalid Base64', 'unb64 rejects garbage with a clean message');
  ok(hex(CK.unb64('-_8')) === 'fbff', 'unb64 accepts Base64URL');
  ok(CK.b64uDec(CK.b64uEnc('ünï ✓ {"a":1}')) === 'ünï ✓ {"a":1}', 'share-link encoding round-trips Unicode');
  var sec = CK.randomSecret(200, 'utf8');
  ok(sec.length === 200 && /^[\x21-\x7e]+$/.test(sec), 'randomSecret: printable ASCII of the requested length');
  ok(/^[0-9a-f]{32}$/.test(CK.randomSecret(16, 'hex')), 'randomSecret hex: 16 bytes');
  // b % 94 without rejection makes the first 68 characters 1.5x as likely as the last 26
  var cnt = new Array(127).fill(0); CK.randomSecret(94000, 'utf8').split('').forEach(function (ch) { cnt[ch.charCodeAt(0)]++; });
  var lo = cnt.slice(33, 101).reduce(function (a, b) { return a + b; }) / 68, hi = cnt.slice(101, 127).reduce(function (a, b) { return a + b; }) / 26;
  ok(lo / hi < 1.1, 'randomSecret: characters are evenly distributed (ratio ' + (lo / hi).toFixed(2) + ')');

  /* Hash: invalid hex is an error, not a hash of nothing */
  var H = mount('hash');
  set(H.field('Input format'), 'hex'); set(H.tas[0], 'hello');
  H.prim('Hash').fire('click'); await sleep(50);
  ok(/error: Invalid hexadecimal/.test(last()) && H.tas[1].value === '', 'hash: hex "hello" is rejected');
  set(H.tas[0], '68 65 6c 6c 6f'); H.prim('Hash').fire('click');
  await until(function () { return H.tas[1].value; });
  ok(H.tas[1].value === nc.createHash('sha256').update('hello').digest('hex'), 'hash: valid hex hashes the right bytes');

  /* Markdown: alt text cannot break out of its attribute */
  var M = mount('markdown');
  set(M.tas[0], '![x" onerror="alert(1)](a.png) and `code`');
  var html = M.byClass('md-preview').innerHTML;
  ok(html.indexOf('" onerror="') < 0 && html.indexOf('alt="x&quot; onerror=&quot;alert(1)"') > 0, 'markdown: quote in alt text is escaped');
  ok(html.indexOf('<code>code</code>') > 0, 'markdown: code spans still render');

  /* QR: colours cannot inject markup */
  var Q = mount('qr');
  set(Q.tas[0], 'hi'); set(Q.field('Foreground'), '"/><image href="x" onerror="alert(1)"/>');
  var svg = Q.byClass('qr-box').innerHTML;
  ok(svg.indexOf('onerror') < 0 && svg.indexOf('fill="#000000"') > 0, 'qr: unsafe colour falls back to the default');

  /* X.509: a length pointing past the data is an error (unchecked, a 4 GB claim loops for minutes) */
  var X = mount('x509');
  set(X.tas[0], '-----BEGIN CERTIFICATE-----\nMIQAEAAA\n-----END CERTIFICATE-----'); // SEQUENCE claiming 1 MB, 0 bytes present
  X.prim('Decode').fire('click');
  ok(/Parse failed: Truncated or invalid certificate/.test(last()), 'x509: length past the end of the data is rejected');

  /* AES: short IV and bad key length are errors; a valid key/IV matches standard AES */
  var A = mount('aes'), keyIn = A.field('Key').children[0], ivIn = A.field('Initialization Vector').children[0];
  set(A.field('Initialization Vector').children[1], 'utf8');
  set(keyIn, '0123456789abcdef0123456789abcdef'); set(ivIn, '1234'); set(A.tas[0], 'hello world');
  A.prim('Encrypt').fire('click');
  ok(/IV must be 16 bytes for CBC \(got 4\)/.test(last()), 'aes: 4-byte IV rejected');
  set(ivIn, 'abcdefghijklmnop'); A.prim('Encrypt').fire('click');
  var c = nc.createCipheriv('aes-256-cbc', Buffer.from('0123456789abcdef0123456789abcdef'), Buffer.from('abcdefghijklmnop'));
  ok(A.tas[1].value === Buffer.concat([c.update('hello world'), c.final()]).toString('base64'), 'aes: CBC output matches Node');
  set(keyIn, 'secret'); set(A.tas[0], A.tas[1].value); A.prim('Decrypt').fire('click');
  ok(/Key must be 16, 24, or 32 bytes \(got 6\)/.test(last()), 'aes: decrypt checks key length too');

  /* scrypt: RFC 7914 test vector 2 */
  var K = mount('kdf');
  set(K.field('Algorithm'), 'scrypt'); set(K.field('Cost (N)'), '10'); set(K.field('Block (r)'), '8'); set(K.field('Parallel (p)'), '16');
  set(K.field('Salt').children[1], 'utf8'); set(K.field('Salt').children[0], 'NaCl');
  var len = all(K.root).filter(function (n) { return n.tagName === 'INPUT' && n.attrs.max === '1024'; })[0]; set(len, '64');
  set(K.tas[0], 'password'); K.prim('Derive').fire('click');
  await until(function () { return K.tas[1].value; }, 20000);
  ok(K.tas[1].value === 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640', 'scrypt: RFC 7914 vector');

  /* HOTP RFC 4226 and TOTP RFC 6238 (SHA-1) */
  var realNow = Date.now; Date.now = function () { return 59000; };
  var T = mount('totp');
  set(T.field('Secret format'), 'utf8'); set(T.tas[0], '12345678901234567890');
  set(T.field('Digits'), '8'); await until(function () { return T.tas[1].value.length === 8; });
  ok(T.tas[1].value === '94287082', 'totp: RFC 6238 at t=59');
  set(T.field('Mode'), 'hotp'); set(T.field('Digits'), '6');
  var hotp = [];
  for (var n = 0; n < 3; n++) { set(T.field('Counter'), String(n)); await until(function () { return T.tas[1].value.length === 6; }); await sleep(30); hotp.push(T.tas[1].value); }
  ok(hotp.join(',') === '755224,287082,359152', 'hotp: RFC 4226 counters 0-2');
  Date.now = realNow;

  /* Ed25519 RFC 8032 test 2 (deterministic) and ECDSA P-256 DER checked by Node */
  var S = mount('signature');
  var pemOf = function (label, h) { return '-----BEGIN ' + label + '-----\n' + Buffer.from(h, 'hex').toString('base64') + '\n-----END ' + label + '-----'; };
  set(S.field('Algorithm'), 'Ed25519'); set(S.field('Signature format'), 'hex');
  set(S.field('Private key').children[0], pemOf('PRIVATE KEY', '302e020100300506032b657004220420' + '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'));
  set(S.tas[0], 'r'); S.prim('Sign').fire('click');
  await until(function () { return S.tas[1].value; });
  ok(S.tas[1].value === '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00', 'ed25519: RFC 8032 test 2');
  var kp = nc.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  set(S.field('Algorithm'), 'P-256'); set(S.field('Signature encoding'), 'der'); set(S.field('Signature format'), 'base64');
  set(S.field('Private key').children[0], kp.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  var derOk = true;
  for (var i = 0; i < 20; i++) {
    S.tas[1].value = ''; set(S.tas[0], 'msg ' + i); S.prim('Sign').fire('click');
    await until(function () { return S.tas[1].value; });
    if (!nc.verify('sha256', Buffer.from('msg ' + i), { key: kp.publicKey, dsaEncoding: 'der' }, Buffer.from(S.tas[1].value, 'base64'))) derOk = false;
  }
  ok(derOk, 'ecdsa: 20 DER signatures verify in Node');

  console.log((fails ? fails + ' FAILED, ' : '') + passes + ' passed');
  process.exit(fails ? 1 : 0);
})().catch(function (e) { console.log('CRASH', e); process.exit(1); });
