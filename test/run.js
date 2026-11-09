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
Node.prototype.dispatchEvent = function (e) { for (var n = this; n; n = e.bubbles ? n.parentNode : null) (n.listeners[e.type] || []).forEach(function (f) { f(e); }); return true; };
Node.prototype.fire = function (t, extra) { var e = Object.assign({ target: this, preventDefault: function () {}, stopPropagation: function () {} }, extra || {}); (this.listeners[t] || []).forEach(function (f) { f(e); }); };
Node.prototype.focus = function () {};
Node.prototype.closest = function (sel) { var c = sel.replace('.', ''); for (var n = this; n; n = n.parentNode) if (n.classList && n.classList.contains(c)) return n; return null; };
Object.defineProperty(Node.prototype, 'options', { get: function () { return this.children.filter(function (c) { return c.tagName === 'OPTION'; }); } });
Object.defineProperty(Node.prototype, 'firstChild', { get: function () { return this.children[0] || null; } });
Object.defineProperty(Node.prototype, 'innerHTML', { get: function () { return this._html || ''; }, set: function (v) { this._html = v; this.children = []; if (/class="lbl"/.test(v)) { var l = new Node('span'); l.className = 'lbl'; this.children.push(l); } } });
Object.defineProperty(Node.prototype, 'textContent', { get: function () { return this._text || this._html || ''; }, set: function (v) { this._text = v; } });
Node.prototype.querySelector = function (sel) { var cls = sel.charAt(0) === '.' ? sel.slice(1) : null, q = this.children.slice(); while (q.length) { var n = q.shift(); if (cls ? n.classList.contains(cls) : n.tagName === sel.toUpperCase()) return n; q = q.concat(n.children); } return null; };
// Supports the '.ancestor tag[attr=value], ...' selectors the app uses
Node.prototype.querySelectorAll = function (sel) {
  var parts = sel.split(',').map(function (p) { return /^\s*\.([\w-]+)\s+(\w+)(?:\[(\w+)=([\w-]+)\])?\s*$/.exec(p); }), out = [], self = this;
  (function walk(n) { n.children.forEach(function (c) {
    if (parts.some(function (m) { if (!m || c.tagName !== m[2].toUpperCase() || (m[3] && c.attrs[m[3]] !== m[4])) return false; for (var p = c.parentNode; p && p !== self.parentNode; p = p.parentNode) if (p.classList && p.classList.contains(m[1])) return true; return false; })) out.push(c);
    walk(c); }); })(this);
  return out;
};
global.HTMLTextAreaElement = function () {};
Object.defineProperty(HTMLTextAreaElement.prototype, 'value', { configurable: true, get: function () { return this._v || ''; }, set: function (v) { this._v = String(v); } });
global.window = global;
global.document = { createElement: function (t) { return new Node(t); }, createTextNode: function (t) { var n = new Node('#text'); n._text = t; return n; }, body: new Node('body'), documentElement: new Node('html'), getElementById: function () { return null; }, addEventListener: function () {} };
global.location = { hash: '', href: 'https://x.test/' };
var LS = {}; global.localStorage = { getItem: function (k) { return k in LS ? LS[k] : null; }, setItem: function (k, v) { LS[k] = String(v); } };
var clip = null; Object.defineProperty(global.navigator, 'clipboard', { configurable: true, value: { writeText: function (t) { clip = t; return Promise.resolve(); } } });

/* ---- Load the real app ---- */
function load(p) { vm.runInThisContext(fs.readFileSync(path.join(ROOT, p), 'utf8'), { filename: p }); }
global.CryptoJS = require(path.join(ROOT, 'assets/js/vendor/crypto-js.min.js'));
['assets/js/core.js', 'assets/js/ui.js', 'assets/js/vendor/hashlib.js', 'assets/js/vendor/qrcode.min.js'].forEach(load);
var toasts = [];
CK.toast = function (m, t) { toasts.push((t || 'success') + ': ' + m); };
var mounts = {};
CK.registerTool = function (id, fn) { mounts[id] = fn; };
['hash', 'checksum', 'jwt', 'text', 'encode', 'markdown', 'qr', 'x509', 'aes', 'kdf', 'totp', 'signature'].forEach(function (t) { load('assets/js/tools/' + t + '.js'); });

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

  ok(CK.b64u([251, 255, 255]) === '-___' && hex(CK.textBytes('6869', 'hex')) === '6869' && hex(CK.textBytes('aGk=', 'base64')) === '6869' && hex(CK.textBytes('hi', 'utf8')) === '6869', 'b64u and textBytes formats');
  ok(CK.detectFmt('deadbeef') === 'hex' && CK.detectFmt('aGVsbG8=') === 'base64' && CK.detectFmt('hello!') === 'utf8' && CK.fmtByteLen('aGVsbG8=', 'base64') === 5, 'detectFmt and fmtByteLen');
  ok(CK.ipStr(0xC0A80001) === '192.168.0.1' && [0, 0, 0, 0, 0].every(function () { var r = CK.randInt(7); return r >= 0 && r < 7 && r === Math.floor(r); }), 'ipStr and randInt');

  /* Encoder: Base64URL and JWT go through the shared helpers */
  var E = mount('encode'), U = 'hüllö ✓ ??>';
  set(E.field('Bases'), 'base64url'); set(E.tas[0], U); E.prim('Encode').fire('click');
  ok(E.tas[1].value === CK.b64uEnc(U) && !/[+/=]/.test(E.tas[1].value), 'encode: Base64URL has no + / =');
  set(E.tas[0], E.tas[1].value); E.prim('Decode').fire('click');
  ok(E.tas[1].value === U, 'encode: Base64URL round-trips Unicode');
  set(E.field('Web'), 'jwt'); set(E.tas[0], '{"name":"Jürgen"}'); E.prim('Encode').fire('click');
  set(E.tas[0], E.tas[1].value); E.prim('Decode').fire('click');
  ok(/"name": "Jürgen"/.test(E.tas[1].value) && /"alg": "none"/.test(E.tas[1].value), 'encode: JWT decode reads UTF-8 payloads');

  /* Hash: invalid hex is an error, not a hash of nothing */
  var H = mount('hash');
  set(H.field('Input format'), 'hex'); set(H.tas[0], 'hello');
  H.prim('Hash').fire('click'); await sleep(50);
  ok(/error: Invalid hexadecimal/.test(last()) && H.tas[1].value === '', 'hash: hex "hello" is rejected');
  set(H.tas[0], '68 65 6c 6c 6f'); H.prim('Hash').fire('click');
  await until(function () { return H.tas[1].value; });
  ok(H.tas[1].value === nc.createHash('sha256').update('hello').digest('hex'), 'hash: valid hex hashes the right bytes');

  /* File Checksum: one algorithm at a time; Verify checks the output panel against it */
  var C = mount('checksum'), out = C.tas[0], picker = all(C.root).filter(function (n) { return n.attrs.type === 'file'; })[0];
  var h = function (a) { return nc.createHash(a).update('hello').digest('hex'); };
  picker.files = [new File(['hello'], 'hello.txt')]; picker.fire('change');
  await until(function () { return out.value; });
  ok(out.value === h('sha256'), 'checksum: SHA-256 of the file by default');
  set(C.field('Output format'), 'HEX');
  ok(out.value === h('sha256').toUpperCase(), 'checksum: format change rewrites its own output');
  set(out, h('md5')); C.byTitle('Verify').fire('click'); await sleep(50);
  ok(/No match: SHA-256 is 32 bytes, this is 16 bytes \(that length is MD5\)/.test(last()), 'checksum: wrong-length value names the algorithm it fits');
  set(C.field('Algorithm'), 'md5'); await sleep(50);
  ok(/Match: MD5 of hello\.txt/.test(last()) && out.value === h('md5'), 'checksum: switching algorithm verifies a pasted value instead of overwriting it');
  set(out, h('md5').toUpperCase() + '  hello.txt'); C.byTitle('Verify').fire('click'); await sleep(50);
  ok(/Match: MD5/.test(last()), 'checksum: sha256sum-style "HASH  filename" line verifies');
  set(out, ''); set(C.field('Algorithm'), 'sha1'); await until(function () { return out.value; });
  ok(out.value === h('sha1').toUpperCase(), 'checksum: empty output is filled for the newly selected algorithm');

  /* JWT alg "none": unsigned token, no secret needed */
  var J = mount('jwt'), algoSel = J.field('Algorithm');
  set(algoSel, 'none');
  ok(J.field('Secret').parentNode.style.display === 'none', 'jwt none: secret field hidden');
  set(J.tas[0], '{"sub":"x"}'); J.prim('Sign').fire('click'); await sleep(50);
  var tok = J.tas[1].value, parts = tok.split('.');
  ok(parts.length === 3 && parts[2] === '' && JSON.parse(Buffer.from(parts[0], 'base64url')).alg === 'none' && JSON.parse(Buffer.from(parts[1], 'base64url')).sub === 'x', 'jwt none: signs to header.payload. without a secret');
  set(algoSel, 'HS256'); set(J.tas[0], tok); J.prim('Decode').fire('click');
  ok(algoSel.value === 'none', 'jwt none: decoding an alg-none token selects none');
  J.byTitle('Verify').fire('click'); await sleep(50);
  ok(/Token is unsigned \(alg none\)/.test(last()), 'jwt none: Verify reports the token as unsigned');

  /* JWT Swap: decoded output comes back as signable { header, payload } JSON */
  var JIO = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  var J2 = mount('jwt');
  set(J2.tas[0], JIO); J2.prim('Decode').fire('click');
  J2.byTitle('Swap').fire('click');
  var doc = null; try { doc = JSON.parse(J2.tas[0].value); } catch (e) { }
  ok(doc && doc.header.alg === 'HS256' && doc.payload.name === 'John Doe' && J2.tas[1].value === '', 'jwt swap: decoded view becomes { header, payload } JSON, output cleared');
  set(J2.field('Secret').children[0], 'your-256-bit-secret'); J2.prim('Sign').fire('click');
  await until(function () { return J2.tas[1].value; });
  ok(J2.tas[1].value === JIO, 'jwt swap: the swapped JSON re-signs to the original jwt.io token');
  J2.byTitle('Swap').fire('click');
  ok(J2.tas[0].value === JIO && J2.tas[1].value === '', 'jwt swap: a token in the output moves as-is');

  /* JWT ES256 / ES384 / EdDSA, cross-checked with Node's crypto */
  var J3 = mount('jwt'), sel3 = J3.field('Algorithm'), pubIn = J3.field('Public key').children[0], privIn = J3.field('Private key').children[0];
  function jwtParts(t) { var p = t.split('.'); return { h: JSON.parse(Buffer.from(p[0], 'base64url')), si: p[0] + '.' + p[1], sig: Buffer.from(p[2], 'base64url') }; }
  var ec = nc.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  set(sel3, 'ES256'); set(privIn, ec.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  set(J3.tas[0], '{"sub":"es"}'); J3.prim('Sign').fire('click'); await until(function () { return J3.tas[1].value; });
  var e1 = jwtParts(J3.tas[1].value);
  ok(e1.h.alg === 'ES256' && e1.sig.length === 64 && nc.verify('sha256', Buffer.from(e1.si), { key: ec.publicKey, dsaEncoding: 'ieee-p1363' }, e1.sig), 'jwt ES256: tool signs, Node verifies (64-byte raw r||s)');
  var ed = nc.generateKeyPairSync('ed25519');
  J3.tas[1].value = ''; set(sel3, 'EdDSA'); set(privIn, JSON.stringify(ed.privateKey.export({ format: 'jwk' })));
  set(J3.tas[0], '{"sub":"ed"}'); J3.prim('Sign').fire('click'); await until(function () { return J3.tas[1].value; });
  var e2 = jwtParts(J3.tas[1].value);
  ok(e2.h.alg === 'EdDSA' && nc.verify(null, Buffer.from(e2.si), ed.publicKey, e2.sig), 'jwt EdDSA: signs with a JWK private key, Node verifies');
  var ec384 = nc.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  var si384 = Buffer.from('{"alg":"ES384","typ":"JWT"}').toString('base64url') + '.' + Buffer.from('{"sub":"node"}').toString('base64url');
  var nodeTok = si384 + '.' + nc.sign('sha384', Buffer.from(si384), { key: ec384.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  set(sel3, 'HS256'); set(J3.tas[0], nodeTok); J3.prim('Decode').fire('click');
  ok(sel3.value === 'ES384', 'jwt ES384: decoding selects ES384');
  set(pubIn, ec384.publicKey.export({ type: 'spki', format: 'pem' })); J3.byTitle('Verify').fire('click'); await sleep(150);
  ok(/Signature valid \(ES384\)/.test(last()), 'jwt ES384: Node-signed token verifies in the tool');

  /* Settings are remembered per tool; text fields (keys, inputs) never are */
  var cbOf = function (r) { return all(r).filter(function (n) { return n.attrs.type === 'checkbox'; })[0]; };
  var S1 = mount('hash'); CK.rememberSettings('hash', S1.root);
  set(S1.field('SHA-2'), 'sha512'); set(S1.field('Output format'), 'base64');
  var hm = cbOf(S1.root); hm.checked = true; hm.fire('change');
  set(S1.field('HMAC key').children[0], 'topsecret');
  S1.root.dispatchEvent(new Event('change', { bubbles: true })); await sleep(350);
  var saved = LS['ck.cfg.hash'] || '';
  ok(saved.indexOf('sha512') >= 0 && saved.indexOf('topsecret') < 0, 'settings: saved, but never the HMAC key text');
  var S2 = mount('hash'); CK.rememberSettings('hash', S2.root);
  ok(S2.field('SHA-2').value === 'sha512' && S2.field('Output format').value === 'base64' && cbOf(S2.root).checked && S2.field('HMAC key').children[0].value === '', 'settings: restored on the next visit, key field stays empty');
  location.hash = '#tool=hash&s=abc';
  var S3 = mount('hash'); CK.rememberSettings('hash', S3.root);
  ok(S3.field('SHA-2').value === 'sha256', 'settings: a share link takes precedence over saved settings');
  location.hash = '';

  /* Share links leave secrets out unless the user includes them */
  var shared = function () { return JSON.parse(CK.b64uDec(clip.split('&s=')[1])); };
  clip = null; CK.share('aes', { k: 'mykey', m: 'CBC' }, { k: 'key' }); await sleep(20);
  ok(clip && !('k' in shared()) && shared().m === 'CBC', 'share: secret left out by default');
  var acts = all(document.body).filter(function (n) { return n.className === 'toast-act'; });
  acts[acts.length - 1].fire('click'); await sleep(20);
  ok(shared().k === 'mykey', 'share: "Include it" copies the link with the secret');
  clip = null; CK.share('cidr', { in: '10.0.0.0/8' }); await sleep(20);
  ok(shared().in === '10.0.0.0/8', 'share: links without secrets copy as they are');

  /* Text Cleaner: Clean */
  var X = mount('text'), xin = X.tas[0], xout = X.tas[1], ch = String.fromCharCode;
  var swOf = function (r, label) { return all(r).filter(function (n) { return n.className === 'switch' && n.children[2] && n.children[2].textContent === label; })[0].children[0]; };
  var tick = function (label, on) { var cb = swOf(X.root, label); cb.checked = on; cb.fire('change'); };
  tick('Remove blank lines', true); tick('Remove duplicate lines', true); tick('Strip HTML tags', true); tick('Plain ASCII punctuation', true);
  set(xin, '  Hello' + ch(0x200B) + '   world  \n\nHello world\n' + ch(0x202E) + 'doc\n<b>Bold</b> &amp; ' + ch(0x201C) + 'quoted' + ch(0x201D) + ' ' + ch(0x2014) + ' done' + ch(0x2026) + '\n');
  ok(xout.value === 'Hello world\ndoc\nBold & "quoted" - done...', 'text clean: invisible chars, spaces, blank + duplicate lines, HTML, punctuation');
  ok(/1 duplicate removed, 2 invisible characters removed/.test(X.root.querySelector('.sel-desc').textContent), 'text clean: reports duplicates and invisible characters removed');
  set(X.field('Case'), 'snake'); set(xin, 'Hello World fooBar');
  ok(xout.value === 'hello_world_foo_bar', 'text clean: snake_case splits words and camelCase humps');
  set(X.field('Case'), 'camel'); set(xin, 'hello world-api');
  ok(xout.value === 'helloWorldApi', 'text clean: camelCase');
  set(X.field('Case'), 'none');

  /* Text Cleaner: Extract */
  var h64 = 'a'.repeat(10) + '0123456789abcdef'.repeat(3) + 'abcdef', h32 = '0123456789abcdef'.repeat(2);
  var log = 'user a.b@example.com from 10.0.0.5 (see https://example.com/path?q=1). Version 1.2.3.4.5 at 10:30:00 mac 00:1a:2b:3c:4d:5e ' +
    'v6 2001:db8::1 and fe80::1ff:fe23:4567:890a id 123e4567-e89b-12d3-a456-426614174000 tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc ' +
    'sha ' + h64 + ' md5 ' + h32 + ' again 10.0.0.5 msg aGVsbG8gd29ybGQ= word Authentication2 hex 0x48656c6c6f20776f726c64 ts 1700000000' +
    ' path random/maxObserveMousemove sp 48 69 20 74 68 65 72 65 esc \\x48\\x69\\x21\\x21 col 4f:4b:21:21';
  set(X.field('Mode'), 'extract'); set(xin, log);
  var find = function (t) { set(X.field('Find'), t); return xout.value; };
  ok(find('emails') === 'a.b@example.com', 'text extract: email');
  ok(find('urls') === 'https://example.com/path?q=1', 'text extract: URL without trailing ").');
  ok(find('domains') === 'example.com', 'text extract: domains from URLs and emails, de-duplicated');
  ok(find('ipv4') === '10.0.0.5', 'text extract: IPv4 (unique), version string 1.2.3.4.5 ignored');
  ok(find('ipv6') === '2001:db8::1\nfe80::1ff:fe23:4567:890a', 'text extract: IPv6, not a time or a MAC address');
  ok(find('uuids') === '123e4567-e89b-12d3-a456-426614174000' && /^eyJ/.test(find('jwts')), 'text extract: UUID and JWT');
  ok(find('hashes') === 'SHA-256  ' + h64 + '\nMD5  ' + h32, 'text extract: hashes labelled by length');
  ok(find('base64') === 'aGVsbG8gd29ybGQ=  ->  hello world', 'text extract: Base64 decoded; JWT, URL, hashes and short words skipped');
  ok(find('hex') === '0x48656c6c6f20776f726c64  ->  Hello world\n48 69 20 74 68 65 72 65  ->  Hi there\n\\x48\\x69\\x21\\x21  ->  Hi!!\n4f:4b:21:21  ->  OK!!',
    'text extract: hex plain, spaced, \\x and colon, decoded; hashes, UUID, MAC, IPv6, time and plain numbers skipped');
  tick('Show counts', true);
  ok(find('ipv4') === '   2x  10.0.0.5', 'text extract: counts');
  tick('Show counts', false);

  /* Text Cleaner: Redact */
  var secretText = 'mail bob@corp.com from 192.168.1.10 key AKIAIOSFODNN7EXAMPLE gh ghp_' + 'A1b2C3d4E5'.repeat(4) +
    ' card 4111 1111 1111 1111 not 1234 5678 9012 3456 auth: Bearer abcdefghijklmnop1234 url https://admin:hunter2@host.example/x\n' +
    '-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----';
  set(X.field('Mode'), 'redact'); set(xin, secretText);
  var red = xout.value;
  ok(['[EMAIL]', '[IP]', '[AWS KEY]', '[GITHUB TOKEN]', '[CARD]', 'Bearer [TOKEN]', 'admin:[PASSWORD]@host', '[PRIVATE KEY]'].every(function (t) { return red.indexOf(t) >= 0; }) &&
    !/bob@|192\.168|AKIA|ghp_|4111|hunter2|MIIabc/.test(red), 'text redact: every category hidden');
  ok(red.indexOf('1234 5678 9012 3456') >= 0, 'text redact: a number failing the Luhn check is kept');
  ok(/Hid .*1 card number.*1 email.*1 IP address/.test(X.root.querySelector('.sel-desc').textContent), 'text redact: summary of what was hidden');
  clip = null; X.byTitle('Share').fire('click'); await sleep(20);
  ok(clip && !('in' in shared()) && shared().m === 'redact', 'text share: the text itself is left out by default');

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
  // Codes are computed asynchronously, so wait for the expected one (a wrong code times out and fails)
  var want = ['755224', '287082', '359152'], hotp = [];
  for (var n = 0; n < 3; n++) { set(T.field('Counter'), String(n)); await until(function () { return T.tas[1].value === want[n]; }); hotp.push(T.tas[1].value); }
  ok(hotp.join(',') === want.join(','), 'hotp: RFC 4226 counters 0-2');
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

  /* Offline cache: everything the app loads is precached, and a changed precached file needs a new CACHE version */
  var swSrc = fs.readFileSync(path.join(ROOT, 'sw.js'), 'utf8'), idx = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  var ASSETS = JSON.parse(swSrc.match(/var ASSETS = (\[[\s\S]*?\]);/)[1].replace(/'/g, '"'));
  var refs = (idx.match(/(?:src|href)="(assets\/[^"]+|manifest\.webmanifest)"/g) || []).map(function (r) { return r.replace(/^(?:src|href)="|"$/g, ''); }).concat(['assets/preview.html']);
  var notCached = refs.filter(function (r) { return ASSETS.indexOf(r) < 0; });
  ok(!notCached.length, 'sw.js precaches every file index.html loads' + (notCached.length ? ' (missing: ' + notCached.join(', ') + ')' : ''));
  var missing = ASSETS.filter(function (a) { return a !== './' && !fs.existsSync(path.join(ROOT, a)); });
  ok(!missing.length, 'every precached file exists' + (missing.length ? ' (missing: ' + missing.join(', ') + ')' : ''));
  try {
    var git = function () { return require('child_process').execFileSync('git', [].slice.call(arguments), { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); };
    var changed = (git('diff', '--name-only', 'HEAD') + git('ls-files', '--others', '--exclude-standard')).split(/\r?\n/).filter(Boolean);
    var cachedChanged = changed.filter(function (f) { return f === 'index.html' || ASSETS.indexOf(f) >= 0; });
    var headCache = (git('show', 'HEAD:sw.js').match(/var CACHE = '([^']+)'/) || [])[1], nowCache = swSrc.match(/var CACHE = '([^']+)'/)[1];
    ok(!cachedChanged.length || nowCache !== headCache, 'CACHE version bumped for changed precached files' +
      (cachedChanged.length && nowCache === headCache ? ' (still ' + nowCache + '; changed: ' + cachedChanged.slice(0, 5).join(', ') + ')' : ''));
  } catch (e) { console.log('skip: cache-bump check needs git'); }

  console.log((fails ? fails + ' FAILED, ' : '') + passes + ' passed');
  process.exit(fails ? 1 : 0);
})().catch(function (e) { console.log('CRASH', e); process.exit(1); });
