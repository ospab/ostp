// Run with plain node, no framework: node ostp-gui/test/markdown.test.mjs
import assert from 'node:assert/strict';
import { parseMarkdown, parseInline, safeUrl } from '../src/markdown.js';
import { normalizeServerInfo, subscriptionExpiry, expiryLabel, isKeyExpiredReason } from '../src/server_info.js';

let count = 0;
const test = (name, fn) => { fn(); count += 1; console.log('ok  ' + name); };

test('headings, paragraphs, lists and code blocks', () => {
  const b = parseMarkdown('# Title\n\nFirst line\nsame paragraph\n\n- one\n- two\n  more\n\n1. a\n2. b\n\n```\n<b>x</b>\n```\n### Small');
  assert.deepEqual(b.map(x => x.t), ['h', 'p', 'ul', 'ol', 'code', 'h']);
  assert.equal(b[0].level, 1);
  assert.equal(b[1].inl[0].text, 'First line same paragraph');
  assert.equal(b[2].items.length, 2);
  assert.equal(b[2].items[1][0].text, 'two more');
  assert.equal(b[4].text, '<b>x</b>');
  assert.equal(b[5].level, 3);
});

test('bold, italic, code and links inline', () => {
  const n = parseInline('a **b** *c* `d` [e](https://x.org/y)');
  assert.deepEqual(n.map(x => x.t), ['text', 'text', 'text', 'text', 'text', 'code', 'text', 'link']);
  assert.equal(n[1].b, true);
  assert.equal(n[3].i, true);
  assert.equal(n[7].url, 'https://x.org/y');
});

test('HTML and unknown syntax stay as text', () => {
  const n = parseInline('<script>alert(1)</script> <img src=x onerror=y>');
  assert.equal(n.length, 1);
  assert.equal(n[0].text, '<script>alert(1)</script> <img src=x onerror=y>');
  assert.equal(parseMarkdown('#### four')[0].t, 'p');
  assert.equal(parseInline('2 * 3 * 4')[0].text, '2 * 3 * 4');
  assert.equal(parseInline('**open')[0].text, '**open');
});

test('only http, https, mailto and tg links become links', () => {
  for (const u of ['https://a.b', 'http://a.b', 'mailto:x@y.z', 'tg://resolve?domain=x']) assert.equal(safeUrl(u), u);
  for (const u of ['javascript:alert(1)', 'data:text/html,x', 'file:///etc', 'https://a b', 'vbscript:x', '//a.b']) assert.equal(safeUrl(u), null);
  const n = parseInline('[x](javascript:alert(1))');
  assert.ok(n.every(x => x.t === 'text'));
});

test('server info keeps only known fields of the right type', () => {
  assert.equal(normalizeServerInfo(''), null);
  assert.equal(normalizeServerInfo('{bad'), null);
  const v = normalizeServerInfo(JSON.stringify({
    operator: { name: 'Op', about: 5 }, server: { carriers: ['udp', 7], ipv6: 'yes', log_privacy: 'loud' },
    key: { used_bytes: 10, limit_bytes: null, expires_at: 2000000000 }, extra: 1,
  }));
  assert.deepEqual(v.operator, { name: 'Op', location: null, contact: null, about: null });
  assert.deepEqual(v.server.carriers, ['udp']);
  assert.equal(v.server.ipv6, null);
  assert.equal(v.server.log_privacy, null);
  assert.equal(v.key.expires_at, 2000000000);
  assert.equal(v.extra, undefined);
});

test('expiry: date, days left, expired', () => {
  const now = Date.UTC(2026, 11, 28, 12);
  const end = Date.UTC(2026, 11, 31, 23, 59, 59) / 1000;
  const e = subscriptionExpiry({ serverInfo: { key: { expires_at: end } } }, now);
  assert.equal(expiryLabel(e), 'until 2026-12-31, 4 days left');
  assert.equal(expiryLabel(subscriptionExpiry({ serverInfo: { key: { expires_at: end } } }, now - 30 * 86400000)), 'until 2026-12-31');
  assert.equal(expiryLabel(subscriptionExpiry({ serverInfo: { key: { expires_at: end } } }, now + 5 * 86400000)), 'expired');
  assert.equal(subscriptionExpiry({}, now), null);
  assert.equal(expiryLabel(subscriptionExpiry({ keyExpired: true }, now)), 'expired');
  assert.ok(isKeyExpiredReason('The server closed the connection: this access key expired on 2026-12-31.'));
  assert.ok(!isKeyExpiredReason('The server closed the connection: the traffic limit is used up.'));
});

console.log(`${count} tests passed`);
