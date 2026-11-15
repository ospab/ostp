// Run with plain node, no framework: node ostp-gui/test/server_pk.test.mjs
import assert from 'node:assert/strict';
import { checkServerKey, linkPk, protocolLabel } from '../src/server_pk.js';

const good = Buffer.alloc(32, 1).toString('base64url');
const other = Buffer.from(Array.from({ length: 32 }, (_, i) => i * 8 + 3)).toString('base64url');
let count = 0;
const test = (name, fn) => { fn(); count += 1; console.log('ok  ' + name); };

test('a key of 32 bytes in base64url is accepted as written', () => {
  assert.equal(good.length, 43);
  assert.equal(checkServerKey(good), good);
  assert.equal(checkServerKey(other), other);
  assert.equal(checkServerKey(`  ${good}\n`), good, 'whitespace around it is ignored');
});

test('every key the core can make round-trips (random keys, including - and _)', () => {
  let sawDash = false;
  for (let i = 0; i < 300; i++) {
    const k = Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))).toString('base64url');
    sawDash ||= /[-_]/.test(k);
    assert.equal(checkServerKey(k), k);
  }
  assert.ok(sawDash, 'the sample must have covered the url-safe characters');
});

test('a damaged key is an error, never a quiet v5 profile', () => {
  for (const bad of [
    good.slice(0, 42),
    `${good}A`,
    `${good.slice(0, 42)}!`,
    '%%%',
    '',
    `${good}=`,
    good.replace(/.$/, 'B'), // last character with non-zero spare bits
    Buffer.alloc(32, 1).toString('base64'), // standard alphabet with padding
  ]) {
    assert.throws(() => checkServerKey(bad), Error, `pk=${JSON.stringify(bad)} should be refused`);
  }
});

test('the messages say what is wrong', () => {
  assert.match(
    (() => { try { checkServerKey(good.slice(0, 42)); } catch (e) { return e.message; } })(),
    /32 bytes/,
  );
  assert.match(
    (() => { try { checkServerKey('%%%'); } catch (e) { return e.message; } })(),
    /base64url/,
  );
});

test('a link names itself in the error', () => {
  assert.equal(linkPk(good), good);
  assert.throws(() => linkPk('nope!'), /The link has an invalid server key \(pk\): .*base64url/);
});

test('the protocol of a profile follows its key', () => {
  assert.equal(protocolLabel({ server_pk: good }), 'v6');
  assert.equal(protocolLabel({ server_pk: '' }), 'v5');
  assert.equal(protocolLabel({}), 'v5');
  assert.equal(protocolLabel(null), 'v5');
});

console.log(`${count} tests passed`);
