// Run with plain node, no framework: node ostp-gui/test/key_pin.test.mjs
import assert from 'node:assert/strict';
import { pinAction, pinKey } from '../src/key_pin.js';

let count = 0;
const test = (name, fn) => { fn(); count += 1; console.log('ok  ' + name); };

test('the same key, or a key where there was none, is accepted', () => {
  assert.equal(pinAction('aaa', 'aaa'), 'accept');
  assert.equal(pinAction('', 'bbb'), 'accept');
  assert.equal(pinAction(undefined, 'bbb'), 'accept');
  assert.equal(pinAction('', ''), 'accept');
});

test('a different key or a vanished key is asked about', () => {
  assert.equal(pinAction('aaa', 'bbb'), 'ask');
  assert.equal(pinAction('aaa', ''), 'ask');
  assert.equal(pinAction('aaa', undefined), 'ask');
});

test('a refused key is not asked about again, another new key is', () => {
  assert.equal(pinAction('aaa', 'bbb', 'bbb'), 'keep-old-silent');
  assert.equal(pinAction('aaa', 'ccc', 'bbb'), 'ask');
  assert.equal(pinAction('aaa', '', ''), 'keep-old-silent');
  assert.equal(pinAction('aaa', 'aaa', 'bbb'), 'accept');
});

test('the same server is host:port and carrier, case-insensitive', () => {
  assert.equal(pinKey('Example.com:443', 'tls'), pinKey(' example.com:443', 'tls'));
  assert.notEqual(pinKey('example.com:443', 'tls'), pinKey('example.com:443', 'udp'));
  assert.notEqual(pinKey('example.com:443', 'tls'), pinKey('example.com:444', 'tls'));
});

console.log(`${count} passed`);
