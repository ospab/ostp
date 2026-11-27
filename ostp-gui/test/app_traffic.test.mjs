// Run with plain node, no framework: node ostp-gui/test/app_traffic.test.mjs
import assert from 'node:assert/strict';
import { trafficArgs, viaTunnelOn } from '../src/app_traffic.js';

let count = 0;
const test = (name, fn) => { fn(); count += 1; console.log('ok  ' + name); };

test('the tunnel is used by default', () => {
  assert.equal(viaTunnelOn({}), true);
  assert.equal(viaTunnelOn(undefined), true);
  assert.equal(viaTunnelOn({ viaTunnel: true }), true);
});

test('only an explicit false turns it off', () => {
  assert.equal(viaTunnelOn({ viaTunnel: false }), false);
  assert.equal(viaTunnelOn({ viaTunnel: 0 }), true);
});

test('the command arguments carry the setting and the local proxy address', () => {
  assert.deepEqual(trafficArgs({}), { viaTunnel: true, socks: null });
  assert.deepEqual(trafficArgs({ viaTunnel: false, socks: ' 127.0.0.1:9050 ' }), { viaTunnel: false, socks: '127.0.0.1:9050' });
});

console.log(`${count} passed`);
