import { test } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns';
import net from 'node:net';
import { allowHost, install, isLocal, report, resetReport, selfTest } from '../src/netguard.js';

install();
const lookup = (host) => new Promise((resolve) => dns.lookup(host, (err, address) => resolve({ err, address })));

test('the self-test passes, and leaves the counter at zero', async () => {
  resetReport();
  const r = await selfTest();
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(report().attempts, 0);
  const again = await Promise.all([selfTest(), selfTest()]);
  assert.equal(again[0], again[1], 'overlapping calls share one run');
  assert.equal(report().attempts, 0);
});

test('an outbound lookup is refused and counted', async () => {
  resetReport();
  const { err } = await lookup('outbound.example');
  assert.equal(err?.code, 'ENETGUARD');
  assert.equal(report().attempts, 1);
  assert.equal(report().blocked[0].via, 'lookup');
});

test('a connect to a public IP address is refused and counted', async () => {
  resetReport();
  const err = await new Promise((resolve) => { const s = net.connect({ host: '198.51.100.7', port: 443 }); s.on('error', resolve); s.on('connect', () => resolve(null)); });
  assert.equal(err?.code, 'ENETGUARD');
  assert.equal(report().attempts, 1);
  assert.equal(report().blocked[0].via, 'connect');
});

test('fetch to a name is refused', async () => {
  resetReport();
  await assert.rejects(fetch('https://blocked.example/'), (e) => (e.cause?.code ?? e.code) === 'ENETGUARD');
  assert.ok(report().attempts >= 1);
});

test('loopback is not outbound: a local server answers and nothing is counted', async () => {
  resetReport();
  const server = net.createServer((s) => s.end('hello'));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const text = await new Promise((resolve, reject) => { const s = net.connect({ host: 'localhost', port: server.address().port }); let d = ''; s.on('data', (c) => { d += c; }); s.on('end', () => resolve(d)); s.on('error', reject); });
  assert.equal(text, 'hello');
  assert.equal((await lookup('localhost')).err, null);
  assert.equal(report().attempts, 0);
  server.close();
});

test('allowHost lets one host through for as long as it is held, then takes the allowance away', async () => {
  resetReport();
  const release = allowHost('probe-target.invalid');
  const during = await lookup('probe-target.invalid');
  assert.notEqual(during.err?.code, 'ENETGUARD', 'the allowed host reaches the resolver');
  assert.equal(report().attempts, 0);
  release();
  const after = await lookup('probe-target.invalid');
  assert.equal(after.err?.code, 'ENETGUARD');
  assert.equal(report().attempts, 1);
});

test('two holds on the same host need two releases', async () => {
  resetReport();
  const a = allowHost('twice.invalid'); const b = allowHost('twice.invalid');
  a();
  assert.notEqual((await lookup('twice.invalid')).err?.code, 'ENETGUARD');
  b();
  assert.equal((await lookup('twice.invalid')).err?.code, 'ENETGUARD');
});

test('what counts as local', () => {
  for (const h of ['localhost', '127.0.0.1', '127.9.9.9', '::1', '0.0.0.0', 'api.localhost', undefined, '']) assert.equal(isLocal(h), true, String(h));
  for (const h of ['example.com', '8.8.8.8', '10.0.0.1', 'localhost.example', '1.127.0.0.1']) assert.equal(isLocal(h), false, h);
});
