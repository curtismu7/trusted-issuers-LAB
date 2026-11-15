import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createApp } from '../src/app.js';
import { DATA } from '../src/data.js';
import { report as netguardReport, selfTest } from '../src/netguard.js';
import { isBlockedAddress, guardedLookup, parseProbeTarget } from '../src/ssrf.js';
import { mapNetworkError } from '../src/upstream.js';
import { compareIssuer } from '../src/probe.js';

const started = [];
async function start(opts = {}) {
  const app = createApp({ env: {}, ...opts });
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const handle = { base, app, close: () => new Promise((r) => { app.locals.health.stop(); server.close(r); }) };
  started.push(handle);
  return handle;
}
after(async () => { for (const h of started) await h.close(); });

const post = (base, path, body, headers = {}) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const json = async (res) => ({ status: res.status, body: await res.json() });

// http.request lets a test set Host, Origin and Sec-Fetch-Site, which fetch may not.
function raw(base, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(base);
    const req = http.request({ host: u.hostname, port: u.port, method, path, headers }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let parsed = null; try { parsed = JSON.parse(text); } catch { /* not JSON */ } resolve({ status: res.statusCode, text, body: parsed }); });
    });
    req.on('error', reject); if (body !== undefined) req.write(body); req.end();
  });
}

test('GET /api/health answers demo-health/1 and says ready', async () => {
  const { base } = await start();
  const { status, body } = await json(await fetch(`${base}/api/health`));
  assert.equal(status, 200);
  assert.equal(body.schema, 'demo-health/1');
  assert.equal(body.state, 'ready');
  assert.equal(body.demo.id, 'trusted-issuers');
  assert.equal(body.runtime, 'offline');
  assert.equal((await fetch(`${base}/api/health`, { method: 'POST' })).status, 405);
});

test('a host name the lab does not answer to is refused', async () => {
  const { base } = await start();
  const r = await raw(base, { path: '/api/info', headers: { host: 'evil.example' } });
  assert.equal(r.status, 421);
  assert.equal(r.body.error, 'bad_host');
  assert.equal((await raw(base, { path: '/api/info', headers: { host: 'local.ping-devops.com:8443' } })).status, 200);
});

test('writes: a foreign Origin, a cross-site request, a non-JSON body, bad JSON and a big body are all refused', async () => {
  const { base } = await start();
  const body = JSON.stringify({ issuer: 'okta', surface: 'p1-exchange' });
  const h = { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) };
  assert.equal((await raw(base, { method: 'POST', path: '/api/check', headers: { ...h, origin: 'http://evil.example' }, body })).status, 403);
  assert.equal((await raw(base, { method: 'POST', path: '/api/check', headers: { ...h, 'sec-fetch-site': 'cross-site' }, body })).status, 403);
  assert.equal((await raw(base, { method: 'POST', path: '/api/check', headers: { ...h, origin: 'not a url' }, body })).status, 403);
  assert.equal((await raw(base, { method: 'POST', path: '/api/check', headers: { ...h, origin: 'http://localhost:9999' }, body })).status, 200, 'a known origin is fine');
  const form = 'issuer=okta';
  assert.equal((await raw(base, { method: 'POST', path: '/api/check', headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(form.length) }, body: form })).status, 415);
  const bad = '{"issuer":';
  const r = await raw(base, { method: 'POST', path: '/api/check', headers: { 'content-type': 'application/json', 'content-length': String(bad.length) }, body: bad });
  assert.equal(r.status, 400); assert.equal(r.body.error, 'bad_json');
  const big = JSON.stringify({ issuer: 'okta', surface: 'p1-exchange', token: 'x'.repeat(70000) });
  const rb = await raw(base, { method: 'POST', path: '/api/check', headers: { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(big)) }, body: big });
  assert.equal(rb.status, 413); assert.equal(rb.body.error, 'too_large');
});

test('GET /api/info reports the mode and the counts', async () => {
  const { base } = await start();
  const { body } = await json(await fetch(`${base}/api/info`));
  assert.equal(body.source, 'mock'); assert.equal(body.realAvailable, false); assert.equal(body.simulated, true);
  assert.equal(body.tier, 'Tester');
  assert.deepEqual([body.counts.surfaces, body.counts.issuers, body.counts.cells], [4, 14, 56]);
  assert.match(body.banner, /SIMULATED/);
});

test('rule 19: Real not configured answers 409 naming what is missing, and the mode does not change', async () => {
  const { base } = await start();
  const r = await json(await post(base, '/api/mode', { source: 'real' }));
  assert.equal(r.status, 409); assert.equal(r.body.error, 'real_not_configured'); assert.match(r.body.message, /TI_REAL_PROBE=1/);
  assert.equal((await json(await fetch(`${base}/api/info`))).body.source, 'mock');
  assert.equal((await json(await post(base, '/api/mode', { source: 'mock' }))).body.source, 'mock');
});

test('rule 19: the body is exactly { source }, and anything else is refused', async () => {
  const { base } = await start();
  for (const body of [{}, { source: 'mock', extra: 1 }, { src: 'mock' }, { source: 'live' }, { source: 5 }]) assert.equal((await post(base, '/api/mode', body)).status, 400, JSON.stringify(body));
});

test('rule 19: when Real is configured it is the default, and the toggle switches both ways without a restart', async () => {
  const { base } = await start({ env: { TI_REAL_PROBE: '1' } });
  let info = (await json(await fetch(`${base}/api/info`))).body;
  assert.equal(info.realAvailable, true); assert.equal(info.source, 'real');
  assert.equal((await json(await post(base, '/api/mode', { source: 'mock' }))).body.source, 'mock');
  info = (await json(await fetch(`${base}/api/info`))).body;
  assert.equal(info.source, 'mock');
  assert.equal((await json(await post(base, '/api/mode', { source: 'real' }))).body.source, 'real');
  assert.equal((await json(await fetch(`${base}/api/info`))).body.source, 'real');
  // the data the page reloads after a switch is the same in both modes: the lab's content does not depend on it
  assert.equal((await json(await fetch(`${base}/api/data/matrix`))).body.cells.length, 56);
});

test('the data routes serve every set, with the joins the page needs', async () => {
  const { base } = await start();
  for (const set of ['evidence', 'sources', 'surfaces', 'issuers', 'matrix', 'breakits', 'decide', 'seen-in']) {
    const r = await json(await fetch(`${base}/api/data/${set}`));
    assert.equal(r.status, 200, set);
  }
  const issuers = (await json(await fetch(`${base}/api/data/issuers`))).body.issuers;
  assert.equal(issuers.length, 14);
  assert.deepEqual(issuers.find((i) => i.id === 'pingam').shownIn, []);
  assert.ok(issuers.find((i) => i.id === 'pf').shownIn.includes('pf-privilege-obo-lab'));
  const cells = (await json(await fetch(`${base}/api/data/matrix`))).body.cells;
  assert.ok(cells.every((c) => c.config && typeof c.config === 'object'));
  const surfaces = (await json(await fetch(`${base}/api/data/surfaces`))).body.surfaces;
  assert.ok(surfaces.every((s) => Array.isArray(s.shownIn)));
  assert.equal((await json(await fetch(`${base}/api/data/nope`))).status, 404);
  const one = (await json(await fetch(`${base}/api/data/matrix/okta/p1az-oauth`))).body;
  assert.equal(one.cell.status, 'configurable'); assert.equal(one.config.externalOAuthServer.issuers[0], 'https://okta.example/oauth2/aus1example');
  assert.equal((await json(await fetch(`${base}/api/data/matrix/okta/nope`))).status, 404);
});

test('matrix configs use no real host and show a placeholder, not a key, for a pinned issuer', async () => {
  const { base } = await start();
  const cells = (await json(await fetch(`${base}/api/data/matrix`))).body.cells;
  const text = JSON.stringify(cells);
  for (const m of text.matchAll(/https?:\/\/([^/"\s:]+)/g)) assert.match(m[1], /\.(example|invalid)$/);
  const pinned = cells.find((c) => c.issuer === 'private' && c.surface === 'p1-exchange');
  assert.match(pinned.config.trustedIssuer.jwks, /the issuer's public keys/);
});

test('POST /api/check runs the engine; the run log fills and Reset clears it', async () => {
  const { base } = await start();
  const r = await json(await post(base, '/api/check', { issuer: 'okta', surface: 'p1-exchange', mutation: 'expired' }));
  assert.equal(r.status, 200); assert.equal(r.body.verdict, 'refused'); assert.equal(r.body.stage, 'exp'); assert.equal(r.body.matchesExpected, true);
  await post(base, '/api/check', { issuer: 'pf', surface: 'privilege-fi' });
  const runs = (await json(await fetch(`${base}/api/runs`))).body.runs;
  assert.equal(runs.length, 2); assert.equal(runs[0].issuer, 'pf');
  const reset = await json(await post(base, '/api/reset', {}));
  assert.deepEqual(reset.body, { ok: true, reset: true, cleared: 2 });
  assert.equal((await json(await fetch(`${base}/api/runs`))).body.runs.length, 0);
  const bare = await fetch(`${base}/api/reset`, { method: 'POST' });
  assert.equal(bare.status, 200, 'Reset works with no body, as the script sends it');
});

test('errors come back as JSON: bad input 400, config refused 422, unknown route 404, never HTML', async () => {
  const { base } = await start();
  for (const [status, req] of [
    [400, post(base, '/api/check', { issuer: 'okta', surface: 'p1-exchange', nope: 1 })],
    [400, post(base, '/api/check', { issuer: 'okta', surface: 'p1-exchange', overrides: { x: 1 } })],
    [404, post(base, '/api/check', { issuer: 'ghost', surface: 'p1-exchange' })],
    [422, post(base, '/api/check', { issuer: 'okta', surface: 'p1-exchange', overrides: { trustedIssuer: { clockSkew: 61 } } })],
    [404, fetch(`${base}/api/nothing-here`)],
  ]) {
    const res = await req;
    assert.equal(res.status, status);
    assert.match(res.headers.get('content-type'), /application\/json/);
    const body = await res.json();
    assert.ok(body.error && body.message, JSON.stringify(body));
  }
});

// ---- Real mode: the discovery probe, against an in-process stub only ----
async function stub() {
  let port;
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(typeof obj === 'string' ? obj : JSON.stringify(obj)); };
    const me = `http://127.0.0.1:${port}`;
    switch (u.pathname) {
      case '/.well-known/openid-configuration': return send(200, { issuer: me, jwks_uri: `${me}/jwks`, id_token_signing_alg_values_supported: ['RS256'], extra: 'dropped', authorization_endpoint: `${me}/a‮b` });
      case '/tenant/.well-known/openid-configuration': return send(200, { issuer: `${me}/tenant/`, jwks_uri: `${me}/tenant/jwks` });
      case '/case/.well-known/openid-configuration': return send(200, { issuer: `${me}/CASE` });
      case '/redir/.well-known/openid-configuration': res.writeHead(302, { location: 'http://elsewhere.invalid/' }); return res.end();
      case '/big/.well-known/openid-configuration': return send(200, JSON.stringify({ issuer: me, pad: 'x'.repeat(200000) }));
      case '/bad/.well-known/openid-configuration': return send(503, { error: 'down' });
      case '/hang/.well-known/openid-configuration': return undefined;
      case '/html/.well-known/openid-configuration': res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<html>nope</html>');
      case '/rfc/.well-known/openid-configuration': return send(404, {});
      case '/.well-known/oauth-authorization-server/rfc': return send(200, { issuer: `${me}/rfc` });
      default: return send(404, {});
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
  return { port, origin: `http://127.0.0.1:${port}`, close: () => { server.closeAllConnections(); return new Promise((r) => server.close(r)); } };
}
const real = () => start({ env: { TI_REAL_PROBE: '1' }, probeOptions: { allowLoopback: true, timeoutMs: 400 } });
const probe = (base, body) => post(base, '/api/probe', body).then(json);

test('probe: it reads the discovery document and compares the issuer exactly', async () => {
  const s = await stub(); const { base } = await real();
  const exact = await probe(base, { issuer: s.origin, confirm: true });
  assert.equal(exact.status, 200); assert.equal(exact.body.found, true); assert.equal(exact.body.kind, 'openid-configuration');
  assert.equal(exact.body.comparison.exact, true);
  assert.deepEqual(exact.body.document.id_token_signing_alg_values_supported, ['RS256']);
  assert.equal(exact.body.document.extra, undefined, 'only the fields the lab shows are kept');
  assert.ok(!/‮/.test(exact.body.document.authorization_endpoint), 'control and bidi characters are scrubbed from what comes back');

  const slash = await probe(base, { issuer: `${s.origin}/`, confirm: true });
  assert.deepEqual(slash.body.comparison, { exact: false, differences: ['trailing slash'] });
  const tenant = await probe(base, { issuer: `${s.origin}/tenant`, confirm: true });
  assert.deepEqual(tenant.body.comparison, { exact: false, differences: ['trailing slash'] }, 'a document whose issuer ends in a slash, typed without it');
  const cased = await probe(base, { issuer: `${s.origin}/case`, confirm: true });
  assert.deepEqual(cased.body.comparison, { exact: false, differences: ['letter case'] });
  const rfc = await probe(base, { issuer: `${s.origin}/rfc`, confirm: true });
  assert.equal(rfc.body.kind, 'oauth-authorization-server', 'falls back to RFC 8414');
  await s.close();
});

test('probe: compareIssuer names the difference in plain words', () => {
  assert.deepEqual(compareIssuer('https://a.example', 'https://a.example'), { exact: true, differences: [] });
  assert.deepEqual(compareIssuer('https://a.example/', 'https://a.example'), { exact: false, differences: ['trailing slash'] });
  assert.deepEqual(compareIssuer('HTTPS://A.EXAMPLE', 'https://a.example'), { exact: false, differences: ['letter case'] });
  assert.deepEqual(compareIssuer('https://A.example/', 'https://a.example'), { exact: false, differences: ['letter case and trailing slash'] });
  assert.deepEqual(compareIssuer('https://b.example', 'https://a.example'), { exact: false, differences: ['a different string'] });
});

test('probe: the confirm gate, the mode gate and the configuration gate', async () => {
  const s = await stub(); const { base } = await real();
  const noConfirm = await probe(base, { issuer: s.origin });
  assert.equal(noConfirm.status, 400); assert.equal(noConfirm.body.error, 'confirm_required'); assert.equal(noConfirm.body.willContact, s.origin);
  assert.equal((await probe(base, { issuer: s.origin, confirm: 'yes' })).status, 400, 'only true confirms');
  await post(base, '/api/mode', { source: 'mock' });
  const mock = await probe(base, { issuer: s.origin, confirm: true });
  assert.equal(mock.status, 409); assert.equal(mock.body.error, 'mock_mode');
  const off = await start();
  const none = await probe(off.base, { issuer: s.origin, confirm: true });
  assert.equal(none.status, 409); assert.equal(none.body.error, 'real_not_configured');
  assert.equal((await probe(base, { issuer: s.origin, confirm: true, extra: 1 })).status, 409, 'still in mock mode');
  await post(base, '/api/mode', { source: 'real' });
  assert.equal((await probe(base, { issuer: s.origin, confirm: true, extra: 1 })).status, 400);
  await s.close();
});

test('probe: rule 23. Every way the other side can fail comes back as named JSON', async () => {
  const s = await stub(); const { base } = await real();
  const cases = [
    ['/redir', 400, 'redirect_refused'],
    ['/big', 502, 'upstream_too_large'],
    ['/bad', 502, 'upstream_bad_gateway'],
    ['/hang', 504, 'upstream_timeout'],
  ];
  for (const [path, status, code] of cases) {
    const r = await probe(base, { issuer: `${s.origin}${path}`, confirm: true });
    assert.equal(r.status, status, path); assert.equal(r.body.error, code, path); assert.ok(r.body.message, path);
  }
  const html = await probe(base, { issuer: `${s.origin}/html`, confirm: true });
  assert.equal(html.status, 200); assert.equal(html.body.found, false);
  await s.close();
  const refused = await probe(base, { issuer: s.origin, confirm: true });
  assert.equal(refused.status, 502); assert.equal(refused.body.error, 'upstream_unreachable'); assert.match(refused.body.message, /connection refused/);
});

test('probe: what may be typed. https only, no IPs, no credentials, no odd ports, no private addresses', async () => {
  const { base } = await start({ env: { TI_REAL_PROBE: '1' }, probeOptions: {} });
  for (const issuer of ['http://issuer.example', 'https://127.0.0.1', 'https://10.0.0.5', 'https://[::1]', 'https://user:pw@issuer.example', 'https://issuer.example:8443', 'https://issuer.example/?a=1', 'https://issuer.example/#x', 'https://localhost', 'ftp://issuer.example', 'not a url', ' https://issuer.example', 'https://issuer.example/‮', `https://${'a'.repeat(300)}.example`, '', 5, null]) {
    const r = await probe(base, { issuer, confirm: true });
    assert.equal(r.status, 400, String(issuer)); assert.equal(r.body.error, 'bad_issuer', String(issuer));
  }
  const loopbackHttp = await probe(base, { issuer: 'http://127.0.0.1:9', confirm: true });
  assert.equal(loopbackHttp.status, 400, 'loopback http is only for the lab\'s own tests');
});

test('ssrf: private, loopback, link-local and mapped addresses are blocked; a public one is not', () => {
  for (const ip of ['10.1.2.3', '172.16.0.1', '192.168.1.1', '127.0.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fe80::1', 'fc00::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1', '224.0.0.1', 'garbage', undefined]) assert.equal(isBlockedAddress(ip), true, String(ip));
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(isBlockedAddress(ip), false, ip);
  assert.equal(isBlockedAddress('127.0.0.1', true), false, 'loopback is open only when a test turns it on');
  assert.equal(isBlockedAddress('10.0.0.1', true), true);
  assert.throws(() => parseProbeTarget('http://127.0.0.1:1', {}), (e) => e.code === 'bad_issuer');
  assert.doesNotThrow(() => parseProbeTarget('http://127.0.0.1:1', { allowLoopback: true }));
});

test('ssrf: a name that resolves to a private address is refused at connect time', async () => {
  const result = await new Promise((resolve) => guardedLookup(false)('localhost', {}, (err, address) => resolve({ err, address })));
  assert.equal(result.err?.code, 'SSRF_BLOCKED');
  const open = await new Promise((resolve) => guardedLookup(true)('localhost', {}, (err, address) => resolve({ err, address })));
  assert.ok(!open.err && open.address);
});

test('upstream: connection refused, DNS failure, timeout, TLS and a blocked call each map to a named error', () => {
  const code = (c) => mapNetworkError(Object.assign(new Error('x'), { code: c }), 'the issuer').code;
  assert.equal(code('ECONNREFUSED'), 'upstream_unreachable'); assert.equal(code('ENOTFOUND'), 'upstream_unreachable');
  assert.equal(code('ETIMEDOUT'), 'upstream_timeout'); assert.equal(code('DEPTH_ZERO_SELF_SIGNED_CERT'), 'upstream_tls');
  assert.equal(code('SSRF_BLOCKED'), 'address_refused'); assert.equal(code('ENETGUARD'), 'outbound_blocked'); assert.equal(code('WHATEVER'), 'upstream_error');
  assert.equal(mapNetworkError(Object.assign(new Error('x'), { cause: { code: 'ECONNREFUSED' } }), 'x').code, 'upstream_unreachable');
});

test('the lab makes no outbound call: netguard counts zero attempts after all of the above, and its self-test passes', async () => {
  const st = await selfTest();
  assert.equal(st.ok, true, JSON.stringify(st));
  assert.deepEqual(st.results.map((r) => r.id), ['lookup-blocked', 'connect-blocked', 'loopback-allowed']);
  const rep = netguardReport();
  assert.equal(rep.attempts, 0, JSON.stringify(rep.blocked));
  const { base } = await start();
  const viaApi = (await json(await fetch(`${base}/api/netguard`))).body;
  assert.equal(viaApi.attempts, 0); assert.equal(viaApi.ok, true); assert.equal(viaApi.selfTest.ok, true);
  assert.ok(DATA.matrix.cells.length > 0 && net.isIP('127.0.0.1') === 4);
});
