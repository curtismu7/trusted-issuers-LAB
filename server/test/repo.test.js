import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { allowedHosts, bindProblem, portProblem } from '../src/safety.js';

const root = fileURLToPath(new URL('../../', import.meta.url));
const read = (p) => readFileSync(path.join(root, p), 'utf8');

function files(dir = root, out = []) {
  for (const name of readdirSync(dir)) {
    if (['node_modules', '.git', 'dist'].includes(name)) continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) files(full, out); else out.push(full);
  }
  return out;
}
const textFiles = () => files().filter((f) => !/package-lock\.json$|\.(png|jpe?g|gif|ico|woff2?|zip)$/i.test(f));

test('docker: published on 127.0.0.1 only, restarts, read-only, no privilege, no host network, no socket', () => {
  const c = read('docker-compose.yml');
  assert.match(c, /"127\.0\.0\.1:7815:7818"/);
  const portLines = c.split('\n').filter((l) => /^\s*-\s*"?\d/.test(l));
  assert.ok(portLines.length >= 1, 'a published port');
  for (const l of portLines) assert.match(l, /"127\.0\.0\.1:\d+:\d+"/, `every published port is loopback-only: ${l.trim()}`);
  assert.match(c, /restart:\s*unless-stopped/);
  assert.match(c, /read_only:\s*true/);
  assert.doesNotMatch(c, /privileged|network_mode|docker\.sock/);
  assert.match(c, /TI_REAL_PROBE=\$\{TI_REAL_PROBE:-\}/, 'Real is off unless the .env sets it');
});

test('docker image: Node 26, a non-root user, a health check', () => {
  const d = read('Dockerfile');
  assert.match(d, /FROM node:26/);
  assert.match(d, /^USER node$/m);
  assert.match(d, /HEALTHCHECK/);
  assert.match(d, /TI_IN_DOCKER=1/);
});

test('ci: Node 26, v5 actions, the forbidden-strings scan, gitleaks and the attribution check', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /node-version:\s*26/);
  assert.match(ci, /actions\/checkout@v5/); assert.match(ci, /actions\/setup-node@v5/);
  assert.match(ci, /FORBIDDEN_STRINGS/); assert.match(ci, /gitleaks/); assert.match(ci, /check-no-ai-attribution/);
  assert.doesNotMatch(ci, /pull_request_target/);
  assert.doesNotMatch(ci, /self-hosted/);
});

test('README declares the tier and the port; CLAUDE.md exists', () => {
  assert.match(read('README.md'), /^\*\*Tier: Tester\.\*\*/m);
  assert.match(read('README.md'), /host port is 7815/);
  assert.ok(existsSync(path.join(root, 'CLAUDE.md')));
});

test('tests run by glob, on Node 26 or newer', () => {
  assert.match(JSON.parse(read('server/package.json')).scripts.test, /test\/\*\.test\.js/);
  assert.equal(JSON.parse(read('package.json')).engines.node, '>=26');
  assert.equal(read('.nvmrc').trim(), '26');
});

test('the shelf entry is portable and honest', () => {
  const e = JSON.parse(read('docs/shelf-entry.json'));
  assert.equal(e.id, 'trusted-issuers'); assert.equal(e.port, 7815); assert.equal(e.kind, 'Tester');
  assert.equal(e.healthPath, '/api/health');
  assert.ok(!path.isAbsolute(e.composeFile) && !/^\/(Users|home)\//.test(e.composeFile));
  assert.ok(e.description.length <= 300, `${e.description.length} characters`);
  assert.equal(e.catalogId, null, 'no catalog row matches this app');
});

test('the vendored health.js and doctor.js are unchanged', () => {
  const pins = Object.fromEntries(read('server/src/vendored.sha256').split('\n').filter(Boolean).map((l) => l.split(/\s+/).reverse()));
  for (const f of ['health.js', 'doctor.js']) assert.equal(createHash('sha256').update(readFileSync(path.join(root, 'server/src', f))).digest('hex'), pins[f], `${f} was edited`);
});

test('no AI attribution in any file (the pattern is built from pieces so this file does not match itself)', () => {
  const pat = new RegExp(`${'Gener'}ated with \\[?${'Cla'}ude Code|${'Co-Auth'}ored-By:`, 'i');
  const hits = textFiles().filter((f) => !f.endsWith('check-no-ai-attribution.sh') && pat.test(readFileSync(f, 'utf8')));
  assert.deepEqual(hits.map((f) => path.relative(root, f)), []);
});

test('no file carries an absolute path from the author\'s machine', () => {
  const hits = textFiles().filter((f) => /\/Users\/[a-z]|\/home\/[a-z]/i.test(readFileSync(f, 'utf8')));
  assert.deepEqual(hits.map((f) => path.relative(root, f)), []);
});

test('nothing secret-shaped is committed, and .env is ignored', () => {
  assert.match(read('.gitignore'), /^\.env$/m);
  assert.ok(!existsSync(path.join(root, '.env')) || /^\.env$/m.test(read('.gitignore')));
  const shaped = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9]{20,}|\bghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|client_secret\s*[:=]\s*['"][^'"]{8,}/;
  const hits = textFiles().filter((f) => !/\.test\.js$/.test(f) && shaped.test(readFileSync(f, 'utf8')));
  assert.deepEqual(hits.map((f) => path.relative(root, f)), []);
  const example = read('.env.example').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepEqual(example, ['TI_REAL_PROBE=']);
});

test('safety rules: bind, port range, allowed hosts', () => {
  assert.equal(bindProblem('127.0.0.1', {}), null);
  assert.match(bindProblem('0.0.0.0', {}), /not loopback/);
  assert.equal(bindProblem('0.0.0.0', { TI_IN_DOCKER: '1' }), null);
  assert.equal(portProblem(7818), null);
  assert.match(portProblem(8080), /outside 7800-7999/);
  assert.match(portProblem(NaN), /whole number/);
  assert.ok(allowedHosts({}).includes('local.ping-devops.com'));
  assert.deepEqual(allowedHosts({ LAB_ALLOWED_HOSTS: 'a.example:8443, b.example' }), ['a.example', 'b.example']);
});

test('the doctor passes, and the reset script says so when the app is not running', () => {
  const doctor = spawnSync(process.execPath, ['scripts/doctor.mjs'], { cwd: root, encoding: 'utf8', timeout: 60000 });
  assert.equal(doctor.status, 0, doctor.stdout + doctor.stderr);
  assert.match(doctor.stdout, /\[pass\] data:/);
  assert.match(doctor.stdout, /\[pass\] netguard:/);
  assert.doesNotMatch(doctor.stdout, /\[fail\]/);
  const reset = spawnSync(process.execPath, ['scripts/reset.mjs'], { cwd: root, encoding: 'utf8', env: { ...process.env, PORT: '1' }, timeout: 20000 });
  assert.equal(reset.status, 0);
  assert.match(reset.stdout, /not reachable/);
});

test('the server refuses to start off loopback, and outside the port range', () => {
  const run = (env) => spawnSync(process.execPath, ['server/src/index.js'], { cwd: root, encoding: 'utf8', env: { ...process.env, ...env }, timeout: 20000 });
  const a = run({ HOST: '0.0.0.0', TI_IN_DOCKER: '' });
  assert.equal(a.status, 1); assert.match(a.stderr, /refusing to start/);
  const b = run({ PORT: '8080', HOST: '127.0.0.1' });
  assert.equal(b.status, 1); assert.match(b.stderr, /outside 7800-7999/);
});
