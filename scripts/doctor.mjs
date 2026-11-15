#!/usr/bin/env node
// Doctor: what a presenter runs before showing the lab. The content and engine checks are the same ones GET /api/health uses.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { runChecks } from '../server/src/checks.js';
import { printChecks } from '../server/src/doctor.js';
import { selfTest } from '../server/src/netguard.js';

const root = new URL('../', import.meta.url);
const read = (p) => (existsSync(new URL(p, root)) ? readFileSync(new URL(p, root), 'utf8') : '');
await selfTest();
const checks = runChecks();
const add = (id, ok, detail) => checks.push({ id, level: ok ? 'pass' : 'fail', detail });

const readme = read('README.md');
add('readme-tier', /^\*?\*?Tier:\s*Tester/im.test(readme), 'README declares "Tier: Tester"');
add('claude-md', existsSync(new URL('CLAUDE.md', root)), 'CLAUDE.md present');
const compose = read('docker-compose.yml');
add('compose-loopback', /"127\.0\.0\.1:7818:7818"/.test(compose) && !/^\s*-\s*"?(0\.0\.0\.0:)?7818:7818/m.test(compose), 'docker-compose publishes 127.0.0.1:7818 only');
add('compose-restart', /restart:\s*unless-stopped/.test(compose), 'restart: unless-stopped on the long-running service');
const ci = read('.github/workflows/ci.yml');
add('ci', /gitleaks/.test(ci) && /FORBIDDEN_STRINGS/.test(ci) && /check-no-ai-attribution/.test(ci), 'ci.yml runs gitleaks, the forbidden-strings scan and the attribution check');
add('env-ignored', /^\.env$/m.test(read('.gitignore')), '.env is git-ignored');
const pins = Object.fromEntries(read('server/src/vendored.sha256').split('\n').filter(Boolean).map((l) => l.split(/\s+/).reverse()));
const pinsOk = ['health.js', 'doctor.js'].every((f) => pins[f] && createHash('sha256').update(readFileSync(new URL(`server/src/${f}`, root))).digest('hex') === pins[f]);
add('vendored-pins', pinsOk, 'the vendored health.js and doctor.js match their sha256 pins');

printChecks(checks);
process.exit(checks.some((c) => c.level === 'fail') ? 1 : 0);
