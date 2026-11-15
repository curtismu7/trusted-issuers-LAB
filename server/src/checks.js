// Preflight checks shared by `npm run doctor` and GET /api/health. Synchronous, no network, never prints a secret.
// Each check is { id, level: 'pass' | 'info' | 'fail', detail }.
import { DATA, evidenceCensus, validateData } from './data.js';
import { nodeCheck } from './doctor.js';
import { runCheck } from './check.js';
import { bindHost, bindProblem, portOf, portProblem } from './safety.js';
import { lastSelfTest } from './netguard.js';
import { createMode } from './mode.js';

const FIXED_NOW = 1_800_000_000;

export function runChecks({ env = process.env } = {}) {
  const checks = [nodeCheck(26)];
  const add = (id, level, detail) => checks.push({ id, level, detail });

  const problems = validateData();
  add('data', problems.length ? 'fail' : 'pass', problems.length
    ? `${problems.length} content problem(s). First: ${problems[0]}`
    : `${DATA.surfaces.surfaces.length} surfaces, ${DATA.issuers.issuers.length} issuers, ${DATA.matrix.cells.length} matrix cells; every claim has an evidence tag and a source`);

  const census = evidenceCensus();
  add('evidence', 'info', Object.entries(census).map(([k, v]) => `${k} ${v}`).join(', '));

  try {
    const bad = [];
    for (const s of DATA.surfaces.surfaces) {
      const ok = runCheck({ issuer: 'private', surface: s.id }, { now: FIXED_NOW });
      const rf = runCheck({ issuer: 'private', surface: s.id, mutation: 'wrong-iss' }, { now: FIXED_NOW });
      if (ok.verdict !== 'accepted') bad.push(`${s.id}: a good token was refused at ${ok.stage}`);
      if (rf.verdict !== 'refused') bad.push(`${s.id}: a wrong issuer was accepted`);
    }
    add('engine', bad.length ? 'fail' : 'pass', bad.length ? bad.join('; ') : 'a good token is accepted and a wrong issuer refused on every surface, with real RS256 verification');
  } catch (e) { add('engine', 'fail', `the engine threw: ${String(e.message).slice(0, 160)}`); }

  const host = bindHost(env);
  const bind = bindProblem(host, env);
  add('bind', bind ? 'fail' : 'pass', bind || (['127.0.0.1', '::1', 'localhost'].includes(host) ? `${host} (loopback)` : `${host} (container; the host publishes 127.0.0.1 only)`));

  const port = portOf(env);
  const pp = portProblem(port);
  add('port-range', pp ? 'fail' : 'pass', pp || `${port} is inside the 7800-7999 range`);

  const st = lastSelfTest();
  add('netguard', st === null ? 'info' : st.ok ? 'pass' : 'fail', st === null ? 'self-test has not run yet' : st.ok ? 'blocks outbound lookups and connects, allows loopback (self-test passed)' : 'the self-test failed: outbound calls are not being blocked');

  const mode = createMode(env);
  add('real-mode', 'info', mode.realAvailable() ? 'Real is configured (TI_REAL_PROBE=1): a read-only issuer discovery probe' : 'Real is not configured: Mock only (set TI_REAL_PROBE=1 in .env for the discovery probe)');
  return checks;
}
