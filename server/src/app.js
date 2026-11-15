// The Express app. One factory so tests can make as many apps as they like. State is in memory only; Reset clears it.
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DATA, evidenceCensus, getCell, getIssuer, getSurface, labsForSurface, labsShowing } from './data.js';
import { defaultConfig } from './config.js';
import { runCheck } from './check.js';
import { runChecks } from './checks.js';
import { allPassed } from './doctor.js';
import { HttpError, badRequest, errorHandler } from './errors.js';
import { createHealth } from './health.js';
import { createMode } from './mode.js';
import { install as installNetguard, report as netguardReport, lastSelfTest, selfTest } from './netguard.js';
import { probeIssuer } from './probe.js';
import { allowedHosts } from './safety.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(fs.readFileSync(path.join(here, '../../package.json'), 'utf8'));
const MAX_RUNS = 100;
// Express 4 does not pass a rejected promise to the error handler, so async routes go through this.
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const DATA_SETS = ['evidence', 'sources', 'surfaces', 'issuers', 'matrix', 'breakits', 'decide', 'seen-in'];

export const BANNER = 'SIMULATED: every token here is minted and checked inside this app with its own keys. Nothing calls PingOne, PingFederate, Privilege or any tenant. Each claim says where it comes from.';

export function createApp({ env = process.env, probeOptions = {}, now } = {}) {
  installNetguard();
  if (lastSelfTest() === null) selfTest().catch(() => {});
  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  const mode = createMode(env);
  const hosts = allowedHosts(env);
  const runs = [];

  // Loopback host check: the page and the API answer only to the names this lab is reached by.
  app.use((req, res, next) => {
    const host = String(req.headers.host || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
    if (!hosts.includes(host)) return res.status(421).json({ error: 'bad_host', message: 'This host name is not one this lab answers to.' });
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    return next();
  });

  // Writes must come from this lab's own page: a known Origin, never a cross-site request, and JSON when there is a body.
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method === 'GET' || req.method === 'HEAD') return next();
    if (req.headers['sec-fetch-site'] === 'cross-site') return res.status(403).json({ error: 'cross_origin', message: 'A cross-site write was refused.' });
    if (req.headers.origin) {
      let originHost;
      try { originHost = new URL(req.headers.origin).hostname.replace(/^\[|\]$/g, ''); } catch { return res.status(403).json({ error: 'bad_origin', message: 'The Origin header is not a URL.' }); }
      if (!hosts.includes(originHost)) return res.status(403).json({ error: 'cross_origin', message: 'A write from another origin was refused.' });
    }
    const hasBody = Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'];
    if (hasBody && !/^application\/json\b/i.test(req.headers['content-type'] || '')) return res.status(415).json({ error: 'unsupported_media_type', message: 'Send JSON with Content-Type: application/json.' });
    return next();
  });
  app.use(express.json({ limit: '64kb', strict: true }));

  const health = createHealth({ demoId: 'trusted-issuers', demoName: 'Trusted Issuers LAB', version: PKG.version, runChecks: () => runChecks({ env }), allPassed });
  app.use('/api/health', health.router);

  app.get('/api/info', (_req, res) => res.json({
    app: 'trusted-issuers', name: 'Trusted Issuers LAB', tier: 'Tester', version: PKG.version,
    source: mode.source, realAvailable: mode.realAvailable(), simulated: true, banner: BANNER,
    counts: { surfaces: DATA.surfaces.surfaces.length, issuers: DATA.issuers.issuers.length, cells: DATA.matrix.cells.length, mutations: DATA.breakits.mutations.length, labs: DATA.seenIn.labs.length },
    evidence: evidenceCensus(),
  }));

  app.post('/api/mode', (req, res) => {
    const keys = req.body && typeof req.body === 'object' ? Object.keys(req.body) : [];
    if (keys.length !== 1 || keys[0] !== 'source') return res.status(400).json({ error: 'bad_source', message: 'Send exactly { "source": "mock" | "real" }.' });
    const r = mode.set(req.body.source);
    if (!r.ok) return res.status(r.status).json({ error: r.error, message: r.message });
    return res.json({ source: mode.source, realAvailable: mode.realAvailable() });
  });

  // ---- content
  app.get('/api/data', (_req, res) => res.json({ sets: DATA_SETS, counts: { surfaces: DATA.surfaces.surfaces.length, issuers: DATA.issuers.issuers.length, cells: DATA.matrix.cells.length }, evidence: evidenceCensus() }));
  app.get('/api/data/matrix/:issuer/:surface', (req, res) => {
    const issuer = getIssuer(req.params.issuer); const surface = getSurface(req.params.surface);
    if (!issuer || !surface) throw new HttpError(404, 'not_found', 'No such issuer or surface.');
    res.json({ cell: getCell(issuer.id, surface.id), issuer, surface, config: defaultConfig(issuer, surface.id, null) });
  });
  app.get('/api/data/:set', (req, res) => {
    const set = req.params.set;
    if (!DATA_SETS.includes(set)) throw new HttpError(404, 'not_found', `There is no data set called "${set.slice(0, 40)}".`);
    if (set === 'issuers') return res.json({ issuers: DATA.issuers.issuers.map((i) => ({ ...i, shownIn: labsShowing(i.id) })) });
    if (set === 'matrix') return res.json({ cells: DATA.matrix.cells.map((c) => ({ ...c, config: defaultConfig(getIssuer(c.issuer), c.surface, null) })) });
    if (set === 'surfaces') return res.json({ surfaces: DATA.surfaces.surfaces.map((s) => ({ ...s, shownIn: labsForSurface(s.id) })) });
    return res.json(DATA[set === 'seen-in' ? 'seenIn' : set]);
  });

  // ---- the engine
  app.post('/api/check', (req, res) => {
    const result = runCheck(req.body, { now: now ? now() : undefined });
    runs.unshift({ at: new Date().toISOString(), issuer: result.input.issuer, surface: result.input.surface, mutation: result.input.mutation, pasted: result.input.pasted, verdict: result.verdict, stage: result.stage });
    if (runs.length > MAX_RUNS) runs.length = MAX_RUNS;
    res.json(result);
  });
  app.get('/api/runs', (_req, res) => res.json({ runs }));

  // ---- Real mode: the read-only discovery probe
  app.post('/api/probe', wrap(async (req, res) => {
    if (!mode.realAvailable()) throw new HttpError(409, 'real_not_configured', 'Real mode needs TI_REAL_PROBE=1 in the app\'s own .env.');
    if (mode.source !== 'real') throw new HttpError(409, 'mock_mode', 'The issuer probe runs in Real mode. Switch to Real first.');
    const body = req.body;
    if (body === null || typeof body !== 'object' || Array.isArray(body)) throw badRequest('bad_input', 'The body must be a JSON object.');
    for (const k of Object.keys(body)) if (!['issuer', 'confirm'].includes(k)) throw badRequest('bad_input', `"${k}" is not a field this call takes.`);
    res.json(await probeIssuer(body, probeOptions));
  }));

  app.post('/api/reset', (_req, res) => { const cleared = runs.length; runs.length = 0; res.json({ ok: true, reset: true, cleared }); });
  app.get('/api/netguard', (_req, res) => res.json({ ...netguardReport(), selfTest: lastSelfTest() }));
  app.use('/api', (_req, res) => res.status(404).json({ error: 'not_found', message: 'There is no such API route.' }));

  // ---- the built web page, when there is one
  const dist = path.join(here, '../../web/dist');
  if (fs.existsSync(path.join(dist, 'index.html'))) {
    app.use(express.static(dist));
    app.get(/^\/(?!api\/).*/, (_req, res) => res.sendFile(path.join(dist, 'index.html')));
  } else {
    app.get('/', (_req, res) => res.json({ app: 'trusted-issuers', message: 'The web page has not been built. The API is at /api/info.' }));
  }

  app.use(errorHandler);
  app.locals.health = health;
  return app;
}
