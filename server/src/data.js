// The lab's content, loaded once from data/*.json and checked by validateData(). The same validator backs the tests,
// `npm run doctor` and GET /api/health, so a content mistake (a claim with no source, a dangling id, a real host name)
// shows up everywhere. Nothing here touches the network.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const DATA_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../data');
const FILES = ['evidence', 'sources', 'surfaces', 'issuers', 'matrix', 'breakits', 'decide', 'seen-in'];

function deepFreeze(root) {
  const stack = [root];
  while (stack.length) {
    const v = stack.pop();
    if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.freeze(v); for (const k of Object.keys(v)) stack.push(v[k]); }
  }
  return root;
}

export function loadData(dir = DATA_DIR) {
  const out = {};
  for (const f of FILES) out[f === 'seen-in' ? 'seenIn' : f] = JSON.parse(fs.readFileSync(path.join(dir, `${f}.json`), 'utf8'));
  return out;
}

export const DATA = deepFreeze(loadData());

const STATUSES = ['supported', 'configurable', 'not-proven', 'na', 'unknown'];
const URL_HOST = /\b[a-z][a-z0-9+.-]*:\/\/([^/\s:"'<>)\]]+)/gi;
const hostOk = (h) => /\.(example|invalid)$/i.test(h);

// Iterative walk over every string in a value, with its path.
function* strings(root, base) {
  const stack = [[root, base]];
  while (stack.length) {
    const [v, p] = stack.pop();
    if (typeof v === 'string') yield [v, p];
    else if (Array.isArray(v)) v.forEach((x, i) => stack.push([x, `${p}[${i}]`]));
    else if (v && typeof v === 'object') for (const k of Object.keys(v)) stack.push([v[k], `${p}.${k}`]);
  }
}

export function validateData(data = DATA) {
  const problems = [];
  const bad = (msg) => problems.push(msg);
  const tagIds = new Set(data.evidence.tags.map((t) => t.id));
  const messageSources = new Set(data.evidence.messageSources.map((m) => m.id));
  const sources = new Map(data.sources.sources.map((s) => [s.id, s]));
  const surfaceIds = data.surfaces.surfaces.map((s) => s.id);
  const surfaces = new Map(data.surfaces.surfaces.map((s) => [s.id, s]));
  const issuers = new Map(data.issuers.issuers.map((i) => [i.id, i]));
  const labs = new Set(data.seenIn.labs.map((l) => l.id));

  // A claim: anything that states a fact. It must carry a known evidence tag and a source of the matching kind.
  const claim = (where, c) => {
    if (!c || typeof c !== 'object') return bad(`${where}: not an object`);
    if (!tagIds.has(c.evidence)) return bad(`${where}: evidence tag missing or unknown (${String(c.evidence)})`);
    const src = sources.get(c.source);
    if (!src) return bad(`${where}: source "${String(c.source)}" is not in sources.json`);
    if (!data.sources.kindsByTag[c.evidence].includes(src.kind)) bad(`${where}: tag ${c.evidence} does not fit source kind ${src.kind}`);
    if (c.source === 'unsourced' && c.evidence !== 'unverified') bad(`${where}: "unsourced" may only back an unverified claim`);
  };

  if (!(data.sources.sources.length > 0)) bad('sources.json: no sources');
  for (const [id, s] of sources) if (!s.title) bad(`sources.${id}: no title`);

  // ---- surfaces
  if (surfaceIds.length !== 4) bad(`surfaces.json: expected 4 surfaces, found ${surfaceIds.length}`);
  for (const s of data.surfaces.surfaces) {
    const w = `surface ${s.id}`;
    for (const k of ['whereConfigured', 'fields', 'refusals', 'limits']) {
      if (!Array.isArray(s[k]) || s[k].length === 0) bad(`${w}: ${k} is empty`);
      (s[k] || []).forEach((c, i) => claim(`${w}.${k}[${i}]`, c));
    }
    for (const k of ['useWhen', 'dontUseWhen']) if (!Array.isArray(s[k]) || s[k].length === 0 || !s[k].every((t) => typeof t === 'string' && t.trim())) bad(`${w}: ${k} must be a non-empty list of text`);
    claim(`${w}.checks.errorEnvelope`, s.checks?.errorEnvelope);
    if (!tagIds.has(s.checks?.orderEvidence)) bad(`${w}.checks.orderEvidence: unknown tag`);
    if (!s.checks?.orderNote) bad(`${w}.checks.orderNote: missing (say what the docs state about the order)`);
    const ids = new Set();
    for (const [i, c] of (s.checks?.items || []).entries()) {
      claim(`${w}.checks.items[${i}]`, c);
      if (!c.id || ids.has(c.id)) bad(`${w}.checks.items[${i}]: id missing or repeated`);
      ids.add(c.id);
      if (!messageSources.has(c.messageSource)) bad(`${w}.checks.items[${i}]: messageSource unknown`);
      if (!c.message || !c.label) bad(`${w}.checks.items[${i}]: label and message are required`);
      for (const [variant, alt] of Object.entries(c.alt || {})) if (!alt.message || !messageSources.has(alt.messageSource)) bad(`${w}.checks.items[${i}].alt.${variant}: message and a known messageSource are required`);
    }
    if (!s.mock || typeof s.mock !== 'object') bad(`${w}: mock defaults missing`);
  }

  // ---- issuers
  for (const i of data.issuers.issuers) {
    const w = `issuer ${i.id}`;
    if (!/^https:\/\//.test(i.exampleIssuer || '')) bad(`${w}: exampleIssuer must be an https URL`);
    if (!Array.isArray(i.useWhen) || i.useWhen.length === 0) bad(`${w}: no useWhen`);
    if (!Array.isArray(i.gotchas) || i.gotchas.length === 0) bad(`${w}: no gotchas`);
    claim(`${w}.shape`, i.shape);
    (i.gotchas || []).forEach((g, n) => claim(`${w}.gotchas[${n}]`, g));
    if (!i.pinnedOnly && !i.jwksUrl) bad(`${w}: needs a jwksUrl, or pinnedOnly`);
    if (!i.claims || Object.keys(i.claims).length === 0) bad(`${w}: needs at least one claim to pin`);
  }

  // ---- matrix: every issuer against every surface, exactly once
  const seen = new Set();
  for (const [n, c] of data.matrix.cells.entries()) {
    const w = `matrix[${n}] ${c.issuer} x ${c.surface}`;
    if (!issuers.has(c.issuer)) bad(`${w}: unknown issuer`);
    if (!surfaces.has(c.surface)) bad(`${w}: unknown surface`);
    const key = `${c.issuer}|${c.surface}`;
    if (seen.has(key)) bad(`${w}: listed twice`);
    seen.add(key);
    if (!STATUSES.includes(c.status)) bad(`${w}: unknown status ${c.status}`);
    claim(w, c);
    if (c.status === 'supported' && !['docs', 'measured'].includes(c.evidence)) bad(`${w}: "supported" needs docs or measured evidence`);
    if (!c.note || c.note.length > 500) bad(`${w}: note missing or over 500 characters`);
  }
  for (const i of issuers.keys()) for (const s of surfaceIds) if (!seen.has(`${i}|${s}`)) bad(`matrix: no cell for ${i} x ${s}`);

  // ---- break-its and the expected-outcome table
  const mutIds = new Set(data.breakits.mutations.map((m) => m.id));
  const reached = new Map(surfaceIds.map((s) => [s, new Set()]));
  for (const m of data.breakits.mutations) {
    for (const s of m.appliesTo || []) if (!surfaces.has(s)) bad(`breakit ${m.id}: appliesTo names unknown surface ${s}`);
    const applies = m.appliesTo || surfaceIds;
    const row = data.breakits.expected[m.id];
    if (!row) { bad(`breakit ${m.id}: no expected outcomes`); continue; }
    for (const s of applies) {
      const e = row[s];
      if (!e) { bad(`breakit ${m.id}: no expected outcome for ${s}`); continue; }
      claim(`expected ${m.id} x ${s}`, e);
      if (!['accepted', 'refused'].includes(e.verdict)) bad(`expected ${m.id} x ${s}: bad verdict`);
      if (e.verdict === 'refused') {
        const stages = new Set((surfaces.get(s)?.checks.items || []).map((c) => c.id));
        if (!stages.has(e.stage)) bad(`expected ${m.id} x ${s}: stage "${e.stage}" is not a check of that surface`);
        else reached.get(s).add(e.stage);
      }
    }
    for (const s of Object.keys(row)) if (!applies.includes(s)) bad(`expected ${m.id}: outcome for ${s}, which the break-it does not apply to`);
  }
  for (const id of Object.keys(data.breakits.expected)) if (!mutIds.has(id)) bad(`expected: unknown break-it ${id}`);
  for (const s of data.surfaces.surfaces) for (const c of s.checks.items) if (!reached.get(s.id).has(c.id)) bad(`surface ${s.id}: no break-it reaches the check "${c.id}"`);

  // ---- decision tree: every option leads somewhere, nothing is orphaned, there are no loops
  const { nodes, leaves, start } = data.decide;
  if (!nodes[start]) bad('decide: start node is missing');
  const visitedNodes = new Set(); const visitedLeaves = new Set();
  const stack = [[start, []]];
  while (stack.length) {
    const [id, trail] = stack.pop();
    if (trail.includes(id)) { bad(`decide: a loop through ${id}`); continue; }
    const node = nodes[id];
    if (!node) { bad(`decide: unknown node ${id}`); continue; }
    visitedNodes.add(id);
    if (!node.question || !Array.isArray(node.options) || node.options.length < 2) bad(`decide.${id}: needs a question and at least two options`);
    for (const o of node.options || []) {
      if (o.leaf) { if (!leaves[o.leaf]) bad(`decide.${id}: unknown leaf ${o.leaf}`); else visitedLeaves.add(o.leaf); }
      else if (o.next) stack.push([o.next, [...trail, id]]);
      else bad(`decide.${id}: an option has neither next nor leaf`);
    }
  }
  for (const id of Object.keys(nodes)) if (!visitedNodes.has(id)) bad(`decide: node ${id} is never reached`);
  for (const [id, l] of Object.entries(leaves)) {
    if (!visitedLeaves.has(id)) bad(`decide: leaf ${id} is never reached`);
    if (l.surface !== null && !surfaces.has(l.surface)) bad(`decide.${id}: unknown surface ${l.surface}`);
    if (l.then && !surfaces.has(l.then)) bad(`decide.${id}: unknown surface ${l.then} in then`);
    for (const s of l.alsoConsider || []) if (!surfaces.has(s)) bad(`decide.${id}: alsoConsider names unknown surface ${s}`);
    if (!l.reason || !Array.isArray(l.watchOut) || l.watchOut.length === 0) bad(`decide.${id}: needs a reason and watchOut`);
  }
  for (const [n, m] of data.decide.moreThanOneIssuer.entries()) { claim(`decide.moreThanOneIssuer[${n}]`, m); if (!surfaces.has(m.surface)) bad(`decide.moreThanOneIssuer[${n}]: unknown surface`); }
  for (const s of surfaceIds) if (!data.decide.moreThanOneIssuer.some((m) => m.surface === s)) bad(`decide: no "more than one issuer" answer for ${s}`);

  // ---- seen-in: only labs we actually read, and the file we read
  for (const e of data.seenIn.seenIn) {
    const w = `seenIn ${e.lab}`;
    if (!labs.has(e.lab)) bad(`${w}: lab is not in the labs list`);
    if (!Array.isArray(e.checkedIn) || e.checkedIn.length === 0 || !e.checkedIn.every((f) => typeof f === 'string' && f.trim())) bad(`${w}: no checkedIn (a lab may be listed only if we read a file that confirms it)`);
    if (!/^[0-9a-f]{7}$/.test(e.checkedAtCommit || '')) bad(`${w}: checkedAtCommit must be a 7-character commit`);
    if (!e.role) bad(`${w}: no role`);
    for (const s of e.surfaces || []) if (!surfaces.has(s)) bad(`${w}: unknown surface ${s}`);
    for (const i of e.issuers || []) if (!issuers.has(i)) bad(`${w}: unknown issuer ${i}`);
    if (!(e.surfaces || []).length) bad(`${w}: names no surface`);
  }
  for (const c of data.seenIn.candidates) {
    if (!labs.has(c.lab)) bad(`candidate ${c.lab}: not in the labs list`);
    if (!c.why) bad(`candidate ${c.lab}: no reason`);
    if (data.seenIn.seenIn.some((e) => e.lab === c.lab)) bad(`candidate ${c.lab}: is also listed as seen-in`);
  }
  for (const g of data.seenIn.gaps) {
    if (g.surface && !surfaces.has(g.surface)) bad(`gap ${g.id}: unknown surface ${g.surface}`);
    if (g.lab && !labs.has(g.lab)) bad(`gap ${g.id}: unknown lab ${g.lab}`);
    if (!g.text) bad(`gap ${g.id}: no text`);
  }

  // ---- hosts: only .example or .invalid, apart from the vendor's public documentation links
  for (const [file, value] of Object.entries(data)) {
    for (const [text, where] of strings(value, file)) {
      for (const m of text.matchAll(URL_HOST)) {
        const host = m[1].replace(/\/$/, '');
        const isDocsLink = /^sources\.sources\[\d+\]\.where$/.test(where) && host === 'docs.pingidentity.com';
        if (!hostOk(host) && !isDocsLink) bad(`${where}: host "${host}" is not on .example or .invalid`);
      }
    }
  }
  return problems;
}

export const getSurface = (id) => DATA.surfaces.surfaces.find((s) => s.id === id) || null;
export const getIssuer = (id) => DATA.issuers.issuers.find((i) => i.id === id) || null;
export const getCell = (issuerId, surfaceId) => DATA.matrix.cells.find((c) => c.issuer === issuerId && c.surface === surfaceId) || null;

// The labs that show an issuer, joined from seen-in. An empty list is an honest answer.
export const labsShowing = (issuerId) => DATA.seenIn.seenIn.filter((e) => e.issuers.includes(issuerId)).map((e) => e.lab);
export const labsForSurface = (surfaceId) => DATA.seenIn.seenIn.filter((e) => e.surfaces.includes(surfaceId)).map((e) => e.lab);

// Counts of each evidence tag across the matrix, for the census.
export function evidenceCensus(data = DATA) {
  const census = Object.fromEntries(data.evidence.tags.map((t) => [t.id, 0]));
  for (const c of data.matrix.cells) census[c.evidence] += 1;
  return census;
}
