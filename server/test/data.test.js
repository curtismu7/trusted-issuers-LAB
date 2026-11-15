import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DATA, evidenceCensus, labsShowing, loadData, validateData } from '../src/data.js';

const fresh = () => structuredClone(loadData());
const problemsWith = (mutate) => { const d = fresh(); mutate(d); return validateData(d); };
const has = (problems, text) => problems.some((p) => p.includes(text));

test('the shipped data has no problems', () => {
  assert.deepEqual(validateData(), []);
});

test('four surfaces, fourteen issuers, and a cell for every pair', () => {
  assert.equal(DATA.surfaces.surfaces.length, 4);
  assert.equal(DATA.issuers.issuers.length, 14);
  assert.equal(DATA.matrix.cells.length, 56);
  const pairs = new Set(DATA.matrix.cells.map((c) => `${c.issuer}|${c.surface}`));
  assert.equal(pairs.size, 56);
});

test('the evidence census adds up to the matrix', () => {
  const census = evidenceCensus();
  assert.equal(Object.values(census).reduce((a, b) => a + b, 0), 56);
  assert.ok(census.docs > 0 && census.measured > 0 && census['lab-reading'] > 0 && census.deck > 0 && census.unverified > 0);
});

test('every issuer that a lab shows is joined to a lab that exists', () => {
  const labs = new Set(DATA.seenIn.labs.map((l) => l.id));
  for (const i of DATA.issuers.issuers) for (const l of labsShowing(i.id)) assert.ok(labs.has(l));
  assert.deepEqual(DATA.issuers.issuers.filter((i) => labsShowing(i.id).length === 0).map((i) => i.id).sort(), ['docker-sensor', 'eks', 'pingam']);
});

// ---- the validator really does fail on each kind of mistake ----
test('a claim with no evidence tag fails', () => {
  const p = problemsWith((d) => { delete d.surfaces.surfaces[0].fields[0].evidence; });
  assert.ok(has(p, 'evidence tag missing'), p.join('\n'));
});

test('a claim with no source, or a source that does not exist, fails', () => {
  assert.ok(has(problemsWith((d) => { d.matrix.cells[0].source = 'no-such-source'; }), 'not in sources.json'));
  assert.ok(has(problemsWith((d) => { delete d.matrix.cells[0].source; }), 'not in sources.json'));
});

test('a tag that does not fit its source fails', () => {
  const p = problemsWith((d) => { d.matrix.cells[0].evidence = 'measured'; });
  assert.ok(has(p, 'does not fit source kind'), p.join('\n'));
});

test('"unsourced" can only back an unverified claim', () => {
  const p = problemsWith((d) => { d.matrix.cells[0].source = 'unsourced'; });
  assert.ok(has(p, 'does not fit source kind') || has(p, 'unsourced'), p.join('\n'));
});

test('a "supported" cell needs docs or measured evidence', () => {
  const p = problemsWith((d) => {
    const c = d.matrix.cells.find((x) => x.status === 'supported' && x.evidence === 'docs');
    c.evidence = 'lab-reading'; c.source = 'l-inference';
  });
  assert.ok(has(p, '"supported" needs docs or measured'), p.join('\n'));
});

test('a seen-in lab with no checkedIn fails', () => {
  const p = problemsWith((d) => { d.seenIn.seenIn[0].checkedIn = []; });
  assert.ok(has(p, 'no checkedIn'), p.join('\n'));
});

test('a surface with no useWhen fails, and so does an issuer with none', () => {
  assert.ok(has(problemsWith((d) => { d.surfaces.surfaces[1].useWhen = []; }), 'useWhen must be a non-empty list'), 'surface useWhen');
  assert.ok(has(problemsWith((d) => { delete d.issuers.issuers[3].useWhen; }), 'no useWhen'));
});

test('a reference to an id that does not exist fails', () => {
  assert.ok(has(problemsWith((d) => { d.matrix.cells[0].issuer = 'nobody'; }), 'unknown issuer'));
  assert.ok(has(problemsWith((d) => { d.matrix.cells[0].surface = 'nowhere'; }), 'unknown surface'));
  assert.ok(has(problemsWith((d) => { d.seenIn.seenIn[0].issuers.push('ghost'); }), 'unknown issuer ghost'));
  assert.ok(has(problemsWith((d) => { d.seenIn.candidates[0].lab = 'ghost-lab'; }), 'not in the labs list'));
  assert.ok(has(problemsWith((d) => { d.decide.nodes['q-where'].options[0].leaf = 'l-nope'; }), 'unknown leaf'));
  assert.ok(has(problemsWith((d) => { d.breakits.expected['wrong-iss']['p1-exchange'].stage = 'nope'; }), 'is not a check of that surface'));
});

test('a missing matrix cell fails', () => {
  assert.ok(has(problemsWith((d) => { d.matrix.cells.pop(); }), 'no cell for'));
});

test('a break-it that never reaches a check fails', () => {
  const p = problemsWith((d) => { d.breakits.expected['wrong-iss']['p1-exchange'].verdict = 'accepted'; delete d.breakits.expected['wrong-iss']['p1-exchange'].stage; d.breakits.expected['iss-case']['p1-exchange'].verdict = 'accepted'; delete d.breakits.expected['iss-case']['p1-exchange'].stage; d.breakits.expected['iss-trailing-slash']['p1-exchange'].verdict = 'accepted'; delete d.breakits.expected['iss-trailing-slash']['p1-exchange'].stage; });
  assert.ok(has(p, 'no break-it reaches the check "issuer"'), p.join('\n'));
});

test('a loop or an orphan in the decision tree fails', () => {
  assert.ok(has(problemsWith((d) => { d.decide.nodes['q-oneoff'].options[0] = { label: 'back', next: 'q-where' }; }), 'a loop'));
  assert.ok(has(problemsWith((d) => { d.decide.nodes['q-orphan'] = { question: 'x', options: [{ label: 'a', leaf: 'l-a' }, { label: 'b', leaf: 'l-b' }] }; }), 'never reached'));
});

test('a real host name fails; .example and .invalid pass', () => {
  assert.ok(has(problemsWith((d) => { d.issuers.issuers[0].gotchas[0].text = 'See https://login.realcorp.com/oauth for details'; }), 'is not on .example or .invalid'), 'a real host is caught');
  assert.ok(!has(problemsWith((d) => { d.issuers.issuers[0].gotchas[0].text = 'See https://login.realcorp.example/oauth and https://x.invalid/'; }), 'is not on .example'), '.example and .invalid are allowed');
  assert.ok(has(problemsWith((d) => { d.issuers.issuers[0].typicalAud = 'api://example-app'; }), 'is not on .example or .invalid'), 'a bare scheme host is caught');
});

test('only the vendor docs host is allowed in a docs source link', () => {
  assert.ok(has(problemsWith((d) => { d.sources.sources[0].where = 'https://docs.other-vendor.com/page'; }), 'is not on .example or .invalid'));
});

test('a message source we do not know fails', () => {
  assert.ok(has(problemsWith((d) => { d.surfaces.surfaces[0].checks.items[0].messageSource = 'made up'; }), 'messageSource unknown'));
});

test('the order of the checks is labelled for every surface', () => {
  for (const s of DATA.surfaces.surfaces) { assert.ok(s.checks.orderNote.length > 20); assert.ok(['unverified', 'docs', 'measured', 'deck', 'lab-reading'].includes(s.checks.orderEvidence)); }
  const b = DATA.surfaces.surfaces.find((s) => s.id === 'p1az-oauth');
  assert.match(b.checks.orderNote, /do not say they run in that order/i, 'B must say the docs state no order');
});
