import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DATA, getIssuer } from '../src/data.js';
import { runCheck } from '../src/check.js';
import { defaultConfig } from '../src/config.js';
import { signRS256, tamperSignature } from '../src/jwt.js';
import { jwks, signingKey } from '../src/keys.js';
import { mint, mutationApplies } from '../src/mint.js';
import { stageIds, verify } from '../src/verify.js';
import { jsonEqual, show } from '../src/util.js';

const NOW = 1_800_000_000;
const SURFACES = DATA.surfaces.surfaces.map((s) => s.id);
const ISSUERS = DATA.issuers.issuers.map((i) => i.id);

// A hand-built token for the cases the break-its do not cover: the visitor's token, signed by the issuer's real mock key.
function signed(issuerId, claims, header = {}) {
  const i = getIssuer(issuerId);
  const k = signingKey(issuerId, 1);
  return signRS256({ typ: 'JWT', kid: k.kid, ...header }, { iss: i.exampleIssuer, sub: i.sub, aud: 'https://api.example/orders', iat: NOW - 60, exp: NOW + 3540, ...claims }, k.privateKey);
}

test('every issuer, every surface, every break-it: the result is what data/breakits.json says', () => {
  let runs = 0; const wrong = [];
  for (const issuer of ISSUERS) {
    for (const surface of SURFACES) {
      for (const m of DATA.breakits.mutations) {
        if (!mutationApplies(m.id, surface)) continue;
        const r = runCheck({ issuer, surface, mutation: m.id }, { now: NOW });
        runs += 1;
        if (!r.matchesExpected) wrong.push(`${issuer} x ${surface} x ${m.id}: got ${r.verdict}/${r.stage}, expected ${JSON.stringify(r.expected)}`);
      }
    }
  }
  assert.deepEqual(wrong, []);
  assert.equal(runs, 14 * (17 * 4 + 5));
});

test('the audience, redeemer and resource a token is made for match the surfaces\' default settings', () => {
  for (const s of DATA.surfaces.surfaces) {
    const issuer = getIssuer('okta');
    const cfg = defaultConfig(issuer, s.id, null);
    const claims = JSON.parse(Buffer.from(mint({ issuer, surfaceId: s.id, config: cfg, now: NOW }).token.split('.')[1], 'base64url'));
    const want = { 'p1-exchange': cfg.trustedIssuer?.audiences[0], 'p1az-oauth': cfg.apiService?.audience, 'privilege-fi': cfg.Federation?.Audience, 'pf-idjag': cfg.redeemerIssuer }[s.id];
    assert.equal(claims.aud, want, `${s.id}: the token's aud is not the default setting`);
  }
  const d = defaultConfig(getIssuer('pf'), 'pf-idjag', null);
  const claims = JSON.parse(Buffer.from(mint({ issuer: getIssuer('pf'), surfaceId: 'pf-idjag', config: d, now: NOW }).token.split('.')[1], 'base64url'));
  assert.equal(claims.resource, d.tokenManager.resourceUris[0]);
  assert.equal(claims.client_id, d.client.clientId);
});

test('a good token is accepted by every surface, for every issuer', () => {
  for (const issuer of ISSUERS) for (const surface of SURFACES) {
    const r = runCheck({ issuer, surface }, { now: NOW });
    assert.equal(r.verdict, 'accepted', `${issuer} x ${surface} refused at ${r.stage}: ${r.detail}`);
    assert.ok(r.checks.every((c) => c.status === 'pass'));
  }
});

test('the checks a verifier runs are the checks data/surfaces.json lists, in the same order', () => {
  for (const surface of SURFACES) {
    const listed = DATA.surfaces.surfaces.find((s) => s.id === surface).checks.items.map((i) => i.id);
    assert.deepEqual(stageIds(surface), listed);
    const r = runCheck({ issuer: 'private', surface }, { now: NOW });
    assert.deepEqual(r.checks.map((c) => c.id), listed);
  }
});

test('a refusal marks the failing check and skips the rest', () => {
  const r = runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'wrong-aud' }, { now: NOW });
  const statuses = Object.fromEntries(r.checks.map((c) => [c.id, c.status]));
  assert.equal(statuses.aud, 'fail');
  assert.equal(statuses.issuer, 'pass');
  assert.equal(statuses.signature, 'pass');
  const wrongIss = runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'wrong-iss' }, { now: NOW });
  assert.equal(wrongIss.checks.find((c) => c.id === 'issuer').status, 'fail');
  assert.equal(wrongIss.checks.find((c) => c.id === 'signature').status, 'skipped');
});

test('verification is real: a token signed by one issuer fails against another issuer\'s keys', () => {
  const i = getIssuer('okta');
  const config = defaultConfig(i, 'p1-exchange', jwks('okta'));
  const { token } = mint({ issuer: i, surfaceId: 'p1-exchange', config, now: NOW });
  const ok = verify('p1-exchange', { token, config, jwks: jwks('okta'), now: NOW });
  assert.equal(ok.verdict, 'accepted');
  const wrongKeys = verify('p1-exchange', { token, config, jwks: jwks('auth0'), now: NOW });
  assert.equal(wrongKeys.stage, 'signature');
  const tampered = verify('p1-exchange', { token: tamperSignature(token), config, jwks: jwks('okta'), now: NOW });
  assert.equal(tampered.stage, 'signature');
});

test('a payload changed after signing is refused', () => {
  const i = getIssuer('okta');
  const config = defaultConfig(i, 'p1az-oauth', jwks('okta'));
  const { token } = mint({ issuer: i, surfaceId: 'p1az-oauth', config, now: NOW });
  const [h, p, s] = token.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url'));
  payload.sub = 'attacker';
  const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
  assert.equal(verify('p1az-oauth', { token: forged, config, jwks: jwks('okta'), now: NOW }).stage, 'signature');
});

test('the message labels are honest: product wording is only ever a text from the sources', () => {
  const product = new Set();
  for (const s of DATA.surfaces.surfaces) for (const it of s.checks.items) {
    if (it.messageSource !== 'lab wording') product.add(it.message);
    for (const alt of Object.values(it.alt || {})) if (alt.messageSource !== 'lab wording') product.add(alt.message);
  }
  let labelled = 0;
  for (const issuer of ISSUERS) for (const surface of SURFACES) for (const m of DATA.breakits.mutations) {
    if (!mutationApplies(m.id, surface) || m.id === 'none') continue;
    const r = runCheck({ issuer, surface, mutation: m.id }, { now: NOW });
    if (r.verdict !== 'refused') continue;
    if (['docs', 'measured'].includes(r.messageSource)) {
      labelled += 1;
      assert.ok(product.has(r.message), `${issuer} x ${surface} x ${m.id}: "${r.message}" is labelled ${r.messageSource} but is not a text from the sources`);
    }
  }
  assert.ok(labelled > 100, 'expected many refusals to carry a measured or docs text');
});

test('when we only have a reading for a fault, the product\'s measured text is not shown for it', () => {
  const r = runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'iss-trailing-slash' }, { now: NOW });
  assert.equal(r.verdict, 'refused'); assert.equal(r.stage, 'issuer');
  assert.equal(r.downgraded, true);
  assert.equal(r.messageSource, 'lab wording');
  assert.notEqual(r.message, DATA.surfaces.surfaces[0].checks.items.find((i) => i.id === 'issuer').message);
  const measured = runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'wrong-iss' }, { now: NOW });
  assert.equal(measured.messageSource, 'measured');
  assert.equal(measured.downgraded, false);
});

test('the PingOne refusal envelope is the measured one', () => {
  const r = runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'expired' }, { now: NOW });
  assert.equal(r.response.http, 400);
  assert.equal(r.response.body.error, 'invalid_request');
  assert.equal(r.response.body.error_description, 'The request could not be completed. The request was malformed or invalid.: The provided JWT has expired');
  assert.equal(r.response.shapeSource, 'measured');
});

test('surface B refuses with 401 and says its wrapper is our wording', () => {
  const r = runCheck({ issuer: 'okta', surface: 'p1az-oauth', mutation: 'wrong-aud' }, { now: NOW });
  assert.equal(r.response.http, 401);
  assert.match(r.response.headers['WWW-Authenticate'], /invalid audience/);
  assert.equal(r.message, 'invalid audience');
  assert.equal(r.messageSource, 'docs');
  assert.equal(r.response.shapeSource, 'lab wording');
});

// ---- surface A: the trusted-issuer settings ----
test('A: the nbf trap. Okta tokens have no nbf, so Require Not-before refuses them with the measured missing-nbf text', () => {
  const r = runCheck({ issuer: 'okta', surface: 'p1-exchange', overrides: { trustedIssuer: { nbfRequired: true } } }, { now: NOW });
  assert.equal(r.stage, 'nbf');
  assert.equal(r.message, 'Missing nbf claim; the Trusted Issuer requires a not-before time');
  assert.equal(r.messageSource, 'measured');
  assert.equal(runCheck({ issuer: 'entra', surface: 'p1-exchange', overrides: { trustedIssuer: { nbfRequired: true } } }, { now: NOW }).verdict, 'accepted', 'Microsoft tokens carry nbf');
});

test('A: a missing exp is refused with the missing-exp text, an expired one with the expired text', () => {
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'missing-exp' }, { now: NOW }).message, 'Missing exp claim; the Trusted Issuer requires an expiration time');
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'expired' }, { now: NOW }).message, 'The provided JWT has expired');
});

test('A: clock skew absorbs a small expiry, zero does not, and above 60 is refused when saved', () => {
  const token = signed('okta', { exp: NOW - 10 });
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', token, overrides: { trustedIssuer: { clockSkew: 30 } } }, { now: NOW }).verdict, 'accepted');
  const zero = runCheck({ issuer: 'okta', surface: 'p1-exchange', token, overrides: { trustedIssuer: { clockSkew: 0 } } }, { now: NOW });
  assert.equal(zero.stage, 'exp');
  assert.throws(() => runCheck({ issuer: 'okta', surface: 'p1-exchange', overrides: { trustedIssuer: { clockSkew: 61 } } }, { now: NOW }), (e) => e.status === 422 && e.code === 'config_refused' && e.message === 'clockSkew must be less than or equal to 60' && e.extra.messageSource === 'measured');
});

test('A: blank Audiences accept any aud; Max Future Validity 0 accepts a long exp; switches off accept missing claims', () => {
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'wrong-aud', overrides: { trustedIssuer: { audiences: [] } } }, { now: NOW }).verdict, 'accepted');
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'long-lifetime', overrides: { trustedIssuer: { maxFutureValidity: 0 } } }, { now: NOW }).verdict, 'accepted');
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'missing-iat', overrides: { trustedIssuer: { iatRequired: false } } }, { now: NOW }).verdict, 'accepted');
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'missing-exp', overrides: { trustedIssuer: { expRequired: false } } }, { now: NOW }).verdict, 'accepted');
});

test('A: an audience list takes any one match', () => {
  const token = signed('okta', { aud: ['https://elsewhere.example/', 'https://api.example/orders'] });
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', token }, { now: NOW }).verdict, 'accepted');
});

test('the expected-outcome table is only used for a minted token with default settings', () => {
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'expired' }, { now: NOW }).matchesExpected, true);
  const changed = runCheck({ issuer: 'okta', surface: 'p1-exchange', mutation: 'expired', overrides: { trustedIssuer: { clockSkew: 30 } } }, { now: NOW });
  assert.equal(changed.expected, null);
  assert.equal(changed.matchesExpected, null);
  assert.equal(runCheck({ issuer: 'okta', surface: 'p1-exchange', token: signed('okta', {}) }, { now: NOW }).expected, null);
});

test('A: the token type must be the jwt type', () => {
  const r = runCheck({ issuer: 'okta', surface: 'p1-exchange', tokenType: 'urn:ietf:params:oauth:token-type:access_token' }, { now: NOW });
  assert.equal(r.stage, 'type');
  assert.equal(r.message, 'Provided token type must be urn:ietf:params:oauth:token-type:jwt');
});

// ---- surface B ----
test('B: one external server can list several Issuers (Microsoft v1.0 and v2.0)', () => {
  const entra = getIssuer('entra');
  const token = signed('entra', { iss: entra.alternateIssuers[0] });
  assert.equal(runCheck({ issuer: 'entra', surface: 'p1az-oauth', token }, { now: NOW }).stage, 'issuer', 'v1.0 alone is not configured');
  const both = runCheck({ issuer: 'entra', surface: 'p1az-oauth', token, overrides: { externalOAuthServer: { issuers: [entra.exampleIssuer, entra.alternateIssuers[0]] } } }, { now: NOW });
  assert.equal(both.verdict, 'accepted');
});

test('B: the audience lives on the API service', () => {
  const r = runCheck({ issuer: 'okta', surface: 'p1az-oauth', overrides: { apiService: { audience: 'https://other-api.example/' } } }, { now: NOW });
  assert.equal(r.stage, 'audience');
});

// ---- surface C ----
test('C: AllowAnySubject lets another subject in; a lifetime cap of 0 means 3600', () => {
  assert.equal(runCheck({ issuer: 'github-actions', surface: 'privilege-fi', mutation: 'wrong-sub', overrides: { Federation: { AllowAnySubject: true } } }, { now: NOW }).verdict, 'accepted');
  assert.equal(runCheck({ issuer: 'github-actions', surface: 'privilege-fi', mutation: 'long-lifetime', overrides: { Federation: { MaxTokenLifetimeSec: 0 } } }, { now: NOW }).stage, 'lifetime');
  assert.equal(runCheck({ issuer: 'github-actions', surface: 'privilege-fi', overrides: { Federation: { MaxTokenLifetimeSec: 60 } } }, { now: NOW }).stage, 'lifetime', 'a 3600s token against a 60s cap');
});

test('C: RequiredClaims pins repository, workflow and environment exactly', () => {
  const required = { repository: 'example-org/orders-agent', environment: 'production' };
  assert.equal(runCheck({ issuer: 'github-actions', surface: 'privilege-fi', overrides: { Federation: { RequiredClaims: required } } }, { now: NOW }).verdict, 'accepted');
  const fork = signed('github-actions', { aud: 'https://gateway.example/mcp/orders', repository: 'someone-else/fork', environment: 'production', sub: 'repo:example-org/orders-agent:ref:refs/heads/main' }, {});
  const r = runCheck({ issuer: 'github-actions', surface: 'privilege-fi', token: fork, overrides: { Federation: { RequiredClaims: required } } }, { now: NOW });
  assert.equal(r.stage, 'claims');
});

test('C: the gateway log lines are labelled as our wording', () => {
  const ok = runCheck({ issuer: 'k8s', surface: 'privilege-fi' }, { now: NOW });
  assert.match(ok.log, /^workload token accepted for key /);
  const no = runCheck({ issuer: 'k8s', surface: 'privilege-fi', mutation: 'wrong-aud' }, { now: NOW });
  assert.equal(no.log, 'workload token rejected: audience');
  assert.equal(no.messageSource, 'lab wording');
});

// ---- surface D ----
test('D: aud must be a single value', () => {
  const token = signed('pf', { aud: ['https://pf-redeemer.example', 'https://other.example'], client_id: 'agent-client', resource: 'https://mcp.example/orders', jti: 'j1' }, { typ: 'oauth-id-jag+jwt' });
  const r = runCheck({ issuer: 'pf', surface: 'pf-idjag', token }, { now: NOW });
  assert.equal(r.stage, 'audience');
});

test('D: the resource must be listed on the token manager', () => {
  const r = runCheck({ issuer: 'pf', surface: 'pf-idjag', overrides: { tokenManager: { resourceUris: ['https://mcp.example/another'] } } }, { now: NOW });
  assert.equal(r.stage, 'resource');
  assert.equal(r.response.body.error, 'invalid_target');
});

// ---- hostile input ----
test('a pasted token that is not a token is refused with a reason, never a crash', () => {
  for (const token of ['abc', 'a.b', 'a.b.c.d', '....', ' ', '\u0000.\u0000.\u0000', 'e30.e30.', 'x'.repeat(9000), `${'e30'}.${'W1tdXQ'}.sig`]) {
    for (const surface of SURFACES) {
      const r = runCheck({ issuer: 'okta', surface, token }, { now: NOW });
      assert.equal(r.verdict, 'refused', `${surface} accepted ${token.slice(0, 20)}`);
    }
  }
});

test('a token over 16 KB is refused before it is read', () => {
  assert.throws(() => runCheck({ issuer: 'okta', surface: 'p1-exchange', token: 'a.'.repeat(9000) }, { now: NOW }), (e) => e.code === 'token_too_long');
});

test('a deeply nested claim neither crashes nor passes a required-claims check', () => {
  const deep = `${'['.repeat(3000)}${']'.repeat(3000)}`;
  const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: signingKey('okta', 1).kid, typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(`{"iss":"https://okta.example/oauth2/aus1example","workload":${deep}}`).toString('base64url');
  const r = runCheck({ issuer: 'okta', surface: 'privilege-fi', token: `${h}.${p}.AAAA` }, { now: NOW });
  assert.equal(r.verdict, 'refused');
  assert.equal(jsonEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] }), true);
  assert.equal(jsonEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 3 }] }), false);
  assert.equal(jsonEqual(JSON.parse(deep), JSON.parse(deep)), false, 'past the depth cap it answers "not equal" rather than recursing');
});

test('values from a token are shown inert: control and bidirectional characters become escapes, long values are cut', () => {
  const shown = show('a‮b\u0000c​d');
  assert.ok(!/[‮\u0000​]/.test(shown));
  assert.match(shown, /\\u202e/);
  assert.ok(show('x'.repeat(500)).length < 140);
  const r = runCheck({ issuer: 'okta', surface: 'p1-exchange', token: signed('okta', { iss: 'https://evil.example/‮slash' }) }, { now: NOW });
  assert.ok(!/[‮]/.test(r.detail));
});

test('overrides: only the listed settings, with the right types and bounds', () => {
  const bad = (overrides, surface = 'p1-exchange') => assert.throws(() => runCheck({ issuer: 'okta', surface, overrides }, { now: NOW }), (e) => e.code === 'bad_override', JSON.stringify(overrides));
  bad({ trustedIssuer: { issuer: 'https://other.example' } });
  bad({ trustedIssuer: { clockSkew: '30' } });
  bad({ trustedIssuer: { clockSkew: -1 } });
  bad({ trustedIssuer: { clockSkew: 99999 } });
  bad({ trustedIssuer: { audiences: 'one' } });
  bad({ trustedIssuer: { audiences: ['a', 'b', 'c', 'd', 'e', 'f'] } });
  bad({ trustedIssuer: { expRequired: 'yes' } });
  bad({ nope: 1 });
  bad(JSON.parse('{"__proto__": {"polluted": true}}'));
  bad(JSON.parse('{"trustedIssuer": {"__proto__": {"polluted": true}}}'));
  bad({ trustedIssuer: { constructor: { prototype: { polluted: true } } } });
  bad(JSON.parse('{"Federation":{"RequiredClaims":{"__proto__":"x"}}}'), 'privilege-fi');
  bad({ Federation: { RequiredClaims: { ok: { nested: 'object' } } } }, 'privilege-fi');
  bad([1, 2]);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
});

test('inputs: unknown fields, unknown ids, a break-it that does not apply, a token and a break-it together', () => {
  const code = (input) => { try { runCheck(input, { now: NOW }); return null; } catch (e) { return e.code; } };
  assert.equal(code({ issuer: 'okta', surface: 'p1-exchange', extra: 1 }), 'bad_input');
  assert.equal(code({ issuer: 'nobody', surface: 'p1-exchange' }), 'unknown_issuer');
  assert.equal(code({ issuer: 'okta', surface: 'nowhere' }), 'unknown_surface');
  assert.equal(code({ issuer: 'okta', surface: 'p1-exchange', mutation: 'wrong-typ' }), 'bad_mutation');
  assert.equal(code({ issuer: 'okta', surface: 'p1-exchange', mutation: 'bogus' }), 'bad_mutation');
  assert.equal(code({ issuer: 'okta', surface: 'p1-exchange', mutation: 'none', token: 'a.b.c' }), 'bad_input');
  assert.equal(code({ issuer: 'okta', surface: 'p1-exchange', tokenType: 'nope' }), 'bad_input');
  assert.equal(code(null), 'bad_input');
  assert.equal(code({ issuer: 5, surface: 'p1-exchange' }), 'bad_input');
});

test('a minted token is labelled MOCK-ISSUED and shown raw; a pasted one is not echoed', () => {
  const minted = runCheck({ issuer: 'okta', surface: 'p1-exchange' }, { now: NOW });
  assert.match(minted.token.label, /^MOCK-ISSUED/);
  assert.equal(minted.token.raw.split('.').length, 3);
  const pasted = runCheck({ issuer: 'okta', surface: 'p1-exchange', token: minted.token.raw }, { now: NOW });
  assert.equal(pasted.token.raw, undefined);
});

test('the lab never generates EC keys and never evaluates text', async () => {
  const { readdirSync, readFileSync } = await import('node:fs');
  const dir = new URL('../src/', import.meta.url);
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.js'))) {
    const src = readFileSync(new URL(f, dir), 'utf8');
    assert.ok(!/generateKeyPair(Sync)?\(\s*['"]ec['"]/.test(src), `${f} generates an EC key`);
    assert.ok(!/\beval\s*\(|new Function\s*\(|node:vm/.test(src), `${f} evaluates text`);
  }
});
