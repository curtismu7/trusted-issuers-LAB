// One verifier per trust surface. Each runs the surface's checks, in the order listed in data/surfaces.json, over a trust
// configuration that uses the product's own field names, with REAL signature verification (RS256 on node:crypto).
// The verifier stops at the first failing check and marks the rest "skipped". The order is the lab's: the sources do not
// state one (see each surface's orderNote), so the grid of break-its only ever breaks ONE thing at a time.
//
// A refusal carries two texts. `message` is the product's wording where we have it (docs or measured) and says where
// it came from; `detail` is always lab-written and names the actual values. When the cause is one whose product text
// we do not have (for example HS256 against a key set), the verifier marks it inexact and `message` falls back to the
// lab's own wording: lab wording is never shown as the product's text.
import { DATA, getSurface } from './data.js';
import { JWT_TYPE } from './config.js';
import { audList, isFiniteNumber, parseCompact, verifyRS256 } from './jwt.js';
import { jsonEqual, show } from './util.js';

const ASYMMETRIC = /^(RS|ES|PS)(256|384|512)$/;
const B_ALGS = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512'];
const REQUIRED_D = ['iss', 'sub', 'aud', 'client_id', 'jti', 'exp', 'iat'];
const SKEW_D = 5;

const fail = (detail, extra = {}) => ({ detail, ...extra });
const unsigned = (p) => p.header.alg === 'none' || p.signature === '';

// Find the key by kid, then verify. exact=false marks causes whose product wording we do not have.
function checkSignature(p, jwks) {
  if (p.header.alg !== 'RS256') return fail(`the token says alg ${show(p.header.alg)}, and the key set holds RSA keys: this lab verifies RS256 only`, { subcause: 'alg', exact: false });
  const key = (jwks.keys || []).find((k) => k.kid === p.header.kid);
  if (!key) return fail(`no key with kid ${show(p.header.kid)} in the key set`, { subcause: 'unknown-kid', exact: false });
  return verifyRS256(p.signingInput, p.signature, key) ? null : fail('the signature does not verify with the issuer\'s key');
}

function execute(surfaceId, steps, { parsed, config, now }) {
  const surface = getSurface(surfaceId);
  const checks = [];
  let failure = null;
  for (const [id, fn] of steps) {
    const item = surface.checks.items.find((i) => i.id === id);
    if (failure) { checks.push({ id, label: item.label, status: 'skipped' }); continue; }
    const r = fn();
    if (!r) checks.push({ id, label: item.label, status: 'pass' });
    else { failure = { id, item, ...r }; checks.push({ id, label: item.label, status: 'fail', detail: r.detail }); }
  }
  const claims = parsed.kind === 'jws' ? parsed.payload : null;
  const header = parsed.header ?? null;
  if (!failure) return { verdict: 'accepted', stage: null, checks, claims, header, now };
  const variant = failure.variant && failure.item.alt?.[failure.variant];
  const productText = variant || { message: failure.item.message, messageSource: failure.item.messageSource };
  const useProduct = failure.exact !== false && productText.messageSource !== 'lab wording';
  return {
    verdict: 'refused', stage: failure.id, subcause: failure.subcause ?? null, detail: failure.detail,
    message: useProduct ? productText.message : (failure.exact === false ? failure.detail : productText.message),
    messageSource: useProduct ? productText.messageSource : 'lab wording',
    checks, claims, header, now,
  };
}

// ---- A: PingOne token exchange, trusted issuers -------------------------------------------------------------------
function verifyA({ parsed, config, jwks, now, tokenType }) {
  const ti = config.trustedIssuer;
  const c = parsed.payload ?? {};
  const skew = ti.clockSkew;
  const steps = [
    ['type', () => (tokenType === JWT_TYPE ? null : fail(`the token type is ${show(tokenType)}, not the jwt type`))],
    ['form', () => {
      if (parsed.kind !== 'jws') return fail(`not a signed JWT: ${parsed.reason}`);
      return unsigned(parsed) ? fail('the token is unsigned (alg none or an empty signature)') : null;
    }],
    ['assigned', () => (config.assigned ? null : fail('the calling application has no trusted issuer assigned to it'))],
    ['issuer', () => (c.iss === ti.issuer ? null : fail(`iss ${show(c.iss)} is not the trusted issuer ${show(ti.issuer)}`))],
    ['signature', () => checkSignature(parsed, jwks)],
    ['exp', () => {
      if (c.exp === undefined) return ti.expRequired ? fail('the token has no exp, and the trusted issuer requires one', { variant: 'missing' }) : null;
      if (!isFiniteNumber(c.exp)) return fail('exp is not a number');
      return c.exp > now - skew ? null : fail(`exp ${c.exp} is ${now - c.exp}s in the past (clock skew ${skew}s)`);
    }],
    ['maxfuture', () => {
      if (!ti.maxFutureValidity || c.exp === undefined || !isFiniteNumber(c.exp)) return null;
      return c.exp - now <= ti.maxFutureValidity ? null : fail(`exp is ${c.exp - now}s ahead, more than Max Future Validity ${ti.maxFutureValidity}s`);
    }],
    ['iat', () => (!ti.iatRequired || c.iat !== undefined ? null : fail('the token has no iat, and the trusted issuer requires one'))],
    ['nbf', () => {
      if (c.nbf === undefined) return ti.nbfRequired ? fail('the token has no nbf, and the trusted issuer requires one', { variant: 'missing' }) : null;
      if (!isFiniteNumber(c.nbf)) return fail('nbf is not a number');
      return c.nbf <= now + skew ? null : fail(`nbf ${c.nbf} is ${c.nbf - now}s in the future (clock skew ${skew}s)`);
    }],
    ['aud', () => {
      const wanted = ti.audiences;
      if (!wanted.length) return null;
      return audList(c.aud).some((a) => wanted.includes(a)) ? null : fail(`aud ${show(c.aud)} has none of the configured audiences`);
    }],
  ];
  return execute('p1-exchange', steps, { parsed, config, now });
}

// ---- B: PingOne Authorize, external OAuth servers -----------------------------------------------------------------
function verifyB({ parsed, config, jwks, now }) {
  const s = config.externalOAuthServer;
  const c = parsed.payload ?? {};
  const skew = s.clockSkewTolerance;
  const present = (v) => (Array.isArray(v) ? v.length > 0 : v !== undefined && v !== null && v !== '');
  const steps = [
    ['form', () => {
      if (parsed.kind !== 'jws') return fail(`not a signed JWT: ${parsed.reason}`);
      return unsigned(parsed) ? fail('the token is unsigned (alg none or an empty signature)') : null;
    }],
    ['alg', () => (B_ALGS.includes(parsed.header.alg) ? null : fail(`the algorithm ${show(parsed.header.alg)} is not one of ${B_ALGS.join(', ')}`))],
    ['claims', () => {
      const missing = ['aud', 'exp', 'iat', 'iss'].filter((k) => !present(c[k]));
      return missing.length ? fail(`mandatory claim${missing.length > 1 ? 's' : ''} missing: ${missing.join(', ')}`) : null;
    }],
    ['issuer', () => (s.issuers.includes(c.iss) ? null : fail(`iss ${show(c.iss)} matches none of the configured Issuers (the match is exact and case-sensitive)`))],
    ['audience', () => (audList(c.aud).includes(config.apiService.audience) ? null : fail(`aud ${show(c.aud)} is not the API service's Audience ${show(config.apiService.audience)}`))],
    ['nbf', () => {
      if (c.nbf === undefined) return null;
      return isFiniteNumber(c.nbf) && c.nbf <= now + skew ? null : fail(`nbf ${show(c.nbf)} is after the validation time (clock skew ${skew}s)`);
    }],
    ['exp', () => {
      if (!isFiniteNumber(c.exp) || c.exp <= now - skew) return fail(`exp ${show(c.exp)} is not after the validation time (clock skew ${skew}s)`);
      if (isFiniteNumber(c.iat) && c.exp <= c.iat) return fail('exp is not after iat');
      if (isFiniteNumber(c.nbf) && c.exp <= c.nbf) return fail('exp is not after nbf');
      return null;
    }],
    ['signature', () => checkSignature(parsed, jwks)],
  ];
  return execute('p1az-oauth', steps, { parsed, config, now });
}

// ---- C: PingOne Privilege, Federated Identity ---------------------------------------------------------------------
function verifyC({ parsed, config, jwks, now }) {
  const f = config.Federation;
  const c = parsed.payload ?? {};
  const cap = f.MaxTokenLifetimeSec || 3600;
  const steps = [
    ['form', () => (parsed.kind === 'jws' ? null : fail(`not a readable JWT: ${parsed.reason}`))],
    ['identity', () => (config.Enabled === false ? fail('the Federated Identity has Enabled set to false') : null)],
    ['alg', () => (ASYMMETRIC.test(String(parsed.header.alg)) ? null : fail(`the algorithm ${show(parsed.header.alg)} is not on the asymmetric allow-list (never none, never HS256)`))],
    ['issuer', () => (c.iss === f.Issuer ? null : fail(`iss ${show(c.iss)} is not Federation.Issuer ${show(f.Issuer)}`))],
    ['keyset', () => ((jwks.keys || []).some((k) => k.kid === parsed.header.kid) ? null : fail(`kid ${show(parsed.header.kid)} is not in the key set; one refresh was tried and the key is still not there`))],
    ['signature', () => checkSignature(parsed, jwks)],
    ['expiry', () => {
      if (c.exp === undefined) return fail('the token has no exp');
      return isFiniteNumber(c.exp) && c.exp > now ? null : fail(`exp ${show(c.exp)} has passed`);
    }],
    ['notbefore', () => (c.nbf === undefined || (isFiniteNumber(c.nbf) && c.nbf <= now) ? null : fail(`nbf ${show(c.nbf)} has not been reached`))],
    ['issued', () => {
      if (c.iat === undefined) return fail('the token has no iat');
      return isFiniteNumber(c.iat) && c.iat <= now ? null : fail(`iat ${show(c.iat)} is in the future`);
    }],
    ['lifetime', () => (c.exp - c.iat <= cap ? null : fail(`exp minus iat is ${c.exp - c.iat}s, over the cap of ${cap}s`))],
    ['audience', () => (audList(c.aud).includes(f.Audience) ? null : fail(`aud ${show(c.aud)} is not Federation.Audience ${show(f.Audience)}`))],
    ['subject', () => (f.AllowAnySubject || c.sub === f.Subject ? null : fail(`sub ${show(c.sub)} is not Federation.Subject ${show(f.Subject)}`))],
    ['claims', () => {
      const wrong = Object.entries(f.RequiredClaims || {}).filter(([k, v]) => !Object.hasOwn(c, k) || !jsonEqual(c[k], v)).map(([k]) => k);
      return wrong.length ? fail(`required claim${wrong.length > 1 ? 's' : ''} missing or different: ${wrong.join(', ')}`) : null;
    }],
  ];
  const result = execute('privilege-fi', steps, { parsed, config, now });
  if (result.verdict === 'accepted') result.log = `workload token accepted for key ${show(config.Description, 60)} issuer=${show(c.iss, 80)} subject=${show(c.sub, 80)}`;
  else result.log = `workload token rejected: ${result.stage}`;
  return result;
}

// ---- D: PingFederate, ID-JAG trusted IdP --------------------------------------------------------------------------
function verifyD({ parsed, config, jwks, now }) {
  const c = parsed.payload ?? {};
  const steps = [
    ['form', () => (parsed.kind === 'jws' ? null : fail(`not a readable JWT: ${parsed.reason}`))],
    ['alg', () => (parsed.header.alg === 'RS256' ? null : fail(`the algorithm ${show(parsed.header.alg)} is not RS256`))],
    ['typ', () => (parsed.header.typ === 'oauth-id-jag+jwt' ? null : fail(`the header typ is ${show(parsed.header.typ)}, not oauth-id-jag+jwt`))],
    ['issuer', () => (c.iss === config.idpConnection.entityId ? null : fail(`iss ${show(c.iss)} is not an IdP connection's entity id ${show(config.idpConnection.entityId)}`))],
    ['signature', () => checkSignature(parsed, jwks)],
    ['claims', () => {
      const missing = REQUIRED_D.filter((k) => c[k] === undefined || c[k] === null || c[k] === '');
      return missing.length ? fail(`required claim${missing.length > 1 ? 's' : ''} missing: ${missing.join(', ')}`) : null;
    }],
    ['audience', () => (typeof c.aud === 'string' && c.aud === config.redeemerIssuer ? null : fail(`aud ${show(c.aud)} is not this server's issuer ${show(config.redeemerIssuer)} as a single value`))],
    ['exp', () => (isFiniteNumber(c.exp) && c.exp > now - SKEW_D ? null : fail(`exp ${show(c.exp)} has passed (tolerance ${SKEW_D}s)`))],
    ['resource', () => (config.tokenManager.resourceUris.includes(c.resource) ? null : fail(`resource ${show(c.resource)} is not listed on the token manager`))],
  ];
  return execute('pf-idjag', steps, { parsed, config, now });
}

const VERIFIERS = { 'p1-exchange': verifyA, 'p1az-oauth': verifyB, 'privilege-fi': verifyC, 'pf-idjag': verifyD };

// What each surface sends back to the caller on a refusal. The wrapper's shape is only measured for PingOne exchange.
const ENVELOPES = {
  'p1-exchange': (r) => ({ http: 400, body: { error: 'invalid_request', error_description: getSurface('p1-exchange').checks.errorEnvelope.prefix + r.message }, shapeSource: 'measured' }),
  'p1az-oauth': (r) => ({ http: 401, headers: { 'WWW-Authenticate': `Bearer error="invalid_token", error_description=${JSON.stringify(r.message)}` }, body: null, shapeSource: 'lab wording' }),
  'privilege-fi': (r) => ({ http: 401, body: { error: r.message }, shapeSource: 'lab wording' }),
  'pf-idjag': (r) => ({ http: 400, body: { error: r.stage === 'resource' ? 'invalid_target' : 'invalid_grant', error_description: r.message }, shapeSource: 'lab wording' }),
};

export const envelope = (surfaceId, result) => (result.verdict === 'refused' ? ENVELOPES[surfaceId](result) : { http: 200, body: null, shapeSource: 'lab wording' });

export const stageIds = (surfaceId) => getSurface(surfaceId).checks.items.map((i) => i.id);

export function verify(surfaceId, { token, config, jwks, now, tokenType = JWT_TYPE }) {
  const fn = VERIFIERS[surfaceId];
  if (!fn) throw Object.assign(new Error(`unknown surface ${surfaceId}`), { code: 'bad_surface' });
  const parsed = parseCompact(token);
  const result = fn({ parsed, config, jwks, now, tokenType });
  result.response = envelope(surfaceId, result);
  return result;
}

export const SURFACE_IDS = DATA.surfaces.surfaces.map((s) => s.id);
