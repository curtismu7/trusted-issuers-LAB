// POST /api/check: pick an issuer and a surface, then either mint a MOCK-ISSUED token (with at most one deliberate fault)
// or take a token the visitor pasted, and run the surface's checks over it.
import { DATA, getCell, getIssuer, getSurface } from './data.js';
import { ACCESS_TOKEN_TYPE, JWT_TYPE, applyOverrides, configProblems, defaultConfig } from './config.js';
import { HttpError, badRequest } from './errors.js';
import { MAX_TOKEN_CHARS } from './jwt.js';
import { jwks } from './keys.js';
import { mint } from './mint.js';
import { nowSeconds } from './util.js';
import { envelope, verify } from './verify.js';

const TOKEN_TYPES = [JWT_TYPE, ACCESS_TOKEN_TYPE];
const KNOWN_INPUT = ['issuer', 'surface', 'mutation', 'overrides', 'token', 'tokenType'];

export const MOCK_LABEL = 'MOCK-ISSUED: signed by this lab\'s own key for this issuer. It is not a token from the real product.';

export function runCheck(input, { now = nowSeconds() } = {}) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw badRequest('bad_input', 'The body must be a JSON object.');
  for (const k of Object.keys(input)) if (!KNOWN_INPUT.includes(k)) throw badRequest('bad_input', `"${k}" is not a field this call takes.`);
  const { issuer: issuerId, surface: surfaceId, overrides } = input;
  const mutation = input.mutation ?? 'none';
  const tokenType = input.tokenType ?? JWT_TYPE;
  if (typeof issuerId !== 'string' || typeof surfaceId !== 'string') throw badRequest('bad_input', 'issuer and surface are required.');
  if (typeof mutation !== 'string') throw badRequest('bad_input', 'mutation must be text.');
  if (!TOKEN_TYPES.includes(tokenType)) throw badRequest('bad_input', 'tokenType must be the jwt type or the access_token type.');
  const issuer = getIssuer(issuerId);
  const surface = getSurface(surfaceId);
  if (!issuer) throw new HttpError(404, 'unknown_issuer', `There is no issuer called "${issuerId.slice(0, 60)}".`);
  if (!surface) throw new HttpError(404, 'unknown_surface', `There is no surface called "${surfaceId.slice(0, 60)}".`);

  const keys = jwks(issuer.id);
  const config = applyOverrides(defaultConfig(issuer, surfaceId, keys), surfaceId, overrides);
  const problems = configProblems(surfaceId, config);
  if (problems.length) throw new HttpError(422, 'config_refused', problems[0].message, { messageSource: problems[0].messageSource, source: problems[0].source });

  const pasted = typeof input.token === 'string' && input.token.length > 0;
  if (input.token !== undefined && typeof input.token !== 'string') throw badRequest('bad_input', 'token must be text.');
  if (pasted && input.mutation !== undefined) throw badRequest('bad_input', 'Give a token or a break-it, not both.');
  if (pasted && input.token.length > MAX_TOKEN_CHARS) throw badRequest('token_too_long', `A token longer than ${MAX_TOKEN_CHARS} characters is refused.`);

  let token = input.token;
  let ctxTokenType = tokenType;
  if (!pasted) {
    const m = mint({ issuer, surfaceId, config, mutation, now });
    token = m.token;
    if (mutation === 'wrong-token-type') ctxTokenType = m.ctx.tokenType;
    Object.assign(config, m.ctx.configPatch);
  }

  const result = verify(surfaceId, { token, config, jwks: keys, now, tokenType: ctxTokenType });
  // The expected-outcome table assumes the default settings, so it only applies to a minted token with none changed.
  const usesDefaults = !pasted && (overrides === undefined || overrides === null || Object.keys(overrides).length === 0) && tokenType === JWT_TYPE;
  const expected = usesDefaults ? DATA.breakits.expected[mutation]?.[surfaceId] ?? null : null;
  const matchesExpected = expected ? (result.verdict === expected.verdict && (expected.verdict === 'accepted' || result.stage === expected.stage)) : null;

  // If we only have a reading (not the product's own text) for this fault, say so rather than show product wording.
  let downgraded = false;
  if (expected && expected.verdict === 'refused' && result.stage === expected.stage && !['docs', 'measured'].includes(expected.evidence) && ['docs', 'measured'].includes(result.messageSource)) {
    result.message = result.detail; result.messageSource = 'lab wording'; downgraded = true;
    result.response = envelope(surfaceId, result);
  }

  return {
    input: { issuer: issuer.id, surface: surface.id, mutation: pasted ? null : mutation, tokenType: ctxTokenType, pasted },
    now,
    cell: getCell(issuer.id, surface.id),
    trustConfig: config,
    keySet: keys,
    token: pasted ? { label: 'Pasted by you. Its claims are shown decoded; nothing about it is trusted until it is verified.' } : { raw: token, label: MOCK_LABEL },
    header: result.header, claims: result.claims,
    verdict: result.verdict, stage: result.stage, subcause: result.subcause ?? null,
    message: result.message ?? null, messageSource: result.messageSource ?? null, detail: result.detail ?? null, downgraded,
    checks: result.checks, response: result.response, log: result.log ?? null,
    lesson: pasted ? null : DATA.breakits.mutations.find((x) => x.id === mutation).teaches,
    expected, matchesExpected,
  };
}
