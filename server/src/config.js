// The trust configuration for one issuer on one surface, in each product's own field names, and the few settings a
// visitor may change. Overrides go through a strict allow-list with types and bounds: anything else is refused, never
// merged, so a hostile body cannot reach a prototype or add a setting the lab does not model.
import { DATA } from './data.js';

export const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

// The audience each surface's token is made for (the thing the recipient calls itself).
export const AUDIENCE = {
  'p1-exchange': 'https://api.example/orders',
  'p1az-oauth': 'https://api.example/orders',
  'privilege-fi': 'https://gateway.example/mcp/orders',
  'pf-idjag': 'https://pf-redeemer.example',
};
export const REDEEMER_ISSUER = AUDIENCE['pf-idjag'];
export const RESOURCE = 'https://mcp.example/orders';

const PLATFORM = { k8s: 'kubernetes', eks: 'kubernetes', 'github-actions': 'github_actions', spiffe: 'spiffe', 'docker-sensor': 'docker' };
export const platformOf = (issuerId) => PLATFORM[issuerId] || 'oidc';

// The first claim an issuer sets that a surface can be told to require.
export const pinnedClaim = (issuer) => Object.keys(issuer.claims)[0];

// keys: the key set the product holds for this issuer. For the static matrix view pass null and a placeholder is shown.
export function defaultConfig(issuer, surfaceId, keys = null) {
  const jwksText = keys ? JSON.stringify(keys) : '{"keys":[ ...the issuer\'s public keys... ]}';
  const keySource = issuer.pinnedOnly ? { jwks: jwksText } : { jwksUrl: issuer.jwksUrl };
  const mock = DATA.surfaces.surfaces.find((s) => s.id === surfaceId)?.mock;
  if (!mock) return null;
  switch (surfaceId) {
    case 'p1-exchange':
      return { trustedIssuer: { name: issuer.name, issuer: issuer.exampleIssuer, ...keySource, ...structuredClone(mock.trustedIssuer) }, assigned: mock.assigned };
    case 'p1az-oauth':
      return { externalOAuthServer: { name: issuer.name, issuers: [issuer.exampleIssuer], ...keySource, ...structuredClone(mock.externalOAuthServer) }, apiService: structuredClone(mock.apiService) };
    case 'privilege-fi':
      return {
        Enabled: mock.Enabled,
        Description: `Federated Identity for ${issuer.name}`,
        Scopes: [...mock.Scopes],
        UserClaim: 'sub',
        Federation: {
          Issuer: issuer.exampleIssuer,
          Audience: AUDIENCE['privilege-fi'],
          Subject: issuer.sub,
          AllowAnySubject: mock.Federation.AllowAnySubject,
          ...(issuer.pinnedOnly ? { JWKS: jwksText } : { JwksURI: issuer.jwksUrl }),
          MaxTokenLifetimeSec: mock.Federation.MaxTokenLifetimeSec,
          RequiredClaims: { [pinnedClaim(issuer)]: issuer.claims[pinnedClaim(issuer)] },
          Platform: platformOf(issuer.id),
        },
      };
    case 'pf-idjag':
      return {
        idpConnection: { entityId: issuer.exampleIssuer, ...keySource },
        client: { grantType: 'EXTENSION (urn:ietf:params:oauth:grant-type:jwt-bearer)', clientId: 'agent-client' },
        tokenManager: { resourceUris: [...mock.tokenManager.resourceUris] },
        redeemerIssuer: mock.redeemerIssuer,
      };
    default:
      return null;
  }
}

// ---- overrides ----------------------------------------------------------------------------------------------------

const bool = (v) => typeof v === 'boolean';
const int = (min, max) => (v) => Number.isInteger(v) && v >= min && v <= max;
const text = (v) => typeof v === 'string' && v.length >= 1 && v.length <= 200 && !/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/.test(v);
const textList = (maxItems) => (v) => Array.isArray(v) && v.length <= maxItems && v.every(text);
const claimsMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length <= 6
  && Object.entries(v).every(([k, x]) => /^[A-Za-z0-9_.:/-]{1,40}$/.test(k) && !['__proto__', 'constructor', 'prototype'].includes(k) && typeof x === 'string' && text(x));

// path -> validator. A path is dot-separated and never longer than three parts.
const ALLOWED = {
  'p1-exchange': {
    'trustedIssuer.audiences': textList(5), 'trustedIssuer.expRequired': bool, 'trustedIssuer.iatRequired': bool, 'trustedIssuer.nbfRequired': bool,
    'trustedIssuer.clockSkew': int(0, 600), 'trustedIssuer.maxFutureValidity': int(0, 31536000), assigned: bool,
  },
  'p1az-oauth': { 'externalOAuthServer.issuers': textList(5), 'externalOAuthServer.clockSkewTolerance': int(0, 3600), 'apiService.audience': text },
  'privilege-fi': {
    Enabled: bool, 'Federation.Audience': text, 'Federation.Subject': text, 'Federation.AllowAnySubject': bool,
    'Federation.MaxTokenLifetimeSec': int(0, 86400), 'Federation.RequiredClaims': claimsMap,
  },
  'pf-idjag': { 'tokenManager.resourceUris': textList(5), redeemerIssuer: text },
};

export class OverrideError extends Error {
  constructor(message) { super(message); this.code = 'bad_override'; }
}

// Flatten {a:{b:1}} into {'a.b':1}, but stop at a leaf the allow-list treats as a whole value (a list or a claims map).
function flatten(obj, allowed, prefix = '', depth = 0, out = {}) {
  if (depth > 3) throw new OverrideError('overrides are nested too deeply');
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) throw new OverrideError('overrides must be an object');
  for (const k of Object.keys(obj)) {
    if (['__proto__', 'constructor', 'prototype'].includes(k)) throw new OverrideError(`override key "${k}" is not allowed`);
    const p = prefix ? `${prefix}.${k}` : k;
    if (Object.hasOwn(allowed, p)) out[p] = obj[k];
    else if (obj[k] !== null && typeof obj[k] === 'object' && !Array.isArray(obj[k]) && Object.keys(allowed).some((a) => a.startsWith(`${p}.`))) flatten(obj[k], allowed, p, depth + 1, out);
    else throw new OverrideError(`"${p}" is not a setting this lab lets you change`);
  }
  return out;
}

function setPath(obj, path, value) {
  const parts = path.split('.');
  let cur = obj;
  for (const part of parts.slice(0, -1)) cur = cur[part];
  cur[parts.at(-1)] = value;
}

export function applyOverrides(config, surfaceId, overrides) {
  if (overrides === undefined || overrides === null) return config;
  const allowed = ALLOWED[surfaceId];
  const flat = flatten(overrides, allowed);
  for (const [path, value] of Object.entries(flat)) {
    if (!allowed[path](value)) throw new OverrideError(`"${path}" has a value this lab does not accept`);
    setPath(config, path, structuredClone(value));
  }
  return config;
}

// PingOne refuses a clock skew above 60 when you save the trusted issuer (measured, 2026-10-27).
export const CLOCK_SKEW_REFUSAL = { message: 'clockSkew must be less than or equal to 60', messageSource: 'measured', source: 'm-p1-2026-10-27' };
export function configProblems(surfaceId, config) {
  if (surfaceId === 'p1-exchange' && config.trustedIssuer.clockSkew > 60) return [CLOCK_SKEW_REFUSAL];
  return [];
}
