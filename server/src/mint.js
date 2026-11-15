// Mint a MOCK-ISSUED token for one issuer on one surface, optionally with one deliberate fault (a "break-it").
// The token is really signed with this lab's own RSA key for that issuer. It is not a token from the real product.
import crypto from 'node:crypto';
import { DATA } from './data.js';
import { ACCESS_TOKEN_TYPE, AUDIENCE, JWT_TYPE, REDEEMER_ISSUER, RESOURCE, pinnedClaim } from './config.js';
import { fakeJwe, signHS256, signRS256, tamperSignature, unsecured } from './jwt.js';
import { hmacConfusionSecret, signingKey } from './keys.js';

export const mutationIds = () => DATA.breakits.mutations.map((m) => m.id);
export const mutationApplies = (mutationId, surfaceId) => {
  const m = DATA.breakits.mutations.find((x) => x.id === mutationId);
  return Boolean(m) && (!m.appliesTo || m.appliesTo.includes(surfaceId));
};

// The audience, redeemer and resource a token is made FOR are fixed per surface. They do not follow a visitor's changes to
// the product's settings: changing "Audience" on the product while the issuer keeps writing the old one is exactly the
// mistake the lab exists to show.
function audienceFor(surfaceId) {
  return surfaceId === 'pf-idjag' ? REDEEMER_ISSUER : AUDIENCE[surfaceId];
}

export function mint({ issuer, surfaceId, config, mutation = 'none', now }) {
  if (!mutationApplies(mutation, surfaceId)) throw Object.assign(new Error(`the break-it "${mutation}" does not apply to ${surfaceId}`), { code: 'bad_mutation' });
  const iat = now - 60;
  const claims = { iss: issuer.exampleIssuer, sub: issuer.sub, aud: audienceFor(surfaceId), exp: iat + 3600, jti: crypto.randomUUID(), ...structuredClone(issuer.claims) };
  if (issuer.hasIat) claims.iat = iat;
  if (issuer.hasNbf) claims.nbf = iat;
  if (surfaceId === 'pf-idjag') { claims.client_id = 'agent-client'; claims.resource = RESOURCE; }
  const header = { typ: surfaceId === 'pf-idjag' ? 'oauth-id-jag+jwt' : 'JWT', kid: signingKey(issuer.id, 1).kid };
  const ctx = { tokenType: JWT_TYPE, configPatch: {} };
  let key = signingKey(issuer.id, 1);

  switch (mutation) {
    case 'none': break;
    case 'wrong-iss': claims.iss = 'https://not-trusted.example/'; break;
    case 'iss-trailing-slash': claims.iss = claims.iss.endsWith('/') ? claims.iss.slice(0, -1) : `${claims.iss}/`; break;
    case 'iss-case': claims.iss = claims.iss.replace(/^(https?:\/\/)([a-z])/, (_m, a, b) => a + b.toUpperCase()); break;
    case 'wrong-aud': claims.aud = 'https://other.example/api'; break;
    case 'expired': if (issuer.hasIat) claims.iat = now - 7200; if (issuer.hasNbf) claims.nbf = now - 7200; claims.exp = now - 3600; break;
    case 'not-yet-valid': claims.nbf = now + 3600; break;
    case 'long-lifetime': claims.exp = (claims.iat ?? now) + 2592000; break;
    case 'missing-exp': delete claims.exp; break;
    case 'missing-iat': delete claims.iat; break;
    case 'wrong-sub': claims.sub = 'someone-else'; break;
    case 'missing-required-claim': delete claims[surfaceId === 'pf-idjag' ? 'client_id' : pinnedClaim(issuer)]; break;
    case 'wrong-resource': claims.resource = 'https://other.example/mcp'; break;
    case 'wrong-token-type': ctx.tokenType = ACCESS_TOKEN_TYPE; break;
    case 'not-assigned': ctx.configPatch.assigned = false; break;
    case 'disabled-identity': ctx.configPatch.Enabled = false; break;
    case 'wrong-typ': header.typ = 'JWT'; break;
    case 'unknown-kid': key = signingKey(issuer.id, 2); header.kid = key.kid; break;
    default: break;
  }

  let token;
  if (mutation === 'alg-none') token = unsecured(header, claims);
  else if (mutation === 'hs256') token = signHS256(header, claims, hmacConfusionSecret(issuer.id));
  else if (mutation === 'nested-jwe') token = fakeJwe(header.kid);
  else {
    token = signRS256(header, claims, key.privateKey);
    if (mutation === 'tampered-signature') token = tamperSignature(token);
  }
  return { token, ctx };
}
