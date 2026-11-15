// In-process signing keys for the MOCK issuers. RSA only (the rulebook bans EC keygen: it aborted Node on CI).
// A key pair is made the first time an issuer is used and kept for the life of the process, so booting is fast.
// Slot 1 is the key an issuer publishes. Slot 2 is a key nobody published, used to show an unknown kid.
import crypto from 'node:crypto';

const pairs = new Map();

function pair(issuerId, slot) {
  const k = `${issuerId}:${slot}`;
  if (!pairs.has(k)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    pairs.set(k, { publicKey, privateKey, kid: `${issuerId}-key-${slot}` });
  }
  return pairs.get(k);
}

export const signingKey = (issuerId, slot = 1) => pair(issuerId, slot);

export function publicJwk(issuerId, slot = 1) {
  const p = pair(issuerId, slot);
  const { kty, n, e } = p.publicKey.export({ format: 'jwk' });
  return { kty, use: 'sig', alg: 'RS256', kid: p.kid, n, e };
}

// The key set the issuer publishes: slot 1 only.
export const jwks = (issuerId) => ({ keys: [publicJwk(issuerId, 1)] });

// What a mock server would hold for "the HMAC secret an attacker guesses": the public key's modulus text.
export const hmacConfusionSecret = (issuerId) => publicJwk(issuerId, 1).n;
