// Compact JWT helpers on node:crypto. RSA only: this lab never generates EC keys (the rulebook bans it).
// Everything that reads a token is bounded: the whole token, each segment and the number of segments have caps,
// and a header or payload must parse to a plain object.
import crypto from 'node:crypto';

export const MAX_TOKEN_CHARS = 16384;
const MAX_SEGMENT_CHARS = 8192;

export const b64u = (input) => Buffer.from(input).toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');
const BASE64URL = /^[A-Za-z0-9_-]*$/;

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function readJsonSegment(seg) {
  if (typeof seg !== 'string' || seg.length === 0 || seg.length > MAX_SEGMENT_CHARS || !BASE64URL.test(seg)) return null;
  try {
    const v = JSON.parse(fromB64u(seg).toString('utf8'));
    return isPlainObject(v) ? v : null;
  } catch { return null; }
}

// kind: 'jws' (three segments), 'jwe' (five segments: an encrypted token), 'opaque' (no dots) or 'malformed'.
export function parseCompact(token) {
  if (typeof token !== 'string' || token.length === 0) return { kind: 'malformed', reason: 'empty or not text' };
  if (token.length > MAX_TOKEN_CHARS) return { kind: 'malformed', reason: `longer than ${MAX_TOKEN_CHARS} characters` };
  if (!token.includes('.')) return { kind: 'opaque', reason: 'no dots: an opaque or reference token' };
  const parts = token.split('.', 7);
  if (parts.length === 5) {
    const header = readJsonSegment(parts[0]);
    return header ? { kind: 'jwe', header, reason: 'five segments: an encrypted token' } : { kind: 'malformed', reason: 'five segments, but the first is not a JSON header' };
  }
  if (parts.length !== 3) return { kind: 'malformed', reason: `${parts.length} dot-separated segments` };
  const header = readJsonSegment(parts[0]);
  const payload = readJsonSegment(parts[1]);
  if (!header) return { kind: 'malformed', reason: 'the header is not a JSON object' };
  if (!payload) return { kind: 'malformed', reason: 'the payload is not a JSON object' };
  if (!BASE64URL.test(parts[2]) || parts[2].length > MAX_SEGMENT_CHARS) return { kind: 'malformed', reason: 'the signature segment is not base64url' };
  return { kind: 'jws', header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] };
}

const segment = (obj) => b64u(JSON.stringify(obj));

export function signRS256(header, payload, privateKey) {
  const input = `${segment({ alg: 'RS256', ...header })}.${segment(payload)}`;
  return `${input}.${b64u(crypto.sign('RSA-SHA256', Buffer.from(input), privateKey))}`;
}

// HS256 with an arbitrary secret. Used for the key-confusion mutation: the public key's text as the HMAC secret.
export function signHS256(header, payload, secret) {
  const input = `${segment({ alg: 'HS256', ...header })}.${segment(payload)}`;
  return `${input}.${b64u(crypto.createHmac('sha256', secret).update(input).digest())}`;
}

// An unsecured JWT: alg none and an empty signature segment.
export function unsecured(header, payload) {
  return `${segment({ ...header, alg: 'none' })}.${segment(payload)}.`;
}

// The shape of an encrypted token: five segments with a JWE header. It carries random bytes, not a real ciphertext:
// the lab only needs a surface to see five segments.
export function fakeJwe(kid) {
  const rand = (n) => b64u(crypto.randomBytes(n));
  return `${segment({ alg: 'dir', enc: 'A256GCM', kid })}..${rand(12)}.${rand(48)}.${rand(16)}`;
}

// Flip the FIRST character of the signature. The last character can hold unused padding bits, so changing it may not change the bytes.
export function tamperSignature(token) {
  const i = token.lastIndexOf('.');
  const sig = token.slice(i + 1);
  if (!sig) return token;
  const swap = sig[0] === 'A' ? 'B' : 'A';
  return `${token.slice(0, i + 1)}${swap}${sig.slice(1)}`;
}

// Verify an RS256 signature against one JWK. Returns false on any problem, never throws.
export function verifyRS256(signingInput, signature, jwk) {
  try {
    if (!jwk || jwk.kty !== 'RSA') return false;
    const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    return crypto.verify('RSA-SHA256', Buffer.from(signingInput), pub, fromB64u(signature));
  } catch { return false; }
}

export const isFiniteNumber = (v) => typeof v === 'number' && Number.isFinite(v);
export const audList = (aud) => (Array.isArray(aud) ? aud : aud === undefined ? [] : [aud]).filter((a) => typeof a === 'string');
