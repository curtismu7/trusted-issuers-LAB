// Real mode: a READ-ONLY issuer discovery probe. For the one issuer URL a visitor types, fetch its discovery document
// (OIDC first, then RFC 8414) and compare the issuer string they would paste into a product with the document's
// `issuer`, character for character. That exact comparison is what every trust surface in this lab does.
// Guards: https only (loopback http only when a test turns it on), no redirects, 64 KB and 5 s caps, a private-address
// refusal at connect time, a confirm gate, and netguard allows only the one typed host for the one request.
import http from 'node:http';
import https from 'node:https';
import { badRequest, HttpError } from './errors.js';
import { allowHost } from './netguard.js';
import { guardedLookup, parseProbeTarget } from './ssrf.js';
import { mapNetworkError, mapUpstreamStatus } from './upstream.js';

const MAX_BYTES = 65536;
const TIMEOUT_MS = 5000;
const KEEP = ['issuer', 'jwks_uri', 'token_endpoint', 'authorization_endpoint'];
const KEEP_LISTS = ['id_token_signing_alg_values_supported'];
const CONTROL = /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g;
const clean = (v) => String(v).replace(CONTROL, '?').slice(0, 300);

function getJson(url, { allowLoopback, timeoutMs }) {
  return new Promise((resolve, reject) => {
    // After we cut the connection for size, several events can follow (a reset on the request, an abort on the response).
    // They all mean the same thing, so they all report the size problem.
    let tooLarge = false;
    const fail = (e) => reject(tooLarge ? new HttpError(502, 'upstream_too_large', 'The discovery document is larger than 64 KB, so it was not read.') : e);
    const lib = url.protocol === 'http:' ? http : https;
    const req = lib.request(url, { method: 'GET', headers: { accept: 'application/json', 'user-agent': 'trusted-issuers-lab' }, lookup: guardedLookup(allowLoopback), timeout: timeoutMs }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400) { res.resume(); return reject(badRequest('redirect_refused', 'The server answered with a redirect, and the lab does not follow redirects.')); }
      const chunks = []; let size = 0;
      res.on('data', (c) => { size += c.length; if (size > MAX_BYTES) { tooLarge = true; req.destroy(); } else chunks.push(c); });
      res.on('end', () => {
        if (tooLarge) return fail(null);
        if (status !== 200) return resolve({ status });
        try {
          const json = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          return json !== null && typeof json === 'object' && !Array.isArray(json) ? resolve({ status, json }) : resolve({ status, notJson: true });
        } catch { return resolve({ status, notJson: true }); }
      });
      res.on('error', fail);
      res.on('close', () => { if (!res.complete) fail(Object.assign(new Error('the connection closed early'), { code: 'ECONNRESET' })); });
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', fail);
    req.end();
  });
}

// Why the typed string differs from the document's issuer, in plain words.
export function compareIssuer(typed, documentIssuer) {
  if (typed === documentIssuer) return { exact: true, differences: [] };
  const differences = [];
  if (typed.replace(/\/$/, '') === documentIssuer.replace(/\/$/, '')) differences.push('trailing slash');
  else if (typed.toLowerCase() === documentIssuer.toLowerCase()) differences.push('letter case');
  else if (typed.replace(/\/$/, '').toLowerCase() === documentIssuer.replace(/\/$/, '').toLowerCase()) differences.push('letter case and trailing slash');
  else differences.push('a different string');
  return { exact: false, differences };
}

export async function probeIssuer({ issuer, confirm }, { allowLoopback = false, timeoutMs = TIMEOUT_MS } = {}) {
  const url = parseProbeTarget(issuer, { allowLoopback });
  if (confirm !== true) throw badRequest('confirm_required', `This will contact ${url.origin} and read its discovery document. Send confirm: true to go ahead.`, { willContact: url.origin });
  const path = url.pathname.replace(/\/$/, '');
  const candidates = [
    { kind: 'openid-configuration', url: new URL(`${url.origin}${path}/.well-known/openid-configuration`) },
    { kind: 'oauth-authorization-server', url: new URL(`${url.origin}/.well-known/oauth-authorization-server${path}`) },
  ];
  const release = allowHost(url.hostname.replace(/^\[|\]$/g, ''));
  const tried = [];
  try {
    for (const c of candidates) {
      let r;
      try { r = await getJson(c.url, { allowLoopback, timeoutMs }); } catch (e) { throw e instanceof HttpError ? e : mapNetworkError(e, url.origin); }
      tried.push({ kind: c.kind, status: r.status });
      const bad = mapUpstreamStatus(r.status, url.origin);
      if (bad) throw bad;
      if (r.status === 200 && r.json) {
        const doc = {};
        for (const k of KEEP) if (typeof r.json[k] === 'string') doc[k] = clean(r.json[k]);
        for (const k of KEEP_LISTS) if (Array.isArray(r.json[k])) doc[k] = r.json[k].slice(0, 12).map(clean);
        if (typeof doc.issuer !== 'string') return { found: false, tried, message: 'The document has no issuer.' };
        return { found: true, kind: c.kind, tried, document: doc, typed: issuer, comparison: compareIssuer(issuer, doc.issuer), note: 'Every surface in this lab compares iss with the Issuer you enter exactly. Paste the document\'s issuer, character for character.' };
      }
    }
    return { found: false, tried, message: 'No discovery document was found at either well-known address.' };
  } finally { release(); }
}
