// SSRF guard for Real mode's issuer probe. The probe may contact ONE origin the visitor typed, and only if it is a public
// https host: no IP literals, no credentials in the URL, no odd ports, and no name that resolves to a private, loopback or
// link-local address. The address check runs at connect time, inside the lookup, so a name that changes its answer
// between the check and the connection (DNS rebinding) still cannot reach a private address.
import dns from 'node:dns';
import net from 'node:net';
import { badRequest } from './errors.js';

const BLOCK = new net.BlockList();
for (const [net4, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]]) BLOCK.addSubnet(net4, prefix, 'ipv4');
for (const [net6, prefix] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32]]) BLOCK.addSubnet(net6, prefix, 'ipv6');

const isLoopback = (ip) => /^127\./.test(ip) || ip === '::1';

export function isBlockedAddress(ip, allowLoopback = false) {
  if (typeof ip !== 'string') return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  const addr = mapped ? mapped[1] : ip;
  if (allowLoopback && isLoopback(addr)) return false;
  const family = net.isIP(addr);
  if (!family) return true;
  return BLOCK.check(addr, family === 6 ? 'ipv6' : 'ipv4');
}

// A lookup function for https.request({ lookup }) that refuses a forbidden address.
export function guardedLookup(allowLoopback = false) {
  return (hostname, options, cb) => {
    if (typeof options === 'function') { cb = options; options = {}; }
    dns.lookup(hostname, options, (err, address, family) => {
      if (err) return cb(err);
      const list = Array.isArray(address) ? address : [{ address, family }];
      if (list.some((a) => isBlockedAddress(a.address, allowLoopback))) return cb(Object.assign(new Error('that name resolves to an address the lab will not contact'), { code: 'SSRF_BLOCKED' }));
      return Array.isArray(address) ? cb(null, address) : cb(null, address, family);
    });
  };
}

const CONTROL = /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/;

// Turn what the visitor typed into a URL the probe may contact, or refuse it with a plain reason.
export function parseProbeTarget(input, { allowLoopback = false } = {}) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 200 || CONTROL.test(input) || input !== input.trim()) throw badRequest('bad_issuer', 'Type the issuer as one https URL, at most 200 characters, with no spaces around it.');
  let url;
  try { url = new URL(input); } catch { throw badRequest('bad_issuer', 'That is not a URL.'); }
  const loopbackHost = allowLoopback && (url.hostname === '127.0.0.1' || url.hostname === '[::1]' || url.hostname === 'localhost');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopbackHost)) throw badRequest('bad_issuer', 'Only https issuers can be probed.');
  if (url.username || url.password) throw badRequest('bad_issuer', 'A URL with a user name or password is refused.');
  if (url.search || url.hash) throw badRequest('bad_issuer', 'An issuer has no query string or fragment.');
  if (!url.hostname) throw badRequest('bad_issuer', 'The URL has no host.');
  if (!loopbackHost) {
    if (net.isIP(url.hostname.replace(/^\[|\]$/g, ''))) throw badRequest('bad_issuer', 'An IP address is refused: type the issuer\'s host name.');
    if (url.port && url.port !== '443') throw badRequest('bad_issuer', 'Only the standard https port can be probed.');
    if (!/\./.test(url.hostname)) throw badRequest('bad_issuer', 'A host name with no dot is refused.');
  }
  return url;
}
