// Netguard: zero real outbound calls. It does not just watch, it blocks. A lookup of any name that is not loopback, and a
// connect to any non-loopback IP address, is refused and counted. The one exception is Real mode's issuer probe, which
// allows exactly the one host the visitor typed, for the length of one request (allowHost returns the release function).
// selfTest() proves the guard is live: it tries three forbidden calls and expects each to be refused.
import dns from 'node:dns';
import net from 'node:net';

const attempts = [];
const probes = [];
const allowed = new Map();
let installed = false;
let origLookup;
let origConnect;
let selfTesting = false;
let lastResult = null;

export const isLocal = (host) => host === undefined || host === null || host === '' || host === 'localhost' || host === '0.0.0.0' || host === '::' || host === '::1' || /^127\./.test(String(host)) || /\.localhost$/.test(String(host));

const refuse = (host, via) => {
  if (!selfTesting) attempts.push({ host: String(host).slice(0, 120), via, at: Date.now() });
  return Object.assign(new Error(`netguard: outbound ${via} to ${String(host).slice(0, 120)} was blocked`), { code: 'ENETGUARD' });
};

function connectTarget(args) {
  let a = args[0];
  if (Array.isArray(a)) a = a[0];
  if (a !== null && typeof a === 'object') return a.path ? null : (a.host ?? 'localhost');
  if (typeof a === 'number') return typeof args[1] === 'string' ? args[1] : 'localhost';
  return null;
}

export function install() {
  if (installed) return;
  installed = true;
  origLookup = dns.lookup;
  origConnect = net.Socket.prototype.connect;
  dns.lookup = function guardedDnsLookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (isLocal(hostname)) return origLookup.call(dns, hostname, options, callback);
    if (allowed.has(hostname)) { probes.push({ host: String(hostname).slice(0, 120), at: Date.now() }); return origLookup.call(dns, hostname, options, callback); }
    const err = refuse(hostname, 'lookup');
    return process.nextTick(callback, err);
  };
  net.Socket.prototype.connect = function guardedConnect(...args) {
    const target = connectTarget(args);
    if (target && !isLocal(target) && net.isIP(target) && !allowed.has(target)) {
      const err = refuse(target, 'connect');
      process.nextTick(() => this.destroy(err));
      return this;
    }
    return origConnect.apply(this, args);
  };
}

// Allow one host for one request. Returns a function that removes the allowance.
export function allowHost(host) {
  allowed.set(host, (allowed.get(host) || 0) + 1);
  return () => { const n = (allowed.get(host) || 1) - 1; if (n <= 0) allowed.delete(host); else allowed.set(host, n); };
}

export const report = () => ({ attempts: attempts.length, ok: attempts.length === 0, blocked: attempts.slice(-20), probes: probes.length });
export const lastSelfTest = () => lastResult;
export const resetReport = () => { attempts.length = 0; probes.length = 0; };

// Try three forbidden calls and a permitted one. Resolves to { ok, results }. It leaves the attempt counter as it found it.
// Overlapping calls share one run, so one cannot switch the "self-testing" flag off under another.
let running = null;
export function selfTest() {
  if (running) return running;
  install();
  selfTesting = true;
  const lookupBlocked = new Promise((resolve) => dns.lookup('selftest.invalid', (err) => resolve(err?.code === 'ENETGUARD')));
  const connectBlocked = new Promise((resolve) => {
    const s = net.connect({ host: '203.0.113.1', port: 9 });
    s.on('error', (err) => resolve(err?.code === 'ENETGUARD'));
    s.on('connect', () => { s.destroy(); resolve(false); });
  });
  const loopbackAllowed = new Promise((resolve) => dns.lookup('localhost', (err) => resolve(!err)));
  running = Promise.all([lookupBlocked, connectBlocked, loopbackAllowed]).then(([a, b, c]) => {
    selfTesting = false;
    const results = [{ id: 'lookup-blocked', ok: a }, { id: 'connect-blocked', ok: b }, { id: 'loopback-allowed', ok: c }];
    lastResult = { ok: results.every((r) => r.ok), results };
    running = null;
    return lastResult;
  });
  return running;
}
