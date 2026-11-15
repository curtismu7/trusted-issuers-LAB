// Rule 23: a failure downstream is named, never blank. Real mode's one outbound call goes through here, and every way it
// can fail (connection refused, a name that does not resolve, a timeout, a 502/503/504 from the other side) becomes a
// structured { error, message } with a status, never an HTML page, a hang or an empty 200.
import { HttpError } from './errors.js';

export function mapNetworkError(e, what) {
  const code = e?.code || e?.cause?.code;
  if (code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT' || e?.name === 'TimeoutError') return new HttpError(504, 'upstream_timeout', `${what} did not answer in time.`);
  if (code === 'ECONNREFUSED') return new HttpError(502, 'upstream_unreachable', `${what} refused the connection (connection refused).`);
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return new HttpError(502, 'upstream_unreachable', `${what} could not be found: the name does not resolve.`);
  if (code === 'SSRF_BLOCKED') return new HttpError(400, 'address_refused', 'That name resolves to an address the lab will not contact.');
  if (code === 'ENETGUARD') return new HttpError(409, 'outbound_blocked', 'Outbound calls are blocked: switch to Real mode first.');
  if (code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || code === 'SELF_SIGNED_CERT_IN_CHAIN' || code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'CERT_HAS_EXPIRED' || /^ERR_TLS_/.test(code || '')) return new HttpError(502, 'upstream_tls', `${what} presented a certificate this lab does not trust.`);
  return new HttpError(502, 'upstream_error', `${what} could not be reached.`);
}

export function mapUpstreamStatus(status, what) {
  if (status === 502 || status === 503 || status === 504) return new HttpError(502, 'upstream_bad_gateway', `${what} answered ${status}.`);
  return null;
}
