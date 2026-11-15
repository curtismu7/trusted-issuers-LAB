// Rule 19: Mock or Real, switchable at runtime. Real here is a read-only issuer discovery probe and it needs
// TI_REAL_PROBE=1 in the app's own .env. It carries no credential. Default: Real if configured, else Mock.
export const REAL_NEEDS = ['TI_REAL_PROBE=1'];

export function createMode(env = process.env) {
  const realAvailable = () => env.TI_REAL_PROBE === '1';
  let source = realAvailable() ? 'real' : 'mock';
  return {
    get source() { return source; },
    realAvailable,
    set(next) {
      if (next !== 'mock' && next !== 'real') return { ok: false, status: 400, error: 'bad_source', message: 'source must be "mock" or "real".' };
      if (next === 'real' && !realAvailable()) return { ok: false, status: 409, error: 'real_not_configured', message: `Real mode needs ${REAL_NEEDS.join(' and ')} in the app's own .env (a read-only issuer discovery probe; no credential).` };
      source = next;
      return { ok: true };
    },
  };
}
