// Bind and port rules. The server listens on loopback. Inside Docker it must listen on all interfaces so the published
// port works, and the compose file publishes 127.0.0.1 only; TI_IN_DOCKER=1 is the marker that says so.
export const DEFAULT_PORT = 7818;
export const PORT_MIN = 7800;
export const PORT_MAX = 7999;
const LOOPBACK = ['127.0.0.1', '::1', 'localhost'];

export const bindHost = (env = process.env) => (env.HOST ? String(env.HOST) : '127.0.0.1');

export function bindProblem(host, env = process.env) {
  if (LOOPBACK.includes(host)) return null;
  if (env.TI_IN_DOCKER === '1') return null;
  return `HOST ${host} is not loopback. Only a container (TI_IN_DOCKER=1, with the port published on 127.0.0.1) may listen on all interfaces.`;
}

export const portOf = (env = process.env) => (env.PORT === undefined || env.PORT === '' ? DEFAULT_PORT : Number(env.PORT));

export function portProblem(port) {
  if (!Number.isInteger(port)) return 'PORT is not a whole number.';
  if (port < PORT_MIN || port > PORT_MAX) return `${port} is outside ${PORT_MIN}-${PORT_MAX}, the range new apps use.`;
  return null;
}

export function allowedHosts(env = process.env) {
  const given = env.LAB_ALLOWED_HOSTS;
  const list = given ? given.split(',') : ['localhost', '127.0.0.1', 'local.ping-devops.com', 'trusted-issuers', 'trusted-issuers.local.ping-devops.com', 'trusted-issuers-lab.local.ping-devops.com'];
  return list.map((h) => h.trim().split(':')[0]).filter(Boolean);
}
