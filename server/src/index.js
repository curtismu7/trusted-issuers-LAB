import { createApp } from './app.js';
import { bindHost, bindProblem, portOf, portProblem } from './safety.js';

const host = bindHost();
const port = portOf();
const problem = bindProblem(host) || portProblem(port);
if (problem) { console.error(`[trusted-issuers] refusing to start: ${problem}`); process.exit(1); }

const app = createApp();
const server = app.listen(port, host, () => console.log(`[trusted-issuers] listening on ${host}:${port}`));
const stop = () => { app.locals.health.stop(); server.close(() => process.exit(0)); };
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
