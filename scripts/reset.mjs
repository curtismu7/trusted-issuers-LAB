#!/usr/bin/env node
// Reset: clear the in-memory run log through the API, or say so when the app is not running (state is in memory only).
const port = process.env.PORT || 7818;
try {
  const r = await fetch(`http://127.0.0.1:${port}/api/reset`, { method: 'POST' });
  console.log(r.ok ? '[reset] run log cleared' : `[reset] the API answered ${r.status}`);
  process.exit(r.ok ? 0 : 1);
} catch {
  console.log(`[reset] the app is not reachable on ${port}; nothing to reset (state is in memory only).`);
}
