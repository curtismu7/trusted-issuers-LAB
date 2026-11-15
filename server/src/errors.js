// Structured errors (rule 23): every failure an /api route can hit becomes { error, message } JSON, never an HTML page,
// a hang or an empty 200.
export class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status; this.code = code; this.extra = extra;
  }
}

export const badRequest = (code, message, extra) => new HttpError(400, code, message, extra);

// Express error handler: maps known errors to JSON and hides the rest behind a generic message (no stack, no internals).
export function errorHandler(err, _req, res, _next) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.code, message: err.message, ...err.extra });
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'too_large', message: 'The request body is too large.' });
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad_json', message: 'The request body is not valid JSON.' });
  if (err?.code === 'bad_override') return res.status(400).json({ error: 'bad_override', message: err.message });
  if (err?.code === 'bad_mutation' || err?.code === 'bad_surface') return res.status(400).json({ error: err.code, message: err.message });
  return res.status(500).json({ error: 'internal_error', message: 'Something went wrong inside the lab. Nothing was changed.' });
}
