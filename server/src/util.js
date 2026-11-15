// Small helpers. Anything that came from a visitor (a pasted token, an override) is shown through show(): bounded, and
// with control and bidirectional characters turned into visible escapes, so it can never hide or reorder text.
export const nowSeconds = () => Math.floor(Date.now() / 1000);

const HIDDEN = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;

export function show(value, max = 120) {
  let s;
  try { s = typeof value === 'string' ? value : JSON.stringify(value); } catch { s = String(value); }
  if (s === undefined) s = 'undefined';
  s = s.replace(HIDDEN, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  return `"${s.length > max ? `${s.slice(0, max)}…` : s}"`;
}

// Deep equality for JSON values, iterative so a hostile, deeply nested claim cannot overflow the stack.
export function jsonEqual(a, b) {
  const stack = [[a, b, 0]];
  while (stack.length) {
    const [x, y, depth] = stack.pop();
    if (depth > 20) return false;
    if (x === y) continue;
    if (typeof x !== typeof y || x === null || y === null || typeof x !== 'object') return false;
    if (Array.isArray(x) !== Array.isArray(y)) return false;
    const kx = Object.keys(x); const ky = Object.keys(y);
    if (kx.length !== ky.length) return false;
    for (const k of kx) { if (!Object.hasOwn(y, k)) return false; stack.push([x[k], y[k], depth + 1]); }
  }
  return true;
}
