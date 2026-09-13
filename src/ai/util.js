/** Shared string helpers for the AI modules. */

export function truncate(s, n) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

export function safeHost(u) {
  try { return new URL(u).host; } catch { return u; }
}

export function groupBy(arr, fn) {
  const o = {};
  for (const x of arr) (o[fn(x)] ||= []).push(x);
  return o;
}
