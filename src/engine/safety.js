import dns from 'node:dns/promises';
import net from 'node:net';

/**
 * Target safety gate. Scanning is only permitted against http(s) URLs.
 * Private/loopback ranges are blocked unless ALLOW_PRIVATE_TARGETS=true
 * (default true for local lab use — set false when exposing the dashboard).
 */
export async function assertTargetAllowed(target) {
  let url;
  try { url = new URL(target); } catch { throw new Error(`Invalid URL: ${target}`); }
  if (!/^https?:$/.test(url.protocol)) throw new Error('Only http:// and https:// targets are supported');

  const allowPrivate = (process.env.ALLOW_PRIVATE_TARGETS ?? 'true') !== 'false';
  if (allowPrivate) return;

  const host = url.hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true }).catch(() => [])).map(a => a.address);
  if (!addrs.length) throw new Error(`Could not resolve ${host}`);
  for (const ip of addrs) {
    if (isPrivateIp(ip)) throw new Error(`Target ${host} resolves to a private/loopback address (${ip}); refusing to scan. Set ALLOW_PRIVATE_TARGETS=true for lab use.`);
  }
}

export function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:') && isPrivateIp(l.slice(7));
  }
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/** Normalize user-supplied input ("example.com", "https://example.com/x") to a full URL. */
export function normalizeTarget(input) {
  let t = String(input || '').trim();
  if (!t) throw new Error('Target is required');
  if (!/^https?:\/\//i.test(t)) t = 'https://' + t;
  const u = new URL(t);
  return u.href;
}
