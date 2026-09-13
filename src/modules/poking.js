import net from 'node:net';
import tls from 'node:tls';
import { Buffer } from 'node:buffer';

/**
 * Pokes an HTTP/HTTPS endpoint with custom parameters, returning detailed response metadata.
 */
export async function pokeHttp({
  url,
  method = 'GET',
  headers = {},
  body = null,
  auth = null,
  timeoutMs = 10000,
}) {
  if (!url) throw new Error('URL is required');
  let targetUrl = url.trim();
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = `https://${targetUrl}`;

  const reqHeaders = { ...headers };

  // Apply Auth if specified
  if (auth) {
    if (auth.type === 'bearer' && auth.token) {
      reqHeaders['Authorization'] = `Bearer ${auth.token}`;
    } else if (auth.type === 'basic' && (auth.username || auth.password)) {
      const creds = Buffer.from(`${auth.username || ''}:${auth.password || ''}`).toString('base64');
      reqHeaders['Authorization'] = `Basic ${creds}`;
    } else if (auth.type === 'apikey' && auth.header && auth.value) {
      reqHeaders[auth.header] = auth.value;
    }
  }

  if (!reqHeaders['User-Agent']) {
    reqHeaders['User-Agent'] = 'Monarch-Security-Engine/2.0 Inspector';
  }

  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(targetUrl, {
      method: method.toUpperCase(),
      headers: reqHeaders,
      body: ['GET', 'HEAD'].includes(method.toUpperCase()) ? undefined : body,
      signal: controller.signal,
    });
    const timingMs = Date.now() - started;

    const resHeaders = {};
    for (const [k, v] of res.headers.entries()) {
      resHeaders[k] = v;
    }

    const contentType = res.headers.get('content-type') || '';
    let responseBody = '';
    let sizeBytes = 0;

    const buffer = await res.arrayBuffer();
    sizeBytes = buffer.byteLength;

    if (contentType.includes('application/json') || contentType.includes('text') || contentType.includes('xml') || contentType.includes('javascript')) {
      const decoder = new TextDecoder('utf-8');
      responseBody = decoder.decode(buffer);
    } else {
      responseBody = `[Binary content (${sizeBytes} bytes) - Type: ${contentType}]`;
    }

    return {
      status: res.status,
      statusText: res.statusText,
      headers: resHeaders,
      body: responseBody,
      sizeBytes,
      timingMs,
      contentType,
      url: res.url,
      redirected: res.redirected,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Pokes an SSH service, grabs identification banner and checks latency.
 */
export function pokeSsh({ host, port = 22, timeoutMs = 4000 }) {
  return new Promise(resolve => {
    if (!host) {
      return resolve({ reachable: false, error: 'Host is required' });
    }

    const started = Date.now();
    const socket = new net.Socket();
    let banner = '';

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      // Wait for the SSH server to send its identification banner
    });

    socket.on('data', data => {
      banner += data.toString('utf8');
      if (banner.includes('\n')) {
        const latencyMs = Date.now() - started;
        socket.destroy();

        const cleanBanner = banner.trim();
        // SSH-protoversion-softwareversion comments
        // Example: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
        let sshVersion = 'Unknown';
        let osHint = null;

        const parts = cleanBanner.split(' ');
        if (parts[0]) {
          sshVersion = parts[0];
        }
        if (parts.length > 1) {
          osHint = parts.slice(1).join(' ');
        }

        resolve({
          host,
          port,
          reachable: true,
          latencyMs,
          banner: cleanBanner,
          sshVersion,
          osHint,
        });
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        host,
        port,
        reachable: false,
        latencyMs: Date.now() - started,
        error: `Connection timed out after ${timeoutMs}ms`,
      });
    });

    socket.on('error', err => {
      socket.destroy();
      resolve({
        host,
        port,
        reachable: false,
        latencyMs: Date.now() - started,
        error: err.message || err.code,
      });
    });

    try {
      socket.connect(Number(port) || 22, host);
    } catch (err) {
      resolve({
        host,
        port,
        reachable: false,
        latencyMs: 0,
        error: err.message,
      });
    }
  });
}
