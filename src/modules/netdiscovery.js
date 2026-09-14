import os from 'node:os';
import net from 'node:net';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import { exec, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolveVendor, normalizeMac } from './oui.js';
import { assertTargetAllowed } from '../engine/safety.js';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);
const PLATFORM = os.platform(); // 'win32' | 'linux' | 'darwin'

/** Upper bound on how many hosts one target sweep may expand to. */
export const MAX_HOSTS = 65536;

/* ------------------------------------------------------------------ */
/* Service Dictionaries & Port Definitions (TCP + UDP)                */
/* ------------------------------------------------------------------ */

export const TCP_SERVICES = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPC',
  135: 'MSRPC',
  139: 'NetBIOS',
  143: 'IMAP',
  161: 'SNMP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  515: 'LPD',
  548: 'AFP',
  554: 'RTSP',
  587: 'SMTP',
  631: 'IPP',
  993: 'IMAPS',
  995: 'POP3S',
  1080: 'SOCKS',
  1433: 'MSSQL',
  1521: 'Oracle',
  1723: 'PPTP',
  1883: 'MQTT',
  1900: 'SSDP',
  2049: 'NFS',
  2375: 'Docker',
  3000: 'Dev/HTTP',
  3306: 'MySQL',
  3389: 'RDP',
  5000: 'UPnP/Dev',
  5060: 'SIP',
  5353: 'mDNS',
  5432: 'Postgres',
  5555: 'ADB',
  5900: 'VNC',
  6379: 'Redis',
  7000: 'HTTP',
  8000: 'HTTP-alt',
  8006: 'Proxmox',
  8080: 'HTTP-alt',
  8081: 'HTTP-alt',
  8443: 'HTTPS-alt',
  8883: 'MQTTS',
  9000: 'PHP-FPM',
  9100: 'Printer',
  9200: 'Elasticsearch',
  27017: 'MongoDB',
  32400: 'Plex',
  62078: 'iOS-sync',
};

export const COMMON_PORTS = Object.entries(TCP_SERVICES).map(([port, service]) => ({
  port: Number(port),
  service,
}));

export const FAST_TCP_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 443, 445, 515, 548, 554, 631,
  993, 1883, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8006, 8080, 8443, 9100, 27017,
];

export const UDP_SERVICES = {
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  69: 'TFTP',
  123: 'NTP',
  137: 'NetBIOS',
  138: 'NetBIOS',
  161: 'SNMP',
  162: 'SNMP-trap',
  500: 'IKE',
  514: 'Syslog',
  520: 'RIP',
  631: 'IPP',
  1194: 'OpenVPN',
  1900: 'SSDP',
  4500: 'IPsec-NAT',
  5060: 'SIP',
  5353: 'mDNS',
  11211: 'Memcached',
};

export const COMMON_UDP_PORTS = Object.keys(UDP_SERVICES).map(Number);

/** Service-specific UDP probe payloads to elicit replies without authentication */
const DEFAULT_UDP_PROBE = Buffer.from([0x00]);
const UDP_PROBES = {
  53: Buffer.from('0000010000010000000000000377777706676f6f676c6503636f6d0000010001', 'hex'), // DNS A query
  123: Buffer.concat([Buffer.from([0x1b]), Buffer.alloc(47)]), // NTP client request
  161: Buffer.from('302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500', 'hex'), // SNMP get sysDescr
  1900: Buffer.from('M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:1\r\nST:ssdp:all\r\n\r\n'),
  5353: Buffer.from('000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001', 'hex'), // mDNS PTR
};

/* ------------------------------------------------------------------ */
/* IPv4 Calculations & Subnet Target Parsing (from NetLAN net-utils)  */
/* ------------------------------------------------------------------ */

export function ipToInt(ip) {
  const p = String(ip || '').trim().split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

export function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export function parseTargets(input) {
  const raw = String(input || '').trim();
  if (!raw) throw new Error('Empty target');

  if (raw.includes('-') && !raw.includes('/')) {
    const [a, b] = raw.split('-').map(s => s.trim());
    const start = ipToInt(a);
    const end = ipToInt(b);
    if (end < start) throw new Error('Range end is before start');
    const count = end - start + 1;
    if (count > MAX_HOSTS) throw new Error(`Range too large: ${count} hosts (max ${MAX_HOSTS})`);
    return { cidr: raw, first: start, last: end, count };
  }

  const [ip, bitsStr] = raw.split('/');
  const bits = bitsStr === undefined ? 32 : parseInt(bitsStr, 10);
  if (Number.isNaN(bits) || bits < 0 || bits > 32) throw new Error(`Invalid prefix /${bitsStr}`);

  const ipInt = ipToInt(ip);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;

  let first = network;
  let last = broadcast;
  if (bits <= 30) {
    first = (network + 1) >>> 0;
    last = (broadcast - 1) >>> 0;
  }
  const count = last - first + 1;
  if (count > MAX_HOSTS) throw new Error(`Subnet too large: ${count} hosts (max ${MAX_HOSTS})`);
  return { cidr: `${intToIp(network)}/${bits}`, first, last, count };
}

export function* iterateHosts(targets) {
  for (let n = targets.first; n <= targets.last; n++) {
    yield intToIp(n >>> 0);
  }
}

export function expandTargets(input) {
  const specs = String(input || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!specs.length) throw new Error('Empty target');

  const seen = new Set();
  const ips = [];
  for (const spec of specs) {
    const t = parseTargets(spec);
    for (const ip of iterateHosts(t)) {
      if (!seen.has(ip)) {
        seen.add(ip);
        ips.push(ip);
      }
    }
  }
  ips.sort((a, b) => ipToInt(a) - ipToInt(b));
  return { ips, count: ips.length };
}

export async function resolveTargets(target) {
  const specs = String(target || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!specs.length) throw new Error('Empty target');

  const parts = [];
  const labels = [];
  for (const spec of specs) {
    if (/[a-z]/i.test(spec)) {
      try {
        const lookup = await dns.lookup(spec);
        parts.push(lookup.address);
        labels.push(`${spec} (${lookup.address})`);
      } catch {
        throw new Error(`Could not resolve hostname: ${spec}`);
      }
    } else {
      parts.push(spec);
      labels.push(spec);
    }
  }
  return { target: parts.join(', '), label: labels.join(', ') };
}

/* ------------------------------------------------------------------ */
/* Default Gateway & Routing Detection (from NetLAN discovery)         */
/* ------------------------------------------------------------------ */

export async function getDefaultRoute() {
  try {
    if (PLATFORM === 'win32') {
      const { stdout } = await execAsync('route print 0.0.0.0');
      // Format in route print:
      // 0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.187     50
      const lines = stdout.split('\n');
      for (const line of lines) {
        const match = line.trim().match(/^0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9.]+)\s+([0-9.]+)/i);
        if (match) {
          return { gateway: match[1], ifaceIp: match[2] };
        }
      }
    } else if (PLATFORM === 'darwin') {
      const { stdout } = await execAsync('route -n get default');
      const gw = stdout.match(/gateway:\s*([0-9.]+)/i);
      const iface = stdout.match(/interface:\s*(\S+)/i);
      return { gateway: gw ? gw[1] : null, iface: iface ? iface[1] : null };
    } else {
      // Linux
      const { stdout } = await execAsync('ip route show default');
      const gw = stdout.match(/via\s+([0-9.]+)/i);
      const dev = stdout.match(/dev\s+(\S+)/i);
      return { gateway: gw ? gw[1] : null, iface: dev ? dev[1] : null };
    }
  } catch {
    // fallback
  }
  return { gateway: null, iface: null };
}

/* ------------------------------------------------------------------ */
/* Active ICMP Ping Prober (from NetLAN discovery)                    */
/* ------------------------------------------------------------------ */

export function ping(ip, timeoutMs = 800) {
  if (!ip || typeof ip !== 'string' || !net.isIP(ip.trim())) {
    return Promise.resolve({ alive: false, rtt: null });
  }
  const cleanIp = ip.trim();
  let args;
  if (PLATFORM === 'win32') {
    args = ['-n', '1', '-w', String(timeoutMs), cleanIp];
  } else if (PLATFORM === 'darwin') {
    args = ['-c', '1', '-t', String(Math.max(1, Math.round(timeoutMs / 1000))), cleanIp];
  } else {
    args = ['-c', '1', '-W', String(Math.max(1, Math.round(timeoutMs / 1000))), cleanIp];
  }

  return new Promise((resolve) => {
    execFile('ping', args, { timeout: timeoutMs + 1200, windowsHide: true }, (err, stdout) => {
      if (err || !stdout) return resolve({ alive: false, rtt: null });
      const m = /time[=<]\s*([\d.]+)\s*ms/i.exec(stdout);
      resolve({ alive: true, rtt: m ? parseFloat(m[1]) : null });
    });
  });
}

export async function pingAlive(ip, timeoutMs = 800, attempts = 2) {
  let last = { alive: false, rtt: null };
  for (let i = 0; i < attempts; i++) {
    last = await ping(ip, timeoutMs);
    if (last.alive) return last;
  }
  return last;
}

/* ------------------------------------------------------------------ */
/* Network Interfaces & ARP Table Discovery                           */
/* ------------------------------------------------------------------ */

export function getLocalInterfaces() {
  const ifaces = os.networkInterfaces();
  const results = [];
  for (const [name, list] of Object.entries(ifaces)) {
    if (!list) continue;
    for (const info of list) {
      if (info.family === 'IPv4') {
        const vendor = resolveVendor(info.mac);
        results.push({
          name,
          address: info.address,
          netmask: info.netmask,
          mac: info.mac,
          cidr: info.cidr,
          internal: info.internal,
          vendor,
        });
      }
    }
  }
  return results;
}

export async function getArpTable() {
  try {
    const { stdout } = await execAsync('arp -a');
    return parseArpOutput(stdout);
  } catch {
    return [];
  }
}

export function parseArpOutput(output) {
  const lines = output.split('\n');
  const devices = [];
  const seenIps = new Set();
  let currentInterface = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const ifaceMatch = line.match(/Interface:\s*([0-9.]+)/i);
    if (ifaceMatch) {
      currentInterface = ifaceMatch[1];
      continue;
    }

    const winMatch = line.match(/^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})\s+(\w+)/i);
    const nixMatch = line.match(/\(?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)?\s+(?:at\s+)?([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})/i);

    const match = winMatch || nixMatch;
    if (match) {
      const ip = match[1];
      const mac = normalizeMac(match[2]);
      const type = winMatch ? winMatch[3] : 'dynamic';

      if (ip.endsWith('.255') || ip.startsWith('224.') || ip.startsWith('239.') || mac.toLowerCase() === 'ff:ff:ff:ff:ff:ff') {
        continue;
      }

      if (!seenIps.has(ip)) {
        seenIps.add(ip);
        devices.push({
          ip,
          mac,
          type,
          interface: currentInterface,
          vendor: resolveVendor(mac),
          hostname: null,
          openPorts: [],
          lastSeen: new Date().toISOString(),
        });
      }
    }
  }

  return devices;
}

/* ------------------------------------------------------------------ */
/* TCP & UDP Port Probing with Banners                                */
/* ------------------------------------------------------------------ */

/**
 * Parse port ranges or lists (e.g. "80,443,8000-8005") into an array of port numbers
 */
export function parsePortList(input) {
  if (Array.isArray(input)) return input.map(Number).filter(n => !Number.isNaN(n) && n > 0 && n <= 65535);
  if (typeof input !== 'string') return [];
  const ports = new Set();
  const parts = input.split(',').map(s => s.trim()).filter(Boolean);
  for (const part of parts) {
    if (part.includes('-')) {
      const [startStr, endStr] = part.split('-').map(s => s.trim());
      const start = parseInt(startStr, 10);
      const end = parseInt(endStr, 10);
      if (!Number.isNaN(start) && !Number.isNaN(end) && start <= end) {
        for (let p = Math.max(1, start); p <= Math.min(65535, end); p++) {
          ports.add(p);
        }
      }
    } else {
      const p = parseInt(part, 10);
      if (!Number.isNaN(p) && p > 0 && p <= 65535) {
        ports.add(p);
      }
    }
  }
  return Array.from(ports).sort((a, b) => a - b);
}

/**
 * Infer operating system hints from device banner, vendor, and open ports
 */
export function inferOsFromDevice(device) {
  if (!device) return 'Unknown';
  const openPorts = device.openPorts || [];
  const ports = openPorts.map(p => p.port);
  const vendor = (device.vendor || '').toLowerCase();
  const banners = openPorts.map(p => (p.banner || '').toLowerCase()).join(' ');

  if (vendor.includes('apple') || banners.includes('darwin') || ports.includes(548) || ports.includes(62078)) {
    return 'Apple macOS/iOS';
  }
  if (vendor.includes('microsoft') || ports.includes(135) || ports.includes(445) || ports.includes(3389) || banners.includes('windows')) {
    return 'Windows';
  }
  if (banners.includes('ubuntu') || banners.includes('debian') || banners.includes('centos') || banners.includes('linux') || banners.includes('openssh')) {
    return 'Linux';
  }
  if (vendor.includes('cisco') || vendor.includes('ubiquiti') || vendor.includes('tp-link') || vendor.includes('netgear') || vendor.includes('synology') || vendor.includes('qnap')) {
    return 'Embedded Network Appliance';
  }
  if (ports.includes(22)) {
    return 'Linux/Unix';
  }
  return 'Unknown';
}

export function checkTcpPort(hostInput, port, timeoutMs = 700) {
  const host = String(hostInput || '').trim();
  if (!host || !/^[a-zA-Z0-9.:_-]+$/.test(host)) {
    return Promise.resolve({ port, proto: 'tcp', open: false, latencyMs: 0, service: TCP_SERVICES[port] || 'Custom', banner: null });
  }

  return new Promise((resolve) => {
    const started = Date.now();
    const socket = new net.Socket();
    let banner = '';
    let settled = false;

    const finish = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      const latencyMs = Date.now() - started;

      let extractedBanner = banner.trim().slice(0, 150) || null;
      let serviceExtra = TCP_SERVICES[port] || 'Custom';

      // SSH version regex parsing
      if (extractedBanner) {
        const sshMatch = extractedBanner.match(/^SSH-([\d.]+)-(\S+)/i);
        if (sshMatch) {
          serviceExtra = `SSH (${sshMatch[2]})`;
        }
        // HTTP Server header extraction
        const serverMatch = extractedBanner.match(/server:\s*([^\r\n]+)/i);
        if (serverMatch) {
          extractedBanner = `Server: ${serverMatch[1].trim()}`;
        }
      }

      resolve({
        port,
        proto: 'tcp',
        open,
        latencyMs,
        service: serviceExtra,
        banner: extractedBanner,
      });
    };

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      // Elicit banner on common protocols
      try {
        if ([80, 8080, 3000, 5000, 7000, 8000, 8006, 8081, 8443].includes(port)) {
          const safeHost = host.replace(/[\r\n]/g, '');
          socket.write('HEAD / HTTP/1.0\r\nHost: ' + safeHost + '\r\n\r\n');
        } else {
          socket.write('\r\n');
        }
      } catch { /* ignore */ }

      setTimeout(() => finish(true), 80);
    });

    socket.on('data', (data) => {
      banner += data.toString('utf8', 0, Math.min(data.length, 256));
      finish(true);
    });

    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));

    try {
      socket.connect(port, host);
    } catch {
      finish(false);
    }
  });
}

export function checkUdpPort(host, port, timeoutMs = 900) {
  return new Promise((resolve) => {
    const started = Date.now();
    let client;
    try {
      client = dgram.createSocket('udp4');
    } catch {
      return resolve({ port, proto: 'udp', open: false, service: UDP_SERVICES[port] || 'UDP' });
    }

    let settled = false;
    const finish = (open, banner = null) => {
      if (settled) return;
      settled = true;
      try { client.close(); } catch { /* ignore */ }
      const latencyMs = Date.now() - started;
      resolve({
        port,
        proto: 'udp',
        open,
        latencyMs,
        service: UDP_SERVICES[port] || 'UDP',
        banner,
      });
    };

    const timer = setTimeout(() => finish(false), timeoutMs);

    client.on('message', (msg) => {
      clearTimeout(timer);
      const snippet = msg.toString('utf8', 0, Math.min(msg.length, 64)).replace(/[^\x20-\x7E]/g, '.');
      finish(true, snippet || null);
    });

    client.on('error', () => {
      clearTimeout(timer);
      finish(false);
    });

    const probe = UDP_PROBES[port] || DEFAULT_UDP_PROBE;
    try {
      client.send(probe, port, host, (err) => {
        if (err) finish(false);
      });
    } catch {
      finish(false);
    }
  });
}

export async function scanHostPorts(host, tcpPorts = FAST_TCP_PORTS, udpPorts = [], timeoutMs = 700, concurrency = 25) {
  const results = [];
  const tcpQueue = [...tcpPorts];
  const udpQueue = [...udpPorts];

  // TCP worker pool
  const tcpWorkers = Array.from({ length: Math.min(concurrency, tcpQueue.length || 1) }, async () => {
    while (tcpQueue.length > 0) {
      const port = tcpQueue.shift();
      const res = await checkTcpPort(host, port, timeoutMs);
      if (res.open) results.push(res);
    }
  });

  // UDP worker pool
  const udpWorkers = Array.from({ length: Math.min(10, udpQueue.length || 1) }, async () => {
    while (udpQueue.length > 0) {
      const port = udpQueue.shift();
      const res = await checkUdpPort(host, port, timeoutMs + 200);
      if (res.open) results.push(res);
    }
  });

  await Promise.all([...tcpWorkers, ...udpWorkers]);
  results.sort((a, b) => a.port - b.port);
  return results;
}

export async function resolveHostname(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames[0] || null;
  } catch {
    return null;
  }
}

/**
 * Deep Host & Web Server / VPS Inspector
 * Probes HTTP/HTTPS response headers, SSL cert, banners, OUI vendor, and reverse DNS.
 */
export async function inspectHostDetails(hostInput) {
  const host = String(hostInput || '').trim();
  if (!host || !/^[a-zA-Z0-9.:_-]+$/.test(host)) throw new Error('Invalid or unsafe host input');

  const started = Date.now();
  let resolvedIp = host;

  if (/[a-z]/i.test(host)) {
    try {
      const lookup = await dns.lookup(host);
      resolvedIp = lookup.address;
    } catch {
      /* continue with raw input */
    }
  }

  if (!net.isIP(resolvedIp)) {
    throw new Error(`Host could not be resolved to a valid IP address: ${host}`);
  }

  const hostname = await resolveHostname(resolvedIp);
  const openPorts = await scanHostPorts(resolvedIp, FAST_TCP_PORTS, COMMON_UDP_PORTS.slice(0, 5), 800, 25);
  const osHint = inferOsFromDevice({ vendor: '', openPorts });

  // Web server & VPS details probe
  let webInfo = null;
  const httpPort = openPorts.find(p => [80, 443, 8000, 8080, 8443, 3000].includes(p.port));
  if (httpPort || /[a-z]/i.test(host)) {
    const scheme = (httpPort?.port === 443 || httpPort?.port === 8443) ? 'https' : 'http';
    const parsedUrl = new URL(`${scheme}://${resolvedIp}:${httpPort?.port || 80}`);
    if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
      try {
        await assertTargetAllowed(parsedUrl.href);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        try {
          const res = await fetch(parsedUrl.href, { method: 'HEAD', signal: controller.signal, redirect: 'manual' }).catch(async () => {
            return await fetch(parsedUrl.href, { method: 'GET', signal: controller.signal, redirect: 'manual' });
          });
          clearTimeout(timer);
          const headers = {};
          res.headers.forEach((v, k) => { headers[k] = v; });
          webInfo = {
            url: parsedUrl.href,
            status: res.status,
            server: headers['server'] || headers['x-powered-by'] || null,
            title: null,
            headers,
          };
        } catch {
          clearTimeout(timer);
        }
      } catch {
        /* target not allowed or invalid */
      }
    }
  }

  return {
    host,
    ip: resolvedIp,
    hostname,
    osHint,
    openPorts,
    webInfo,
    latencyMs: Date.now() - started,
    timestamp: new Date().toISOString(),
  };
}

/**
 * High-performance worker pool with bounded concurrency
 */
export async function pool(items, concurrency, worker, onTick) {
  const queue = items.slice();
  let active = 0;
  let done = 0;
  return new Promise((resolve) => {
    if (queue.length === 0) return resolve();
    const next = () => {
      while (active < concurrency && queue.length) {
        const item = queue.shift();
        active++;
        Promise.resolve(worker(item))
          .catch(() => {})
          .finally(() => {
            active--;
            done++;
            if (onTick) onTick(done);
            if (queue.length || active) next();
            else resolve();
          });
      }
    };
    next();
  });
}

/* ------------------------------------------------------------------ */
/* Full Network Discovery & Port Mapper Engine                        */
/* ------------------------------------------------------------------ */

export async function runNetworkDiscovery({
  subnet = null,
  mode = 'fast', // 'fast' | 'full' | 'custom'
  customTcp = null,
  customUdp = null,
  pingTimeout = 800,
  portTimeout = 700,
  hostConcurrency = 50,
  onEvent = () => {},
} = {}) {
  onEvent({ type: 'status', message: 'Analyzing network topology, default routes, and interfaces…' });

  const interfaces = getLocalInterfaces();
  const route = await getDefaultRoute();
  const arpDevices = await getArpTable();

  // Determine target IPs to sweep
  let targetIps = [];
  let sweepRangeLabel = subnet;

  if (subnet) {
    try {
      const resolved = await resolveTargets(subnet);
      const expanded = expandTargets(resolved.target);
      targetIps = expanded.ips;
      sweepRangeLabel = resolved.label;
    } catch {
      targetIps = [];
    }
  }

  // If no subnet provided or empty, sweep the primary interface /24
  if (!targetIps.length && interfaces.length > 0) {
    const primary = interfaces.find(i => !i.internal && (route.ifaceIp ? i.address === route.ifaceIp : true)) || interfaces[0];
    if (primary && primary.cidr) {
      try {
        const expanded = expandTargets(primary.cidr);
        // Limit auto-sweep to 256 hosts for fast responsive discovery
        targetIps = expanded.ips.slice(0, 256);
        sweepRangeLabel = primary.cidr;
      } catch { /* ignore */ }
    }
  }

  // Map of discovered hosts keyed by IP
  const hostsMap = new Map();

  // Populate known local interfaces
  for (const iface of interfaces) {
    hostsMap.set(iface.address, {
      ip: iface.address,
      mac: iface.mac,
      type: 'local-interface',
      interface: iface.name,
      vendor: iface.vendor,
      hostname: os.hostname(),
      isGateway: route.gateway === iface.address,
      isSelf: true,
      alive: true,
      rtt: 0,
      openPorts: [],
      lastSeen: new Date().toISOString(),
    });
  }

  // Populate known ARP entries
  for (const dev of arpDevices) {
    hostsMap.set(dev.ip, {
      ...dev,
      isGateway: route.gateway === dev.ip,
      isSelf: false,
      alive: true,
      rtt: null,
      openPorts: [],
      lastSeen: new Date().toISOString(),
    });
  }

  // Step 1: Active ICMP Ping Sweep across target IPs
  if (targetIps.length > 0) {
    onEvent({
      type: 'status',
      message: `Running active ICMP ping sweep across ${targetIps.length} target hosts (${sweepRangeLabel})…`,
    });

    await pool(targetIps, hostConcurrency, async (ip) => {
      const pingRes = await pingAlive(ip, pingTimeout, 1);
      if (pingRes.alive) {
        let host = hostsMap.get(ip);
        if (!host) {
          host = {
            ip,
            mac: null,
            type: 'ping-discovered',
            interface: null,
            vendor: 'Unknown',
            hostname: null,
            isGateway: route.gateway === ip,
            isSelf: false,
            alive: true,
            rtt: pingRes.rtt,
            openPorts: [],
            lastSeen: new Date().toISOString(),
          };
          hostsMap.set(ip, host);
        } else {
          host.alive = true;
          host.rtt = pingRes.rtt;
        }
        onEvent({ type: 'host_found', host });
      }
    }, (done) => {
      onEvent({ type: 'sweep_progress', done, total: targetIps.length });
    });
  }

  // Step 2: Re-read ARP table (ICMP ping responses populate OS ARP cache!)
  const updatedArp = await getArpTable();
  for (const dev of updatedArp) {
    const existing = hostsMap.get(dev.ip);
    if (existing) {
      if (!existing.mac) existing.mac = dev.mac;
      if (!existing.vendor || existing.vendor === 'Unknown') existing.vendor = dev.vendor;
    } else {
      hostsMap.set(dev.ip, {
        ...dev,
        isGateway: route.gateway === dev.ip,
        isSelf: false,
        alive: true,
        rtt: null,
        openPorts: [],
        lastSeen: new Date().toISOString(),
      });
    }
  }

  const liveHosts = Array.from(hostsMap.values());
  // Sort with Gateway first, then Local Host, then IP order
  liveHosts.sort((a, b) => {
    if (a.isGateway) return -1;
    if (b.isGateway) return 1;
    if (a.isSelf) return -1;
    if (b.isSelf) return 1;
    return ipToInt(a.ip) - ipToInt(b.ip);
  });

  onEvent({
    type: 'devices',
    devices: liveHosts,
    count: liveHosts.length,
    gateway: route.gateway,
  });

  // Step 3: Layered Port Mapping (TCP + UDP)
  let scanTcp = FAST_TCP_PORTS;
  let scanUdp = [];

  if (mode === 'full') {
    scanTcp = Object.keys(TCP_SERVICES).map(Number);
    scanUdp = COMMON_UDP_PORTS;
  } else if (mode === 'custom') {
    scanTcp = typeof customTcp === 'string' ? parsePortList(customTcp) : (Array.isArray(customTcp) && customTcp.length ? customTcp : FAST_TCP_PORTS);
    scanUdp = typeof customUdp === 'string' ? parsePortList(customUdp) : (Array.isArray(customUdp) && customUdp.length ? customUdp : []);
  }

  onEvent({
    type: 'status',
    message: `Conducting layered port scanning (${scanTcp.length} TCP, ${scanUdp.length} UDP) across ${liveHosts.length} live hosts…`,
  });

  for (let i = 0; i < liveHosts.length; i++) {
    const host = liveHosts[i];
    onEvent({
      type: 'progress',
      current: i + 1,
      total: liveHosts.length,
      device: host.ip,
    });

    // Reverse DNS resolution
    if (!host.hostname) {
      host.hostname = await resolveHostname(host.ip);
    }

    // Port scan
    try {
      host.openPorts = await scanHostPorts(host.ip, scanTcp, scanUdp, portTimeout, 20);
    } catch {
      host.openPorts = [];
    }

    onEvent({ type: 'device_updated', device: host });
  }

  onEvent({
    type: 'done',
    devices: liveHosts,
    gateway: route.gateway,
    summary: {
      totalHosts: liveHosts.length,
      onlineHosts: liveHosts.filter(h => h.alive).length,
      gateway: route.gateway,
    },
  });

  return { interfaces, devices: liveHosts, gateway: route.gateway };
}
