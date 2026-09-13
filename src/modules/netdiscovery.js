import os from 'node:os';
import net from 'node:net';
import dns from 'node:dns/promises';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { resolveVendor, normalizeMac } from './oui.js';

const execAsync = promisify(exec);

export const COMMON_PORTS = [
  { port: 21, service: 'FTP' },
  { port: 22, service: 'SSH' },
  { port: 23, service: 'Telnet' },
  { port: 25, service: 'SMTP' },
  { port: 53, service: 'DNS' },
  { port: 80, service: 'HTTP' },
  { port: 110, service: 'POP3' },
  { port: 143, service: 'IMAP' },
  { port: 443, service: 'HTTPS' },
  { port: 445, service: 'SMB' },
  { port: 993, service: 'IMAPS' },
  { port: 995, service: 'POP3S' },
  { port: 1433, service: 'MSSQL' },
  { port: 1521, service: 'Oracle' },
  { port: 3000, service: 'Node / Dev' },
  { port: 3306, service: 'MySQL' },
  { port: 3389, service: 'RDP' },
  { port: 5000, service: 'Flask / Dev' },
  { port: 5432, service: 'PostgreSQL' },
  { port: 6379, service: 'Redis' },
  { port: 8000, service: 'HTTP Alt' },
  { port: 8080, service: 'HTTP Proxy' },
  { port: 8443, service: 'HTTPS Alt' },
  { port: 9000, service: 'SonarQube / PHP' },
  { port: 9200, service: 'Elasticsearch' },
  { port: 27017, service: 'MongoDB' },
];

/**
 * Returns all local active network interfaces with IP, netmask, MAC, and CIDR.
 */
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

/**
 * Parses OS ARP cache table (`arp -a`) and returns discovered local network devices.
 */
export async function getArpTable() {
  try {
    const { stdout } = await execAsync('arp -a');
    return parseArpOutput(stdout);
  } catch (err) {
    return [];
  }
}

/**
 * Parse cross-platform `arp -a` output (Windows, Linux, macOS).
 */
export function parseArpOutput(output) {
  const lines = output.split('\n');
  const devices = [];
  const seenIps = new Set();
  let currentInterface = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    // Windows interface header: "Interface: 192.168.1.10 --- 0x11"
    const ifaceMatch = line.match(/Interface:\s*([0-9.]+)/i);
    if (ifaceMatch) {
      currentInterface = ifaceMatch[1];
      continue;
    }

    // Windows ARP entry: "192.168.1.1        00-11-22-33-44-55     dynamic"
    // Linux/macOS ARP entry: "? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]"
    const winMatch = line.match(/^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})\s+(\w+)/i);
    const nixMatch = line.match(/\(?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)?\s+(?:at\s+)?([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})/i);

    const match = winMatch || nixMatch;
    if (match) {
      const ip = match[1];
      const mac = normalizeMac(match[2]);
      const type = winMatch ? winMatch[3] : 'dynamic';

      // Skip broadcast or loopback ARP entries
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

/**
 * Scans a single TCP port on a target host.
 */
export function checkTcpPort(host, port, timeoutMs = 800) {
  return new Promise(resolve => {
    const started = Date.now();
    const socket = new net.Socket();
    let banner = '';

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      const latencyMs = Date.now() - started;
      // Send small probe to elicit banner
      try {
        if (port === 80 || port === 8080 || port === 3000 || port === 5000) {
          socket.write('HEAD / HTTP/1.0\r\n\r\n');
        } else {
          socket.write('\r\n');
        }
      } catch { /* ignore */ }

      setTimeout(() => {
        socket.destroy();
        resolve({
          port,
          open: true,
          latencyMs,
          banner: banner.trim().slice(0, 150) || null,
        });
      }, 100);
    });

    socket.on('data', data => {
      banner += data.toString('utf8', 0, Math.min(data.length, 256));
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, open: false, error: 'TIMEOUT' });
    });

    socket.on('error', err => {
      socket.destroy();
      resolve({ port, open: false, error: err.code });
    });

    try {
      socket.connect(port, host);
    } catch {
      resolve({ port, open: false, error: 'CONNECT_ERR' });
    }
  });
}

/**
 * Scans multiple TCP ports on a host in parallel.
 */
export async function scanHostPorts(host, portList = COMMON_PORTS.map(p => p.port), timeoutMs = 800, concurrency = 20) {
  const results = [];
  const queue = [...portList];

  const worker = async () => {
    while (queue.length > 0) {
      const port = queue.shift();
      const res = await checkTcpPort(host, port, timeoutMs);
      if (res.open) {
        const known = COMMON_PORTS.find(p => p.port === port);
        results.push({
          ...res,
          service: known ? known.service : 'Custom',
        });
      }
    }
  };

  const pool = Array.from({ length: Math.min(concurrency, portList.length) }, () => worker());
  await Promise.all(pool);
  results.sort((a, b) => a.port - b.port);
  return results;
}

/**
 * Resolves reverse DNS / hostname if possible.
 */
export async function resolveHostname(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames[0] || null;
  } catch {
    return null;
  }
}

/**
 * Run a full local network discovery scan:
 * 1. Read ARP table + local interfaces
 * 2. Optional ping/probe on subnet
 * 3. Resolve hostnames and scan key ports
 * 4. Yield live progress via onEvent
 */
export async function runNetworkDiscovery({ subnet = null, ports = null, onEvent = () => {} } = {}) {
  onEvent({ type: 'status', message: 'Reading local network interfaces and ARP table…' });
  const interfaces = getLocalInterfaces();
  const devices = await getArpTable();

  // Add loopback / local interface host device if not present
  for (const iface of interfaces) {
    if (!devices.some(d => d.ip === iface.address)) {
      devices.unshift({
        ip: iface.address,
        mac: iface.mac,
        type: 'local-interface',
        interface: iface.name,
        vendor: iface.vendor,
        hostname: os.hostname(),
        openPorts: [],
        lastSeen: new Date().toISOString(),
      });
    }
  }

  const scanPorts = Array.isArray(ports) && ports.length ? ports : [21, 22, 53, 80, 443, 445, 3000, 3306, 5432, 6379, 8080, 8443, 27017];
  onEvent({ type: 'devices', devices, count: devices.length });

  // Scan open ports and resolve hostnames for each discovered device
  for (let i = 0; i < devices.length; i++) {
    const device = devices[i];
    onEvent({ type: 'progress', current: i + 1, total: devices.length, device: device.ip });

    // Hostname lookup
    if (!device.hostname) {
      device.hostname = await resolveHostname(device.ip);
    }

    // Port scan
    try {
      device.openPorts = await scanHostPorts(device.ip, scanPorts, 600, 15);
    } catch {
      device.openPorts = [];
    }

    onEvent({ type: 'device_updated', device });
  }

  onEvent({ type: 'done', devices });
  return { interfaces, devices };
}
