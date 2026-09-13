import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const MONITORS_FILE = path.resolve(process.cwd(), 'reports', 'monitors.json');

class MonitorService {
  constructor() {
    this.monitors = new Map();
    this.timers = new Map();
    this.listeners = new Set();
    this.broadcast = null;
  }

  async init(broadcastFn = null) {
    this.broadcast = broadcastFn;
    await this.load();
    for (const monitor of this.monitors.values()) {
      if (monitor.active) {
        this.schedule(monitor);
      }
    }
  }

  async load() {
    try {
      const data = await fs.readFile(MONITORS_FILE, 'utf8');
      const list = JSON.parse(data);
      for (const m of list) {
        this.monitors.set(m.id, m);
      }
    } catch {
      // File doesn't exist yet, that's fine
    }
  }

  async persist() {
    try {
      await fs.mkdir(path.dirname(MONITORS_FILE), { recursive: true });
      const list = Array.from(this.monitors.values());
      await fs.writeFile(MONITORS_FILE, JSON.stringify(list, null, 2));
    } catch (err) {
      console.error('[Monitor] Failed to persist monitors:', err.message);
    }
  }

  getMonitors() {
    return Array.from(this.monitors.values()).map(m => this.computeStats(m));
  }

  getMonitor(id) {
    const m = this.monitors.get(id);
    return m ? this.computeStats(m) : null;
  }

  computeStats(m) {
    const hist = m.history || [];
    if (!hist.length) {
      return { ...m, uptimePercent: 100, avgLatencyMs: 0 };
    }
    const upCount = hist.filter(h => h.status === 'up').length;
    const uptimePercent = Math.round((upCount / hist.length) * 1000) / 10;
    const totalLatency = hist.reduce((acc, h) => acc + (h.latencyMs || 0), 0);
    const avgLatencyMs = Math.round(totalLatency / hist.length);
    return { ...m, uptimePercent, avgLatencyMs };
  }

  async createMonitor({ name, url, intervalSeconds = 30, expectedStatus = 200, keyword = '' }) {
    if (!url) throw new Error('Monitor URL is required');
    let normalizedUrl = url.trim();
    if (!/^https?:\/\//i.test(normalizedUrl)) normalizedUrl = `https://${normalizedUrl}`;

    const monitor = {
      id: randomUUID(),
      name: name?.trim() || new URL(normalizedUrl).hostname,
      url: normalizedUrl,
      intervalSeconds: Math.max(10, Number(intervalSeconds) || 30),
      expectedStatus: Number(expectedStatus) || 200,
      keyword: keyword?.trim() || '',
      status: 'pending',
      active: true,
      lastChecked: null,
      lastLatencyMs: null,
      lastStatusCode: null,
      lastError: null,
      history: [],
      createdAt: new Date().toISOString(),
    };

    this.monitors.set(monitor.id, monitor);
    await this.persist();
    this.schedule(monitor);
    // Perform initial check immediately
    this.checkMonitor(monitor.id).catch(() => {});
    return this.computeStats(monitor);
  }

  async deleteMonitor(id) {
    if (this.timers.has(id)) {
      clearInterval(this.timers.get(id));
      this.timers.delete(id);
    }
    const deleted = this.monitors.delete(id);
    await this.persist();
    return deleted;
  }

  async toggleMonitor(id) {
    const m = this.monitors.get(id);
    if (!m) return null;
    m.active = !m.active;
    if (m.active) {
      this.schedule(m);
      this.checkMonitor(m.id).catch(() => {});
    } else if (this.timers.has(id)) {
      clearInterval(this.timers.get(id));
      this.timers.delete(id);
      m.status = 'paused';
    }
    await this.persist();
    return this.computeStats(m);
  }

  schedule(monitor) {
    if (this.timers.has(monitor.id)) {
      clearInterval(this.timers.get(monitor.id));
    }
    const intervalMs = monitor.intervalSeconds * 1000;
    const timer = setInterval(() => {
      this.checkMonitor(monitor.id).catch(() => {});
    }, intervalMs);
    this.timers.set(monitor.id, timer);
  }

  async checkMonitor(id) {
    const m = this.monitors.get(id);
    if (!m || !m.active) return null;

    const started = Date.now();
    const checkPoint = {
      timestamp: new Date().toISOString(),
      status: 'down',
      latencyMs: 0,
      statusCode: null,
      error: null,
    };

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 12000);
      const res = await fetch(m.url, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Monarch-Security-Engine/2.0 Uptime-Probe (+https://github.com/mahmud-r-farhan/Monarch-Security-Engine)',
        },
      });
      clearTimeout(timeout);
      checkPoint.latencyMs = Date.now() - started;
      checkPoint.statusCode = res.status;

      let bodyValid = true;
      if (m.keyword) {
        const text = await res.text();
        bodyValid = text.includes(m.keyword);
      }

      const isStatusOk = m.expectedStatus ? res.status === m.expectedStatus : (res.status >= 200 && res.status < 400);

      if (isStatusOk && bodyValid) {
        checkPoint.status = checkPoint.latencyMs > 1500 ? 'degraded' : 'up';
      } else {
        checkPoint.status = 'down';
        if (!bodyValid) checkPoint.error = `Keyword "${m.keyword}" missing in response`;
        else checkPoint.error = `HTTP status ${res.status} (expected ${m.expectedStatus})`;
      }
    } catch (err) {
      checkPoint.latencyMs = Date.now() - started;
      checkPoint.status = 'down';
      checkPoint.error = err.message || 'Connection error';
    }

    m.status = checkPoint.status;
    m.lastChecked = checkPoint.timestamp;
    m.lastLatencyMs = checkPoint.latencyMs;
    m.lastStatusCode = checkPoint.statusCode;
    m.lastError = checkPoint.error;

    // Keep last 60 data points for sparkline/timeline
    m.history.push(checkPoint);
    if (m.history.length > 60) m.history.shift();

    await this.persist();
    const updated = this.computeStats(m);

    // Notify WebSocket subscribers
    if (this.broadcast) {
      this.broadcast('monitor_update', updated);
    }
    for (const listener of this.listeners) {
      listener(updated);
    }
    return updated;
  }
}

export const monitorService = new MonitorService();
