import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const NOTIFICATIONS_FILE = path.resolve(process.cwd(), 'reports', 'notifications.json');
const MAX_NOTIFICATIONS = 250;         // cap stored notifications (memory + disk)
const RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // keep notifications for 7 days

/**
 * NotificationService — central in-app notification hub.
 *
 * Producers (monitor status changes, future scan alerts, speed regressions…)
 * call `notify()`; the service persists the item, broadcasts it over the
 * `notification` WebSocket channel and fans out to registered listeners.
 *
 * Consumers (REST API + frontend notification center) read, mark-read and
 * clear notifications through the service.
 */
class NotificationService {
  constructor() {
    this.notifications = new Map(); // id -> notification
    this.listeners = new Set();     // fn(notification)
    this.broadcast = null;          // ws broadcast fn (channel, payload)
    this.initialized = false;
  }

  async init(broadcastFn = null) {
    this.broadcast = broadcastFn;
    await this.load();
    await this.pruneExpired();
    this.initialized = true;
  }

  async load() {
    try {
      const data = JSON.parse(await fs.readFile(NOTIFICATIONS_FILE, 'utf8'));
      if (Array.isArray(data)) {
        for (const n of data) {
          if (n && n.id) this.notifications.set(n.id, n);
        }
      }
    } catch {
      // File doesn't exist yet — first run
    }
  }

  async persist() {
    try {
      await fs.mkdir(path.dirname(NOTIFICATIONS_FILE), { recursive: true });
      const list = this.sorted().slice(0, MAX_NOTIFICATIONS);
      await fs.writeFile(NOTIFICATIONS_FILE, JSON.stringify(list, null, 2));
    } catch (err) {
      console.error('[Notifications] Failed to persist:', err.message);
    }
  }

  sorted() {
    return Array.from(this.notifications.values()).sort((a, b) =>
      (b.createdAt || '').localeCompare(a.createdAt || '')
    );
  }

  async pruneExpired() {
    const now = Date.now();
    let changed = false;
    for (const [id, n] of this.notifications) {
      if (n.createdAt && now - new Date(n.createdAt).getTime() > RETENTION_MS) {
        this.notifications.delete(id);
        changed = true;
      }
    }
    // Trim to cap
    while (this.notifications.size > MAX_NOTIFICATIONS) {
      const oldest = this.sorted().pop();
      if (!oldest) break;
      this.notifications.delete(oldest.id);
      changed = true;
    }
    if (changed) await this.persist();
  }

  /**
   * Create a notification. Returns the created item.
   * @param {object} opts { type, severity, title, message, meta }
   */
  async notify({ type = 'info', severity = 'info', title, message = '', meta = {} }) {
    if (!title) return null;
    const notification = {
      id: randomUUID(),
      type,
      severity, // 'critical' | 'warning' | 'success' | 'info'
      title: String(title),
      message: String(message || ''),
      meta,
      read: false,
      createdAt: new Date().toISOString(),
    };
    this.notifications.set(notification.id, notification);
    await this.pruneExpired();
    await this.persist();

    if (this.broadcast) this.broadcast('notification', notification);
    for (const listener of this.listeners) {
      try { listener(notification); } catch { /* listener error is non-fatal */ }
    }
    return notification;
  }

  /** Convenience helper: monitor status-change notifications. */
  async notifyMonitorStatus(monitor, checkPoint, prevStatus) {
    const name = monitor.name || monitor.url;
    const when = new Date(checkPoint.timestamp).toLocaleTimeString();
    const detail = `HTTP ${checkPoint.statusCode ?? '—'} • ${checkPoint.latencyMs}ms${checkPoint.error ? ` • ${checkPoint.error}` : ''} • ${when}`;

    if (checkPoint.status === 'down') {
      return this.notify({
        type: 'monitor_down',
        severity: 'critical',
        title: `🔴 ${name} is DOWN`,
        message: detail,
        meta: { monitorId: monitor.id, url: monitor.url, status: checkPoint.status, prevStatus, ...pickProbe(checkPoint) },
      });
    }
    if (checkPoint.status === 'degraded') {
      return this.notify({
        type: 'monitor_degraded',
        severity: 'warning',
        title: `🟠 ${name} is SLOW (${checkPoint.latencyMs}ms)`,
        message: detail,
        meta: { monitorId: monitor.id, url: monitor.url, status: checkPoint.status, prevStatus, ...pickProbe(checkPoint) },
      });
    }
    // up — recovery if it was previously down/degraded, plain status otherwise
    const isRecovery = prevStatus === 'down' || prevStatus === 'degraded';
    return this.notify({
      type: isRecovery ? 'monitor_up' : 'monitor_status',
      severity: 'success',
      title: isRecovery ? `🟢 ${name} is back LIVE` : `🟢 ${name} is LIVE`,
      message: detail,
      meta: { monitorId: monitor.id, url: monitor.url, status: checkPoint.status, prevStatus, ...pickProbe(checkPoint) },
    });
  }

  list({ limit = 100, unreadOnly = false } = {}) {
    let items = this.sorted();
    if (unreadOnly) items = items.filter(n => !n.read);
    return { items: items.slice(0, Math.min(Math.max(Number(limit) || 100, 1), MAX_NOTIFICATIONS)), unread: this.unreadCount(), total: this.notifications.size };
  }

  unreadCount() {
    let c = 0;
    for (const n of this.notifications.values()) if (!n.read) c++;
    return c;
  }

  async markRead(id) {
    const n = this.notifications.get(id);
    if (!n) return null;
    n.read = true;
    await this.persist();
    return n;
  }

  async markAllRead() {
    for (const n of this.notifications.values()) n.read = true;
    await this.persist();
    return this.unreadCount();
  }

  async delete(id) {
    const deleted = this.notifications.delete(id);
    if (deleted) await this.persist();
    return deleted;
  }

  async clearAll() {
    this.notifications.clear();
    await this.persist();
    return true;
  }

  addListener(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
}

function pickProbe(checkPoint) {
  return {
    statusCode: checkPoint.statusCode,
    latencyMs: checkPoint.latencyMs,
    error: checkPoint.error || null,
    checkedAt: checkPoint.timestamp,
  };
}

export const notificationService = new NotificationService();
