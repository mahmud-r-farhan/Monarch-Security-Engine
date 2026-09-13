import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORT_DIR = path.resolve(process.env.REPORT_DIR || path.join(__dirname, '..', 'reports'));
const SCAN_TTL_MS = Number(process.env.SCAN_TTL_HOURS || 24) * 60 * 60 * 1000;

/**
 * ScanRegistry — encapsulates the in-memory scan registry backed by JSON
 * files on disk. Extracted from server.js so route modules stay thin.
 */
class ScanRegistry {
  constructor() {
    this.scans = new Map(); // id -> { status, events, scan?, error?, listeners:Set, createdAt, target }
    this.running = 0;
    this.maxConcurrent = Number(process.env.MAX_CONCURRENT_SCANS || 3);
    this.reportDir = REPORT_DIR;
  }

  getReportFilePath(id) {
    if (!/^[0-9a-f-]{36}$/.test(id)) return null;
    const baseDir = path.resolve(REPORT_DIR);
    const filePath = path.resolve(baseDir, `${id}.json`);
    if (!filePath.startsWith(baseDir + path.sep)) return null;
    return filePath;
  }

  async persist(scan) {
    await fs.mkdir(REPORT_DIR, { recursive: true });
    const filePath = this.getReportFilePath(scan.id);
    if (!filePath) return;
    await fs.writeFile(filePath, JSON.stringify(scan));
  }

  async loadFromDisk(id) {
    const filePath = this.getReportFilePath(id);
    if (!filePath) return null;
    try {
      return JSON.parse(await fs.readFile(filePath, 'utf8'));
    } catch {
      return null;
    }
  }

  async getScan(id) {
    const rec = this.scans.get(id);
    if (rec?.scan) return rec.scan;
    return this.loadFromDisk(id);
  }

  createRecord(target) {
    return { status: 'running', events: [], listeners: new Set(), createdAt: Date.now(), target };
  }

  /** Periodic TTL cleanup of expired scans (memory + disk). */
  startTtlCleanup(intervalMs = 60 * 60 * 1000) {
    const timer = setInterval(async () => {
      const now = Date.now();
      for (const [id, rec] of this.scans) {
        if (now - rec.createdAt > SCAN_TTL_MS && rec.status !== 'running') {
          this.scans.delete(id);
        }
      }
      try {
        const files = await fs.readdir(REPORT_DIR);
        for (const f of files) {
          if (!f.endsWith('.json') || f.includes('monitors') || f.includes('notifications')) continue;
          const fp = path.join(REPORT_DIR, f);
          const stat = await fs.stat(fp).catch(() => null);
          if (stat && now - stat.mtimeMs > SCAN_TTL_MS) {
            await fs.unlink(fp).catch(() => {});
          }
        }
      } catch {}
    }, intervalMs);
    timer.unref();
    return timer;
  }
}

export const scanRegistry = new ScanRegistry();
