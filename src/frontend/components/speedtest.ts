import { $, escapeHtml, toast } from '../utils.js';

export interface SpeedPhase { key: string; label: string; ms: number; }
export interface SpeedAudit { id: string; severity: string; title: string; detail: string; }
export interface SpeedResult {
  url: string;
  reachable: boolean;
  error?: string;
  score?: number;
  grade?: string;
  metrics?: Record<string, any>;
  phases?: SpeedPhase[];
  audits?: SpeedAudit[];
  advice?: string[];
  runsRequested?: number;
  runsSuccessful?: number;
  ipAddresses?: string[];
}

const PHASE_COLORS: Record<string, string> = {
  dns: '#8b5cf6',
  tcp: '#38c5ff',
  tls: '#4f7cff',
  ttfb: '#ffb02e',
  download: '#1fcf7a',
};

function fmtMs(ms?: number | null): string {
  if (ms == null) return '—';
  return ms >= 1000 ? (ms / 1000).toFixed(2) + 's' : Math.round(ms) + 'ms';
}

function fmtBytes(b?: number | null): string {
  if (!b) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function msClass(ms?: number | null, warn = 500, bad = 1200): string {
  if (ms == null) return '';
  if (ms <= warn) return 'good';
  if (ms <= bad) return 'warn';
  return 'bad';
}

/** Speed tab — real connection-timing waterfall, weight, audits and advice. */
export function setupSpeedTester() {
  const form = $('speed-form') as HTMLFormElement;
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = ($('speed-target') as HTMLInputElement).value.trim();
    const runs = Number(($('speed-runs') as HTMLSelectElement).value);
    const wrap = $('speed-results');
    const btn = $('speed-btn') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = '⏳ Measuring…';
    wrap.innerHTML = '<div class="empty">⏳ Fetching target and measuring connection phases…</div>';
    try {
      const res = await fetch('/api/speed/analyze', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ target, runs }),
      });
      const data: SpeedResult = await res.json();
      renderSpeedResult(data);
    } catch (err: any) {
      wrap.innerHTML = `<div class="empty" style="color:var(--danger);">${escapeHtml(err.message)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = '⚡ Analyze Speed';
    }
  });
}

export function renderSpeedResult(data: SpeedResult) {
  const wrap = $('speed-results');
  if (!wrap) return;
  if (!data.reachable) {
    wrap.innerHTML = `<div class="empty" style="color:var(--danger);">❌ ${escapeHtml(data.error || 'Target unreachable')}</div>`;
    return;
  }

  const m = data.metrics || {};
  const grade = data.grade || '–';
  const score = data.score ?? 0;

  let html = `<div class="speed-hero">
    <div class="speed-gauge">
      <div class="speed-num grade-${grade}">${score}</div>
      <div class="speed-grade-lbl">Grade ${grade}</div>
      <div style="font-size:10px;color:var(--text-faint);margin-top:6px;">${data.runsSuccessful}/${data.runsRequested ?? 1} runs</div>
    </div>
    <div>
      <div class="speed-metrics">
        <div class="speed-metric"><div class="speed-metric-k">TTFB</div><div class="speed-metric-v ${msClass(m.ttfbMs, 200, 800)}">${fmtMs(m.ttfbMs)}</div></div>
        <div class="speed-metric"><div class="speed-metric-k">Total</div><div class="speed-metric-v ${msClass(m.totalMs, 800, 2000)}">${fmtMs(m.totalMs)}</div></div>
        <div class="speed-metric"><div class="speed-metric-k">Page Size</div><div class="speed-metric-v">${fmtBytes(m.sizeBytes)}</div></div>
        <div class="speed-metric"><div class="speed-metric-k">Compression</div><div class="speed-metric-v ${m.contentEncoding ? 'good' : 'bad'}">${m.contentEncoding ? m.contentEncoding.toUpperCase() : 'NONE'}</div></div>
        <div class="speed-metric"><div class="speed-metric-k">HTTP</div><div class="speed-metric-v">${escapeHtml(String(m.httpVersion || '—').toUpperCase())}</div></div>
        <div class="speed-metric"><div class="speed-metric-k">Status</div><div class="speed-metric-v ${m.status && m.status < 400 ? 'good' : 'bad'}">${m.status ?? '—'}</div></div>
      </div>
      ${data.ipAddresses?.length ? `<div style="margin-top:10px;font-size:10.5px;color:var(--text-muted);font-family:var(--font-mono);">IP: ${escapeHtml(data.ipAddresses.join(', '))}${m.redirected ? ' • redirected → ' + escapeHtml(m.finalUrl || '') : ''}</div>` : ''}
    </div>
  </div>`;

  // Connection waterfall
  if (data.phases?.length) {
    const maxMs = Math.max(...data.phases.map(p => p.ms || 0), 1);
    html += `<div class="box" style="margin-bottom:16px;">
      <div class="box-head"><h3>Connection Waterfall</h3><span class="badge">total ${fmtMs(m.totalMs)}</span></div>
      <div class="speed-waterfall">
        ${data.phases.map(p => `
          <div class="speed-phase">
            <div class="speed-phase-lbl">${escapeHtml(p.label)}</div>
            <div class="speed-phase-bar-track"><div class="speed-phase-bar" style="width:${Math.max(2, ((p.ms || 0) / maxMs) * 100)}%;background:${PHASE_COLORS[p.key] || 'var(--primary)'};"></div></div>
            <div class="speed-phase-ms">${fmtMs(p.ms)}</div>
          </div>`).join('')}
      </div>
    </div>`;
  }

  // Advice
  if (data.advice?.length) {
    html += `<div style="margin-bottom:16px;">${data.advice.map(a => `<div class="speed-advice">💡 <span>${escapeHtml(a)}</span></div>`).join('')}</div>`;
  }

  // Audits
  if (data.audits?.length) {
    const sevCls = (s: string) => s === 'high' ? 'critical' : s === 'medium' ? 'medium' : 'low';
    html += `<div class="box">
      <div class="box-head"><h3>Performance Audits</h3><span class="badge">${data.audits.length} found</span></div>
      ${data.audits.map(a => `
        <div class="card" style="margin-bottom:8px;">
          <div class="card-head"><span class="sev ${sevCls(a.severity)}">${a.severity}</span><span class="title">${escapeHtml(a.title)}</span></div>
          <div class="desc">${escapeHtml(a.detail)}</div>
        </div>`).join('')}
    </div>`;
  } else {
    html += `<div class="box"><div class="empty" style="color:var(--success);">✅ No performance issues detected — excellent!</div></div>`;
  }

  wrap.innerHTML = html;
  toast(`Speed test complete — score ${score}/100 (${grade})`, score >= 75 ? 'success' : score >= 50 ? 'info' : 'error');
}
