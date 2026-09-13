import { $, escapeHtml, toast } from '../utils.js';
import { state } from '../state.js';

export function setupMonitors() {
  const form = $('create-monitor-form') as HTMLFormElement;
  if (form) form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = ( $('mon-name') as HTMLInputElement).value.trim();
    const url = ( $('mon-url') as HTMLInputElement).value.trim();
    const intervalSeconds = Number(( $('mon-interval') as HTMLSelectElement).value);
    const expectedStatus = Number(( $('mon-status') as HTMLInputElement).value);
    const keyword = ( $('mon-keyword') as HTMLInputElement).value.trim();
    try {
      const res = await fetch('/api/monitors', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ name, url, intervalSeconds, expectedStatus, keyword }) });
      if (!res.ok) throw new Error((await res.json()).error);
      const newMon = await res.json();
      state.monitors.push(newMon);
      renderMonitors(); updateMonitorBadge(); $('monitor-modal').classList.add('hidden');
      toast('Monitor created', 'success');
    } catch (err:any) { toast('Failed: ' + err.message, 'error'); }
  });
  loadMonitors();
}

export async function loadMonitors() {
  try { const res = await fetch('/api/monitors'); state.monitors = await res.json(); renderMonitors(); updateMonitorBadge(); } catch {}
}

export function updateMonitorBadge() { const el = $('mon-count'); if (el) el.textContent = String(state.monitors.length); }

export function renderMonitors() {
  const grid = $('monitors-grid');
  if (!state.monitors.length) { grid.innerHTML='<div class="empty">No monitors yet. Add your first endpoint.</div>'; return; }
  let html = '';
  for (const m of state.monitors) {
    let spark = '';
    const history = (m.history||[]).slice(-30);
    for (const h of history) {
      const cls = h.status==='down'?'down':h.status==='degraded'?'deg':'';
      const height = Math.min(100,Math.max(15,(h.latencyMs||20)/10));
      spark += '<div class="spark-bar ' + cls + '" style="height:' + height + '%;" title="' + h.latencyMs + 'ms (' + h.status + ')"></div>';
    }
    const statusCls = m.status==='up'?'low':m.status==='degraded'?'medium':'critical';
    const checked = m.lastChecked ? new Date(m.lastChecked).toLocaleTimeString() : 'Never';
    html += '<div class="monitor"><div class="mon-head"><div class="mon-name">' + escapeHtml(m.name) + '</div><span class="sev ' + statusCls + '">' + m.status.toUpperCase() + '</span></div><div class="mon-url" title="' + escapeHtml(m.url) + '">' + escapeHtml(m.url) + '</div><div class="spark">' + spark + '</div><div class="mon-stats"><div class="mon-stat"><div class="mon-val">' + m.uptimePercent + '%</div><div class="mon-lbl">Uptime</div></div><div class="mon-stat"><div class="mon-val">' + (m.lastLatencyMs||0) + 'ms</div><div class="mon-lbl">Latency</div></div><div class="mon-stat"><div class="mon-val">' + m.intervalSeconds + 's</div><div class="mon-lbl">Interval</div></div></div><div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;"><span style="font-size:10px;color:var(--text-muted);">Checked: ' + checked + '</span><div style="display:flex;gap:4px;"><button class="icon-btn" title="Check now" onclick="checkMonitorNow(\'' + m.id + '\')">🔄</button><button class="icon-btn" title="Delete" onclick="deleteMonitor(\'' + m.id + '\')">🗑️</button></div></div></div>';
  }
  grid.innerHTML = html;
}
