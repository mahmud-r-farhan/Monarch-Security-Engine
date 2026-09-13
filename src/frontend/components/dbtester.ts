import { $, escapeHtml } from '../utils.js';

export function setupDatabaseTester() {
  const dbForm = $('db-form') as HTMLFormElement;
  if (dbForm) dbForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const type = ( $('db-type') as HTMLSelectElement).value;
    const host = ( $('db-host') as HTMLInputElement).value.trim();
    const port = ( $('db-port') as HTMLInputElement).value.trim()||undefined;
    const wrap = $('db-results-wrap');
    wrap.innerHTML='<div class="empty">Executing handshake…</div>';
    try {
      const res = await fetch('/api/db/test', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ type, host, port }) });
      const data = await res.json();
      wrap.innerHTML = '<div style="margin-bottom:10px;"><span class="sev ' + (data.connected?'low':'critical') + '">' + data.status + '</span><span style="font-family:var(--font-mono);font-size:11px;margin-left:6px;color:var(--text-muted);">' + data.latencyMs + 'ms • Port ' + data.port + '</span></div><div class="form-group"><label>Version & Handshake</label><div class="codeblock">' + escapeHtml(data.serverVersion||data.error||'') + '</div></div><div class="desc">' + escapeHtml(data.details||'') + '</div>';
    } catch (err:any) { wrap.innerHTML='<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });

  const stressBtn = $('db-stress-btn');
  if (stressBtn) stressBtn.addEventListener('click', async () => {
    const type = ( $('db-type') as HTMLSelectElement).value;
    const host = ( $('db-host') as HTMLInputElement).value.trim();
    const port = ( $('db-port') as HTMLInputElement).value.trim()||undefined;
    const wrap = $('db-results-wrap');
    wrap.innerHTML='<div class="empty">Running 30 concurrent probes…</div>';
    try {
      const res = await fetch('/api/db/stress', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ type, host, port, concurrency:10, totalQueries:30 }) });
      const data = await res.json();
      wrap.innerHTML = '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px;"><div class="stat" style="padding:10px;"><div class="stat-val" style="color:var(--success);">' + data.successful + ' / ' + data.totalAttempts + '</div><div class="stat-lbl">Success</div></div><div class="stat" style="padding:10px;"><div class="stat-val">' + data.avgLatencyMs + 'ms</div><div class="stat-lbl">Avg Latency</div></div><div class="stat" style="padding:10px;"><div class="stat-val">' + data.maxLatencyMs + 'ms</div><div class="stat-lbl">Max</div></div></div>';
    } catch (err:any) { wrap.innerHTML='<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });
}
