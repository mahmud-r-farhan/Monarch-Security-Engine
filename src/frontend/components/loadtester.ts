import { $, escapeHtml } from '../utils.js';

export function setupLoadTester() {
  const form = $('loadtest-form') as HTMLFormElement;
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = ( $('lt-url') as HTMLInputElement).value.trim();
    const method = ( $('lt-method') as HTMLSelectElement).value;
    const concurrency = Number(( $('lt-concurrency') as HTMLInputElement).value)||10;
    const totalRequests = Number(( $('lt-total') as HTMLInputElement).value)||50;
    let headers:any = {};
    try { if (( $('lt-headers') as HTMLTextAreaElement).value.trim()) headers = JSON.parse(( $('lt-headers') as HTMLTextAreaElement).value); } catch {}
    const body = ( $('lt-body') as HTMLTextAreaElement).value.trim()||undefined;
    const securityProbes = { csrf: ( $('lt-probe-csrf') as HTMLInputElement).checked, sqli: ( $('lt-probe-sqli') as HTMLInputElement).checked, xss: ( $('lt-probe-xss') as HTMLInputElement).checked, rateLimit: ( $('lt-probe-rate') as HTMLInputElement).checked };
    const btn = $('lt-start-btn') as HTMLButtonElement;
    btn.disabled=true; btn.innerHTML='⏳ Testing…';
    const liveWrap = $('lt-live-container');
    liveWrap.innerHTML='<div class="empty">Launching concurrent requests…</div>';
    try {
      const res = await fetch('/api/loadtest/run', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ url, method, concurrency, totalRequests, headers, body, securityProbes }) });
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer='';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n'); buffer = lines.pop()!;
        for (const block of lines) {
          if (block.includes('event: progress')) {
            const jsonStr = block.slice(block.indexOf('data: ')+6);
            try { const data = JSON.parse(jsonStr); renderLoadProgress(data); } catch {}
          } else if (block.includes('event: done')) {
            const jsonStr = block.slice(block.indexOf('data: ')+6);
            try { const summary = JSON.parse(jsonStr); renderLoadSummary(summary); } catch {}
          }
        }
      }
    } catch (err:any) { liveWrap.innerHTML='<div class="empty" style="color:var(--danger);">Failed: ' + escapeHtml(err.message) + '</div>'; }
    finally { btn.disabled=false; btn.innerHTML='🚀 Launch Test'; }
  });
}

export function renderLoadProgress(p:any) {
  $('lt-live-container').innerHTML = '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px;"><div class="stat" style="padding:10px;"><div class="stat-val">' + p.completed + ' / ' + p.total + '</div><div class="stat-lbl">Completed</div></div><div class="stat" style="padding:10px;"><div class="stat-val" style="color:var(--primary);">' + p.rps + '</div><div class="stat-lbl">RPS</div></div><div class="stat" style="padding:10px;"><div class="stat-val">' + p.latestLatency + 'ms</div><div class="stat-lbl">Latency</div></div></div><div class="progress-wrap"><div class="progress" style="width:' + (p.completed/p.total)*100 + '%;"></div></div>';
}

export function renderLoadSummary(s:any) {
  let statusHtml = '';
  for (const code in s.statusCodes) { statusHtml += '<span class="badge">' + code + ': ' + s.statusCodes[code] + '</span>'; }
  let secFindings = '';
  if (s.securityFindings?.length) {
    secFindings += '<div style="margin-top:12px;"><h4 style="color:var(--danger);font-size:12px;margin-bottom:8px;">Security Findings (' + s.securityFindings.length + ')</h4>';
    for (const f of s.securityFindings) { secFindings += '<div class="card" style="margin-bottom:6px;"><div style="display:flex;gap:6px;align-items:center;"><span class="sev ' + f.severity + '">' + f.severity + '</span><span class="title">' + escapeHtml(f.title) + '</span></div><div class="desc">' + escapeHtml(f.description) + '</div></div>'; }
    secFindings += '</div>';
  } else {
    secFindings = '<div style="margin-top:10px;font-size:11px;color:var(--success);">✅ Security checks passed</div>';
  }
  $('lt-live-container').innerHTML = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px;"><div class="stat" style="padding:10px;"><div class="stat-val" style="color:var(--primary);">' + s.rps + '</div><div class="stat-lbl">Avg RPS</div></div><div class="stat" style="padding:10px;"><div class="stat-val">' + s.latencies.p50 + 'ms</div><div class="stat-lbl">p50</div></div><div class="stat" style="padding:10px;"><div class="stat-val" style="color:#ff7a3d;">' + s.latencies.p95 + 'ms</div><div class="stat-lbl">p95</div></div><div class="stat" style="padding:10px;"><div class="stat-val" style="color:var(--danger);">' + s.latencies.p99 + 'ms</div><div class="stat-lbl">p99</div></div></div><div class="form-group"><label>Status Distribution</label><div style="display:flex;gap:6px;flex-wrap:wrap;">' + statusHtml + '</div></div>' + secFindings;
}
