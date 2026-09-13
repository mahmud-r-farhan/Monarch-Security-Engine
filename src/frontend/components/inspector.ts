import { $, escapeHtml, formatBytes } from '../utils.js';

export function setupInspector() {
  const httpForm = $('poke-http-form') as HTMLFormElement;
  if (httpForm) httpForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const method = ( $('poke-method') as HTMLSelectElement).value;
    const url = ( $('poke-url') as HTMLInputElement).value.trim();
    const authType = ( $('poke-auth-type') as HTMLSelectElement).value;
    const authVal = ( $('poke-auth-val') as HTMLInputElement).value.trim();
    const rawHeaders = ( $('poke-headers') as HTMLTextAreaElement).value.trim();
    const body = ( $('poke-body') as HTMLTextAreaElement).value.trim()||undefined;
    const headers:any = {};
    if (rawHeaders) rawHeaders.split('\n').forEach((line:string)=>{ const idx=line.indexOf(':'); if (idx>0) headers[line.slice(0,idx).trim()]=line.slice(idx+1).trim(); });
    let auth:any=null;
    if (authType==='bearer') auth={ type:'bearer', token:authVal };
    else if (authType==='basic') { const parts=authVal.split(':'); auth={ type:'basic', username:parts[0], password:parts[1] }; }
    else if (authType==='apikey') { const parts=authVal.split(':'); auth={ type:'apikey', header:parts[0]?.trim(), value:parts[1]?.trim() }; }
    const wrap = $('poke-response-wrap');
    wrap.innerHTML='<div class="empty">Sending request…</div>';
    try {
      const res = await fetch('/api/poke', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ url, method, headers, body, auth }) });
      const data = await res.json();
      let hdrStr = '';
      for (const k in data.headers||{}) { hdrStr += k + ': ' + data.headers[k] + '\n'; }
      wrap.innerHTML = '<div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span class="sev ' + (data.status<400?'low':'critical') + '">' + data.status + ' ' + escapeHtml(data.statusText||'') + '</span><span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">' + data.timingMs + 'ms • ' + formatBytes(data.sizeBytes) + '</span></div><div class="form-group"><label>Headers</label><div class="codeblock" style="max-height:120px;">' + escapeHtml(hdrStr) + '</div></div><div class="form-group"><label>Body (' + escapeHtml(data.contentType||'unknown') + ')</label><div class="codeblock" style="max-height:180px;">' + escapeHtml(data.body||'(Empty)') + '</div></div>';
    } catch (err:any) { wrap.innerHTML='<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });

  const sshForm = $('poke-ssh-form') as HTMLFormElement;
  if (sshForm) sshForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const host = ( $('ssh-host') as HTMLInputElement).value.trim();
    const port = Number(( $('ssh-port') as HTMLInputElement).value)||22;
    const timeoutMs = Number(( $('ssh-timeout') as HTMLInputElement).value)||4000;
    const wrap = $('ssh-response-wrap');
    wrap.innerHTML='<div class="empty">Connecting to SSH…</div>';
    try {
      const res = await fetch('/api/poke/ssh', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ host, port, timeoutMs }) });
      const data = await res.json();
      if (data.reachable) {
        wrap.innerHTML = '<div style="margin-bottom:10px;"><span class="sev low">ONLINE</span><span style="font-family:var(--font-mono);font-size:11px;margin-left:6px;color:var(--text-muted);">' + data.latencyMs + 'ms</span></div><div class="form-group"><label>Banner</label><div class="codeblock">' + escapeHtml(data.banner) + '</div></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;"><div class="seo-item"><div class="seo-k">SSH Version</div><div class="seo-v">' + escapeHtml(data.sshVersion||'–') + '</div></div><div class="seo-item"><div class="seo-k">OS Hint</div><div class="seo-v">' + escapeHtml(data.osHint||'Linux/BSD') + '</div></div></div>';
      } else {
        wrap.innerHTML = '<div class="empty" style="color:var(--danger);">' + escapeHtml(data.error||'Connection refused') + '</div>';
      }
    } catch (err:any) { wrap.innerHTML='<div class="empty" style="color:var(--danger);">' + escapeHtml(err.message) + '</div>'; }
  });
}
