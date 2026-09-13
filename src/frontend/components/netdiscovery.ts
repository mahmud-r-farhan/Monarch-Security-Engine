import { $, escapeHtml, toast } from '../utils.js';
import { state } from '../state.js';

let networkSearchQuery = '';
let liveSweepTimer: any = null;

export async function triggerBackgroundSweep() {
  try {
    const res = await fetch('/api/netdiscovery/arp');
    if (res.ok) {
      const freshArp = await res.json();
      if (Array.isArray(freshArp) && freshArp.length) {
        state.discoveredDevices = freshArp;
        renderDevicesTable();
      }
    }
  } catch {}
}

export async function inspectHostDetailsModal(hostIp: string) {
  const modal = $('host-inspect-modal');
  const box = $('host-inspect-content');
  if (!modal || !box) return;
  modal.classList.remove('hidden');
  box.innerHTML = '<div class="empty">⏳ Deep probing host & VPS details for ' + escapeHtml(hostIp) + '…</div>';

  try {
    const res = await fetch('/api/netdiscovery/inspect-host', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ host: hostIp }),
    });
    if (!res.ok) throw new Error('Inspection request failed');
    const data = await res.json();

    const portsList = (data.openPorts || []).map((p: any) =>
      `<span class="badge-${p.proto || 'tcp'}">${p.port}/${p.proto || 'tcp'} ${escapeHtml(p.service || '')}</span>`
    ).join(' ') || '<span style="color:var(--text-muted);font-size:11px;">No open ports observed</span>';

    const webSection = data.webInfo
      ? `<div class="seo-item"><div class="seo-k">Web Target</div><div class="seo-v">${escapeHtml(data.webInfo.url)} (${data.webInfo.status})</div></div>
         <div class="seo-item"><div class="seo-k">Server Header</div><div class="seo-v">${escapeHtml(data.webInfo.server || 'None declared')}</div></div>`
      : '<div class="seo-item"><div class="seo-k">Web Server</div><div class="seo-v">No HTTP/HTTPS server detected</div></div>';

    box.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
        <div class="seo-item"><div class="seo-k">Target IP / Host</div><div class="seo-v">${escapeHtml(data.ip)}</div></div>
        <div class="seo-item"><div class="seo-k">Reverse Hostname</div><div class="seo-v">${escapeHtml(data.hostname || 'None resolved')}</div></div>
        <div class="seo-item"><div class="seo-k">Inferred OS</div><div class="seo-v">${escapeHtml(data.osHint || 'Unknown')}</div></div>
        <div class="seo-item"><div class="seo-k">Probe Latency</div><div class="seo-v">${Math.round(data.latencyMs || 0)}ms</div></div>
        ${webSection}
      </div>
      <div class="box" style="margin-top:12px;">
        <div class="box-head"><h3>Discovered Open Ports & Banners</h3></div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0;">${portsList}</div>
      </div>
    `;
  } catch (err: any) {
    box.innerHTML = '<div class="empty" style="color:var(--danger);">Failed to inspect host: ' + escapeHtml(err.message) + '</div>';
  }
}

export function setupNetworkDiscovery() {
  loadNetworkInfo();
  const modeSelect = $('net-mode-select') as HTMLSelectElement;
  if (modeSelect) modeSelect.addEventListener('change', (e) => {
    const isCustom = (e.target as HTMLSelectElement).value === 'custom';
    const customRow = $('net-custom-row');
    if (customRow) customRow.classList.toggle('hidden', !isCustom);
  });

  const inspectClose = $('host-inspect-close');
  if (inspectClose) inspectClose.addEventListener('click', () => $('host-inspect-modal').classList.add('hidden'));

  const liveToggle = $('net-live-toggle') as HTMLButtonElement;
  if (liveToggle) liveToggle.addEventListener('click', () => {
    if (liveSweepTimer) {
      clearInterval(liveSweepTimer);
      liveSweepTimer = null;
      liveToggle.textContent = '📡 Live Sweep: OFF';
      liveToggle.style.color = '';
      toast('Live monitoring sweep stopped', 'info');
    } else {
      liveSweepTimer = setInterval(() => triggerBackgroundSweep(), 15000);
      liveToggle.textContent = '📡 Live Sweep: ON (15s)';
      liveToggle.style.color = 'var(--success)';
      toast('Live monitoring sweep active (updates every 15s)', 'success');
      triggerBackgroundSweep();
    }
  });
  const segSelect = $('net-segment-select') as HTMLSelectElement;
  if (segSelect) segSelect.addEventListener('change', (e) => {
    if ((e.target as HTMLSelectElement).value) {
      ( $('net-target-input') as HTMLInputElement).value = (e.target as HTMLSelectElement).value;
    }
  });
  const devSearch = $('dev-search-input') as HTMLInputElement;
  if (devSearch) devSearch.addEventListener('input', (e) => {
    networkSearchQuery = (e.target as HTMLInputElement).value.toLowerCase().trim();
    renderDevicesTable();
  });
  const exportCsv = $('dev-export-csv');
  if (exportCsv) exportCsv.addEventListener('click', () => {
    if (!state.discoveredDevices.length) return toast('No devices to export', 'error');
    const rows = [['IP','MAC','Vendor','Hostname','Gateway','Latency','TCP','UDP']];
    for (const d of state.discoveredDevices) {
      const tcp = (d.openPorts||[]).filter((p:any)=>p.proto==='tcp'||!p.proto).map((p:any)=>p.port + '/' + p.service).join(';');
      const udp = (d.openPorts||[]).filter((p:any)=>p.proto==='udp').map((p:any)=>p.port + '/' + p.service).join(';');
      rows.push([d.ip, d.mac||'', d.vendor||'', d.hostname||'', d.isGateway?'YES':'NO', String(d.rtt??''), tcp, udp]);
    }
    const csv = rows.map(r=>r.map(c=>'"' + String(c).replace(/"/g,'""') + '"').join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'monarch-net-' + new Date().toISOString().slice(0,10) + '.csv'; a.click(); URL.revokeObjectURL(url);
  });
  const exportJson = $('dev-export-json');
  if (exportJson) exportJson.addEventListener('click', () => {
    if (!state.discoveredDevices.length) return toast('No devices to export', 'error');
    const blob = new Blob([JSON.stringify(state.discoveredDevices,null,2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'monarch-net-' + new Date().toISOString().slice(0,10) + '.json'; a.click(); URL.revokeObjectURL(url);
  });
  const scanBtn = $('net-scan-btn') as HTMLButtonElement;
  if (scanBtn) scanBtn.addEventListener('click', async () => {
    const btn = $('net-scan-btn') as HTMLButtonElement;
    const subnet = ( $('net-target-input') as HTMLInputElement).value.trim() || undefined;
    const mode = ( $('net-mode-select') as HTMLSelectElement).value;
    let customTcp: any = undefined;
    let customUdp: any = undefined;
    if (mode==='custom') {
      const tcpRaw = ( $('net-custom-tcp') as HTMLInputElement).value.trim();
      if (tcpRaw) customTcp = tcpRaw.split(',').map(n=>parseInt(n.trim(),10)).filter(n=>!isNaN(n));
      const udpRaw = ( $('net-custom-udp') as HTMLInputElement).value.trim();
      if (udpRaw) customUdp = udpRaw.split(',').map(n=>parseInt(n.trim(),10)).filter(n=>!isNaN(n));
    }
    btn.innerHTML = '⏳ Scanning…';
    btn.disabled = true;
    const progWrap = $('net-progress-wrap');
    if (progWrap) progWrap.classList.remove('hidden');
    ( $('net-progress-fill') as HTMLElement).style.width = '5%';
    $('net-status-text').textContent = 'Initializing network sweep…';
    try {
      const res = await fetch('/api/netdiscovery/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ subnet, mode, customTcp, customUdp }) });
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      const processLine = (line:string) => {
        if (!line.startsWith('data: ')) return;
        try { const ev = JSON.parse(line.slice(6)); handleDiscoveryEvent(ev); } catch {}
      };
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop()!;
        for (const part of parts) for (const line of part.split('\n')) processLine(line);
      }
    } catch (err:any) { toast('Discovery error: ' + err.message, 'error'); }
    finally { btn.disabled = false; btn.innerHTML = '⚡ Start Discovery'; ( $('net-progress-fill') as HTMLElement).style.width = '100%'; $('net-status-text').textContent = 'Completed • ' + state.discoveredDevices.length + ' hosts'; }
  });
}

export function handleDiscoveryEvent(ev:any) {
  if (ev.type==='status') $('net-status-text').textContent = ev.message;
  else if (ev.type==='sweep_progress') { ( $('net-progress-fill') as HTMLElement).style.width = Math.round((ev.done/ev.total)*40) + '%'; $('net-status-text').textContent = 'ICMP sweep: ' + ev.done + '/' + ev.total; }
  else if (ev.type==='devices') { state.discoveredDevices = ev.devices||[]; renderDevicesTable(); if (ev.gateway) { $('net-gateway-badge').style.display='inline-flex'; $('net-gateway-badge').textContent='Gateway: ' + ev.gateway; } }
  else if (ev.type==='progress') { ( $('net-progress-fill') as HTMLElement).style.width = (40+Math.round((ev.current/ev.total)*60)) + '%'; $('net-status-text').textContent = 'Scanning ' + ev.device + ' (' + ev.current + '/' + ev.total + ')'; }
  else if (ev.type==='device_updated') { const idx = state.discoveredDevices.findIndex(d=>d.ip===ev.device.ip); if (idx>=0) state.discoveredDevices[idx]=ev.device; else state.discoveredDevices.push(ev.device); renderDevicesTable(); }
  else if (ev.type==='done') { ( $('net-progress-fill') as HTMLElement).style.width='100%'; $('net-status-text').textContent = 'Done • ' + (ev.devices?.length||state.discoveredDevices.length) + ' hosts'; }
}

export async function loadNetworkInfo() {
  try {
    const [ifacesRes, arpRes] = await Promise.all([fetch('/api/netdiscovery/interfaces'), fetch('/api/netdiscovery/arp')]);
    const ifacesData = await ifacesRes.json();
    state.networkInterfaces = ifacesData.interfaces || (Array.isArray(ifacesData)?ifacesData:[]);
    state.gateway = ifacesData.gateway||null;
    state.discoveredDevices = await arpRes.json();
    const segSelect = $('net-segment-select') as HTMLSelectElement;
    if (segSelect && state.networkInterfaces.length) {
      let opts = '<option value="">Select Subnet…</option>';
      for (const iface of state.networkInterfaces) {
        const i = iface as any;
        if (!i.internal && i.cidr) {
          const star = state.gateway && i.address.slice(0,i.address.lastIndexOf('.'))===state.gateway.slice(0,state.gateway.lastIndexOf('.'))?'★ ':'';
          opts += '<option value="' + escapeHtml(i.cidr) + '">' + star + escapeHtml(i.cidr) + ' (' + escapeHtml(i.name) + ')</option>';
        }
      }
      segSelect.innerHTML = opts;
      const firstExt = state.networkInterfaces.find((i:any)=>!i.internal&&i.cidr) as any;
      if (firstExt && !( $('net-target-input') as HTMLInputElement).value) { ( $('net-target-input') as HTMLInputElement).value = firstExt.cidr; segSelect.value = firstExt.cidr; }
    }
    if (state.gateway) { const badge = $('net-gateway-badge'); if (badge) { badge.style.display='inline-flex'; badge.textContent='Gateway: ' + state.gateway; } }
    renderInterfaces();
    renderDevicesTable();
  } catch {}
}

export function renderInterfaces() {
  const c = $('ifaces-list');
  if (!state.networkInterfaces.length) { c.innerHTML='<div class="empty">No interfaces found</div>'; return; }
  let html = '';
  for (const iface of state.networkInterfaces) {
    const i = iface as any;
    const cidrBadge = i.cidr ? '<span class="badge" style="font-size:10px;">' + escapeHtml(i.cidr) + '</span>' : '';
    html += '<div class="iface"><div style="display:flex;justify-content:space-between;"><span class="iface-name">' + escapeHtml(i.name) + '</span>' + cidrBadge + '</div><div class="iface-ip">' + escapeHtml(i.address) + ' / ' + escapeHtml(i.netmask) + '</div><div class="iface-mac">' + escapeHtml(i.mac||'–') + ' • <span class="vendor">' + escapeHtml(i.vendor||'Unknown') + '</span></div></div>';
  }
  c.innerHTML = html;
}

export function renderDevicesTable() {
  const tbody = $('devices-body');
  let list = state.discoveredDevices||[];
  if (networkSearchQuery) list = list.filter(d=>d.ip.toLowerCase().includes(networkSearchQuery)||(d.mac&&d.mac.toLowerCase().includes(networkSearchQuery))||(d.vendor&&d.vendor.toLowerCase().includes(networkSearchQuery))||(d.hostname&&d.hostname.toLowerCase().includes(networkSearchQuery)));
  $('dev-count-badge').textContent = list.length + ' Hosts';
  if (!list.length) { tbody.innerHTML='<tr><td colspan="7" class="empty">No hosts found</td></tr>'; return; }
  let html = '';
  for (const d of list) {
    const tcp = (d.openPorts||[]).filter((p:any)=>p.proto==='tcp'||!p.proto);
    const udp = (d.openPorts||[]).filter((p:any)=>p.proto==='udp');
    let tcpHtml = '';
    for (const p of tcp) { tcpHtml += '<span class="badge-tcp">' + p.port + '/tcp ' + escapeHtml(p.service||'') + '</span>'; }
    let udpHtml = '';
    for (const p of udp) { udpHtml += '<span class="badge-udp">' + p.port + '/udp ' + escapeHtml(p.service||'') + '</span>'; }
    const noPorts = (!tcp.length&&!udp.length) ? '<span style="color:var(--text-muted);font-size:11px;">No open ports</span>' : '';
    const gwBadge = d.isGateway ? '<span style="margin-left:6px;padding:1px 6px;border-radius:6px;background:rgba(255,176,46,0.15);color:#ffb02e;font-size:10px;font-weight:700;">★ GW</span>' : '';
    const selfBadge = d.isSelf ? '<span style="margin-left:6px;padding:1px 6px;border-radius:6px;background:rgba(79,124,255,0.15);color:var(--primary);font-size:10px;font-weight:700;">SELF</span>' : '';
    const rttHtml = d.rtt!=null ? '<span class="badge-icmp">' + Math.round(d.rtt) + 'ms</span>' : (d.alive?'<span class="sev low" style="font-size:9px;">ONLINE</span>':'–');
    html += '<tr><td><span style="font-weight:700;font-family:var(--font-mono);cursor:pointer;" onclick="copyToClipboard(\'' + escapeHtml(d.ip) + '\',\'IP copied\')">' + escapeHtml(d.ip) + '</span>' + gwBadge + selfBadge + '</td><td style="font-family:var(--font-mono);font-size:11px;">' + (d.mac?escapeHtml(d.mac):'–') + '</td><td><span class="vendor">' + escapeHtml(d.vendor||'Unknown') + '</span></td><td style="font-size:11px;color:var(--text-soft);">' + escapeHtml(d.hostname||d.interface||'–') + '</td><td>' + rttHtml + '</td><td><div style="display:flex;flex-wrap:wrap;max-width:340px;">' + tcpHtml + udpHtml + noPorts + '</div></td><td style="text-align:right;"><button class="btn btn-ghost" style="height:26px;font-size:10px;margin-right:4px;" onclick="inspectHostDetailsModal(\'' + escapeHtml(d.ip) + '\')">Inspect</button></td></tr>';
  }
  tbody.innerHTML = html;
}
