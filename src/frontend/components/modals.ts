import { $, $$, toast, escapeHtml } from '../utils.js';
import { state } from '../state.js';

/** Fallback suggestions — refreshed from /api/ai/providers when the modal opens. */
const MODEL_DEFAULTS: Record<string, string> = {
  openrouter: 'openai/gpt-4o-mini',
  'openai-compatible': 'gpt-4o-mini',
  openai: 'gpt-4o-mini',
  anthropic: 'claude-3-5-haiku-latest',
  gemini: 'gemini-1.5-flash',
  ollama: 'llama3.2',
  none: 'monarch-rules-v1',
};

const PROVIDER_HINTS: Record<string, string> = {
  openrouter: 'One key, 300+ models at openrouter.ai/keys. Support for OpenRouter free models like meta-llama/llama-3.3-70b-instruct:free.',
  'openai-compatible': 'Works with any OpenAI API wire-compatible endpoint (vLLM, LM Studio, LocalAI, Together, DeepSeek, Groq, etc.).',
  openai: 'Uses platform.openai.com keys. gpt-4o-mini is fast, cheap and dependable for structured output.',
  anthropic: 'Uses console.anthropic.com keys. claude-3-5-haiku is the fast tier; sonnet for deeper analysis.',
  gemini: 'Uses aistudio.google.com API keys. gemini-1.5-flash has a generous free tier.',
  ollama: 'Runs fully offline against your own Ollama server — no key, no data leaves the machine.',
  none: 'Deterministic rules-based analyst. No network calls, always available.',
};

let providerInfoCache: any[] | null = null;

export function setupModals() {
  const devBtn = $('dev-modal-btn');
  if (devBtn) devBtn.addEventListener('click', () => { loadDevProfile(); $('dev-modal').classList.remove('hidden'); });
  const devClose = $('dev-modal-close');
  if (devClose) devClose.addEventListener('click', () => $('dev-modal').classList.add('hidden'));

  $('ai-config-btn').addEventListener('click', () => {
    const cfg: any = state.aiConfig;
    ( $('ai-provider-select') as HTMLSelectElement).value = cfg.provider;
    ( $('ai-key-input') as HTMLInputElement).value = cfg.apiKey || '';
    ( $('ai-model-input') as HTMLInputElement).value = cfg.model || MODEL_DEFAULTS[cfg.provider] || '';
    ( $('ai-url-input') as HTMLInputElement).value = cfg.baseUrl || '';
    const timeoutSel = $('ai-timeout-select') as HTMLSelectElement | null;
    if (timeoutSel) timeoutSel.value = String(cfg.timeoutMs || 120000);
    updateProviderFields();
    hideHealthResult();
    $('ai-modal').classList.remove('hidden');
    loadProviderSuggestions();
    loadProviderStatusBoard();
  });

  $('ai-modal-close').addEventListener('click', () => $('ai-modal').classList.add('hidden'));

  const updateProviderFields = () => {
    const prov = ( $('ai-provider-select') as HTMLSelectElement).value;
    const modelInput = $('ai-model-input') as HTMLInputElement;
    // Only auto-fill the model when it does not belong to another provider already
    if (!modelInput.value || Object.values(MODEL_DEFAULTS).includes(modelInput.value)) {
      modelInput.value = MODEL_DEFAULTS[prov] || '';
    }
    $('ai-key-group').style.display = prov === 'ollama' || prov === 'none' ? 'none' : 'block';
    $('ai-url-group').style.display = prov === 'ollama' || prov === 'openai-compatible' ? 'block' : 'none';
    const urlLabel = $('ai-url-group')?.querySelector('label');
    if (urlLabel) {
      urlLabel.textContent = prov === 'openai-compatible' ? 'Custom API Base URL' : 'Ollama Server URL';
    }
    const urlHint = $('ai-url-hint');
    if (urlHint) {
      urlHint.textContent = prov === 'openai-compatible'
        ? 'Base URL for OpenAI-compatible completions API (e.g. http://localhost:1234/v1, https://api.together.xyz/v1).'
        : 'No API key needed — point at your local or remote Ollama server. Default: http://localhost:11434';
    }
    const hint = $('ai-provider-hint');
    if (hint) { hint.textContent = PROVIDER_HINTS[prov] || ''; hint.style.display = prov === 'none' ? 'none' : 'block'; }
    renderProviderSuggestions(prov);
    hideHealthResult();
  };

  $('ai-provider-select').addEventListener('change', updateProviderFields);

  // Show/hide the API key while typing
  const keyToggle = $('ai-key-toggle');
  if (keyToggle) keyToggle.addEventListener('click', () => {
    const input = $('ai-key-input') as HTMLInputElement;
    input.type = input.type === 'password' ? 'text' : 'password';
    keyToggle.textContent = input.type === 'password' ? '👁' : '🙈';
  });

  // Load the provider's live model catalog into the datalist
  const loadBtn = ($('ai-models-load') as HTMLButtonElement) || null;
  if (loadBtn) loadBtn.addEventListener('click', async () => {
    const provider = ( $('ai-provider-select') as HTMLSelectElement).value;
    if (provider === 'none' || provider === 'ollama') {
      toast('Live model listing is not available for ' + provider + ' — use the suggestions', 'info');
      return;
    }
    const keyVal = ( $('ai-key-input') as HTMLInputElement).value.trim();
    loadBtn.disabled = true;
    loadBtn.textContent = '…';
    try {
      const res = await fetch('/api/ai/models', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider, apiKey: keyVal || undefined }),
      });
      const data = await res.json();
      if (data.ok && data.models?.length) {
        renderModelList(data.models);
        setModelHint(`Loaded ${data.count} live models from ${provider} — pick one from the autocomplete list.`);
        toast(`Loaded ${data.count} models`, 'success');
      } else {
        setModelHint('Could not load the live list: ' + (data.error || 'unknown error') + ' — curated suggestions are still available.');
        toast('Failed to load models: ' + (data.error || 'unknown error'), 'error');
      }
    } catch (err: any) {
      toast('Failed to load models: ' + err.message, 'error');
    } finally {
      loadBtn.disabled = false;
      loadBtn.textContent = '⟳';
    }
  });

  // Deep health probe against the form's current (possibly unsaved) values.
  // Validates the key AND the model with a tiny real chat completion.
  const testBtn = $('ai-test-btn') as HTMLButtonElement | null;
  if (testBtn) testBtn.addEventListener('click', async () => {
    const provider = ( $('ai-provider-select') as HTMLSelectElement).value;
    const body: any = { provider, deep: provider !== 'none' };
    const keyVal = ( $('ai-key-input') as HTMLInputElement).value.trim();
    const urlVal = ( $('ai-url-input') as HTMLInputElement).value.trim();
    const modelVal = ( $('ai-model-input') as HTMLInputElement).value.trim();
    const timeoutSel = $('ai-timeout-select') as HTMLSelectElement | null;
    if (keyVal) body.apiKey = keyVal;
    if (urlVal) body.baseUrl = urlVal;
    if (modelVal) body.model = modelVal;
    if (timeoutSel?.value) body.timeoutMs = Number(timeoutSel.value);

    testBtn.disabled = true;
    testBtn.textContent = '⏳ Probing…';
    showHealthResult({ pending: true, deep: body.deep });
    try {
      const res = await fetch('/api/ai/health', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      showHealthResult(data);
      if (data.ok && provider !== 'none') setAiDot('ok');
      else if (!data.ok) setAiDot('fail');
    } catch (err: any) {
      showHealthResult({ ok: false, error: err.message });
      setAiDot('fail');
    } finally {
      testBtn.disabled = false;
      testBtn.textContent = '🔌 Test Connection';
    }
  });

  $('ai-config-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const provider = ( $('ai-provider-select') as HTMLSelectElement).value as any;
    const apiKey = ( $('ai-key-input') as HTMLInputElement).value.trim();
    const model = ( $('ai-model-input') as HTMLInputElement).value.trim();
    const baseUrl = ( $('ai-url-input') as HTMLInputElement).value.trim();
    const timeoutSel = $('ai-timeout-select') as HTMLSelectElement | null;
    const timeoutMs = timeoutSel ? Number(timeoutSel.value) : 120000;
    state.aiConfig = { provider, apiKey, model, baseUrl, timeoutMs };
    sessionStorage.setItem('monarch_provider', provider);
    sessionStorage.setItem('monarch_model', model);
    sessionStorage.setItem('monarch_timeout', String(timeoutMs));

    const saveBtn = (e.target as HTMLFormElement).querySelector('button[type="submit"]') as HTMLButtonElement | null;
    if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = 'Saving…'; }

    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(state.aiConfig),
    }).catch(() => null);

    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save'; }

    if (res && !res.ok) {
      const err = await res.json().catch(() => ({ error: 'Configuration rejected' }));
      toast('Failed: ' + (err.error || 'invalid config'), 'error');
      return;
    }

    updateAiLabel();
    $('ai-modal').classList.add('hidden');
    toast(provider === 'ollama' ? 'AI configuration saved — using Ollama at ' + (baseUrl || 'http://localhost:11434') : 'AI configuration saved', 'success');
    // Refresh the header status dot against the newly saved config
    refreshAiStatusDot();
  });

  $('ai-clear-btn').addEventListener('click', async () => {
    state.aiConfig = { provider: 'none', apiKey: '', model: 'monarch-rules-v1', baseUrl: '' };
    sessionStorage.setItem('monarch_provider', 'none');
    ( $('ai-provider-select') as HTMLSelectElement).value = 'none';
    ( $('ai-key-input') as HTMLInputElement).value = '';
    ( $('ai-model-input') as HTMLInputElement).value = 'monarch-rules-v1';
    ( $('ai-url-input') as HTMLInputElement).value = '';
    updateProviderFields();

    await fetch('/api/config', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(state.aiConfig),
    }).catch(() => {});

    updateAiLabel();
    setAiDot('unknown');
    $('ai-modal').classList.add('hidden');
    toast('Switched to offline heuristic', 'success');
  });

  const addMonBtn = $('add-monitor-btn');
  if (addMonBtn) addMonBtn.addEventListener('click', () => {
    const notifySel = $('mon-notify') as HTMLSelectElement | null;
    if (notifySel) notifySel.value = 'all';
    $('monitor-modal').classList.remove('hidden');
  });
  const monClose = $('mon-modal-close');
  if (monClose) monClose.addEventListener('click', () => $('monitor-modal').classList.add('hidden'));
  const monCancel = $('mon-cancel-btn');
  if (monCancel) monCancel.addEventListener('click', () => $('monitor-modal').classList.add('hidden'));

  $$('.backdrop').forEach(bd => {
    bd.addEventListener('click', (e) => { if (e.target === bd) bd.classList.add('hidden'); });
  });

  // Warm the curated suggestions and reflect the saved provider's health in the header
  loadProviderSuggestions();
  refreshAiStatusDot();
}

/* ------------------------------------------------------------------ */
/* AI provider config helpers                                          */
/* ------------------------------------------------------------------ */

async function fetchProviderInfo(): Promise<any[]> {
  if (providerInfoCache) return providerInfoCache;
  try {
    const res = await fetch('/api/ai/providers');
    providerInfoCache = await res.json();
  } catch { providerInfoCache = []; }
  return providerInfoCache || [];
}

async function loadProviderSuggestions() {
  const info = await fetchProviderInfo();
  if (info.length) {
    for (const p of info) {
      if (p.id && Array.isArray(p.models) && p.models.length) MODEL_DEFAULTS[p.id] = p.defaultModel || MODEL_DEFAULTS[p.id] || p.models[0];
    }
  }
  renderProviderSuggestions(( $('ai-provider-select') as HTMLSelectElement).value);
}

function renderProviderSuggestions(provider: string) {
  const list = $('ai-model-list');
  if (!list) return;
  fetchProviderInfo().then(info => {
    const entry = info.find(p => p.id === provider);
    const models = entry?.models?.length ? entry.models : [MODEL_DEFAULTS[provider]].filter(Boolean);
    renderModelList(models);
  });
}

function renderModelList(models: string[]) {
  const list = $('ai-model-list');
  if (!list) return;
  list.innerHTML = models.map(m => `<option value="${escapeHtml(m)}"></option>`).join('');
}

function setModelHint(text: string) {
  const el = $('ai-model-hint');
  if (el) el.textContent = text;
}

/** Per-provider reachability board shown under the provider selector. */
async function loadProviderStatusBoard() {
  const box = $('ai-provider-status');
  if (!box) return;
  box.classList.remove('hidden');
  box.innerHTML = '<div class="ps-row muted"><span class="ps-dot pending"></span>Checking providers…</div>';
  try {
    const res = await fetch('/api/ai/health?all=1');
    const data = await res.json();
    const rows = (data.providers || []).map((p: any) => {
      const cls = p.provider === 'none' ? 'ok' : p.ok ? 'ok' : 'fail';
      const label = p.provider === 'none' ? 'Offline rules' : p.provider;
      const detail = p.ok ? (p.detail || 'reachable') : (p.error || 'unreachable');
      const short = String(detail).length > 46 ? String(detail).slice(0, 46) + '…' : detail;
      return `<div class="ps-row" data-provider="${escapeHtml(p.provider)}" title="${escapeHtml(detail)}"><span class="ps-dot ${cls}"></span><span class="ps-name">${escapeHtml(label)}</span><span class="ps-detail">${escapeHtml(short)}</span></div>`;
    });
    box.innerHTML = rows.join('');
    $$('#ai-provider-status .ps-row').forEach(row => {
      row.addEventListener('click', () => {
        const prov = (row as HTMLElement).dataset.provider;
        if (!prov) return;
        ( $('ai-provider-select') as HTMLSelectElement).value = prov;
        ( $('ai-provider-select') as HTMLSelectElement).dispatchEvent(new Event('change'));
      });
    });
  } catch {
    box.classList.add('hidden');
  }
}

function setAiDot(cls: 'ok' | 'fail' | 'unknown') {
  const dot = $('ai-dot');
  if (dot) dot.className = 'dot ' + cls;
}

/** Ask the server to probe the active provider and color the header dot. */
export async function refreshAiStatusDot() {
  try {
    const res = await fetch('/api/ai/health');
    const data = await res.json();
    if (data.provider === 'none') { setAiDot('unknown'); return; }
    setAiDot(data.ok ? 'ok' : 'fail');
    if (!data.ok && data.error) {
      const label = $('ai-config-label');
      if (label) label.title = data.error + (data.hint ? ' — ' + data.hint : '');
    }
  } catch { setAiDot('unknown'); }
}

function showHealthResult(data: any) {
  const box = $('ai-health-result');
  if (!box) return;
  box.classList.remove('hidden', 'ok', 'fail');
  if (data.pending) {
    box.innerHTML = '⏳ ' + (data.deep ? 'Probing provider and test-running the model…' : 'Probing provider…');
    return;
  }
  if (data.ok) {
    box.classList.add('ok');
    const models = Array.isArray(data.models) && data.models.length
      ? `<span class="hint">Models: ${escapeHtml(data.models.slice(0, 8).join(', '))}${data.models.length > 8 ? ' …' : ''}</span>`
      : data.detail && /no models/i.test(data.detail) ? '<span class="hint">Pull a model first, e.g. <code>ollama pull llama3.2</code></span>' : '';
    const chat = data.chat?.ok
      ? `<span class="hint">✅ Model check passed — test completion in ${data.chat.latencyMs}ms</span>`
      : '';
    const warn = data.ok && data.hint ? `<span class="hint warn">⚠️ ${escapeHtml(data.hint)}</span>` : '';
    box.innerHTML = `✅ <strong>${escapeHtml(data.provider)}</strong> — ${escapeHtml(data.detail || 'reachable')} (${data.latencyMs ?? 0}ms)${chat}${warn}${models}`;
  } else {
    box.classList.add('fail');
    box.innerHTML = `❌ <strong>${escapeHtml(data.provider || 'provider')}</strong> — ${escapeHtml(data.error || 'unreachable')}${data.hint ? `<span class="hint">💡 ${escapeHtml(data.hint)}</span>` : ''}`;
  }
}

function hideHealthResult() {
  const box = $('ai-health-result');
  if (box) box.classList.add('hidden');
}

export function updateAiLabel() {
  const names: any = {
    openrouter: 'AI: OpenRouter',
    'openai-compatible': 'AI: OpenAI-Compatible',
    openai: 'AI: OpenAI',
    anthropic: 'AI: Claude',
    gemini: 'AI: Gemini',
    ollama: 'AI: Ollama (Local)',
    none: 'Offline',
  };
  const label = $('ai-config-label');
  if (label) label.textContent = names[state.aiConfig.provider] || 'AI: ' + state.aiConfig.provider;
}

export async function loadDevProfile() {
  try {
    const res = await fetch('https://api.github.com/users/mahmud-r-farhan', {
      headers: { Accept: 'application/vnd.github.v3+json' },
    });
    if (res.ok) {
      const d = await res.json();
      if (d.avatar_url) ( $('dev-avatar') as HTMLImageElement).src = d.avatar_url;
      if (d.name) $('dev-name').textContent = d.name;
      if (d.login) $('dev-handle').textContent = '@' + d.login;
      if (d.bio) $('dev-bio').textContent = d.bio;
    }
  } catch {}
}
