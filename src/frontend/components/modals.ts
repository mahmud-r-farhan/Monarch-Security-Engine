import { $, $$, toast, escapeHtml } from '../utils.js';
import { state } from '../state.js';

export function setupModals() {
  const devBtn = $('dev-modal-btn');
  if (devBtn) devBtn.addEventListener('click', () => { loadDevProfile(); $('dev-modal').classList.remove('hidden'); });
  const devClose = $('dev-modal-close');
  if (devClose) devClose.addEventListener('click', () => $('dev-modal').classList.add('hidden'));

  $('ai-config-btn').addEventListener('click', () => {
    ( $('ai-provider-select') as HTMLSelectElement).value = state.aiConfig.provider;
    ( $('ai-key-input') as HTMLInputElement).value = state.aiConfig.apiKey;
    ( $('ai-model-input') as HTMLInputElement).value = state.aiConfig.model || '';
    ( $('ai-url-input') as HTMLInputElement).value = state.aiConfig.baseUrl || '';
    updateProviderFields();
    hideHealthResult();
    $('ai-modal').classList.remove('hidden');
  });

  $('ai-modal-close').addEventListener('click', () => $('ai-modal').classList.add('hidden'));

  const updateProviderFields = () => {
    const prov = ( $('ai-provider-select') as HTMLSelectElement).value;
    const defaults: any = {
      openrouter: 'deepseek/deepseek-r1-distill-qwen-7b',
      openai: 'gpt-4o-mini',
      anthropic: 'claude-3-5-haiku-latest',
      gemini: 'gemini-1.5-flash',
      ollama: 'llama3.2',
      none: 'monarch-rules-v1',
    };
    ( $('ai-model-input') as HTMLInputElement).value = defaults[prov] || '';
    $('ai-key-group').style.display = prov === 'ollama' || prov === 'none' ? 'none' : 'block';
    $('ai-url-group').style.display = prov === 'ollama' ? 'block' : 'none';
    hideHealthResult();
  };

  $('ai-provider-select').addEventListener('change', updateProviderFields);

  // Health probe against the form's current (possibly unsaved) values
  const testBtn = $('ai-test-btn') as HTMLButtonElement | null;
  if (testBtn) testBtn.addEventListener('click', async () => {
    const provider = ( $('ai-provider-select') as HTMLSelectElement).value;
    const body: any = { provider };
    const keyVal = ( $('ai-key-input') as HTMLInputElement).value.trim();
    const urlVal = ( $('ai-url-input') as HTMLInputElement).value.trim();
    const modelVal = ( $('ai-model-input') as HTMLInputElement).value.trim();
    if (keyVal) body.apiKey = keyVal;
    if (urlVal) body.baseUrl = urlVal;
    if (modelVal) body.model = modelVal;

    testBtn.disabled = true;
    testBtn.textContent = '⏳ Probing…';
    showHealthResult({ pending: true });
    try {
      const res = await fetch('/api/ai/health', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      showHealthResult(data);
    } catch (err: any) {
      showHealthResult({ ok: false, error: err.message });
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
    state.aiConfig = { provider, apiKey, model, baseUrl };
    sessionStorage.setItem('monarch_provider', provider);
    sessionStorage.setItem('monarch_model', model);

    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(state.aiConfig),
    }).catch(() => null);

    if (res && !res.ok) {
      const err = await res.json().catch(() => ({ error: 'Configuration rejected' }));
      toast('Failed: ' + (err.error || 'invalid config'), 'error');
      return;
    }

    updateAiLabel();
    $('ai-modal').classList.add('hidden');
    toast(provider === 'ollama' ? 'AI configuration saved — using Ollama at ' + (baseUrl || 'http://localhost:11434') : 'AI configuration saved', 'success');
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
}

function showHealthResult(data: any) {
  const box = $('ai-health-result');
  if (!box) return;
  box.classList.remove('hidden', 'ok', 'fail');
  if (data.pending) {
    box.innerHTML = '⏳ Probing provider…';
    return;
  }
  if (data.ok) {
    box.classList.add('ok');
    const models = Array.isArray(data.models) && data.models.length
      ? `<span class="hint">Models: ${escapeHtml(data.models.slice(0, 8).join(', '))}${data.models.length > 8 ? ' …' : ''}</span>`
      : data.detail && /no models/i.test(data.detail) ? '<span class="hint">Pull a model first, e.g. <code>ollama pull llama3.2</code></span>' : '';
    box.innerHTML = `✅ <strong>${escapeHtml(data.provider)}</strong> — ${escapeHtml(data.detail || 'reachable')} (${data.latencyMs ?? 0}ms)${models}`;
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
