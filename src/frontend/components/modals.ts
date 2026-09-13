import { $, $$, toast } from '../utils.js';
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
  };

  $('ai-provider-select').addEventListener('change', updateProviderFields);

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
