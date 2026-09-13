import type { AppState } from './types.js';

export const state: AppState = {
  activeView: 'scanner',
  activeSubtab: 'findings',
  currentScan: null,
  scansHistory: [],
  monitors: [],
  discoveredDevices: [],
  networkInterfaces: [],
  gateway: null,
  aiConfig: {
    provider: (sessionStorage.getItem('monarch_provider') as any) || 'openrouter',
    apiKey: '',
    model: sessionStorage.getItem('monarch_model') || 'openai/gpt-4o-mini',
    timeoutMs: Number(sessionStorage.getItem('monarch_timeout')) || 120000,
  },
  filters: {
    findingText: '',
    severities: new Set(['critical', 'high', 'medium', 'low', 'info']),
  },
  notifications: [],
  ws: null,
};
