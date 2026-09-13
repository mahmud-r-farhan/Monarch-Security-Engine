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
    apiKey: sessionStorage.getItem('monarch_ai_key') || '',
    model: sessionStorage.getItem('monarch_model') || 'deepseek/deepseek-r1-distill-qwen-7b',
  },
  filters: {
    findingText: '',
    severities: new Set(['critical', 'high', 'medium', 'low', 'info']),
  },
  ws: null,
};
