import { openAiChat, openAiListModels } from './openaiCompatible.js';

/** OpenAI-Compatible generic chat provider (vLLM, LM Studio, LocalAI, Together, DeepSeek, etc.). */
export const openaiCompatible = {
  id: 'openai-compatible',

  async chat({ apiKey, baseUrl, model, system, prompt, fetchImpl, timeoutMs }) {
    let targetBase = baseUrl || 'https://api.openai.com/v1';
    while (typeof targetBase === 'string' && targetBase.endsWith('/')) {
      targetBase = targetBase.slice(0, -1);
    }
    return openAiChat({
      baseUrl: targetBase,
      apiKey: apiKey || '',
      model,
      system,
      prompt,
      timeoutMs,
      fetchImpl,
    });
  },

  async listModels({ apiKey, baseUrl, fetchImpl, timeoutMs }) {
    let targetBase = baseUrl || 'https://api.openai.com/v1';
    while (typeof targetBase === 'string' && targetBase.endsWith('/')) {
      targetBase = targetBase.slice(0, -1);
    }
    return openAiListModels({
      baseUrl: targetBase,
      apiKey: apiKey || '',
      fetchImpl,
      timeoutMs,
    });
  },
};
