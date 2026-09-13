import { openAiChat, openAiListModels } from './openaiCompatible.js';

/** OpenAI-Compatible generic chat provider (vLLM, LM Studio, LocalAI, Together, DeepSeek, etc.). */
export const openaiCompatible = {
  id: 'openai-compatible',

  async chat({ apiKey, baseUrl, model, system, prompt, fetchImpl, timeoutMs }) {
    const targetBase = (baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
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
    const targetBase = (baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
    return openAiListModels({
      baseUrl: targetBase,
      apiKey: apiKey || '',
      fetchImpl,
      timeoutMs,
    });
  },
};
