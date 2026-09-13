import { openAiChat } from './openaiCompatible.js';

/**
 * OpenRouter — OpenAI-wire-compatible multi-model gateway.
 * Adds the recommended attribution headers.
 */
export const openrouter = {
  id: 'openrouter',

  async chat({ apiKey, model, system, prompt, fetchImpl, timeoutMs }) {
    return openAiChat({
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey,
      model,
      system,
      prompt,
      timeoutMs,
      extraHeaders: {
        'HTTP-Referer': 'https://github.com/mahmud-r-farhan/Monarch-Security-Engine',
        'X-Title': 'Monarch Security Engine',
      },
      fetchImpl,
    });
  },
};
