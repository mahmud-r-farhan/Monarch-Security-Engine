import { openAiChat } from './openaiCompatible.js';

/** OpenAI chat-completions provider. */
export const openai = {
  id: 'openai',

  async chat({ apiKey, model, system, prompt, fetchImpl }) {
    return openAiChat({
      baseUrl: 'https://api.openai.com/v1',
      apiKey,
      model,
      system,
      prompt,
      fetchImpl,
    });
  },
};
