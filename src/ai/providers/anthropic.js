import { postJson } from './http.js';

/** Anthropic Messages API provider. */
export const anthropic = {
  id: 'anthropic',

  async chat({ apiKey, model, system, prompt, fetchImpl }) {
    const { json } = await postJson('https://api.anthropic.com/v1/messages', {
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: {
        model,
        max_tokens: 2500,
        temperature: 0.2,
        system,
        messages: [{ role: 'user', content: prompt }],
      },
      fetchImpl,
    });
    return json.content?.map(c => c.text || '').join('') || '';
  },
};
