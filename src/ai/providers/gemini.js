import { postJson } from './http.js';

/** Google Gemini generateContent provider. */
export const gemini = {
  id: 'gemini',

  async chat({ apiKey, model, system, prompt, fetchImpl, timeoutMs }) {
    const { json } = await postJson(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
      {
        body: {
          systemInstruction: { parts: [{ text: system }] },
          contents: [{ role: 'user', parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.2, responseMimeType: 'application/json' },
        },
        fetchImpl,
        timeoutMs,
      }
    );
    return json.candidates?.[0]?.content?.parts?.map(p => p.text).join('') || '';
  },
};
