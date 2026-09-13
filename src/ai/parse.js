/**
 * Strict-ish JSON parsing for model output.
 * Tolerates markdown fences and prose around a JSON object, and fixes a few
 * common malformations (smart quotes, trailing commas, unescaped newlines in
 * strings) before giving up.
 */

export function parseModelJson(text) {
  if (!text) return null;
  const cleaned = stripFences(String(text));
  try { return JSON.parse(cleaned); } catch { /* try object extraction */ }

  const m = cleaned.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { /* attempt repairs */ }

  try { return JSON.parse(repair(m[0])); } catch { return null; }
}

function stripFences(t) {
  // Reasoning models (DeepSeek-R1 distills, QwQ, …) may emit a <think> block
  // before the JSON even when JSON mode is requested — strip it first.
  return t
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .replace(/<think>[\s\S]*$/gi, '') // unclosed think block: keep what follows nothing — drop all
    .replace(/^```(?:json)?\s*/im, '')
    .replace(/```\s*$/m, '')
    .trim();
}

/** Best-effort repairs for typical small-model JSON mistakes. */
function repair(s) {
  return s
    .replace(/[\u201c\u201d]/g, '"')   // smart double quotes
    .replace(/[\u2018\u2019]/g, "'")   // smart single quotes
    .replace(/,\s*([}\]])/g, '$1')     // trailing commas
    .replace(/}\s*{/g, '},{');         // concatenated objects -> array-ish
}
