import fs from 'node:fs';
import path from 'node:path';

/** Minimal .env loader (no dependency). Existing process.env values win. */
export function loadEnv(file = path.resolve(process.cwd(), '.env')) {
  try {
    for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq < 0) continue;
      const key = line.slice(0, eq).trim();
      let val = line.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
      if (!(key in process.env) && val !== '') process.env[key] = val;
    }
  } catch { /* no .env — fine */ }
}
