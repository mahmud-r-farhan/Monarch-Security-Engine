# Contributing

Thanks for helping make Monarch better!

## Ground rules
- Monarch is a **passive, defensive** scanner. PRs that add exploitation, brute-forcing, or payload injection against targets will not be merged.
- Every new finding must include: a stable `id`, severity, `description`, actionable `remediation`, and where possible a CWE / OWASP mapping and a reference link.
- Keep the default install dependency-light (no native modules in `dependencies`).

## Adding a check
1. Create `src/engine/checks/<name>.js` exporting `function <name>Check(ctx)` → `Finding[]`.
2. Register it in `src/engine/checks/index.js`.
3. Add a unit test in `test/` (see `test/checks.test.js` for fixtures).
4. If the check needs new crawl data, extend both crawler engines in `src/engine/crawler.js` so their output shape stays identical.

## Architecture (v2.1)
The backend is deliberately modular — keep it that way:
- `src/server.js` is a **slim orchestrator** only: security headers, CORS, static serving, health/config endpoints. Do not add feature routes there.
- Feature routes live in `src/routes/` (`scans.js`, `monitors.js`, `tools.js`) as Express routers mounted under `/api`.
- Shared scan state belongs in `src/scanRegistry.js` (in-memory registry + disk persistence + TTL cleanup).
- Background services live in `src/modules/` (`monitor.js`, `notifications.js`, `speed.js`, …) and are wired to WebSocket broadcast in `server.js`.
- Emitting user-facing events: use `notificationService.notify()` so alerts appear in the notification center and over the `notification` WS channel.
- Frontend: one file per tab in `src/frontend/components/`, shared state in `src/frontend/state.ts`, types in `types.ts`.

## Running locally
```bash
npm install
npm run demo:target   # terminal 1
npm start             # terminal 2 → http://localhost:3000
npm test
npm run typecheck
```

## Before you open a PR
- `npm test` and `npm run typecheck` must pass (33+ tests).
- New endpoints must be added to the `/api/docs` list in `server.js` and documented in `README.md` + `docs/USAGE_GUIDE.md`.
- New background behavior (monitors, notifications, speed) needs a unit test in `test/`.

## Reporting security issues in Monarch itself
Please email the maintainer privately rather than opening a public issue.
