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

## Running locally
```bash
npm install
npm run demo:target   # terminal 1
npm start             # terminal 2 → http://localhost:3000
npm test
```

## Reporting security issues in Monarch itself
Please email the maintainer privately rather than opening a public issue.
