# Security Policy

## Intended use
Monarch Security Engine is a passive auditing tool for systems you own or are authorised to test.
It does not exploit vulnerabilities, but it does issue HTTP requests (crawl, well-known probes, a CORS preflight, uptime probes, page-speed runs) to the target.

## Deploying the dashboard
If you expose the dashboard beyond localhost:
- set `ALLOW_PRIVATE_TARGETS=false` to prevent it being used as an SSRF proxy into your network;
- put it behind authentication (reverse proxy / SSO) — the API has no built-in auth;
- keep `MAX_CONCURRENT_SCANS` low and rate-limit `POST /api/scans`;
- treat `reports/` as sensitive: it contains headers, cookies (redacted previews) and findings for scanned hosts;
- `reports/monitors.json` and `reports/notifications.json` (v2.1) reveal internal hostnames and availability patterns — exclude them from backups/logs if that matters for your threat model.

## Reporting a vulnerability
Please report issues in Monarch itself privately to the maintainer via GitHub (security advisories) rather than a public issue. We aim to acknowledge within 72 hours.
