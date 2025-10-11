# Prompt: Generate a Context-Aware XSS Probe (Python)

Goal
- Test for reflected and stored XSS by injecting context-specific payloads into parameters discovered from captures and target.json routes.

Constraints
- Read `target.json`; no hardcoded IPs. Respect timeouts, rate limit, proxies, and optional auth.
- Evidence under `targets-local/<target-key>/evidence/`; sanitized summary to `reports/`.

Features
- Captures-first parameter discovery (query, form, JSON keys) and route prioritization.
- Surfaces: query, form (`application/x-www-form-urlencoded`), JSON (`application/json`), multipart fields, headers likely reflected (e.g., `Referer`, only if seen), path params.
- Context payload sets: HTML body, attribute, JS string, URL; with URL/HTML entity/double encodings and Unicode homoglyphs.
- Methods: GET and POST variants; preserve content-types seen in captures.
- Heuristics: reflection detection with context markers, script tag traces, CSP/report-only hints, suspicious event attributes; anti‑CSRF detection to avoid state changes.
- Output artifacts: JSONL (method, url, params/body keys, headers subset, status, indicators) + truncated responses; summary status line; sanitized summary.

CLI
- `--target-json`, `--out-dir`, `--max`, `--https-proxy`, `--http-proxy`.

Suggested path
- `scripts/probes/xss_probe.py`

Safety
- Only target safe lab systems. Do not brute-force forms or authenticated areas without consent.
