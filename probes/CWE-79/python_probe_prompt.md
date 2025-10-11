# Prompt: Generate a Context-Aware XSS Probe (Python)

Goal
- Test for reflected and stored XSS by injecting context-specific payloads into parameters discovered from captures and target.json routes.

Constraints
- Read `target.json`; no hardcoded IPs. Respect timeouts, rate limit, proxies, and optional auth.
- Evidence under `targets-local/<target-key>/evidence/`; sanitized summary to `reports/`.

Features
- Parameter discovery from captures and query templates.
- Context payload sets: HTML body, attribute, JS string, URL. Encodings: URL, HTML entities, double-encoding.
- Heuristics: reflection detection, script tag injection traces, CSP/report-only hints, suspicious attributes.
- Output artifacts: JSONL attempts + truncated responses; summary status line.

CLI
- `--target-json`, `--out-dir`, `--max`, `--https-proxy`, `--http-proxy`.

Suggested path
- `scripts/probes/xss_probe.py`

Safety
- Only target safe lab systems. Do not brute-force forms or authenticated areas without consent.
