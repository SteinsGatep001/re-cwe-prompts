# Prompt: Generate an Open Redirect Probe (Python)

Goal
- Detect open redirects by manipulating typical redirect parameters in routes from target.json and captures.

Constraints
- Read `target.json`; no hardcoded IPs. Respect timeouts, rate limit, proxies, and optional auth.
- Evidence under `targets-local/<target-key>/evidence/`; sanitized summary to `reports/`.

Features
- Parameter discovery for names like `next`, `url`, `redirect`, `returnTo`, plus capture-derived.
- Payload families: absolute URLs (`http://attacker/`, `//host`), encoded/mixed separators, userinfo tricks, double-decoding.
- Heuristics: 3xx with Location header controlled by input; verify external host/scheme.
- Output: JSONL attempts; note Location header, status, normalized target.

CLI
- `--target-json`, `--out-dir`, `--max`, `--https-proxy`, `--http-proxy`.

Suggested path
- `scripts/probes/open_redirect_probe.py`

Safety
- Authorized testing only.
