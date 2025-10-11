# Prompt: Generate an Open Redirect Probe (Python)

Goal
- Detect open redirects by manipulating typical redirect parameters in routes from target.json and captures.

Constraints
- Read `target.json`; no hardcoded IPs. Respect timeouts, rate limit, proxies, and optional auth.
- Evidence under `targets-local/<target-key>/evidence/`; sanitized summary to `reports/`.

Features
- Parameter discovery for names like `next`, `url`, `redirect`, `returnTo`, plus capture-derived names and locations (query, form, JSON).
- Surfaces: query params, form fields (`application/x-www-form-urlencoded`), JSON keys (`application/json`); optional headers if observed (rare) — do not include CRLF injection.
- Payload families: absolute URLs (`http://example/`), scheme-relative (`//host`), backslash (`\\host`), encoded/mixed separators, userinfo (`http://attacker@trusted/`), double-decoding.
- Heuristics: 3xx with Location header controlled by input; detect external host/scheme; normalize and compare.
- Output: JSONL attempts (method, surface, param, value, status, Location), normalized target; truncated bodies; sanitized summary.

CLI
- `--target-json`, `--out-dir`, `--max`, `--https-proxy`, `--http-proxy`.

Suggested path
- `scripts/probes/open_redirect_probe.py`

Safety
- Authorized testing only.
 - Avoid CRLF and response splitting vectors unless in an isolated lab explicitly scoped for it.
