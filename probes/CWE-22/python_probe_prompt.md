# Prompt: Generate a CWE-22 Traversal Probe (Python)

Goal
- Write and run a Python 3 script that checks for CWE-22 (path traversal) using target settings from a private JSON file.

Constraints
- Do not hardcode real IPs/hosts. Read `target.json` from `re-cwe-prompts/targets-local/<target-key>/`.
- Respect `timeouts` and `rate_limit` in `target.json`.
- Write sensitive evidence under `re-cwe-prompts/targets-local/<target-key>/evidence/`.
- Save a sanitized summary to `reports/` (no real IPs/secrets). Optionally write a full report to `re-cwe-prompts/reports-private/`.

Inputs
- Path to target JSON: e.g., `re-cwe-prompts/targets-local/http-example.local-8000/target.json`

Expected features
- Read `base_url`, TLS (`verify`, `sni_host`), `headers`, `routes`, `timeouts`, `rate_limit` from `target.json`.
- Traverse-probe payload set (examples): `../`, `..%2f`, `%2e%2e/`, `%252e%252e/`, `..\`, mixed separators, double-encoded chains, trailing/leading encoded slashes.
- Probe both route path and common static endpoints (e.g., `/Storage.html`, plus any listed in `routes`).
- Support optional auth from `target.json` (none/basic/digest/bearer) with standard libraries.
- Timeouts and simple rate limiting (sleep between requests).
- HTTPS support via `verify` and optional `Host` header for SNI.
- Output
  - Console summary: vulnerable or not; first observed evidence indicator.
  - Write raw responses (truncated) and a CSV/JSONL of attempts to `targets-local/<target-key>/evidence/`.
  - Write a sanitized summary TXT to `reports/` using `workflows/write_reports.md` naming.

Suggested file path (in your main repo)
- `scripts/probes/cwe22_probe.py`

High-level pseudocode
```
load target.json
init session (requests) with headers, auth, TLS verify
build candidate URLs from base_url + routes + payload combinations
for each candidate url:
  send GET with timeouts
  if response suggests traversal (e.g., passwd-like markers, XML/INI leaks, directory listings):
    record evidence and mark vulnerable
  sleep per rate limit
summarize and write outputs
```

Agent actions
1) Create `scripts/probes/cwe22_probe.py` with the features above (no real IPs; read target.json path passed via `--target-json`).
2) Accept args: `--target-json`, `--out-dir` (default to the corresponding `targets-local/<target-key>/evidence/`), `--max` (#requests cap), `--https-proxy`, `--http-proxy`.
3) Print a one-line status at the end: `CWE-22: Vulnerable|Not Reproducible|Inconclusive`.
4) Optionally write a sanitized summary to `reports/` using `workflows/write_reports.md` patterns.
5) Echo the locations of any created files.

Safety note
- Only run against authorized test targets.
