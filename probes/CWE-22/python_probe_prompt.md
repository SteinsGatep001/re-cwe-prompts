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
- Captures-first seeding: prefer routes/params seen in `targets-local/<target-key>/captures/`.
- Injection surfaces for traversal:
  - Path segments (insert traversal at segment boundaries, with/without trailing slash)
  - Query parameters (names from captures: `path`, `file`, `name`, `download`, etc.)
  - Headers (only if observed): `X-Original-URL`, `X-Rewrite-URL`, `X-Accel-Redirect`, `Host`
  - Bodies: `application/x-www-form-urlencoded` and `multipart/form-data` (Content-Disposition `filename`), mirroring real requests from captures
- Payload families: `../`, `..%2f`, `%2e%2e/`, `%252e%252e/`, `..\\`, mixed separators, double-encoded chains, leading/trailing encoded slashes, Unicode dot variants.
- Methods: attempt GET and POST (form/multipart) where appropriate.
- Support optional auth from `target.json` (none/basic/digest/bearer) with standard libraries.
- Timeouts, backoff on 429/5xx, and simple rate limiting with jitter.
- HTTPS support via `verify` and optional `Host` header for SNI.
- Output
  - Console summary: Vulnerable | Not Reproducible | Inconclusive + first indicator
  - JSONL per attempt: method, url, params, headers subset, status, len, content-type, indicators, preview
  - Truncated raw bodies and artifacts under `targets-local/<target-key>/evidence/`
  - Sanitized summary TXT to `reports/` using `workflows/write_reports.md` naming

Suggested file path (in your main repo)
- `scripts/probes/cwe22_probe.py`

High-level pseudocode
```
load target.json
seed routes/params/headers from target.json and captures
init session with headers, auth, TLS verify
build candidates across surfaces: path, query, headers, body (form/json/multipart)
for each candidate (respect --max, rate_limit, backoff):
  send request with timeouts
  detect indicators (passwd-like markers, INI/XML keys, listings, path echoes)
  write JSONL + truncated body artifact
summarize and write outputs (reports/)
```

Agent actions
1) Create `scripts/probes/cwe22_probe.py` with the features above (no real IPs; read target.json path passed via `--target-json`).
2) Accept args: `--target-json`, `--out-dir` (default to the corresponding `targets-local/<target-key>/evidence/`), `--max` (#requests cap), `--https-proxy`, `--http-proxy`.
3) Print a one-line status at the end: `CWE-22: Vulnerable|Not Reproducible|Inconclusive`.
4) Optionally write a sanitized summary to `reports/` using `workflows/write_reports.md` patterns.
5) Echo the locations of any created files.

Safety note
- Only run against authorized test targets.
