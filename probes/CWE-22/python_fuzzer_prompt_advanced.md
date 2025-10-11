# Prompt: Generate an Advanced CWE-22 Traversal Fuzzer (Python)

Goal
- Build on the basic probe to support combinatorial payload generation, multi-encoding, mixed separators, capture-driven seeding, and stronger detection heuristics.

Constraints
- No hardcoded IPs; read target.json (`targets-local/<target-key>/target.json`).
- Respect `timeouts`, `rate_limit`, and proxies; support optional auth.
- Evidence under `targets-local/<target-key>/evidence/`; sanitized summary to `reports/`.

Features
- Seed extraction: from `target.json` routes and any captures (paths in `targets-local/<target-key>/captures/`).
- Payload families: segments (`../`, `..%2f`, `%2e%2e/`, `%252e%252e/`, `..\\`), slashes (`/`, `%2f`, `%252f`, `\\`, `%5c`), depth 1..8.
- Combinators: double-encoding, mixed separators, unicode dot variants, trailing/leading encoded slashes.
- Generators: layered composition with caps (`--max`), deterministic seed for reproducibility.
- Heuristics: regex matchers for passwd-like markers, INI/XML keys, directory listing patterns; response length and content-type deltas.
- Output: JSONL attempts with fields (url, payload_id, status, len, indicators, preview), plus truncated response bodies.

CLI
- `--target-json`, `--out-dir`, `--max`, `--seed`, `--https-proxy`, `--http-proxy`, `--auth` override (optional).

Pseudocode
```
load target.json
seed routes from target.json and captures
build payload generators (families × combinators) with cap
for each route × payload:
  send GET with timeouts, headers, auth
  detect indicators; record attempt and write artifact
  sleep per rate limit
write sanitized summary to reports/
print one-line status
```

Safety
- Only for authorized testing; avoid destructive endpoints.

Suggested path
- `scripts/probes/cwe22_fuzzer.py`

Follow-ups
- Integrate with static RE findings to prioritize handlers and utilities.
