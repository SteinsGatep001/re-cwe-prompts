# Prompt: Import and Replay HAR

Goal
- Parse a HAR file (HTTP Archive) captured from a browser and generate a Python 3 script that replays selected requests against the current target using `targets-local/<target-key>/target.json`.

Inputs
- HAR path (private): `re-cwe-prompts/targets-local/<target-key>/captures/<file>.har`
- Target JSON path: `re-cwe-prompts/targets-local/<target-key>/target.json`

Constraints
- Do not hardcode real IPs; read base URL, TLS, headers from `target.json`.
- Respect `timeouts` and `rate_limit`.
- Sanitize and store public output in `reports/`; store raw responses under `targets-local/<target-key>/evidence/`.

Agent actions
1) Load target.json and the HAR file.
2) Extract entries matching the target host/port and allowed methods (GET, POST, PUT).
3) Convert each entry to `requests` calls: method, path, query, headers, cookies, body (form/json/multipart detection).
4) Drop or override sensitive headers: Authorization, Cookie; use target.json auth instead.
5) Replay in timestamp order with simple rate limiting.
6) Save per-request results (status, headers, brief body preview) to a CSV/JSONL under `targets-local/<target-key>/evidence/har_replay/`.
7) Print a one-line summary per request; at the end, write a sanitized summary to `reports/`.

Suggested script path
- `scripts/probes/har_replayer.py` (in your main repo)

Optional
- Include filters: by path regex, method, status code.
- Implement a `--dry-run` to preview without sending.
