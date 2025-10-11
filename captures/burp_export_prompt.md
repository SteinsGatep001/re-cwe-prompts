# Prompt: Import Burp Saved Requests and Replay

Goal
- Parse Burp saved requests (raw HTTP or XML/JSON export) and generate a Python 3 replayer that uses `targets-local/<target-key>/target.json` to send them safely.

Inputs
- Private export under: `re-cwe-prompts/targets-local/<target-key>/captures/burp/`
- Target JSON: `re-cwe-prompts/targets-local/<target-key>/target.json`

Constraints
- Do not hardcode real IPs. Build URLs from target.json’s `base_url` and merge sanitized headers.
- Drop or override sensitive headers (Authorization, Cookie). Use target.json auth.
- Preserve method, path, query, body, and key headers (Content-Type, Referer, Accept, User-Agent as needed).

Agent actions
1) Load requests (raw or structured) and parse into method/path/query/headers/body.
2) Normalize line endings and header casing.
3) Map cookies to a `requests.Session` cookie jar; avoid embedding secrets in code.
4) Replay sequentially with rate limiting and per-request timeouts.
5) Save per-request results under `targets-local/<target-key>/evidence/burp_replay/` and write a sanitized summary to `reports/`.

Optional
- Add filters (by path/method/status) and a `--dry-run` mode.
