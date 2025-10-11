# Reference Scripts (HTTP)

Purpose
- Minimal, tool-agnostic examples to interact with targets described by `targets-local/<target-key>/target.json`.
- Avoid hardcoding sensitive data. Always read from the private JSON.

Requirements
- Python 3.8+
- Install: `pip install requests`

Files
- `http/common.py` — helpers to load `target.json` and build a `requests.Session` with auth, headers, TLS, proxies, and rate limits.
- `http/login.py` — performs a basic/digest/bearer authenticated probe to a path and stores cookies under the target's evidence folder.
- `http/request.py` — generic GET/POST/PUT with simple params/data/json/file support.

Usage examples
- Login (basic/digest/bearer) and store cookies:
  - `python3 re-cwe-prompts/scripts/http/login.py --target-json re-cwe-prompts/targets-local/http-example.local-8000/target.json --path /`
- Simple GET:
  - `python3 re-cwe-prompts/scripts/http/request.py --target-json re-cwe-prompts/targets-local/http-example.local-8000/target.json --method GET --path /Storage.html`
- POST JSON:
  - `python3 re-cwe-prompts/scripts/http/request.py --target-json re-cwe-prompts/targets-local/http-example.local-8000/target.json --method POST --path /api/test --json '{"a":1}'`
- POST multipart file:
  - `python3 re-cwe-prompts/scripts/http/request.py --target-json re-cwe-prompts/targets-local/http-example.local-8000/target.json --method POST --path /upload --file field=@/tmp/demo.txt;type=text/plain`

Notes
- Evidence and cookies are written to the private, gitignored folder under `targets-local/<target-key>/evidence/`.
- Keep public artifacts sanitized and store them in `reports/` as needed.
