# Prompt: Import cURL and Generate Python (requests)

Goal
- Convert one or more cURL commands (saved from browser/Burp) into a Python 3 script using `requests`, driven by `targets-local/<target-key>/target.json`.

Inputs
- cURL text (private): place under `re-cwe-prompts/targets-local/<target-key>/captures/curl.txt`
- Target JSON: `re-cwe-prompts/targets-local/<target-key>/target.json`

Constraints
- Do not hardcode real IPs; build URLs from `base_url` in target.json.
- Recreate headers, cookies, data, files, and auth according to cURL flags:
  - `-H` heads; `--data/--data-binary/--data-urlencode`; `-F` multipart; `-u` basic; `--compressed` accept-encoding; `--insecure` map to `verify=False` (only if necessary for lab).
- Sanitize for public output; store raw results privately.

Agent actions
1) Parse cURL lines into structured requests.
2) For each request:
   - Construct path+query relative to `base_url`.
   - Map headers; drop Authorization/Cookie unless specified in target.json’s auth.
   - Detect multipart boundaries and preserve filenames/content-type.
   - Choose `requests` call signature: `json=`, `data=`, or `files=`.
3) Generate `scripts/probes/curl_replay.py` that can load `curl.txt` and replay.
4) Add CLI flags: `--target-json`, `--filter-method`, `--filter-path`, `--save-bodies`.
5) Write per-request results under `targets-local/<target-key>/evidence/curl_replay/` and a sanitized summary to `reports/`.

Notes
- For exact multipart reproduction, allow passing a fixed boundary when necessary.
- Respect `timeouts` and `rate_limit` from target.json.
