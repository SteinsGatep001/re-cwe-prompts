# Sanitization for Captures and Replays

Principles
- Private raw captures (HAR, cURL, Burp) must remain under `targets-local/<target-key>/captures/`.
- Public artifacts (reports, summaries) in `reports/` must not contain real IPs, secrets, or tokens.

Recommended steps
- Replace real hosts/IPs/emails with placeholders based on `redaction_map` in `target.json`.
- Remove `Authorization` and `Cookie` headers from public examples; show structure only.
- Truncate or hash sensitive body fields.

Automation
- During replay, produce two outputs:
  - Private: full per-request logs and bodies to `targets-local/<target-key>/evidence/<tool>_replay/`.
  - Public: a sanitized `reports/<tool>_replay_summary_<timestamp>.txt`.

Verification
- Before committing, grep for the real host/IP and confirm no matches in tracked files.
