# Captures (HAR, cURL, Burp) — Import & Replay Prompts

Purpose
- Guide an AI agent to import HTTP requests captured from browsers/tools (HAR, cURL, Burp exports) and safely replay them against a target defined by a private `target.json`.

Where to store private captures
- Use `re-cwe-prompts/targets-local/<target-key>/captures/` for raw tool exports (gitignored).
- Keep any unredacted replays/evidence under `re-cwe-prompts/targets-local/<target-key>/evidence/`.
- Only publish sanitized summaries under `reports/`.

What’s here
- `har_replay_prompt.md` — Prompt to parse a HAR file and generate a Python replayer.
- `curl_import_prompt.md` — Prompt to convert cURL commands into Python (requests) with fidelity.
- `burp_export_prompt.md` — Prompt to parse Burp saved requests and generate a replayer.
- `sanitization.md` — Guidance to redact captures and keep public artifacts clean.

Workflow fit
- Captures can serve as ground truth for dynamic probes. After replay validation, proceed to static analysis and reporting per `workflows/`.

Safety
- Never hardcode real IPs/secrets in scripts. Map tool capture values through `targets-local/<target-key>/target.json`.
- Store raw captures only in private folders.
