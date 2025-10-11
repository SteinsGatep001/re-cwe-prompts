Examples (Copy-Paste Prompts)

Purpose
- Generic, IP-agnostic prompts you can paste into an AI agent. Replace placeholders with your target details, and keep sensitive data out of version control.

Placeholders
- <TARGET_URL> — full URL, e.g., http://192.168.1.10:8000
- <TARGET_HOST> — hostname or IP
- <TARGET_PORT> — port number
- <TARGET_KEY> — scheme-host-port key used for private paths, e.g., http-192.168.1.10-8000

Usage
- Set re-cwe-prompts path: `export RE_CWE_PROMPTS_DIR=${RE_CWE_PROMPTS_DIR:-./re-cwe-prompts}`
- Copy a MASTER.md and the step prompts for your CWE, replace placeholders, and run in order.
- Store private artifacts under `targets-local/<TARGET_KEY>/...` and `reports-private/`; only sanitized reports under `reports/`.

Available packs
- CWE-22 (Directory Traversal): `examples/CWE-22/MASTER.md` and `01..06` step prompts

