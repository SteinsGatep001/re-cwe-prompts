# Probes (Dynamic Testing Prompts)

Purpose
- Prompts that instruct an AI agent to generate and run dynamic test scripts (e.g., Python) against a real target using private `target.json` metadata.

Where target metadata lives (private)
- `re-cwe-prompts/targets-local/<target-key>/target.json` (see `tutorials/init_target_info.md`).
- Keep raw evidence under `re-cwe-prompts/targets-local/<target-key>/evidence/`.
- Keep full, unredacted reports under `re-cwe-prompts/reports-private/`.

How to use
- Open the specific probe prompt (e.g., `cwe-22_python_probe_prompt.md`), paste it into your agent session, and follow instructions to generate a script in your main repo (not in this prompts repo).
- Ensure the script reads `target.json`, respects rate limits, and writes evidence to the private folders.

Safety and hygiene
- Only test lab/authorized systems.
- Never hardcode real IPs; read from `target.json`.
- Store sensitive artifacts privately; commit only sanitized summaries to `reports/`.
