Prompt 06 — Verification via Python Scripts

Goal
- Verify traversal behavior pre/post-fix.

Tasks
1) Build probe from `$RE_CWE_PROMPTS_DIR/probes/CWE-22/python_probe_prompt.md` (or advanced fuzzer).
2) Run: `python3 scripts/probes/cwe22_probe.py --target-json targets-local/<TARGET_KEY>/target.json --max 100`
3) Save evidence to `targets-local/<TARGET_KEY>/evidence/`; write sanitized summary to `reports/`.
4) Re-run after fix; expect blocking or confinement.

