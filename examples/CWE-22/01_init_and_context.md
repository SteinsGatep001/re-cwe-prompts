Prompt 01 — Init and Context (CWE-22)

Goal
- Initialize target folders, target.json, and environment for CWE-22 analysis using re-cwe-prompts.

Context
- Authorization: Only analyze authorized lab targets.
- Set `RE_CWE_PROMPTS_DIR=${RE_CWE_PROMPTS_DIR:-./re-cwe-prompts}`
- Working directory: parent project (not inside re-cwe-prompts)
- Target: `<TARGET_URL>`; key: `<TARGET_KEY>`

Tasks
1) `mkdir -p targets-local/<TARGET_KEY>/{evidence,captures} reports-private`
2) Create `targets-local/<TARGET_KEY>/target.json` from `$RE_CWE_PROMPTS_DIR/templates/target_info_template.json` with `base_url` set to `<TARGET_URL>`.
3) Evidence files:
   - Dynamic: `targets-local/<TARGET_KEY>/evidence/dyn_<timestamp>.jsonl`
   - Static notes: `targets-local/<TARGET_KEY>/evidence/static_notes.md`
4) Read `$RE_CWE_PROMPTS_DIR/rev-prompts/STRATEGY_OVERVIEW.md`.

