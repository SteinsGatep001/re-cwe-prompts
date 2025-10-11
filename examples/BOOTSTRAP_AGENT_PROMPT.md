One-Prompt Bootstrap — Generate Per-Target Prompt Stubs from examples/

Role
- You are a documentation scaffolder agent. Using the re-cwe-prompts examples pack, generate per-target, ready-to-paste prompts under a downstream path. Start with CWE-22 (directory traversal). Do not embed secrets; only render placeholders with the provided target values.

Inputs (provide/confirm before execution)
- RE_CWE_PROMPTS_DIR: path to this repo (default ./re-cwe-prompts)
- CWE: default CWE-22
- TARGET_URL: full URL for the target, e.g., http://target:8010
- OUT_DIR: downstream prompts folder, e.g., ../docs/prompts

What to generate
- Under <OUT_DIR>/<CWE>/<TARGET_KEY>/, create:
  - MASTER.md — controller prompt
  - 01_init_and_context.md
  - 02_discover_and_dynamic_probe.md
  - 03_plan_multi_strategy.md
  - 04_execute_deep_re.md
  - 05_fix_plan_and_reporting.md
  - 06_verification_scripts.md
- Compute <TARGET_KEY> as <scheme>-<host>-<port>, e.g., http-target-8010
- Replace placeholders in all files:
  - <TARGET_URL>, <TARGET_HOST>, <TARGET_PORT>, <TARGET_KEY>

Source templates
- Read from: <RE_CWE_PROMPTS_DIR>/examples/<CWE>/MASTER.md and 01..06 step files
- Keep directory structure and file names

Constraints
- Do not hardcode credentials. Do not include raw evidence or secrets in outputs.
- If files already exist, list them and ask whether to overwrite.

Steps
1) Parse TARGET_URL into scheme, host, port; compute TARGET_KEY.
2) Copy each template file to OUT_DIR/CWE/TARGET_KEY/ and render placeholders.
3) Print the list of created files and the next step: paste MASTER.md followed by steps 01..06 in order.

Next actions (after generation)
- User pastes MASTER.md into an agent session to orchestrate the analysis.
- Follow with 01..06 prompts in order, adjusting per environment.

Safety
- Only proceed with authorized targets.

