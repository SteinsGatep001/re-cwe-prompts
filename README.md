# Reverse Engineering CWE Prompts (Tool‑Agnostic: IDA, Ghidra)

Purpose
- Pattern‑based prompts for guiding an AI agent (Codex/Claude) to discover, analyze, and report common web security weaknesses (CWEs) in binaries using disassemblers like IDA Pro or Ghidra. The prompts are generic and role‑based (dispatcher, handler, sanitizer, sink), so they work across tools and codebases.

Repository layout
- `cwes/` — CWE guides (pattern, sources/sinks, red flags, fix shape)
- `workflows/` — Generic workflows used for any CWE (discover routes, trace sinks, gap analysis, generate report)
- `cases/` — Ready-to-paste session seeds for common analyses (e.g., CWE-22 with IDA MCP)
- `roles/` — Role definitions and heuristics for dispatcher/handler/sanitizer/sink
- `tool-notes/` — Quick references for IDA MCP and Ghidra
- `checklists/` — Analysis, fix, and reporting checklists
- `playbooks/` — Scenario-focused guides that combine workflows (e.g., static resources)
- `templates/` — Report and summary templates used by workflows
- `targets/` — Guidance for storing per-target sensitive data locally (gitignored at root as `targets-local/`)
- `.gitignore` — Inside this folder, `targets-local/` and `reports-private/` are also ignored for standalone use
 - `tutorials/` — Step-by-step guides (e.g., initializing target info JSON)
- `INDEX.md` — Quick index linking CWEs and workflows
- `README_zh-CN.md` — 中文使用说明
 - `rev-prompts/` — Multi-strategy deep RE templates
 - `probes/` — Probe generator prompts (basic + advanced fuzzers)
 - `rev-prompts/` — Deep reverse-engineering prompt templates and multi-strategy playbook

Agent Quick Start (recommended)
- Set prompts path (submodule or sibling): `export RE_CWE_PROMPTS_DIR=${RE_CWE_PROMPTS_DIR:-./re-cwe-prompts}`
- Copy‑paste one prompt to your AI agent: `examples/BOOTSTRAP_AGENT_PROMPT.md`
  - Provide `CWE` (e.g., `CWE-22`), `TARGET_URL`, and `OUT_DIR` (e.g., `../docs/prompts`).
  - The agent scaffolds MASTER + 01..06 prompt files into `<OUT_DIR>/<CWE>/<scheme-host-port>/` using this repo’s docs.
- No agent? Use the script: `bash scripts/export_prompts.sh --cwe CWE-22 --target-url http://host:port --out-dir ../docs/prompts`

Manual Quick Start (optional)
- Create private dirs at your parent project root: `targets-local/<target-key>/...`, `reports-private/`.
- Use the examples pack to guide analysis:
  - Master: `examples/CWE-22/MASTER.md`
  - Steps: `examples/CWE-22/0{1..6}_*.md`
  - Replace placeholders and follow in order.

Example Target Walkthrough (target:8010)
1) Init
   - Create folders: `mkdir -p targets-local/http-target-8010/{evidence,captures}` `mkdir -p reports-private`
   - Create `targets-local/http-target-8010/target.json` using `templates/target_info_template.json` as a guide. Do not commit secrets.

2) Discover routes (dynamic + static)
   - Dynamic: probe `GET /`, `/Storage.html`, `/api`, `/admin`; record headers and behavioral hints.
   - Use `"$RE_CWE_PROMPTS_DIR/probes/CWE-22/python_probe_prompt.md"` to generate `scripts/probes/cwe22_probe.py` (reads `--target-json`; respects timeouts/rate limits). Save evidence in `targets-local/http-target-8010/evidence/`.
   - Static (optional): in IDA/Ghidra, apply `"$RE_CWE_PROMPTS_DIR/workflows/discover_routes.md"` and `trace_to_fs_sinks.md` to identify dispatcher→handler→sink chains.
   - For deep RE strategies and guided prompts, open `rev-prompts/STRATEGY_OVERVIEW.md` then use templates under `rev-prompts/`:
     - `TEMPLATE_SESSION_BOOTSTRAP.md` — bootstrap the session, roles, and plan
     - `TEMPLATE_DISPATCHER_DISCOVERY.md` — top‑down route mapping
     - `TEMPLATE_SINK_TRACING.md` — bottom‑up sink‑led hunt
     - `TEMPLATE_FS_GUARD_AUDIT.md` — traversal guard audit
     - `TEMPLATE_RENAMING_AND_COMMENTS.md` — consistent naming/comments
     - `TEMPLATE_REPORT_AND_FIX_PLAN.md` — expanded reporting + fix plan

3) Deep reverse engineering (main task)
   - In your disassembler (IDA MCP or Ghidra), trace 2–3 hops from route handlers to filesystem sinks using role‑based thinking (`roles/`, `workflows/`).
   - Classify functions (dispatcher/handler/sanitizer/sink), document controls, and add comments/renames consistently.

4) Find vulnerability and define a fix plan
   - Start with CWE‑22. Compare the observed control chain against `checklists/fix_fs_guard.md` and `workflows/gap_analysis_and_fix.md`.
   - Define a guard sequence: decode → validate segments → canonicalize → prefix‑check → FS open.
   - Use `workflows/generate_report.md` and `workflows/write_reports.md` to produce a report + summary.

5) Verify by Python probe
   - Run your generated probe, e.g.: `python3 scripts/probes/cwe22_probe.py --target-json targets-local/http-target-8010/target.json --max 50`
   - Review outputs in `targets-local/http-target-8010/evidence/` and a sanitized summary in `reports/`.
   - After patching, re‑run to confirm mitigation.

Modular External Prompts (copy-paste ready)
- Use the master controller prompt:
  - `local/EXTERNAL_AGENT_PROMPT_CWE22_target_8010_MASTER.md`
- Then follow the modular steps in `local/prompts/`:
  - `01_init_and_context.md` — init target and evidence layout
  - `02_discover_and_dynamic_probe.md` — parse captures, discover routes, run probe
  - `03_plan_multi_strategy.md` — plan multi‑strategy deep RE
  - `04_execute_deep_re.md` — execute in IDA/Ghidra with templates
  - `05_fix_plan_and_reporting.md` — produce fix plan and reports
  - `06_verification_scripts.md` — implement and run verification scripts

Examples (ready-to-paste prompts)
- Generic, IP-agnostic examples for CWE-22 (replace placeholders):
  - Master: `examples/CWE-22/MASTER.md`
  - Steps: `examples/CWE-22/0{1..6}_*.md`
  - See `examples/README.md` for placeholder format and usage.

One-Prompt Bootstrap (generate downstream stubs)
- Prefer a single, copy-paste prompt that instructs your agent to generate per-target prompt files (MASTER + steps) under your downstream project (e.g., `../docs/prompts`). Use:
  - `examples/BOOTSTRAP_AGENT_PROMPT.md`
- Provide the agent with:
  - `RE_CWE_PROMPTS_DIR` (default `./re-cwe-prompts`)
  - `CWE` (e.g., `CWE-22`)
  - `TARGET_URL` (e.g., `http://target:8010`)
  - `OUT_DIR` (e.g., `../docs/prompts`)
- The agent should copy `examples/<CWE>/MASTER.md` and step files to `<OUT_DIR>/<CWE>/<scheme-host-port>/`, rendering placeholders: `<TARGET_URL>`, `<TARGET_HOST>`, `<TARGET_PORT>`, `<TARGET_KEY>`.
- Alternative (no agent): run `scripts/export_prompts.sh --cwe CWE-22 --target-url http://host:port --out-dir ../docs/prompts`

Scaffold downstream prompts (docs/prompts)
- Use the exporter script to render examples with your target values into a downstream project:
  - `bash scripts/export_prompts.sh --cwe CWE-22 \
     --target-url http://target:8010 \
     --out-dir ../docs/prompts`
- Options:
  - `--target-key` to override the auto-generated `<scheme-host-port>` key
  - `--force` to overwrite existing files
- Output layout: `<out-dir>/CWE-22/<scheme-host-port>/MASTER.md` and `01..06_*.md`

Quick start
1) Pick a CWE guide under `cwes/` (e.g., `CWE-22.md`, `CWE-601.md`, `CWE-79.md`).
2) Apply the workflows under `workflows/` in order:
   - `discover_routes.md` — Find request dispatchers and static handlers via strings/xrefs/decompile.
   - `trace_to_fs_sinks.md` — Trace dispatcher→handler→utility→sink (2–3 hops), confirm sinks/imports.
   - `gap_analysis_and_fix.md` — Apply the CWE’s control checklist to locate gaps and define a fix.
   - `generate_report.md` — Produce a role‑based static+dynamic report.
    - `write_reports.md` — Persist a full report and a short summary to `reports/`.

Using in this project (end-to-end)
- Initialize private folders at repo root (preferred):
  - `sh scripts/init_private_dirs.sh` (creates `targets-local/` and `reports-private/`, both gitignored)
- Create per-target JSON:
  - Follow `tutorials/init_target_info.md` and save to `targets-local/<scheme-host-port>/target.json` (e.g., `targets-local/http-target-8010/target.json`).
- Dynamic testing via prompts:
  - Traversal probe (Python): open `probes/CWE-22/python_probe_prompt.md` and generate a script under your main repo (e.g., `scripts/probes/cwe22_probe.py`); run it with `--target-json targets-local/<...>/target.json`.
  - Captures import (HAR/cURL/Burp): place raw files under `targets-local/<...>/captures/` and use prompts in `captures/` to generate replay scripts. Never hardcode real IPs; always read `target.json`.
- Static analysis in IDA MCP:
  - Use `cases/CWE-22_IDA_MCP_Session_Seed.md` plus `workflows/` (discover routes → trace sinks → gap analysis). Use `roles/` and `tool-notes/` for consistent renames/comments and command references.
- Reports and summaries:
  - Generate per `workflows/generate_report.md` and write files per `workflows/write_reports.md`.
  - Public sanitized copies go to `reports/`; private unredacted copies may go to `reports-private/`.

Beyond CWEs (optional helpers)
- Use `roles/README.md` to classify functions by role and drive consistent renaming/comments.
- Use `tool-notes/` as a quick reference for IDA MCP/Ghidra operations.
- Use `checklists/` during analysis, fix definition, and reporting.
- Use `playbooks/` for common end‑to‑end scenarios (e.g., static resources).
- Use `templates/` if you want to generate reports programmatically.
- Keep sensitive target data out of git: use the root‑level `targets-local/` and `reports-private/` (both gitignored). Public reports in `reports/` must be sanitized.
  - Preferred location: `targets-local/<target-key>/` at the repository root (NOT under `re-cwe-prompts/`).
  - Standalone prompts repo note: only if you are using this prompts repository by itself (outside a parent project), you may use `re-cwe-prompts/targets-local/` and `re-cwe-prompts/reports-private/` (both ignored via `re-cwe-prompts/.gitignore`).
  - See `tutorials/init_target_info.md` for creating `target.json` under `targets-local/<target-key>/`.

Preferred private paths
- Root‑level is the default for all private artifacts:
  - Targets (private JSON, captures, evidence): `targets-local/<target-key>/...`
  - Private reports (unredacted): `reports-private/`
- Avoid saving to `re-cwe-prompts/targets-local/` unless you are running this prompts repo in isolation.

Using with IDA or Ghidra
- IDA Pro MCP: use `list_strings_filter`, `get_xrefs_to`, `decompile_function`, `get_callees`, `set_comment`. See `tool-notes/IDA_MCP.md` for a full cheatsheet.
- Ghidra: use String Search, References, Decompiler, Call Tree/Function Graph, and Plate Comments. The same role‑based thinking applies.

Session seeds (cases)
- For a quick start in another Codex/Claude session connected to IDA MCP, open and paste the seed from:
  - `cases/CWE-22_IDA_MCP_Session_Seed.md`
  - The seed references `cwes/CWE-22.md` and the generic workflows under `workflows/`.

General guidance
- Keep analysis role‑driven; don’t hard‑code symbol names.
- Treat transformations (decode/normalize) and controls (validation, canonicalization, prefix checks) as first‑class.
- Blend static with small dynamic probes where safe.

Contributing new CWEs
- Start from `cwes/CWE-TEMPLATE.md` and link it in `INDEX.md`.

Advanced fuzzing
- Read `cwes/ADVANCED_FUZZING_PRIMER.md` for cross-CWE fuzz strategies.
- For traversal: see `cwes/CWE-22.md` (advanced section) and `probes/CWE-22/python_fuzzer_prompt_advanced.md`.
- For XSS: see `cwes/CWE-79.md` (advanced section) and `probes/CWE-79/python_probe_prompt.md`.
- For open redirect: see `cwes/CWE-601.md` (advanced section) and `probes/CWE-601/python_probe_prompt.md`.

Extending guidance beyond CWEs
- Add role notes under `roles/` if you introduce new role conventions.
- For tool specifics, extend `tool-notes/` rather than bloating workflows.
- For repeatable scenarios, add a `playbooks/` page that references existing workflows and checklists.
