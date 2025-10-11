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
  - Follow `tutorials/init_target_info.md` and save to `targets-local/<scheme-host-port>/target.json` (e.g., `targets-local/http-192.168.159.249-8010/target.json`).
- Dynamic testing via prompts:
  - Traversal probe (Python): open `probes/cwe-22_python_probe_prompt.md` and generate a script under your main repo (e.g., `scripts/probes/cwe22_probe.py`); run it with `--target-json targets-local/<...>/target.json`.
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
- IDA Pro MCP: use `list_strings_filter`, `get_xrefs_to`, `decompile_function`, `get_callees`, `set_comment`.
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

Extending guidance beyond CWEs
- Add role notes under `roles/` if you introduce new role conventions.
- For tool specifics, extend `tool-notes/` rather than bloating workflows.
- For repeatable scenarios, add a `playbooks/` page that references existing workflows and checklists.
