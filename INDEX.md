# Prompt Index

## CWE patterns
- `cwes/CWE-22.md` — Directory Traversal (decode→validate segments→canonicalize→prefix‑check→FS)
- `cwes/CWE-601.md` — Open Redirect (validate/allowlist redirect target; enforce relative)
- `cwes/CWE-79.md` — Cross‑Site Scripting (context‑sensitive encoding)
- `cwes/CWE-TEMPLATE.md` — Template for adding new CWE guides

## Workflows (generic, tool‑agnostic)
1) `workflows/discover_routes.md` — Find request dispatchers/static handlers via strings/xrefs/decompile
2) `workflows/trace_to_fs_sinks.md` — Trace dispatcher→handler→utility→sink (2–3 hops), confirm sinks/imports
3) `workflows/gap_analysis_and_fix.md` — Apply CWE control checklist; define fix points
4) `workflows/generate_report.md` — Produce a role‑based static+dynamic report
5) `workflows/write_reports.md` — Write full report + brief summary into `reports/`

## Roles and conventions
- `roles/README.md` — Role definitions and rename/comment heuristics

## Tool notes
- `tool-notes/IDA_MCP.md` — MCP command cheatsheet
- `tool-notes/Ghidra.md` — Ghidra parallels and tips

## Checklists
- `checklists/analysis.md` — Generic analysis checklist
- `checklists/fix_fs_guard.md` — Filesystem guard fix for traversal
- `checklists/reporting.md` — Reporting checklist and file naming

## Playbooks
- `playbooks/web_static_resources.md` — End-to-end for static resource serving

## Cases (session seeds)
- `cases/CWE-22_IDA_MCP_Session_Seed.md` — Paste into Codex/Claude with IDA MCP to run a generic CWE‑22 analysis
- `cases/CWE-22_IDA_MCP_Session_Seed_zh-CN.md` — 中文会话种子（同上）

## Templates
- `templates/report_CWE_GENERIC.md` — Generic report skeleton
- `templates/summary_CWE_GENERIC.txt` — Generic summary skeleton
