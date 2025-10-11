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

## Cases (session seeds)
- `cases/CWE-22_IDA_MCP_Session_Seed.md` — Paste into Codex/Claude with IDA MCP to run a generic CWE‑22 analysis
