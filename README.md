# Reverse Engineering CWE Prompts (Tool‑Agnostic: IDA, Ghidra)

Purpose
- Pattern‑based prompts for guiding an AI agent (Codex/Claude) to discover, analyze, and report common web security weaknesses (CWEs) in binaries using disassemblers like IDA Pro or Ghidra. The prompts are generic and role‑based (dispatcher, handler, sanitizer, sink), so they work across tools and codebases.

Repository layout
- `cwes/` — CWE guides (pattern, sources/sinks, red flags, fix shape)
- `workflows/` — Generic workflows used for any CWE (discover routes, trace sinks, gap analysis, generate report)
- `cases/` — Ready-to-paste session seeds for common analyses (e.g., CWE-22 with IDA MCP)
- `INDEX.md` — Quick index linking CWEs and workflows
- `README_zh-CN.md` — 中文使用说明

Quick start
1) Pick a CWE guide under `cwes/` (e.g., `CWE-22.md`, `CWE-601.md`, `CWE-79.md`).
2) Apply the workflows under `workflows/` in order:
   - `discover_routes.md` — Find request dispatchers and static handlers via strings/xrefs/decompile.
   - `trace_to_fs_sinks.md` — Trace dispatcher→handler→utility→sink (2–3 hops), confirm sinks/imports.
   - `gap_analysis_and_fix.md` — Apply the CWE’s control checklist to locate gaps and define a fix.
   - `generate_report.md` — Produce a role‑based static+dynamic report.

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
