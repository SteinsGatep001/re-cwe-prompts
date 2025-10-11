# Using These Prompts To Guide An AI Agent (Codex/Claude CLI)

This folder contains pattern‑based prompts that teach an AI agent how to statically discover and report common web security weaknesses in binaries using IDA Pro MCP — without relying on specific symbol names. The prompts are modular so you can pick a CWE and apply the same generic workflow.

How to use
- Step 1: Pick a CWE guide under `prompts/cwes/` (e.g., `CWE-22.md`, `CWE-601.md`, `CWE-79.md`).
  - Learn the vulnerability pattern, typical sources/sinks, red flags, and desired fix shape.
- Step 2: Run the generic workflow prompts in order:
  1) `11_discover_routes_generically.md` — find HTTP route dispatchers/static handlers via strings/xrefs/decompile.
  2) `12_trace_to_fs_sinks.md` — trace dispatcher→handler→utility→sink (2–3 hops), confirm sinks.
  3) `13_gap_analysis_and_fix.md` — apply the CWE’s control checklist to locate gaps and define a fix.
  4) `14_generate_report_generic.md` — produce a role‑based static+dynamic report.

IDA Pro MCP actions commonly used
- `list_strings_filter` — surface relevant strings (protocol markers, headers, MIME, “redirect”, “open”, extensions)
- `get_xrefs_to` — jump from strings to code, identify dispatchers/handlers
- `decompile_function` — inspect logic
- `get_callees` — walk the call graph toward the sinks
- `set_comment` — annotate functions with roles and security notes (keep role‑based, not name‑based)

General advice
- Keep analysis role‑driven: use terms like dispatcher, static handler, path utility, validation/sanitizer, sink wrapper, import sink.
- Never treat headers/templating as sanitizers unless they demonstrably constrain the attack surface for that CWE.
- Blend static with targeted dynamic checks (e.g., a small Python probe script) to confirm impact.

Adding a new CWE guide
- Copy `prompts/cwes/CWE-TEMPLATE.md` and fill in:
  - Sources/sinks by role, red flags, high‑level ida‑mcp steps, dynamic spot‑checks, fix blueprint, reporting guidance.
- Link the new file from `prompts/00_index.md`.

