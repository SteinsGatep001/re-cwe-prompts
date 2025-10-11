# Prompt Index

- CWE patterns
  - `cwes/CWE-22.md` — Directory Traversal: symptoms, sources/sinks, controls, and fix shape.
  - `cwes/CWE-601.md` — Open Redirect: sources, sinks (Location), and allowlist/relative‑only fixes.
  - `cwes/CWE-79.md` — Cross-Site Scripting: sources/sinks and context‑sensitive encoding.
  - `cwes/CWE-TEMPLATE.md` — Template for adding new CWE guides.

- Workflow (generic, role‑based)
  1) `11_discover_routes_generically.md` — Find route dispatchers and static handlers.
  2) `12_trace_to_fs_sinks.md` — Build a call graph to filesystem sinks and confirm sinks.
  3) `13_gap_analysis_and_fix.md` — Identify missing controls and define the fix.
  4) `14_generate_report_generic.md` — Produce a comprehensive report (static + dynamic).

Tips
- Apply `set_comment` to key functions to preserve insights (role, security notes).
- Keep findings role‑based (no reliance on symbol names) so the approach generalizes to other binaries.
