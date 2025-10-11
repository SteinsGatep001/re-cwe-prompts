# Playbook — Web Static Resources (Path Traversal Focus)

Use when
- The binary serves files (e.g., `.html`, `Storage.html`, assets) via HTTP handlers.

Flow
1) Run `workflows/discover_routes.md`
2) Trace candidate static handlers via `workflows/trace_to_fs_sinks.md`
3) Apply `cwes/CWE-22.md` and `checklists/analysis.md`
4) If gaps exist, use `checklists/fix_fs_guard.md`
5) Generate and write reports via `workflows/generate_report.md` and `workflows/write_reports.md`

Notes
- Rename functions to role-based names for clarity; annotate expected guard sequence at handler.

